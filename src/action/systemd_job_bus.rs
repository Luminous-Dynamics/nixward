// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! systemd start-job submission and observation through zbus.
//!
//! The submit path performs one mutating StartUnit request, then observes only
//! the corresponding manager job lifecycle. This module is crate-private and
//! must not be wired into production until the existing transaction
//! authorization, interlock, canonical unit definition, and VM qualification
//! are integrated. It does not authorize the unit, create/qualify the
//! privileged worker, mutate the transaction journal itself, or assert host
//! activation success. The caller must persist the pre-launch intent before
//! calling submit_start, then persist the returned StartUnit reply before
//! waiting for the completion signal.

use std::time::Duration;

use futures_util::StreamExt;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Proxy, proxy::SignalStream};

use super::systemd_job_evidence::{
    JobRemovedEvidence, JobRemovedResult, ManagerStartReply, PersistedStart,
    PreparedStartIntent, StartJobCorrelation, StartReplyDisposition, SubmittedStart,
    SystemdStartEvidence, classify_start_reply, correlate_job_removed,
};

const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const START_UNIT_REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// Start intent plus the live JobRemoved subscription and exact direct reply.
///
/// The returned value is not yet waitable. First call persist_before_observing
/// with the caller's durable journal publication routine; only the resulting
/// PersistedStart can be passed to wait_for_job_removed.
pub async fn submit_start(
    intent: PreparedStartIntent,
) -> Result<SubmittedStart<SignalStream<'static>>, String> {
    let connection = Connection::system()
        .await
        .map_err(|error| format!("failed to connect to the system bus: {error}"))?;
    // Own the connection and all proxy addressing strings. The returned signal
    // stream is carried beyond this function, so it must not borrow a local
    // Connection, Proxy, or unit-name buffer.
    let manager = Proxy::new_owned(
        connection,
        SYSTEMD_SERVICE,
        SYSTEMD_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .await
    .map_err(|error| format!("failed to create systemd manager proxy: {error}"))?;

    // Match only JobRemoved events for this attempt's canonical unit. This
    // prevents unrelated host job traffic from filling the connection queue
    // while the StartUnit method reply is in flight. A conflicting/missing
    // matching event still yields a conservative hold or timeout.
    let expected_unit = intent.unit_name().to_owned();

    // The subscription closure first installs the JobRemoved match, then
    // calls Manager.Subscribe(). If either operation fails, no SubscribedStart
    // capability is returned and StartUnit is never called.
    let subscribed = intent
        .subscribe_before_start(|| async {
            let stream = manager
                .receive_signal_with_args("JobRemoved", &[(2, expected_unit.as_str())])
                .await
                .map_err(|error| format!("failed to install JobRemoved subscription: {error}"))?;
            let _: () = manager
                .call("Subscribe", &())
                .await
                .map_err(|error| format!("systemd Manager.Subscribe failed: {error}"))?;
            Ok::<_, String>(stream)
        })
        .await?;

    // Use mode=fail: a replay that encounters an existing/in-flight unit must
    // not replace or merge into that job. Transport errors are conservatively
    // recorded as Unknown because a lost method reply does not prove no job
    // was enqueued. Never retry this attempt from this adapter.
    Ok(subscribed
        .submit_start(|unit_name| {
            // Move an owned proxy into the request future. Borrowing the
            // function-local proxy here would make the future's lifetime
            // depend on the closure's inferred lifetime.
            let manager = manager.clone();
            async move {
                let result: Result<OwnedObjectPath, zbus::Error> =
                    match tokio::time::timeout(
                        START_UNIT_REPLY_TIMEOUT,
                        manager.call("StartUnit", &(unit_name.as_str(), "fail")),
                    )
                    .await
                    {
                        Ok(result) => result,
                        // The request may already have reached PID 1. Expiry
                        // is therefore an ambiguous reply, never permission
                        // to resubmit this attempt.
                        Err(_) => return ManagerStartReply::Unknown,
                    };
                match result {
                    Ok(job_object_path) => ManagerStartReply::Enqueued {
                        job_object_path: job_object_path.to_string(),
                    },
                    // A D-Bus method-error reply is known manager rejection.
                    // Other errors may indicate a lost reply after enqueue and
                    // therefore remain ambiguous.
                    Err(zbus::Error::MethodError(name, _, _)) => {
                        ManagerStartReply::Rejected {
                            error_name: name.to_string(),
                        }
                    }
                    Err(_) => ManagerStartReply::Unknown,
                }
            }
        })
        .await)
}

/// Decide whether signal observation is appropriate after the direct reply.
///
/// Unknown is intentionally waitable: if the transport remains alive, retain a
/// JobRemoved event as additional reconciliation evidence. The correlator still
/// holds because a signal alone cannot replace a lost StartUnit object path.
fn classify_wait_precondition(
    evidence: &SystemdStartEvidence,
) -> Result<(), StartJobCorrelation> {
    match classify_start_reply(evidence) {
        Ok(StartReplyDisposition::Enqueued { .. }) => Ok(()),
        Ok(StartReplyDisposition::Ambiguous) => Ok(()),
        Ok(StartReplyDisposition::ManagerRejected { error_name }) => {
            Err(StartJobCorrelation::ManagerRejected { error_name })
        }
        Err(reason) => Err(StartJobCorrelation::RejectedEvidence { reason }),
    }
}

/// Result of observing one manager-level job. This is not a transaction result:
/// done means the systemd job completed, not that the worker exited or the
/// desired NixOS runtime/profile became active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdStartObservation {
    pub start_evidence: SystemdStartEvidence,
    pub job_removed: Option<JobRemovedEvidence>,
    /// Raw systemd result text is retained for auditing even if it is newer
    /// than this version of Nixward's closed result enum.
    pub raw_job_result: Option<String>,
    pub correlation: StartJobCorrelation,
}

/// Consume a durably recorded start ticket and wait for the matching manager
/// event. Unrelated jobs are ignored; any partial identity collision holds for
/// reconciliation. Timeout, disconnect, malformed tuples, and unknown results
/// never become successful transaction classifications.
pub async fn wait_for_job_removed(
    persisted: PersistedStart<SignalStream<'static>>,
    timeout: Duration,
) -> SystemdStartObservation {
    let (start_evidence, mut stream) = persisted.into_parts();

    if let Err(correlation) = classify_wait_precondition(&start_evidence) {
        return SystemdStartObservation {
            start_evidence,
            job_removed: None,
            raw_job_result: None,
            correlation,
        };
    }

    type DecodedSignal = (JobRemovedEvidence, String, StartJobCorrelation);
    let wait = tokio::time::timeout(timeout, async {
        loop {
            let Some(message) = stream.next().await else {
                return None;
            };

            let decoded: (u32, OwnedObjectPath, String, String) =
                match message.body().deserialize() {
                    Ok(value) => value,
                    Err(error) => return Some(Err(format!(
                        "JobRemoved signal did not match the documented (id, path, unit, result) tuple: {error}"
                    ))),
                };

            let (job_id, job_path, unit_name, raw_result) = decoded;
            let event = JobRemovedEvidence {
                job_id,
                job_object_path: job_path.to_string(),
                unit_name,
                result: parse_job_result(&raw_result),
            };
            let correlation = correlate_job_removed(&start_evidence, &event);
            if correlation == StartJobCorrelation::UnrelatedSignal {
                continue;
            }
            return Some(Ok::<DecodedSignal, String>((event, raw_result, correlation)));
        }
    })
    .await;

    match wait {
        Err(_) => SystemdStartObservation {
            start_evidence,
            job_removed: None,
            raw_job_result: None,
            correlation: StartJobCorrelation::HoldForReconciliation {
                reason: "timed out waiting for the exact JobRemoved event; keep the attempt indeterminate".into(),
            },
        },
        Ok(None) => SystemdStartObservation {
            start_evidence,
            job_removed: None,
            raw_job_result: None,
            correlation: StartJobCorrelation::HoldForReconciliation {
                reason: "JobRemoved stream ended before the exact job was observed".into(),
            },
        },
        Ok(Some(Err(reason))) => SystemdStartObservation {
            start_evidence,
            job_removed: None,
            raw_job_result: None,
            correlation: StartJobCorrelation::RejectedEvidence { reason },
        },
        Ok(Some(Ok((event, raw_job_result, correlation)))) => SystemdStartObservation {
            start_evidence,
            job_removed: Some(event),
            raw_job_result: Some(raw_job_result),
            correlation,
        },
    }
}

fn parse_job_result(raw: &str) -> JobRemovedResult {
    match raw {
        "done" => JobRemovedResult::Done,
        "canceled" => JobRemovedResult::Canceled,
        "timeout" => JobRemovedResult::Timeout,
        "failed" => JobRemovedResult::Failed,
        "dependency" => JobRemovedResult::Dependency,
        "skipped" => JobRemovedResult::Skipped,
        _ => JobRemovedResult::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_direct_reply_remains_observable_but_never_proves_completion() {
        use super::super::systemd_job_evidence::{
            canonical_attempt_unit_name, correlate_job_removed, JobRemovedEvidence,
            StartJobCorrelation, SystemdStartEvidence, TransactionWorkerPurpose,
        };

        let transaction_id = "tx-observer-test";
        let attempt_id = "attempt-unknown-reply";
        let purpose = TransactionWorkerPurpose::Activation;
        let evidence = SystemdStartEvidence {
            transaction_id: transaction_id.into(),
            attempt_id: attempt_id.into(),
            purpose,
            unit_name: canonical_attempt_unit_name(transaction_id, attempt_id, purpose).unwrap(),
            reply: ManagerStartReply::Unknown,
        };
        assert_eq!(classify_wait_precondition(&evidence), Ok(()));

        let signal = JobRemovedEvidence {
            job_id: 41,
            job_object_path: "/org/freedesktop/systemd1/job/41".into(),
            unit_name: evidence.unit_name.clone(),
            result: JobRemovedResult::Done,
        };
        assert!(matches!(
            correlate_job_removed(&evidence, &signal),
            StartJobCorrelation::HoldForReconciliation { .. }
        ));
    }

    #[test]
    fn unknown_manager_result_is_never_mapped_to_done() {
        assert_eq!(parse_job_result("done"), JobRemovedResult::Done);
        for raw in ["", "finished", "future-result", "OOM-kill"] {
            assert_eq!(parse_job_result(raw), JobRemovedResult::Unknown, "{raw}");
        }
    }

    /// This mutates the systemd manager and therefore must only be executed
    /// by the explicit disposable-VM test harness. Ordinary cargo test runs
    /// ignore it so a developer's host is never changed by the test suite.
    #[cfg(feature = "systemd")]
    #[tokio::test]
    #[ignore = "requires the dedicated NixOS VM and nixward-transaction@.service test template"]
    async fn live_systemd_start_job_round_trip() {
        use super::super::systemd_job_evidence::{
            StartIntent, StartJobCorrelation, TransactionWorkerPurpose,
        };

        let intent = StartIntent::new(
            "vm-systemd-observer",
            "round-trip-0001",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();

        // This callback intentionally tests protocol order only. It is not a
        // durable-journal implementation and must never be used in production.
        let prepared = intent
            .persist_before_submission(|evidence| async move {
                assert_eq!(evidence.transaction_id, "vm-systemd-observer");
                assert_eq!(evidence.attempt_id, "round-trip-0001");
                Ok::<(), String>(())
            })
            .await
            .unwrap();

        let submitted = submit_start(prepared).await.unwrap();
        assert!(
            matches!(
                submitted.evidence().reply,
                ManagerStartReply::Enqueued { .. }
            ),
            "the VM's dedicated template unit must be enqueued: {:?}",
            submitted.evidence().reply
        );

        let persisted = submitted
            .persist_before_observing(|evidence| async move {
                assert!(matches!(evidence.reply, ManagerStartReply::Enqueued { .. }));
                Ok::<(), String>(())
            })
            .await
            .unwrap();

        let observation =
            wait_for_job_removed(persisted, Duration::from_secs(15)).await;
        assert_eq!(
            observation.correlation,
            StartJobCorrelation::MatchedStartJobCompleted,
            "expected a path/ID/unit-correlated JobRemoved done event: {observation:?}"
        );
        assert_eq!(
            observation.raw_job_result.as_deref(),
            Some("done"),
            "preserve the manager's raw result string"
        );
        assert!(observation.job_removed.is_some());
    }
}
