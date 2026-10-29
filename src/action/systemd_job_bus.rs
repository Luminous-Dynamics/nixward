// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Live, read-only systemd start-job observation through zbus.
//!
//! This module submits one transaction-derived unit start and observes only
//! its manager job lifecycle. It does not authorize the unit, create the
//! privileged worker, mutate the NixOS transaction journal, or assert host
//! activation success. The caller must persist the pre-launch write-ahead
//! intent before calling submit_start, then persist the returned StartUnit
//! reply before waiting for the completion signal.

use std::time::Duration;

use futures_util::StreamExt;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Proxy, proxy::SignalStream};

use super::systemd_job_evidence::{
    JobRemovedEvidence, JobRemovedResult, ManagerStartReply, PersistedStart, StartIntent,
    PreparedStartIntent, StartJobCorrelation, StartReplyDisposition, SubmittedStart,
    SystemdStartEvidence, classify_start_reply, correlate_job_removed,
};

const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";

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
    let manager = Proxy::new(
        &connection,
        SYSTEMD_SERVICE,
        SYSTEMD_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .await
    .map_err(|error| format!("failed to create systemd manager proxy: {error}"))?;

    // The subscription closure first installs the JobRemoved match, then
    // calls Manager.Subscribe(). If either operation fails, no SubscribedStart
    // capability is returned and StartUnit is never called.
    let subscribed = intent
        .subscribe_before_start(|| async {
            let stream = manager
                .receive_signal("JobRemoved")
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
            let manager = &manager;
            async move {
                let result: Result<OwnedObjectPath, zbus::Error> = manager
                    .call("StartUnit", &(unit_name.as_str(), "fail"))
                    .await;
                match result {
                    Ok(job_object_path) => ManagerStartReply::Enqueued {
                        job_object_path: job_object_path.to_string(),
                    },
                    Err(_) => ManagerStartReply::Unknown,
                }
            }
        })
        .await)
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

    match classify_start_reply(&start_evidence) {
        Ok(StartReplyDisposition::Enqueued { .. }) => {}
        Ok(StartReplyDisposition::Ambiguous) => {
            return SystemdStartObservation {
                start_evidence,
                job_removed: None,
                raw_job_result: None,
                correlation: StartJobCorrelation::HoldForReconciliation {
                    reason: "StartUnit reply is unknown; reconcile the canonical unit before any retry".into(),
                },
            };
        }
        Ok(StartReplyDisposition::ManagerRejected { error_name }) => {
            return SystemdStartObservation {
                start_evidence,
                job_removed: None,
                raw_job_result: None,
                correlation: StartJobCorrelation::ManagerRejected { error_name },
            };
        }
        Err(reason) => {
            return SystemdStartObservation {
                start_evidence,
                job_removed: None,
                raw_job_result: None,
                correlation: StartJobCorrelation::RejectedEvidence { reason },
            };
        }
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
    fn unknown_manager_result_is_never_mapped_to_done() {
        assert_eq!(parse_job_result("done"), JobRemovedResult::Done);
        for raw in ["", "finished", "future-result", "OOM-kill"] {
            assert_eq!(parse_job_result(raw), JobRemovedResult::Unknown, "{raw}");
        }
    }
}
