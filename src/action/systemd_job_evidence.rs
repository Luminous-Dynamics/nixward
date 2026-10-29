// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Pure correlation contract for asynchronous systemd start-job evidence.
//!
//! This module deliberately does not talk to D-Bus or authorize host mutation.
//! It prevents callers from confusing a StartUnit acknowledgement, an
//! unrelated JobRemoved signal, or a lost reply with proof that a worker ran.
//! Production D-Bus integration must subscribe before StartUnit and feed this
//! contract the exact reply and signal values it observed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const UNIT_NAME_DOMAIN: &[u8] = b"nixward-systemd-attempt-unit-v1\0";
const JOB_OBJECT_PATH_PREFIX: &str = "/org/freedesktop/systemd1/job/";

/// Purpose is part of the derived unit identity, so activation and recovery
/// attempts cannot accidentally alias one another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionWorkerPurpose {
    ProfileTransition,
    Activation,
    RecoveryProfileTransition,
    RecoveryActivation,
}

impl TransactionWorkerPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProfileTransition => "profile_transition",
            Self::Activation => "activation",
            Self::RecoveryProfileTransition => "recovery_profile_transition",
            Self::RecoveryActivation => "recovery_activation",
        }
    }
}

/// Derive the only acceptable unit name for a transaction/attempt/purpose
/// tuple. Input identifiers are never copied into a privileged unit name.
pub fn canonical_attempt_unit_name(
    transaction_id: &str,
    attempt_id: &str,
    purpose: TransactionWorkerPurpose,
) -> Result<String, String> {
    validate_identity("transaction ID", transaction_id)?;
    validate_identity("attempt ID", attempt_id)?;

    let mut hash = Sha256::new();
    hash.update(UNIT_NAME_DOMAIN);
    for field in [transaction_id, attempt_id, purpose.as_str()] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    let digest = format!("{:x}", hash.finalize());
    // Hex is safe as a systemd template instance; caller-controlled input
    // cannot inject unit separators, specifiers, or another unit name.
    Ok(format!("nixward-transaction@{digest}.service"))
}

fn validate_identity(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be blank"));
    }
    if value.len() > 256 {
        return Err(format!("{label} exceeds the 256-byte contract limit"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{label} contains a control character"));
    }
    Ok(())
}


/// Unsubmitted transaction-scoped start intent. It contains no start authority
/// and cannot be passed to the systemd adapter until the caller's durable
/// preflight callback succeeds.
#[derive(Debug, PartialEq, Eq)]
pub struct StartIntent {
    transaction_id: String,
    attempt_id: String,
    purpose: TransactionWorkerPurpose,
    unit_name: String,
}

impl StartIntent {
    pub fn new(
        transaction_id: impl Into<String>,
        attempt_id: impl Into<String>,
        purpose: TransactionWorkerPurpose,
    ) -> Result<Self, String> {
        let transaction_id = transaction_id.into();
        let attempt_id = attempt_id.into();
        let unit_name = canonical_attempt_unit_name(&transaction_id, &attempt_id, purpose)?;
        Ok(Self {
            transaction_id,
            attempt_id,
            purpose,
            unit_name,
        })
    }

    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    pub fn purpose(&self) -> TransactionWorkerPurpose {
        self.purpose
    }

    pub fn unit_name(&self) -> &str {
        &self.unit_name
    }

    pub fn journal_evidence(&self) -> StartIntentEvidence {
        StartIntentEvidence {
            transaction_id: self.transaction_id.clone(),
            attempt_id: self.attempt_id.clone(),
            purpose: self.purpose,
            unit_name: self.unit_name.clone(),
        }
    }

    /// Run the caller's durable write-ahead publication before any manager
    /// connection or StartUnit call is allowed by this type-state API.
    pub async fn persist_before_submission<E, F, Fut>(
        self,
        persist: F,
    ) -> Result<PreparedStartIntent, E>
    where
        F: FnOnce(StartIntentEvidence) -> Fut,
        Fut: std::future::Future<Output = Result<(), E>>,
    {
        persist(self.journal_evidence()).await?;
        Ok(PreparedStartIntent { intent: self })
    }
}

/// Serializable, journal-bound intent for exactly one transaction/attempt.
/// The caller's persistence callback must publish this before allowing
/// PreparedStartIntent to be used for a manager request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartIntentEvidence {
    pub transaction_id: String,
    pub attempt_id: String,
    pub purpose: TransactionWorkerPurpose,
    pub unit_name: String,
}

/// Non-serializable authority to proceed past the pre-launch write-ahead
/// barrier. Its constructor is private and only persistence success returns it.
#[derive(Debug, PartialEq, Eq)]
pub struct PreparedStartIntent {
    intent: StartIntent,
}

impl PreparedStartIntent {
    pub fn transaction_id(&self) -> &str {
        self.intent.transaction_id()
    }

    pub fn attempt_id(&self) -> &str {
        self.intent.attempt_id()
    }

    pub fn purpose(&self) -> TransactionWorkerPurpose {
        self.intent.purpose()
    }

    pub fn unit_name(&self) -> &str {
        self.intent.unit_name()
    }

    /// Establish the manager signal subscription before advancing the intent.
    /// The closure should install the JobRemoved match and call Manager.Subscribe().
    /// The resulting type retains the live subscription across StartUnit.
    pub(crate) async fn subscribe_before_start<E, F, Fut, S>(
        self,
        establish_subscription: F,
    ) -> Result<SubscribedStart<S>, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<S, E>>,
    {
        let subscription = establish_subscription().await?;
        Ok(SubscribedStart {
            intent: self.intent,
            subscription,
        })
    }
}

/// Ephemeral capability proving the in-process adapter's subscription closure
/// returned successfully. This non-serializable object retains the live signal
/// subscription; its constructor is private.
#[derive(Debug, PartialEq, Eq)]
pub struct SubscribedStart<S> {
    intent: StartIntent,
    subscription: S,
}

impl<S> SubscribedStart<S> {
    pub fn unit_name(&self) -> &str {
        self.intent.unit_name()
    }

    pub fn transaction_id(&self) -> &str {
        self.intent.transaction_id()
    }

    pub fn attempt_id(&self) -> &str {
        self.intent.attempt_id()
    }

    /// Submit exactly one start request after the subscription stage. Any
    /// transport failure should be represented as Unknown and never retried
    /// here. The live subscription is carried forward in SubmittedStart.
    pub(crate) async fn submit_start<F, Fut>(self, submit: F) -> SubmittedStart<S>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = ManagerStartReply>,
    {
        let reply = submit(self.intent.unit_name.clone()).await;
        SubmittedStart {
            evidence: SystemdStartEvidence {
                transaction_id: self.intent.transaction_id,
                attempt_id: self.intent.attempt_id,
                purpose: self.intent.purpose,
                unit_name: self.intent.unit_name,
                reply,
            },
            subscription: self.subscription,
        }
    }

    #[cfg(test)]
    fn record_reply(self, reply: ManagerStartReply) -> Result<SubmittedStart<S>, String> {
        validate_start_reply(&reply)?;
        Ok(SubmittedStart {
            evidence: SystemdStartEvidence {
                transaction_id: self.intent.transaction_id,
                attempt_id: self.intent.attempt_id,
                purpose: self.intent.purpose,
                unit_name: self.intent.unit_name,
                reply,
            },
            subscription: self.subscription,
        })
    }
}

/// A direct StartUnit reply and its live subscription. Before observing any
/// JobRemoved signal, the caller must durably publish the reply evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct SubmittedStart<S> {
    evidence: SystemdStartEvidence,
    subscription: S,
}

impl<S> SubmittedStart<S> {
    pub fn evidence(&self) -> &SystemdStartEvidence {
        &self.evidence
    }

    pub async fn persist_before_observing<E, F, Fut>(
        self,
        persist: F,
    ) -> Result<PersistedStart<S>, StartEvidencePersistenceFailure<S, E>>
    where
        F: FnOnce(SystemdStartEvidence) -> Fut,
        Fut: std::future::Future<Output = Result<(), E>>,
    {
        let Self { evidence, subscription } = self;
        match persist(evidence.clone()).await {
            Ok(()) => Ok(PersistedStart { evidence, subscription }),
            Err(source) => Err(StartEvidencePersistenceFailure {
                attempt: Self { evidence, subscription },
                source,
            }),
        }
    }
}

/// The only typestate that permits signal observation: StartUnit reply
/// evidence has been handed to a persistence callback and it succeeded.
#[derive(Debug, PartialEq, Eq)]
pub struct PersistedStart<S> {
    evidence: SystemdStartEvidence,
    subscription: S,
}

impl<S> PersistedStart<S> {
    pub fn evidence(&self) -> &SystemdStartEvidence {
        &self.evidence
    }

    pub(crate) fn into_parts(self) -> (SystemdStartEvidence, S) {
        (self.evidence, self.subscription)
    }
}

/// A failed evidence write after StartUnit. The attempt and signal stream are
/// retained so the caller can retry persistence without repeating StartUnit.
#[derive(Debug)]
pub struct StartEvidencePersistenceFailure<S, E> {
    pub attempt: SubmittedStart<S>,
    pub source: E,
}

/// The method-level result of asking systemd to enqueue a unit start.
///
/// Unknown is important: a dropped D-Bus connection after the request does
/// not distinguish "request never arrived" from "job enqueued, reply lost".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ManagerStartReply {
    Enqueued {
        /// The actual value returned by systemd StartUnit(): an object path.
        job_object_path: String,
    },
    Rejected {
        error_name: String,
    },
    Unknown,
}

/// Durable fields bound to the exact request and direct manager reply.
/// This record is not a runtime capability and proves neither signal ordering
/// nor process exit or the intended NixOS post-state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdStartEvidence {
    pub transaction_id: String,
    pub attempt_id: String,
    pub purpose: TransactionWorkerPurpose,
    pub unit_name: String,
    pub reply: ManagerStartReply,
}

fn validate_start_reply(reply: &ManagerStartReply) -> Result<(), String> {
    match reply {
        ManagerStartReply::Unknown => Ok(()),
        ManagerStartReply::Rejected { error_name } if error_name.trim().is_empty() => {
            Err("manager rejection is missing its D-Bus error name".into())
        }
        ManagerStartReply::Rejected { .. } => Ok(()),
        ManagerStartReply::Enqueued { job_object_path } => {
            job_id_from_object_path(job_object_path)?;
            Ok(())
        }
    }
}

/// The result field documented by systemd's JobRemoved signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobRemovedResult {
    Done,
    Canceled,
    Timeout,
    Failed,
    Dependency,
    Skipped,
    /// An unrecognized future manager result. Never interpreted as success.
    Unknown,
}

/// A single observed JobRemoved signal. The D-Bus adapter must preserve the
/// job ID, object path, unit name and result from the same signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRemovedEvidence {
    pub job_id: u32,
    pub job_object_path: String,
    pub unit_name: String,
    pub result: JobRemovedResult,
}

/// Correlation is deliberately not named "transaction success": even a
/// completed systemd start job does not prove process exit or desired NixOS
/// state. Later evidence gates must verify those independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartJobCorrelation {
    MatchedStartJobCompleted,
    MatchedStartJobFailed { result: JobRemovedResult },
    UnrelatedSignal,
    HoldForReconciliation { reason: String },
    RejectedEvidence { reason: String },
    ManagerRejected { error_name: String },
}

/// Classification of the method-level StartUnit response. This is useful
/// before any JobRemoved signal exists: a definite rejection is a rejection,
/// while a lost reply remains ambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartReplyDisposition {
    Enqueued { job_id: u32, job_object_path: String },
    ManagerRejected { error_name: String },
    Ambiguous,
}

/// Validate the start intent and classify the direct manager response without
/// requiring a fabricated JobRemoved event.
pub fn classify_start_reply(
    start: &SystemdStartEvidence,
) -> Result<StartReplyDisposition, String> {
    let expected_unit = canonical_attempt_unit_name(
        &start.transaction_id,
        &start.attempt_id,
        start.purpose,
    )?;
    if start.unit_name != expected_unit {
        return Err("start evidence unit name is not derived from its transaction/attempt identity".into());
    }
    validate_start_reply(&start.reply)?;

    match &start.reply {
        ManagerStartReply::Unknown => Ok(StartReplyDisposition::Ambiguous),
        ManagerStartReply::Rejected { error_name } => Ok(StartReplyDisposition::ManagerRejected {
            error_name: error_name.clone(),
        }),
        ManagerStartReply::Enqueued { job_object_path } => {
            let job_id = job_id_from_object_path(job_object_path)?;
            Ok(StartReplyDisposition::Enqueued {
                job_id,
                job_object_path: job_object_path.clone(),
            })
        },
    }
}

/// Correlate one event with one exact StartUnit request.
///
/// Rules:
/// - the signal subscription must be established before the call;
/// - the requested unit is derived from transaction/attempt/purpose;
/// - StartUnit's returned job ID and object path must both match JobRemoved;
/// - a different job is ignored only when it cannot concern the expected unit;
/// - matching the exact job still reports only the manager's job result.
pub fn correlate_job_removed(
    start: &SystemdStartEvidence,
    signal: &JobRemovedEvidence,
) -> StartJobCorrelation {
    let reply = match classify_start_reply(start) {
        Ok(reply) => reply,
        Err(reason) => return StartJobCorrelation::RejectedEvidence { reason },
    };
    let (expected_job_id, expected_job_path) = match reply {
        StartReplyDisposition::Ambiguous => {
            return StartJobCorrelation::HoldForReconciliation {
                reason: "StartUnit reply is unknown; do not infer submission or retry the mutation".into(),
            };
        }
        StartReplyDisposition::ManagerRejected { error_name } => {
            return StartJobCorrelation::ManagerRejected { error_name };
        }
        StartReplyDisposition::Enqueued { job_id, job_object_path } => {
            (job_id, job_object_path)
        }
    };

    if signal.job_id == 0 || !valid_job_object_path(&signal.job_object_path) {
        return StartJobCorrelation::RejectedEvidence {
            reason: "JobRemoved evidence has an invalid job ID or object path".into(),
        };
    }
    if job_id_from_object_path(&signal.job_object_path).ok() != Some(signal.job_id) {
        return StartJobCorrelation::HoldForReconciliation {
            reason: "JobRemoved numeric ID conflicts with the ID encoded in its object path".into(),
        };
    }
    if signal.unit_name.trim().is_empty() || signal.unit_name.chars().any(char::is_control) {
        return StartJobCorrelation::RejectedEvidence {
            reason: "JobRemoved evidence has an invalid unit name".into(),
        };
    }

    if signal.job_id != expected_job_id || signal.job_object_path != expected_job_path {
        if signal.job_id == expected_job_id
            || signal.unit_name == start.unit_name
            || signal.job_object_path == expected_job_path
        {
            return StartJobCorrelation::HoldForReconciliation {
                reason: "JobRemoved shares the expected job ID, unit, or object path but conflicts with the acknowledged job identity".into(),
            };
        }
        return StartJobCorrelation::UnrelatedSignal;
    }

    if signal.unit_name != start.unit_name {
        return StartJobCorrelation::HoldForReconciliation {
            reason: "acknowledged job identity was reported for a different unit name".into(),
        };
    }

    match signal.result {
        JobRemovedResult::Done => StartJobCorrelation::MatchedStartJobCompleted,
        result => StartJobCorrelation::MatchedStartJobFailed { result },
    }
}

fn job_id_from_object_path(path: &str) -> Result<u32, String> {
    let Some(suffix) = path.strip_prefix(JOB_OBJECT_PATH_PREFIX) else {
        return Err("systemd job object path has the wrong prefix".into());
    };
    if suffix.is_empty() || suffix.contains('/') {
        return Err("systemd job object path has an invalid suffix".into());
    }
    let job_id = suffix
        .parse::<u32>()
        .map_err(|_| "systemd job object path does not end in a numeric job ID".to_string())?;
    if job_id == 0 || suffix != job_id.to_string() {
        return Err("systemd job object path has a non-canonical or zero job ID".into());
    }
    Ok(job_id)
}

fn valid_job_object_path(path: &str) -> bool {
    job_id_from_object_path(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn start(reply: ManagerStartReply) -> SystemdStartEvidence {
        let transaction_id = "tx-7f3c".to_owned();
        let attempt_id = "attempt-0004".to_owned();
        SystemdStartEvidence {
            unit_name: canonical_attempt_unit_name(
                &transaction_id,
                &attempt_id,
                TransactionWorkerPurpose::Activation,
            )
            .unwrap(),
            transaction_id,
            attempt_id,
            purpose: TransactionWorkerPurpose::Activation,
            reply,
        }
    }

    fn enqueued_start() -> SystemdStartEvidence {
        start(ManagerStartReply::Enqueued {
            job_object_path: "/org/freedesktop/systemd1/job/41".into(),
        })
    }

    fn signal(result: JobRemovedResult) -> JobRemovedEvidence {
        JobRemovedEvidence {
            job_id: 41,
            job_object_path: "/org/freedesktop/systemd1/job/41".into(),
            unit_name: canonical_attempt_unit_name(
                "tx-7f3c",
                "attempt-0004",
                TransactionWorkerPurpose::Activation,
            )
            .unwrap(),
            result,
        }
    }

    #[test]
    fn unit_name_is_stable_and_bound_to_all_attempt_identity_fields() {
        let expected = canonical_attempt_unit_name(
            "tx-7f3c",
            "attempt-0004",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();
        assert_eq!(
            expected,
            canonical_attempt_unit_name(
                "tx-7f3c",
                "attempt-0004",
                TransactionWorkerPurpose::Activation,
            )
            .unwrap()
        );
        assert_ne!(
            expected,
            canonical_attempt_unit_name(
                "tx-7f3c",
                "attempt-0005",
                TransactionWorkerPurpose::Activation,
            )
            .unwrap()
        );
        assert_ne!(
            expected,
            canonical_attempt_unit_name(
                "tx-7f3c",
                "attempt-0004",
                TransactionWorkerPurpose::RecoveryActivation,
            )
            .unwrap()
        );
        assert!(canonical_attempt_unit_name("", "attempt", TransactionWorkerPurpose::Activation).is_err());
        assert!(canonical_attempt_unit_name("tx", " \t ", TransactionWorkerPurpose::Activation).is_err());
        assert!(canonical_attempt_unit_name("tx\nother", "attempt", TransactionWorkerPurpose::Activation).is_err());
    }

    #[test]
    fn only_the_exact_acknowledged_job_and_unit_match() {
        let start = enqueued_start();
        assert_eq!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::MatchedStartJobCompleted
        );

        let mut other_job = signal(JobRemovedResult::Done);
        other_job.job_id += 1;
        other_job.job_object_path = "/org/freedesktop/systemd1/job/42".into();
        other_job.unit_name = "unrelated.service".into();
        assert_eq!(
            correlate_job_removed(&start, &other_job),
            StartJobCorrelation::UnrelatedSignal
        );

        let mut same_unit_wrong_job = other_job;
        same_unit_wrong_job.unit_name = start.unit_name.clone();
        assert!(matches!(
            correlate_job_removed(&start, &same_unit_wrong_job),
            StartJobCorrelation::HoldForReconciliation { .. }
        ));

        let mut same_id_wrong_path = signal(JobRemovedResult::Done);
        same_id_wrong_path.job_object_path = "/org/freedesktop/systemd1/job/42".into();
        same_id_wrong_path.unit_name = "unrelated.service".into();
        assert!(matches!(
            correlate_job_removed(&start, &same_id_wrong_path),
            StartJobCorrelation::HoldForReconciliation { .. }
        ));
    }

    #[test]
    fn every_non_done_job_result_is_not_success() {
        let start = enqueued_start();
        for result in [
            JobRemovedResult::Canceled,
            JobRemovedResult::Timeout,
            JobRemovedResult::Failed,
            JobRemovedResult::Dependency,
            JobRemovedResult::Skipped,
        ] {
            assert_eq!(
                correlate_job_removed(&start, &signal(result)),
                StartJobCorrelation::MatchedStartJobFailed { result }
            );
        }
    }

    #[test]
    fn a_lost_start_reply_stays_ambiguous_even_if_a_signal_arrives() {
        let start = start(ManagerStartReply::Unknown);
        assert!(matches!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::HoldForReconciliation { .. }
        ));
    }

    #[test]
    fn start_intent_derives_and_freezes_the_expected_unit_identity() {
        let intent = StartIntent::new(
            "tx-7f3c",
            "attempt-0004",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();
        assert_eq!(intent.unit_name(), canonical_attempt_unit_name(
            intent.transaction_id(),
            intent.attempt_id(),
            intent.purpose(),
        ).unwrap());
        assert_eq!(intent.unit_name(), enqueued_start().unit_name);
    }

    #[cfg(feature = "native")]
    #[tokio::test]
    async fn failed_prelaunch_persistence_does_not_produce_a_prepared_intent() {
        let intent = StartIntent::new(
            "tx-7f3c",
            "attempt-0004",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();
        let result = intent
            .persist_before_submission(|_evidence| async {
                Err::<(), _>("injected journal write failure")
            })
            .await;
        assert!(result.is_err());
    }

    #[cfg(feature = "native")]
    #[tokio::test]
    async fn failed_reply_persistence_retains_attempt_without_replaying_start() {
        let intent = StartIntent::new(
            "tx-7f3c",
            "attempt-0004",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();
        let prepared = intent
            .persist_before_submission(|_evidence| async { Ok::<(), ()>(()) })
            .await
            .unwrap();
        let subscribed = prepared
            .subscribe_before_start(|| async { Ok::<(), ()>(()) })
            .await
            .unwrap();
        let submitted = subscribed.record_reply(ManagerStartReply::Unknown).unwrap();
        let failure = submitted
            .persist_before_observing(|evidence| async move {
                assert_eq!(evidence.reply, ManagerStartReply::Unknown);
                Err::<(), _>("injected reply journal failure")
            })
            .await
            .unwrap_err();
        assert_eq!(failure.attempt.evidence().reply, ManagerStartReply::Unknown);
        assert_eq!(failure.attempt.subscription, ());
    }

    #[cfg(feature = "native")]
    #[tokio::test]
    async fn failed_subscription_does_not_produce_a_subscribed_start() {
        let intent = StartIntent::new(
            "tx-7f3c",
            "attempt-0004",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();
        let prepared = intent
            .persist_before_submission(|_evidence| async { Ok::<(), ()>(()) })
            .await
            .unwrap();
        let result = prepared
            .subscribe_before_start(|| async { Err::<(), _>("injected subscription failure") })
            .await;
        assert!(result.is_err());
    }

    #[cfg(feature = "native")]
    #[tokio::test]
    async fn successful_subscription_is_required_before_reply_can_be_recorded() {
        let intent = StartIntent::new(
            "tx-7f3c",
            "attempt-0004",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();
        let prepared = intent
            .persist_before_submission(|evidence| async move {
                assert_eq!(evidence.transaction_id, "tx-7f3c");
                assert_eq!(evidence.attempt_id, "attempt-0004");
                Ok::<(), ()>(())
            })
            .await
            .unwrap();
        let mut subscription_completed = false;
        let subscribed = prepared
            .subscribe_before_start(|| async {
                subscription_completed = true;
                Ok::<_, ()>(())
            })
            .await
            .unwrap();
        assert!(subscription_completed);
        assert!(subscribed.unit_name().starts_with("nixward-transaction@"));

        let submitted = subscribed.record_reply(ManagerStartReply::Unknown).unwrap();
        assert_eq!(
            classify_start_reply(submitted.evidence()),
            Ok(StartReplyDisposition::Ambiguous)
        );
        let persisted = submitted
            .persist_before_observing(|evidence| async move {
                assert_eq!(evidence.reply, ManagerStartReply::Unknown);
                Ok::<(), ()>(())
            })
            .await
            .unwrap();
        assert_eq!(persisted.evidence().reply, ManagerStartReply::Unknown);
        let (evidence, subscription) = persisted.into_parts();
        assert_eq!(classify_start_reply(&evidence), Ok(StartReplyDisposition::Ambiguous));
        assert_eq!(subscription, ());
    }

    #[cfg(feature = "native")]
    #[tokio::test]
    async fn subscribed_capability_rejects_malformed_manager_reply() {
        let intent = StartIntent::new(
            "tx-7f3c",
            "attempt-0004",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();
        let prepared = intent
            .persist_before_submission(|_evidence| async { Ok::<(), ()>(()) })
            .await
            .unwrap();
        let subscribed = prepared
            .subscribe_before_start(|| async { Ok::<(), ()>(()) })
            .await
            .unwrap();
        assert!(subscribed
            .record_reply(ManagerStartReply::Enqueued {
                job_object_path: "/org/freedesktop/systemd1/job/0".into(),
            })
            .is_err());
        // Malformed manager errors are rejected before a durable record exists.
        assert!(validate_start_reply(&ManagerStartReply::Rejected {
            error_name: "  ".into(),
        })
        .is_err());
    }

    #[test]
    fn identity_mismatch_and_malformed_paths_fail_closed() {
        let mut start = enqueued_start();
        start.transaction_id = "different-transaction".into();
        assert!(matches!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::RejectedEvidence { .. }
        ));

        let start = enqueued_start();
        let mut malformed = signal(JobRemovedResult::Done);
        malformed.job_object_path = "/org/freedesktop/systemd1/unit/nixward".into();
        assert!(matches!(
            correlate_job_removed(&start, &malformed),
            StartJobCorrelation::RejectedEvidence { .. }
        ));

        let mut conflicting = signal(JobRemovedResult::Done);
        conflicting.unit_name = "other.service".into();
        assert!(matches!(
            correlate_job_removed(&start, &conflicting),
            StartJobCorrelation::HoldForReconciliation { .. }
        ));
    }

    #[test]
    fn start_reply_can_be_classified_without_fabricating_a_job_signal() {
        assert_eq!(
            classify_start_reply(&enqueued_start()),
            Ok(StartReplyDisposition::Enqueued {
                job_id: 41,
                job_object_path: "/org/freedesktop/systemd1/job/41".into(),
            })
        );
        assert_eq!(
            classify_start_reply(&start(ManagerStartReply::Unknown)),
            Ok(StartReplyDisposition::Ambiguous)
        );
        assert_eq!(
            classify_start_reply(&start(ManagerStartReply::Rejected {
                error_name: "org.freedesktop.systemd1.UnitMasked".into(),
            })),
            Ok(StartReplyDisposition::ManagerRejected {
                error_name: "org.freedesktop.systemd1.UnitMasked".into(),
            })
        );
    }

    #[test]
    fn known_manager_rejection_is_not_a_success_signal() {
        let start = start(ManagerStartReply::Rejected {
            error_name: "org.freedesktop.systemd1.UnitMasked".into(),
        });
        assert_eq!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::ManagerRejected {
                error_name: "org.freedesktop.systemd1.UnitMasked".into(),
            }
        );
    }

    #[test]
    fn acknowledgement_with_zero_job_id_is_rejected() {
        let start = start(ManagerStartReply::Enqueued {
            job_object_path: "/org/freedesktop/systemd1/job/0".into(),
        });
        assert!(matches!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::RejectedEvidence { .. }
        ));
    }

    #[test]
    fn startunit_object_path_is_the_reply_source_for_job_identity() {
        assert_eq!(
            job_id_from_object_path("/org/freedesktop/systemd1/job/41"),
            Ok(41)
        );
        assert!(job_id_from_object_path("/org/freedesktop/systemd1/job/0").is_err());
        assert!(job_id_from_object_path("/org/freedesktop/systemd1/job/041").is_err());
        assert!(job_id_from_object_path("/org/freedesktop/systemd1/job/not-a-number").is_err());
        assert!(job_id_from_object_path("/org/freedesktop/systemd1/unit/example.service").is_err());

        let mut inconsistent_signal = signal(JobRemovedResult::Done);
        inconsistent_signal.job_id = 42;
        assert!(matches!(
            correlate_job_removed(&enqueued_start(), &inconsistent_signal),
            StartJobCorrelation::HoldForReconciliation { .. }
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// A single-field mismatch must not be downgraded to an unrelated event:
        /// each partial identity collision is suspicious and therefore held.
        #[test]
        fn one_field_job_identity_mutation_never_completes(field in 0u8..3) {
            let start = enqueued_start();
            let mut event = signal(JobRemovedResult::Done);
            match field {
                0 => event.job_id += 1,
                1 => event.job_object_path = "/org/freedesktop/systemd1/job/42".into(),
                _ => event.unit_name = "unrelated.service".into(),
            }

            prop_assert!(matches!(
                correlate_job_removed(&start, &event),
                StartJobCorrelation::HoldForReconciliation { .. }
            ));
        }

        /// A lost direct reply is ambiguous irrespective of the later signal's
        /// apparent completion; it never becomes evidence of completed start.
        #[test]
        fn unknown_manager_reply_never_becomes_completed_start(field in 0u8..3) {
            let start = start(ManagerStartReply::Unknown);
            let mut event = signal(JobRemovedResult::Done);
            match field {
                0 => event.job_id += 1,
                1 => event.job_object_path = "/org/freedesktop/systemd1/job/42".into(),
                _ => event.unit_name = "unrelated.service".into(),
            }
            prop_assert!(matches!(
                correlate_job_removed(&start, &event),
                StartJobCorrelation::HoldForReconciliation { .. }
            ));
        }

        /// Only a matched JobRemoved done result can be start-job completion.
        #[test]
        fn every_non_done_job_result_is_non_success(result_code in 0u8..5) {
            let result = match result_code {
                0 => JobRemovedResult::Canceled,
                1 => JobRemovedResult::Timeout,
                2 => JobRemovedResult::Failed,
                3 => JobRemovedResult::Dependency,
                _ => JobRemovedResult::Skipped,
            };
            prop_assert_eq!(
                correlate_job_removed(&enqueued_start(), &signal(result)),
                StartJobCorrelation::MatchedStartJobFailed { result }
            );
        }

        /// Canonical names must be independent of raw IDs and limited to one
        /// unit prefix + exactly 64 lowercase hexadecimal digest characters.
        #[test]
        fn canonical_unit_name_is_bounded_and_safe(
            transaction_id in "[g-z]{1,32}",
            attempt_id in "[g-z]{1,32}"
        ) {
            let name = canonical_attempt_unit_name(
                &transaction_id,
                &attempt_id,
                TransactionWorkerPurpose::Activation
            ).unwrap();
            let prefix = "nixward-transaction@";
            let suffix = ".service";
            prop_assert!(name.starts_with(prefix));
            prop_assert!(name.ends_with(suffix));
            let digest = &name[prefix.len()..name.len() - suffix.len()];
            prop_assert_eq!(digest.len(), 64);
            prop_assert!(digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
            prop_assert!(!digest.contains(transaction_id.as_str()));
            prop_assert!(!digest.contains(attempt_id.as_str()));
        }
    }
}
