// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Pure correlation contract for asynchronous systemd start-job evidence.
//!
//! This module is the pure evidence/correlation layer; the sibling
//! systemd_job_bus adapter performs live zbus I/O but remains crate-private
//! and unqualified. Neither module authorizes host mutation or proves that a
//! worker ran. They prevent a StartUnit acknowledgement, unrelated
//! JobRemoved signal, or lost reply from being treated as transaction success.
//! Production integration still requires the authorized transaction path,
//! durable journal interlocks, worker receipt validation, and fresh host-state
//! verification.

use super::config_transaction::{ActivationWorkerIdentity, ActivationWorkerPurpose};
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

impl From<ActivationWorkerPurpose> for TransactionWorkerPurpose {
    fn from(value: ActivationWorkerPurpose) -> Self {
        match value {
            ActivationWorkerPurpose::ProfileTransition => Self::ProfileTransition,
            ActivationWorkerPurpose::Activation => Self::Activation,
            ActivationWorkerPurpose::RecoveryProfileTransition => Self::RecoveryProfileTransition,
            ActivationWorkerPurpose::RecoveryActivation => Self::RecoveryActivation,
        }
    }
}

impl From<TransactionWorkerPurpose> for ActivationWorkerPurpose {
    fn from(value: TransactionWorkerPurpose) -> Self {
        match value {
            TransactionWorkerPurpose::ProfileTransition => Self::ProfileTransition,
            TransactionWorkerPurpose::Activation => Self::Activation,
            TransactionWorkerPurpose::RecoveryProfileTransition => Self::RecoveryProfileTransition,
            TransactionWorkerPurpose::RecoveryActivation => Self::RecoveryActivation,
        }
    }
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

/// Validate a recovered or deserialized write-ahead intent before it is used
/// to reconcile systemd. Deserializing fields is not proof they bind to the
/// original canonical transaction/attempt unit identity.
pub fn validate_start_intent_evidence(
    evidence: &StartIntentEvidence,
) -> Result<(), String> {
    let expected_unit = canonical_attempt_unit_name(
        &evidence.transaction_id,
        &evidence.attempt_id,
        evidence.purpose,
    )?;
    if evidence.unit_name != expected_unit {
        return Err(
            "start intent unit name is not derived from its transaction/attempt identity".into(),
        );
    }
    Ok(())
}

/// Validate recovered intent against an identity obtained independently from
/// the already-validated transaction/authorization context.
///
/// The expected tuple must not be reconstructed from `evidence`: doing so
/// would let a coherently rewritten transaction/attempt/purpose/unit tuple
/// validate itself. This check establishes identity binding, not journal
/// integrity or authorization; callers must validate those sources first.
pub fn validate_start_intent_evidence_against(
    evidence: &StartIntentEvidence,
    expected_transaction_id: &str,
    expected_attempt_id: &str,
    expected_purpose: TransactionWorkerPurpose,
) -> Result<(), String> {
    validate_start_intent_evidence(evidence)?;
    let expected_unit = canonical_attempt_unit_name(
        expected_transaction_id,
        expected_attempt_id,
        expected_purpose,
    )?;
    if evidence.transaction_id != expected_transaction_id
        || evidence.attempt_id != expected_attempt_id
        || evidence.purpose != expected_purpose
        || evidence.unit_name != expected_unit
    {
        return Err(
            "recovered start intent does not match the independently validated transaction/attempt identity".into(),
        );
    }
    Ok(())
}

/// Durable binding between the journal-owned start attempt and one exact
/// systemd service invocation observed through GetUnitByPIDFD.
///
/// The invocation ID is stored as 32 lowercase hexadecimal characters (the
/// canonical encoding of systemd's 16-byte D-Bus `ay` value). A PID alone is
/// not sufficient: this record must be captured while a pidfd for the exact
/// worker is available and correlated with the manager's unit/MainPID data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdWorkerInvocationEvidence {
    pub transaction_id: String,
    pub attempt_id: String,
    pub purpose: TransactionWorkerPurpose,
    pub unit_name: String,
    pub invocation_id: String,
    pub worker_pid: u32,
}

fn encode_systemd_invocation_id(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() != 16 {
        return Err("systemd InvocationID must contain exactly 16 bytes".into());
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err("systemd InvocationID is unset (all-zero value)".into());
    }
    let mut encoded = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| "failed to encode systemd InvocationID".to_string())?;
    }
    Ok(encoded)
}

fn validate_encoded_systemd_invocation_id(value: &str) -> Result<(), String> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "systemd InvocationID must be 32 lowercase hexadecimal characters".into(),
        );
    }
    if value.bytes().all(|byte| byte == b'0') {
        return Err("systemd InvocationID must not be the unset all-zero value".into());
    }
    Ok(())
}

/// Join PIDFD-bound systemd invocation evidence to the repository's
/// existing, fully validated activation worker identity.
///
/// `expected_attempt_id` must come from the independently loaded durable
/// attempt record. The worker identity supplies the authoritative transaction,
/// purpose, PID, boot ID, start time and executable/argv/environment bindings.
/// This function deliberately does not synthesize an attempt ID from either
/// evidence record.
pub fn validate_systemd_worker_invocation_against_activation_identity(
    evidence: &SystemdWorkerInvocationEvidence,
    intent: &StartIntentEvidence,
    expected_attempt_id: &str,
    worker: &ActivationWorkerIdentity,
) -> Result<(), String> {
    worker.validate_identity()?;
    let expected_purpose = TransactionWorkerPurpose::from(worker.purpose);
    validate_start_intent_evidence_against(
        intent,
        &worker.transaction_id,
        expected_attempt_id,
        expected_purpose,
    )?;
    validate_systemd_worker_invocation_evidence_against(
        evidence,
        &worker.transaction_id,
        expected_attempt_id,
        expected_purpose,
        worker.pid,
    )?;
    Ok(())
}

/// Capture the service invocation that owns the exact worker process.
///
/// The caller obtains `pidfd_unit_name` and `pidfd_invocation_id` from
/// Manager.GetUnitByPIDFD(pidfd), then reads `Id`, `InvocationID`, and
/// `MainPID` from the returned unit object. Requiring the two invocation ID
/// observations to agree detects a unit restart/race between those queries.
/// The PIDFD lookup is essential: this function does not treat a PID-only
/// GetUnitByPID result as equivalent evidence.
pub fn capture_systemd_worker_invocation_evidence(
    intent: &StartIntentEvidence,
    expected_transaction_id: &str,
    expected_attempt_id: &str,
    expected_purpose: TransactionWorkerPurpose,
    pidfd_unit_name: &str,
    unit_property_unit_name: &str,
    pidfd_invocation_id: &[u8],
    unit_property_invocation_id: &[u8],
    unit_main_pid: u32,
    expected_worker_pid: u32,
) -> Result<SystemdWorkerInvocationEvidence, String> {
    validate_start_intent_evidence_against(
        intent,
        expected_transaction_id,
        expected_attempt_id,
        expected_purpose,
    )?;
    if expected_worker_pid <= 1 || unit_main_pid != expected_worker_pid {
        return Err(
            "systemd unit MainPID does not match the exact journal-owned worker PID".into(),
        );
    }
    if pidfd_unit_name != intent.unit_name
        || unit_property_unit_name != intent.unit_name
        || pidfd_unit_name != unit_property_unit_name
    {
        return Err(
            "GetUnitByPIDFD unit ID and unit object Id do not both match the canonical attempt unit".into(),
        );
    }
    let pidfd_id = encode_systemd_invocation_id(pidfd_invocation_id)?;
    let property_id = encode_systemd_invocation_id(unit_property_invocation_id)?;
    if pidfd_id != property_id {
        return Err(
            "GetUnitByPIDFD and unit InvocationID property disagree; the unit may have restarted during observation".into(),
        );
    }

    Ok(SystemdWorkerInvocationEvidence {
        transaction_id: intent.transaction_id.clone(),
        attempt_id: intent.attempt_id.clone(),
        purpose: intent.purpose,
        unit_name: intent.unit_name.clone(),
        invocation_id: pidfd_id,
        worker_pid: expected_worker_pid,
    })
}

/// Validate a persisted unit-invocation binding against trusted attempt and
/// worker identities. The expected values must come from the validated
/// transaction journal, not from this evidence record.
pub fn validate_systemd_worker_invocation_evidence_against(
    evidence: &SystemdWorkerInvocationEvidence,
    expected_transaction_id: &str,
    expected_attempt_id: &str,
    expected_purpose: TransactionWorkerPurpose,
    expected_worker_pid: u32,
) -> Result<(), String> {
    let intent = StartIntentEvidence {
        transaction_id: evidence.transaction_id.clone(),
        attempt_id: evidence.attempt_id.clone(),
        purpose: evidence.purpose,
        unit_name: evidence.unit_name.clone(),
    };
    validate_start_intent_evidence_against(
        &intent,
        expected_transaction_id,
        expected_attempt_id,
        expected_purpose,
    )?;
    validate_encoded_systemd_invocation_id(&evidence.invocation_id)?;
    if expected_worker_pid <= 1 || evidence.worker_pid != expected_worker_pid {
        return Err(
            "systemd invocation evidence does not match the independently validated worker PID".into(),
        );
    }
    Ok(())
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
    fn recovered_start_intent_must_bind_transaction_attempt_purpose_and_unit() {
        let intent = StartIntent::new(
            "tx-7f3c",
            "attempt-0004",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();
        let original = intent.journal_evidence();
        assert_eq!(validate_start_intent_evidence(&original), Ok(()));

        let mut changed_transaction = original.clone();
        changed_transaction.transaction_id = "tx-other".into();
        assert!(validate_start_intent_evidence(&changed_transaction).is_err());

        let mut changed_attempt = original.clone();
        changed_attempt.attempt_id = "attempt-other".into();
        assert!(validate_start_intent_evidence(&changed_attempt).is_err());

        let mut changed_unit = original.clone();
        changed_unit.unit_name = "nixward-transaction@forged.service".into();
        assert!(validate_start_intent_evidence(&changed_unit).is_err());

        let mut changed_purpose = original;
        changed_purpose.purpose = TransactionWorkerPurpose::RecoveryActivation;
        assert!(validate_start_intent_evidence(&changed_purpose).is_err());
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
            JobRemovedResult::Unknown,
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
        let journal_evidence = intent.journal_evidence();
        assert_eq!(journal_evidence.unit_name, intent.unit_name());
        assert_eq!(
            journal_evidence.unit_name,
            canonical_attempt_unit_name(
                &journal_evidence.transaction_id,
                &journal_evidence.attempt_id,
                journal_evidence.purpose,
            )
            .unwrap()
        );
    }

    #[cfg(feature = "native")]
    #[tokio::test]
    async fn failed_prelaunch_persistence_does_not_subscribe_or_start() {
        use std::cell::Cell;

        let intent = StartIntent::new(
            "tx-7f3c",
            "attempt-0004",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();
        let subscribe_called = Cell::new(false);
        let start_called = Cell::new(false);
        let result = intent
            .persist_before_submission(|_evidence| async {
                Err::<(), _>("injected journal write failure")
            })
            .await;

        if let Ok(prepared) = result {
            let subscribed = prepared
                .subscribe_before_start(|| async {
                    subscribe_called.set(true);
                    Ok::<(), ()>(())
                })
                .await;
            if let Ok(subscribed) = subscribed {
                let _ = subscribed
                    .submit_start(|_| {
                        start_called.set(true);
                        async { ManagerStartReply::Unknown }
                    })
                    .await;
            }
        }

        assert!(!subscribe_called.get(), "subscription must not be installed before durable intent");
        assert!(!start_called.get(), "StartUnit must not run before durable intent");
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
    async fn failed_subscription_does_not_produce_a_subscribed_start_or_call_start() {
        use std::cell::Cell;

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
        let start_called = Cell::new(false);
        let result = prepared
            .subscribe_before_start(|| async { Err::<(), _>("injected subscription failure") })
            .await;

        if let Ok(subscribed) = result {
            let _ = subscribed
                .submit_start(|_| {
                    start_called.set(true);
                    async { ManagerStartReply::Unknown }
                })
                .await;
        }

        assert!(!start_called.get(), "StartUnit must not run if subscription setup failed");
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

    fn activation_worker_identity_for_invocation_test(
        purpose: ActivationWorkerPurpose,
        pid: u32,
    ) -> ActivationWorkerIdentity {
        let transaction_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let executable = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixward-worker-gate/bin/nixward-worker-gate";
        let payload_executable = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-switch-to-configuration/bin/switch-to-configuration";
        let payload_args = vec!["switch".to_string()];
        let release_challenge_digest = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();
        let mut gate_args = vec![
            "--nixward-worker-gate-v1".to_string(),
            payload_executable.to_string(),
            release_challenge_digest.clone(),
        ];
        gate_args.extend(payload_args.iter().cloned());

        ActivationWorkerIdentity {
            transaction_id: transaction_id.into(),
            purpose,
            pid,
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            start_time_ticks: 42,
            executable: executable.into(),
            process_image: executable.into(),
            argv_digest: super::super::config_transaction::activation_argv_digest(executable, &gate_args),
            environment_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            payload_executable: payload_executable.into(),
            payload_args: payload_args.clone(),
            release_challenge_digest,
            payload_argv_digest: super::super::config_transaction::activation_argv_digest(payload_executable, &payload_args),
        }
    }

    #[test]
    fn worker_purpose_mapping_is_exhaustive_and_bidirectional() {
        for (activation, systemd) in [
            (ActivationWorkerPurpose::ProfileTransition, TransactionWorkerPurpose::ProfileTransition),
            (ActivationWorkerPurpose::Activation, TransactionWorkerPurpose::Activation),
            (ActivationWorkerPurpose::RecoveryProfileTransition, TransactionWorkerPurpose::RecoveryProfileTransition),
            (ActivationWorkerPurpose::RecoveryActivation, TransactionWorkerPurpose::RecoveryActivation),
        ] {
            assert_eq!(TransactionWorkerPurpose::from(activation), systemd);
            assert_eq!(ActivationWorkerPurpose::from(systemd), activation);
        }
    }

    #[test]
    fn systemd_invocation_evidence_joins_the_existing_activation_worker_identity() {
        let worker = activation_worker_identity_for_invocation_test(
            ActivationWorkerPurpose::Activation,
            4242,
        );
        worker.validate_identity().unwrap();
        let expected_purpose = TransactionWorkerPurpose::from(worker.purpose);
        let intent = StartIntent::new(
            worker.transaction_id.clone(),
            "attempt-joined-0001",
            expected_purpose,
        )
        .unwrap()
        .journal_evidence();
        let invocation_id = [0x5au8; 16];
        let evidence = capture_systemd_worker_invocation_evidence(
            &intent,
            &worker.transaction_id,
            "attempt-joined-0001",
            expected_purpose,
            &intent.unit_name,
            &intent.unit_name,
            &invocation_id,
            &invocation_id,
            worker.pid,
            worker.pid,
        )
        .unwrap();

        assert_eq!(
            validate_systemd_worker_invocation_against_activation_identity(
                &evidence,
                &intent,
                "attempt-joined-0001",
                &worker,
            ),
            Ok(())
        );
    }

    #[test]
    fn systemd_invocation_join_rejects_process_or_purpose_drift() {
        let worker = activation_worker_identity_for_invocation_test(
            ActivationWorkerPurpose::Activation,
            4242,
        );
        let expected_purpose = TransactionWorkerPurpose::from(worker.purpose);
        let intent = StartIntent::new(
            worker.transaction_id.clone(),
            "attempt-joined-0002",
            expected_purpose,
        )
        .unwrap()
        .journal_evidence();
        let invocation_id = [0x6bu8; 16];
        let evidence = capture_systemd_worker_invocation_evidence(
            &intent,
            &worker.transaction_id,
            "attempt-joined-0002",
            expected_purpose,
            &intent.unit_name,
            &intent.unit_name,
            &invocation_id,
            &invocation_id,
            worker.pid,
            worker.pid,
        )
        .unwrap();

        let mut changed_pid = worker.clone();
        changed_pid.pid += 1;
        assert!(validate_systemd_worker_invocation_against_activation_identity(
            &evidence,
            &intent,
            "attempt-joined-0002",
            &changed_pid,
        )
        .is_err());

        let mut changed_purpose = worker.clone();
        changed_purpose.purpose = ActivationWorkerPurpose::RecoveryActivation;
        assert!(validate_systemd_worker_invocation_against_activation_identity(
            &evidence,
            &intent,
            "attempt-joined-0002",
            &changed_purpose,
        )
        .is_err());

        assert!(validate_systemd_worker_invocation_against_activation_identity(
            &evidence,
            &intent,
            "attempt-joined-foreign",
            &worker,
        )
        .is_err());
    }

    #[test]
    fn pidfd_systemd_invocation_binding_requires_exact_unit_main_pid_and_matching_ids() {
        let intent = StartIntent::new(
            "tx-invocation",
            "attempt-invocation",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap()
        .journal_evidence();
        let invocation_id = [0x5au8; 16];
        let evidence = capture_systemd_worker_invocation_evidence(
            &intent,
            &intent.transaction_id,
            &intent.attempt_id,
            intent.purpose,
            &intent.unit_name,
            &intent.unit_name,
            &invocation_id,
            &invocation_id,
            4242,
            4242,
        )
        .unwrap();

        assert_eq!(evidence.invocation_id, "5a".repeat(16));
        assert_eq!(
            validate_systemd_worker_invocation_evidence_against(
                &evidence,
                &intent.transaction_id,
                &intent.attempt_id,
                intent.purpose,
                4242,
            ),
            Ok(())
        );
    }

    #[test]
    fn pidfd_systemd_invocation_binding_rejects_unit_pid_and_id_conflicts() {
        let intent = StartIntent::new(
            "tx-invocation-conflict",
            "attempt-invocation-conflict",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap()
        .journal_evidence();
        let expected = [0x5au8; 16];
        let different = [0x6bu8; 16];

        assert!(capture_systemd_worker_invocation_evidence(
            &intent,
            &intent.transaction_id,
            &intent.attempt_id,
            intent.purpose,
            "foreign.service",
            &intent.unit_name,
            &expected,
            &expected,
            4242,
            4242,
        )
        .is_err());
        assert!(capture_systemd_worker_invocation_evidence(
            &intent,
            &intent.transaction_id,
            &intent.attempt_id,
            intent.purpose,
            &intent.unit_name,
            "foreign.service",
            &expected,
            &expected,
            4242,
            4242,
        )
        .is_err());
        assert!(capture_systemd_worker_invocation_evidence(
            &intent,
            &intent.transaction_id,
            &intent.attempt_id,
            intent.purpose,
            &intent.unit_name,
            &intent.unit_name,
            &expected,
            &expected,
            4243,
            4242,
        )
        .is_err());
        assert!(capture_systemd_worker_invocation_evidence(
            &intent,
            &intent.transaction_id,
            &intent.attempt_id,
            intent.purpose,
            &intent.unit_name,
            &intent.unit_name,
            &expected,
            &different,
            4242,
            4242,
        )
        .is_err());
        assert!(capture_systemd_worker_invocation_evidence(
            &intent,
            &intent.transaction_id,
            &intent.attempt_id,
            intent.purpose,
            &intent.unit_name,
            &intent.unit_name,
            &[0u8; 16],
            &[0u8; 16],
            4242,
            4242,
        )
        .is_err());
        assert!(capture_systemd_worker_invocation_evidence(
            &intent,
            "foreign-transaction",
            &intent.attempt_id,
            intent.purpose,
            &intent.unit_name,
            &intent.unit_name,
            &expected,
            &expected,
            4242,
            4242,
        )
        .is_err());
    }

    #[test]
    fn persisted_systemd_invocation_evidence_rejects_malformed_or_rewritten_fields() {
        let intent = StartIntent::new(
            "tx-persisted-invocation",
            "attempt-persisted-invocation",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap()
        .journal_evidence();
        let invocation_id = [0x7cu8; 16];
        let original = capture_systemd_worker_invocation_evidence(
            &intent,
            &intent.transaction_id,
            &intent.attempt_id,
            intent.purpose,
            &intent.unit_name,
            &intent.unit_name,
            &invocation_id,
            &invocation_id,
            5151,
            5151,
        )
        .unwrap();

        let mut changed_invocation = original.clone();
        changed_invocation.invocation_id = "not-an-invocation-id".into();
        assert!(validate_systemd_worker_invocation_evidence_against(
            &changed_invocation,
            &intent.transaction_id,
            &intent.attempt_id,
            intent.purpose,
            5151,
        )
        .is_err());

        let mut changed_worker = original.clone();
        changed_worker.worker_pid = 6161;
        assert!(validate_systemd_worker_invocation_evidence_against(
            &changed_worker,
            &intent.transaction_id,
            &intent.attempt_id,
            intent.purpose,
            5151,
        )
        .is_err());

        let mut changed_attempt = original;
        changed_attempt.attempt_id.push_str("-foreign");
        assert!(validate_systemd_worker_invocation_evidence_against(
            &changed_attempt,
            &intent.transaction_id,
            &intent.attempt_id,
            intent.purpose,
            5151,
        )
        .is_err());
    }

    #[test]
    fn coherent_rewrite_of_recovered_identity_fails_independent_binding() {
        let trusted = StartIntent::new(
            "tx-trusted",
            "attempt-trusted",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap()
        .journal_evidence();

        let rewritten = StartIntent::new(
            "tx-foreign",
            "attempt-foreign",
            TransactionWorkerPurpose::RecoveryActivation,
        )
        .unwrap()
        .journal_evidence();

        // The rewritten tuple is internally canonical and therefore passes
        // the structural check. It must not pass the independent anchor check.
        assert_eq!(validate_start_intent_evidence(&rewritten), Ok(()));
        assert!(validate_start_intent_evidence_against(
            &rewritten,
            &trusted.transaction_id,
            &trusted.attempt_id,
            trusted.purpose,
        )
        .is_err());
        assert!(validate_start_intent_evidence_against(
            &trusted,
            &trusted.transaction_id,
            &trusted.attempt_id,
            trusted.purpose,
        )
        .is_ok());
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
        /// Unknown/future result strings are deliberately part of this property.
        #[test]
        fn every_non_done_job_result_is_non_success(result_code in 0u8..6) {
            let result = match result_code {
                0 => JobRemovedResult::Canceled,
                1 => JobRemovedResult::Timeout,
                2 => JobRemovedResult::Failed,
                3 => JobRemovedResult::Dependency,
                4 => JobRemovedResult::Skipped,
                _ => JobRemovedResult::Unknown,
            };
            prop_assert_eq!(
                correlate_job_removed(&enqueued_start(), &signal(result)),
                StartJobCorrelation::MatchedStartJobFailed { result }
            );
        }

        /// Every serialized/recovered start intent must preserve the same
        /// canonical transaction/attempt/purpose binding.
        #[test]
        fn recovered_intent_rejects_single_field_identity_mutations(
            transaction_id in "[a-z0-9_-]{1,32}",
            attempt_id in "[a-z0-9_-]{1,32}",
            mutation in 0u8..4
        ) {
            let intent = StartIntent::new(
                &transaction_id,
                &attempt_id,
                TransactionWorkerPurpose::Activation,
            ).unwrap();
            let original = intent.journal_evidence();
            prop_assert_eq!(validate_start_intent_evidence(&original), Ok(()));

            let mut changed = original.clone();
            match mutation {
                0 => changed.transaction_id.push_str("-changed"),
                1 => changed.attempt_id.push_str("-changed"),
                2 => changed.unit_name.push_str("-changed"),
                _ => changed.purpose = TransactionWorkerPurpose::RecoveryActivation,
            }
            prop_assert!(validate_start_intent_evidence(&changed).is_err());
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
        
        /// A canonical, coherently rewritten tuple must still match an
        /// independently sourced transaction/attempt/purpose anchor.
        #[test]
        fn coherent_recovered_identity_rewrite_fails_anchor_binding(
            transaction_id in "[a-z0-9_-]{1,32}",
            attempt_id in "[a-z0-9_-]{1,32}"
        ) {
            let trusted = StartIntent::new(
                &transaction_id,
                &attempt_id,
                TransactionWorkerPurpose::Activation
            ).unwrap().journal_evidence();
            let rewritten = StartIntent::new(
                format!("{transaction_id}-foreign"),
                format!("{attempt_id}-foreign"),
                TransactionWorkerPurpose::RecoveryActivation
            ).unwrap().journal_evidence();

            prop_assert_eq!(validate_start_intent_evidence(&rewritten), Ok(()));
            prop_assert!(validate_start_intent_evidence_against(
                &rewritten,
                &trusted.transaction_id,
                &trusted.attempt_id,
                trusted.purpose
            ).is_err());
        }

        
        /// PIDFD-resolved unit and both manager invocation observations must
        /// agree with the canonical attempt and exact worker PID.
        #[test]
        fn pidfd_invocation_binding_rejects_single_field_conflicts(
            transaction_id in "[a-z0-9_-]{1,32}",
            attempt_id in "[a-z0-9_-]{1,32}",
            mutation in 0u8..5
        ) {
            let intent = StartIntent::new(
                &transaction_id,
                &attempt_id,
                TransactionWorkerPurpose::Activation
            ).unwrap().journal_evidence();
            let invocation_id = [0x5au8; 16];
            let pidfd_unit_name = if mutation == 0 {
                "foreign.service"
            } else {
                intent.unit_name.as_str()
            };
            let unit_property_unit_name = if mutation == 4 {
                "foreign.service"
            } else {
                intent.unit_name.as_str()
            };
            let unit_main_pid = if mutation == 1 { 9002 } else { 9001 };
            let property_invocation_id = if mutation == 2 {
                [0x6bu8; 16]
            } else {
                invocation_id
            };
            let expected_transaction_id = if mutation == 3 {
                format!("{transaction_id}-foreign")
            } else {
                transaction_id.clone()
            };

            prop_assert!(capture_systemd_worker_invocation_evidence(
                &intent,
                &expected_transaction_id,
                &intent.attempt_id,
                intent.purpose,
                pidfd_unit_name,
                unit_property_unit_name,
                &invocation_id,
                &property_invocation_id,
                unit_main_pid,
                9001
            ).is_err());
        }

    }
}
