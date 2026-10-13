use nixward_network_observation_verifier::{
    hash_canonical_links, hash_raw_artifact, CollectorIdentity, DeclaredScope, Envelope,
    SourceAttempt, SourceFamily, TargetIdentity, VerificationPolicy, ENVELOPE_SCHEMA_ID,
    SUPPORTED_FAMILY,
};
use std::io::{self, Write};

/// Emits a synthetic fixture only. It does not read or collect live network state.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A byte-exact little-endian NLMSG_DONE(status=0), sequence 7, for a valid empty dump.
    let raw: [u8; 20] = [
        20, 0, 0, 0, // nlmsg_len
        3, 0, // NLMSG_DONE
        2, 0, // NLM_F_MULTI
        7, 0, 0, 0, // request sequence
        0, 0, 0, 0, // sender port ID
        0, 0, 0, 0, // successful completion status
    ];
    let envelope = Envelope {
        schema_id: ENVELOPE_SCHEMA_ID.to_owned(),
        schema_version: 1,
        collection_id: "M1A-SYNTHETIC-EMPTY-LINK-DUMP".to_owned(),
        target: TargetIdentity {
            target_id: "synthetic-lab-router".to_owned(),
            boot_id: "synthetic-boot-id".to_owned(),
            network_namespace_inode: 4026533001,
        },
        scope: DeclaredScope {
            required_families: vec![SUPPORTED_FAMILY.to_owned()],
            resource_kinds: vec!["links".to_owned()],
        },
        collector: CollectorIdentity {
            collector_id: "synthetic-fixture-generator-not-a-live-collector".to_owned(),
            build_digest_blake3: hash_raw_artifact(b"nixward-m1a-synthetic-fixture-generator-v1"),
            source_revision: "synthetic-fixture-only-not-a-source-revision".to_owned(),
        },
        policy: VerificationPolicy {
            policy_id: "m1a-rtnetlink-links".to_owned(),
            policy_version: "1".to_owned(),
            max_age_ms: 60_000,
            max_source_window_ns: 10_000,
            max_total_raw_bytes: 1024,
            max_messages_per_attempt: 8,
            max_objects_per_attempt: 8,
            max_retries: 1,
            decision_critical_link_attribute_ids: vec![5, 999],
        },
        captured_at_unix_ms: 1_000_000,
        verification_time_unix_ms: 1_000_500,
        source_families: vec![SourceFamily {
            family: SUPPORTED_FAMILY.to_owned(),
            attempts: vec![SourceAttempt {
                target_id: "synthetic-lab-router".to_owned(),
                boot_id: "synthetic-boot-id".to_owned(),
                network_namespace_inode: 4026533001,
                request_sequence: 7,
                byte_order: "little".to_owned(),
                retry_index: 0,
                started_monotonic_ns: 100,
                ended_monotonic_ns: 200,
                raw_artifact_hex: raw.iter().map(|byte| format!("{byte:02x}")).collect(),
                raw_artifact_blake3: hash_raw_artifact(&raw),
                canonical_semantic_blake3: Some(hash_canonical_links(&[])),
                enobufs_observed: false,
                msg_trunc_observed: false,
                dropped_message_count: 0,
            }],
        }],
    };
    let mut bytes = serde_json::to_vec_pretty(&envelope)?;
    bytes.push(b'\n');
    let mut stdout = io::stdout().lock();
    stdout.write_all(&bytes)?;
    stdout.flush()?;
    Ok(())
}
