// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline/reference owner-root key and detached challenge signer.
//!
//! Production deployments should prefer a phone/hardware-backed signer. This
//! utility proves the wire format without ever requiring the Spore relay to
//! receive a private key.

use ed25519_dalek::{Signer, SigningKey};
use nixward::authority_signature::{
    AUTHORITY_SCHEMA_VERSION, AUTHORITY_SIGNATURE_KIND, AuthorityChallenge,
    DetachedAuthoritySignature,
};
use nixward::owner_root::{OwnerRecoveryPolicy, OwnerRootPublicIdentity};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn usage() -> ! {
    eprintln!(
        "Generate: nixward-owner-key generate --seed-file <path> --identity-out <json> --release-manifest-blake3 <digest> [--key-id <id>] [--display-name <name>]"
    );
    eprintln!(
        "Sign:     nixward-owner-key sign --seed-file <path> --challenge <json> --signature-out <json> --key-id <id>"
    );
    std::process::exit(2)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_seed(path: &Path) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read owner seed: {e}"))?;
    if bytes.len() != 32 {
        return Err("owner seed must be exactly 32 raw bytes".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn generate(mut args: impl Iterator<Item = String>) {
    let mut seed_file = None::<PathBuf>;
    let mut identity_out = None::<PathBuf>;
    let mut release = None::<String>;
    let mut key_id = "owner-root-1".to_string();
    let mut display = "Primary owner".to_string();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--seed-file" => seed_file = args.next().map(PathBuf::from),
            "--identity-out" => identity_out = args.next().map(PathBuf::from),
            "--release-manifest-blake3" => release = args.next(),
            "--key-id" => key_id = args.next().unwrap_or_else(|| usage()),
            "--display-name" => display = args.next().unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }
    let seed_file = seed_file.unwrap_or_else(|| usage());
    let identity_out = identity_out.unwrap_or_else(|| usage());
    let release = release.unwrap_or_else(|| usage());
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .unwrap_or_else(|e| {
            eprintln!("secure OS entropy unavailable: {e}");
            std::process::exit(2)
        });
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&seed_file)
        .unwrap_or_else(|e| {
            eprintln!(
                "refusing to overwrite owner seed {}: {e}",
                seed_file.display()
            );
            std::process::exit(2)
        });
    use std::io::Write;
    f.write_all(&seed).unwrap();
    f.sync_all().unwrap();
    std::fs::set_permissions(&seed_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let signing = SigningKey::from_bytes(&seed);
    let identity = OwnerRootPublicIdentity::new(
        key_id,
        hex(signing.verifying_key().as_bytes()),
        display,
        now_ms(),
        release,
        OwnerRecoveryPolicy::default(),
    )
    .unwrap_or_else(|e| {
        eprintln!("owner identity invalid: {e}");
        std::process::exit(2)
    });
    std::fs::write(&identity_out, serde_json::to_vec_pretty(&identity).unwrap()).unwrap();
    eprintln!(
        "owner root fingerprint: {}",
        identity.short_fingerprint().unwrap()
    );
    eprintln!(
        "IMPORTANT: move the 0600 seed to owner-controlled/offline storage; do not install it into the Holon config."
    );
}

fn sign(mut args: impl Iterator<Item = String>) {
    let mut seed_file = None::<PathBuf>;
    let mut challenge_path = None::<PathBuf>;
    let mut output = None::<PathBuf>;
    let mut key_id = None::<String>;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--seed-file" => seed_file = args.next().map(PathBuf::from),
            "--challenge" => challenge_path = args.next().map(PathBuf::from),
            "--signature-out" => output = args.next().map(PathBuf::from),
            "--key-id" => key_id = args.next(),
            _ => usage(),
        }
    }
    let signing = SigningKey::from_bytes(
        &read_seed(&seed_file.unwrap_or_else(|| usage())).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(2)
        }),
    );
    let challenge: AuthorityChallenge =
        serde_json::from_slice(&std::fs::read(challenge_path.unwrap_or_else(|| usage())).unwrap())
            .unwrap_or_else(|e| {
                eprintln!("invalid challenge: {e}");
                std::process::exit(2)
            });
    let signature = signing.sign(&challenge.signing_bytes().unwrap_or_else(|e| {
        eprintln!("invalid challenge: {e}");
        std::process::exit(2)
    }));
    let signed = DetachedAuthoritySignature {
        schema_version: AUTHORITY_SCHEMA_VERSION,
        kind: AUTHORITY_SIGNATURE_KIND.into(),
        algorithm: "ed25519".into(),
        key_id: key_id.unwrap_or_else(|| usage()),
        public_key_hex: hex(signing.verifying_key().as_bytes()),
        signature_hex: hex(&signature.to_bytes()),
        challenge,
    };
    std::fs::write(
        output.unwrap_or_else(|| usage()),
        serde_json::to_vec_pretty(&signed).unwrap(),
    )
    .unwrap();
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("generate") => generate(args),
        Some("sign") => sign(args),
        _ => usage(),
    }
}
