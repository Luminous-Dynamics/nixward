// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline reference signer for Symthaea release manifests.

use ed25519_dalek::{Signer, SigningKey};
use nixward::release_integrity::{
    RELEASE_MANIFEST_KIND, RELEASE_SCHEMA_VERSION, RELEASE_SIGNATURE_KIND, ReleaseArtifact,
    ReleaseManifest, SignedReleaseManifest,
};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn usage() -> ! {
    eprintln!(
        "Usage: nixward-release-sign --root <dir> --release-id <id> --source-revision <rev> --seed-file <32-byte-or-64hex> --output <json>"
    );
    std::process::exit(2)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("seed file must contain exactly 32 raw bytes or 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| "invalid hex seed")?;
    }
    Ok(out)
}

fn read_seed(path: &Path) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read signing seed: {e}"))?;
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "seed is neither 32 raw bytes nor UTF-8 hex")?;
    decode_hex_32(text)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<ReleaseArtifact>) -> Result<(), String> {
    let mut entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot enumerate {}: {e}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot enumerate release tree: {e}"))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "release tree contains symlink {}; signed releases require concrete bytes",
                path.display()
            ));
        }
        if meta.is_dir() {
            walk(root, &path, out)?;
            continue;
        }
        if !meta.is_file() {
            return Err(format!(
                "release tree contains unsupported non-file {}",
                path.display()
            ));
        }
        let rel = path
            .strip_prefix(root)
            .map_err(|_| "release path escaped root")?;
        let rel = rel
            .to_str()
            .ok_or("release paths must be UTF-8")?
            .replace('\\', "/");
        let bytes =
            std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        out.push(ReleaseArtifact {
            path: rel,
            blake3: blake3::hash(&bytes).to_hex().to_string(),
            size_bytes: bytes.len() as u64,
            executable: meta.permissions().mode() & 0o111 != 0,
        });
    }
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn main() {
    let mut root = None::<PathBuf>;
    let mut release_id = None::<String>;
    let mut source_revision = None::<String>;
    let mut seed_file = None::<PathBuf>;
    let mut output = None::<PathBuf>;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = args.next().map(PathBuf::from),
            "--release-id" => release_id = args.next(),
            "--source-revision" => source_revision = args.next(),
            "--seed-file" => seed_file = args.next().map(PathBuf::from),
            "--output" => output = args.next().map(PathBuf::from),
            "--help" | "-h" => usage(),
            _ => usage(),
        }
    }
    let root = root.unwrap_or_else(|| usage());
    let release_id = release_id.unwrap_or_else(|| usage());
    let source_revision = source_revision.unwrap_or_else(|| usage());
    let seed_file = seed_file.unwrap_or_else(|| usage());
    let output = output.unwrap_or_else(|| usage());
    let root = root.canonicalize().unwrap_or_else(|e| {
        eprintln!("cannot canonicalize release root: {e}");
        std::process::exit(2)
    });
    if output.starts_with(&root) {
        eprintln!(
            "output manifest must be outside the signed release root to avoid self-reference"
        );
        std::process::exit(2);
    }
    let seed = read_seed(&seed_file).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let signing = SigningKey::from_bytes(&seed);
    let mut artifacts = Vec::new();
    walk(&root, &root, &mut artifacts).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let manifest = ReleaseManifest {
        schema_version: RELEASE_SCHEMA_VERSION,
        kind: RELEASE_MANIFEST_KIND.into(),
        release_id,
        created_at_ms: now_ms(),
        source_revision,
        artifacts,
    };
    let signature = signing.sign(&manifest.signing_bytes().unwrap_or_else(|e| {
        eprintln!("manifest validation failed: {e}");
        std::process::exit(2)
    }));
    let signed = SignedReleaseManifest {
        kind: RELEASE_SIGNATURE_KIND.into(),
        algorithm: "ed25519".into(),
        signer_public_key_hex: hex(signing.verifying_key().as_bytes()),
        signature_hex: hex(&signature.to_bytes()),
        manifest,
    };
    let bytes = serde_json::to_vec_pretty(&signed).expect("release manifest serializes");
    std::fs::write(&output, bytes).unwrap_or_else(|e| {
        eprintln!("cannot write signed manifest: {e}");
        std::process::exit(2)
    });
    eprintln!("release root public key: {}", signed.signer_public_key_hex);
    eprintln!("manifest digest: {}", signed.manifest.digest().unwrap());
}
