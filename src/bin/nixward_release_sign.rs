// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline reference signer for Symthaea release manifests.

use ed25519_dalek::{Signer, SigningKey};
use nixward::release_integrity::{
    RELEASE_MANIFEST_KIND, RELEASE_SCHEMA_VERSION, RELEASE_SIGNATURE_KIND, ReleaseArtifact,
    ReleaseManifest, SignedReleaseManifest,
};
use std::io::{Read, Write};
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

fn resolve_seed_path(path: &Path, release_root: &Path) -> Result<PathBuf, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect signing seed path: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("signing seed must be a regular, non-symlink file".into());
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize signing seed path: {error}"))?;
    if canonical.starts_with(release_root) {
        return Err("signing seed must be outside the signed release root".into());
    }
    Ok(canonical)
}

fn resolve_output_path(path: &Path) -> Result<PathBuf, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err("output manifest path must not be a symbolic link".into());
            }
            if !metadata.is_file() {
                return Err("output manifest path must name a regular file".into());
            }
            Err("output manifest destination already exists; choose a new path".into())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file_name = path
                .file_name()
                .ok_or_else(|| "output manifest path must name a file".to_string())?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let canonical_parent = parent
                .canonicalize()
                .map_err(|error| format!("cannot canonicalize output directory: {error}"))?;
            Ok(canonical_parent.join(file_name))
        }
        Err(error) => Err(format!("cannot inspect output manifest path: {error}")),
    }
}

fn require_outside_release_root(
    release_root: &Path,
    candidate: &Path,
    label: &str,
) -> Result<(), String> {
    if candidate.starts_with(release_root) {
        return Err(format!("{label} must be outside the signed release root"));
    }
    Ok(())
}

fn validate_seed_permissions(seed_path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(seed_path)
        .map_err(|error| format!("cannot inspect signing seed permissions: {error}"))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(
            "signing seed permissions must deny group and other access (for example, mode 0600)"
                .into(),
        );
    }
    Ok(())
}

fn ensure_seed_not_linked_into_release_tree(
    seed_path: &Path,
    release_root: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let seed_metadata = std::fs::metadata(seed_path)
        .map_err(|error| format!("cannot inspect signing seed identity: {error}"))?;

    fn scan(directory: &Path, seed_dev: u64, seed_ino: u64) -> Result<(), String> {
        let mut entries = std::fs::read_dir(directory)
            .map_err(|error| format!("cannot scan release directory {}: {error}", directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot enumerate release directory: {error}"))?;
        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect release path {}: {error}", path.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "release tree contains symbolic link {}; refusing to sign",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                scan(&path, seed_dev, seed_ino)?;
            } else if metadata.is_file() {
                if metadata.dev() == seed_dev && metadata.ino() == seed_ino {
                    return Err(format!(
                        "signing seed shares a hard link with release artifact {}; refusing to sign",
                        path.display()
                    ));
                }
            } else {
                return Err(format!(
                    "release tree contains unsupported non-file {}; refusing to sign",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    scan(release_root, seed_metadata.dev(), seed_metadata.ino())
}

fn write_new_manifest(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut output_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!("cannot create new output manifest without overwriting an existing path: {error}")
        })?;

    if let Err(error) = output_file.write_all(bytes).and_then(|_| output_file.sync_all()) {
        drop(output_file);
        return match std::fs::remove_file(path) {
            Ok(()) => Err(format!("cannot persist signed manifest; incomplete output removed: {error}")),
            Err(cleanup_error) => Err(format!(
                "cannot persist signed manifest: {error}; could not remove incomplete output: {cleanup_error}"
            )),
        };
    }

    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn write_new_manifest_persists_bytes_and_never_overwrites() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("manifest.json");
        let bytes = br#"{"kind":"test-manifest"}"#;

        write_new_manifest(&output, bytes).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), bytes);

        let error = write_new_manifest(&output, b"replacement").unwrap_err();
        assert!(error.contains("without overwriting an existing path"));
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
    }

    #[test]
    fn signing_seed_with_group_or_other_permissions_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let seed = temp.path().join("signing.seed");
        std::fs::write(&seed, [11u8; 32]).unwrap();
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o640)).unwrap();

        assert!(validate_seed_permissions(&seed)
            .unwrap_err()
            .contains("deny group and other access"));

        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_seed_permissions(&seed).is_ok());
    }

    #[test]
    fn signing_seed_hard_linked_into_release_tree_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let release_root = temp.path().join("release");
        std::fs::create_dir_all(&release_root).unwrap();
        let seed = temp.path().join("signing.seed");
        std::fs::write(&seed, [12u8; 32]).unwrap();
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
        let leaked = release_root.join("artifact.bin");
        std::fs::hard_link(&seed, &leaked).unwrap();

        let canonical_seed = seed.canonicalize().unwrap();
        assert!(ensure_seed_not_linked_into_release_tree(&canonical_seed, &release_root)
            .unwrap_err()
            .contains("shares a hard link with release artifact"));
    }

    #[test]
    fn signing_seed_inside_release_root_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let release_root = temp.path().join("release");
        std::fs::create_dir_all(&release_root).unwrap();
        let seed = release_root.join("release-seed");
        std::fs::write(&seed, [7u8; 32]).unwrap();
        let canonical_root = release_root.canonicalize().unwrap();

        assert!(resolve_seed_path(&seed, &canonical_root)
            .unwrap_err()
            .contains("outside the signed release root"));
    }

    #[test]
    fn signing_seed_symbolic_link_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let release_root = temp.path().join("release");
        std::fs::create_dir_all(&release_root).unwrap();
        let seed = temp.path().join("seed");
        let alias = temp.path().join("seed-link");
        std::fs::write(&seed, [8u8; 32]).unwrap();
        symlink(&seed, &alias).unwrap();

        assert!(resolve_seed_path(&alias, &release_root.canonicalize().unwrap())
            .unwrap_err()
            .contains("non-symlink"));
    }

    #[test]
    fn output_inside_release_root_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let release_root = temp.path().join("release");
        std::fs::create_dir_all(&release_root).unwrap();
        let canonical_root = release_root.canonicalize().unwrap();
        let output = resolve_output_path(&release_root.join("manifest.json")).unwrap();

        assert!(require_outside_release_root(&canonical_root, &output, "output manifest")
            .unwrap_err()
            .contains("outside the signed release root"));
    }

    #[test]
    fn output_through_symlinked_parent_inside_release_root_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let release_root = temp.path().join("release");
        std::fs::create_dir_all(&release_root).unwrap();
        let alias = temp.path().join("release-alias");
        symlink(&release_root, &alias).unwrap();

        let output = resolve_output_path(&alias.join("manifest.json")).unwrap();
        assert!(require_outside_release_root(&release_root.canonicalize().unwrap(), &output, "output manifest")
            .unwrap_err()
            .contains("outside the signed release root"));
    }

    #[test]
    fn output_must_not_overwrite_the_signing_seed() {
        let temp = tempfile::tempdir().unwrap();
        let seed = temp.path().join("signing.seed");
        std::fs::write(&seed, [9u8; 32]).unwrap();

        assert!(resolve_output_path(&seed)
            .unwrap_err()
            .contains("already exists"));
    }

    #[test]
    fn output_hard_link_to_signing_seed_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let seed = temp.path().join("signing.seed");
        let output_alias = temp.path().join("manifest.json");
        std::fs::write(&seed, [10u8; 32]).unwrap();
        std::fs::hard_link(&seed, &output_alias).unwrap();

        assert!(resolve_output_path(&output_alias)
            .unwrap_err()
            .contains("already exists"));
    }

    #[test]
    fn output_hard_link_to_release_artifact_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let release_root = temp.path().join("release");
        std::fs::create_dir_all(&release_root).unwrap();
        let artifact = release_root.join("artifact.bin");
        let output_alias = temp.path().join("manifest.json");
        std::fs::write(&artifact, b"artifact payload").unwrap();
        std::fs::hard_link(&artifact, &output_alias).unwrap();

        assert!(resolve_output_path(&output_alias)
            .unwrap_err()
            .contains("already exists"));
    }

    #[test]
    fn existing_output_symlink_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.json");
        let alias = temp.path().join("manifest.json");
        std::fs::write(&target, "{}").unwrap();
        symlink(&target, &alias).unwrap();

        assert!(resolve_output_path(&alias)
            .unwrap_err()
            .contains("must not be a symbolic link"));
    }
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
    let seed_file = resolve_seed_path(&seed_file, &root).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2)
    });
    validate_seed_permissions(&seed_file).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2)
    });
    ensure_seed_not_linked_into_release_tree(&seed_file, &root).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2)
    });
    let output = resolve_output_path(&output).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2)
    });
    require_outside_release_root(&root, &output, "output manifest").unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2)
    });
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
    write_new_manifest(&output, &bytes).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2)
    });
    eprintln!("release root public key: {}", signed.signer_public_key_hex);
    eprintln!("manifest digest: {}", signed.manifest.digest().unwrap());
}
