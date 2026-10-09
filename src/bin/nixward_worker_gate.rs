// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Internal launch gate for journal-receipted Nixward workers.
//!
//! The executor spawns this immutable helper instead of the privileged payload.
//! The helper performs no system mutation and waits for one parent-held pipe
//! capability. It calls exec only after the parent has persisted a pidfd-bound
//! worker receipt and sent a one-time random release token followed by EOF.

use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

const GATE_MODE: &str = "--nixward-worker-gate-v1";
const RELEASE_DOMAIN: &[u8] = b"nixward-worker-gate-release-v1\0";

fn release_digest(token: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RELEASE_DOMAIN);
    hasher.update(token);
    hasher.finalize().to_hex().to_string()
}

fn read_release<R: Read>(reader: &mut R, expected_digest: &str) -> Result<(), String> {
    if expected_digest.len() != 64
        || !expected_digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("worker gate release digest is not canonical lowercase hexadecimal".into());
    }

    let mut token = [0u8; 32];
    reader
        .read_exact(&mut token)
        .map_err(|error| format!("worker gate release token is incomplete: {error}"))?;

    // EOF is part of the frame. The parent closes the one-way pipe after the
    // token; extra bytes are malformed and a live writer cannot release the gate.
    let mut trailing = [0u8; 1];
    loop {
        match reader.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => return Err("worker gate release frame contains trailing bytes".into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("failed reading worker gate release terminator: {error}")),
        }
    }

    if release_digest(&token) != expected_digest {
        return Err("worker gate release token does not match the one-time challenge".into());
    }
    Ok(())
}

fn valid_store_executable(path: &str) -> Result<(), String> {
    if !path.starts_with("/nix/store/") {
        return Err("worker gate payload must be an absolute Nix store executable".into());
    }
    let object = path
        .strip_prefix("/nix/store/")
        .and_then(|rest| rest.split('/').next())
        .ok_or_else(|| "worker gate payload has no store object".to_string())?;
    let store_path = format!("/nix/store/{object}");
    if !nixward::action::execution_intent::is_valid_nix_store_path(&store_path) {
        return Err("worker gate payload has an invalid Nix store object identity".into());
    }
    let supplied = Path::new(path);
    let metadata = std::fs::symlink_metadata(supplied)
        .map_err(|error| format!("worker gate cannot inspect payload executable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("worker gate payload is not a regular immutable store file".into());
    }
    let canonical = supplied
        .canonicalize()
        .map_err(|error| format!("worker gate cannot resolve payload executable: {error}"))?;
    if canonical.as_path() != supplied {
        return Err("worker gate payload path is not canonical".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("worker gate payload is not executable".into());
        }
    }
    Ok(())
}

fn run_with_args<I>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let mode = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "worker gate mode argument is missing".to_string())?;
    if mode != GATE_MODE {
        return Err("worker gate may only be invoked through its private protocol".into());
    }
    let target = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "worker gate payload executable is missing or non-UTF-8".to_string())?;
    let expected_digest = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "worker gate release challenge is missing or non-UTF-8".to_string())?;
    valid_store_executable(&target)?;

    let payload_args = args.collect::<Vec<_>>();
    if payload_args.iter().any(|value| value.to_str().is_none()) {
        return Err("worker gate payload arguments must be valid UTF-8".into());
    }

    let stdin = io::stdin();
    read_release(&mut stdin.lock(), &expected_digest)?;

    // The child is single-threaded and has already completed the durable receipt
    // handshake. Use direct exec semantics—never a shell or PATH lookup.
    let error = Command::new(&target).args(payload_args).exec();
    Err(format!("worker gate could not exec the bound payload: {error}"))
}

fn main() {
    if let Err(error) = run_with_args(std::env::args_os().skip(1)) {
        eprintln!("{error}");
        std::process::exit(125);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn release_requires_exact_one_time_token_and_eof() {
        let token = [0x5au8; 32];
        let digest = release_digest(&token);
        let mut good = Cursor::new(token.to_vec());
        assert!(read_release(&mut good, &digest).is_ok());

        let mut wrong = Cursor::new([0x6bu8; 32].to_vec());
        assert!(read_release(&mut wrong, &digest).unwrap_err().contains("does not match"));

        let mut partial = Cursor::new(token[..31].to_vec());
        assert!(read_release(&mut partial, &digest).unwrap_err().contains("incomplete"));

        let mut trailing_bytes = token.to_vec();
        trailing_bytes.push(1);
        let mut trailing = Cursor::new(trailing_bytes);
        assert!(read_release(&mut trailing, &digest).unwrap_err().contains("trailing bytes"));
    }

    #[test]
    fn release_digest_must_be_canonical() {
        let token = [0x12u8; 32];
        assert!(read_release(&mut Cursor::new(token.to_vec()), &release_digest(&token).to_uppercase()).is_err());
        assert!(read_release(&mut Cursor::new(token.to_vec()), "not-a-digest").is_err());
    }
}
