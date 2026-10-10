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

    // The release token is a short-lived capability. Wipe the child-side
    // copy on every return path, including malformed frames and read errors.
    let mut token = zeroize::Zeroizing::new([0u8; 32]);
    reader
        .read_exact(&mut token[..])
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

/// Run the irreversible operation only after the complete, authenticated
/// release frame has been consumed. Keeping this boundary generic makes the
/// no-callback-on-failure property directly testable without executing a real
/// NixOS activation payload in unit tests.
fn release_then<R, T, F>(
    reader: &mut R,
    expected_digest: &str,
    on_release: F,
) -> Result<T, String>
where
    R: Read,
    F: FnOnce() -> Result<T, String>,
{
    read_release(reader, expected_digest)?;
    on_release()
}

fn nix_store_object(path: &Path) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or_else(|| "worker gate process image path is not valid UTF-8".to_string())?;
    let object = text
        .strip_prefix("/nix/store/")
        .and_then(|rest| rest.split('/').next())
        .filter(|object| !object.is_empty())
        .ok_or_else(|| "worker gate process image is not a Nix store object".to_string())?;
    let store_path = format!("/nix/store/{object}");
    if !nixward::action::execution_intent::is_valid_nix_store_path(&store_path) {
        return Err("worker gate process image has an invalid Nix store object identity".into());
    }
    Ok(object.to_string())
}

fn validate_parent_package_images(current: &Path, parent: &Path) -> Result<(), String> {
    const TRUSTED_LAUNCHERS: [&str; 3] = ["nixward", "nixward-tui", "nixward-daemon"];

    let current_object = nix_store_object(current)?;
    let parent_object = nix_store_object(parent)?;
    if parent_object != current_object {
        return Err("worker gate parent is not from the same immutable Nixward package".into());
    }

    let parent_name = parent
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "worker gate parent executable name is not valid UTF-8".to_string())?;
    if !TRUSTED_LAUNCHERS.contains(&parent_name) {
        return Err("worker gate parent is not an approved Nixward launcher executable".into());
    }
    if parent.parent().and_then(Path::file_name) != Some(std::ffi::OsStr::new("bin")) {
        return Err("worker gate parent is not in the approved Nixward bin directory".into());
    }
    Ok(())
}

/// The gate is an ordering barrier for Nixward's trusted launcher, not a general
/// command-execution interface. Refuse direct invocation by a shell or unrelated
/// executable, which otherwise could choose both the digest and token itself.
/// This is defense in depth, not isolation from a compromised Nixward process.
fn validate_trusted_parent_package() -> Result<(), String> {
    let current = std::env::current_exe()
        .map_err(|error| format!("worker gate cannot resolve its own executable: {error}"))?
        .canonicalize()
        .map_err(|error| format!("worker gate cannot canonicalize its executable: {error}"))?;
    let parent_pid = unsafe { nix::libc::getppid() };
    if parent_pid <= 1 {
        return Err("worker gate has no live Nixward launcher parent".into());
    }
    let parent = std::fs::read_link(format!("/proc/{parent_pid}/exe"))
        .map_err(|error| format!("worker gate cannot inspect launcher parent executable: {error}"))?;
    validate_parent_package_images(&current, &parent)
}

fn run_with_args<I>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = OsString>,
{
    validate_trusted_parent_package()?;
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

    // The child is single-threaded and has already completed the durable receipt
    // handshake. The only route to exec passes through this gate: the complete
    // token must match and the parent must close the pipe (EOF) first. Use direct
    // exec semantics—never a shell or PATH lookup.
    release_then(&mut stdin.lock(), &expected_digest, || {
        let error = Command::new(&target).args(payload_args).exec();
        Err(format!("worker gate could not exec the bound payload: {error}"))
    })
}

fn main() {
    if let Err(error) = run_with_args(std::env::args_os().skip(1)) {
        eprintln!("{error}");
        std::process::exit(125);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn irreversible_callback_is_not_invoked_for_invalid_release_frames() {
        let token = [0x39u8; 32];
        let digest = release_digest(&token);
        let wrong_token = vec![0x4au8; 32];
        let partial_token = token[..31].to_vec();
        let mut trailing_bytes = token.to_vec();
        trailing_bytes.push(0xff);

        for (label, frame, expected, expected_error) in [
            ("wrong token", wrong_token.as_slice(), digest.as_str(), "does not match"),
            ("truncated token", partial_token.as_slice(), digest.as_str(), "incomplete"),
            ("trailing byte", trailing_bytes.as_slice(), digest.as_str(), "trailing bytes"),
            ("parent EOF", &[][..], digest.as_str(), "incomplete"),
        ] {
            let mut reader = Cursor::new(frame.to_vec());
            let mut callback_called = false;
            let result = release_then(&mut reader, expected, || {
                callback_called = true;
                Ok(())
            });
            assert!(result.unwrap_err().contains(expected_error), "{label}");
            assert!(!callback_called, "irreversible callback ran for {label}");
        }
    }

    #[test]
    fn irreversible_callback_runs_once_after_valid_release_and_propagates_exec_error() {
        let token = [0xc3u8; 32];
        let digest = release_digest(&token);
        let mut reader = Cursor::new(token.to_vec());
        let mut callback_count = 0usize;

        let result: Result<(), String> = release_then(&mut reader, &digest, || {
            callback_count += 1;
            Err("injected exec failure".to_string())
        });

        assert_eq!(callback_count, 1, "valid release must invoke the callback exactly once");
        assert_eq!(result.unwrap_err(), "injected exec failure");
    }

    use super::*;
    use std::io::{Cursor, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn unix_stream_release_protocol_requires_real_peer_eof() {
        let token = [0x83u8; 32];
        let digest = release_digest(&token);

        // Use a real kernel-backed stream rather than Cursor so EOF framing is
        // exercised through the same Read implementation shape as the gate's
        // stdin pipe. Dropping the writer models a parent closing its pipe.
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&token).unwrap();
        drop(writer);
        let mut calls = 0usize;
        let result = release_then(&mut reader, &digest, || {
            calls += 1;
            Ok(())
        });
        assert!(result.is_ok());
        assert_eq!(calls, 1, "valid token plus peer EOF invokes exactly once");

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&token[..31]).unwrap();
        drop(writer);
        let mut calls = 0usize;
        let result = release_then(&mut reader, &digest, || {
            calls += 1;
            Ok(())
        });
        assert!(result.unwrap_err().contains("incomplete"));
        assert_eq!(calls, 0, "short pipe frame must not release");

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let mut trailing = token.to_vec();
        trailing.push(0x01);
        writer.write_all(&trailing).unwrap();
        drop(writer);
        let mut calls = 0usize;
        let result = release_then(&mut reader, &digest, || {
            calls += 1;
            Ok(())
        });
        assert!(result.unwrap_err().contains("trailing bytes"));
        assert_eq!(calls, 0, "trailing pipe bytes must not release");
    }

    #[test]
    fn worker_gate_requires_same_package_and_approved_launcher_name() {
        let current_cli = Path::new("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixward/bin/nixward-worker-gate");
        let cli = Path::new("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixward/bin/nixward");
        let current_tui = Path::new("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixward-tui/bin/nixward-worker-gate");
        let tui = Path::new("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixward-tui/bin/nixward-tui");
        let current_daemon = Path::new("/nix/store/cccccccccccccccccccccccccccccccc-nixward-daemon/bin/nixward-worker-gate");
        let daemon = Path::new("/nix/store/cccccccccccccccccccccccccccccccc-nixward-daemon/bin/nixward-daemon");
        let gate = Path::new("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixward/bin/nixward-worker-gate");
        let unapproved_sibling = Path::new("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixward/bin/nixward-owner-key");
        let launcher_outside_bin = Path::new("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixward/libexec/nixward");
        let different_package = Path::new("/nix/store/dddddddddddddddddddddddddddddddd-nixward/bin/nixward");

        assert!(validate_parent_package_images(current_cli, cli).is_ok());
        assert!(validate_parent_package_images(current_tui, tui).is_ok());
        assert!(validate_parent_package_images(current_daemon, daemon).is_ok());
        assert!(validate_parent_package_images(current_cli, gate).is_err());
        assert!(validate_parent_package_images(current_cli, unapproved_sibling).is_err());
        assert!(validate_parent_package_images(current_cli, launcher_outside_bin).is_err());
        assert!(validate_parent_package_images(current_cli, different_package).is_err());
        assert!(validate_parent_package_images(current_cli, Path::new("/usr/bin/bash")).is_err());
    }

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
    fn parent_eof_before_release_fails_closed() {
        // This is the state observed if the executor dies before releasing the
        // gate. No complete token exists, so run_with_args returns before exec.
        let expected = release_digest(&[0x2au8; 32]);
        let mut parent_closed = Cursor::new(Vec::<u8>::new());
        assert!(
            read_release(&mut parent_closed, &expected).is_err(),
            "EOF without a complete release token must never authorize payload exec"
        );
    }

    #[test]
    fn release_digest_must_be_canonical() {
        let token = [0x12u8; 32];
        assert!(read_release(&mut Cursor::new(token.to_vec()), &release_digest(&token).to_uppercase()).is_err());
        assert!(read_release(&mut Cursor::new(token.to_vec()), "not-a-digest").is_err());
    }
}
