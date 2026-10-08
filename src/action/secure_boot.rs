        ))
        .map_err(|error| format!("failed to serialize DB certificate verification evidence: {error}"))?;
        self.observed_at_ms = Some(observed_at_ms);
        self.evidence_digest = Some(*blake3::hash(&preimage).as_bytes());
        Ok(self)
    }
}

#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateVerifierRunState {
    Verified,
    Failed,
    ToolUnavailable,
    ImageChanged,
}

#[cfg(feature = "native")]
struct CertificateVerifierRun {
    state: CertificateVerifierRunState,
    stdout_blake3: [u8; 32],
    stderr_blake3: [u8; 32],
}

#[cfg(feature = "native")]
fn run_sbverify_against_certificate(
    image_path: &std::path::Path,
    certificate_der: &[u8],
) -> Result<CertificateVerifierRun, String> {
    let image_before = std::fs::read(image_path)
        .map_err(|error| format!("failed to read UKI {}: {error}", image_path.display()))?;
    let image_before_hash = *blake3::hash(&image_before).as_bytes();

    let mut image_snapshot = tempfile::NamedTempFile::new()
        .map_err(|error| format!("failed to create temporary image snapshot: {error}"))?;
    use std::io::Write;
    image_snapshot
        .write_all(&image_before)
        .map_err(|error| format!("failed to write temporary image snapshot: {error}"))?;
    image_snapshot
        .flush()
        .map_err(|error| format!("failed to flush temporary image snapshot: {error}"))?;

    let mut certificate_snapshot = tempfile::NamedTempFile::new()
        .map_err(|error| format!("failed to create temporary certificate file: {error}"))?;
    certificate_snapshot
        .write_all(pem_encode_certificate(certificate_der).as_bytes())
        .map_err(|error| format!("failed to write temporary certificate file: {error}"))?;
    certificate_snapshot
        .flush()
        .map_err(|error| format!("failed to flush temporary certificate file: {error}"))?;

    let output = match std::process::Command::new("sbverify")
        .args(["--cert"])
        .arg(certificate_snapshot.path())
        .arg(image_snapshot.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CertificateVerifierRun {
                state: CertificateVerifierRunState::ToolUnavailable,
                stdout_blake3: *blake3::hash(&[]).as_bytes(),
                stderr_blake3: *blake3::hash(error.to_string().as_bytes()).as_bytes(),
            });
        }
        Err(error) => return Err(format!("failed to execute sbverify: {error}")),
    };

    let image_after = std::fs::read(image_path)