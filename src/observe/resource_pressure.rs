// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Read-only Linux resource-pressure observation.
//!
//! Reads procfs and cgroup-v2 accounting files, never writes resource controls,
//! and reports missing or malformed data as unavailable rather than zero.
//! It does not infer per-build usage from nix-daemon service totals.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Version of the in-memory resource observation contract.
pub const RESOURCE_PRESSURE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceState {
    Observed,
    Derived,
    Unavailable,
    Stale,
}

/// A typed measurement with explicit provenance and missing-data semantics.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation<T> {
    pub state: EvidenceState,
    pub value: Option<T>,
    /// Stable source identifier; excludes host paths and user identity.
    pub source: &'static str,
    /// Machine-readable reason that never includes raw file contents.
    pub reason: Option<&'static str>,
}

impl<T> Observation<T> {
    fn observed(value: T, source: &'static str) -> Self {
        Self {
            state: EvidenceState::Observed,
            value: Some(value),
            source,
            reason: None,
        }
    }

    fn unavailable(source: &'static str, reason: &'static str) -> Self {
        Self {
            state: EvidenceState::Unavailable,
            value: None,
            source,
            reason: Some(reason),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsiAverage {
    /// Percentage of wall time in which at least one task was stalled.
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    /// Cumulative stall time in microseconds.
    pub total_usec: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsiPressure {
    pub some: PsiAverage,
    /// CPU PSI does not expose a full line on Linux.
    pub full: Option<PsiAverage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapIoCounters {
    /// Pages read from swap since boot.
    pub pages_in: u64,
    /// Pages written to swap since boot.
    pub pages_out: u64,
}

/// One read-only host sample. Counter deltas must be derived across samples.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourcePressureSnapshot {
    pub schema_version: u32,
    /// Unix epoch milliseconds; None means the wall clock was unavailable.
    pub captured_at_unix_ms: Option<u128>,
    pub memory: Observation<MemoryInfo>,
    pub cpu_pressure: Observation<PsiPressure>,
    pub memory_pressure: Observation<PsiPressure>,
    pub io_pressure: Observation<PsiPressure>,
    pub swap_io: Observation<SwapIoCounters>,
}

/// Read-only observer for Linux procfs resource interfaces.
#[derive(Debug, Clone)]
pub struct ResourcePressureObserver {
    proc_root: PathBuf,
}

impl Default for ResourcePressureObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourcePressureObserver {
    /// Observe the live host using /proc.
    pub fn new() -> Self {
        Self::with_proc_root("/proc")
    }

    /// Construct an observer rooted at a fixture directory (also useful in tests).
    pub fn with_proc_root(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }

    /// Collect one read-only sample. Each source is independent: a missing PSI
    /// file does not discard valid memory or swap observations.
    pub fn snapshot(&self) -> ResourcePressureSnapshot {
        let captured_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_millis());

        ResourcePressureSnapshot {
            schema_version: RESOURCE_PRESSURE_SCHEMA_VERSION,
            captured_at_unix_ms,
            memory: read_observation(
                &self.proc_root.join("meminfo"),
                "proc/meminfo",
                parse_meminfo,
            ),
            cpu_pressure: read_observation(
                &self.proc_root.join("pressure/cpu"),
                "proc/pressure/cpu",
                parse_psi,
            ),
            memory_pressure: read_observation(
                &self.proc_root.join("pressure/memory"),
                "proc/pressure/memory",
                parse_psi,
            ),
            io_pressure: read_observation(
                &self.proc_root.join("pressure/io"),
                "proc/pressure/io",
                parse_psi,
            ),
            swap_io: read_observation(
                &self.proc_root.join("vmstat"),
                "proc/vmstat",
                parse_swap_io,
            ),
        }
    }
}

fn read_observation<T>(
    path: &Path,
    source: &'static str,
    parser: fn(&str) -> Result<T, ParseError>,
) -> Observation<T> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => {
            return Observation::unavailable(source, io_reason(error.kind()));
        }
    };

    match parser(&content) {
        Ok(value) => Observation::observed(value, source),
        Err(_) => Observation::unavailable(source, "source-parse-error"),
    }
}

/// A cgroup-v2 resource sample. Every metric is independent so unsupported
/// kernel files remain explicitly unavailable rather than becoming zero.
#[derive(Debug, Clone, PartialEq)]
pub struct CgroupResourceSnapshot {
    /// Caller-supplied semantic label, for example app-slice or nix-daemon.
    pub target: String,
    pub memory_current_bytes: Observation<u64>,
    pub memory_peak_bytes: Observation<u64>,
    pub memory_swap_current_bytes: Observation<u64>,
    pub pids_current: Observation<u64>,
    pub cpu_usage_usec: Observation<u64>,
    pub io_read_bytes: Observation<u64>,
    pub io_write_bytes: Observation<u64>,
}

/// Read-only cgroup-v2 observer. Relative paths are resolved beneath root;
/// parent traversal, absolute paths and symlink escapes are rejected.
#[derive(Debug, Clone)]
pub struct CgroupV2Observer {
    root: PathBuf,
}

impl Default for CgroupV2Observer {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupV2Observer {
    pub fn new() -> Self {
        Self::with_root("/sys/fs/cgroup")
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Read accounting files for one explicitly selected cgroup-v2 directory.
    /// This method never enumerates unrelated cgroups and has no mutation path.
    pub fn observe(
        &self,
        target: &str,
        relative_path: impl AsRef<Path>,
    ) -> io::Result<CgroupResourceSnapshot> {
        validate_target_label(target)?;
        let relative_path = relative_path.as_ref();
        validate_relative_path(relative_path)?;

        let canonical_root = self.root.canonicalize()?;
        let candidate = canonical_root.join(relative_path);
        let canonical_dir = candidate.canonicalize()?;
        if !canonical_dir.starts_with(&canonical_root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cgroup path escapes the configured cgroup root",
            ));
        }

        Ok(CgroupResourceSnapshot {
            target: target.to_string(),
            memory_current_bytes: read_cgroup_scalar(
                &canonical_dir,
                "memory.current",
                "cgroup-v2/memory.current",
            ),
            memory_peak_bytes: read_cgroup_scalar(
                &canonical_dir,
                "memory.peak",
                "cgroup-v2/memory.peak",
            ),
            memory_swap_current_bytes: read_cgroup_scalar(
                &canonical_dir,
                "memory.swap.current",
                "cgroup-v2/memory.swap.current",
            ),
            pids_current: read_cgroup_scalar(
                &canonical_dir,
                "pids.current",
                "cgroup-v2/pids.current",
            ),
            cpu_usage_usec: read_cgroup_cpu_usage(&canonical_dir),
            io_read_bytes: read_cgroup_io_bytes(&canonical_dir, true),
            io_write_bytes: read_cgroup_io_bytes(&canonical_dir, false),
        })
    }
}

fn validate_target_label(label: &str) -> io::Result<()> {
    if label.is_empty()
        || label.len() > 64
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cgroup target label must be 1-64 ASCII alphanumeric, dot, underscore or hyphen characters",
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cgroup path must be a non-empty relative path without traversal components",
        ));
    }
    Ok(())
}

fn read_cgroup_scalar(
    directory: &Path,
    file: &'static str,
    source: &'static str,
) -> Observation<u64> {
    match fs::read_to_string(directory.join(file)) {
        Ok(content) => match parse_u64_scalar(&content) {
            Ok(value) => Observation::observed(value, source),
            Err(_) => Observation::unavailable(source, "source-parse-error"),
        },
        Err(error) => Observation::unavailable(source, io_reason(error.kind())),
    }
}

fn read_cgroup_cpu_usage(directory: &Path) -> Observation<u64> {
    const SOURCE: &str = "cgroup-v2/cpu.stat";
    match fs::read_to_string(directory.join("cpu.stat")) {
        Ok(content) => match parse_cpu_usage_usec(&content) {
            Ok(value) => Observation::observed(value, SOURCE),
            Err(_) => Observation::unavailable(SOURCE, "source-parse-error"),
        },
        Err(error) => Observation::unavailable(SOURCE, io_reason(error.kind())),
    }
}

fn read_cgroup_io_bytes(directory: &Path, read: bool) -> Observation<u64> {
    const SOURCE: &str = "cgroup-v2/io.stat";
    match fs::read_to_string(directory.join("io.stat")) {
        Ok(content) => match parse_io_bytes(&content) {
            Ok((read_bytes, write_bytes)) => {
                Observation::observed(if read { read_bytes } else { write_bytes }, SOURCE)
            }
            Err(_) => Observation::unavailable(SOURCE, "source-parse-error"),
        },
        Err(error) => Observation::unavailable(SOURCE, io_reason(error.kind())),
    }
}

fn io_reason(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => "source-not-found",
        io::ErrorKind::PermissionDenied => "permission-denied",
        _ => "source-read-error",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParseError;

fn parse_meminfo(content: &str) -> Result<MemoryInfo, ParseError> {
    let mut values = std::collections::BTreeMap::<&str, u64>::new();
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(key_with_colon) = fields.next() else {
            continue;
        };
        let key = key_with_colon.trim_end_matches(':');
        if !matches!(key, "MemTotal" | "MemAvailable" | "SwapTotal" | "SwapFree") {
            continue;
        }
        let value = fields.next().ok_or(ParseError)?.parse::<u64>().map_err(|_| ParseError)?;
        let unit = fields.next().ok_or(ParseError)?;
        if unit != "kB" || fields.next().is_some() || values.insert(key, value).is_some() {
            return Err(ParseError);
        }
    }

    let total_bytes = values.get("MemTotal").copied().ok_or(ParseError)?
        .checked_mul(1024).ok_or(ParseError)?;
    let available_bytes = values.get("MemAvailable").copied().ok_or(ParseError)?
        .checked_mul(1024).ok_or(ParseError)?;
    if available_bytes > total_bytes {
        return Err(ParseError);
    }

    let swap_total_kib = values.get("SwapTotal").copied();
    let swap_free_kib = values.get("SwapFree").copied();
    let (swap_total_bytes, swap_free_bytes) = match (swap_total_kib, swap_free_kib) {
        (Some(total), Some(free)) if free <= total => (
            Some(total.checked_mul(1024).ok_or(ParseError)?),
            Some(free.checked_mul(1024).ok_or(ParseError)?),
        ),
        (None, None) => (None, None),
        _ => return Err(ParseError),
    };

    Ok(MemoryInfo {
        total_bytes,
        available_bytes,
        swap_total_bytes,
        swap_free_bytes,
    })
}

fn parse_psi(content: &str) -> Result<PsiPressure, ParseError> {
    let mut some = None;
    let mut full = None;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(scope) = fields.next() else {
            continue;
        };
        let average = parse_psi_average(fields)?;
        match scope {
            "some" if some.is_none() => some = Some(average),
            "full" if full.is_none() => full = Some(average),
            "some" | "full" => return Err(ParseError),
            _ => return Err(ParseError),
        }
    }
    Ok(PsiPressure {
        some: some.ok_or(ParseError)?,
        full,
    })
}

fn parse_psi_average<'a>(
    fields: impl Iterator<Item = &'a str>,
) -> Result<PsiAverage, ParseError> {
    let mut avg10 = None;
    let mut avg60 = None;
    let mut avg300 = None;
    let mut total_usec = None;

    for field in fields {
        let (key, value) = field.split_once('=').ok_or(ParseError)?;
        match key {
            "avg10" => set_once(&mut avg10, parse_percent(value)?)?,
            "avg60" => set_once(&mut avg60, parse_percent(value)?)?,
            "avg300" => set_once(&mut avg300, parse_percent(value)?)?,
            "total" => set_once(
                &mut total_usec,
                value.parse::<u64>().map_err(|_| ParseError)?,
            )?,
            _ => return Err(ParseError),
        }
    }

    Ok(PsiAverage {
        avg10: avg10.ok_or(ParseError)?,
        avg60: avg60.ok_or(ParseError)?,
        avg300: avg300.ok_or(ParseError)?,
        total_usec: total_usec.ok_or(ParseError)?,
    })
}

fn parse_percent(value: &str) -> Result<f64, ParseError> {
    let number = value.parse::<f64>().map_err(|_| ParseError)?;
    if !number.is_finite() || !(0.0..=100.0).contains(&number) {
        return Err(ParseError);
    }
    Ok(number)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError);
    }
    *slot = Some(value);
    Ok(())
}

fn parse_swap_io(content: &str) -> Result<SwapIoCounters, ParseError> {
    let values = parse_key_value_lines(content, &["pswpin", "pswpout"])?;
    Ok(SwapIoCounters {
        pages_in: *values.get("pswpin").ok_or(ParseError)?,
        pages_out: *values.get("pswpout").ok_or(ParseError)?,
    })
}

fn parse_cpu_usage_usec(content: &str) -> Result<u64, ParseError> {
    let values = parse_key_value_lines(content, &["usage_usec"])?;
    values.get("usage_usec").copied().ok_or(ParseError)
}

fn parse_key_value_lines<'a>(
    content: &'a str,
    selected: &[&str],
) -> Result<std::collections::BTreeMap<&'a str, u64>, ParseError> {
    let mut values = std::collections::BTreeMap::new();
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else {
            continue;
        };
        if !selected.contains(&key) {
            continue;
        }
        let value = fields.next().ok_or(ParseError)?.parse::<u64>().map_err(|_| ParseError)?;
        if fields.next().is_some() || values.insert(key, value).is_some() {
            return Err(ParseError);
        }
    }
    Ok(values)
}

fn parse_io_bytes(content: &str) -> Result<(u64, u64), ParseError> {
    let mut read_total = 0_u64;
    let mut write_total = 0_u64;
    let mut devices = 0_usize;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let device = fields.next().ok_or(ParseError)?;
        let (major, minor) = device.split_once(':').ok_or(ParseError)?;
        if major.parse::<u32>().is_err() || minor.parse::<u32>().is_err() {
            return Err(ParseError);
        }

        let mut read_bytes = None;
        let mut write_bytes = None;
        for field in fields {
            let (key, value) = field.split_once('=').ok_or(ParseError)?;
            match key {
                "rbytes" => set_once(
                    &mut read_bytes,
                    value.parse::<u64>().map_err(|_| ParseError)?,
                )?,
                "wbytes" => set_once(
                    &mut write_bytes,
                    value.parse::<u64>().map_err(|_| ParseError)?,
                )?,
                // io.stat also exposes operation and discard counters.
                _ => {}
            }
        }

        read_total = read_total.checked_add(read_bytes.ok_or(ParseError)?).ok_or(ParseError)?;
        write_total = write_total.checked_add(write_bytes.ok_or(ParseError)?).ok_or(ParseError)?;
        devices += 1;
    }

    if devices == 0 {
        return Err(ParseError);
    }
    Ok((read_total, write_total))
}

fn parse_u64_scalar(content: &str) -> Result<u64, ParseError> {
    content.trim().parse::<u64>().map_err(|_| ParseError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_meminfo_with_byte_conversion() {
        let parsed = parse_meminfo(
            "MemTotal: 32768 kB\nMemAvailable: 8192 kB\nSwapTotal: 65536 kB\nSwapFree: 16384 kB\n",
        ).unwrap();
        assert_eq!(parsed.total_bytes, 32 * 1024 * 1024);
        assert_eq!(parsed.available_bytes, 8 * 1024 * 1024);
        assert_eq!(parsed.swap_total_bytes, Some(64 * 1024 * 1024));
        assert_eq!(parsed.swap_free_bytes, Some(16 * 1024 * 1024));
    }

    #[test]
    fn rejects_inconsistent_or_partial_meminfo() {
        assert!(parse_meminfo("MemTotal: 100 kB\nMemAvailable: 101 kB\n").is_err());
        assert!(parse_meminfo("MemTotal: 100 kB\nSwapTotal: 100 kB\n").is_err());
        assert!(parse_meminfo("MemTotal: 100 MB\nMemAvailable: 20 MB\n").is_err());
    }

    #[test]
    fn parses_cpu_psi_without_full_line() {
        let parsed = parse_psi("some avg10=1.25 avg60=0.75 avg300=0.10 total=900\n").unwrap();
        assert_eq!(parsed.some.avg10, 1.25);
        assert!(parsed.full.is_none());
    }

    #[test]
    fn parses_memory_psi_some_and_full() {
        let parsed = parse_psi(
            "some avg10=0.26 avg60=0.15 avg300=0.08 total=10\nfull avg10=0.07 avg60=0.02 avg300=0.01 total=2\n",
        ).unwrap();
        assert_eq!(parsed.full.unwrap().avg10, 0.07);
    }

    #[test]
    fn rejects_psi_duplicates_invalid_and_non_finite_values() {
        assert!(parse_psi("some avg10=1 avg10=2 avg60=1 avg300=1 total=1\n").is_err());
        assert!(parse_psi("some avg10=101 avg60=1 avg300=1 total=1\n").is_err());
        assert!(parse_psi("some avg10=NaN avg60=1 avg300=1 total=1\n").is_err());
        assert!(parse_psi("some avg10=1 avg60=1 avg300=1\n").is_err());
    }

    #[test]
    fn parses_swap_counters() {
        let parsed = parse_swap_io("pswpin 12\npswpout 34\npgfault 999\n").unwrap();
        assert_eq!(parsed.pages_in, 12);
        assert_eq!(parsed.pages_out, 34);
    }

    #[test]
    fn parses_cpu_usage_usec() {
        assert_eq!(
            parse_cpu_usage_usec("usage_usec 12345\nuser_usec 10000\nsystem_usec 2345\n").unwrap(),
            12345
        );
    }

    #[test]
    fn aggregates_io_bytes_across_devices() {
        let parsed = parse_io_bytes(
            "8:0 rbytes=100 wbytes=200 rios=1 wios=2\n259:0 rbytes=300 wbytes=400 rios=3 wios=4\n",
        ).unwrap();
        assert_eq!(parsed, (400, 600));
    }

    #[test]
    fn rejects_malformed_or_overflowing_io_stats() {
        assert!(parse_io_bytes("device rbytes=1 wbytes=2\n").is_err());
        assert!(parse_io_bytes("8:0 rbytes=1\n").is_err());
        assert!(parse_io_bytes("8:0 rbytes=18446744073709551615 wbytes=0\n8:1 rbytes=1 wbytes=0\n").is_err());
    }

    #[test]
    fn host_snapshot_keeps_source_failures_independent() {
        let proc_root = tempfile::tempdir().unwrap();
        std::fs::write(
            proc_root.path().join("meminfo"),
            "MemTotal: 1024 kB\nMemAvailable: 512 kB\nSwapTotal: 2048 kB\nSwapFree: 1024 kB\n",
        ).unwrap();
        std::fs::write(
            proc_root.path().join("vmstat"),
            "pswpin 7\npswpout 9\n",
        ).unwrap();

        let snapshot = ResourcePressureObserver::with_proc_root(proc_root.path()).snapshot();
        assert_eq!(snapshot.schema_version, RESOURCE_PRESSURE_SCHEMA_VERSION);
        assert_eq!(snapshot.memory.state, EvidenceState::Observed);
        assert_eq!(snapshot.swap_io.state, EvidenceState::Observed);
        assert_eq!(snapshot.cpu_pressure.state, EvidenceState::Unavailable);
        assert_eq!(snapshot.memory_pressure.reason, Some("source-not-found"));
    }

    #[test]
    fn cgroup_observer_preserves_missing_metrics_as_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let group = root.path().join("user.slice/app.slice");
        std::fs::create_dir_all(&group).unwrap();
        std::fs::write(group.join("memory.current"), "4096\n").unwrap();
        std::fs::write(group.join("memory.swap.current"), "512\n").unwrap();
        std::fs::write(group.join("pids.current"), "23\n").unwrap();
        std::fs::write(group.join("cpu.stat"), "usage_usec 900\nuser_usec 700\nsystem_usec 200\n").unwrap();
        std::fs::write(group.join("io.stat"), "8:0 rbytes=100 wbytes=200 rios=1 wios=2\n").unwrap();

        let observed = CgroupV2Observer::with_root(root.path())
            .observe("app-slice", "user.slice/app.slice")
            .unwrap();
        assert_eq!(observed.memory_current_bytes.value, Some(4096));
        assert_eq!(observed.memory_peak_bytes.state, EvidenceState::Unavailable);
        assert_eq!(observed.memory_peak_bytes.reason, Some("source-not-found"));
        assert_eq!(observed.cpu_usage_usec.value, Some(900));
        assert_eq!(observed.io_read_bytes.value, Some(100));
        assert_eq!(observed.io_write_bytes.value, Some(200));
    }

    #[cfg(unix)]
    #[test]
    fn cgroup_observer_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("escape")).unwrap();

        let result = CgroupV2Observer::with_root(root.path()).observe("escaped", "escape");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn labels_and_cgroup_paths_fail_closed() {
        assert!(validate_target_label("app-slice").is_ok());
        assert!(validate_target_label("bad\nlabel").is_err());
        assert!(validate_relative_path(Path::new("user.slice/user-1000.slice")).is_ok());
        assert!(validate_relative_path(Path::new("../etc")).is_err());
        assert!(validate_relative_path(Path::new("/sys/fs/cgroup")).is_err());
    }
}
