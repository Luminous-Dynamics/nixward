// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent OCI runtime observations and temporal consistency checks.
//!
//! A successful snapshot establishes agreement between Podman metadata and
//! host procfs observations across one bounded collection window. It does not
//! authenticate the host, kernel, observer or Podman executable; it does not
//! prove that policy enforcement is active; and it does not establish that
//! these properties remain true after the observation window.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;
use thiserror::Error;

const SNAPSHOT_DOMAIN: &[u8] = b"nixward:oci-runtime-consistency-snapshot:v1\0";
pub const OCI_RUNTIME_OBSERVER_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciRuntimeProfile {
    pub container_id: String,
    pub image_digest: String,
    pub cgroup_path: String,
    pub allowed_effective_capabilities: u64,
}

impl OciRuntimeProfile {
    pub fn validate(&self) -> Result<(), OciRuntimeObservationError> {
        if self.container_id.len() != 64
            || !self.container_id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(OciRuntimeObservationError::InvalidContainerId);
        }
        if !self.image_digest.starts_with("sha256:")
            || self.image_digest.len() != 71
            || !self.image_digest[7..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(OciRuntimeObservationError::InvalidImageDigest);
        }
        if !self.cgroup_path.starts_with('/')
            || self.cgroup_path.contains("/../")
            || self.cgroup_path.ends_with("/..")
            || self.cgroup_path.bytes().any(|b| b.is_ascii_control())
        {
            return Err(OciRuntimeObservationError::InvalidCgroupPath);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdMapEntry {
    pub namespace_id: u32,
    pub host_id: u32,
    pub range: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceInodes {
    pub user: u64,
    pub network: u64,
    pub pid: u64,
    pub mount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PodmanInfoEvidence {
    rootless: bool,
    uid_map: Vec<IdMapEntry>,
    gid_map: Vec<IdMapEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PodmanMountEvidence {
    mount_type: String,
    source: String,
    destination: String,
    read_write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PodmanInspectEvidence {
    container_id: String,
    image_id: String,
    image_name: String,
    running: bool,
    state: String,
    pid: u32,
    network_mode: String,
    pid_mode: String,
    read_only_root: bool,
    privileged: bool,
    mounts: Vec<PodmanMountEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProcfsProcessEvidence {
    pid: u32,
    start_time_ticks: u64,
    real_uid: u32,
    effective_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    effective_capabilities: u64,
    permitted_capabilities: u64,
    bounding_capabilities: u64,
    ambient_capabilities: u64,
    no_new_privileges: bool,
    cgroup_path: String,
    uid_map: Vec<IdMapEntry>,
    gid_map: Vec<IdMapEntry>,
    namespaces: NamespaceInodes,
    host_namespaces: NamespaceInodes,
    root_mount_read_only: bool,
    mount_count: usize,
    podman_declared_mount_count: usize,
    host_network: bool,
    host_pid: bool,
    privileged: bool,
    mountinfo_blake3: String,
    boot_id: String,
    machine_id_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OciRuntimeFrame {
    observer_sequence: u64,
    monotonic_ns: u128,
    podman_binary_blake3: String,
    podman_info: PodmanInfoEvidence,
    podman_inspect: PodmanInspectEvidence,
    procfs: ProcfsProcessEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OciRuntimeConsistencySnapshot {
    schema_version: u32,
    kind: String,
    observer_sequence_start: u64,
    observer_sequence_end: u64,
    observation_interval_ns: u128,
    podman_binary_blake3: String,
    container_id: String,
    image_id: String,
    image_name: String,
    process_pid: u32,
    process_start_time_ticks: u64,
    cgroup_path: String,
    namespaces: NamespaceInodes,
    boot_id: String,
    machine_id_blake3: String,
    root_mount_read_only: bool,
    no_new_privileges: bool,
    effective_capabilities: u64,
    permitted_capabilities: u64,
    bounding_capabilities: u64,
    ambient_capabilities: u64,
    mount_count: usize,
    mountinfo_blake3: String,
    source_agreement: bool,
    stable_across_observation_window: bool,
    runtime_enforcement_proven: bool,
}

impl OciRuntimeConsistencySnapshot {
    pub fn observer_sequence_start(&self) -> u64 { self.observer_sequence_start }
    pub fn observer_sequence_end(&self) -> u64 { self.observer_sequence_end }
    pub fn observation_interval_ns(&self) -> u128 { self.observation_interval_ns }
    pub fn container_id(&self) -> &str { &self.container_id }
    pub fn image_id(&self) -> &str { &self.image_id }
    pub fn process_pid(&self) -> u32 { self.process_pid }
    pub fn process_start_time_ticks(&self) -> u64 { self.process_start_time_ticks }
    pub fn cgroup_path(&self) -> &str { &self.cgroup_path }
    pub fn namespaces(&self) -> &NamespaceInodes { &self.namespaces }
    pub fn boot_id(&self) -> &str { &self.boot_id }
    pub fn machine_id_blake3(&self) -> &str { &self.machine_id_blake3 }
    pub fn podman_binary_blake3(&self) -> &str { &self.podman_binary_blake3 }
    pub fn root_mount_read_only(&self) -> bool { self.root_mount_read_only }
    pub fn no_new_privileges(&self) -> bool { self.no_new_privileges }
    pub fn effective_capabilities(&self) -> u64 { self.effective_capabilities }
    pub fn podman_declared_mount_count(&self) -> usize { self.podman_declared_mount_count }
    pub fn host_network(&self) -> bool { self.host_network }
    pub fn host_pid(&self) -> bool { self.host_pid }
    pub fn privileged(&self) -> bool { self.privileged }
    pub fn source_agreement(&self) -> bool { self.source_agreement }
    pub fn stable_across_observation_window(&self) -> bool { self.stable_across_observation_window }
    pub fn runtime_enforcement_proven(&self) -> bool { self.runtime_enforcement_proven }

    /// Domain-separated commitment to this snapshot. This is not a signature.
    pub fn digest_blake3(&self) -> Result<String, OciRuntimeObservationError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| OciRuntimeObservationError::Serialization)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(SNAPSHOT_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

/// Collects two consecutive snapshots with one process-local monotonic clock.
/// first_sequence must be allocated and persisted by the caller across
/// observer restarts; this method only allocates the adjacent second sequence.
#[cfg(target_os = "linux")]
pub fn collect_live_pair(
    podman_binary: &Path,
    profile: &OciRuntimeProfile,
    first_sequence: u64,
) -> Result<OciRuntimeConsistencySnapshot, OciRuntimeObservationError> {
    profile.validate()?;
    if first_sequence == 0 {
        return Err(OciRuntimeObservationError::InvalidSequence);
    }
    let second_sequence = first_sequence
        .checked_add(1)
        .ok_or(OciRuntimeObservationError::InvalidSequence)?;
    let binary = fs::canonicalize(podman_binary)?;
    if !binary.is_absolute() || !binary.is_file() {
        return Err(OciRuntimeObservationError::InvalidPodmanBinary);
    }
    let origin = Instant::now();
    let before = collect_frame(&binary, profile, first_sequence, &origin)?;
    let after = collect_frame(&binary, profile, second_sequence, &origin)?;
    reconcile_frames(profile, before, after)
}

#[cfg(target_os = "linux")]
fn collect_frame(
    binary: &Path,
    profile: &OciRuntimeProfile,
    sequence: u64,
    origin: &Instant,
) -> Result<OciRuntimeFrame, OciRuntimeObservationError> {
    let (info_bytes, info_binary_hash) = run_podman(binary, &["info", "--format", "json"])?;
    let info = parse_podman_info(&info_bytes)?;
    let (inspect_bytes, inspect_binary_hash) = run_podman(
        binary,
        &["inspect", "--type", "container", &profile.container_id],
    )?;
    if info_binary_hash != inspect_binary_hash {
        return Err(OciRuntimeObservationError::PodmanBinaryChanged);
    }
    let inspect = parse_podman_inspect(&inspect_bytes)?;
    let procfs = collect_procfs_process(inspect.pid)?;
    Ok(OciRuntimeFrame {
        observer_sequence: sequence,
        monotonic_ns: origin.elapsed().as_nanos(),
        podman_binary_blake3: info_binary_hash,
        podman_info: info,
        podman_inspect: inspect,
        procfs,
    })
}

#[cfg(target_os = "linux")]
fn run_podman(
    binary: &Path,
    args: &[&str],
) -> Result<(Vec<u8>, String), OciRuntimeObservationError> {
    let before = hash_file(binary)?;
    let output = Command::new(binary).args(args).output()?;
    let after = hash_file(binary)?;
    if before != after {
        return Err(OciRuntimeObservationError::PodmanBinaryChanged);
    }
    if !output.status.success() {
        return Err(OciRuntimeObservationError::PodmanCommandFailed {
            args: args.join(" "),
            status: output.status.code(),
        });
    }
    Ok((output.stdout, before))
}

#[cfg(target_os = "linux")]
fn collect_procfs_process(pid: u32) -> Result<ProcfsProcessEvidence, OciRuntimeObservationError> {
    if pid <= 1 {
        return Err(OciRuntimeObservationError::InvalidProcessId);
    }
    let proc_root = Path::new("/proc");
    let process = proc_root.join(pid.to_string());
    let status = fs::read_to_string(process.join("status"))?;
    let stat = fs::read_to_string(process.join("stat"))?;
    let cgroup = fs::read_to_string(process.join("cgroup"))?;
    let mountinfo = fs::read_to_string(process.join("mountinfo"))?;
    let uid_map = fs::read_to_string(process.join("uid_map"))?;
    let gid_map = fs::read_to_string(process.join("gid_map"))?;
    let namespaces = read_namespaces(&process.join("ns"))?;
    let host_namespaces = read_namespaces(&proc_root.join("self/ns"))?;
    let boot_id = fs::read_to_string(proc_root.join("sys/kernel/random/boot_id"))?;
    let machine_id = fs::read_to_string("/etc/machine-id")?;
    parse_procfs_evidence(
        pid, &status, &stat, &cgroup, &mountinfo, &uid_map, &gid_map,
        namespaces, host_namespaces, &boot_id, &machine_id,
    )
}

#[cfg(target_os = "linux")]
fn read_namespaces(path: &Path) -> Result<NamespaceInodes, OciRuntimeObservationError> {
    let read = |name: &str| -> Result<String, OciRuntimeObservationError> {
        Ok(fs::read_link(path.join(name))?.to_string_lossy().into_owned())
    };
    parse_namespace_inodes(&read("user")?, &read("net")?, &read("pid")?, &read("mnt")?)
}

fn hash_file(path: &Path) -> Result<String, OciRuntimeObservationError> {
    Ok(blake3::hash(&fs::read(path)?).to_hex().to_string())
}

fn parse_podman_info(raw: &[u8]) -> Result<PodmanInfoEvidence, OciRuntimeObservationError> {
    let value: serde_json::Value = serde_json::from_slice(raw)?;
    let host = object_field(&value, "host")?;
    let security = object_field(host, "security")?;
    let rootless = bool_field(security, "rootless")?;
    let mappings = object_field(host, "idMappings")?;
    let uid_map = parse_podman_id_map(array_field(mappings, "uidmap")?)?;
    let gid_map = parse_podman_id_map(array_field(mappings, "gidmap")?)?;
    if !rootless || uid_map.is_empty() || gid_map.is_empty() {
        return Err(OciRuntimeObservationError::RootlessMappingMissing);
    }
    Ok(PodmanInfoEvidence { rootless, uid_map, gid_map })
}

fn parse_podman_inspect(raw: &[u8]) -> Result<PodmanInspectEvidence, OciRuntimeObservationError> {
    let value: serde_json::Value = serde_json::from_slice(raw)?;
    let object = match &value {
        serde_json::Value::Array(items) if items.len() == 1 => &items[0],
        serde_json::Value::Object(_) => &value,
        _ => return Err(OciRuntimeObservationError::InvalidInspectDocument),
    };
    let state = object_field(object, "state")?;
    let host_config = object_field(object, "hostConfig")?;
    let mounts = array_field(object, "mounts")?
        .iter()
        .map(|mount| {
            Ok(PodmanMountEvidence {
                mount_type: string_field(mount, "type")?.to_owned(),
                source: string_field(mount, "source")?.to_owned(),
                destination: string_field(mount, "destination")?.to_owned(),
                read_write: bool_field(mount, "rw")?,
            })
        })
        .collect::<Result<Vec<_>, OciRuntimeObservationError>>()?;
    Ok(PodmanInspectEvidence {
        container_id: string_field(object, "id")?.to_ascii_lowercase(),
        image_id: string_field(object, "image")?.to_owned(),
        image_name: string_field(object, "imageName")?.to_owned(),
        running: bool_field(state, "running")?,
        state: string_field(state, "status")?.to_ascii_lowercase(),
        pid: number_field(state, "pid")?,
        network_mode: string_field(host_config, "networkMode")?.to_ascii_lowercase(),
        pid_mode: optional_string_field(host_config, "pidMode").unwrap_or_default().to_ascii_lowercase(),
        read_only_root: bool_field(host_config, "readonlyRootfs")?,
        privileged: bool_field(host_config, "privileged")?,
        mounts,
    })
}

fn parse_podman_id_map(
    values: &[serde_json::Value],
) -> Result<Vec<IdMapEntry>, OciRuntimeObservationError> {
    let mut entries = Vec::with_capacity(values.len());
    for item in values {
        entries.push(IdMapEntry {
            namespace_id: number_field(item, "container_id")?,
            host_id: number_field(item, "host_id")?,
            range: number_field(item, "size")?,
        });
    }
    entries.sort_by_key(|e| (e.namespace_id, e.host_id, e.range));
    Ok(entries)
}

fn parse_procfs_evidence(
    pid: u32,
    status: &str,
    stat: &str,
    cgroup: &str,
    mountinfo: &str,
    uid_map: &str,
    gid_map: &str,
    namespaces: NamespaceInodes,
    host_namespaces: NamespaceInodes,
    boot_id: &str,
    machine_id: &str,
) -> Result<ProcfsProcessEvidence, OciRuntimeObservationError> {
    let fields = parse_status(status);
    let uid = integer_quadruple(fields.get("Uid"), "Uid")?;
    let gid = integer_quadruple(fields.get("Gid"), "Gid")?;
    let no_new_privileges = fields.get("NoNewPrivs").map(|v| v == "1").unwrap_or(false);
    if !no_new_privileges {
        return Err(OciRuntimeObservationError::NoNewPrivilegesMissing);
    }
    let (root_mount_read_only, mount_count) = parse_mountinfo(mountinfo)?;
    Ok(ProcfsProcessEvidence {
        pid,
        start_time_ticks: parse_process_start_ticks(stat)?,
        real_uid: uid[0],
        effective_uid: uid[1],
        real_gid: gid[0],
        effective_gid: gid[1],
        effective_capabilities: hex_field(fields.get("CapEff"), "CapEff")?,
        permitted_capabilities: hex_field(fields.get("CapPrm"), "CapPrm")?,
        bounding_capabilities: hex_field(fields.get("CapBnd"), "CapBnd")?,
        ambient_capabilities: hex_field(fields.get("CapAmb"), "CapAmb")?,
        no_new_privileges,
        cgroup_path: parse_unified_cgroup_path(cgroup)?,
        uid_map: parse_proc_id_map(uid_map)?,
        gid_map: parse_proc_id_map(gid_map)?,
        namespaces,
        host_namespaces,
        root_mount_read_only,
        mount_count,
        mountinfo_blake3: blake3::hash(mountinfo.as_bytes()).to_hex().to_string(),
        boot_id: normalize_boot_id(boot_id)?,
        machine_id_blake3: hash_machine_id(machine_id)?,
    })
}

fn reconcile_frames(
    profile: &OciRuntimeProfile,
    before: OciRuntimeFrame,
    after: OciRuntimeFrame,
) -> Result<OciRuntimeConsistencySnapshot, OciRuntimeObservationError> {
    profile.validate()?;
    if before.observer_sequence == 0
        || after.observer_sequence <= before.observer_sequence
        || after.monotonic_ns <= before.monotonic_ns
    {
        return Err(OciRuntimeObservationError::ObservationOrderInvalid);
    }
    validate_frame(profile, &before)?;
    validate_frame(profile, &after)?;
    let mut normalized_after = after.clone();
    normalized_after.observer_sequence = before.observer_sequence;
    normalized_after.monotonic_ns = before.monotonic_ns;
    if before != normalized_after {
        return Err(OciRuntimeObservationError::IdentityChangedDuringObservation);
    }
    let procfs = &after.procfs;
    Ok(OciRuntimeConsistencySnapshot {
        schema_version: OCI_RUNTIME_OBSERVER_SCHEMA_VERSION,
        kind: "nixward-oci-runtime-consistency-v1".into(),
        observer_sequence_start: before.observer_sequence,
        observer_sequence_end: after.observer_sequence,
        observation_interval_ns: after.monotonic_ns - before.monotonic_ns,
        podman_binary_blake3: after.podman_binary_blake3,
        container_id: after.podman_inspect.container_id,
        image_id: after.podman_inspect.image_id,
        image_name: after.podman_inspect.image_name,
        process_pid: procfs.pid,
        process_start_time_ticks: procfs.start_time_ticks,
        cgroup_path: procfs.cgroup_path.clone(),
        namespaces: procfs.namespaces.clone(),
        boot_id: procfs.boot_id.clone(),
        machine_id_blake3: procfs.machine_id_blake3.clone(),
        root_mount_read_only: procfs.root_mount_read_only,
        no_new_privileges: procfs.no_new_privileges,
        effective_capabilities: procfs.effective_capabilities,
        permitted_capabilities: procfs.permitted_capabilities,
        bounding_capabilities: procfs.bounding_capabilities,
        ambient_capabilities: procfs.ambient_capabilities,
        mount_count: procfs.mount_count,
        podman_declared_mount_count: after.podman_inspect.mounts.len(),
        host_network: after.podman_inspect.network_mode == "host",
        host_pid: after.podman_inspect.pid_mode == "host",
        privileged: after.podman_inspect.privileged,
        mountinfo_blake3: procfs.mountinfo_blake3.clone(),
        source_agreement: true,
        stable_across_observation_window: true,
        runtime_enforcement_proven: false,
    })
}

fn validate_frame(
    profile: &OciRuntimeProfile,
    frame: &OciRuntimeFrame,
) -> Result<(), OciRuntimeObservationError> {
    let inspect = &frame.podman_inspect;
    let info = &frame.podman_info;
    let procfs = &frame.procfs;
    if inspect.container_id != profile.container_id.to_ascii_lowercase()
        || inspect.image_id != profile.image_digest
        || !inspect.running
        || inspect.state != "running"
        || inspect.pid != procfs.pid
    {
        return Err(OciRuntimeObservationError::ContainerIdentityMismatch);
    }
    if !info.rootless || info.uid_map != procfs.uid_map || info.gid_map != procfs.gid_map {
        return Err(OciRuntimeObservationError::RootlessMappingMismatch);
    }
    if !inspect.read_only_root || !procfs.root_mount_read_only {
        return Err(OciRuntimeObservationError::RootFilesystemWritable);
    }
    if inspect.privileged || !inspect.mounts.is_empty()
        || inspect.network_mode == "host" || inspect.pid_mode == "host"
    {
        return Err(OciRuntimeObservationError::UnsafeContainerConfiguration);
    }
    if procfs.namespaces.user == procfs.host_namespaces.user
        || procfs.namespaces.network == procfs.host_namespaces.network
        || procfs.namespaces.pid == procfs.host_namespaces.pid
        || procfs.namespaces.mount == procfs.host_namespaces.mount
    {
        return Err(OciRuntimeObservationError::HostNamespaceShared);
    }
    if procfs.cgroup_path != profile.cgroup_path {
        return Err(OciRuntimeObservationError::CgroupMismatch);
    }
    if !procfs.no_new_privileges
        || procfs.effective_capabilities & !profile.allowed_effective_capabilities != 0
    {
        return Err(OciRuntimeObservationError::ExcessiveProcessAuthority);
    }
    if procfs.start_time_ticks == 0 || procfs.machine_id_blake3.len() != 64
        || procfs.boot_id.is_empty() || frame.podman_binary_blake3.len() != 64
        || procfs.mountinfo_blake3.len() != 64 || procfs.mount_count == 0
    {
        return Err(OciRuntimeObservationError::IncompleteEvidence);
    }
    Ok(())
}

fn object_field<'a>(
    value: &'a serde_json::Value,
    name: &str,
) -> Result<&'a serde_json::Value, OciRuntimeObservationError> {
    value.as_object()
        .and_then(|o| o.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v))
        .ok_or_else(|| OciRuntimeObservationError::MissingJsonField(name.into()))
}
fn array_field<'a>(
    value: &'a serde_json::Value,
    name: &str,
) -> Result<&'a Vec<serde_json::Value>, OciRuntimeObservationError> {
    object_field(value, name)?.as_array()
        .ok_or_else(|| OciRuntimeObservationError::InvalidJsonField(name.into()))
}
fn string_field<'a>(
    value: &'a serde_json::Value,
    name: &str,
) -> Result<&'a str, OciRuntimeObservationError> {
    object_field(value, name)?.as_str()
        .ok_or_else(|| OciRuntimeObservationError::InvalidJsonField(name.into()))
}
fn optional_string_field(value: &serde_json::Value, name: &str) -> Option<String> {
    value.as_object()?.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.as_str()).map(str::to_owned)
}
fn bool_field(
    value: &serde_json::Value,
    name: &str,
) -> Result<bool, OciRuntimeObservationError> {
    object_field(value, name)?.as_bool()
        .ok_or_else(|| OciRuntimeObservationError::InvalidJsonField(name.into()))
}
fn number_field<T: TryFrom<u64>>(
    value: &serde_json::Value,
    name: &str,
) -> Result<T, OciRuntimeObservationError> {
    let n = object_field(value, name)?.as_u64()
        .ok_or_else(|| OciRuntimeObservationError::InvalidJsonField(name.into()))?;
    T::try_from(n).map_err(|_| OciRuntimeObservationError::InvalidJsonField(name.into()))
}

fn parse_status(status: &str) -> BTreeMap<String, String> {
    status.lines().filter_map(|line| {
        let (k, v) = line.split_once(':')?;
        Some((k.trim().to_owned(), v.trim().to_owned()))
    }).collect()
}
fn integer_quadruple(value: Option<&String>, name: &str) -> Result<[u32; 4], OciRuntimeObservationError> {
    let value = value.ok_or_else(|| OciRuntimeObservationError::MissingProcField(name.into()))?;
    let items = value.split_whitespace()
        .map(|s| s.parse::<u32>().map_err(|_| OciRuntimeObservationError::InvalidProcField(name.into())))
        .collect::<Result<Vec<_>, _>>()?;
    if items.len() != 4 { return Err(OciRuntimeObservationError::InvalidProcField(name.into())); }
    Ok([items[0], items[1], items[2], items[3]])
}
fn hex_field(value: Option<&String>, name: &str) -> Result<u64, OciRuntimeObservationError> {
    let value = value.ok_or_else(|| OciRuntimeObservationError::MissingProcField(name.into()))?;
    u64::from_str_radix(value, 16)
        .map_err(|_| OciRuntimeObservationError::InvalidProcField(name.into()))
}
fn parse_process_start_ticks(stat: &str) -> Result<u64, OciRuntimeObservationError> {
    // comm is parenthesized and may contain spaces or ')'; use its final ')'.
    let close = stat.rfind(')').ok_or(OciRuntimeObservationError::InvalidProcessStat)?;
    let fields: Vec<&str> = stat.get(close + 1..)
        .ok_or(OciRuntimeObservationError::InvalidProcessStat)?
        .split_whitespace().collect();
    fields.get(19).ok_or(OciRuntimeObservationError::InvalidProcessStat)?
        .parse().map_err(|_| OciRuntimeObservationError::InvalidProcessStat)
}
fn parse_unified_cgroup_path(cgroup: &str) -> Result<String, OciRuntimeObservationError> {
    let mut paths = cgroup.lines().filter_map(|line| {
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        (hierarchy == "0" && controllers.is_empty()).then(|| path.to_owned())
    });
    let path = paths.next().ok_or(OciRuntimeObservationError::UnifiedCgroupMissing)?;
    if paths.next().is_some() || !path.starts_with('/') {
        return Err(OciRuntimeObservationError::InvalidCgroup);
    }
    Ok(path)
}
fn parse_mountinfo(mountinfo: &str) -> Result<(bool, usize), OciRuntimeObservationError> {
    let mut mount_ids = std::collections::BTreeSet::new();
    let mut root_read_only = None;
    let mut mount_count = 0usize;

    for line in mountinfo.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let separator = fields.iter().position(|field| *field == "-")
            .ok_or(OciRuntimeObservationError::InvalidMountInfo)?;
        if separator < 6 || separator + 3 >= fields.len() {
            return Err(OciRuntimeObservationError::InvalidMountInfo);
        }
        let mount_id = fields[0].parse::<u32>()
            .map_err(|_| OciRuntimeObservationError::InvalidMountInfo)?;
        let _parent_id = fields[1].parse::<u32>()
            .map_err(|_| OciRuntimeObservationError::InvalidMountInfo)?;
        let (major, minor) = fields[2].split_once(':')
            .ok_or(OciRuntimeObservationError::InvalidMountInfo)?;
        major.parse::<u32>().map_err(|_| OciRuntimeObservationError::InvalidMountInfo)?;
        minor.parse::<u32>().map_err(|_| OciRuntimeObservationError::InvalidMountInfo)?;
        if !mount_ids.insert(mount_id) {
            return Err(OciRuntimeObservationError::DuplicateMountId);
        }
        let root = fields[3];
        let mount_point = fields[4];
        if root.is_empty() || mount_point.is_empty()
            || fields[separator + 1].is_empty()
            || fields[separator + 2].is_empty()
        {
            return Err(OciRuntimeObservationError::InvalidMountInfo);
        }
        if mount_point == "/" {
            let read_only = fields[5].split(',').any(|option| option == "ro");
            if root_read_only.replace(read_only).is_some() {
                return Err(OciRuntimeObservationError::AmbiguousRootMount);
            }
        }
        mount_count += 1;
    }

    if mount_count == 0 {
        return Err(OciRuntimeObservationError::IncompleteEvidence);
    }
    let root = root_read_only.ok_or(OciRuntimeObservationError::RootMountMissing)?;
    Ok((root, mount_count))
}
fn parse_proc_id_map(raw: &str) -> Result<Vec<IdMapEntry>, OciRuntimeObservationError> {
    let mut entries = Vec::new();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let values = line.split_whitespace()
            .map(|v| v.parse::<u32>().map_err(|_| OciRuntimeObservationError::InvalidIdMap))
            .collect::<Result<Vec<_>, _>>()?;
        if values.len() != 3 || values[2] == 0 {
            return Err(OciRuntimeObservationError::InvalidIdMap);
        }
        entries.push(IdMapEntry { namespace_id: values[0], host_id: values[1], range: values[2] });
    }
    entries.sort_by_key(|e| (e.namespace_id, e.host_id, e.range));
    if entries.is_empty() { return Err(OciRuntimeObservationError::InvalidIdMap); }
    Ok(entries)
}
fn parse_podman_id_map(values: &[serde_json::Value]) -> Result<Vec<IdMapEntry>, OciRuntimeObservationError> {
    let mut entries = Vec::with_capacity(values.len());
    for item in values {
        entries.push(IdMapEntry {
            namespace_id: number_field(item, "container_id")?,
            host_id: number_field(item, "host_id")?,
            range: number_field(item, "size")?,
        });
    }
    entries.sort_by_key(|e| (e.namespace_id, e.host_id, e.range));
    Ok(entries)
}
fn parse_namespace_inodes(
    user: &str, network: &str, pid: &str, mount: &str,
) -> Result<NamespaceInodes, OciRuntimeObservationError> {
    Ok(NamespaceInodes {
        user: parse_namespace_inode(user, "user")?,
        network: parse_namespace_inode(network, "net")?,
        pid: parse_namespace_inode(pid, "pid")?,
        mount: parse_namespace_inode(mount, "mnt")?,
    })
}
fn parse_namespace_inode(value: &str, kind: &str) -> Result<u64, OciRuntimeObservationError> {
    let prefix = format!("{kind}:[");
    let number = value.strip_prefix(&prefix).and_then(|v| v.strip_suffix(']'))
        .ok_or(OciRuntimeObservationError::InvalidNamespaceLink)?;
    number.parse().map_err(|_| OciRuntimeObservationError::InvalidNamespaceLink)
}
fn normalize_boot_id(value: &str) -> Result<String, OciRuntimeObservationError> {
    let value = value.trim().to_ascii_lowercase();
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 5 || parts.iter().map(|part| part.len()).sum::<usize>() != 32
        || !parts.concat().bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(OciRuntimeObservationError::InvalidHostIdentity);
    }
    Ok(value)
}
fn hash_machine_id(value: &str) -> Result<String, OciRuntimeObservationError> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(OciRuntimeObservationError::InvalidHostIdentity);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nixward:host-machine-id:v1\0");
    hasher.update(value.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
pub(crate) fn test_fixture_for_contract(
    image_id: &str,
) -> OciRuntimeConsistencySnapshot {
    OciRuntimeConsistencySnapshot {
        schema_version: OCI_RUNTIME_OBSERVER_SCHEMA_VERSION,
        kind: "nixward-oci-runtime-consistency-v1".into(),
        observer_sequence_start: 10,
        observer_sequence_end: 11,
        observation_interval_ns: 100,
        podman_binary_blake3: "a".repeat(64),
        container_id: "c".repeat(64),
        image_id: image_id.to_owned(),
        image_name: "registry.invalid/worker:fixture".into(),
        process_pid: 4242,
        process_start_time_ticks: 123456,
        cgroup_path: "/machine.slice/agent-task.scope".into(),
        namespaces: NamespaceInodes { user: 1001, network: 1002, pid: 1003, mount: 1004 },
        boot_id: "11111111-2222-3333-4444-555555555555".into(),
        machine_id_blake3: "d".repeat(64),
        root_mount_read_only: true,
        no_new_privileges: true,
        effective_capabilities: 0,
        permitted_capabilities: 0,
        bounding_capabilities: 0,
        ambient_capabilities: 0,
        mount_count: 7,
        podman_declared_mount_count: 0,
        host_network: false,
        host_pid: false,
        privileged: false,
        mountinfo_blake3: "e".repeat(64),
        source_agreement: true,
        stable_across_observation_window: true,
        runtime_enforcement_proven: false,
    }
}

#[derive(Debug, Error)]
pub enum OciRuntimeObservationError {
    #[error("invalid immutable OCI container ID")] InvalidContainerId,
    #[error("invalid immutable OCI image digest")] InvalidImageDigest,
    #[error("invalid expected cgroup path")] InvalidCgroupPath,
    #[error("invalid observer sequence")] InvalidSequence,
    #[error("Podman binary must be an absolute regular file")] InvalidPodmanBinary,
    #[error("Podman command failed: {args}, status {status:?}")] PodmanCommandFailed { args: String, status: Option<i32> },
    #[error("Podman executable changed while collecting evidence")] PodmanBinaryChanged,
    #[error("Podman inspect must identify exactly one container")] InvalidInspectDocument,
    #[error("missing JSON field {0}")] MissingJsonField(String),
    #[error("invalid JSON field {0}")] InvalidJsonField(String),
    #[error("missing procfs field {0}")] MissingProcField(String),
    #[error("invalid procfs field {0}")] InvalidProcField(String),
    #[error("rootless user/group mapping evidence is missing")] RootlessMappingMissing,
    #[error("Podman and procfs user/group mappings disagree")] RootlessMappingMismatch,
    #[error("container identity does not match expected ID, image or PID")] ContainerIdentityMismatch,
    #[error("root filesystem is not read-only in both sources")] RootFilesystemWritable,
    #[error("privileged, host-network/PID or unexpected mount configuration")] UnsafeContainerConfiguration,
    #[error("container shares a host user/network/PID/mount namespace")] HostNamespaceShared,
    #[error("live process cgroup differs from the expected task cgroup")] CgroupMismatch,
    #[error("no_new_privs absent or effective capabilities exceed profile")] ExcessiveProcessAuthority,
    #[error("no_new_privs is not set")] NoNewPrivilegesMissing,
    #[error("host boot or machine identity is invalid")] InvalidHostIdentity,
    #[error("procfs or Podman evidence is incomplete")] IncompleteEvidence,
    #[error("process ID is invalid")] InvalidProcessId,
    #[error("cannot parse /proc/<pid>/stat start time")] InvalidProcessStat,
    #[error("unified cgroup v2 path missing")] UnifiedCgroupMissing,
    #[error("cgroup evidence invalid")] InvalidCgroup,
    #[error("root mount missing")] RootMountMissing,
    #[error("multiple root mounts found")] AmbiguousRootMount,
    #[error("malformed or incomplete mountinfo record")] InvalidMountInfo,
    #[error("duplicate mount ID in mountinfo")] DuplicateMountId,
    #[error("UID/GID mapping invalid")] InvalidIdMap,
    #[error("namespace link does not contain an inode identity")] InvalidNamespaceLink,
    #[error("observation sequence or monotonic clock order invalid")] ObservationOrderInvalid,
    #[error("container/process/namespace/cgroup identity changed during observation")] IdentityChangedDuringObservation,
    #[error("serialization failed")] Serialization,
    #[error("I/O error: {0}")] Io(#[from] std::io::Error),
    #[error("JSON error: {0}")] Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> String {
        [
            "Name:\tworker", "Uid:\t1000\t1000\t1000\t1000",
            "Gid:\t1000\t1000\t1000\t1000", "CapEff:\t0000000000000000",
            "CapPrm:\t0000000000000000", "CapBnd:\t0000000000000000",
            "CapAmb:\t0000000000000000", "NoNewPrivs:\t1",
        ].join("\n")
    }
    fn stat(start: u64) -> String {
        let mut fields = vec!["0".to_owned(); 20];
        fields[0] = "S".to_owned();
        fields[19] = start.to_string();
        format!("4242 (agent worker)) {}\n", fields.join(" "))
    }
    fn info() -> Vec<u8> {
        br#"{"host":{"security":{"rootless":true},"idMappings":{"uidmap":[{"container_id":0,"host_id":100000,"size":65536}],"gidmap":[{"container_id":0,"host_id":100000,"size":65536}]}}}"#.to_vec()
    }
    fn inspect(container: &str) -> Vec<u8> {
        format!(
            r#"[{{"Id":"{container}","Image":"sha256:{}","ImageName":"registry.invalid/worker:fixture","State":{{"Status":"running","Running":true,"Pid":4242}},"HostConfig":{{"NetworkMode":"bridge","PidMode":"private","ReadonlyRootfs":true,"Privileged":false}},"Mounts":[]}}]"#,
            "b".repeat(64)
        ).into_bytes()
    }
    fn procfs(pid: u32, start: u64) -> ProcfsProcessEvidence {
        parse_procfs_evidence(
            pid, &status(), &stat(start),
            "0::/machine.slice/agent-task.scope\n",
            "36 25 0:32 / / ro,relatime - overlay overlay rw,lowerdir=/lower\n",
            "0 100000 65536\n", "0 100000 65536\n",
            NamespaceInodes { user: 1001, network: 1002, pid: 1003, mount: 1004 },
            NamespaceInodes { user: 1, network: 2, pid: 3, mount: 4 },
            "11111111-2222-3333-4444-555555555555",
            "0123456789abcdef0123456789abcdef",
        ).unwrap()
    }
    fn frame(seq: u64, time: u128, start: u64, container: &str) -> OciRuntimeFrame {
        OciRuntimeFrame {
            observer_sequence: seq,
            monotonic_ns: time,
            podman_binary_blake3: "a".repeat(64),
            podman_info: parse_podman_info(&info()).unwrap(),
            podman_inspect: parse_podman_inspect(&inspect(container)).unwrap(),
            procfs: procfs(4242, start),
        }
    }
    fn profile() -> OciRuntimeProfile {
        OciRuntimeProfile {
            container_id: "a".repeat(64),
            image_digest: format!("sha256:{}", "b".repeat(64)),
            cgroup_path: "/machine.slice/agent-task.scope".into(),
            allowed_effective_capabilities: 0,
        }
    }

    #[test]
    fn parses_exact_podman_inspect_identity() {
        let parsed = parse_podman_inspect(&inspect(&"a".repeat(64))).unwrap();
        assert_eq!(parsed.container_id, "a".repeat(64));
        assert_eq!(parsed.pid, 4242);
        assert!(parsed.read_only_root);
        assert!(parsed.mounts.is_empty());
    }
    #[test]
    fn rejects_multiple_containers_in_inspect_document() {
        let one = String::from_utf8(inspect(&"a".repeat(64))).unwrap();
        let two = String::from_utf8(inspect(&"c".repeat(64))).unwrap();
        let raw = format!("{},{}", one.trim().trim_start_matches('[').trim_end_matches(']'),
            two.trim().trim_start_matches('[').trim_end_matches(']'));
        assert!(matches!(parse_podman_inspect(format!("[{raw}]").as_bytes()),
            Err(OciRuntimeObservationError::InvalidInspectDocument)));
    }
    #[test]
    fn requires_rootless_uid_and_gid_mappings() {
        let invalid = br#"{"host":{"security":{"rootless":false},"idMappings":{"uidmap":[],"gidmap":[]}}}"#;
        assert!(matches!(parse_podman_info(invalid), Err(OciRuntimeObservationError::RootlessMappingMissing)));
    }
    #[test]
    fn parses_process_start_time_with_parentheses_in_comm() {
        assert_eq!(parse_process_start_ticks(&stat(98765)).unwrap(), 98765);
    }
    #[test]
    fn requires_no_new_privileges() {
        let bad = status().replace("NoNewPrivs:\t1", "NoNewPrivs:\t0");
        assert!(matches!(
            parse_procfs_evidence(4242, &bad, &stat(42), "0::/x\n",
                "1 1 0:1 / / ro - overlay overlay rw\n", "0 100000 10\n", "0 100000 10\n",
                NamespaceInodes { user: 2, network: 3, pid: 4, mount: 5 },
                NamespaceInodes { user: 1, network: 1, pid: 1, mount: 1 },
                "11111111-2222-3333-4444-555555555555", "0123456789abcdef0123456789abcdef"),
            Err(OciRuntimeObservationError::NoNewPrivilegesMissing)));
    }
    #[test]
    fn parses_read_only_root_mount() {
        assert!(parse_mountinfo("1 1 0:1 / / ro,relatime - overlay overlay rw\n").unwrap().0);
        assert!(!parse_mountinfo("1 1 0:1 / / rw,relatime - overlay overlay rw\n").unwrap().0);
    }
    #[test]
    fn rejects_duplicate_mount_ids() {
        let raw = concat!(
            "1 1 0:1 / / ro - overlay overlay rw\n",
            "1 1 0:2 / /proc rw - proc proc rw\n"
        );
        assert!(matches!(parse_mountinfo(raw), Err(OciRuntimeObservationError::DuplicateMountId)));
    }

    #[test]
    fn rejects_malformed_mountinfo_records() {
        assert!(matches!(parse_mountinfo("not a mount record\n"),
            Err(OciRuntimeObservationError::InvalidMountInfo)));
    }

    #[test]
    fn rejects_non_unified_cgroup_data() {
        assert!(matches!(parse_unified_cgroup_path("2:cpu:/legacy\n"),
            Err(OciRuntimeObservationError::UnifiedCgroupMissing)));
    }
    #[test]
    fn rejects_invalid_namespace_inode() {
        assert!(matches!(parse_namespace_inode("net:[bad]", "net"),
            Err(OciRuntimeObservationError::InvalidNamespaceLink)));
    }
    #[test]
    fn rejects_invalid_machine_identity() {
        assert!(matches!(hash_machine_id("not-a-machine-id"),
            Err(OciRuntimeObservationError::InvalidHostIdentity)));
    }
    #[test]
    fn validates_profile_identity() {
        assert!(profile().validate().is_ok());
        let mut invalid = profile();
        invalid.container_id = "agent".into();
        assert!(matches!(invalid.validate(), Err(OciRuntimeObservationError::InvalidContainerId)));
    }
    #[test]
    fn accepts_consistent_multi_source_pair() {
        let snapshot = reconcile_frames(&profile(), frame(10, 100, 4242, &"a".repeat(64)),
            frame(11, 200, 4242, &"a".repeat(64))).unwrap();
        assert!(snapshot.source_agreement);
        assert!(snapshot.stable_across_observation_window);
        assert!(!snapshot.runtime_enforcement_proven);
        assert_eq!(snapshot.observation_interval_ns, 100);
        assert_eq!(snapshot.digest_blake3().unwrap().len(), 64);
    }
    #[test]
    fn rejects_pid_reuse_between_observations() {
        assert!(matches!(reconcile_frames(&profile(),
            frame(10, 100, 4242, &"a".repeat(64)), frame(11, 200, 7777, &"a".repeat(64))),
            Err(OciRuntimeObservationError::IdentityChangedDuringObservation)));
    }
    #[test]
    fn rejects_container_replacement_between_observations() {
        assert!(matches!(reconcile_frames(&profile(),
            frame(10, 100, 4242, &"a".repeat(64)), frame(11, 200, 4242, &"c".repeat(64))),
            Err(OciRuntimeObservationError::ContainerIdentityMismatch)));
    }
    #[test]
    fn rejects_non_increasing_observer_sequence() {
        assert!(matches!(reconcile_frames(&profile(),
            frame(11, 100, 4242, &"a".repeat(64)), frame(11, 200, 4242, &"a".repeat(64))),
            Err(OciRuntimeObservationError::ObservationOrderInvalid)));
    }
    #[test]
    fn rejects_shared_host_network_namespace() {
        let mut after = frame(11, 200, 4242, &"a".repeat(64));
        after.procfs.namespaces.network = after.procfs.host_namespaces.network;
        assert!(matches!(reconcile_frames(&profile(),
            frame(10, 100, 4242, &"a".repeat(64)), after),
            Err(OciRuntimeObservationError::HostNamespaceShared)));
    }
    #[test]
    fn rejects_effective_capability_expansion() {
        let mut after = frame(11, 200, 4242, &"a".repeat(64));
        after.procfs.effective_capabilities = 1;
        assert!(matches!(reconcile_frames(&profile(),
            frame(10, 100, 4242, &"a".repeat(64)), after),
            Err(OciRuntimeObservationError::ExcessiveProcessAuthority)));
    }
}
