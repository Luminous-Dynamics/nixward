use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("Cargo sets manifest dir"));
    let repository_root = manifest_dir.join("../..");
    let tracked_inputs = [
        ("Cargo.toml", manifest_dir.join("Cargo.toml")),
        ("Cargo.lock", manifest_dir.join("Cargo.lock")),
        ("build.rs", manifest_dir.join("build.rs")),
        ("src/lib.rs", manifest_dir.join("src/lib.rs")),
        ("src/main.rs", manifest_dir.join("src/main.rs")),
        (
            "src/bin/emit_synthetic_evidence.rs",
            manifest_dir.join("src/bin/emit_synthetic_evidence.rs"),
        ),
        (
            "docs/NETWORK_OBSERVATION_ENVELOPE_V1.schema.json",
            repository_root.join("docs/NETWORK_OBSERVATION_ENVELOPE_V1.schema.json"),
        ),
        (
            "docs/NETWORK_OBSERVATION_VERIFIER_RECEIPT_V1.schema.json",
            repository_root.join("docs/NETWORK_OBSERVATION_VERIFIER_RECEIPT_V1.schema.json"),
        ),
    ];

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nixward.network-observation-verifier-source.v1\0");
    for (label, path) in tracked_inputs {
        println!("cargo:rerun-if-changed={}", path.display());
        let contents = fs::read(&path)
            .unwrap_or_else(|error| panic!("cannot hash verifier source {}: {error}", path.display()));
        hasher.update(&(label.len() as u32).to_le_bytes());
        hasher.update(label.as_bytes());
        hasher.update(&(contents.len() as u64).to_le_bytes());
        hasher.update(&contents);
    }
    println!("cargo:rustc-env=NIXWARD_VERIFIER_SOURCE_DIGEST={}", hasher.finalize().to_hex());

    println!("cargo:rerun-if-env-changed=NIXWARD_GIT_COMMIT");
    let revision = env::var("NIXWARD_GIT_COMMIT").unwrap_or_else(|_| "unbound-build".to_owned());
    println!("cargo:rustc-env=NIXWARD_VERIFIER_SOURCE_REVISION={revision}");
}
