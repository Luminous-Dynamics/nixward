use std::process::Command;

fn main() {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| "rustc-version-unavailable".to_owned());

    println!("cargo:rustc-env=NIXWARD_SCENARIO_RUSTC_VERSION={version}");
    println!("cargo:rerun-if-changed=build.rs");
}
