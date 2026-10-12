use std::process::Command;

fn output_version(program: &std::ffi::OsStr, flag: &str, fallback: &str) -> String {
    Command::new(program)
        .arg(flag)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| fallback.to_owned())
}

fn main() {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let rustc_version = output_version(&rustc, "--version", "rustc-version-unavailable");
    let cargo_version = output_version(&cargo, "--version", "cargo-version-unavailable");

    println!("cargo:rustc-env=NIXWARD_SCENARIO_RUSTC_VERSION={rustc_version}");
    println!("cargo:rustc-env=NIXWARD_SCENARIO_CARGO_VERSION={cargo_version}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=CARGO");
}
