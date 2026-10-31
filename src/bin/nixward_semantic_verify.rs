// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only CLI for captured systemd/NixOS semantic evidence.

use std::env;
use std::fs;
use std::process;

fn run() -> Result<i32, String> {
    let mut args = env::args().skip(1);
    let path = match args.next() {
        Some(value) if value == "--input" => args.next().ok_or("--input requires a path")?,
        Some(value) if value == "--help" || value == "-h" => {
            println!("nixward-semantic-verify --input EVIDENCE.json");
            return Ok(0);
        }
        Some(value) => return Err(format!("unknown argument: {value}")),
        None => return Err("--input is required".into()),
    };
    if args.next().is_some() { return Err("unexpected extra arguments".into()); }
    let input = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read evidence {}: {error}", path))?;
    let result = nixward::systemd_semantic_evidence::evaluate_json(&input)?;
    println!("{}", serde_json::to_string_pretty(&result).map_err(|error| error.to_string())?);
    Ok(match result.classification {
        nixward::systemd_semantic_evidence::TerminalClassification::VerifiedSuccess
        | nixward::systemd_semantic_evidence::TerminalClassification::VerifiedRecovery => 0,
        nixward::systemd_semantic_evidence::TerminalClassification::ReconciliationRequired => 3,
        nixward::systemd_semantic_evidence::TerminalClassification::SafeHold => 4,
    })
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(error) => { eprintln!("nixward-semantic-verify: {error}"); process::exit(2); }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_exit_code_contract_is_explicit() {
        let source = include_str!("nixward_semantic_verify.rs");
        assert!(source.contains("TerminalClassification::ReconciliationRequired => 3"));
        assert!(source.contains("TerminalClassification::SafeHold => 4"));
    }
}
