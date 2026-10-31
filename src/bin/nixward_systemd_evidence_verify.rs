// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only CLI for the systemd/NixOS semantic evidence evaluator.
use nixward::systemd_evidence::{verify_execution, SystemdExecutionEvidence, TerminalOutcome};
use std::{env, fs, path::PathBuf, process};

fn run() -> Result<i32,String> {
    let mut args=env::args().skip(1);
    let mut input:Option<PathBuf>=None;
    while let Some(arg)=args.next() {
        match arg.as_str() {
            "--input" => input=args.next().map(PathBuf::from),
            "--help" | "-h" => { println!("nixward-systemd-evidence-verify --input EVIDENCE.json"); process::exit(0); }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let path=input.ok_or("--input is required")?;
    let bytes=fs::read(&path).map_err(|e|format!("cannot read {}: {e}",path.display()))?;
    let evidence:SystemdExecutionEvidence=serde_json::from_slice(&bytes).map_err(|e|format!("invalid evidence JSON: {e}"))?;
    let report=verify_execution(&evidence);
    println!("{}",serde_json::to_string_pretty(&report).map_err(|e|e.to_string())?);
    Ok(match report.outcome {
        TerminalOutcome::VerifiedSuccess=>0,
        TerminalOutcome::VerifiedRecovery=>10,
        TerminalOutcome::ReconciliationRequired=>20,
        TerminalOutcome::SafeHold=>30,
    })
}
fn main() {
    match run() {
        Ok(code)=>process::exit(code),
        Err(error)=>{eprintln!("nixward-systemd-evidence-verify: {error}");process::exit(2);}
    }
}
