use nixward_network_observation_verifier::verify_bytes;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("FAIL: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = env::args_os().skip(1);
    let path = args.next().ok_or_else(|| {
        "usage: nixward-network-observation-verifier <envelope.json|->".to_owned()
    })?;
    if args.next().is_some() {
        return Err("exactly one envelope path is accepted".to_owned());
    }

    let mut input = Vec::new();
    if path == "-" {
        io::stdin()
            .read_to_end(&mut input)
            .map_err(|error| format!("cannot read envelope from stdin: {error}"))?;
    } else {
        input = fs::read(&path).map_err(|error| {
            format!(
                "cannot read envelope {}: {error}",
                std::path::PathBuf::from(path).display()
            )
        })?;
    }

    let receipt = verify_bytes(&input)?;
    let output = receipt.serialize_checked()?;
    let decision = receipt.receipt.decision;
    io::stdout()
        .write_all(&output)
        .map_err(|error| format!("cannot write receipt to stdout: {error}"))?;
    io::stdout()
        .flush()
        .map_err(|error| format!("cannot flush receipt: {error}"))?;

    if decision == nixward_network_observation_verifier::Decision::CompleteForDeclaredScope {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}
