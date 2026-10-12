//! CLI entrypoint for the deterministic scenario receipt generator.

use nixward_network_automation_scenario_harness::{evaluate_repository, repository_root};
use std::process::ExitCode;

fn main() -> ExitCode {
    let result = repository_root().and_then(|root| evaluate_repository(&root));
    match result {
        Ok((receipt, bytes)) => {
            match std::io::Write::write_all(&mut std::io::stdout().lock(), &bytes) {
                Ok(()) => {
                    println!();
                    if receipt.receipt.status == "pass" {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(error) => {
                    eprintln!("cannot write scenario receipt: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Err(error) => {
            eprintln!("scenario harness rejected its inputs: {error}");
            ExitCode::from(2)
        }
    }
}
