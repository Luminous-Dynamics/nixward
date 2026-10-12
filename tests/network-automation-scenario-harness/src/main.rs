//! CLI entrypoint for the deterministic scenario receipt generator.

use nixward_network_automation_scenario_harness::{evaluate_repository, repository_root};
use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let result = repository_root().and_then(|root| evaluate_repository(&root));
    match result {
        Ok((receipt, bytes)) => {
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            if let Err(error) = output.write_all(&bytes).and_then(|_| output.write_all(b"\n")) {
                eprintln!("cannot write scenario receipt: {error}");
                return ExitCode::from(2);
            }
            if receipt.receipt.status == "pass" {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(error) => {
            eprintln!("scenario harness rejected its inputs: {error}");
            ExitCode::from(2)
        }
    }
}
