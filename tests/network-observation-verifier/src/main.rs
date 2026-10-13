use nixward_network_observation_verifier::{verify_bytes_for_target, TargetIdentity};
use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::ExitCode;

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

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
    let mut target_id: Option<String> = None;
    let mut boot_id: Option<String> = None;
    let mut netns_inode: Option<u64> = None;
    let mut path: Option<String> = None;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target-id" => set_once(
                &mut target_id,
                args.next().ok_or_else(usage)?,
                "target ID",
            )?,
            "--boot-id" => set_once(
                &mut boot_id,
                args.next().ok_or_else(usage)?,
                "boot ID",
            )?,
            "--netns-inode" => {
                if netns_inode.is_some() {
                    return Err("duplicate --netns-inode argument".to_owned());
                }
                let value = args.next().ok_or_else(usage)?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| "--netns-inode must be a positive integer".to_owned())?;
                if parsed == 0 {
                    return Err("--netns-inode must be a positive integer".to_owned());
                }
                netns_inode = Some(parsed);
            }
            value if value.starts_with('-') && value != "-" => {
                return Err(format!("unknown option: {value}"));
            }
            value => {
                if path.replace(value.to_owned()).is_some() {
                    return Err("exactly one envelope path is accepted".to_owned());
                }
            }
        }
    }

    let expected_target = TargetIdentity {
        target_id: target_id.ok_or_else(usage)?,
        boot_id: boot_id.ok_or_else(usage)?,
        network_namespace_inode: netns_inode.ok_or_else(usage)?,
    };
    let path = path.ok_or_else(usage)?;

    let input = if path == "-" {
        read_bounded(io::stdin())?
    } else {
        let file = File::open(&path).map_err(|error| format!("cannot open envelope {path}: {error}"))?;
        read_bounded(file)?
    };

    let receipt = verify_bytes_for_target(&input, &expected_target)?;
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

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, String> {
    let mut input = Vec::new();
    reader
        .by_ref()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|error| format!("cannot read evidence envelope: {error}"))?;
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("evidence envelope exceeds {MAX_INPUT_BYTES}-byte input limit"));
    }
    Ok(input)
}

fn set_once(
    slot: &mut Option<String>,
    value: String,
    label: &str,
) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate argument for {label}"));
    }
    Ok(())
}

fn usage() -> String {
    "usage: nixward-network-observation-verifier --target-id ID --boot-id BOOT_ID --netns-inode INODE <envelope.json|->".to_owned()
}
