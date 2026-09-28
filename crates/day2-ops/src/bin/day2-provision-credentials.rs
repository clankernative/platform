//! One-shot registration of an app's mounted provider credentials.
//!
//!   day2-provision-credentials <operator-instance.json> <app> <operator> <provisioning.json>
//!
//! The same native operations as `day2 platform provision-credentials`
//! (ops/Provision.roc), with no provisioning logic of its own:
//! `provisioning_inputs` checks the reviewed plan against the operator-only
//! instance, the app's resolved grants and signed endpoints, and every mounted
//! secret's fingerprint; each returned mount is then registered in order.
//! Registration is idempotent for an unchanged secret and refuses a changed one,
//! so this may run before every start of the app. It never contacts a provider.
//!
//! This binary ships in the distroless runtime image, which has no shell and no
//! Roc workflow runner, so it calls the capabilities directly in the order the
//! Roc recipe does. On success it prints one JSON summary line; any failure
//! exits non-zero.
#![forbid(unsafe_code)]
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

const USAGE: &str =
    "usage: day2-provision-credentials OPERATOR_INSTANCE_JSON APP OPERATOR PROVISIONING_JSON";

fn run() -> Result<Value> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(arguments.len() == 4, "{USAGE}");
    let text = |index: usize, what: &str| -> Result<String> {
        Ok(arguments[index]
            .to_str()
            .with_context(|| format!("{what} must be UTF-8"))?
            .to_owned())
    };
    let instance = PathBuf::from(&arguments[0]);
    let (app, operator) = (text(1, "app name")?, text(2, "operator")?);
    let plan = PathBuf::from(&arguments[3]);
    let inputs = day2::packaging::provisioning_inputs(&instance, &app, &operator, &plan)?;
    for input in &inputs {
        let mount: day2::integration_host::Mount = day2::json::decode(input.as_bytes())?;
        ensure!(
            mount.expected_fingerprint.is_some(),
            "provisioning_requires_reviewed_fingerprint"
        );
        day2::integration_host::mount(&instance, &operator, &mount)?;
    }
    Ok(json!({"registered": inputs.len(), "provider_qualified": false}))
}

fn main() -> ExitCode {
    match run() {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("day2-provision-credentials: {error:#}");
            ExitCode::FAILURE
        }
    }
}
