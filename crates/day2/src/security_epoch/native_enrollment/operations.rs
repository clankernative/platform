//! Fixed native entrypoint capabilities for the private Roc lifecycle recipe.
//! The workflow sees no key, certificate, PID or transferable native owner.

use crate::automation::{self, Request};
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{path::Path, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

pub(super) fn runner() -> Result<std::path::PathBuf> {
    automation::checked_runner(Path::new("/usr/local/lib/day2/day2-workflows"))
}

pub(super) fn empty(request: &Request) -> Result<()> {
    let _: Empty = request.decode()?;
    Ok(())
}

pub(super) fn run() -> Result<()> {
    let mut provisioner = None;
    automation::run_interactive(&runner()?, &["native-enrollment"], |request| {
        empty(&request)?;
        match request.action.as_str() {
            "native-enrollment-start" => {
                ensure!(provisioner.is_none(), "native_enrollment_already_started");
                provisioner = Some(super::birth::start()?);
            }
            "native-enrollment-current" => {
                provisioner
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("native_enrollment_not_started"))?
                    .check()?;
            }
            "native-enrollment-wait" => {
                ensure!(provisioner.is_some(), "native_enrollment_not_started");
                std::thread::sleep(Duration::from_millis(250));
            }
            _ => anyhow::bail!("native_enrollment_unknown_capability"),
        }
        Ok(Value::Object(Default::default()))
    })?;
    // A stopped recipe drops the retained actual child, even on an unexpected
    // successful completion. No workflow result can keep an issuer alive.
    anyhow::bail!("native_enrollment_recipe_stopped")
}
