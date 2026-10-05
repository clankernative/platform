//! Explicit operator approval and bounded execution of the normal release recipe.
use anyhow::{Result, ensure};
use day2_control::{
    gke_release_driver::{self, Configuration},
    provider_conformance::FileToken,
};
use std::{path::PathBuf, sync::Arc};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() >= 2,
        "usage: day2-gke-release prepare CONFIG SOURCE TOOLCHAINS QUALIFIED | approve CONFIG | run CONFIG TOKEN_FILE"
    );
    let configuration = Configuration::load(&PathBuf::from(&args[1]))?;
    let value = match args[0].to_str() {
        Some("prepare") if args.len() == 5 => day2_control::qualified_release_build::prepare(
            configuration,
            &PathBuf::from(&args[2]),
            &PathBuf::from(&args[3]),
            &PathBuf::from(&args[4]),
        )?,
        Some("approve") if args.len() == 2 => configuration.approve()?,
        Some("run") if args.len() == 3 => gke_release_driver::run(
            configuration,
            Arc::new(FileToken::load(&PathBuf::from(&args[2]))?),
        )?,
        _ => anyhow::bail!(
            "usage: day2-gke-release prepare CONFIG SOURCE TOOLCHAINS QUALIFIED | approve CONFIG | run CONFIG TOKEN_FILE"
        ),
    };
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}
