use anyhow::{Context, Result, ensure};
use std::{num::NonZeroU16, path::Path};

fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        arguments.len() == 6 || (arguments.len() == 8 && arguments[6] == "--provisioning"),
        "usage: day2-package INSTANCE APP ACTOR IMAGE_DIGEST PUBLISHED_PORT NEW_DIRECTORY [--provisioning PRIVATE_INPUT_JSON]"
    );
    let port: NonZeroU16 = arguments[4]
        .parse()
        .context("nonzero published port required")?;
    let provisioning = if arguments.len() == 8 {
        use std::io::Read;
        let file = std::fs::File::open(&arguments[7])?;
        let mut bytes = Vec::new();
        file.take(1_048_577).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1_048_576, "provisioning input budget");
        Some(day2::json::decode::<day2::packaging::Provisioning>(&bytes)?)
    } else {
        None
    };
    let output = day2::packaging::export_with_provisioning(
        Path::new(&arguments[0]),
        &arguments[1],
        &arguments[2],
        &arguments[3],
        port,
        Path::new(&arguments[5]),
        provisioning.as_ref(),
    )?;
    println!(
        "{}",
        serde_json::json!({"deployment":output,"mode":"container-development-auth"})
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("day2-package refused: {error}");
        std::process::exit(1);
    }
}
