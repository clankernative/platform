//! CLI adapter only. The private Roc recipe owns campaign iteration and order.
use super::*;
use day2_control::simulation_campaign::{self, Session};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn session(root: &Path, seed: u64, cases: u32) -> Result<Session> {
    ensure!(
        (1..=simulation_campaign::MAX_CASES).contains(&cases),
        "control simulation cases must be 1..128"
    );
    let directory = root.join("artifacts/control-simulation");
    fs::create_dir_all(&directory)?;
    let run = tempfile::Builder::new()
        .prefix("run-")
        .tempdir_in(directory)?
        .keep();
    Session::new(&run.join("campaign"), seed, cases)
}

pub fn simulate(root: &Path, seed: u64, cases: u32) -> Result<()> {
    let runner = workflows::build(root)?;
    let mut session = session(root, seed, cases)?;
    let result = day2::automation::run(
        &runner,
        &["simulate-control", &seed.to_string(), &cases.to_string()],
        |request| session.effect(request),
    );
    println!(
        "Control simulation evidence: {}",
        session.directory().display()
    );
    result?;
    ensure!(
        session.is_complete(),
        "control simulation campaign incomplete"
    );
    simulation_campaign::verify_receipt(
        session.directory(),
        &session.receipt_digest()?,
        seed,
        cases,
    )?;
    println!("Control simulation passed: {cases} generated schedules plus regression corpus");
    if cases < simulation_campaign::CI_CASES {
        println!("Exploratory run: not coverage-qualified for CI");
    } else {
        println!("Generated-schedule coverage gate passed");
    }
    Ok(())
}

pub fn replay(root: &Path, trace: &Path) -> Result<()> {
    let runner = workflows::build(root)?;
    let trace = trace.canonicalize()?;
    let encoded = trace.to_str().context("trace path encoding")?;
    let scratch = root.join("artifacts/control-simulation");
    fs::create_dir_all(&scratch)?;
    let mut completed = false;
    let result = day2::automation::run(&runner, &["replay-control", encoded], |request| {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            trace: PathBuf,
        }
        ensure!(
            !completed && request.action == "simulation-replay",
            "unexpected simulation replay effect"
        );
        let input: Input = request.decode()?;
        ensure!(input.trace == trace, "simulation replay path mismatch");
        let result = simulation_campaign::replay_file(&trace, &scratch)?;
        completed = true;
        Ok(result)
    })?;
    ensure!(completed, "simulation replay did not run");
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
