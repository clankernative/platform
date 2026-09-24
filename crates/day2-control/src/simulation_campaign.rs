//! Native effects for the private Roc simulation recipe. No provider credentials
//! or wall clock enter a scenario; orchestration stays in ops/Simulation.roc.
use crate::{Digest, simulation};
use anyhow::{Context, Result, ensure};
use day2::automation::Request;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use simulation::coverage::Coverage;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const DEFAULT_SEED: u64 = 3_664_912_422;
pub const VERIFY_CASES: u32 = 32;
pub const CI_CASES: u32 = 8;
pub const MAX_CASES: u32 = 128;
const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_REGRESSIONS: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    scenario: Digest,
    trace: Digest,
    coverage: Coverage,
    program: Option<Digest>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    format: u32,
    status: String,
    model: Digest,
    corpus: Digest,
    workflow: String,
    seed: u64,
    cases: u32,
    regressions: u32,
    entries: Vec<Entry>,
    generated_coverage: Coverage,
    regression_coverage: Coverage,
    coverage_qualified: bool,
}

pub struct Session {
    directory: PathBuf,
    seed: u64,
    cases: u32,
    regressions: Vec<simulation::Scenario>,
    opened: bool,
    entries: Vec<Entry>,
    pending: Option<Entry>,
    complete: bool,
}

impl Session {
    pub fn new(directory: &Path, seed: u64, cases: u32) -> Result<Self> {
        ensure!(
            (1..=MAX_CASES).contains(&cases),
            "control simulation cases must be 1..128"
        );
        let regressions = simulation::regressions()?;
        ensure!(
            !regressions.is_empty() && regressions.len() <= MAX_REGRESSIONS,
            "control simulation regression corpus budget"
        );
        fs::create_dir(directory).context("fresh simulation evidence directory required")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            directory: directory.to_owned(),
            seed,
            cases,
            regressions,
            opened: false,
            entries: Vec::new(),
            pending: None,
            complete: false,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn receipt_digest(&self) -> Result<Digest> {
        ensure!(self.complete, "control simulation campaign incomplete");
        Ok(Digest::new(&read_json(
            &self.directory.join("receipt.json"),
        )?))
    }

    pub fn effect(&mut self, request: Request) -> Result<Value> {
        ensure!(
            !self.complete,
            "control simulation campaign already complete"
        );
        match request.action.as_str() {
            "simulation-open" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    seed: String,
                    cases: u32,
                }
                let input: Input = request.decode()?;
                ensure!(
                    !self.opened
                        && input.seed == self.seed.to_string()
                        && input.cases == self.cases,
                    "control simulation campaign binding mismatch"
                );
                self.opened = true;
                Ok(
                    json!({"regressions":(0..self.regressions.len() as u32).collect::<Vec<_>>(),"cases":(0..self.cases).collect::<Vec<_>>()}),
                )
            }
            "simulation-regression" | "simulation-case" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    index: u32,
                }
                let input: Input = request.decode()?;
                ensure!(
                    self.opened && self.pending.is_none(),
                    "open campaign and replay previous schedule first"
                );
                let (name, scenario) = if request.action == "simulation-regression" {
                    ensure!(
                        input.index as usize == self.entries.len(),
                        "regressions must run once in corpus order"
                    );
                    let scenario = self
                        .regressions
                        .get(input.index as usize)
                        .context("unknown regression")?
                        .clone();
                    (format!("regression-{:03}", input.index), scenario)
                } else {
                    ensure!(
                        self.entries.len() == self.regressions.len() + input.index as usize
                            && input.index < self.cases,
                        "run complete corpus then generated cases once in order"
                    );
                    (
                        format!("generated-{:03}", input.index),
                        simulation::generated(self.seed, input.index)?,
                    )
                };
                let program = if request.action == "simulation-case" {
                    let program = simulation::generation::program(self.seed, input.index)?;
                    let bytes = serde_json::to_vec_pretty(&program)?;
                    write_json(&self.directory.join(format!("{name}.program.json")), &bytes)?;
                    Some((program, Digest::new(&bytes)))
                } else {
                    None
                };
                let scenario_bytes = serde_json::to_vec_pretty(&scenario)?;
                write_json(
                    &self.directory.join(format!("{name}.scenario.json")),
                    &scenario_bytes,
                )?;
                let database = tempfile::tempdir_in(&self.directory)?;
                let result = simulation::run(&scenario, database.path());
                let trace = match result {
                    Ok(trace) => trace,
                    Err(error) => {
                        write_json(
                            &self.directory.join(format!("{name}.failure.json")),
                            br#"{"code":"simulation_host_failure"}"#,
                        )?;
                        self.reduce_failure(program.as_ref().map(|(program, _)| program))?;
                        return Err(error).with_context(|| {
                            format!(
                                "simulation failed; scenario: {}",
                                self.directory
                                    .join(format!("{name}.scenario.json"))
                                    .display()
                            )
                        });
                    }
                };
                let trace_bytes = serde_json::to_vec(&trace)?;
                let path = self.directory.join(format!("{name}.trace.json"));
                write_json(&path, &trace_bytes)?;
                trace.validate()?;
                ensure!(
                    Digest::of(&trace.scenario)? == Digest::of(&scenario)?,
                    "simulation runner returned a trace for another scenario"
                );
                if let Err(error) = trace.require_success().with_context(|| {
                    format!(
                        "simulation invariant failed; replay-control {}",
                        path.display()
                    )
                }) {
                    self.reduce_failure(program.as_ref().map(|(program, _)| program))?;
                    return Err(error);
                }
                self.pending = Some(Entry {
                    name,
                    scenario: Digest::new(&scenario_bytes),
                    trace: Digest::new(&trace_bytes),
                    coverage: Coverage::from_trace(&trace)?,
                    program: program.map(|(_, digest)| digest),
                });
                Ok(json!({"trace":Digest::new(&trace_bytes)}))
            }
            "simulation-check-replay" => {
                empty(&request)?;
                let entry = self
                    .pending
                    .as_ref()
                    .context("completed schedule required before replay")?;
                let bytes = read_json(&self.directory.join(format!("{}.trace.json", entry.name)))?;
                ensure!(
                    Digest::new(&bytes) == entry.trace,
                    "simulation trace changed before replay"
                );
                let trace: simulation::Trace = day2::json::decode_evidence(&bytes)?;
                trace.validate()?;
                let database = tempfile::tempdir_in(&self.directory)?;
                simulation::replay(&trace, database.path())?;
                trace.require_success()?;
                self.entries
                    .push(self.pending.take().context("simulation replay entry")?);
                Ok(json!({"status":"reproduced"}))
            }
            "simulation-receipt" => {
                empty(&request)?;
                ensure!(
                    self.opened
                        && self.pending.is_none()
                        && self.entries.len() == self.regressions.len() + self.cases as usize,
                    "control simulation campaign incomplete"
                );
                let (generated_coverage, regression_coverage) =
                    coverage_totals(&self.entries, self.regressions.len())?;
                let coverage_qualified = self.cases >= CI_CASES;
                if coverage_qualified {
                    generated_coverage.require_campaign()?;
                }
                let receipt = Receipt {
                    format: 2,
                    status: "passed".into(),
                    model: simulation::implementation_digest()?,
                    corpus: Digest::of(&self.regressions)?,
                    workflow: day2::automation::source_digest(),
                    seed: self.seed,
                    cases: self.cases,
                    regressions: self.regressions.len() as u32,
                    entries: self.entries.clone(),
                    generated_coverage,
                    regression_coverage,
                    coverage_qualified,
                };
                write_json(
                    &self.directory.join("receipt.json"),
                    &serde_json::to_vec_pretty(&receipt)?,
                )?;
                self.complete = true;
                Ok(
                    json!({"status":"passed","seed":self.seed,"cases":self.cases,"regressions":self.regressions.len(),"coverage_qualified":coverage_qualified,"receipt":self.receipt_digest()?}),
                )
            }
            _ => anyhow::bail!("unknown control simulation capability"),
        }
    }

    fn reduce_failure(&self, program: Option<&simulation::generation::Program>) -> Result<()> {
        if let Some(program) = program {
            // Failure reduction is bounded separately from campaign execution.
            // Original scenario/trace evidence has already been persisted.
            simulation::shrink::check_and_persist(
                program,
                &self.directory.join("counterexamples"),
                simulation::shrink::ShrinkBudget::new(16)?,
            )?;
        }
        Ok(())
    }
}

fn coverage_totals(entries: &[Entry], regressions: usize) -> Result<(Coverage, Coverage)> {
    let mut generated = Coverage::default();
    let mut regression = Coverage::default();
    for (index, entry) in entries.iter().enumerate() {
        if index < regressions {
            regression.merge(&entry.coverage)?;
        } else {
            generated.merge(&entry.coverage)?;
        }
    }
    Ok((generated, regression))
}

fn empty(request: &Request) -> Result<()> {
    ensure!(
        request.decode::<Value>()? == json!({}),
        "simulation capability accepts no overrides"
    );
    Ok(())
}

fn read_json(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "simulation evidence must be a regular file"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_JSON_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_JSON_BYTES,
        "simulation evidence byte budget"
    );
    Ok(bytes)
}

fn write_json(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_JSON_BYTES,
        "simulation evidence byte budget"
    );
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn replay_file(path: &Path, scratch: &Path) -> Result<Value> {
    let bytes = read_json(path)?;
    let trace: simulation::Trace = day2::json::decode_evidence(&bytes)?;
    trace.validate()?;
    let database = tempfile::tempdir_in(scratch)?;
    simulation::replay(&trace, database.path())?;
    Ok(
        json!({"status":"reproduced","trace":Digest::new(&bytes),"invariants_passed":trace.require_success().is_ok()}),
    )
}

pub fn verify_receipt(directory: &Path, expected: &Digest, seed: u64, cases: u32) -> Result<()> {
    let bytes = read_json(&directory.join("receipt.json"))?;
    ensure!(
        &Digest::new(&bytes) == expected,
        "control simulation receipt changed"
    );
    let receipt: Receipt = day2::json::decode(&bytes)?;
    let regressions = simulation::regressions()?;
    ensure!(
        receipt.format == 2
            && receipt.status == "passed"
            && receipt.seed == seed
            && receipt.cases == cases
            && receipt.model == simulation::implementation_digest()?
            && receipt.corpus == Digest::of(&regressions)?
            && receipt.workflow == day2::automation::source_digest()
            && receipt.regressions as usize == regressions.len()
            && receipt.entries.len() == regressions.len() + cases as usize,
        "control simulation receipt contract mismatch"
    );
    for (index, entry) in receipt.entries.iter().enumerate() {
        let name = if index < regressions.len() {
            format!("regression-{index:03}")
        } else {
            format!("generated-{:03}", index - regressions.len())
        };
        ensure!(entry.name == name, "simulation evidence order mismatch");
        let scenario = read_json(&directory.join(format!("{name}.scenario.json")))?;
        let trace = read_json(&directory.join(format!("{name}.trace.json")))?;
        ensure!(
            Digest::new(&scenario) == entry.scenario && Digest::new(&trace) == entry.trace,
            "simulation evidence changed"
        );
        let scenario: simulation::Scenario = day2::json::decode(&scenario)?;
        let expected = if index < regressions.len() {
            ensure!(
                entry.program.is_none(),
                "regression cannot claim generated program evidence"
            );
            regressions[index].clone()
        } else {
            let bytes = read_json(&directory.join(format!("{name}.program.json")))?;
            ensure!(
                entry.program.as_ref() == Some(&Digest::new(&bytes)),
                "simulation program evidence changed"
            );
            let program: simulation::generation::Program = day2::json::decode(&bytes)?;
            ensure!(
                program
                    == simulation::generation::program(seed, (index - regressions.len()) as u32)?,
                "simulation generated program differs from required inputs"
            );
            simulation::generation::compile(&program)?
        };
        ensure!(
            Digest::of(&scenario)? == Digest::of(&expected)?,
            "simulation coverage differs from required schedule"
        );
        let trace: simulation::Trace = day2::json::decode_evidence(&trace)?;
        ensure!(
            Digest::of(&trace.scenario)? == Digest::of(&scenario)?,
            "simulation trace belongs to another scenario"
        );
        trace.validate()?;
        trace.require_success()?;
        ensure!(
            entry.coverage == Coverage::from_trace(&trace)?,
            "simulation coverage differs from witnessed events"
        );
    }
    let (generated, regression) = coverage_totals(&receipt.entries, regressions.len())?;
    ensure!(
        receipt.generated_coverage == generated
            && receipt.regression_coverage == regression
            && receipt.coverage_qualified == (cases >= CI_CASES),
        "simulation campaign coverage mismatch"
    );
    if receipt.coverage_qualified {
        generated.require_campaign()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(action: &str, value: Value) -> Request {
        Request {
            protocol: 1,
            action: action.into(),
            input: value.to_string(),
        }
    }

    #[test]
    fn campaign_receipt_cannot_skip_cases_or_accept_wrong_parameters() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut session = Session::new(&directory.path().join("campaign"), DEFAULT_SEED, 1)?;
        assert!(
            session
                .effect(request("simulation-receipt", json!({})))
                .is_err()
        );
        assert!(
            session
                .effect(request("simulation-open", json!({"seed":"1","cases":1})))
                .is_err()
        );
        session.effect(request(
            "simulation-open",
            json!({"seed":DEFAULT_SEED.to_string(),"cases":1}),
        ))?;
        assert!(
            session
                .effect(request("simulation-case", json!({"index":0})))
                .is_err()
        );
        assert!(
            session
                .effect(request("simulation-regression", json!({"index":1})))
                .is_err()
        );
        assert!(
            session
                .effect(request("simulation-check-replay", json!({})))
                .is_err()
        );
        assert!(!session.is_complete());
        Ok(())
    }

    #[test]
    fn completed_campaign_pins_coverage_and_trace_association() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("campaign");
        let mut session = Session::new(&path, DEFAULT_SEED, 1)?;
        session.effect(request(
            "simulation-open",
            json!({"seed":DEFAULT_SEED.to_string(),"cases":1}),
        ))?;
        for index in 0..session.regressions.len() {
            session.effect(request("simulation-regression", json!({"index":index})))?;
            session.effect(request("simulation-check-replay", json!({})))?;
        }
        session.effect(request("simulation-case", json!({"index":0})))?;
        assert!(
            session
                .effect(request("simulation-receipt", json!({})))
                .is_err()
        );
        session.effect(request("simulation-check-replay", json!({})))?;
        session.effect(request("simulation-receipt", json!({})))?;
        verify_receipt(&path, &session.receipt_digest()?, DEFAULT_SEED, 1)?;
        assert!(
            session
                .effect(request("simulation-receipt", json!({})))
                .is_err()
        );

        let receipt_path = path.join("receipt.json");
        let original = read_json(&receipt_path)?;
        let mut forged: Receipt = day2::json::decode(&original)?;
        assert!(!forged.coverage_qualified);
        forged.coverage_qualified = true;
        let bytes = serde_json::to_vec_pretty(&forged)?;
        fs::write(&receipt_path, &bytes)?;
        assert!(verify_receipt(&path, &Digest::new(&bytes), DEFAULT_SEED, 1).is_err());
        let mut forged: Receipt = day2::json::decode(&original)?;
        forged
            .entries
            .last_mut()
            .context("generated entry")?
            .coverage
            .scheduled
            .admitted += 1;
        let bytes = serde_json::to_vec_pretty(&forged)?;
        fs::write(&receipt_path, &bytes)?;
        assert!(verify_receipt(&path, &Digest::new(&bytes), DEFAULT_SEED, 1).is_err());
        let mut forged: Receipt = day2::json::decode(&original)?;
        forged.generated_coverage = forged.regression_coverage.clone();
        let bytes = serde_json::to_vec_pretty(&forged)?;
        fs::write(&receipt_path, &bytes)?;
        assert!(verify_receipt(&path, &Digest::new(&bytes), DEFAULT_SEED, 1).is_err());
        let mut receipt: Receipt = day2::json::decode(&original)?;
        receipt.entries.pop();
        let bytes = serde_json::to_vec_pretty(&receipt)?;
        fs::write(&receipt_path, &bytes)?;
        assert!(verify_receipt(&path, &Digest::new(&bytes), DEFAULT_SEED, 1).is_err());

        // Rehashing substituted evidence cannot turn another schedule into required coverage.
        let mut receipt: Receipt = day2::json::decode(&original)?;
        let entry = receipt.entries.last_mut().context("generated entry")?;
        let scenario_path = path.join(format!("{}.scenario.json", entry.name));
        let scenario_bytes = read_json(&scenario_path)?;
        let mut scenario: simulation::Scenario = day2::json::decode(&scenario_bytes)?;
        scenario.seed ^= 1;
        let bytes = serde_json::to_vec_pretty(&scenario)?;
        fs::write(&scenario_path, &bytes)?;
        entry.scenario = Digest::new(&bytes);
        let bytes = serde_json::to_vec_pretty(&receipt)?;
        fs::write(&receipt_path, &bytes)?;
        assert!(
            verify_receipt(&path, &Digest::new(&bytes), DEFAULT_SEED, 1)
                .unwrap_err()
                .to_string()
                .contains("coverage differs")
        );

        fs::write(&scenario_path, scenario_bytes)?;
        let mut receipt: Receipt = day2::json::decode(&original)?;
        let entry = receipt.entries.last_mut().context("generated entry")?;
        let trace_path = path.join(format!("{}.trace.json", entry.name));
        let mut trace: simulation::Trace = day2::json::decode_evidence(&read_json(&trace_path)?)?;
        trace.scenario.seed ^= 1;
        let bytes = serde_json::to_vec_pretty(&trace)?;
        fs::write(trace_path, &bytes)?;
        entry.trace = Digest::new(&bytes);
        let bytes = serde_json::to_vec_pretty(&receipt)?;
        fs::write(&receipt_path, &bytes)?;
        assert!(
            verify_receipt(&path, &Digest::new(&bytes), DEFAULT_SEED, 1)
                .unwrap_err()
                .to_string()
                .contains("another scenario")
        );
        Ok(())
    }
}
