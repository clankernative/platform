//! Admission of fresh, closed-schema DST observations. Recipes still select
//! campaigns; this guard cannot run tests or substitute generated intent.
use anyhow::{Context, Result, ensure};
use day2::simulation::coverage::{Campaign, Observation, Transition};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

const MAX_OBSERVATIONS: usize = 4096;

#[derive(Default, Serialize)]
struct Coverage {
    seeds: BTreeSet<u64>,
    histories: u64,
    transitions: BTreeMap<Transition, u64>,
}

fn aggregate(observations: &[&Observation]) -> Result<BTreeMap<Campaign, Coverage>> {
    ensure!(observations.len() <= MAX_OBSERVATIONS, "DST history bound");
    let mut campaigns: BTreeMap<Campaign, Coverage> = BTreeMap::new();
    for observation in observations {
        let coverage = campaigns.entry(observation.campaign).or_default();
        coverage.seeds.insert(observation.seed);
        coverage.histories += 1;
        for (&transition, &count) in &observation.transitions {
            ensure!(count > 0, "DST unwitnessed transition");
            let total = coverage.transitions.entry(transition).or_default();
            *total = total.checked_add(count).context("DST count overflow")?;
        }
    }
    for campaign in Campaign::ALL {
        let coverage = campaigns
            .get(&campaign)
            .context("declared DST campaign did not run")?;
        ensure!(
            campaign
                .required_seeds()
                .into_iter()
                .all(|seed| coverage.seeds.contains(&seed)),
            "declared DST campaign lost a required seed: {campaign:?}"
        );
        if campaign == Campaign::CommandGenerated {
            ensure!(
                coverage.seeds.len() >= 12,
                "generated command campaign incomplete"
            );
        }
        ensure!(
            [
                Transition::StateChanged,
                Transition::DecisionCommitted,
                Transition::ProviderAccepted,
                Transition::RegistrationStepCompleted
            ]
            .iter()
            .any(|transition| coverage.transitions.get(transition).is_some_and(|n| *n > 0)),
            "declared DST campaign covered zero transitions: {campaign:?}"
        );
    }
    Ok(campaigns)
}

pub(super) struct Session {
    directory: PathBuf,
    suite: String,
}

impl Session {
    pub(super) fn start(root: &Path, suite: &str) -> Result<Option<Self>> {
        if !["workspace-day2", "workspace-day2-lifecycle", "workspace-runtime"].contains(&suite) {
            return Ok(None);
        }
        let parent = root.join("artifacts/dst");
        fs::create_dir_all(&parent)?;
        let directory = tempfile::Builder::new()
            .prefix("run-")
            .tempdir_in(parent)?
            .keep();
        Ok(Some(Self {
            directory,
            suite: suite.into(),
        }))
    }

    pub(super) fn configure(&self, command: &mut Command) {
        command.env("DAY2_DST_OBSERVATIONS", &self.directory);
    }

    pub(super) fn partial(self) -> Result<Vec<Observation>> {
        let mut observations = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            ensure!(observations.len() < MAX_OBSERVATIONS, "DST history bound");
            ensure!(
                entry.file_type()?.is_file()
                    && entry.path().extension().is_some_and(|v| v == "complete"),
                "incomplete DST observation"
            );
            let mut bytes = Vec::new();
            fs::File::open(entry.path())?
                .take(4097)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 4096, "DST observation byte bound");
            observations.push(day2::json::decode::<Observation>(&bytes)?);
        }
        fs::write(self.directory.join("coverage.json"), serde_json::to_vec_pretty(&serde_json::json!({
            "format":1,"status":"partial","suite":self.suite,
            "scope":"portable_oracle_and_replay_observations_not_native_qualification",
            "observations":observations,
        }))?)?;
        Ok(observations)
    }

    pub(super) fn finish(self) -> Result<()> {
        let directory = self.directory.clone();
        let suite = self.suite.clone();
        let observations = self.partial()?;
        write_coverage(&directory, &suite, &observations.iter().collect::<Vec<_>>())
    }
}

fn write_coverage(directory: &Path, suite: &str, observations: &[&Observation]) -> Result<()> {
    let campaigns = aggregate(observations)?;
    fs::write(
            directory.join("coverage.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "format":1,"status":"passed","suite":suite,
                "scope":"portable_oracle_and_replay_observations_not_native_qualification",
                "campaigns":campaigns,
            }))?,
        )?;
        println!(
            "DST coverage: {}",
            directory.join("coverage.json").display()
        );
        Ok(())
}

pub(super) fn join<'a>(root: &Path, observations: impl IntoIterator<Item = &'a Observation>) -> Result<()> {
    let observations: Vec<_> = observations.into_iter().take(MAX_OBSERVATIONS + 1).collect();
    let directory = root.join("artifacts/dst");
    fs::create_dir_all(&directory)?;
    write_coverage(&directory, "workspace-day2-joined", &observations)
}

pub(super) fn validate<'a>(observations: impl IntoIterator<Item = &'a Observation>) -> Result<()> {
    let observations: Vec<_> = observations.into_iter().take(MAX_OBSERVATIONS + 1).collect();
    aggregate(&observations)?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::verification) fn complete() -> Vec<Observation> {
        Campaign::ALL
            .into_iter()
            .flat_map(|campaign| {
                let seeds = if campaign == Campaign::CommandGenerated {
                    (0..12).collect()
                } else {
                    campaign.required_seeds()
                };
                seeds.into_iter().map(move |seed| Observation {
                    campaign,
                    seed,
                    transitions: [(Transition::StateChanged, 1)].into(),
                })
            })
            .collect()
    }

    #[test]
    fn every_declared_campaign_and_seed_must_actually_report_progress() -> Result<()> {
        assert_eq!(aggregate(&complete().iter().collect::<Vec<_>>())?.len(), Campaign::ALL.len());
        let missing: Vec<_> = complete()
            .into_iter()
            .filter(|o| o.campaign != Campaign::StorageLifecycle)
            .collect();
        assert!(aggregate(&missing.iter().collect::<Vec<_>>()).is_err());
        let missing_seed: Vec<_> = complete()
            .into_iter()
            .filter(|o| !(o.campaign == Campaign::Oauth && o.seed == 7))
            .collect();
        assert!(aggregate(&missing_seed.iter().collect::<Vec<_>>()).is_err());
        let mut empty = complete();
        for observation in &mut empty {
            if observation.campaign == Campaign::EnrollmentHandshake {
                observation.transitions.clear();
            }
        }
        assert!(aggregate(&empty.iter().collect::<Vec<_>>()).is_err());
        let mut refused_only = complete();
        for observation in &mut refused_only {
            if observation.campaign == Campaign::Oauth {
                observation.transitions = [(Transition::Refused, 1)].into();
            }
        }
        assert!(aggregate(&refused_only.iter().collect::<Vec<_>>()).is_err());
        Ok(())
    }

    #[test]
    fn fresh_directory_cannot_adopt_old_success_or_unfinished_output() -> Result<()> {
        let root = tempfile::tempdir()?;
        let old = Session::start(root.path(), "workspace-day2")?.unwrap();
        fs::write(
            old.directory.join("old.complete"),
            serde_json::to_vec(&complete()[0])?,
        )?;
        let fresh = Session::start(root.path(), "workspace-day2")?.unwrap();
        assert_ne!(old.directory, fresh.directory);
        assert!(fresh.finish().is_err());
        fs::write(old.directory.join("unfinished.tmp"), b"{")?;
        assert!(old.finish().is_err());
        Ok(())
    }

    #[test]
    fn split_observations_require_the_same_complete_seed_and_transition_union() -> Result<()> {
        let observations = complete();
        let (left, right) = observations.split_at(observations.len() / 2);
        assert!(validate(left).is_err());
        assert!(validate(right).is_err());
        validate(left.iter().chain(right))?;
        let mut missing = complete();
        missing.retain(|o| !(o.campaign == Campaign::NativeOauthConsumer && o.seed == 0));
        assert!(validate(&missing).is_err());
        Ok(())
    }
}
