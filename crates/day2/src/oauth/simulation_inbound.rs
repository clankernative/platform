//! Inbound histories use a separate symbolic oracle: no production transition
//! or stored state predicts acceptance. Custody failure must roll back issuance.
use super::{World, effects, implementation, next, snapshot};
use crate::oauth::{custody, inbound};
use anyhow::{Result, ensure};
use day2_capabilities::{
    BindingRef, Name,
    oauth::{ClientChannelContract, OAuthClientRedirectRef},
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    Consent,
    Offer,
    Redeem,
    WrongClient,
    FailedRedeem,
    Narrow,
    Broaden,
    FailedRefresh,
    ReplayRefresh,
    Access,
    RemovedChannel,
    Revoke,
    Reopen,
    Advance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    version: u32,
    seed: u64,
    steps: Vec<Step>,
}

#[derive(Default, Serialize)]
struct Model {
    grant: bool,
    active: bool,
    epoch: i64,
    code: Option<&'static str>,
    generation: i64,
    family_active: bool,
    narrowed: bool,
    access_until: i64,
}

impl Model {
    fn step(&mut self, step: Step, now: i64) -> bool {
        match step {
            Step::Consent if !self.grant => {
                self.grant = true;
                self.active = true;
                self.epoch = 1;
                true
            }
            Step::Offer if self.active && self.code.is_none() && now < 100 => {
                self.code = Some("ready");
                true
            }
            Step::Redeem if self.active && self.code == Some("ready") && now < 100 => {
                self.code = Some("consumed");
                self.generation = 1;
                self.family_active = true;
                self.access_until = now + 60;
                true
            }
            Step::Narrow | Step::Broaden
                if self.active
                    && self.family_active
                    && !(matches!(step, Step::Broaden) && self.narrowed) =>
            {
                self.generation += 1;
                self.narrowed = matches!(step, Step::Narrow);
                self.access_until = now + 60;
                true
            }
            Step::ReplayRefresh if self.active && self.family_active && self.generation == 1 => {
                // The original token's first use is ordinary narrowing; only
                // a subsequent use is a replay of a consumed credential.
                self.generation += 1;
                self.narrowed = true;
                self.access_until = now + 60;
                true
            }
            Step::ReplayRefresh if self.active && self.generation > 1 => {
                // Replay revokes the refresh family. It does not revoke the
                // grant or already issued access credentials before expiry.
                self.family_active = false;
                false
            }
            Step::Access => self.active && self.generation > 0 && now < self.access_until,
            Step::Revoke if self.active => {
                self.active = false;
                self.epoch += 1;
                self.family_active = false;
                true
            }
            Step::Reopen | Step::Advance => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Observation {
    accepted: bool,
    snapshot: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct Failure {
    category: &'static str,
    expected: Option<serde_json::Value>,
    predicted_acceptance: Option<bool>,
    observations: Vec<Observation>,
    replay: Option<Vec<Observation>>,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.category)
    }
}
impl std::error::Error for Failure {}

fn pin(name: &str) -> Result<BindingRef> {
    BindingRef::pin(Name::try_from(name.to_owned())?, &name)
}

fn credentials() -> Result<inbound::CredentialHashes> {
    let mut access = [0; 32];
    let mut refresh = [0; 32];
    effects::fill(&mut access)?;
    effects::fill(&mut refresh)?;
    let hashes = inbound::CredentialHashes::from_secrets(&access, &refresh);
    access.fill(0);
    refresh.fill(0);
    hashes
}

fn run(program: &Program) -> Result<Vec<Observation>> {
    ensure!(
        program.version == 1 && program.steps.len() <= 128,
        "unsupported inbound OAuth history"
    );
    let world = World::new(program.seed);
    effects::scope(world.clone(), || {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("inbound.sqlite");
        let mut db = Connection::open(&path)?;
        db.execute_batch("PRAGMA journal_mode=WAL;")?;
        inbound::install_schema(&db)?;
        let ceiling = inbound::tests::ceiling();
        let channel = ClientChannelContract::derive("mcp".into(), ceiling.roots.clone())?;
        let operation = ceiling.roots["ghostwright.read"].clone();
        let code = inbound::AuthorizationCodeHash::from_secret(effects::random()?.as_bytes())?;
        let verifier = effects::random()?;
        let mut model = Model::default();
        let mut current: Option<inbound::CredentialHashes> = None;
        let mut original: Option<inbound::CredentialHashes> = None;
        let mut observations = Vec::new();
        for &step in &program.steps {
            if matches!(step, Step::Advance) {
                world.advance(37);
            }
            let now = effects::wall_time()?;
            let predicted = model.step(step, now);
            let candidate = credentials()?;
            let accepted = match step {
                Step::Consent => inbound::record_grant(&db, "grant", &ceiling, 1)?,
                Step::Offer => inbound::issue_code(
                    &mut db,
                    inbound::CodeOffer {
                        code_hash: code.clone(),
                        grant_id: "grant".into(),
                        client: ceiling.client.clone(),
                        redirect: OAuthClientRedirectRef(pin("redirect")?),
                        pkce_challenge: custody::pkce_challenge(&verifier)?,
                        audience: ceiling.audience.clone(),
                        expires_at: 100,
                        now,
                    },
                )
                .unwrap_or(false),
                Step::Redeem | Step::WrongClient | Step::FailedRedeem => {
                    let result = inbound::redeem_code(
                        &mut db,
                        inbound::CodeRedemption {
                            code_hash: code.clone(),
                            client: if matches!(step, Step::WrongClient) {
                                pin("other_client")?
                            } else {
                                ceiling.client.clone()
                            },
                            redirect: OAuthClientRedirectRef(pin("redirect")?),
                            pkce_verifier: verifier.clone(),
                            audience: ceiling.audience.clone(),
                            hashes: candidate.clone(),
                            family: "family".into(),
                            receipt: "receipt".into(),
                            access_expires_at: now + 60,
                            now,
                        },
                        |_| {
                            if matches!(step, Step::FailedRedeem) {
                                anyhow::bail!("simulated custody write failure");
                            }
                            Ok(())
                        },
                    )
                    .unwrap_or(false);
                    if result {
                        current = Some(candidate.clone());
                        original = Some(candidate);
                    }
                    result
                }
                Step::Narrow | Step::Broaden | Step::FailedRefresh | Step::ReplayRefresh => {
                    let old = if matches!(step, Step::ReplayRefresh) {
                        &original
                    } else {
                        &current
                    };
                    let old = old.as_ref().unwrap_or(&candidate).refresh().clone();
                    let roots = if matches!(step, Step::Broaden) {
                        ceiling.roots.keys().cloned().collect()
                    } else {
                        BTreeSet::from(["ghostwright.read".into()])
                    };
                    let result = inbound::refresh(
                        &mut db,
                        inbound::RefreshExchange {
                            old_hash: old,
                            client: ceiling.client.clone(),
                            requested_roots: roots,
                            hashes: candidate.clone(),
                            access_expires_at: now + 60,
                            now,
                        },
                        |_| {
                            if matches!(step, Step::FailedRefresh) {
                                anyhow::bail!("simulated custody write failure");
                            }
                            Ok(())
                        },
                    )
                    .unwrap_or(false);
                    if result {
                        current = Some(candidate);
                    }
                    result
                }
                Step::Access | Step::RemovedChannel => {
                    let channel = if matches!(step, Step::RemovedChannel) {
                        ClientChannelContract::derive(
                            "mcp".into(),
                            [(
                                "ghostwright.publish".into(),
                                ceiling.roots["ghostwright.publish"].clone(),
                            )]
                            .into(),
                        )?
                    } else {
                        channel.clone()
                    };
                    inbound::authorize_channel_operation(
                        &db,
                        current.as_ref().unwrap_or(&candidate).access(),
                        &ceiling.client,
                        &ceiling.audience,
                        &channel,
                        &operation,
                        now,
                    )?
                }
                Step::Revoke => inbound::revoke_grant(&mut db, "grant", 1)?,
                Step::Reopen => {
                    drop(db);
                    db = Connection::open(&path)?;
                    inbound::install_schema(&db)?;
                    true
                }
                Step::Advance => true,
            };
            use rusqlite::OptionalExtension;
            let grant: Option<(String, i64)> = db
                .query_row("SELECT status,epoch FROM oauth_inbound_grants", [], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()?;
            let code_state: Option<String> = db
                .query_row("SELECT state FROM oauth_inbound_codes", [], |row| {
                    row.get(0)
                })
                .optional()?;
            let mut statement = db.prepare(
                "SELECT generation,state FROM oauth_inbound_refresh ORDER BY generation",
            )?;
            let refresh = statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let access: i64 =
                db.query_row("SELECT count(*) FROM oauth_inbound_access", [], |row| {
                    row.get(0)
                })?;
            let expected_grant = model.grant.then(|| {
                (
                    if model.active { "active" } else { "revoked" }.to_owned(),
                    model.epoch,
                )
            });
            let expected_refresh = (1..=model.generation)
                .map(|generation| {
                    (
                        generation,
                        if generation < model.generation {
                            "consumed"
                        } else if model.family_active {
                            "active"
                        } else {
                            "revoked"
                        }
                        .to_owned(),
                    )
                })
                .collect::<Vec<_>>();
            observations.push(Observation {
                accepted,
                snapshot: snapshot(&db)?,
            });
            if accepted != predicted
                || grant != expected_grant
                || code_state.as_deref() != model.code
                || refresh != expected_refresh
                || access != model.generation
            {
                return Err(Failure {
                    category: "inbound_oracle",
                    expected: Some(serde_json::to_value(&model)?),
                    predicted_acceptance: Some(predicted),
                    observations,
                    replay: None,
                }
                .into());
            }
        }
        ensure!(
            world.requests().is_empty(),
            "inbound kernel unexpectedly contacted a provider"
        );
        Ok(observations)
    })
}

fn checked(program: &Program) -> Result<Vec<Observation>> {
    let observations = run(program)?;
    let replay = run(program)?;
    if observations != replay {
        return Err(Failure {
            category: "inbound_replay",
            expected: None,
            predicted_acceptance: None,
            observations,
            replay: Some(replay),
        }
        .into());
    }
    Ok(observations)
}

fn category(error: &anyhow::Error) -> String {
    error
        .downcast_ref::<Failure>()
        .map_or_else(|| error.to_string(), |failure| failure.category.into())
}

fn verify(program: &Program) -> Result<()> {
    if let Err(error) = checked(program) {
        let failure = category(&error);
        let (steps, observed) =
            super::reduce_steps(&program.steps, 128, &failure, category, |steps| {
                checked(&Program {
                    steps: steps.to_vec(),
                    ..program.clone()
                })
                .map(|_| ())
            });
        let reduced = Program {
            steps,
            ..program.clone()
        };
        let minimized = observed.as_ref().unwrap_or(&error);
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/oauth-simulation");
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!("inbound-failure-{}.json", program.seed));
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(
                &serde_json::json!({"version":1,"domain":"inbound", "implementation":implementation(),
            "original":program, "reduced":reduced,"failure":failure,"observation":error.downcast_ref::<Failure>(),
            "reduced_observation":minimized.downcast_ref::<Failure>(),
            "replay":"DAY2_OAUTH_REPLAY=<path> cargo test --locked -p day2 --lib oauth::simulation::replay_saved_oauth_history -- --exact"}),
            )?,
        )?;
        anyhow::bail!(
            "inbound OAuth simulation failed; private counterexample: {}",
            path.display()
        );
    }
    Ok(())
}

pub(super) fn replay(evidence: &serde_json::Value) -> Result<()> {
    let program: Program = serde_json::from_value(evidence["reduced"].clone())?;
    checked(&program)?;
    Ok(())
}

#[test]
fn inbound_histories_match_independent_oracle_and_replay_complete_snapshots() -> Result<()> {
    for seed in 0..32 {
        let mut schedule = seed;
        let choices = [
            Step::Consent,
            Step::Offer,
            Step::Redeem,
            Step::WrongClient,
            Step::FailedRedeem,
            Step::Narrow,
            Step::Broaden,
            Step::FailedRefresh,
            Step::ReplayRefresh,
            Step::Access,
            Step::RemovedChannel,
            Step::Revoke,
            Step::Reopen,
            Step::Advance,
        ];
        let mut steps = vec![
            Step::Consent,
            Step::Offer,
            Step::FailedRedeem,
            Step::WrongClient,
            Step::Reopen,
        ];
        match seed % 4 {
            0 => steps.extend([
                Step::Redeem,
                Step::FailedRefresh,
                Step::Narrow,
                Step::Broaden,
                Step::ReplayRefresh,
                Step::Access,
            ]),
            1 => steps.extend([Step::Advance, Step::Advance, Step::Advance, Step::Redeem]),
            2 => steps.extend([Step::Revoke, Step::Redeem, Step::Narrow]),
            _ => steps.extend([
                Step::Redeem,
                Step::Narrow,
                Step::Reopen,
                Step::Narrow,
                Step::Access,
            ]),
        }
        for _ in 0..48 {
            steps.push(choices[next(&mut schedule) as usize % choices.len()]);
        }
        verify(&Program {
            version: 1,
            seed,
            steps,
        })?;
    }
    Ok(())
}
