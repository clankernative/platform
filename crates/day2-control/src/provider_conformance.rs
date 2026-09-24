//! Explicit live-provider probes. Captured observations are not simulation replay
//! or production qualification. A persisted dispatch is never automatically repeated.

use crate::gcp_secret_conformance::{
    AliasResolution, DisableAttempt, DisableOutcome, DisabledObservation, Fixture,
    GcpSandboxClient, ObservationReason, ResponseDelivery, VersionMetadata, VersionState,
};
use crate::kubernetes_conformance::{GkeKubernetesProbe, GkeTarget, KubernetesObservation};
use crate::secrets::{AccessToken, AccessTokenProvider};
use crate::{Digest, Name};
use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    num::NonZeroU64,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

const MAX_BYTES: usize = 256 * 1024;
const MAX_EVENTS: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub format: u32,
    pub installation: Name,
    pub environment: Name,
    pub project_number: NonZeroU64,
    pub secret: String,
    pub run_marker: String,
    pub aliases: [String; 2],
    pub lost_ack_version: NonZeroU64,
    pub late_version: NonZeroU64,
    pub expires_at_unix: u64,
    pub gke: Option<GkeTarget>,
}

impl Profile {
    pub fn validate(&self, now: u64) -> Result<()> {
        ensure!(self.format == 1, "unsupported conformance profile");
        ensure!(
            self.environment.as_str() == "sandbox",
            "sandbox environment required"
        );
        ensure!(
            self.secret.starts_with("day2-conformance-") && self.secret.len() <= 255,
            "explicit disposable secret name required"
        );
        ensure!(
            self.secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
            "invalid disposable secret name"
        );
        ensure!(
            !self.run_marker.is_empty()
                && self.run_marker.len() <= 63
                && self.run_marker.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || b"_-".contains(&byte)),
            "invalid conformance ownership marker"
        );
        ensure!(
            self.lost_ack_version != self.late_version,
            "two distinct disposable versions required"
        );
        ensure!(
            self.aliases[0] != self.aliases[1],
            "two distinct aliases required"
        );
        for alias in &self.aliases {
            ensure!(
                !alias.is_empty()
                    && alias.len() <= 63
                    && alias != "latest"
                    && alias
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
                "explicit bounded aliases required"
            );
        }
        ensure!(
            self.expires_at_unix > now && self.expires_at_unix - now <= 3600,
            "conformance authorization must expire within one hour"
        );
        if let Some(gke) = &self.gke {
            gke.validate()?;
            ensure!(
                gke.project_number == self.project_number,
                "GKE project scope mismatch"
            );
            ensure!(
                gke.namespace.starts_with("day2-conformance-"),
                "disposable GKE namespace required"
            );
        }
        Ok(())
    }

    pub fn load(path: &Path, now: u64) -> Result<Self> {
        let profile: Self = serde_json::from_slice(&bounded_file(path, MAX_BYTES)?)?;
        profile.validate(now)?;
        Ok(profile)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Open,
    Aliases,
    LostAckDispatch,
    LostAckObserve,
    LateHold,
    LateObserve,
    LateDeliver,
    LateReconcile,
    Quiescence,
    Receipt,
}

impl Step {
    pub const ALL: [Self; 10] = [
        Self::Open,
        Self::Aliases,
        Self::LostAckDispatch,
        Self::LostAckObserve,
        Self::LateHold,
        Self::LateObserve,
        Self::LateDeliver,
        Self::LateReconcile,
        Self::Quiescence,
        Self::Receipt,
    ];

    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "provider-open" => Self::Open,
            "provider-aliases" => Self::Aliases,
            "provider-lost-ack-dispatch" => Self::LostAckDispatch,
            "provider-lost-ack-observe" => Self::LostAckObserve,
            "provider-late-hold" => Self::LateHold,
            "provider-late-observe" => Self::LateObserve,
            "provider-late-deliver" => Self::LateDeliver,
            "provider-late-reconcile" => Self::LateReconcile,
            "provider-quiescence" => Self::Quiescence,
            "provider-receipt" => Self::Receipt,
            _ => bail!("unknown provider conformance capability"),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    LiveGcp,
    TransportFixture,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Open {},
    Aliases {
        version: VersionMetadata,
        secret_create_time: String,
    },
    Dispatch {
        attempt: DisableAttempt,
        lose_ack: bool,
    },
    Observe {
        attempt: DisableAttempt,
    },
    Hold {
        attempt: DisableAttempt,
    },
    Quiescence {},
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    Fixture {
        fixture: Fixture,
    },
    Aliases {
        aliases: [AliasResolution; 2],
    },
    Dispatch {
        outcome: DisableOutcome,
    },
    State {
        readback: DisabledObservation,
    },
    Held {},
    Quiescence {
        observation: Option<KubernetesObservation>,
    },
}

/// Only trusted native adapters implement this boundary; it is not an app capability.
pub trait Probe {
    fn origin(&self) -> Origin;
    fn execute(&mut self, profile: &Profile, request: &Request) -> Result<Observation>;
}

pub struct LiveProbe {
    secrets: GcpSandboxClient,
    tokens: Arc<dyn AccessTokenProvider>,
}

impl LiveProbe {
    pub fn new(profile: &Profile, tokens: Arc<dyn AccessTokenProvider>) -> Result<Self> {
        let secrets = GcpSandboxClient::new(
            profile.project_number.get(),
            BTreeSet::from([profile.secret.clone()]),
            profile.run_marker.clone(),
            tokens.clone(),
        )?;
        Ok(Self { secrets, tokens })
    }
}

impl Probe for LiveProbe {
    fn origin(&self) -> Origin {
        Origin::LiveGcp
    }

    fn execute(&mut self, profile: &Profile, request: &Request) -> Result<Observation> {
        Ok(match request {
            Request::Open {} => Observation::Fixture {
                fixture: self.secrets.validate_fixture(
                    &profile.secret,
                    [profile.lost_ack_version.get(), profile.late_version.get()],
                )?,
            },
            Request::Aliases { .. } => Observation::Aliases {
                aliases: [
                    self.secrets
                        .resolve_alias(&profile.secret, &profile.aliases[0])?,
                    self.secrets
                        .resolve_alias(&profile.secret, &profile.aliases[1])?,
                ],
            },
            Request::Dispatch { attempt, lose_ack } => Observation::Dispatch {
                outcome: self.secrets.disable_once(
                    attempt,
                    if *lose_ack {
                        ResponseDelivery::LoseAck
                    } else {
                        ResponseDelivery::Deliver
                    },
                )?,
            },
            Request::Observe { attempt } => Observation::State {
                // Transient absence is inconclusive; integrity/authentication failures
                // remain failures rather than becoming plausible provider evidence.
                readback: self
                    .secrets
                    .observe_disabled(&attempt.version, &attempt.expected_create_time)?,
            },
            Request::Hold { .. } => Observation::Held {},
            Request::Quiescence {} => Observation::Quiescence {
                observation: profile
                    .gke
                    .as_ref()
                    .map(|target| GkeKubernetesProbe::new(self.tokens.as_ref())?.inspect(target))
                    .transpose()?,
            },
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    profile: Digest,
    implementation: Digest,
    origin: Origin,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum EventKind {
    Started { request: Request },
    Completed { observation: Box<Observation> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    sequence: usize,
    previous: Digest,
    step: Step,
    event: EventKind,
}

/// Holds a single-process file lease and an append-only SQLite transcript. This is
/// a probe checkpoint, not a second durable workflow engine or an authority service.
pub struct Session<P: Probe> {
    profile: Profile,
    identity: Identity,
    directory: PathBuf,
    _lock: File,
    connection: Connection,
    probe: P,
    replay_cursor: usize,
}

impl<P: Probe> Session<P> {
    pub fn open(
        directory: &Path,
        profile: Profile,
        probe: P,
        now: u64,
        resume: bool,
    ) -> Result<Self> {
        profile.validate(now)?;
        let identity = Identity {
            profile: Digest::of(&profile)?,
            implementation: implementation()?,
            origin: probe.origin(),
        };
        if !resume {
            fs::DirBuilder::new().mode(0o700).create(directory)?;
        }
        let metadata = fs::symlink_metadata(directory)?;
        ensure!(
            metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
            "private evidence directory required"
        );
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(directory.join("session.lock"))?;
        lock.try_lock()
            .context("conformance session already open")?;
        let identity_path = directory.join("identity.json");
        if resume {
            let previous: Identity =
                serde_json::from_slice(&bounded_file(&identity_path, MAX_BYTES)?)?;
            ensure!(
                serde_json::to_vec(&previous)? == serde_json::to_vec(&identity)?,
                "conformance identity mismatch"
            );
        } else {
            write_new(&identity_path, &identity)?;
            write_new(&directory.join("profile.json"), &profile)?;
        }
        let database = directory.join("observations.sqlite3");
        if resume {
            ensure!(
                fs::symlink_metadata(&database)?.is_file(),
                "missing observation journal"
            );
        }
        let connection = Connection::open(database)?;
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")?;
        if !resume {
            connection.execute_batch("PRAGMA user_version=1;
            CREATE TABLE IF NOT EXISTS observations(sequence INTEGER PRIMARY KEY, body TEXT NOT NULL, digest TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS observations_no_update BEFORE UPDATE ON observations BEGIN SELECT RAISE(ABORT,'append only'); END;
            CREATE TRIGGER IF NOT EXISTS observations_no_delete BEFORE DELETE ON observations BEGIN SELECT RAISE(ABORT,'append only'); END;
            CREATE TRIGGER IF NOT EXISTS observations_no_replace BEFORE INSERT ON observations
                WHEN EXISTS(SELECT 1 FROM observations WHERE sequence=NEW.sequence) BEGIN SELECT RAISE(ABORT,'append only'); END;")?;
        }
        let schema: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        ensure!(schema == 1, "unsupported conformance journal schema");
        let result = Self {
            profile,
            identity,
            directory: directory.to_path_buf(),
            _lock: lock,
            connection,
            probe,
            replay_cursor: 0,
        };
        result.events()?;
        Ok(result)
    }

    pub fn effect(
        &mut self,
        request: &day2::automation::Request,
        now: u64,
    ) -> Result<serde_json::Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Empty {}
        let _: Empty = request.decode()?;
        let step = Step::parse(&request.action)?;
        ensure!(
            Step::ALL.get(self.replay_cursor) == Some(&step),
            "conformance recipe order mismatch"
        );
        if step == Step::Receipt {
            let report = self.report()?;
            let path = self.directory.join("receipt.json");
            if path.exists() {
                ensure!(
                    bounded_file(&path, MAX_BYTES)? == serde_json::to_vec_pretty(&report)?,
                    "receipt mismatch"
                );
            } else {
                write_new(&path, &report)?;
            }
            self.replay_cursor += 1;
            return Ok(report);
        }
        let events = self.events()?;
        if let Some(observation) = completed(&events).get(&step) {
            self.replay_cursor += 1;
            return Ok(serde_json::to_value(observation)?);
        }
        self.profile.validate(now)?;
        let expected = self.prepare(step, &events)?;
        let pending =
            events
                .last()
                .filter(|event| event.step == step)
                .and_then(|event| match &event.event {
                    EventKind::Started { request } => Some(request),
                    _ => None,
                });
        let observation = if let Some(pending) = pending {
            ensure!(
                serde_json::to_vec(pending)? == serde_json::to_vec(&expected)?,
                "persisted probe intent mismatch"
            );
            if matches!(pending, Request::Dispatch { .. }) {
                // The previous process may have died on either side of network I/O.
                // Preserve uncertainty; reconstructing the recipe cannot redispatch.
                Observation::Dispatch {
                    outcome: DisableOutcome::Uncertain {},
                }
            } else {
                self.probe.execute(&self.profile, &expected)?
            }
        } else {
            self.append(
                step,
                EventKind::Started {
                    request: expected.clone(),
                },
            )?;
            self.probe.execute(&self.profile, &expected)?
        };
        validate_observation(&self.profile, &expected, &observation)?;
        self.append(
            step,
            EventKind::Completed {
                observation: Box::new(observation.clone()),
            },
        )?;
        self.replay_cursor += 1;
        Ok(serde_json::to_value(observation)?)
    }

    fn prepare(&self, step: Step, events: &[Event]) -> Result<Request> {
        let observations = completed(events);
        let fixture = || match observations.get(&Step::Open) {
            Some(Observation::Fixture { fixture }) => Ok(fixture),
            _ => bail!("fixture not admitted"),
        };
        let attempt = |version: &VersionMetadata, step: Step| -> Result<DisableAttempt> {
            Ok(DisableAttempt {
                effect: Digest::of(&(
                    "day2-provider-probe-v1",
                    &self.identity.profile,
                    step,
                    version,
                ))?,
                version: version.version.clone(),
                expected_etag: version.etag.clone(),
                expected_create_time: version.create_time.clone(),
            })
        };
        let prior_attempt = |prior: Step| -> Result<DisableAttempt> {
            events
                .iter()
                .find_map(|event| {
                    if event.step == prior {
                        match &event.event {
                            EventKind::Started {
                                request:
                                    Request::Dispatch { attempt, .. } | Request::Hold { attempt },
                            } => Some(attempt.clone()),
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
                .context("missing original probe intent")
        };
        Ok(match step {
            Step::Open => Request::Open {},
            Step::Aliases => Request::Aliases {
                version: fixture()?.first.clone(),
                secret_create_time: fixture()?.secret.create_time.clone(),
            },
            Step::LostAckDispatch => {
                ensure!(
                    matches!(
                        observations.get(&Step::Aliases),
                        Some(Observation::Aliases { .. })
                    ),
                    "alias check required before mutation"
                );
                Request::Dispatch {
                    attempt: attempt(&fixture()?.first, step)?,
                    lose_ack: true,
                }
            }
            Step::LostAckObserve => Request::Observe {
                attempt: prior_attempt(Step::LostAckDispatch)?,
            },
            Step::LateHold => Request::Hold {
                attempt: attempt(&fixture()?.second, step)?,
            },
            Step::LateObserve | Step::LateReconcile => Request::Observe {
                attempt: prior_attempt(Step::LateHold)?,
            },
            Step::LateDeliver => Request::Dispatch {
                attempt: prior_attempt(Step::LateHold)?,
                lose_ack: false,
            },
            Step::Quiescence => Request::Quiescence {},
            Step::Receipt => bail!("receipt has no provider request"),
        })
    }

    fn events(&self) -> Result<Vec<Event>> {
        let mut query = self
            .connection
            .prepare("SELECT sequence,body,digest FROM observations ORDER BY sequence LIMIT 65")?;
        let rows = query.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut result: Vec<Event> = Vec::new();
        let mut previous = Digest::of(&self.identity)?;
        let mut step_index = 0;
        let mut pending = false;
        for row in rows {
            let (sequence, body, digest) = row?;
            let sequence = usize::try_from(sequence)?;
            ensure!(
                result.len() < MAX_EVENTS && body.len() <= MAX_BYTES,
                "observation budget exceeded"
            );
            let event: Event = serde_json::from_str(&body)?;
            ensure!(
                sequence == result.len()
                    && event.sequence == sequence
                    && event.previous == previous
                    && Digest::of(&event)?.as_str() == digest,
                "observation chain corrupted"
            );
            ensure!(
                Step::ALL.get(step_index) == Some(&event.step),
                "observation order corrupted"
            );
            match &event.event {
                EventKind::Started { request } => {
                    ensure!(!pending, "duplicate probe start");
                    let expected = self.prepare(event.step, &result)?;
                    ensure!(
                        serde_json::to_vec(request)? == serde_json::to_vec(&expected)?,
                        "recorded request differs from admitted profile and prior observations"
                    );
                    pending = true;
                }
                EventKind::Completed { observation } => {
                    ensure!(pending, "observation without request");
                    let EventKind::Started { request } =
                        &result.last().context("request missing")?.event
                    else {
                        bail!("request missing")
                    };
                    validate_observation(&self.profile, request, observation)?;
                    pending = false;
                    step_index += 1;
                }
            }
            previous = Digest::of(&event)?;
            result.push(event);
        }
        Ok(result)
    }

    fn append(&self, step: Step, event: EventKind) -> Result<()> {
        let events = self.events()?;
        ensure!(events.len() < MAX_EVENTS, "probe event budget exceeded");
        let previous = events
            .last()
            .map(Digest::of)
            .transpose()?
            .unwrap_or(Digest::of(&self.identity)?);
        let event = Event {
            sequence: events.len(),
            previous,
            step,
            event,
        };
        let body = serde_json::to_string(&event)?;
        ensure!(body.len() <= MAX_BYTES, "probe observation too large");
        self.connection.execute(
            "INSERT INTO observations(sequence,body,digest) VALUES(?1,?2,?3)",
            params![
                i64::try_from(event.sequence)?,
                body,
                Digest::of(&event)?.as_str()
            ],
        )?;
        Ok(())
    }

    pub fn report(&self) -> Result<serde_json::Value> {
        let events = self.events()?;
        let observations = completed(&events);
        ensure!(
            observations.len() == 9 && events.len() == 18,
            "incomplete provider probes"
        );
        let last = events.last().context("missing observations")?;
        let state = |step| match observations.get(&step) {
            Some(Observation::State {
                readback: DisabledObservation::DisabledObservation { metadata },
            }) => Some(metadata.state),
            Some(Observation::State {
                readback:
                    DisabledObservation::Inconclusive {
                        metadata: Some(metadata),
                        ..
                    },
            }) => Some(metadata.state),
            _ => None,
        };
        let lost_ack_observed = matches!(
            observations.get(&Step::LostAckDispatch),
            Some(Observation::Dispatch {
                outcome: DisableOutcome::Uncertain {}
            })
        ) && state(Step::LostAckObserve) == Some(VersionState::Disabled);
        let delivered = match observations.get(&Step::LateDeliver) {
            Some(Observation::Dispatch {
                outcome: DisableOutcome::Acknowledged { metadata },
            }) => Some(metadata),
            _ => None,
        };
        let late_application_observed = state(Step::LateObserve) == Some(VersionState::Enabled)
            && delivered.is_some_and(|acknowledged| matches!(observations.get(&Step::LateReconcile),
                Some(Observation::State { readback: DisabledObservation::DisabledObservation { metadata } })
                    if metadata == acknowledged));
        Ok(serde_json::json!({
            "format": 1, "status": "observed_not_qualified", "origin": self.identity.origin,
            "identity": self.identity, "transcript": Digest::of(last)?, "provider_qualified": false,
            "observations": observations,
            "checks": {
                "canonical_aliases": "observed_exact_numeric_identity",
                "lost_ack": if lost_ack_observed {"disabled_state_observed_without_redispatch"} else {"inconclusive_no_redispatch"},
                "late_application": if late_application_observed {"controlled_late_delivery_observed"} else {"inconclusive"},
                "physical_quiescence": if self.profile.gke.is_some() {"unproven"} else {"not_configured"},
                "remote_nonapplication_proof": "unsupported"
            },
            "limitations": ["opaque_etag_is_not_native_ordered_revision", "disabled_readback_is_not_exact_effect_attribution",
                "remote_absence_cannot_exclude_late_application", "kubernetes_api_is_not_physical_quiescence"],
            "cleanup": {"automatic": false, "secret": self.profile.secret,
                "versions": [self.profile.lost_ack_version, self.profile.late_version],
                "instruction": "Keep these disposable versions disabled. Cleanup requires explicit operator review; no destroy or re-enable is performed."},
            "live_provider_calls_replayed": false
        }))
    }
}

fn completed(events: &[Event]) -> BTreeMap<Step, Observation> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            EventKind::Completed { observation } => {
                Some((event.step, observation.as_ref().clone()))
            }
            _ => None,
        })
        .collect()
}

fn validate_observation(
    profile: &Profile,
    request: &Request,
    observation: &Observation,
) -> Result<()> {
    match (request, observation) {
        (Request::Open {}, Observation::Fixture { fixture }) => {
            ensure!(
                fixture.first.version.project_number == profile.project_number.get()
                    && fixture.second.version.project_number == profile.project_number.get()
                    && fixture.first.version.secret == profile.secret
                    && fixture.second.version.secret == profile.secret
                    && fixture.first.version.version == profile.lost_ack_version.get()
                    && fixture.second.version.version == profile.late_version.get(),
                "fixture identity mismatch"
            );
            ensure!(
                fixture.secret.project_number == profile.project_number.get()
                    && fixture.secret.secret == profile.secret
                    && fixture.secret.run_marker == profile.run_marker
                    && fixture.first.state == VersionState::Enabled
                    && fixture.second.state == VersionState::Enabled,
                "fixture ownership or initial state mismatch"
            );
        }
        (
            Request::Aliases {
                version,
                secret_create_time,
            },
            Observation::Aliases { aliases },
        ) => {
            for (alias, expected) in aliases.iter().zip(&profile.aliases) {
                ensure!(
                    &alias.alias == expected
                        && alias.version.version.project_number == profile.project_number.get()
                        && alias.version.version.secret == profile.secret
                        && alias.version.version.version == profile.lost_ack_version.get(),
                    "aliases must resolve to the exact shared numeric version"
                );
                ensure!(
                    alias.parent.project_number == profile.project_number.get()
                        && alias.parent.secret == profile.secret
                        && alias.parent.run_marker == profile.run_marker
                        && alias.parent.create_time == *secret_create_time
                        && alias.version.create_time == version.create_time
                        && alias.parent.version_aliases.get(expected)
                            == Some(&profile.lost_ack_version.get()),
                    "alias metadata scope mismatch"
                );
            }
        }
        (Request::Observe { attempt }, Observation::State { readback }) => {
            let coherent = match readback {
                DisabledObservation::DisabledObservation { metadata } => {
                    metadata.state == VersionState::Disabled
                }
                DisabledObservation::Inconclusive {
                    reason: ObservationReason::NotDisabled,
                    metadata: Some(metadata),
                } => metadata.state == VersionState::Enabled,
                DisabledObservation::Inconclusive {
                    reason: ObservationReason::Destroyed,
                    metadata: Some(metadata),
                } => metadata.state == VersionState::Destroyed,
                DisabledObservation::Inconclusive {
                    reason:
                        ObservationReason::NotFound
                        | ObservationReason::TransportUnknown
                        | ObservationReason::RateLimited,
                    metadata: None,
                } => true,
                _ => false,
            };
            ensure!(coherent, "contradictory provider readback");
            let metadata = match readback {
                DisabledObservation::DisabledObservation { metadata } => Some(metadata),
                DisabledObservation::Inconclusive { metadata, .. } => metadata.as_ref(),
            };
            if let Some(metadata) = metadata {
                ensure!(
                    metadata.version == attempt.version
                        && metadata.create_time == attempt.expected_create_time,
                    "observed resource identity changed"
                );
            }
        }
        (Request::Dispatch { attempt, .. }, Observation::Dispatch { outcome }) => {
            if let DisableOutcome::Acknowledged { metadata } = outcome {
                ensure!(
                    metadata.version == attempt.version
                        && metadata.create_time == attempt.expected_create_time
                        && metadata.state == VersionState::Disabled
                        && metadata.etag != attempt.expected_etag,
                    "disable acknowledgement mismatch"
                );
            }
        }
        (Request::Hold { .. }, Observation::Held {}) => {}
        (Request::Quiescence {}, Observation::Quiescence { observation }) => {
            ensure!(
                profile.gke.is_some() == observation.is_some(),
                "missing configured GKE observation"
            );
            if let (Some(target), Some(observation)) = (&profile.gke, observation) {
                ensure!(
                    &observation.target == target && observation.format == 1,
                    "GKE observation scope mismatch"
                );
            }
        }
        _ => bail!("provider observation shape mismatch"),
    }
    Ok(())
}

pub fn implementation() -> Result<Digest> {
    Digest::of(&(
        "day2-provider-conformance-v1",
        include_str!("provider_conformance.rs"),
        include_str!("gcp_secret_conformance.rs"),
        include_str!("kubernetes_conformance.rs"),
        include_str!("secrets.rs"),
        include_str!("../../../Cargo.lock"),
        day2::automation::source_digest(),
    ))
}

pub fn bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "bounded regular file required"
    );
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "file read budget exceeded");
    Ok(bytes)
}

fn write_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(bytes.len() <= MAX_BYTES, "evidence file budget exceeded");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("evidence parent missing")?)?.sync_all()?;
    Ok(())
}

/// Explicit operator-supplied token only. Never consult ADC, metadata, ambient
/// gcloud configuration or environment variables, and never serialize the token.
pub struct FileToken(String);

impl FileToken {
    pub fn load(path: &Path) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(path)?.permissions().mode() & 0o077 == 0,
            "private token file required"
        );
        let raw = String::from_utf8(bounded_file(path, 8193)?)?;
        let value = raw.trim_end_matches(['\n', '\r']).to_owned();
        AccessToken::new(value.clone())?;
        Ok(Self(value))
    }
}

impl AccessTokenProvider for FileToken {
    fn access_token(&self) -> std::result::Result<AccessToken, crate::source::SourceError> {
        AccessToken::new(self.0.clone())
    }
}
