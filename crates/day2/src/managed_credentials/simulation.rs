//! Test-only private credential ports and an independent lifecycle oracle.
//! Exported histories contain symbolic material identities, never token bytes,
//! verifier/ciphertext bytes, key bytes or the private synthetic entropy state.

use super::{crypto::KeyLease, effects, store};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    BindingRef, Digest, Name,
    credentials::{
        CredentialRoot, FamilyDeclaration, GrantMode, LineageRef, ManagedProfile,
        ManagementSnapshot, ManagementState, ManifestFamily, Namespace, SourceLocation, VersionRef,
    },
    oauth::{
        AuthorityAction, AuthorityNode, GrantCeiling, OperationAuthorityContract, OperationKind,
        ResourceAudienceRef,
    },
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    sync::{Arc, Mutex},
    time::Duration,
};

pub(crate) struct World {
    domain: u64,
    state: Mutex<EffectsState>,
}

struct EffectsState {
    wall: i64,
    ticks: Duration,
    id_stream: u64,
    secret_stream: u64,
    secret_failure: bool,
}

impl World {
    pub(crate) fn new(id_seed: u64) -> Arc<Self> {
        Arc::new(Self {
            domain: id_seed,
            state: Mutex::new(EffectsState {
                wall: 1_000,
                ticks: Duration::ZERO,
                id_stream: id_seed,
                // Synthetic fixture entropy is private and independent of
                // replayable ID entropy. This constant never serves a host.
                secret_stream: 0xd591_64c0_8a2e_073b,
                secret_failure: false,
            }),
        })
    }

    pub(crate) fn set_wall(&self, wall: i64) {
        self.state.lock().unwrap().wall = wall;
    }

    fn advance_monotonic(&self, duration: Duration) {
        let mut state = self.state.lock().unwrap();
        state.ticks = state.ticks.checked_add(duration).unwrap();
    }

    fn fail_secret(&self, fail: bool) {
        self.state.lock().unwrap().secret_failure = fail;
    }
}

fn fill_synthetic(stream: &mut u64, bytes: &mut [u8]) {
    for byte in bytes {
        *stream = stream.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = *stream;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *byte = (value ^ (value >> 31)) as u8;
    }
}

impl effects::Hooks for World {
    fn domain(&self) -> u64 {
        self.domain
    }

    fn wall_time(&self) -> Result<i64> {
        Ok(self.state.lock().unwrap().wall)
    }

    fn monotonic(&self) -> Duration {
        self.state.lock().unwrap().ticks
    }

    fn fill_id(&self, bytes: &mut [u8]) -> Result<()> {
        fill_synthetic(&mut self.state.lock().unwrap().id_stream, bytes);
        Ok(())
    }

    fn fill_secret(&self, bytes: &mut [u8]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        ensure!(
            !state.secret_failure,
            "synthetic credential entropy unavailable"
        );
        fill_synthetic(&mut state.secret_stream, bytes);
        Ok(())
    }
}

fn name(value: &str) -> Name {
    Name::try_from(value.to_owned()).unwrap()
}

fn namespace() -> Namespace {
    Namespace {
        installation: name("fixture"),
        environment: name("disposable"),
        app: name("credential-dst"),
        binding_generation: 1,
    }
}

fn lease() -> KeyLease {
    KeyLease::new(
        &[3; 32],
        &[4; 32],
        "verifier-v1".into(),
        "encryption-v1".into(),
    )
    .unwrap()
}

fn ceiling() -> GrantCeiling {
    let operation = OperationAuthorityContract::derive(
        "fixture.submit".into(),
        1,
        Digest::of(&"fixture.submit-v1").unwrap(),
        OperationKind::Command,
        AuthorityNode {
            actions: BTreeSet::from([AuthorityAction::LocalData {
                category: "fixture-entry".into(),
                policy: Digest::of(&"own").unwrap(),
                write: true,
            }]),
            children: BTreeMap::new(),
        },
    )
    .unwrap();
    GrantCeiling::derive(
        BindingRef::pin(name("client"), &"client-v1").unwrap(),
        "fixture-client".into(),
        ResourceAudienceRef(BindingRef::pin(name("fixture-api"), &"audience-v1").unwrap()),
        BTreeMap::from([("fixture.submit".into(), operation)]),
    )
    .unwrap()
}

fn family() -> ManifestFamily {
    ManifestFamily::derive(
        FamilyDeclaration {
            registration: name("fixture_client"),
            id: name("fixture-client"),
            profile: ManagedProfile::Client,
            grant: GrantMode::Fixed,
            roots: vec!["fixture.submit".into()],
            lifetime_seconds: 2_000,
            source: SourceLocation {
                file: "Fixture.roc".into(),
                line: 1,
            },
        },
        &BTreeMap::from([(
            "fixture.submit".into(),
            CredentialRoot {
                authority: ceiling().roots["fixture.submit"].clone(),
                direct_ingress: true,
                interactive_security: false,
                single_resource_model: None,
            },
        )]),
    )
    .unwrap()
}

fn issue(now: i64) -> store::IssueIntent {
    store::IssueIntent {
        namespace: namespace(),
        family: family().id.as_str().into(),
        family_contract: family().contract,
        invocation: "issue-1".into(),
        instruction_slot: 0,
        principal: "fixture-client".into(),
        creator: "issuer/human".into(),
        recipient: "issuer/human".into(),
        session: "session-1".into(),
        label: "Synthetic client".into(),
        ceiling: ceiling(),
        issued_at: now,
        expires_at: now + 1_000,
        grant_valid_until: 5_000,
        reveal_until: now + 100,
        security_epoch: 7,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Step {
    Issue,
    LostIssueResponse,
    Reveal,
    Acknowledge,
    Rotate,
    Revoke,
    Advance(u16),
    EntropyUnavailable,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    // ID entropy only. Private synthetic secret entropy never enters this value.
    id_seed: u64,
    steps: Vec<Step>,
}

#[derive(Default)]
struct Model {
    issued: bool,
    revoked: bool,
    closed: bool,
    versions: u64,
    revision: u64,
    now: i64,
    reveal_until: i64,
}

// This oracle uses only its own symbolic state and the scheduled input. It
// never calls a production transition, policy or ciphertext helper.
impl Model {
    fn apply(&mut self, step: Step) -> bool {
        match step {
            Step::Issue | Step::LostIssueResponse => {
                if !self.issued {
                    self.issued = true;
                    self.versions = 1;
                    self.revision = 1;
                    self.reveal_until = self.now + 100;
                }
                true
            }
            Step::Reveal => {
                self.issued && !self.revoked && !self.closed && self.now < self.reveal_until
            }
            Step::Acknowledge => {
                self.closed = true;
                true
            }
            Step::Rotate => {
                if !self.issued || self.revoked || self.now >= 5_000 {
                    return false;
                }
                self.versions += 1;
                self.revision += 1;
                self.closed = false;
                self.reveal_until = self.now + 100;
                true
            }
            Step::Revoke => {
                let changed = self.issued && !self.revoked;
                if changed {
                    self.revision += 1;
                }
                self.revoked = true;
                self.closed = true;
                changed
            }
            Step::Advance(seconds) => {
                self.now += i64::from(seconds);
                true
            }
            Step::EntropyUnavailable => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Observation {
    accepted: bool,
    lineage: String,
    head: String,
    versions: u64,
    revision: u64,
    state: String,
    delivery: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Trace {
    family: Digest,
    namespace: Namespace,
    observations: Vec<Observation>,
}

#[derive(Debug)]
struct Divergence {
    category: String,
    slot: usize,
    observations: Vec<Observation>,
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "credential {} divergence at scheduled step {}",
            self.category, self.slot
        )
    }
}

impl std::error::Error for Divergence {}

fn check_observation(
    model: &Model,
    expected: bool,
    observation: &Observation,
    slot: usize,
) -> Result<()> {
    ensure!(
        observation.accepted == expected,
        "credential model divergence at scheduled step {slot}"
    );
    ensure!(
        observation.versions == model.versions && observation.revision == model.revision,
        "credential snapshot divergence at scheduled step {slot}"
    );
    ensure!(
        observation.state == if model.revoked { "revoked" } else { "active" },
        "credential state divergence at scheduled step {slot}"
    );
    ensure!(
        observation.delivery == if model.closed { "closed" } else { "available" },
        "credential delivery divergence at scheduled step {slot}"
    );
    Ok(())
}

fn run(seed: u64, steps: &[Step]) -> Result<Trace> {
    ensure!(
        steps.len() <= 32
            && steps
                .first()
                .is_some_and(|step| matches!(step, Step::Issue | Step::LostIssueResponse)),
        "credential replay requires a bounded issue-first schedule"
    );
    let world = World::new(seed);
    effects::scope(world.clone(), || {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("credentials.sqlite");
        let mut db = Connection::open(&path)?;
        store::install_schema(&db)?;
        let mut model = Model {
            now: 1_000,
            ..Model::default()
        };
        let mut receipt: Option<store::PublicReceipt> = None;
        let mut observations = Vec::new();
        for (slot, step) in steps.iter().copied().enumerate() {
            let expected = model.apply(step);
            let now = effects::wall_time()?;
            let accepted = match step {
                Step::Issue | Step::LostIssueResponse => {
                    let prepared = store::prepare_issue(&lease(), &family(), issue(now))?;
                    let tx = crate::write_queue::immediate(&mut db)?;
                    let issued = store::stage_issue(&tx, prepared)?.public_identity().clone();
                    tx.commit()?;
                    receipt = Some(issued);
                    if matches!(step, Step::LostIssueResponse) {
                        drop(db);
                        db = Connection::open(&path)?;
                        store::install_schema(&db)?;
                    }
                    true
                }
                Step::Reveal => {
                    let issued = receipt.as_ref().context("issue before reveal")?;
                    let permit = store::authorize_reveal(
                        &mut db,
                        store::VerifiedHumanPost {
                            namespace: namespace(),
                            version: issued.version.clone().unwrap(),
                            recipient: "issuer/human".into(),
                            session: "session-1".into(),
                            attempt: effects::navigation_id()?,
                            now,
                            security_epoch: 7,
                        },
                    )?;
                    if let Some(permit) = permit {
                        // The actual consuming sink decrypts only after a known
                        // authorization commit. Keep its synthetic token private.
                        let token = permit.into_response_body(&lease())?;
                        ensure!(
                            token.starts_with("d2c1."),
                            "invalid private fixture material"
                        );
                        true
                    } else {
                        false
                    }
                }
                Step::Acknowledge => {
                    let tx = crate::write_queue::immediate(&mut db)?;
                    store::close_delivery(
                        &tx,
                        receipt.as_ref().unwrap().version.as_ref().unwrap(),
                        "acknowledged",
                    )?;
                    tx.commit()?;
                    true
                }
                Step::Rotate => {
                    let issued = receipt.as_ref().context("issue before rotation")?;
                    let lineage = LineageRef {
                        namespace: namespace(),
                        family: family().id,
                        id: issued.lineage.clone(),
                    };
                    let snapshot = ManagementSnapshot {
                        head: VersionRef {
                            lineage: lineage.clone(),
                            id: issued.version.clone().unwrap(),
                        },
                        lineage,
                        revision: u64::try_from(db.query_row(
                            "SELECT revision FROM day2_credential_lineages WHERE id=?1",
                            [&issued.lineage],
                            |row| row.get::<_, i64>(0),
                        )?)?,
                        state: ManagementState::Active,
                    };
                    let tx = crate::write_queue::immediate(&mut db)?;
                    let rotated = store::stage_rotation(
                        &tx,
                        &lease(),
                        &snapshot,
                        store::RotationIntent {
                            invocation: &format!("rotate-{slot}"),
                            instruction_slot: 0,
                            recipient: "issuer/human",
                            session: "session-1",
                            issued_at: now,
                            expires_at: now + 1_000,
                            reveal_until: now + 100,
                        },
                    );
                    match rotated {
                        Ok(store::RotationResult::Rotated(pending)) => {
                            receipt = Some(pending.public_identity().clone());
                            tx.commit()?;
                            true
                        }
                        Ok(store::RotationResult::Conflict) | Err(_) => false,
                    }
                }
                Step::Revoke => {
                    let tx = crate::write_queue::immediate(&mut db)?;
                    let changed =
                        store::stage_revoke(&tx, &namespace(), &receipt.as_ref().unwrap().lineage)?;
                    tx.commit()?;
                    changed
                }
                Step::Advance(seconds) => {
                    world.set_wall(now + i64::from(seconds));
                    world.advance_monotonic(Duration::from_secs(u64::from(seconds)));
                    true
                }
                Step::EntropyUnavailable => {
                    world.fail_secret(true);
                    let failed = store::prepare_issue(&lease(), &family(), issue(now));
                    world.fail_secret(false);
                    failed.is_ok()
                }
            };
            let (lineage, head, revision, state, delivery, versions):
                (String, String, i64, String, String, i64) = db.query_row(
                "SELECT l.id,l.head,l.revision,l.state,d.state,(SELECT count(*) FROM day2_credential_versions) FROM day2_credential_lineages l JOIN day2_credential_deliveries d ON d.version=l.head",
                [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )?;
            let observation = Observation {
                accepted,
                lineage,
                head,
                revision: u64::try_from(revision)?,
                state,
                delivery,
                versions: u64::try_from(versions)?,
            };
            observations.push(observation);
            if let Err(error) =
                check_observation(&model, expected, observations.last().unwrap(), slot)
            {
                return Err(Divergence {
                    category: category(&error),
                    slot,
                    observations,
                }
                .into());
            }
        }
        Ok(Trace {
            family: family().contract,
            namespace: namespace(),
            observations,
        })
    })
}

fn implementation() -> Digest {
    Digest::of(&(
        "credential-native-store-dst-v1",
        include_str!("effects.rs"),
        include_str!("crypto.rs"),
        include_str!("store.rs"),
        include_str!("simulation.rs"),
    ))
    .unwrap()
}

fn category(error: &anyhow::Error) -> String {
    // Never export a downstream error message, which could contain secret
    // material after a regression. Only this closed oracle category is saved.
    for category in ["model", "snapshot", "state", "delivery", "replay"] {
        if error
            .to_string()
            .starts_with(&format!("credential {category} divergence"))
        {
            return category.into();
        }
    }
    "native-operation".into()
}

fn replayed(program: &Program) -> Result<Trace> {
    let first = run(program.id_seed, &program.steps)?;
    let second = run(program.id_seed, &program.steps)?;
    if first != second {
        return Err(Divergence {
            category: "replay".into(),
            slot: 0,
            observations: first
                .observations
                .into_iter()
                .chain(second.observations)
                .collect(),
        }
        .into());
    }
    Ok(first)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedFailure {
    version: u8,
    implementation: Digest,
    family: Digest,
    namespace: Namespace,
    original: Program,
    reduced: Program,
    category: String,
    observations: Vec<Observation>,
    reduced_observations: Vec<Observation>,
    replay: String,
}

fn checked(program: &Program) -> Result<Trace> {
    match replayed(program) {
        Ok(trace) => Ok(trace),
        Err(error) => {
            let failure = category(&error);
            let mut reduced = program.clone();
            let mut attempts = 0;
            let mut index = 1; // Preserve the initial issuance prerequisite.
            while index < reduced.steps.len() && attempts < 64 {
                let mut candidate = reduced.clone();
                candidate.steps.remove(index);
                attempts += 1;
                if replayed(&candidate).is_err_and(|error| category(&error) == failure) {
                    reduced = candidate;
                    index = 1;
                } else {
                    index += 1;
                }
            }
            let evidence = SavedFailure {
                version: 1, implementation: implementation(), family: family().contract,
                namespace: namespace(), original: program.clone(),
                reduced_observations: replayed(&reduced).err()
                    .and_then(|error| error.downcast::<Divergence>().ok())
                    .map(|failure| failure.observations).unwrap_or_default(),
                observations: error.downcast::<Divergence>().ok()
                    .map(|failure| failure.observations).unwrap_or_default(),
                reduced, category: failure,
                replay: "DAY2_CREDENTIAL_REPLAY=<path> cargo test --locked -p day2 --lib managed_credentials::simulation::replay_saved_credential_history -- --exact".into(),
            };
            let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../artifacts/credential-simulation");
            std::fs::create_dir_all(&directory)?;
            let path = directory.join(format!("failure-{}.json", program.id_seed));
            std::fs::write(&path, serde_json::to_vec_pretty(&evidence)?)?;
            anyhow::bail!(
                "credential simulation failed; redacted counterexample: {}",
                path.display()
            );
        }
    }
}

#[test]
fn replay_saved_credential_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_CREDENTIAL_REPLAY") else {
        return Ok(());
    };
    const MAXIMUM: u64 = 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAXIMUM + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAXIMUM,
        "credential replay byte budget"
    );
    let evidence: SavedFailure = crate::json::decode(&bytes)?;
    ensure!(
        evidence.version == 1
            && evidence.implementation == implementation()
            && evidence.family == family().contract
            && evidence.namespace == namespace(),
        "credential replay identity mismatch"
    );
    replayed(&evidence.reduced)?;
    Ok(())
}

#[test]
fn credential_lifecycle_and_consuming_sink_replay_exactly() -> Result<()> {
    for seed in [1, 19, 401] {
        for steps in [
            vec![
                Step::LostIssueResponse,
                Step::Issue,
                Step::Reveal,
                Step::Reveal,
                Step::Acknowledge,
                Step::Reveal,
                Step::Rotate,
                Step::Reveal,
                Step::Revoke,
                Step::Reveal,
            ],
            vec![
                Step::Issue,
                Step::EntropyUnavailable,
                Step::Advance(101),
                Step::Reveal,
                Step::Rotate,
                Step::Reveal,
                Step::Revoke,
                Step::Rotate,
                Step::Reveal,
            ],
        ] {
            let program = Program {
                id_seed: seed,
                steps,
            };
            checked(&program)?;
        }
    }
    Ok(())
}

#[test]
fn independent_credential_oracle_rejects_an_extra_successor() -> Result<()> {
    let mut model = Model {
        now: 1_000,
        ..Model::default()
    };
    let expected = model.apply(Step::Issue);
    let mut observed = Observation {
        accepted: true,
        lineage: "symbolic-lineage".into(),
        head: "symbolic-head".into(),
        versions: 1,
        revision: 1,
        state: "active".into(),
        delivery: "available".into(),
    };
    check_observation(&model, expected, &observed, 0)?;
    observed.versions = 2;
    assert!(check_observation(&model, expected, &observed, 0).is_err());
    Ok(())
}

// Explicit disposable fixture only; this does not install a serving authority
// or assert an external security epoch/clock service is ready.
struct HttpAuthority;

impl super::issuance::Authority for HttpAuthority {
    fn verification_epoch(
        &self,
        binding: &day2_capabilities::credentials::CredentialFamilyBinding,
        _management: &day2_capabilities::credentials::ManagementPolicy,
        _version: &str,
        _now: i64,
    ) -> Result<Option<u64>> {
        ensure!(
            binding.namespace.environment.as_str() == "disposable",
            "disposable HTTP authority required"
        );
        Ok(Some(7))
    }

    fn verification_keys(
        &self,
        binding: &day2_capabilities::credentials::CredentialFamilyBinding,
        _management: &day2_capabilities::credentials::ManagementPolicy,
        _now: i64,
    ) -> Result<super::crypto::VerifierLease> {
        ensure!(
            binding.namespace.environment.as_str() == "disposable",
            "disposable HTTP authority required"
        );
        super::crypto::VerifierLease::new(&[3; 32], "verifier-v1".into())
    }

    fn prepare(
        &self,
        binding: &day2_capabilities::credentials::CredentialFamilyBinding,
        _management: &day2_capabilities::credentials::ManagementPolicy,
        _actor: &str,
        _subject: &str,
        now: i64,
    ) -> Result<super::issuance::ReadyKeys> {
        ensure!(
            binding.namespace.environment.as_str() == "disposable",
            "disposable HTTP authority required"
        );
        Ok(super::issuance::ReadyKeys {
            keys: lease(),
            binding: Digest::of(binding)?,
            security_epoch: 7,
            valid_until: now
                .checked_add(31_536_001)
                .context("HTTP fixture deadline overflow")?,
            max_active_lineages: 100,
        })
    }

    fn validate(
        &self,
        binding: &day2_capabilities::credentials::CredentialFamilyBinding,
        _management: &day2_capabilities::credentials::ManagementPolicy,
        _actor: &str,
        _subject: &str,
        ready: &super::issuance::ReadyKeys,
        now: i64,
    ) -> Result<()> {
        ensure!(
            binding.namespace.environment.as_str() == "disposable"
                && ready.binding == Digest::of(binding)?
                && ready.security_epoch == 7
                && now < ready.valid_until,
            "disposable HTTP readiness changed"
        );
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct HttpTrace {
    artifact: String,
    invoked: Vec<String>,
    statuses: Vec<u16>,
    results: Vec<serde_json::Value>,
}

async fn http_history(seed: u64) -> Result<HttpTrace> {
    let world = World::new(seed);
    effects::scope_async(world.clone(), async {
        let artifact = std::path::PathBuf::from(
            std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
                .context("credential metadata artifact required")?,
        );
        let directory = tempfile::tempdir()?;
        let runtime = crate::development::create_verification_for(
            &artifact,
            &directory.path().join("instance"),
            None,
            "alice@example.com",
        )?;
        let mut instance = crate::artifact::Instance::load(runtime.instance_path())?;
        let binding = instance
            .apps
            .get_mut(runtime.app())
            .context("HTTP fixture app binding")?;
        binding
            .readers
            .insert("credential_client:client_keys".into());
        binding
            .writers
            .insert("credential_client:client_keys".into());
        for operation in ["credential_metadata.ping", "credential_metadata.record_use"] {
            binding
                .authority
                .as_mut()
                .context("HTTP fixture authority")?
                .operations
                .get_mut(operation)
                .context("HTTP fixture operation")?
                .actors
                .insert("credential_client:client_keys".into());
        }
        crate::development::repin_credential_verification_data(&mut instance, runtime.artifact())?;
        std::fs::write(runtime.instance_path(), serde_json::to_vec(&instance)?)?;
        let runtime = crate::store::Runtime::load(runtime.instance_path(), runtime.app())?
            .with_credential_authority(Arc::new(HttpAuthority));
        let current = crate::authority_state::current(&crate::store::open(runtime.db())?)?;
        crate::authority_state::apply_desired(
            &runtime,
            &crate::authority_state::LocalOperator::assert_local("alice@example.com")?,
            "credential-dst-http-membership",
            Some(current.stamp),
        )?;
        let simulation = crate::simulation::Simulation::new(runtime, [71; 32], 1_000_000)?;
        let runtime = simulation.runtime();
        let input = serde_json::json!({"label":"Synthetic HTTP client"});
        super::verification::confirm(
            runtime,
            "credential_metadata.create_client",
            "alice@example.com",
            "issue-http",
            &input,
            effects::wall_time()?,
        )?;
        runtime.accept(
            "credential_metadata.create_client",
            "alice@example.com",
            "issue-http",
            &input,
            effects::wall_time()?,
        )?;
        let issued = runtime.execute("issue-http", crate::store::Fault::None)?;
        ensure!(issued.status == "success", "HTTP fixture issuance failed");
        let mut db = crate::store::open(runtime.db())?;
        let active = crate::authority_state::current(&db)?;
        let namespace = active.document.credentials["client_keys"]
            .binding
            .namespace
            .clone();
        let version: String = db.query_row(
            "SELECT version FROM day2_credential_receipts WHERE invocation='issue-http'",
            [],
            |row| row.get(0),
        )?;
        let permit = store::authorize_reveal(
            &mut db,
            store::VerifiedHumanPost {
                namespace,
                version,
                recipient: "alice@example.com".into(),
                session: "verification-issue-http".into(),
                attempt: effects::navigation_id()?,
                now: effects::wall_time()?,
                security_epoch: 7,
            },
        )?
        .context("HTTP fixture private reveal")?;
        let token = permit.into_response_body(&lease())?;
        let server = crate::web::LocalServer::bind(runtime.clone(), "alice@example.com", 0).await?;
        let origin = server.origin.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(server.serve(async {
            let _ = stopped.await;
        }));
        let client = reqwest::Client::builder().no_proxy().build()?;
        let requests = async {
            let mut trace = HttpTrace {
                artifact: runtime.artifact().id().into(),
                invoked: Vec::new(),
                statuses: Vec::new(),
                results: Vec::new(),
            };
            let url = format!("{origin}{}credential_metadata.ping", super::ingress::PREFIX);
            for _ in 0..2 {
                let response = client.get(&url).bearer_auth(&token).send().await?;
                trace.statuses.push(response.status().as_u16());
                trace.invoked.push(
                    response
                        .headers()
                        .get("x-day2-invocation")
                        .context("HTTP fixture invocation missing")?
                        .to_str()?
                        .into(),
                );
                trace
                    .results
                    .push(crate::json::decode(&response.bytes().await?)?);
            }
            assert_ne!(trace.invoked[0], trace.invoked[1]);
            assert_eq!(trace.statuses, [200, 200]);
            // The native request clock must come from the captured credential
            // port on Axum's connection task and then its blocking dispatch.
            // A wall-clock jump expires the token; monotonic time stays fixed.
            world.set_wall(5_000);
            let response = client.get(&url).bearer_auth(&token).send().await?;
            trace.statuses.push(response.status().as_u16());
            ensure!(
                response.status() == reqwest::StatusCode::UNAUTHORIZED,
                "expired credential HTTP token admitted"
            );
            let body = response.bytes().await?;
            ensure!(
                !body
                    .windows(token.len())
                    .any(|window| window == token.as_bytes()),
                "secret escaped the HTTP error response"
            );
            Ok::<_, anyhow::Error>(trace)
        }
        .await;
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(5), serving).await???;
        requests
    })
    .await
}

#[tokio::test]
async fn actual_credential_http_inherits_ports_and_replays_exact_ids() -> Result<()> {
    assert_eq!(http_history(91).await?, http_history(91).await?);
    Ok(())
}

#[test]
fn credential_id_entropy_cannot_change_secret_entropy_and_clock_domains_are_distinct() -> Result<()>
{
    fn observed(world: Arc<World>, id_calls: usize) -> Result<Vec<u8>> {
        effects::scope(world, || {
            for _ in 0..id_calls {
                let _ = effects::navigation_id()?;
            }
            let mut secret = vec![0; 44];
            effects::fill_secret(&mut secret)?;
            Ok(secret)
        })
    }
    assert_eq!(observed(World::new(1), 0)?, observed(World::new(999), 27)?);
    let world = World::new(1);
    let start = effects::scope(world.clone(), effects::Instant::now);
    world.set_wall(1);
    world.advance_monotonic(Duration::from_secs(3));
    effects::scope(world, || {
        assert_eq!(effects::wall_time().unwrap(), 1);
        assert_eq!(start.checked_elapsed(), Some(Duration::from_secs(3)));
    });
    effects::scope(World::new(2), || assert!(start.checked_elapsed().is_none()));
    Ok(())
}

#[tokio::test]
async fn credential_effects_follow_async_and_blocking_scopes() -> Result<()> {
    let world = World::new(19);
    world.set_wall(42);
    effects::scope_async(world, async {
        tokio::task::yield_now().await;
        assert_eq!(effects::wall_time()?, 42);
        assert_eq!(effects::spawn_blocking(effects::wall_time).await??, 42);
        Ok::<_, anyhow::Error>(())
    })
    .await?;
    assert!(effects::wall_time()? > 42);
    Ok(())
}

#[tokio::test]
async fn credential_blocking_requests_preserve_both_tracks_and_scripted_http() -> Result<()> {
    struct HttpPorts(Arc<std::sync::atomic::AtomicUsize>);
    impl crate::oauth::effects::Hooks for HttpPorts {
        fn domain(&self) -> u64 {
            91
        }
        fn wall_time(&self) -> Result<i64> {
            Ok(73)
        }
        fn monotonic(&self) -> Duration {
            Duration::from_secs(11)
        }
        fn fill(&self, bytes: &mut [u8]) -> Result<()> {
            bytes.fill(9);
            Ok(())
        }
        fn send(
            &self,
            request: reqwest::blocking::Request,
        ) -> Result<crate::oauth::effects::Response> {
            ensure!(
                request.url().as_str() == "http://127.0.0.1:1/never-open-a-socket",
                "unexpected replay request"
            );
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(crate::oauth::effects::Response::Simulated {
                status: reqwest::StatusCode::OK,
                headers: reqwest::header::HeaderMap::new(),
                body: std::io::Cursor::new(b"scripted".to_vec()),
                peer: None,
            })
        }
    }
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let world = World::new(19);
    world.set_wall(42);
    let task = crate::oauth::effects::scope(Arc::new(HttpPorts(sends.clone())), || {
        effects::scope(world, || {
            effects::spawn_blocking(|| -> Result<()> {
                ensure!(
                    effects::wall_time()? == 42 && crate::oauth::effects::wall_time()? == 73,
                    "one effect track escaped replay"
                );
                let mut response = crate::oauth::effects::Client::builder()
                    .no_proxy()
                    .build()?
                    .get("http://127.0.0.1:1/never-open-a-socket")
                    .send()?;
                let mut body = String::new();
                response.read_to_string(&mut body)?;
                ensure!(body == "scripted", "scripted transport escaped replay");
                Ok(())
            })
        })
    });
    tokio::task::yield_now().await;
    task.await??;
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(effects::wall_time()? > 73 && crate::oauth::effects::wall_time()? > 73);
    Ok(())
}
