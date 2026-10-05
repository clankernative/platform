//! Seeded histories execute production parsers, custody, account approval and
//! protocol hosts. The oracle uses symbolic state and never calls a production
//! transition to predict a result. HTTP faults and both clocks are controlled.

use super::registration;
use super::{connect, effects, exchange, external, outbound, profiles};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

#[path = "simulation_sources.rs"]
mod sources;

#[path = "simulation_inbound.rs"]
mod inbound_campaign;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    version: u32,
    seed: u64,
    steps: Vec<Step>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    Begin,
    Callback,
    WrongSession,
    Exchange,
    LostExchange,
    Approve,
    WrongAccount,
    Cancel,
    Expire,
    Reopen,
    Advance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SymbolicState {
    Absent,
    Awaiting,
    Ready,
    Uncertain,
    Approval,
    Active,
    Cancelled,
    Expired,
}

struct Model {
    state: SymbolicState,
    now: i64,
}

impl Model {
    fn step(&mut self, step: Step) -> bool {
        use SymbolicState::*;
        match step {
            Step::Begin if self.state == Absent && self.now < 100 => {
                self.state = Awaiting;
                true
            }
            Step::Callback if self.state == Awaiting && self.now < 100 => {
                self.state = Ready;
                true
            }
            Step::Exchange if self.state == Ready && self.now < 100 => {
                self.state = Approval;
                true
            }
            Step::LostExchange if self.state == Ready && self.now < 100 => {
                self.state = Uncertain;
                true
            }
            Step::Approve if self.state == Approval && self.now < 100 => {
                self.state = Active;
                true
            }
            Step::Cancel if matches!(self.state, Awaiting | Ready | Uncertain | Approval) => {
                self.state = Cancelled;
                true
            }
            Step::Expire
                if matches!(self.state, Awaiting | Ready | Uncertain | Approval)
                    && self.now >= 100 =>
            {
                self.state = Expired;
                true
            }
            Step::Reopen => true,
            Step::Advance => {
                self.now += 37;
                true
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    accepted: bool,
    state: String,
    snapshot: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    version: u32,
    implementation: String,
    program: Program,
    observations: Vec<Observation>,
}

#[derive(Default)]
struct Provider {
    replies: VecDeque<(u16, String)>,
    requests: Vec<(String, String)>,
    fail_at: Option<usize>,
}

pub(crate) struct World {
    domain: u64,
    wall: Mutex<i64>,
    ticks: Mutex<Duration>,
    entropy: Mutex<u64>,
    provider: Mutex<Provider>,
}

impl World {
    pub(crate) fn new(seed: u64) -> Arc<Self> {
        static DOMAINS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Arc::new(Self {
            domain: DOMAINS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            wall: Mutex::new(5),
            ticks: Mutex::new(Duration::from_secs(10_000)),
            entropy: Mutex::new(seed ^ 0x6f617574685f7465),
            provider: Mutex::new(Provider::default()),
        })
    }

    pub(crate) fn advance(&self, seconds: u64) {
        *self.wall.lock().unwrap() += seconds as i64;
        *self.ticks.lock().unwrap() += Duration::from_secs(seconds);
    }

    pub(crate) fn script(&self, replies: Vec<(u16, String)>, fault: Option<usize>) {
        let mut provider = self.provider.lock().unwrap();
        provider.replies = replies.into();
        provider.fail_at = fault;
    }

    pub(crate) fn requests(&self) -> Vec<(String, String)> {
        self.provider.lock().unwrap().requests.clone()
    }
}

fn next(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e3779b97f4a7c15);
    let mut value = *seed;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

impl effects::Hooks for World {
    fn domain(&self) -> u64 {
        self.domain
    }
    fn wall_time(&self) -> Result<i64> {
        Ok(*self.wall.lock().unwrap())
    }
    fn monotonic(&self) -> Duration {
        *self.ticks.lock().unwrap()
    }
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        let mut seed = self.entropy.lock().unwrap();
        for chunk in bytes.chunks_mut(8) {
            let random = next(&mut seed).to_le_bytes();
            chunk.copy_from_slice(&random[..chunk.len()]);
        }
        Ok(())
    }
    fn send(&self, request: reqwest::blocking::Request) -> Result<effects::Response> {
        let mut provider = self.provider.lock().unwrap();
        let index = provider.requests.len();
        let host = request.url().host_str().unwrap_or_default();
        ensure!(
            matches!(
                host,
                "oauth2.googleapis.com"
                    | "openidconnect.googleapis.com"
                    | "secretmanager.googleapis.com"
                    | "www.googleapis.com"
                    | "169.254.169.254"
                    | "compute.googleapis.com"
                    | "cloudresourcemanager.googleapis.com"
                    | "iamcredentials.googleapis.com"
                    | "www.gstatic.com"
                    | "security.example.com"
                    | "app.example"
                    | "gitlab.com"
            ),
            "unselected simulation endpoint"
        );
        // Only public address roles are recorded. Headers and request bodies
        // contain private material and never enter counterexample evidence.
        provider
            .requests
            .push((request.method().to_string(), request.url().path().into()));
        ensure!(provider.fail_at != Some(index), "simulated response loss");
        let (status, body) = provider
            .replies
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("unscripted OAuth request"))?;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("content-type", "application/json".parse()?);
        headers.insert("metadata-flavor", "Google".parse()?);
        Ok(effects::Response::Simulated {
            status: reqwest::StatusCode::from_u16(status)?,
            headers,
            body: std::io::Cursor::new(body.into_bytes()),
            peer: Some("203.0.113.42:443".parse()?),
        })
    }
}

fn implementation() -> String {
    crate::digest(
        &serde_json::to_vec(&(
            sources::SOURCES,
            crate::automation::source_digest(),
            crate::automation::toolchain_digest(),
            std::env::consts::OS,
            std::env::consts::ARCH,
        ))
        .expect("fixed OAuth source catalog"),
    )
}

#[derive(Debug, Serialize)]
struct Divergence {
    category: &'static str,
    expected: SymbolicState,
    predicted_acceptance: bool,
    trace: Trace,
    replay: Option<Trace>,
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.category)
    }
}
impl std::error::Error for Divergence {}

/// Complete bounded reserved-table snapshots. Blobs are fingerprints, not
/// exported encrypted material. Every row and every column participates.
fn snapshot(db: &Connection) -> Result<serde_json::Value> {
    let mut tables = db.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'oauth_%' ORDER BY name",
    )?;
    let names = tables
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut value = serde_json::Map::new();
    for table in names {
        ensure!(
            table
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid private table name"
        );
        let mut statement = db.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
        let columns = statement
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut rows = statement.query([])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            ensure!(records.len() < 128, "OAuth snapshot row budget exceeded");
            let mut record = serde_json::Map::new();
            for (index, column) in columns.iter().enumerate() {
                use rusqlite::types::ValueRef;
                let field = match row.get_ref(index)? {
                    ValueRef::Null => serde_json::Value::Null,
                    ValueRef::Integer(number) => number.into(),
                    ValueRef::Real(_) => anyhow::bail!("unsupported OAuth snapshot value"),
                    ValueRef::Text(bytes) => std::str::from_utf8(bytes)?.into(),
                    ValueRef::Blob(bytes) => {
                        serde_json::json!({"bytes":bytes.len(), "fingerprint":crate::digest(bytes)})
                    }
                };
                record.insert(column.clone(), field);
            }
            records.push(serde_json::Value::Object(record));
        }
        value.insert(table, records.into());
    }
    Ok(value.into())
}

fn actual_state(db: &Connection, attempt: &str) -> Result<SymbolicState> {
    use connect::ConnectState::*;
    Ok(match connect::state(db, attempt)? {
        None => SymbolicState::Absent,
        Some(AwaitingProviderAuthorization) => SymbolicState::Awaiting,
        Some(ExchangeReady) => SymbolicState::Ready,
        Some(ExchangeUncertain) => SymbolicState::Uncertain,
        Some(AwaitingAccountApproval) => SymbolicState::Approval,
        Some(Activated { .. }) => SymbolicState::Active,
        Some(Cancelled) => SymbolicState::Cancelled,
        Some(Expired) => SymbolicState::Expired,
        state => anyhow::bail!("unexpected OAuth state {state:?}"),
    })
}

fn run(program: &Program) -> Result<Trace> {
    ensure!(
        program.version == 1 && program.steps.len() <= 256,
        "unsupported OAuth history"
    );
    let world = World::new(program.seed);
    effects::scope(world.clone(), || {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("oauth.sqlite");
        let mut db = Connection::open(&path)?;
        db.execute_batch("PRAGMA journal_mode=WAL;")?;
        connect::install_schema(&db)?;
        let fixture = profiles::tests::external_fixture();
        let key = profiles::tests::exchange_key();
        let mut model = Model {
            state: SymbolicState::Absent,
            now: 5,
        };
        let mut code_ref = String::new();
        let mut observations = Vec::new();
        for &step in &program.steps {
            if matches!(step, Step::Approve | Step::WrongAccount) {
                world.advance(1);
                model.now += 1;
            }
            let predicted = model.step(step);
            let now = effects::wall_time()?;
            let actual = match step {
                Step::Begin => {
                    let prepared = exchange::prepare_authorization(
                        fixture.input(),
                        &key,
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
                    )?;
                    code_ref = prepared.code_ref().into();
                    prepared.begin(&mut db, now).unwrap_or(false)
                }
                Step::Callback | Step::WrongSession => {
                    let wrong = Digest::of(&"different_session")?;
                    let result = exchange::handle_qualified_callback(&mut db, fixture.input(), outbound::CallbackIngress {
                        attempt: &fixture.intent.attempt,
                        raw_query: b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&code=secret_code&iss=https%3A%2F%2Fissuer.example%2Ftenant",
                        route: &fixture.instance.registration.callback,
                        session: if matches!(step, Step::WrongSession) { &wrong } else { fixture.binding.session() },
                        issuer_binding: &fixture.reviewed.issuer, code_ref: &code_ref, now,
                    }, &key)?;
                    matches!(result, outbound::CallbackOutcome::CodeAccepted { .. })
                }
                Step::Exchange | Step::LostExchange => {
                    if let Some(permit) = exchange::authorize_and_commit_qualified_exchange(
                        &mut db,
                        fixture.input(),
                        now,
                    )? {
                        let outcome = permit.send(|request| {
                            ensure!(request.load_code(&db, &key)? == "secret_code", "private code mismatch");
                            request.load_verifier(&db, &key)?;
                            if matches!(step, Step::LostExchange) { anyhow::bail!("provider accepted; response lost"); }
                            Ok(exchange::TokenHttpResponse { status: 200, content_type: "application/json".into(),
                                body: br#"{"access_token":"secret_external_access","token_type":"Bearer","expires_in":3600,"scope":"calendar.read"}"#.to_vec() })
                        });
                        match outcome {
                            exchange::ExchangeObservation::Uncertain(uncertain) => {
                                uncertain.record(&db)?
                            }
                            exchange::ExchangeObservation::Response(response) => {
                                let account = super::account::ProviderAccount {
                                    issuer: fixture.reviewed.issuer_url.clone(),
                                    subject: "subject_1".into(),
                                    tenant: "tenant_1".into(),
                                    display_email: "person@example.com".into(),
                                };
                                let prepared = response
                                    .validate_external(fixture.input(), &account)?
                                    .prepare_quarantine(&key, now)?;
                                external::quarantine_external(
                                    &mut db,
                                    prepared,
                                    fixture.input(),
                                    now,
                                )?
                            }
                        }
                    } else {
                        false
                    }
                }
                Step::Approve | Step::WrongAccount => {
                    if let Some(pending) =
                        external::load_pending_external(&db, fixture.input(), &key, now)?
                    {
                        let shell = external::ShellApprovalKeyLease::new(
                            &[12; 32],
                            "shell_v1".into(),
                            pending.security_origin().clone(),
                            pending.approval_binding().clone(),
                        )?;
                        let mut input_fixture = fixture.clone();
                        if matches!(step, Step::WrongAccount) {
                            input_fixture.intent.owner = "other_human".into();
                        }
                        let proof =
                            shell.attest(&pending, Digest::of(&"fresh_session")?, now, now)?;
                        external::approve_external(
                            &mut db,
                            input_fixture.input(),
                            &key,
                            &shell,
                            proof,
                            now,
                        )
                        .unwrap_or(false)
                    } else {
                        false
                    }
                }
                Step::Cancel => connect::cancel(&mut db, &fixture.intent.attempt, |_| Ok(()))?,
                Step::Expire => connect::expire(&mut db, &fixture.intent.attempt, now, |_| Ok(()))?,
                Step::Reopen => {
                    drop(db);
                    db = Connection::open(&path)?;
                    connect::install_schema(&db)?;
                    true
                }
                Step::Advance => {
                    world.advance(37);
                    true
                }
            };
            let state = actual_state(&db, &fixture.intent.attempt)?;
            observations.push(Observation {
                accepted: actual,
                state: serde_json::to_string(&state)?,
                snapshot: snapshot(&db)?,
            });
            if actual != predicted || state != model.state {
                return Err(Divergence {
                    category: if actual != predicted {
                        "oracle_acceptance"
                    } else {
                        "oracle_state"
                    },
                    expected: model.state,
                    predicted_acceptance: predicted,
                    trace: Trace {
                        version: 1,
                        implementation: implementation(),
                        program: program.clone(),
                        observations,
                    },
                    replay: None,
                }
                .into());
            }
        }
        Ok(Trace {
            version: 1,
            implementation: implementation(),
            program: program.clone(),
            observations,
        })
    })
}

fn generated(seed: u64) -> Program {
    let mut schedule = seed;
    let choices = [
        Step::Begin,
        Step::Callback,
        Step::WrongSession,
        Step::Exchange,
        Step::LostExchange,
        Step::Approve,
        Step::WrongAccount,
        Step::Cancel,
        Step::Expire,
        Step::Reopen,
        Step::Advance,
    ];
    let mut steps = Vec::new();
    // Each campaign witnesses a real complete path before generated adversity.
    steps.extend([
        Step::Begin,
        Step::WrongSession,
        Step::Callback,
        Step::WrongSession,
    ]);
    match seed % 4 {
        0 => steps.extend([
            Step::Exchange,
            Step::WrongAccount,
            Step::Reopen,
            Step::Approve,
        ]),
        1 => steps.extend([Step::LostExchange, Step::Reopen, Step::Exchange]),
        2 => steps.extend([
            Step::Exchange,
            Step::Advance,
            Step::Advance,
            Step::Advance,
            Step::Approve,
            Step::Expire,
        ]),
        _ => steps.extend([Step::Cancel, Step::Exchange, Step::Approve]),
    }
    for _ in 0..48 {
        steps.push(choices[next(&mut schedule) as usize % choices.len()]);
    }
    Program {
        version: 1,
        seed,
        steps,
    }
}

fn checked(program: &Program) -> Result<Trace> {
    let trace = run(program)?;
    let replay = run(program)?;
    if trace != replay {
        return Err(Divergence {
            category: "exact_replay",
            expected: SymbolicState::Absent,
            predicted_acceptance: false,
            trace,
            replay: Some(replay),
        }
        .into());
    }
    Ok(trace)
}

fn failure_category(error: &anyhow::Error) -> String {
    error
        .downcast_ref::<Divergence>()
        .map_or_else(|| error.to_string(), |failure| failure.category.into())
}

/// Keep the actual last failing observation. Re-running a reduced history and
/// assuming it fails again would discard evidence of intermittent nondeterminism.
pub(super) fn reduce_steps<T: Clone>(
    steps: &[T],
    budget: usize,
    category: &str,
    classify: impl Fn(&anyhow::Error) -> String,
    mut check: impl FnMut(&[T]) -> Result<()>,
) -> (Vec<T>, Option<anyhow::Error>) {
    let mut reduced = steps.to_vec();
    let mut observed = None;
    let mut index = 0;
    let mut attempts = 0;
    while index < reduced.len() && attempts < budget {
        let mut candidate = reduced.clone();
        candidate.remove(index);
        attempts += 1;
        if let Err(error) = check(&candidate)
            && classify(&error) == category
        {
            reduced = candidate;
            observed = Some(error);
            continue;
        }
        index += 1;
    }
    (reduced, observed)
}

#[test]
fn reduction_keeps_observed_evidence_when_a_failure_does_not_repeat() {
    let mut calls = 0;
    let (steps, observed) = reduce_steps(
        &[1, 2, 3],
        8,
        "replay",
        |error| error.to_string(),
        |_| {
            calls += 1;
            if calls == 1 {
                anyhow::bail!("replay");
            }
            Ok(())
        },
    );
    assert_eq!(steps, [2, 3]);
    assert_eq!(observed.unwrap().to_string(), "replay");
    let (steps, observed) =
        reduce_steps(&[1, 2], 8, "replay", |error| error.to_string(), |_| Ok(()));
    assert_eq!(steps, [1, 2]);
    assert!(
        observed.is_none(),
        "retain the original failure when no reduction repeats it"
    );
}

fn verify(program: &Program) -> Result<Trace> {
    match checked(program) {
        Ok(trace) => Ok(trace),
        Err(error) => {
            let fingerprint = failure_category(&error);
            // Bounded semantic deletion preserves the failing oracle category.
            // Reduction never approves or modifies the committed regression corpus.
            let (steps, observed) = reduce_steps(
                &program.steps,
                256,
                &fingerprint,
                failure_category,
                |steps| {
                    checked(&Program {
                        steps: steps.to_vec(),
                        ..program.clone()
                    })
                    .map(|_| ())
                },
            );
            let reduced = Program {
                steps,
                ..program.clone()
            };
            let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../artifacts/oauth-simulation");
            std::fs::create_dir_all(&directory)?;
            let path = directory.join(format!("failure-{}.json", program.seed));
            let minimized = observed.as_ref().unwrap_or(&error);
            let evidence = serde_json::json!({ "version":1, "implementation":implementation(), "original":program,
                "reduced":reduced, "failure":fingerprint, "observation":error.downcast_ref::<Divergence>(),
                "reduced_observation":minimized.downcast_ref::<Divergence>(),
                "replay":"DAY2_OAUTH_REPLAY=<path> cargo test --locked -p day2 --lib oauth::simulation::replay_saved_oauth_history -- --exact" });
            std::fs::write(&path, serde_json::to_vec_pretty(&evidence)?)?;
            anyhow::bail!(
                "OAuth simulation failed; private counterexample: {}",
                path.display()
            )
        }
    }
}

#[test]
fn replay_saved_oauth_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_OAUTH_REPLAY") else {
        return Ok(());
    };
    const MAX_REPLAY_BYTES: u64 = 64 * 1024 * 1024;
    ensure!(
        std::fs::metadata(&path)?.len() <= MAX_REPLAY_BYTES,
        "OAuth replay byte budget"
    );
    let bytes = std::fs::read(path)?;
    ensure!(
        bytes.len() as u64 <= MAX_REPLAY_BYTES,
        "OAuth replay byte budget"
    );
    let evidence: serde_json::Value = crate::json::decode(&bytes)?;
    ensure!(
        evidence["version"] == 1 && evidence["implementation"] == implementation(),
        "OAuth replay implementation mismatch"
    );
    if evidence["domain"] == "inbound" {
        return inbound_campaign::replay(&evidence);
    }
    if evidence["domain"] == "registration" {
        let seed = evidence["seed"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("registration replay seed missing"))?;
        let fault = serde_json::from_value(evidence["fault"].clone())?;
        let expires = evidence["expires"]
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("registration replay expiry missing"))?;
        let driver = serde_json::from_value(evidence["driver"].clone())?;
        checked_registration(seed, fault, expires, driver)?;
        return Ok(());
    }
    ensure!(
        evidence.get("domain").is_none() || evidence["domain"] == "outbound",
        "unsupported OAuth replay domain"
    );
    let program: Program = serde_json::from_value(evidence["reduced"].clone())?;
    checked(&program)?;
    Ok(())
}

#[test]
fn composed_oauth_histories_replay_exactly_without_network() -> Result<()> {
    for seed in 0..32 {
        let program = generated(seed);
        let first = verify(&program)?;
        let exported = serde_json::to_string(&first)?;
        for canary in [
            "secret_code",
            "secret_external_access",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        ] {
            ensure!(
                !exported.contains(canary),
                "private OAuth material escaped into replay evidence"
            );
        }
    }
    for steps in [
        vec![
            Step::Begin,
            Step::Callback,
            Step::LostExchange,
            Step::Reopen,
            Step::Exchange,
            Step::Cancel,
        ],
        vec![
            Step::Begin,
            Step::Callback,
            Step::Exchange,
            Step::Advance,
            Step::Advance,
            Step::Advance,
            Step::Approve,
            Step::Expire,
        ],
        vec![
            Step::Begin,
            Step::Callback,
            Step::Cancel,
            Step::Exchange,
            Step::Approve,
        ],
    ] {
        let program = Program {
            version: 1,
            seed: 42,
            steps,
        };
        ensure!(
            run(&program)? == run(&program)?,
            "OAuth fault replay diverged"
        );
    }
    Ok(())
}

pub(super) fn registration_codes(target: &registration::Target) -> Result<registration::Codes> {
    let human = Digest::of(&"verified-shell-session")?;
    let code = |purpose, value: &str| -> Result<registration::Code> {
        let (authorization, location) =
            registration::Authorization::begin(target, purpose, human.clone())?;
        let url = url::Url::parse(&location)?;
        let state = url
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1
            .into_owned();
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", &state)
            .append_pair("code", value)
            .finish();
        authorization.complete(query.as_bytes(), &human)
    };
    Ok(registration::Codes {
        positive: code(
            registration::Purpose::Positive,
            "private-fixture-code-canary",
        )?,
        reject_pkce: code(registration::Purpose::RejectPkce, "negative-pkce-code")?,
        reject_credential: code(
            registration::Purpose::RejectCredential,
            "negative-credential-code",
        )?,
    })
}

pub(super) const REGISTRATION_ACTIONS: [&str; 9] = [
    "oauth-registration-open",
    "oauth-registration-reject-pkce",
    "oauth-registration-verify-pkce",
    "oauth-registration-reject-credential",
    "oauth-registration-exchange",
    "oauth-registration-account",
    "oauth-registration-refresh",
    "oauth-registration-refresh-account",
    "oauth-registration-seal",
];

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RegistrationDriver {
    GoogleMapped,
    GoogleExternal,
    GitlabExternal,
}

impl RegistrationDriver {
    fn target(self) -> Result<registration::Target> {
        use day2_capabilities::oauth::AccountBindingPolicy::*;
        match self {
            Self::GoogleMapped => registration::tests::target_for(MappedHuman),
            Self::GoogleExternal => registration::tests::target_for(ExplicitExternalAccount),
            Self::GitlabExternal => registration::tests::gitlab_target(),
        }
    }

    fn responses(self) -> Vec<(u16, String)> {
        match self {
            Self::GoogleMapped | Self::GoogleExternal => registration::tests::responses(),
            Self::GitlabExternal => registration::tests::gitlab_responses(),
        }
    }

    /// Independent protocol obligations, not counts learned from production I/O.
    fn calls(self) -> [usize; 9] {
        match self {
            Self::GoogleMapped | Self::GoogleExternal => [1; 9],
            Self::GitlabExternal => [1, 1, 2, 1, 2, 1, 2, 1, 1],
        }
    }

    fn pins(self) -> (&'static str, &'static str, &'static str, &'static str) {
        match self {
            Self::GoogleMapped | Self::GoogleExternal => (
                "google_calendar_simulator_v1",
                "google-calendar-registration-reference-v1",
                "google_calendar_conformance_v1",
                "google-calendar-registration-wire-campaign-v1",
            ),
            Self::GitlabExternal => (
                "gitlab_projects_simulator_v1",
                "gitlab-projects-registration-reference-v1",
                "gitlab_projects_conformance_v1",
                "gitlab-projects-registration-wire-campaign-v1",
            ),
        }
    }
}

fn registration_campaign(
    seed: u64,
    fault: Option<usize>,
    expires: bool,
    driver: RegistrationDriver,
) -> Result<serde_json::Value> {
    ensure!(
        fault.is_none_or(|at| at < driver.calls().iter().sum::<usize>()),
        "invalid registration fault boundary"
    );
    let world = World::new(seed);
    world.provider.lock().unwrap().replies = driver.responses().into();
    world.provider.lock().unwrap().fail_at = fault;
    effects::scope(world.clone(), || {
        let target = driver.target()?;
        let codes = registration_codes(&target)?;
        let mut session = registration::Session::new(
            target,
            codes,
            Arc::new(registration::tests::TokensSource(
                std::sync::atomic::AtomicUsize::new(0),
            )),
        )?;
        let mut results = Vec::new();
        let mut end = 0;
        let mut expired = false;
        for (index, action) in REGISTRATION_ACTIONS.iter().enumerate() {
            end += driver.calls()[index];
            if expires && !expired && fault.is_some_and(|at| at < end) {
                world.advance(301);
                expired = true;
            }
            let result = session.call(crate::automation::Request {
                protocol: 1,
                action: (*action).into(),
                input: "{}".into(),
            });
            let expected = fault.is_none_or(|boundary| end <= boundary);
            results.push(result.is_ok());
            if result.is_ok() != expected {
                return Err(RegistrationDivergence { category: "registration_acceptance",
                    observation: serde_json::json!({"step":index,"expected":expected,"steps":results,"requests":world.requests()}) }.into());
            }
        }
        let receipt = session.finish();
        if receipt.is_ok() != fault.is_none() {
            return Err(RegistrationDivergence { category: "registration_readiness",
                observation: serde_json::json!({"expected":fault.is_none(),"ready":receipt.is_ok(),"steps":results,"requests":world.requests()}) }.into());
        }
        if let Ok(receipt) = receipt {
            if !receipt.fresh(effects::wall_time()?) {
                return Err(RegistrationDivergence {
                    category: "registration_freshness",
                    observation: serde_json::json!({"expected":true,"fresh":false,"steps":results,"requests":world.requests()}),
                }.into());
            }
            world.advance(300);
            if receipt.fresh(effects::wall_time()?) {
                return Err(RegistrationDivergence {
                    category: "registration_expiry",
                    observation: serde_json::json!({"expected":false,"fresh":true,"steps":results,"requests":world.requests()}),
                }.into());
            }
        }
        Ok(serde_json::json!({"steps":results,"requests":world.provider.lock().unwrap().requests}))
    })
}

#[derive(Debug, Serialize)]
struct RegistrationDivergence {
    category: &'static str,
    observation: serde_json::Value,
}

impl std::fmt::Display for RegistrationDivergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.category)
    }
}

impl std::error::Error for RegistrationDivergence {}

fn checked_registration(
    seed: u64,
    fault: Option<usize>,
    expires: bool,
    driver: RegistrationDriver,
) -> Result<()> {
    let first = registration_campaign(seed, fault, expires, driver)?;
    let replay = registration_campaign(seed, fault, expires, driver)?;
    if first != replay {
        return Err(RegistrationDivergence {
            category: "registration_replay",
            observation: serde_json::json!({"first":first,"replay":replay}),
        }
        .into());
    }
    Ok(())
}

fn verify_registration(
    seed: u64,
    fault: Option<usize>,
    expires: bool,
    driver: RegistrationDriver,
) -> Result<()> {
    if let Err(error) = checked_registration(seed, fault, expires, driver) {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/oauth-simulation");
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!(
            "registration-{driver:?}-{seed}-{}-{expires}.json",
            fault.map_or("none".into(), |at| at.to_string())
        ));
        let evidence = serde_json::json!({"version":1,"domain":"registration","implementation":implementation(),
            "seed":seed,"fault":fault,"expires":expires,"driver":driver,
            "observation":error.downcast_ref::<RegistrationDivergence>(),
            "replay":"DAY2_OAUTH_REPLAY=<path> cargo test --locked -p day2 --lib oauth::simulation::replay_saved_oauth_history -- --exact"});
        std::fs::write(&path, serde_json::to_vec_pretty(&evidence)?)?;
        anyhow::bail!(
            "OAuth registration simulation failed; counterexample: {}",
            path.display()
        );
    }
    Ok(())
}

#[test]
fn registration_protocol_and_faults_replay_without_network_or_real_time() -> Result<()> {
    let mut covered = std::collections::BTreeSet::new();
    for driver in [
        RegistrationDriver::GoogleMapped,
        RegistrationDriver::GoogleExternal,
        RegistrationDriver::GitlabExternal,
    ] {
        let target = driver.target()?;
        let profile = target.reviewed();
        let expected = |name: &str, contract: &str| {
            day2_capabilities::BindingRef::pin(
                day2_capabilities::Name::try_from(name.to_owned())?,
                &contract,
            )
        };
        let (simulator, model, conformance, campaign) = driver.pins();
        ensure!(
            profile.simulator == expected(simulator, model)?
                && profile.conformance == expected(conformance, campaign)?,
            "unbound runnable OAuth campaign"
        );
        covered.insert(Digest::of(&(
            profile.protocol.identity().binding.clone(),
            &profile.adapter,
            &profile.simulator,
            &profile.conformance,
        ))?);
        for seed in 0..8 {
            for fault in
                std::iter::once(None).chain((0..driver.calls().iter().sum::<usize>()).map(Some))
            {
                for expires in [false, true] {
                    verify_registration(seed, fault, expires, driver)?;
                }
            }
        }
    }
    require_registration_drivers(&covered)
}

fn require_registration_drivers(covered: &std::collections::BTreeSet<Digest>) -> Result<()> {
    let catalog = super::catalog::reviewed()?;
    let required = catalog
        .entries()
        .map(|entry| {
            Digest::of(&(
                entry.profile.protocol.identity().binding.clone(),
                &entry.profile.adapter,
                &entry.profile.simulator,
                &entry.profile.conformance,
            ))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        &required == covered,
        "every reviewed OAuth adapter/profile/simulator/conformance tuple needs a runnable campaign"
    );
    Ok(())
}

#[test]
fn publishing_a_profile_without_its_driver_fails_the_coverage_gate() -> Result<()> {
    let mut covered = std::collections::BTreeSet::new();
    for driver in [
        RegistrationDriver::GoogleMapped,
        RegistrationDriver::GoogleExternal,
    ] {
        let target = driver.target()?;
        let profile = target.reviewed();
        covered.insert(Digest::of(&(
            profile.protocol.identity().binding.clone(),
            &profile.adapter,
            &profile.simulator,
            &profile.conformance,
        ))?);
    }
    assert!(require_registration_drivers(&covered).is_err());
    Ok(())
}

#[test]
fn virtual_effects_inherit_blocking_work_and_do_not_escape_scope() -> Result<()> {
    let world = World::new(7);
    world
        .provider
        .lock()
        .unwrap()
        .replies
        .push_back((200, "{}".into()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let virtual_deadline = effects::scope(world.clone(), || -> Result<effects::Instant> {
        let start = effects::Instant::now();
        let first = effects::random()?;
        let (wall, second) = runtime.block_on(async {
            effects::spawn_blocking(|| -> Result<_> {
                let response = effects::Client::builder()
                    .build()?
                    .get("https://oauth2.googleapis.com/token")
                    .send()?;
                ensure!(response.status().is_success(), "scripted transport failed");
                Ok((effects::wall_time()?, effects::random()?))
            })
            .await
        })??;
        ensure!(
            wall == 5 && first != second,
            "simulation environment was lost on blocking pool"
        );
        world.advance(23);
        ensure!(
            start.elapsed() == Duration::from_secs(23),
            "virtual time diverged"
        );
        Ok(effects::Instant::now())
    })?;
    ensure!(
        effects::Instant::now()
            .partial_cmp(&virtual_deadline)
            .is_none(),
        "simulated deadline escaped into live clock domain"
    );
    ensure!(
        world.provider.lock().unwrap().requests.len() == 1,
        "scripted HTTP bypassed"
    );
    Ok(())
}

#[test]
fn selected_workload_metadata_replays_identity_substitution_and_transport_loss() -> Result<()> {
    use super::approval_keys::{AccessTokenSource, GkeMetadataAccessTokens};
    for seed in 0..8 {
        for scenario in 0..4 {
            let run = || -> Result<_> {
                let world = World::new(seed);
                world.script(vec![(200, if scenario == 2 { "other@company.iam.gserviceaccount.com" } else { "shell@company.iam.gserviceaccount.com" }.into()),
                    (200, r#"{"access_token":"private-access","token_type":"Bearer","expires_in":3600}"#.into())],
                    match scenario { 1 => Some(0), 3 => Some(1), _ => None });
                effects::scope(world.clone(), || {
                    let source =
                        GkeMetadataAccessTokens::selected("shell@company.iam.gserviceaccount.com")?;
                    let result = source.access_token();
                    ensure!(
                        result.is_ok() == (scenario == 0),
                        "metadata identity oracle diverged"
                    );
                    ensure!(
                        world.requests().len() == if matches!(scenario, 1 | 2) { 1 } else { 2 },
                        "metadata request boundary diverged"
                    );
                    Ok((result.is_ok(), world.requests()))
                })
            };
            ensure!(run()? == run()?, "metadata replay diverged");
        }
    }
    Ok(())
}

#[test]
fn private_roc_registration_recipe_obeys_virtual_effects() -> Result<()> {
    use day2_capabilities::oauth::AccountBindingPolicy;
    let runner = crate::automation::runner()?;
    for seed in 0..4 {
        for fault in [None, Some(5)] {
            let run = || -> Result<_> {
                let world = World::new(seed);
                world.script(registration::tests::responses(), fault);
                effects::scope(world.clone(), || {
                    let target = registration::tests::target_for(
                        AccountBindingPolicy::ExplicitExternalAccount,
                    )?;
                    let codes = registration_codes(&target)?;
                    let session = registration::Session::new(
                        target,
                        codes,
                        Arc::new(registration::tests::TokensSource(
                            std::sync::atomic::AtomicUsize::new(0),
                        )),
                    )?;
                    let result = session.run(&runner);
                    ensure!(
                        result.is_ok() == fault.is_none(),
                        "native Roc registration fault oracle diverged"
                    );
                    if let Ok(receipt) = &result {
                        ensure!(
                            receipt.fresh(effects::wall_time()?),
                            "native Roc registration did not use virtual lease time"
                        );
                    }
                    ensure!(
                        world.requests().len() == if fault.is_none() { 9 } else { 6 },
                        "native Roc campaign retried or skipped protocol effects"
                    );
                    Ok((result.is_ok(), world.requests()))
                })
            };
            ensure!(run()? == run()?, "native Roc registration replay diverged");
        }
    }
    Ok(())
}
