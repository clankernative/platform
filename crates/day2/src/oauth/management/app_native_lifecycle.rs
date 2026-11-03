// Composed DATA simulation. Native permissions are never constructed here.
// The storage and both transcript models remain independent of OAuth's oracle.
use super::*;
use crate::simulation::coverage::{self as dst, Campaign, Transition};
use crate::{
    oauth::native_management,
    protocol::{Instruction, Request},
    security_epoch::{
        ConsumerEvent, ConsumerHandshakeProgress, ConsumerLifecycle, ConsumerShellReference,
    },
};
use day2_capabilities::security_epoch::{AuthorityScope, bootstrap::NativeRole};
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeSet};

const MAX_STEPS: usize = 64;
const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Failure {
    App,
    Shell,
    Controller,
    Epoch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Boundary {
    Dispatch,
    Material,
    Publication,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fault", rename_all = "snake_case", deny_unknown_fields)]
enum RefreshFault {
    Delay { millis: u64 },
    LostReply,
    Crash { at: Boundary },
    LatePublication,
}

#[derive(Debug)]
struct RefreshCrash;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
enum Step {
    Capture { disconnect: bool },
    Approve,
    Authorize,
    Callback,
    ReplayCallback,
    Read,
    CachedRead,
    Refresh,
    FaultRefresh { fault: RefreshFault },
    Disconnect,
    Fail { owner: Failure, cut: usize },
    Advance { seconds: u64 },
    Reopen,
    Restart,
    Restore,
    ResetMonotonic,
    BeginShell { death_cut: Option<usize> },
    AdvanceShell { events: u8 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    version: u32,
    seed: u64,
    steps: Vec<Step>,
}

struct Native {
    lifecycle: ConsumerLifecycle,
    scope: AuthorityScope,
    app: bool,
    shell: bool,
    records: Vec<Value>,
}

thread_local! {
    static NATIVE: RefCell<Option<Native>> = const { RefCell::new(None) };
}

struct NativeScope;
impl Drop for NativeScope {
    fn drop(&mut self) {
        NATIVE.with(|slot| slot.replace(None));
    }
}

fn native_event(event: ConsumerEvent) -> Result<()> {
    NATIVE.with(|slot| {
        let mut slot = slot.try_borrow_mut()?;
        let native = slot.as_mut().context("native lifecycle supplier absent")?;
        native.records.push(native.lifecycle.step(event)?);
        Ok(())
    })
}

struct Port {
    original: Arc<super::Port>,
    domain: u64,
    ticks: AtomicU64,
    reads: AtomicUsize,
    refreshes: AtomicUsize,
    journal: std::sync::Mutex<Vec<ProviderEvent>>,
    fault: std::sync::Mutex<Option<RefreshFault>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProviderEvent {
    ClientSecret,
    Code,
    Refresh,
    Account,
    Calendar,
}

impl Port {
    fn record(&self, event: ProviderEvent) -> Result<()> {
        let mut journal = self.journal.lock().unwrap();
        ensure!(
            journal.len() < MAX_STEPS * 8,
            "consumer provider event bound"
        );
        journal.push(event);
        Ok(())
    }
}

impl effects::Hooks for Port {
    fn domain(&self) -> u64 {
        self.domain
    }
    fn wall_time(&self) -> Result<i64> {
        self.original.wall_time()
    }
    fn monotonic(&self) -> Duration {
        Duration::from_millis(self.ticks.load(SeqCst))
    }
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        self.original.fill(bytes)
    }
    fn provider_observation(
        &self,
        data: crate::oauth::shell_oidc::ProviderObservationData,
    ) -> Result<()> {
        self.original.provider_observation(data)
    }
    fn simulate_runtime_owner(&self) -> bool {
        true
    }
    fn refresh_boundary(&self, boundary: effects::RefreshBoundary) {
        let at = match boundary {
            effects::RefreshBoundary::DispatchCommitted => Boundary::Dispatch,
            effects::RefreshBoundary::MaterialWritten => Boundary::Material,
            effects::RefreshBoundary::PublicationCommitted => Boundary::Publication,
        };
        let selected = {
            let mut fault = self.fault.lock().unwrap();
            match *fault {
                Some(RefreshFault::Crash { at: expected }) if expected == at => fault.take(),
                Some(RefreshFault::LatePublication) if at == Boundary::Publication => fault.take(),
                _ => None,
            }
        };
        match selected {
            Some(RefreshFault::Crash { .. }) => {
                native_event(ConsumerEvent::Current {
                    death_cut: Some(0),
                    rewrite_provider: false,
                })
                .expect("crash cut native model agreement");
                NATIVE.with(|slot| slot.borrow_mut().as_mut().unwrap().app = false);
                std::panic::panic_any(RefreshCrash);
            }
            Some(RefreshFault::LatePublication) => {
                self.ticks.fetch_add(5_000, SeqCst);
            }
            _ => {}
        }
    }
    fn native_check(&self, role: NativeRole, scope: Option<&AuthorityScope>) -> Result<()> {
        NATIVE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            let native = slot.as_mut().context("native lifecycle executor absent")?;
            ensure!(
                scope == Some(&native.scope),
                "native lifecycle selection changed"
            );
            ensure!(
                match role {
                    NativeRole::AppHost => native.app,
                    NativeRole::SecurityShell => native.shell,
                    _ => false,
                },
                "native lifecycle owner ended"
            );
            native
                .lifecycle
                .check(&native.scope, role == NativeRole::SecurityShell)
        })
    }
    fn send(&self, request: reqwest::blocking::Request) -> Result<effects::Response> {
        let value = if request.method() == reqwest::Method::POST
            && request.url().as_str() == crate::oauth::google::TOKEN
        {
            let form = crate::web_security::fields(
                request
                    .body()
                    .and_then(|body| body.as_bytes())
                    .context("token form")?,
            )?;
            if form.get("grant_type").map(String::as_str) == Some("refresh_token") {
                self.record(ProviderEvent::Refresh)?;
                ensure!(
                    form.get("refresh_token").map(String::as_str) == Some("private-refresh-token"),
                    "refresh credential changed"
                );
                self.refreshes.fetch_add(1, SeqCst);
                let selected = {
                    let mut fault = self.fault.lock().unwrap();
                    if matches!(
                        *fault,
                        Some(RefreshFault::Delay { .. } | RefreshFault::LostReply)
                    ) {
                        fault.take()
                    } else {
                        None
                    }
                };
                match selected {
                    Some(RefreshFault::Delay { millis }) => {
                        self.ticks.fetch_add(millis, SeqCst);
                    }
                    Some(RefreshFault::LostReply) => {
                        anyhow::bail!("scripted accepted refresh reply lost")
                    }
                    _ => {}
                }
                json!({"access_token":"private-access-token","refresh_token":"private-refresh-token","token_type":"Bearer","expires_in":90,
                    "scope":"openid email https://www.googleapis.com/auth/calendar.events.readonly"})
            } else {
                self.record(ProviderEvent::Code)?;
                let response = self.original.send(request)?;
                let effects::Response::Simulated { mut body, .. } = response else {
                    anyhow::bail!("simulation transport changed")
                };
                use std::io::Read as _;
                let mut bytes = Vec::new();
                body.read_to_end(&mut bytes)?;
                let mut value: Value = serde_json::from_slice(&bytes)?;
                value["expires_in"] = json!(90);
                value
            }
        } else if request.method() == reqwest::Method::GET
            && request
                .url()
                .as_str()
                .starts_with("https://www.googleapis.com/calendar/v3/calendars/primary/events?")
        {
            ensure!(
                request.headers()[reqwest::header::AUTHORIZATION].is_sensitive(),
                "calendar credential header is public"
            );
            self.reads.fetch_add(1, SeqCst);
            self.record(ProviderEvent::Calendar)?;
            json!({"kind":"calendar#events","items":[]})
        } else {
            self.record(if request.url().as_str() == crate::oauth::google::USERINFO { ProviderEvent::Account } else if request.url().as_str() == "https://secretmanager.googleapis.com/v1/projects/12345/secrets/google_client_secret/versions/7:access" { ProviderEvent::ClientSecret } else { anyhow::bail!("unscripted consumer provider request") })?;
            return self.original.send(request);
        };
        Ok(effects::Response::Simulated {
            status: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::from_iter([(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/json"),
            )]),
            body: std::io::Cursor::new(serde_json::to_vec(&value)?),
            peer: None,
        })
    }
}

struct World {
    _native: NativeScope,
    fixture: Fixture,
    port: Arc<Port>,
    view: Option<View>,
    proof: Option<Attestation>,
    query: String,
    original_callback: Option<(String, String)>,
    cached: Option<(Request, String)>,
    requests: usize,
}

impl World {
    fn new(seed: u64) -> Result<Self> {
        let mut fixture = Fixture::selected(false, true)?;
        fixture.port.entropy.store(seed.wrapping_add(1), SeqCst);
        fixture.manager.runtime.connections = Some(fixture.manager.authority.clone());
        static DOMAIN: AtomicU64 = AtomicU64::new(600_000);
        let port = Arc::new(Port {
            original: fixture.port.clone(),
            domain: DOMAIN.fetch_add(1, SeqCst),
            ticks: AtomicU64::new(100_000),
            reads: AtomicUsize::new(0),
            refreshes: AtomicUsize::new(0),
            journal: Default::default(),
            fault: Default::default(),
        });
        let scope = AuthorityScope {
            installation: "company".to_owned().try_into()?,
            environment: "production".to_owned().try_into()?,
            app: "workspace".to_owned().try_into()?,
        };
        NATIVE.with(|slot| {
            ensure!(
                slot.borrow().is_none(),
                "native lifecycle supplier already present"
            );
            slot.replace(Some(Native {
                lifecycle: ConsumerLifecycle::new(seed, &scope)?,
                scope,
                app: true,
                shell: true,
                records: vec![],
            }));
            Ok::<_, anyhow::Error>(())
        })?;
        let native = NativeScope;
        Ok(Self {
            _native: native,
            fixture,
            port,
            view: None,
            proof: None,
            query: String::new(),
            original_callback: None,
            cached: None,
            requests: 0,
        })
    }

    fn boot(&mut self) -> Result<()> {
        native_event(ConsumerEvent::FirstHolder { death_cut: None })?;
        for activation in [false, true] {
            native_event(ConsumerEvent::Reserve { activation })?;
            native_event(ConsumerEvent::Dispatch { activation })?;
            native_event(ConsumerEvent::Settle { activation })?;
        }
        native_event(ConsumerEvent::Current {
            death_cut: None,
            rewrite_provider: false,
        })?;
        native_event(ConsumerEvent::Shell { death_cut: None })?;
        Ok(())
    }

    fn request(&mut self) -> Result<Request> {
        self.requests += 1;
        let runtime = &self.fixture.manager.runtime;
        let db = store::open(runtime.db())?;
        let human = &self.fixture.identity;
        let now = self.fixture.port.now.load(SeqCst);
        crate::iap::bind_subject(&db, human, now)?;
        let id = format!("native_read_{}", self.requests);
        runtime.accept_on_behalf_of_verified(
            "read",
            crate::store::ActingAs {
                authenticated: &human.email,
                actor: &human.email,
                trigger: crate::audit::Trigger::Request,
            },
            &id,
            &json!({}),
            now,
            Some(human),
        )?;
        Ok(Request {
            operation: "read".into(),
            input: "{}".into(),
            context: store::invocation_context(&db, &id)?,
            observations: vec![],
        })
    }

    fn read(&mut self, cached: bool) -> Result<bool> {
        let (request, reference) = if cached {
            self.cached.clone().context("cached read absent")?
        } else {
            let request = self.request()?;
            let result: Value = serde_json::from_str(&usage::execute(
                &self.fixture.manager.runtime,
                &request,
                &Instruction {
                    kind: "observe".into(),
                    model: crate::connection_codegen::RESOLVE.into(),
                    data: json!({"registration":"calendar"}).to_string(),
                    ..Default::default()
                },
            )?)?;
            let Some(reference) = result["Available"].as_str() else {
                return Ok(false);
            };
            (request, reference.to_owned())
        };
        let result: Value = serde_json::from_str(&usage::execute(
            &self.fixture.manager.runtime,
            &request,
            &Instruction {
                kind: "observe".into(),
                model: crate::connection_codegen::LIST_EVENTS.into(),
                data: json!({"registration":"calendar","reference":reference,
                "window":{"start":"2026-10-24T00:00:00Z","end":"2026-10-25T00:00:00Z"}})
                .to_string(),
                ..Default::default()
            },
        )?)?;
        if self.cached.is_none() {
            self.cached = Some((request, reference));
        }
        Ok(result.get("Listed").is_some())
    }

    fn step(&mut self, step: Step) -> Result<bool> {
        let now = self.fixture.port.now.load(SeqCst);
        let identity = &self.fixture.identity;
        match step {
            Step::Capture { disconnect } => {
                self.view = Some(self.fixture.manager.capture(
                    "calendar",
                    if disconnect {
                        Action::Disconnect
                    } else {
                        Action::Connect
                    },
                    identity,
                    now,
                )?);
                self.proof = None;
            }
            Step::Approve => {
                let view = self.view.as_ref().context("pending absent")?;
                let intent = FreshIntent::management(view, identity)?;
                native_management::reserve_shell(&intent, now)?;
                let fresh = VerifiedAuthTime::from_google(shell_oidc::Reauthenticated::fixture(
                    intent,
                    identity.email.clone(),
                    identity.subject.clone(),
                    now,
                ));
                self.proof = Some(self.fixture.signer.attest_management(
                    view,
                    &fresh,
                    identity,
                    Digest::new(b"native-browser"),
                    now,
                )?);
            }
            Step::Authorize => {
                let view = self.view.as_ref().context("pending absent")?;
                let location = self.fixture.manager.authorize_connect(
                    &view.id,
                    self.proof.as_ref().context("proof absent")?,
                    identity,
                    now,
                )?;
                let state = url::Url::parse(&location)?
                    .query_pairs()
                    .find(|(key, _)| key == "state")
                    .context("state absent")?
                    .1
                    .into_owned();
                self.query = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("state", &state)
                    .append_pair("code", "private-provider-code")
                    .append_pair("iss", crate::oauth::google::ISSUER)
                    .finish();
                self.original_callback = Some((view.id.clone(), self.query.clone()));
            }
            Step::Callback => {
                self.fixture.manager.callback(
                    &self.view.as_ref().context("pending absent")?.id,
                    &self.query,
                    &Digest::new(b"native-browser"),
                    identity,
                    now,
                )?;
            }
            Step::ReplayCallback => {
                let (id, query) = self
                    .original_callback
                    .as_ref()
                    .context("original callback absent")?;
                self.fixture.manager.callback(
                    id,
                    query,
                    &Digest::new(b"native-browser"),
                    identity,
                    now,
                )?;
            }
            Step::Disconnect => {
                self.fixture.manager.disconnect(
                    self.view.as_ref().context("pending absent")?,
                    self.proof.as_ref().context("proof absent")?,
                    identity,
                    now,
                )?;
            }
            Step::Read => return self.read(false),
            Step::CachedRead => return self.read(true),
            Step::Refresh => {
                self.fixture.port.now.fetch_add(31, SeqCst);
                self.port.ticks.fetch_add(31_000, SeqCst);
                return self.read(false);
            }
            Step::FaultRefresh { fault } => {
                self.fixture.port.now.fetch_add(31, SeqCst);
                self.port.ticks.fetch_add(31_000, SeqCst);
                *self.port.fault.lock().unwrap() = Some(fault);
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.read(false)));
                *self.port.fault.lock().unwrap() = None;
                return match result {
                    Ok(result) => result,
                    Err(payload) if payload.is::<RefreshCrash>() => Ok(false),
                    Err(payload) => std::panic::resume_unwind(payload),
                };
            }
            Step::Advance { seconds } => {
                self.fixture.port.now.fetch_add(seconds as i64, SeqCst);
                self.port.ticks.fetch_add(seconds * 1_000, SeqCst);
            }
            Step::Fail { owner, cut } => match owner {
                Failure::App => {
                    native_event(ConsumerEvent::Current {
                        death_cut: Some(cut),
                        rewrite_provider: false,
                    })?;
                    NATIVE.with(|slot| slot.borrow_mut().as_mut().unwrap().app = false);
                }
                Failure::Shell => {
                    native_event(ConsumerEvent::Shell {
                        death_cut: Some(cut),
                    })?;
                    NATIVE.with(|slot| slot.borrow_mut().as_mut().unwrap().shell = false);
                }
                Failure::Controller => native_event(ConsumerEvent::ControllerDeath { cut })?,
                Failure::Epoch => native_event(ConsumerEvent::Current {
                    death_cut: None,
                    rewrite_provider: true,
                })?,
            },
            Step::Reopen => {
                drop(store::open(self.fixture.manager.runtime.db())?);
                native_event(ConsumerEvent::Reopen)?;
            }
            Step::Restore => {
                native_event(ConsumerEvent::RestoreClock)?;
            }
            Step::Restart => {
                NATIVE.with(|slot| {
                    let mut slot = slot.borrow_mut();
                    let native = slot.as_mut().unwrap();
                    native.app = false;
                    native.shell = false;
                });
            }
            Step::ResetMonotonic => {
                self.port.ticks.store(100_000, SeqCst);
            }
            Step::BeginShell { death_cut } => {
                native_event(ConsumerEvent::BeginShell { death_cut })?
            }
            Step::AdvanceShell { events } => native_event(ConsumerEvent::AdvanceShell { events })?,
        }
        Ok(true)
    }

    fn record(&self, accepted: bool, model: &Oracle) -> Result<Value> {
        let db = store::open(self.fixture.manager.runtime.db())?;
        let slot = db
            .query_row(
                "SELECT status,generation,token_version,security_epoch FROM oauth_connection_slots",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let mut query = db.prepare("SELECT base_version,state,next_version FROM oauth_refresh_attempts ORDER BY base_version,attempt")?;
        let refresh_rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let tokens: i64 = db.query_row("SELECT count(*) FROM oauth_private_tokens", [], |row| {
            row.get(0)
        })?;
        Ok(
            json!({"accepted":accepted,"oracle":model,"owners":native_management::fixtures::observation()?,"projection":{"slot":slot,
            "exchanges":self.fixture.port.posts.load(SeqCst),"refreshes":self.port.refreshes.load(SeqCst),
            "reads":self.port.reads.load(SeqCst),"revokes":self.fixture.port.revokes.load(SeqCst),"journal":*self.port.journal.lock().unwrap(),"refresh_rows":refresh_rows,"tokens":tokens},"sql":crate::oauth::simulation::snapshot(&db)?,
            "native":NATIVE.with(|slot| slot.borrow().as_ref().unwrap().lifecycle.observation())?,
            "shell_reference":model.shell_reference.observation(),"shell_progress":model.shell_reference.progress()?}),
        )
    }
}

// The oracle consumes only the schedule, never World results, SQL or production
// transition functions. OAuth slots and provider effects have independent rules.
#[derive(Serialize)]
struct Oracle {
    #[serde(skip)]
    shell_reference: ConsumerShellReference,
    stage: u8,
    disconnect: bool,
    pending: bool,
    approved: bool,
    signer_refused: bool,
    created: i64,
    now: i64,
    app: bool,
    shell: bool,
    controller: bool,
    exchanges: usize,
    refreshes: usize,
    publications: usize,
    token_expires: Option<i64>,
    refresh_rows: Vec<(i64, String, Option<i64>)>,
    reads: usize,
    cached: Option<(usize, i64)>,
    journal: Vec<ProviderEvent>,
}

impl Oracle {
    fn new(seed: u64) -> Result<Self> {
        let mut shell_reference = ConsumerShellReference::new(seed)?;
        ensure!(
            shell_reference.exchange(None)?,
            "reference Shell setup refused"
        );
        Ok(Self {
            shell_reference,
            stage: 0,
            disconnect: false,
            pending: false,
            approved: false,
            signer_refused: false,
            created: 100,
            now: 100,
            app: true,
            shell: true,
            controller: true,
            exchanges: 0,
            refreshes: 0,
            publications: 0,
            token_expires: None,
            refresh_rows: vec![],
            reads: 0,
            cached: None,
            journal: vec![],
        })
    }
    fn resolve_read(&mut self, fault: Option<RefreshFault>) -> bool {
        if !self.app || !self.controller || self.stage != 3 {
            return false;
        }
        if self
            .token_expires
            .is_some_and(|expiry| expiry <= self.now + 60)
        {
            let base = 1 + self.publications as i64;
            self.journal.push(ProviderEvent::ClientSecret);
            if fault
                == Some(RefreshFault::Crash {
                    at: Boundary::Dispatch,
                })
            {
                self.refresh_rows
                    .push((base, "may_have_been_sent".into(), None));
                self.app = false;
                self.controller = false;
                return false;
            }
            self.refreshes += 1;
            self.journal.push(ProviderEvent::Refresh);
            if fault == Some(RefreshFault::LostReply)
                || matches!(fault, Some(RefreshFault::Delay { millis }) if millis >= 5_000)
            {
                // The original send fence remains unresolved. Refusing the
                // App owner does not authorize a cleanup write afterwards.
                // Replacing this with such a write must fail the row oracle.
                self.refresh_rows
                    .push((base, "may_have_been_sent".into(), None));
                self.app = false;
                return false;
            }
            self.journal.push(ProviderEvent::Account);
            if fault
                == Some(RefreshFault::Crash {
                    at: Boundary::Material,
                })
            {
                self.refresh_rows
                    .push((base, "may_have_been_sent".into(), None));
                self.app = false;
                self.controller = false;
                return false;
            }
            self.publications += 1;
            self.token_expires = Some(self.now + 90);
            self.refresh_rows
                .push((base, "replacement_committed".into(), Some(base + 1)));
            if fault
                == Some(RefreshFault::Crash {
                    at: Boundary::Publication,
                })
            {
                self.app = false;
                self.controller = false;
                return false;
            }
            if fault == Some(RefreshFault::LatePublication) {
                self.app = false;
                return false;
            }
        }
        self.reads += 1;
        self.journal.push(ProviderEvent::Calendar);
        if self.cached.is_none() {
            self.cached = Some((1 + self.publications, self.now + 60));
        }
        true
    }

    fn step(&mut self, step: Step) -> Result<bool> {
        let app = self.app && self.controller;
        let original = app && self.pending && self.now < self.created + 300;
        Ok(match step {
            Step::Capture { disconnect } => {
                let accepted = app
                    && if disconnect {
                        self.stage == 3
                    } else {
                        self.stage == 0
                    };
                if accepted {
                    self.pending = true;
                    self.approved = false;
                    self.signer_refused = false;
                    self.disconnect = disconnect;
                    self.created = self.now;
                    if !disconnect {
                        self.stage = 1;
                    }
                }
                accepted
            }
            Step::Approve => {
                // The actual reserve_shell reaches the selected fixture role
                // before signing. Failure there permanently refuses that owner;
                // completing DATA later never renews its original or role.
                if self.pending
                    && self.shell
                    && self.shell_reference.progress()? != ConsumerHandshakeProgress::Completed
                {
                    self.shell = false;
                }
                let available = self.shell
                    && self.controller
                    && self.pending
                    && !self.signer_refused
                    && self.now < self.created + 300;
                let accepted = available && self.now > self.created;
                if available && !accepted {
                    self.signer_refused = true;
                }
                if accepted {
                    self.approved = true;
                }
                accepted
            }
            Step::Authorize => {
                let accepted = original && self.approved && !self.disconnect && self.stage == 1;
                if accepted {
                    self.stage = 2;
                }
                accepted
            }
            Step::Callback | Step::ReplayCallback => {
                let accepted = original && self.stage == 2;
                if accepted {
                    self.stage = 3;
                    self.exchanges += 1;
                    self.token_expires = Some(self.now + 90);
                    self.journal.extend([
                        ProviderEvent::ClientSecret,
                        ProviderEvent::Code,
                        ProviderEvent::Account,
                    ]);
                }
                accepted
            }
            Step::Disconnect => {
                let accepted = original && self.approved && self.disconnect && self.stage == 3;
                if accepted {
                    self.stage = 4;
                    self.pending = false;
                }
                accepted
            }
            Step::Read => self.resolve_read(None),
            Step::Refresh => {
                self.now += 31;
                self.resolve_read(None)
            }
            Step::FaultRefresh { fault } => {
                self.now += 31;
                self.resolve_read(Some(fault))
            }
            Step::CachedRead => {
                let accepted = app
                    && self.stage == 3
                    && self.cached.is_some_and(|(version, expiry)| {
                        version == 1 + self.publications && self.now < expiry
                    });
                if accepted {
                    self.reads += 1;
                    self.journal.push(ProviderEvent::Calendar);
                } else if app && self.cached.is_some() {
                    self.app = false;
                }
                accepted
            }
            Step::Fail { owner, cut } => {
                match owner {
                    Failure::App => {
                        self.app = false;
                        self.controller = false;
                    }
                    Failure::Shell => {
                        self.shell_reference.exchange(Some(cut))?;
                        self.shell = false;
                    }
                    Failure::Controller | Failure::Epoch => self.controller = false,
                };
                true
            }
            Step::Advance { seconds } => {
                self.now += seconds as i64;
                true
            }
            Step::Reopen | Step::Restore | Step::ResetMonotonic => true,
            Step::Restart => {
                self.app = false;
                self.shell = false;
                true
            }
            Step::BeginShell { death_cut } => {
                self.shell_reference.begin(death_cut)?;
                true
            }
            Step::AdvanceShell { events } => {
                self.shell_reference.advance(events)?;
                true
            }
        })
    }
    fn slot(&self) -> Option<(String, i64, i64, i64)> {
        match self.stage {
            3 => Some(("active".into(), 1, 1 + self.publications as i64, 1)),
            4 => Some(("disabled".into(), 1, 1 + self.publications as i64, 2)),
            _ => None,
        }
    }
    fn projection(&self) -> Value {
        json!({"slot":self.slot(),"exchanges":self.exchanges,"refreshes":self.refreshes,"reads":self.reads,"revokes":0,"journal":self.journal,"refresh_rows":self.refresh_rows,"tokens":usize::from(self.stage == 3)})
    }
}

#[derive(Debug, Serialize)]
struct Divergence {
    category: &'static str,
    index: usize,
    records: Vec<Value>,
}
impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.category)
    }
}
impl std::error::Error for Divergence {}

fn original_invariants(
    record: &Value,
    seen: &mut std::collections::BTreeMap<String, Value>,
) -> bool {
    let nanos = |value: &Value| -> Option<u64> {
        value["secs"]
            .as_u64()?
            .checked_mul(1_000_000_000)?
            .checked_add(value["nanos"].as_u64()?)
    };
    let Some(originals) = record["owners"]["originals"].as_array() else {
        return false;
    };
    for row in originals {
        let original = &row["original"];
        let (Some(origin), Some(latest), Some(ceiling)) = (
            nanos(&original["origin"]),
            nanos(&original["latest"]),
            nanos(&original["ceiling"]),
        ) else {
            return false;
        };
        if original["same_executor"] != true
            || !original["binding"].is_string()
            || latest < origin
            || ceiling <= origin
            || ceiling - origin > 300_000_000_000
        {
            return false;
        }
        let key = format!("{}/{}", row["role"], row["attempt"]);
        if let Some(previous) = seen.get(&key) {
            for field in ["origin", "ceiling", "binding"] {
                if previous["original"][field] != original[field] {
                    return false;
                }
            }
            if previous["original"]["refused"] == true && original["refused"] != true {
                return false;
            }
            if previous["role_refused"] == true && row["role_refused"] != true {
                return false;
            }
            if nanos(&previous["original"]["latest"]).is_none_or(|before| before > latest) {
                return false;
            }
        }
        seen.insert(key, row.clone());
    }
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OracleControl {
    None,
    OvercountFirstRead,
    PendingShellCompletes,
}

fn run(program: &Program, control: OracleControl) -> Result<Vec<Value>> {
    ensure!(
        program.version == 1 && !program.steps.is_empty() && program.steps.len() <= MAX_STEPS,
        "consumer campaign version/history bound"
    );
    ensure!(program.steps.iter().all(|step| !matches!(step, Step::Advance { seconds } if *seconds > 600)
            && !matches!(step, Step::FaultRefresh { fault: RefreshFault::Delay { millis } } if *millis > 10_000)),
        "consumer clock input bound");
    let mut world = World::new(program.seed)?;
    let hooks = world.port.clone();
    let mut model = Oracle::new(program.seed)?;
    effects::scope(hooks.clone(), || -> Result<()> {
        let scope = NATIVE.with(|slot| slot.borrow().as_ref().unwrap().scope.clone());
        native_management::fixtures::select_app_scope(&scope)?;
        if world.boot().is_err() {
            return Err(Divergence {
                category: "setup",
                index: 0,
                records: vec![world.record(false, &model)?],
            }
            .into());
        }
        Ok(())
    })?;
    let mut records = vec![];
    let mut originals = std::collections::BTreeMap::new();
    let mut corrupted = false;
    for (index, &step) in program.steps.iter().enumerate() {
        let mut expected = model.step(step).map_err(|_| Divergence {
            category: "native_model",
            index,
            records: records.clone(),
        })?;
        if control == OracleControl::PendingShellCompletes
            && step == Step::Approve
            && model.shell_reference.progress()? == ConsumerHandshakeProgress::Pending
        {
            // Negative expectation only, never supplied to the real consumer.
            expected = true;
        }
        if !corrupted
            && control == OracleControl::OvercountFirstRead
            && step == Step::Read
            && expected
        {
            // Negative oracle control only. World, native hooks, providers and
            // the actual consumer receive neither this value nor altered DATA.
            model.reads += 1;
            corrupted = true;
        }
        if step == Step::Restart {
            native_management::fixtures::restart(hooks.domain);
        }
        let (actual, panicked, native_divergence, observed) = effects::scope(hooks.clone(), || {
            let attempted =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| world.step(step)));
            let panicked = attempted.is_err();
            let result = attempted.unwrap_or_else(|_| anyhow::bail!("consumer adapter panic"));
            let native_divergence = result.as_ref().is_err_and(|error| {
                error
                    .downcast_ref::<crate::security_epoch::ConsumerModelError>()
                    .is_some()
            });
            let actual = result.unwrap_or(false);
            (
                actual,
                panicked,
                native_divergence,
                world.record(actual, &model),
            )
        });
        let record = match observed {
            Ok(record) => record,
            Err(_) => {
                return Err(Divergence {
                    category: "snapshot",
                    index,
                    records,
                }
                .into());
            }
        };
        let category = if panicked {
            Some("adapter_panic")
        } else if native_divergence {
            Some("native_model")
        } else if !shell_reference_matches(&record) {
            Some("native_model")
        } else if actual != expected {
            Some("acceptance")
        } else if record["projection"] != model.projection() {
            Some("state")
        } else if !original_invariants(&record, &mut originals) {
            Some("originals")
        } else {
            None
        };
        records.push(record);
        if let Some(category) = category {
            return Err(Divergence {
                category,
                index,
                records,
            }
            .into());
        }
    }
    Ok(records)
}

fn shell_reference_matches(record: &Value) -> bool {
    let actual = &record["native"]["serving"];
    let reference = &record["shell_reference"];
    actual["actual"].is_object()
        && actual["oracle"].is_object()
        && reference["world"].is_object()
        && actual["schedule"].is_object()
        && reference["schedule"].is_object()
        && actual["failed"] == false
        && reference["failed"] == false
        && actual["oracle"] == reference["world"]
        && actual["schedule"] == reference["schedule"]
        && actual["failed"] == reference["failed"]
        && matches!(
            record["shell_progress"].as_str(),
            Some("pending" | "completed" | "refused")
        )
        && record["native"]["serving_progress"] == record["shell_progress"]
}

fn source() -> Digest {
    Digest::of(&(
        "native-oauth-consumers-v1",
        crate::oauth::simulation::implementation(),
        ConsumerLifecycle::source(),
    ))
    .unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    Setup,
    Snapshot,
    AdapterPanic,
    NativeModel,
    Acceptance,
    State,
    Originals,
    Unobserved,
    Replay,
}

impl FailureKind {
    fn from_error(error: &anyhow::Error) -> Self {
        match error
            .downcast_ref::<Divergence>()
            .map(|failure| failure.category)
        {
            Some("setup") => Self::Setup,
            Some("snapshot") => Self::Snapshot,
            Some("adapter_panic") => Self::AdapterPanic,
            Some("native_model") => Self::NativeModel,
            Some("acceptance") => Self::Acceptance,
            Some("state") => Self::State,
            Some("originals") => Self::Originals,
            _ => Self::Unobserved,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Outcome {
    Passed(Vec<Value>),
    Failed {
        kind: FailureKind,
        index: Option<usize>,
        records: Vec<Value>,
    },
}

impl Outcome {
    fn records(&self) -> &[Value] {
        match self {
            Self::Passed(records) | Self::Failed { records, .. } => records,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ReplayPair {
    first: Outcome,
    second: Outcome,
}

impl ReplayPair {
    fn fully_observed(&self) -> bool {
        [&self.first, &self.second].iter().all(|outcome| {
            !matches!(
                outcome,
                Outcome::Failed {
                    kind: FailureKind::Unobserved,
                    ..
                }
            )
        })
    }

    fn failure(&self) -> Option<FailureKind> {
        if self.first != self.second {
            return Some(FailureKind::Replay);
        }
        match &self.first {
            Outcome::Passed(_) => None,
            Outcome::Failed { kind, .. } => Some(*kind),
        }
    }
}

fn replay_pair(program: &Program, control: OracleControl) -> ReplayPair {
    let observe = || match run(program, control) {
        Ok(records) => Outcome::Passed(records),
        Err(error) => {
            let kind = FailureKind::from_error(&error);
            let observed = error.downcast_ref::<Divergence>();
            Outcome::Failed {
                kind,
                index: observed.map(|failure| failure.index),
                records: observed.map_or_else(Vec::new, |failure| failure.records.clone()),
            }
        }
    };
    // Deliberately do not use `?`: a real failure must also run twice.
    ReplayPair {
        first: observe(),
        second: observe(),
    }
}

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 4 * (MAX_STEPS + 1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordRef {
    digest: Digest,
    bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum SavedOutcome {
    Passed {
        records: Vec<usize>,
    },
    Failed {
        kind: FailureKind,
        index: Option<usize>,
        records: Vec<usize>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPair {
    first: SavedOutcome,
    second: SavedOutcome,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: u32,
    source: Digest,
    original: Program,
    reduced: Program,
    oracle_control: OracleControl,
    category: FailureKind,
    original_observation: SavedPair,
    reduced_observation: SavedPair,
    records: Vec<RecordRef>,
}

fn record_name(index: usize) -> String {
    format!("record-{index:03}.json")
}

fn store_outcome(outcome: &Outcome, chunks: &mut Vec<Vec<u8>>) -> Result<SavedOutcome> {
    let mut records = Vec::new();
    ensure!(
        outcome.records().len() <= MAX_STEPS + 1,
        "consumer record count bound"
    );
    for value in outcome.records() {
        ensure!(value.is_object(), "consumer record object required");
        let bytes = serde_json::to_vec(value)?;
        ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "consumer record byte bound"
        );
        let decoded: Value = crate::json::decode_evidence(&bytes)?;
        ensure!(&decoded == value, "consumer record encoding changed");
        let index = match chunks.iter().position(|old| old == &bytes) {
            Some(index) => index,
            None => {
                ensure!(chunks.len() < MAX_RECORDS, "consumer archive record bound");
                chunks.push(bytes);
                chunks.len() - 1
            }
        };
        records.push(index);
    }
    Ok(match outcome {
        Outcome::Passed(_) => SavedOutcome::Passed { records },
        Outcome::Failed { kind, index, .. } => SavedOutcome::Failed {
            kind: *kind,
            index: *index,
            records,
        },
    })
}

fn store_pair(pair: &ReplayPair, chunks: &mut Vec<Vec<u8>>) -> Result<SavedPair> {
    Ok(SavedPair {
        first: store_outcome(&pair.first, chunks)?,
        second: store_outcome(&pair.second, chunks)?,
    })
}

// Borrow each already bounded parsed chunk. Repeated wire references must not
// create repeated Value trees or require a larger archive budget.
#[derive(PartialEq)]
struct LoadedOutcome<'a> {
    failure: Option<(FailureKind, Option<usize>)>,
    records: Vec<&'a Value>,
}

impl LoadedOutcome<'_> {
    fn matches(&self, actual: &Outcome) -> bool {
        let failure = match actual {
            Outcome::Passed(_) => None,
            Outcome::Failed { kind, index, .. } => Some((*kind, *index)),
        };
        self.failure == failure
            && self.records.len() == actual.records().len()
            && self
                .records
                .iter()
                .zip(actual.records())
                .all(|(saved, actual)| *saved == actual)
    }
}

struct LoadedPair<'a> {
    first: LoadedOutcome<'a>,
    second: LoadedOutcome<'a>,
}

impl LoadedPair<'_> {
    fn fully_observed(&self) -> bool {
        [&self.first, &self.second]
            .iter()
            .all(|outcome| !matches!(outcome.failure, Some((FailureKind::Unobserved, _))))
    }

    fn failure(&self) -> Option<FailureKind> {
        if self.first != self.second {
            return Some(FailureKind::Replay);
        }
        self.first.failure.map(|(kind, _)| kind)
    }

    fn matches(&self, actual: &ReplayPair) -> bool {
        self.first.matches(&actual.first) && self.second.matches(&actual.second)
    }
}

fn load_outcome<'a>(
    outcome: &SavedOutcome,
    chunks: &'a [Value],
    used: &mut BTreeSet<usize>,
) -> Result<LoadedOutcome<'a>> {
    let references = match outcome {
        SavedOutcome::Passed { records } | SavedOutcome::Failed { records, .. } => records,
    };
    ensure!(
        references.len() <= MAX_STEPS + 1,
        "consumer record count bound"
    );
    let mut records = Vec::new();
    for &index in references {
        records.push(chunks.get(index).context("consumer record missing")?);
        used.insert(index);
    }
    let failure = match outcome {
        SavedOutcome::Passed { .. } => None,
        SavedOutcome::Failed { kind, index, .. } => Some((*kind, *index)),
    };
    Ok(LoadedOutcome { failure, records })
}

fn load_pair<'a>(
    pair: &SavedPair,
    chunks: &'a [Value],
    used: &mut BTreeSet<usize>,
) -> Result<LoadedPair<'a>> {
    Ok(LoadedPair {
        first: load_outcome(&pair.first, chunks, used)?,
        second: load_outcome(&pair.second, chunks, used)?,
    })
}

fn retain_at(
    root: &std::path::Path,
    program: &Program,
    original: ReplayPair,
    control: OracleControl,
) -> Result<std::path::PathBuf> {
    retain_with(root, program, original, control, replay_pair)
}

// Private test-campaign probe seam only: neither a native callback nor an SDK.
fn retain_with(
    root: &std::path::Path,
    program: &Program,
    original: ReplayPair,
    control: OracleControl,
    mut probe: impl FnMut(&Program, OracleControl) -> ReplayPair,
) -> Result<std::path::PathBuf> {
    let category = original
        .failure()
        .context("consumer archive requires disagreement")?;
    let (steps, observed) = if !original.fully_observed() {
        // An unavailable cause cannot justify reducing the original input.
        (program.steps.clone(), None)
    } else {
        crate::oauth::simulation::reduce_steps(
            &program.steps,
            96,
            &format!("{category:?}"),
            |error| {
                error
                    .downcast_ref::<RetainedFailure>()
                    .map_or("unobserved".to_owned(), |failure| {
                        format!("{:?}", failure.kind)
                    })
            },
            |steps| {
                // Invalid input is not a reproduction of a consumer disagreement.
                if steps.is_empty() {
                    return Ok(());
                }
                let pair = probe(
                    &Program {
                        steps: steps.to_vec(),
                        ..program.clone()
                    },
                    control,
                );
                match pair.failure() {
                    Some(kind) => Err(anyhow::Error::new(RetainedFailure {
                        kind,
                        pair: Box::new(pair),
                    })),
                    None => Ok(()),
                }
            },
        )
    };
    // Keep the ACTUAL last winning observation. A transient disagreement need
    // not repeat later; neither a new probe nor its failure can erase this one.
    let (reduced, reduced_pair) =
        match observed.and_then(|error| error.downcast::<RetainedFailure>().ok()) {
            Some(observed)
                if observed.kind == category && observed.pair.failure() == Some(category) =>
            {
                (
                    Program {
                        steps,
                        ..program.clone()
                    },
                    *observed.pair,
                )
            }
            _ => (program.clone(), original.clone()),
        };
    let mut chunks = Vec::new();
    let original_observation = store_pair(&original, &mut chunks)?;
    let reduced_observation = store_pair(&reduced_pair, &mut chunks)?;
    let bundle = Bundle {
        version: 1,
        source: source(),
        original: program.clone(),
        reduced,
        oracle_control: control,
        category,
        original_observation,
        reduced_observation,
        records: chunks
            .iter()
            .map(|bytes| RecordRef {
                digest: Digest::new(bytes),
                bytes: bytes.len(),
            })
            .collect(),
    };
    let descriptor = serde_json::to_vec(&bundle)?;
    let _: Bundle = decode_descriptor(&descriptor)?;
    let total = chunks.iter().try_fold(descriptor.len(), |total, bytes| {
        total
            .checked_add(bytes.len())
            .context("consumer archive size overflow")
    })?;
    ensure!(total as u64 <= MAX_BYTES, "consumer archive byte bound");
    std::fs::create_dir_all(root)?;
    let directory = tempfile::Builder::new()
        .prefix("failure-")
        .tempdir_in(root)?
        .keep();
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let write = |path: &std::path::Path, bytes: &[u8]| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    };
    for (index, bytes) in chunks.iter().enumerate() {
        write(&directory.join(record_name(index)), bytes)?;
    }
    let manifest = directory.join("failure.json");
    // Publish the complete descriptor only after every referenced chunk closed.
    write(&manifest, &descriptor)?;
    Ok(manifest)
}

#[derive(Debug)]
struct RetainedFailure {
    kind: FailureKind,
    pair: Box<ReplayPair>,
}
impl std::fmt::Display for RetainedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("consumer oracle disagreement")
    }
}
impl std::error::Error for RetainedFailure {}

fn verify(program: &Program) -> Result<Vec<Value>> {
    let pair = replay_pair(program, OracleControl::None);
    if pair.failure().is_none() {
        return Ok(pair.first.records().to_vec());
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/oauth-native-consumer-simulation");
    let path = retain_at(&root, program, pair, OracleControl::None)?;
    anyhow::bail!(
        "native OAuth consumer divergence; replay {}",
        path.display()
    )
}

fn decode_descriptor(bytes: &[u8]) -> Result<Bundle> {
    let wire: Value = crate::json::decode_evidence(bytes)?;
    ensure!(
        wire.is_object() && wire["original"].is_object() && wire["reduced"].is_object(),
        "consumer replay object shape"
    );
    for program in [&wire["original"], &wire["reduced"]] {
        ensure!(
            program["steps"]
                .as_array()
                .is_some_and(|steps| steps.iter().all(Value::is_object)),
            "consumer step object required"
        );
    }
    let bundle: Bundle = serde_json::from_value(wire.clone())?;
    ensure!(
        wire == serde_json::to_value(&bundle)?,
        "consumer replay discarded input fields"
    );
    ensure!(
        bundle.version == 1 && bundle.source == source(),
        "consumer replay source/version mismatch"
    );
    ensure!(
        bundle.original.version == 1
            && bundle.original.seed == bundle.reduced.seed
            && bundle.reduced.version == 1
            && !bundle.original.steps.is_empty()
            && bundle.original.steps.len() <= MAX_STEPS
            && !bundle.reduced.steps.is_empty()
            && bundle.reduced.steps.len() <= MAX_STEPS,
        "consumer replay original binding"
    );
    let mut original = bundle.original.steps.iter();
    ensure!(
        bundle
            .reduced
            .steps
            .iter()
            .all(|step| original.by_ref().any(|candidate| candidate == step)),
        "consumer replay reduction is not deletion-only"
    );
    ensure!(
        bundle.records.len() <= MAX_RECORDS
            && bundle
                .records
                .iter()
                .all(|record| record.bytes > 0 && record.bytes <= MAX_RECORD_BYTES),
        "consumer replay record bound"
    );
    let total = bundle
        .records
        .iter()
        .try_fold(bytes.len(), |total, record| {
            total
                .checked_add(record.bytes)
                .context("consumer archive size overflow")
        })?;
    ensure!(total as u64 <= MAX_BYTES, "consumer archive byte bound");
    // Counts and indices are bounded before allocating borrowed references.
    // Each unique Value is decoded only once from the bounded archive.
    for outcome in [
        &bundle.original_observation.first,
        &bundle.original_observation.second,
        &bundle.reduced_observation.first,
        &bundle.reduced_observation.second,
    ] {
        let records = match outcome {
            SavedOutcome::Passed { records } | SavedOutcome::Failed { records, .. } => records,
        };
        ensure!(
            records.len() <= MAX_STEPS + 1,
            "consumer record count bound"
        );
        for &index in records {
            bundle
                .records
                .get(index)
                .context("consumer record missing")?;
        }
    }
    Ok(bundle)
}

fn bounded_file(path: &std::path::Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;
    ensure!(
        std::fs::symlink_metadata(path)?.is_file(),
        "consumer evidence regular file required"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "consumer evidence byte bound");
    Ok(bytes)
}

fn replay_file_inner(path: &std::path::Path) -> Result<()> {
    ensure!(
        path.file_name() == Some(std::ffi::OsStr::new("failure.json")),
        "consumer manifest filename required"
    );
    let bytes = bounded_file(path, MAX_RECORD_BYTES)?;
    let bundle = decode_descriptor(&bytes)?;
    let directory = path
        .parent()
        .context("consumer evidence directory absent")?;
    let expected: BTreeSet<String> = std::iter::once("failure.json".to_owned())
        .chain((0..bundle.records.len()).map(record_name))
        .collect();
    let mut observed = BTreeSet::new();
    for entry in std::fs::read_dir(directory)?.take(MAX_RECORDS + 2) {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("consumer evidence filename rejected"))?;
        ensure!(
            expected.contains(&name) && observed.insert(name),
            "consumer archive contains unexpected entry"
        );
    }
    ensure!(observed == expected, "consumer archive incomplete");
    let mut chunks = Vec::new();
    for (index, record) in bundle.records.iter().enumerate() {
        let bytes = bounded_file(&directory.join(record_name(index)), record.bytes)?;
        ensure!(
            bytes.len() == record.bytes && Digest::new(&bytes) == record.digest,
            "consumer evidence record changed"
        );
        let value: Value = crate::json::decode_evidence(&bytes)?;
        ensure!(
            value.is_object(),
            "consumer evidence record object required"
        );
        chunks.push(value);
    }
    let mut used = BTreeSet::new();
    let original = load_pair(&bundle.original_observation, &chunks, &mut used)?;
    let reduced = load_pair(&bundle.reduced_observation, &chunks, &mut used)?;
    ensure!(
        used.len() == chunks.len(),
        "consumer archive has unreferenced records"
    );
    ensure!(
        original.failure() == Some(bundle.category) && reduced.failure() == Some(bundle.category),
        "consumer saved category mismatch"
    );
    ensure!(
        original.fully_observed() && reduced.fully_observed(),
        "unobserved consumer failure remains unqualified"
    );
    // Validate the complete original as well as the deletion-only reduction.
    ensure!(
        original.matches(&replay_pair(&bundle.original, bundle.oracle_control)),
        "consumer original observation changed"
    );
    ensure!(
        reduced.matches(&replay_pair(&bundle.reduced, bundle.oracle_control)),
        "consumer reduced observation changed"
    );
    Ok(())
}

fn replay_file(path: &std::path::Path) -> Result<()> {
    replay_file_inner(path).map_err(|_| anyhow::anyhow!("native OAuth consumer replay refused"))
}

#[test]
fn replay_saved_native_oauth_consumer_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_NATIVE_OAUTH_REPLAY") else {
        return Ok(());
    };
    replay_file(std::path::Path::new(&path))
}

#[test]
fn saved_replay_checks_source_wire_shape_and_original_history_before_execution() -> Result<()> {
    let program = Program {
        version: 1,
        seed: 93,
        steps: happy(),
    };
    let first = replay_pair(&program, OracleControl::OvercountFirstRead);
    ensure!(
        first.failure() == Some(FailureKind::State),
        "negative oracle control did not disagree"
    );
    ensure!(
        first.first == first.second,
        "actual failure did not replay twice"
    );
    let root = tempfile::tempdir()?;
    let path = retain_at(
        root.path(),
        &program,
        first.clone(),
        OracleControl::OvercountFirstRead,
    )?;
    replay_file(&path)?;
    let original = std::fs::read(&path)?;
    // Keep a full witness in the reduction slot so changing both original
    // outcomes leaves every chunk referenced. Only actual content replay can
    // reject this otherwise valid repeated-reference substitution.
    let full = retain_with(
        root.path(),
        &program,
        first,
        OracleControl::OvercountFirstRead,
        |_, _| ReplayPair {
            first: Outcome::Passed(vec![]),
            second: Outcome::Passed(vec![]),
        },
    )?;
    let full_bytes = bounded_file(&full, MAX_RECORD_BYTES)?;
    let mut repeated: Value = crate::json::decode_evidence(&full_bytes)?;
    for outcome in ["first", "second"] {
        let records = repeated["original_observation"][outcome]["records"]
            .as_array_mut()
            .unwrap();
        ensure!(
            records.len() > 1 && records[0] != records[1],
            "reference substitution did not change a record"
        );
        records[1] = records[0].clone();
    }
    std::fs::write(&full, serde_json::to_vec(&repeated)?)?;
    let error = replay_file_inner(&full)
        .err()
        .context("wrong repeated record qualified")?;
    ensure!(
        error.to_string() == "consumer original observation changed",
        "substitution did not reach actual replay comparison"
    );
    std::fs::write(&full, full_bytes)?;
    replay_file(&full)?;
    for entry in std::fs::read_dir(path.parent().unwrap())? {
        let bytes = bounded_file(&entry?.path(), MAX_RECORD_BYTES)?;
        for secret in [
            b"private-provider-code".as_slice(),
            b"private-access-token",
            b"private-refresh-token",
            b"fixture-client-secret",
        ] {
            ensure!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "private material in consumer archive"
            );
        }
    }
    for mutation in 0..5 {
        let mut wire: Value = crate::json::decode_evidence(&original)?;
        match mutation {
            0 => wire["source"] = json!(Digest::new(b"different compiled implementation")),
            1 => wire["reduced"] = json!([1, 93, []]),
            2 => wire["reduced"]["seed"] = json!(94),
            3 => wire["original_observation"]["first"]["records"]
                .as_array_mut()
                .unwrap()
                .pop()
                .map(|_| ())
                .unwrap(),
            _ => wire["category"] = json!("acceptance"),
        }
        std::fs::write(&path, serde_json::to_vec(&wire)?)?;
        ensure!(
            replay_file(&path).is_err(),
            "changed counterexample was accepted"
        );
    }
    for step in [
        json!({"step":"read","extra":true}),
        json!({"step":"fault_refresh","fault":{"fault":"lost_reply","extra":true}}),
    ] {
        let mut wire: Value = crate::json::decode_evidence(&original)?;
        wire["original"]["steps"][0] = step;
        std::fs::write(&path, serde_json::to_vec(&wire)?)?;
        let error = replay_file_inner(&path)
            .err()
            .context("extra replay content accepted")?;
        ensure!(
            error.to_string() == "consumer replay discarded input fields",
            "structural control did not hit actual discarded-field guard"
        );
    }
    let mut inserted: Value = crate::json::decode_evidence(&original)?;
    inserted["reduced"]["steps"] = json!([{"step":"fail","owner":"controller","cut":99}]);
    std::fs::write(&path, serde_json::to_vec(&inserted)?)?;
    let error = replay_file_inner(&path)
        .err()
        .context("new fault inserted by reduction")?;
    ensure!(
        error.to_string() == "consumer replay reduction is not deletion-only",
        "inserted fault missed actual deletion guard"
    );
    ensure!(
        NATIVE.with(|slot| slot.borrow().is_none()),
        "rejected manifest created a native model world"
    );
    std::fs::write(&path, &original)?;
    let bundle = decode_descriptor(&original)?;
    let record = path.parent().unwrap().join(record_name(0));
    let bytes = std::fs::read(&record)?;
    std::fs::write(&record, b"{}")?;
    ensure!(replay_file(&path).is_err(), "changed record accepted");
    std::fs::write(&record, &bytes)?;
    ensure!(!bundle.records.is_empty(), "no complete records retained");
    replay_file(&path)?;
    let missing = record.with_extension("held");
    std::fs::rename(&record, &missing)?;
    ensure!(replay_file(&path).is_err(), "missing part accepted");
    std::fs::rename(&missing, &record)?;
    let extra = path.parent().unwrap().join("record-999.json");
    std::fs::write(&extra, b"{}")?;
    ensure!(replay_file(&path).is_err(), "extra part accepted");
    std::fs::remove_file(extra)?;
    let duplicate = String::from_utf8(original.clone())?.replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    ensure!(
        duplicate.as_bytes() != original.as_slice(),
        "duplicate control did not mutate"
    );
    std::fs::write(&path, duplicate)?;
    ensure!(replay_file(&path).is_err(), "duplicate descriptor accepted");
    let mut unknown: Value = crate::json::decode_evidence(&original)?;
    unknown["category"] = json!("PRIVATE-UNTRUSTED-CATEGORY");
    std::fs::write(&path, serde_json::to_vec(&unknown)?)?;
    let error = replay_file(&path).unwrap_err();
    ensure!(
        error.chain().count() == 1 && error.to_string() == "native OAuth consumer replay refused",
        "foreign diagnostic escaped"
    );
    std::fs::write(&path, &original)?;
    replay_file(&path)?;
    Ok(())
}

#[test]
fn complete_consumer_failure_larger_than_transport_budget_replays_without_truncation() -> Result<()>
{
    let mut steps = happy()[..5].to_vec();
    steps.extend((0..MAX_STEPS - 6).map(|_| Step::Advance { seconds: 1 }));
    steps.push(Step::Read);
    ensure!(
        steps.len() == MAX_STEPS,
        "maximum history control incomplete"
    );
    let program = Program {
        version: 1,
        seed: 94,
        steps,
    };
    let pair = replay_pair(&program, OracleControl::OvercountFirstRead);
    ensure!(
        pair.failure() == Some(FailureKind::State),
        "late disagreement did not occur"
    );
    ensure!(
        pair.first.records().len() == MAX_STEPS,
        "actual prefix truncated"
    );
    ensure!(
        serde_json::to_vec(pair.first.records())?.len() > 1_048_576,
        "control did not exceed ordinary transport bound"
    );
    let root = tempfile::tempdir()?;
    let path = retain_at(
        root.path(),
        &program,
        pair,
        OracleControl::OvercountFirstRead,
    )?;
    replay_file(&path)?;
    Ok(())
}

fn happy() -> Vec<Step> {
    vec![
        Step::Capture { disconnect: false },
        Step::Advance { seconds: 2 },
        Step::Approve,
        Step::Authorize,
        Step::Callback,
        Step::Read,
        Step::Refresh,
        Step::Capture { disconnect: true },
        Step::Advance { seconds: 2 },
        Step::Approve,
        Step::Disconnect,
        Step::Read,
        Step::ReplayCallback,
        Step::CachedRead,
    ]
}

fn shell_schedule(seed: u64, death_cut: Option<usize>) -> Result<usize> {
    let mut reference = ConsumerShellReference::new(seed)?;
    ensure!(reference.exchange(None)?, "Shell reference setup");
    reference.begin(death_cut)?;
    Ok(reference.observation()["schedule"]["pending"]
        .as_array()
        .context("reference schedule missing")?
        .len())
}

fn advance_shell(steps: &mut Vec<Step>, events: usize) {
    let mut remaining = events;
    while remaining > 0 {
        let events = remaining.min(64) as u8;
        steps.push(Step::AdvanceShell { events });
        remaining -= usize::from(events);
    }
}

#[test]
fn shell_progress_drives_selected_oauth_decisions_without_reviving_a_refused_owner() -> Result<()> {
    let mut covered = BTreeSet::new();
    for seed in 0..4 {
        let count = shell_schedule(seed, None)?;
        for pause in [0, 1, count / 2, count - 1, count] {
            for attempt in [false, true] {
                let mut steps = happy()[..5].to_vec(); // Real connect and callback.
                steps.extend([
                    Step::Capture { disconnect: true },
                    Step::Advance { seconds: 2 },
                    Step::BeginShell { death_cut: None },
                ]);
                advance_shell(&mut steps, pause);
                let at = steps.len();
                if attempt {
                    steps.push(Step::Approve);
                }
                steps.push(Step::Read); // App does not borrow the Shell owner.
                advance_shell(&mut steps, count - pause);
                let final_approval = steps.len();
                steps.extend([
                    Step::Reopen,
                    Step::Restore,
                    Step::Approve,
                    Step::Read,
                    Step::Refresh,
                ]);
                let records = verify(&Program {
                    version: 1,
                    seed,
                    steps,
                })?;
                let expected_approval = !attempt || pause == count;
                ensure!(
                    records[final_approval + 2]["accepted"] == expected_approval,
                    "completion restored a refused Shell owner or denied completed serving"
                );
                ensure!(
                    records[final_approval + 3]["accepted"] == true
                        && records[final_approval + 4]["accepted"] == true,
                    "Shell progress leaked into independent App reads"
                );
                if attempt && pause < count {
                    ensure!(
                        records[at]["accepted"] == false
                            && records[at]["shell_progress"] == "pending",
                        "pending transcript reused a prior completion"
                    );
                }
                ensure!(
                    records.last().unwrap()["shell_progress"] == "completed",
                    "resume did not complete the same transcript"
                );
                covered.insert((seed, pause, attempt));
            }
        }
    }
    ensure!(covered.len() == 40, "Shell pause coverage incomplete");
    Ok(())
}

#[test]
fn shell_peer_death_and_reopen_do_not_reclassify_app_or_restore_shell() -> Result<()> {
    for seed in 0..8 {
        let death_cut = Some(seed as usize * 17);
        let count = shell_schedule(seed, death_cut)?;
        let mut steps = happy()[..5].to_vec();
        steps.push(Step::BeginShell { death_cut });
        advance_shell(&mut steps, count);
        let at = steps.len();
        steps.extend([
            Step::Read,
            Step::Capture { disconnect: true },
            Step::Advance { seconds: 2 },
            Step::Approve,
            Step::Reopen,
            Step::Restore,
            Step::Approve,
            Step::Read,
            Step::Restart,
            Step::Approve,
            Step::Read,
        ]);
        let records = verify(&Program {
            version: 1,
            seed,
            steps,
        })?;
        ensure!(
            records[at]["accepted"] == true && records[at]["shell_progress"] == "refused",
            "peer death did not select Shell"
        );
        for index in [at + 3, at + 6, at + 9, at + 10] {
            ensure!(records[index]["accepted"] == false, "dead owner revived");
        }
        ensure!(
            records[at + 7]["accepted"] == true,
            "Shell death denied App"
        );
    }
    Ok(())
}

#[test]
fn pending_shell_oracle_mutation_is_retained_and_replayed_as_a_real_consumer_disagreement()
-> Result<()> {
    let program = Program {
        version: 1,
        seed: 71,
        steps: vec![
            Step::Capture { disconnect: false },
            Step::Advance { seconds: 2 },
            Step::BeginShell { death_cut: None },
            Step::Approve,
        ],
    };
    let pair = replay_pair(&program, OracleControl::PendingShellCompletes);
    ensure!(
        pair.failure() == Some(FailureKind::Acceptance),
        "false completion expectation escaped"
    );
    ensure!(
        pair.first
            .records()
            .last()
            .context("missing failed consumer record")?["shell_progress"]
            == "pending",
        "failure lost pending progress"
    );
    let root = tempfile::tempdir()?;
    let path = retain_at(
        root.path(),
        &program,
        pair,
        OracleControl::PendingShellCompletes,
    )?;
    replay_file(&path)?;
    Ok(())
}

#[test]
fn pending_shell_hook_checks_exact_role_scope_and_model_errors() -> Result<()> {
    let mut world = World::new(71)?;
    let hooks = world.port.clone();
    effects::scope(hooks.clone(), || -> Result<()> {
        world.boot()?;
        native_event(ConsumerEvent::BeginShell { death_cut: None })?;
        let scope = NATIVE.with(|slot| slot.borrow().as_ref().unwrap().scope.clone());
        let mut before =
            NATIVE.with(|slot| slot.borrow().as_ref().unwrap().lifecycle.observation())?;
        ensure!(
            effects::Hooks::native_check(hooks.as_ref(), NativeRole::AppHost, Some(&scope)).is_ok(),
            "pending Shell blocked App"
        );
        ensure!(
            effects::Hooks::native_check(hooks.as_ref(), NativeRole::SecurityShell, Some(&scope))
                .is_err(),
            "pending Shell accepted"
        );
        ensure!(
            effects::Hooks::native_check(hooks.as_ref(), NativeRole::EpochController, Some(&scope))
                .is_err(),
            "unsupported role accepted"
        );
        ensure!(
            effects::Hooks::native_check(hooks.as_ref(), NativeRole::AppHost, None).is_err(),
            "missing scope accepted"
        );
        let mut foreign = scope.clone();
        foreign.app = "foreign".to_owned().try_into()?;
        ensure!(
            effects::Hooks::native_check(hooks.as_ref(), NativeRole::AppHost, Some(&foreign))
                .is_err(),
            "foreign scope accepted"
        );
        let mut after =
            NATIVE.with(|slot| slot.borrow().as_ref().unwrap().lifecycle.observation())?;
        // Both selected roles still perform their real read-only counter
        // observation. Preserve that complete journal; compare all remaining
        // state without mistaking these mandatory reads for writes.
        let before_calls = before["storage"]["provider"]["counter"]
            .as_object_mut()
            .unwrap()
            .remove("calls")
            .unwrap();
        let after_calls = after["storage"]["provider"]["counter"]
            .as_object_mut()
            .unwrap()
            .remove("calls")
            .unwrap();
        let before_calls = before_calls.as_array().unwrap();
        let after_calls = after_calls.as_array().unwrap();
        ensure!(
            after_calls.starts_with(before_calls) && after_calls.len() > before_calls.len(),
            "selected roles skipped fresh reads"
        );
        ensure!(
            before == after && hooks.journal.lock().unwrap().is_empty(),
            "hook changed state or called a provider"
        );
        NATIVE.with(|slot| {
            slot.borrow_mut()
                .as_mut()
                .unwrap()
                .lifecycle
                .corrupt_shell_reference_for_control()
        });
        let error =
            effects::Hooks::native_check(hooks.as_ref(), NativeRole::SecurityShell, Some(&scope))
                .expect_err("pending denial hid model error");
        ensure!(
            error.is::<crate::security_epoch::ConsumerModelError>(),
            "model error collapsed into denial"
        );
        Ok(())
    })
}

#[test]
fn consumer_progress_requires_complete_known_reference_observations() -> Result<()> {
    let records = verify(&Program {
        version: 1,
        seed: 4,
        steps: vec![Step::BeginShell { death_cut: None }],
    })?;
    let original = &records[0];
    ensure!(
        shell_reference_matches(original),
        "complete pending observation refused"
    );
    for (side, field) in [
        ("shell_reference", "world"),
        ("shell_reference", "schedule"),
        ("shell_reference", "failed"),
    ] {
        let mut changed = original.clone();
        changed[side].as_object_mut().unwrap().remove(field);
        ensure!(
            !shell_reference_matches(&changed),
            "absent reference field accepted"
        );
    }
    for value in [Value::Null, json!("unknown"), json!(true)] {
        let mut changed = original.clone();
        changed["shell_progress"] = value.clone();
        changed["native"]["serving_progress"] = value;
        ensure!(
            !shell_reference_matches(&changed),
            "unknown progress accepted"
        );
    }
    let mut changed = original.clone();
    changed["shell_reference"]["world"] = Value::Null;
    changed["native"]["serving"]["oracle"] = Value::Null;
    ensure!(
        !shell_reference_matches(&changed),
        "two absent worlds compared equal"
    );
    let mut changed = original.clone();
    changed["shell_reference"]["failed"] = json!(true);
    changed["native"]["serving"]["failed"] = json!(true);
    ensure!(!shell_reference_matches(&changed), "two failed worlds compared equal");
    Ok(())
}

#[test]
fn shell_batch_bounds_and_overlapping_begin_preserve_the_pending_original() -> Result<()> {
    let mut actual = ConsumerLifecycle::new(71, &AuthorityScope {
        installation: "company".to_owned().try_into()?,
        environment: "production".to_owned().try_into()?,
        app: "workspace".to_owned().try_into()?,
    })?;
    let mut reference = ConsumerShellReference::new(71)?;
    actual.step(ConsumerEvent::BeginShell { death_cut: None })?;
    reference.begin(None)?;
    let before = actual.observation()?;
    let expected = reference.observation();
    for events in [0, 65, u8::MAX] {
        ensure!(actual.step(ConsumerEvent::AdvanceShell { events }).is_err(), "invalid batch admitted");
        ensure!(reference.advance(events).is_err(), "invalid reference batch admitted");
        ensure!(actual.observation()? == before && reference.observation() == expected, "invalid batch changed original");
    }
    ensure!(actual.step(ConsumerEvent::BeginShell { death_cut: None }).is_err(), "overlap replaced original");
    ensure!(reference.begin(None).is_err(), "reference overlap replaced original");
    ensure!(actual.observation()? == before && reference.observation() == expected, "overlap changed original");
    Ok(())
}

#[test]
fn native_oauth_consumer_happy_lifecycle_replays_with_both_native_models() -> Result<()> {
    for seed in 0..4 {
        let program = Program {
            version: 1,
            seed,
            steps: happy(),
        };
        verify(&program)?;
    }
    Ok(())
}

#[test]
fn seeded_native_oauth_failures_cannot_restore_originals_or_current_authority() -> Result<()> {
    let mut coverage = std::collections::BTreeSet::new();
    for seed in 0..56 {
        let owner = [
            Failure::App,
            Failure::Shell,
            Failure::Controller,
            Failure::Epoch,
        ][seed as usize % 4];
        let mut steps = happy();
        let at = (seed as usize / 4) % happy().len();
        steps.insert(
            at,
            Step::Fail {
                owner,
                cut: seed as usize,
            },
        );
        steps.extend([
            Step::Reopen,
            Step::Restore,
            Step::Read,
            Step::Callback,
            Step::Authorize,
            Step::Disconnect,
        ]);
        let program = Program {
            version: 1,
            seed,
            steps,
        };
        let records = verify(&program)?;
        dst::record(
            Campaign::NativeOauthConsumer,
            seed,
            [(
                Transition::StateChanged,
                records
                    .windows(2)
                    .filter(|w| w[0]["projection"] != w[1]["projection"])
                    .count() as u64,
            )],
        )?;
        let encoded = serde_json::to_string(&records)?;
        for secret in [
            "private-provider-code",
            "private-access-token",
            "private-refresh-token",
            "fixture-client-secret",
        ] {
            ensure!(
                !encoded.contains(secret),
                "private material in consumer replay evidence"
            );
        }
        let observed = &records[at]["native"];
        let closed = match owner {
            Failure::Shell => observed["serving"]["actual"]["endpoints"][0]["alive"] == false,
            _ => observed["storage"]["state"]["continuation"] == false,
        };
        ensure!(closed, "generated fault never reached its native owner");
        coverage.insert((seed % 4, at));
    }
    ensure!(
        coverage.len() == 56,
        "native consumer owner/prefix coverage incomplete"
    );
    Ok(())
}

#[test]
fn original_deadline_is_not_reset_by_native_reobservation_or_sqlite_reopen() -> Result<()> {
    for at in [1, 3, 4, 10] {
        let mut steps = happy();
        // The ordinary path spends two seconds between capture and approval.
        // Spend the remainder so the selected consumer meets deadline equality.
        steps.insert(at, Step::Advance { seconds: 298 });
        steps.extend([Step::Reopen, Step::Restore, Step::Authorize, Step::Callback]);
        let records = verify(&Program {
            version: 1,
            seed: at as u64,
            steps,
        })?;
        let boundary = &records[at + 1 + usize::from(at == 1)];
        ensure!(
            boundary["oracle"]["now"].as_i64()
                == boundary["oracle"]["created"]
                    .as_i64()
                    .map(|created| created + 300)
                && boundary["accepted"] == false,
            "original expiry schedule missed deadline equality"
        );
    }
    Ok(())
}

#[test]
fn post_pending_freshness_and_unexpired_old_version_remain_distinct_fences() -> Result<()> {
    let records = verify(&Program {
        version: 1,
        seed: 12,
        steps: vec![
            Step::Capture { disconnect: false },
            Step::Approve,
            Step::Advance { seconds: 2 },
            Step::Approve,
        ],
    })?;
    ensure!(
        records[1]["accepted"] == false && records[3]["accepted"] == false,
        "failed signer finalization recovered the same original"
    );
    let mut steps = happy();
    steps.truncate(7); // Through refresh; the first Use is still within 60s.
    steps.extend([Step::CachedRead, Step::Reopen, Step::Restore, Step::Read]);
    let records = verify(&Program {
        version: 1,
        seed: 13,
        steps,
    })?;
    ensure!(
        records[6]["projection"]["slot"][2] == 2,
        "freshness/version regression did not reach its intended boundary"
    );
    ensure!(
        records[7]["accepted"] == false && records.last().unwrap()["accepted"] == false,
        "a stale Use or reopened store restored consumer authority"
    );
    Ok(())
}

#[test]
fn refresh_final_checks_and_durable_cuts_do_not_regrant_authority() -> Result<()> {
    for (seed, fault) in [
        RefreshFault::Delay { millis: 4_999 },
        RefreshFault::Delay { millis: 5_000 },
        RefreshFault::LostReply,
        RefreshFault::Crash {
            at: Boundary::Dispatch,
        },
        RefreshFault::Crash {
            at: Boundary::Material,
        },
        RefreshFault::Crash {
            at: Boundary::Publication,
        },
        RefreshFault::LatePublication,
    ]
    .into_iter()
    .enumerate()
    {
        let mut steps = happy()[..6].to_vec();
        steps.push(Step::FaultRefresh { fault });
        if seed == 0 {
            steps.extend([
                Step::Capture { disconnect: true },
                Step::Advance { seconds: 2 },
                Step::Approve,
                Step::Disconnect,
            ]);
        } else {
            steps.extend([
                Step::Reopen,
                Step::Restore,
                Step::ResetMonotonic,
                Step::Read,
                Step::Refresh,
            ]);
        }
        let records = verify(&Program {
            version: 1,
            seed: seed as u64,
            steps,
        })?;
        ensure!(
            records[6]["accepted"] == (seed == 0),
            "refresh cut was not actually observed"
        );
        if seed != 0 {
            ensure!(
                records.last().unwrap()["accepted"] == false,
                "recovered observations regranted a refresh"
            );
        }
    }
    Ok(())
}

#[test]
fn vanished_executor_cannot_restore_originals_or_use_from_durable_rows() -> Result<()> {
    for at in [1, 4, 6, 10] {
        let mut steps = happy()[..at].to_vec();
        steps.extend([
            Step::Restart,
            Step::Reopen,
            Step::Restore,
            Step::Read,
            Step::Authorize,
            Step::Callback,
        ]);
        let records = verify(&Program {
            version: 1,
            seed: at as u64,
            steps,
        })?;
        ensure!(
            records[at]["owners"]["originals"] == json!([]),
            "restart retained the original registry"
        );
        ensure!(
            records.last().unwrap()["accepted"] == false,
            "rows restored the vanished original"
        );
    }
    Ok(())
}

#[test]
fn another_company_runtime_cannot_borrow_the_selected_simulated_owner() -> Result<()> {
    let mut world = World::new(101)?;
    effects::scope(world.port.clone(), || -> Result<()> {
        let scope = NATIVE.with(|slot| slot.borrow().as_ref().unwrap().scope.clone());
        native_management::fixtures::select_app_scope(&scope)?;
        world.boot()?;
        let before = native_management::fixtures::observation()?;
        let path = world
            .fixture
            ._directory
            .path()
            .join("foreign-instance.json");
        std::fs::write(
            &path,
            serde_json::to_vec(
                &json!({"installation":"other_company","environment":"production",
            "apps":{"workspace":{"artifact":"unused","readers":[],"writers":[]}}}),
            )?,
        )?;
        let db = world.fixture._directory.path().join("foreign.sqlite");
        let foreign = Runtime::from_artifact_for_tests(
            path,
            "workspace".into(),
            db.clone(),
            world.fixture.manager.runtime.artifact().clone(),
        )?;
        let entered = std::cell::Cell::new(false);
        let result = native_management::with_runtime_consumer(
            &foreign,
            native_management::RuntimePhase::Read,
            |_| {
                entered.set(true);
                Ok(())
            },
        );
        ensure!(
            result.is_err() && !entered.get() && !db.exists(),
            "foreign namespace entered the selected owner"
        );
        ensure!(
            native_management::fixtures::observation()? == before,
            "pure foreign input damaged the selected owner"
        );
        native_management::with_runtime_consumer(
            &world.fixture.manager.runtime,
            native_management::RuntimePhase::Read,
            |current| current.check(),
        )
    })
}

#[test]
fn successful_consumer_execution_is_not_a_saved_disagreement() -> Result<()> {
    let program = Program {
        version: 1,
        seed: 95,
        steps: happy(),
    };
    let pair = replay_pair(&program, OracleControl::None);
    ensure!(
        pair.failure().is_none() && pair.first == pair.second,
        "happy replay changed"
    );
    let root = tempfile::tempdir()?;
    ensure!(
        retain_at(root.path(), &program, pair, OracleControl::None).is_err(),
        "success saved as failure"
    );
    ensure!(
        std::fs::read_dir(root.path())?.next().is_none(),
        "success created failure output"
    );
    Ok(())
}

#[test]
fn intermittent_consumer_failure_keeps_actual_winning_evidence_without_rerunning() -> Result<()> {
    let program = Program {
        version: 1,
        seed: 96,
        steps: happy(),
    };
    let original = replay_pair(&program, OracleControl::OvercountFirstRead);
    ensure!(
        original.failure() == Some(FailureKind::State),
        "initial disagreement absent"
    );
    for first_wins in [false, true] {
        let mut calls = 0;
        let root = tempfile::tempdir()?;
        let path = retain_with(
            root.path(),
            &program,
            original.clone(),
            OracleControl::OvercountFirstRead,
            |_, _| {
                calls += 1;
                if first_wins && calls == 1 {
                    original.clone()
                } else {
                    ReplayPair {
                        first: Outcome::Passed(vec![]),
                        second: Outcome::Passed(vec![]),
                    }
                }
            },
        )?;
        ensure!(calls > 1, "intermittent control never stopped reproducing");
        let bundle = decode_descriptor(&bounded_file(&path, MAX_RECORD_BYTES)?)?;
        let directory = path.parent().unwrap();
        let mut chunks = Vec::new();
        for (index, reference) in bundle.records.iter().enumerate() {
            let bytes = bounded_file(&directory.join(record_name(index)), reference.bytes)?;
            chunks.push(crate::json::decode_evidence(&bytes)?);
        }
        let mut used = BTreeSet::new();
        ensure!(
            load_pair(&bundle.original_observation, &chunks, &mut used)?.matches(&original),
            "original captured pair was lost"
        );
        ensure!(
            load_pair(&bundle.reduced_observation, &chunks, &mut used)?.matches(&original),
            "last winning pair was lost"
        );
        ensure!(
            bundle.reduced.steps.len() == program.steps.len() - usize::from(first_wins),
            "unwitnessed reduction was retained"
        );
    }
    Ok(())
}

#[test]
fn replay_unknown_causes_refuse_and_repeated_records_borrow_one_bounded_value() -> Result<()> {
    let program = Program {
        version: 1,
        seed: 97,
        steps: happy(),
    };
    let unknown = ReplayPair {
        first: Outcome::Failed {
            kind: FailureKind::Unobserved,
            index: None,
            records: vec![],
        },
        second: Outcome::Passed(vec![]),
    };
    ensure!(
        unknown.failure() == Some(FailureKind::Replay) && !unknown.fully_observed(),
        "unknown replay control invalid"
    );
    let root = tempfile::tempdir()?;
    let path = retain_with(
        root.path(),
        &program,
        unknown,
        OracleControl::None,
        |_, _| ReplayPair {
            first: Outcome::Passed(vec![]),
            second: Outcome::Passed(vec![]),
        },
    )?;
    let error = replay_file_inner(&path)
        .err()
        .context("unobserved outcome qualified")?;
    ensure!(
        error.to_string() == "unobserved consumer failure remains unqualified",
        "unknown guard did not inspect actual outcomes"
    );
    let mut bundle = decode_descriptor(&bounded_file(&path, MAX_RECORD_BYTES)?)?;
    let chunks = vec![json!({"complete": "x".repeat(1_048_576)})];
    let bytes = serde_json::to_vec(&chunks[0])?;
    bundle.records = vec![RecordRef {
        digest: Digest::new(&bytes),
        bytes: bytes.len(),
    }];
    let repeated = SavedOutcome::Failed {
        kind: FailureKind::State,
        index: Some(MAX_STEPS - 1),
        records: vec![0; MAX_STEPS],
    };
    bundle.original_observation = SavedPair {
        first: repeated.clone(),
        second: repeated.clone(),
    };
    bundle.reduced_observation = SavedPair {
        first: repeated.clone(),
        second: repeated,
    };
    bundle.category = FailureKind::State;
    let decoded = decode_descriptor(&serde_json::to_vec(&bundle)?)?;
    let mut used = BTreeSet::new();
    let original = load_pair(&decoded.original_observation, &chunks, &mut used)?;
    let reduced = load_pair(&decoded.reduced_observation, &chunks, &mut used)?;
    for outcome in [
        &original.first,
        &original.second,
        &reduced.first,
        &reduced.second,
    ] {
        ensure!(
            outcome.records.len() == MAX_STEPS
                && outcome
                    .records
                    .iter()
                    .all(|record| std::ptr::eq(*record, &chunks[0])),
            "repeated record allocated a replacement Value"
        );
    }
    ensure!(
        used == BTreeSet::from([0]) && original.failure() == Some(FailureKind::State),
        "shared record changed content or metadata"
    );
    for (outcome, expected) in [
        (
            SavedOutcome::Passed {
                records: vec![0; MAX_STEPS + 2],
            },
            "consumer record count bound",
        ),
        (
            SavedOutcome::Passed { records: vec![1] },
            "consumer record missing",
        ),
    ] {
        bundle.original_observation.first = outcome;
        let error = decode_descriptor(&serde_json::to_vec(&bundle)?)
            .err()
            .context("invalid references accepted")?;
        ensure!(
            error.to_string() == expected,
            "reference refusal missed actual bound"
        );
    }
    bundle.records = vec![
        RecordRef {
            digest: Digest::new(b"bounded physical part"),
            bytes: MAX_RECORD_BYTES
        };
        16
    ];
    let error = decode_descriptor(&serde_json::to_vec(&bundle)?)
        .err()
        .context("physical archive overflow accepted")?;
    ensure!(
        error.to_string() == "consumer archive byte bound",
        "physical archive bound changed"
    );

    Ok(())
}

#[test]
fn unobserved_consumer_failure_never_reduces_to_invalid_empty_input() -> Result<()> {
    let program = Program {
        version: 1,
        seed: 98,
        steps: happy(),
    };
    let outcome = Outcome::Failed {
        kind: FailureKind::Unobserved,
        index: None,
        records: vec![],
    };
    for other in [
        outcome.clone(),
        Outcome::Passed(vec![]),
        Outcome::Failed {
            kind: FailureKind::State,
            index: Some(0),
            records: vec![],
        },
    ] {
        for (first, second) in [(outcome.clone(), other.clone()), (other, outcome.clone())] {
            let pair = ReplayPair { first, second };
            let root = tempfile::tempdir()?;
            let path = retain_with(
                root.path(),
                &program,
                pair.clone(),
                OracleControl::None,
                |_, _| panic!("unobserved failure was minimized"),
            )?;
            let descriptor = decode_descriptor(&bounded_file(&path, MAX_RECORD_BYTES)?)?;
            ensure!(
                descriptor.reduced.steps == program.steps,
                "unknown cause lost original history"
            );
            let mut used = BTreeSet::new();
            ensure!(
                load_pair(&descriptor.reduced_observation, &[], &mut used)?.matches(&pair),
                "unknown outcomes changed"
            );
            ensure!(replay_file(&path).is_err(), "unobserved cause qualified");
        }
    }
    Ok(())
}
