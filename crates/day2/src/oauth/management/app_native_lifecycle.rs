// Composed DATA simulation. Native permissions are never constructed here.
// The storage and both transcript models remain independent of OAuth's oracle.
use super::*;
use crate::{
    oauth::native_management,
    protocol::{Instruction, Request},
    security_epoch::{ConsumerEvent, ConsumerLifecycle},
};
use day2_capabilities::security_epoch::{AuthorityScope, bootstrap::NativeRole};
use serde_json::Value;
use std::cell::RefCell;

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
            "native":NATIVE.with(|slot| slot.borrow().as_ref().unwrap().lifecycle.observation())?}),
        )
    }
}

// The oracle consumes only the schedule, never World results, SQL or production
// transition functions. OAuth slots and provider effects have independent rules.
#[derive(Clone, Debug, Serialize)]
struct Oracle {
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
    fn new() -> Self {
        Self {
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
        }
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

    fn step(&mut self, step: Step) -> bool {
        let app = self.app && self.controller;
        let original = app && self.pending && self.now < self.created + 300;
        match step {
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
            Step::Fail { owner, .. } => {
                match owner {
                    Failure::App => {
                        self.app = false;
                        self.controller = false;
                    }
                    Failure::Shell => self.shell = false,
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
        }
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

fn run(program: &Program) -> Result<Vec<Value>> {
    ensure!(
        program.version == 1 && !program.steps.is_empty() && program.steps.len() <= MAX_STEPS,
        "consumer campaign version/history bound"
    );
    ensure!(program.steps.iter().all(|step| !matches!(step, Step::Advance { seconds } if *seconds > 600)
            && !matches!(step, Step::FaultRefresh { fault: RefreshFault::Delay { millis } } if *millis > 10_000)),
        "consumer clock input bound");
    let mut world = World::new(program.seed)?;
    let hooks = world.port.clone();
    let mut model = Oracle::new();
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
    for (index, &step) in program.steps.iter().enumerate() {
        let expected = model.step(step);
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

fn source() -> Digest {
    Digest::of(&(
        "native-oauth-consumers-v1",
        crate::oauth::simulation::implementation(),
        ConsumerLifecycle::source(),
    ))
    .unwrap()
}

fn checked(program: &Program) -> Result<Vec<Value>> {
    let first = run(program)?;
    let second = run(program)?;
    ensure!(
        first == second,
        Divergence {
            category: "replay",
            index: 0,
            records: first.clone()
        }
    );
    Ok(first)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: u32,
    source: Digest,
    original: Program,
    reduced: Program,
    failure: Value,
}

fn verify(program: &Program) -> Result<Vec<Value>> {
    let failure = match checked(program) {
        Ok(records) => return Ok(records),
        Err(error) => error,
    };
    let category = |error: &anyhow::Error| {
        error
            .downcast_ref::<Divergence>()
            .map_or("input", |failure| failure.category)
            .to_owned()
    };
    let (steps, _) = crate::oauth::simulation::reduce_steps(
        &program.steps,
        96,
        &category(&failure),
        category,
        |steps| {
            checked(&Program {
                steps: steps.to_vec(),
                ..program.clone()
            })
            .map(|_| ())
        },
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/oauth-native-consumer-simulation");
    std::fs::create_dir_all(&root)?;
    let directory = tempfile::Builder::new()
        .prefix("failure-")
        .tempdir_in(root)?
        .keep();
    let bundle = Bundle {
        version: 1,
        source: source(),
        original: program.clone(),
        reduced: Program {
            steps,
            ..program.clone()
        },
        failure: failure
            .downcast_ref::<Divergence>()
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or_else(|| json!({"category":"input"})),
    };
    let bytes = serde_json::to_vec_pretty(&bundle)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "consumer failure bundle byte bound"
    );
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let path = directory.join("failure.json");
    options.open(&path)?.write_all(&bytes)?;
    anyhow::bail!(
        "native OAuth consumer divergence; replay {}",
        path.display()
    )
}

fn replay_bytes(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "consumer replay byte bound"
    );
    // Derived structs accept positional arrays; constrain the actual external
    // descriptor objects before typed decoding, after strict raw duplicate checks.
    let wire: Value = crate::json::decode(bytes)?;
    ensure!(
        wire.is_object() && wire["original"].is_object() && wire["reduced"].is_object(),
        "consumer replay object shape"
    );
    let bundle: Bundle = serde_json::from_value(wire.clone())?;
    // Serde's internally tagged unit variants can consume unknown content even
    // with deny_unknown_fields. Refuse any wire content discarded by decoding.
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
            && !bundle.original.steps.is_empty()
            && bundle.original.steps.len() <= MAX_STEPS,
        "consumer replay original binding"
    );
    let mut original = bundle.original.steps.iter();
    ensure!(
        bundle
            .reduced
            .steps
            .iter()
            .all(|step| original.by_ref().any(|candidate| candidate == step)),
        "consumer replay reduction is not a deletion history"
    );
    checked(&bundle.reduced)?;
    Ok(())
}

fn replay_file(path: &std::path::Path) -> Result<()> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    replay_bytes(&bytes)
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
    let bundle = Bundle {
        version: 1,
        source: source(),
        original: program.clone(),
        reduced: program,
        failure: Value::Null,
    };
    let bytes = serde_json::to_vec(&bundle)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("replay.json");
    std::fs::write(&path, &bytes)?;
    replay_file(&path)?;
    for step in [
        json!({"step":"read","extra":true}),
        json!({"step":"fault_refresh","fault":{"fault":"lost_reply","extra":true}}),
    ] {
        let mut extra = serde_json::to_value(&bundle)?;
        for program in ["original", "reduced"] {
            extra[program]["steps"][6] = step.clone();
        }
        ensure!(
            replay_bytes(&serde_json::to_vec(&extra)?)
                .unwrap_err()
                .to_string()
                == "consumer replay discarded input fields",
            "unit variant discarded unknown replay content"
        );
    }
    let mut changed = serde_json::to_value(&bundle)?;
    changed["source"] = json!(Digest::new(b"different compiled implementation"));
    ensure!(
        replay_bytes(&serde_json::to_vec(&changed)?).is_err(),
        "changed source replayed"
    );
    changed = serde_json::to_value(&bundle)?;
    changed["reduced"] = json!([1, 93, []]);
    ensure!(
        replay_bytes(&serde_json::to_vec(&changed)?).is_err(),
        "positional descriptor replayed"
    );
    changed = serde_json::to_value(&bundle)?;
    changed["reduced"]["seed"] = json!(94);
    ensure!(
        replay_bytes(&serde_json::to_vec(&changed)?).is_err(),
        "replacement seed replayed"
    );
    changed = serde_json::to_value(&bundle)?;
    changed["reduced"]["steps"] = json!([{"step":"fail","owner":"controller","cut":99}]);
    ensure!(
        replay_bytes(&serde_json::to_vec(&changed)?).is_err(),
        "new fault inserted by reduction"
    );
    ensure!(
        NATIVE.with(|slot| slot.borrow().is_none()),
        "rejected replay created an owner"
    );
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
