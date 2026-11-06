use anyhow::{Context, Result};
use day2::{
    app_secrets::{self, Operation, Provider, ProviderFailure, State, Target, Write},
    artifact::Instance,
    authority_state::{self, LocalOperator},
    store::Runtime,
    web::LocalServer,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    thread,
};
use zeroize::Zeroizing;

const FIRST: &[u8] = b"SYNTHETIC_OWNER_SECRET_FIRST_NEVER_JOURNAL";
const SECOND: &[u8] = b"SYNTHETIC_OWNER_SECRET_REPLACEMENT_NEVER_JOURNAL";

struct World {
    directory: tempfile::TempDir,
    runtime: Runtime,
}
impl World {
    fn new() -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_OWNED_PROBE_ARTIFACT")
            .map(PathBuf::from)
            .context("build the public owned-probe fixture")?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        let policy: Value = serde_json::from_str(include_str!(
            "../../../fixtures/authority-policies/owned-links.json"
        ))?;
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "installation":"secret_test", "environment":"test", "apps":{"owned":{
                    "artifact":artifact,"readers":["viewer"],"writers":["alice","admin"],"authority":policy,
                    "managed_secrets":{"project_number":123456,"access_token_file":directory.path().join("token")}
                }}
            }))?,
        )?;
        let runtime = Runtime::load(&path, "owned")?;
        runtime.initialize()?;
        Ok(Self { directory, runtime })
    }
    fn input(
        &self,
        operation: Operation,
        id: &str,
        value: &[u8],
        expected: Option<u64>,
    ) -> Result<Write> {
        Ok(Write {
            operation,
            name: "API_KEY".into(),
            request_id: id.into(),
            expected_authority: app_secrets::list(&self.runtime, "admin")?.authority,
            expected_version: expected,
            value: Zeroizing::new(value.into()),
        })
    }
    fn assert_private(&self) -> Result<()> {
        let db = rusqlite::Connection::open(self.runtime.db())?;
        let receipts: Vec<String> = db
            .prepare("SELECT receipt FROM day2_app_secret_requests")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for receipt in receipts {
            assert!(!receipt.contains(std::str::from_utf8(FIRST)?));
            assert!(!receipt.contains(std::str::from_utf8(SECOND)?));
            assert!(!receipt.contains("payload"));
            assert!(!receipt.contains("dataCrc32c"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<String>>,
    values: Mutex<Vec<Vec<u8>>>,
    unknown: bool,
    revoke_after_create: Option<Runtime>,
    revoke_after_version: Option<Runtime>,
}

#[test]
fn audit_tampering_and_missing_schema_refuse_before_provider_io() -> Result<()> {
    let world = World::new()?;
    let provider = Fake::default();
    let input = world.input(Operation::Create, "guarded-create", FIRST, None)?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    db.execute_batch("DROP TRIGGER day2_app_secret_events_no_update")?;
    assert!(app_secrets::list(&world.runtime, "admin").is_err());
    assert!(app_secrets::write(&world.runtime, "admin", &input, &provider).is_err());
    assert!(provider.calls.lock().unwrap().is_empty());
    let other = World::new()?;
    let input = other.input(Operation::Create, "restored-create", FIRST, None)?;
    let db = rusqlite::Connection::open(other.runtime.db())?;
    db.execute("DELETE FROM day2_meta WHERE key='app_secrets_schema'", [])?;
    assert!(app_secrets::write(&other.runtime, "admin", &input, &provider).is_err());
    assert!(provider.calls.lock().unwrap().is_empty());
    Ok(())
}

fn revoke(runtime: &Runtime) -> Result<()> {
    let active = authority_state::current(&rusqlite::Connection::open(runtime.db())?)?;
    let mut document = active.document;
    document.policy.as_mut().unwrap().admins = std::collections::BTreeSet::from(["backup".into()]);
    authority_state::apply(
        runtime,
        &LocalOperator::assert_local("operator")?,
        &authority_state::ApplyAuthority {
            request_id: "revoke-during-provider-call".into(),
            expected: Some(active.stamp),
            document,
        },
    )?;
    Ok(())
}

impl Provider for Fake {
    fn create(&self, target: &Target, _: &str) -> Result<(), ProviderFailure> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("create:{}", target.resource()));
        if let Some(runtime) = &self.revoke_after_create {
            revoke(runtime).unwrap();
        }
        Ok(())
    }
    fn add_version(&self, target: &Target, value: &[u8]) -> Result<u64, ProviderFailure> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("version:{}", target.resource()));
        let mut values = self.values.lock().unwrap();
        values.push(value.into());
        if let Some(runtime) = &self.revoke_after_version {
            revoke(runtime).unwrap();
        }
        if self.unknown {
            Err(ProviderFailure::Unknown)
        } else {
            Ok(u64::try_from(values.len()).unwrap())
        }
    }
}

#[test]
fn create_rotate_scope_cas_and_receipts_never_persist_values() -> Result<()> {
    let world = World::new()?;
    let provider = Fake::default();
    let first = world.input(Operation::Create, "create-first", FIRST, None)?;
    assert!(app_secrets::write(&world.runtime, "alice", &first, &provider).is_err());
    assert!(provider.calls.lock().unwrap().is_empty());
    let created = app_secrets::write(&world.runtime, "admin", &first, &provider)?;
    assert_eq!(created.state, State::Stored);
    assert_eq!(created.version, Some(1));
    assert!(!created.activation_performed);
    assert_eq!(
        app_secrets::status(&world.runtime, "admin", "create-first")?,
        created
    );
    assert!(app_secrets::status(&world.runtime, "alice", "create-first").is_err());
    let before = provider.calls.lock().unwrap().len();
    assert!(app_secrets::write(&world.runtime, "admin", &first, &provider).is_err());
    assert_eq!(provider.calls.lock().unwrap().len(), before);
    let mut changed_retry = world.input(Operation::Create, "create-first", SECOND, None)?;
    assert!(app_secrets::write(&world.runtime, "admin", &changed_retry, &provider).is_err());
    changed_retry.request_id = "second-create".into();
    assert!(app_secrets::write(&world.runtime, "admin", &changed_retry, &provider).is_err());
    let stale = world.input(Operation::Rotate, "stale-version", SECOND, Some(2))?;
    assert!(app_secrets::write(&world.runtime, "admin", &stale, &provider).is_err());
    assert_eq!(provider.calls.lock().unwrap().len(), before);
    let second = world.input(Operation::Rotate, "rotate-second", SECOND, Some(1))?;
    let rotated = app_secrets::write(&world.runtime, "admin", &second, &provider)?;
    assert_eq!(rotated.version, Some(2));
    let listed = app_secrets::list(&world.runtime, "admin")?;
    assert_eq!(listed.secrets.len(), 1);
    assert_eq!(listed.secrets[0].version, Some(2));
    assert!(!listed.secrets[0].blocked);
    assert_eq!(
        *provider.values.lock().unwrap(),
        [FIRST.to_vec(), SECOND.to_vec()]
    );
    assert!(
        provider
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(
                |call| call.contains(&day2_capabilities::app_secrets::prefix(
                    world.runtime.scope()
                ))
            )
    );
    let unchanged: Instance = Instance::load(world.runtime.instance_path())?;
    assert_eq!(
        unchanged.apps["owned"].authority.as_ref().unwrap().admins,
        std::collections::BTreeSet::from(["admin".into()])
    );
    world.assert_private()?;
    Ok(())
}

#[test]
fn uncertain_write_is_visible_and_blocks_blind_repetition() -> Result<()> {
    let world = World::new()?;
    let provider = Fake {
        unknown: true,
        ..Default::default()
    };
    let first = world.input(Operation::Create, "lost-version-reply", FIRST, None)?;
    let result = app_secrets::write(&world.runtime, "admin", &first, &provider)?;
    assert_eq!(result.state, State::Unknown);
    assert_eq!(
        app_secrets::status(&world.runtime, "admin", "lost-version-reply")?.state,
        State::Unknown
    );
    assert!(app_secrets::list(&world.runtime, "admin")?.secrets[0].blocked);
    let count = provider.calls.lock().unwrap().len();
    for id in ["lost-version-reply", "unsafe-new-request"] {
        let repeat = world.input(Operation::Rotate, id, FIRST, None)?;
        assert!(app_secrets::write(&world.runtime, "admin", &repeat, &provider).is_err());
    }
    assert_eq!(provider.calls.lock().unwrap().len(), count);
    world.assert_private()?;
    Ok(())
}

#[test]
fn revocation_prevents_next_dispatch_but_preserves_dispatched_outcome() -> Result<()> {
    let world = World::new()?;
    let provider = Fake {
        revoke_after_create: Some(world.runtime.clone()),
        ..Default::default()
    };
    let input = world.input(Operation::Create, "revoked-before-value", FIRST, None)?;
    assert!(app_secrets::write(&world.runtime, "admin", &input, &provider).is_err());
    assert!(provider.values.lock().unwrap().is_empty());
    let listed = app_secrets::list(&world.runtime, "backup")?;
    assert!(listed.secrets[0].container_created);
    assert!(!listed.secrets[0].blocked);
    assert_eq!(listed.secrets[0].version, None);
    assert!(app_secrets::list(&world.runtime, "admin").is_err());
    let world = World::new()?;
    let provider = Fake {
        revoke_after_version: Some(world.runtime.clone()),
        ..Default::default()
    };
    let input = world.input(Operation::Create, "revoked-after-dispatch", FIRST, None)?;
    assert!(app_secrets::write(&world.runtime, "admin", &input, &provider).is_err());
    let receipt = app_secrets::status(&world.runtime, "backup", "revoked-after-dispatch")?;
    assert_eq!(receipt.state, State::Stored);
    assert_eq!(receipt.version, Some(1));
    world.assert_private()?;
    Ok(())
}

#[test]
fn changed_namespace_and_malformed_inputs_refuse_before_provider_io() -> Result<()> {
    let world = World::new()?;
    let provider = Fake::default();
    for (id, value) in [("empty", Vec::new()), ("oversized", vec![b'x'; 65_537])] {
        let input = world.input(Operation::Create, id, &value, None)?;
        assert!(app_secrets::write(&world.runtime, "admin", &input, &provider).is_err());
    }
    let mut input = world.input(Operation::Create, "wrong-authority", FIRST, None)?;
    input.expected_authority.revision += 1;
    assert!(app_secrets::write(&world.runtime, "admin", &input, &provider).is_err());
    input.expected_authority.revision -= 1;
    input.name = "../another-app".into();
    assert!(app_secrets::write(&world.runtime, "admin", &input, &provider).is_err());
    input.name = "API_KEY".into();
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance
        .apps
        .get_mut("owned")
        .unwrap()
        .managed_secrets
        .as_mut()
        .unwrap()
        .project_number = 999_999.try_into()?;
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    assert!(app_secrets::list(&world.runtime, "admin").is_err());
    assert!(app_secrets::write(&world.runtime, "admin", &input, &provider).is_err());
    assert!(provider.calls.lock().unwrap().is_empty());
    Ok(())
}

struct Server {
    origin: String,
    login: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn start(runtime: Runtime, actor: &str, provider: Arc<dyn Provider>) -> Result<Self> {
        let actor = actor.to_owned();
        let (sender, receiver) = mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let join = thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let server = LocalServer::bind(runtime, &actor, 0)
                        .await
                        .unwrap()
                        .with_app_secret_provider(provider)
                        .unwrap();
                    sender
                        .send((server.origin.clone(), server.login_url.clone()))
                        .unwrap();
                    server
                        .serve(async {
                            let _ = stopped.await;
                        })
                        .await
                        .unwrap();
                });
        });
        let (origin, login) = receiver.recv()?;
        Ok(Self {
            origin,
            login,
            stop: Some(stop),
            join: Some(join),
        })
    }
    fn client(&self) -> Result<reqwest::blocking::Client> {
        let client = reqwest::blocking::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        assert!(client.get(&self.login).send()?.status().is_success());
        let token = reqwest::Url::parse(&self.login)?
            .query_pairs()
            .find(|(key, _)| key == "token")
            .context("login token")?
            .1
            .into_owned();
        assert_eq!(
            client
                .post(format!("{}/login", self.origin))
                .header("Origin", &self.origin)
                .form(&[("token", token)])
                .send()?
                .status()
                .as_u16(),
            303
        );
        Ok(client)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[test]
fn http_secrets_require_owner_session_origin_csrf_and_exact_input() -> Result<()> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let world = World::new()?;
    let provider = Arc::new(Fake::default());
    let server = Server::start(world.runtime.clone(), "admin", provider.clone())?;
    let uri = format!("{}{}", server.origin, app_secrets::PATH);
    assert_eq!(reqwest::blocking::get(&uri)?.status().as_u16(), 401);
    let client = server.client()?;
    let response = client
        .get(format!("{}/api/session", server.origin))
        .send()?;
    assert_eq!(response.status().as_u16(), 200);
    let session: Value = response.json()?;
    let response = client.get(&uri).send()?;
    assert_eq!(response.status().as_u16(), 200);
    let listed: Value = response.json()?;
    let body = json!({"operation":"create","name":"API_KEY","expected_authority":listed["authority"],"expected_version":null,"value":STANDARD.encode(FIRST)});
    assert_eq!(client.post(&uri).json(&body).send()?.status().as_u16(), 403);
    let send = |value: &Value, origin: &str, csrf: &str, id: &str| {
        client
            .post(&uri)
            .header("Origin", origin)
            .header("X-CSRF-Token", csrf)
            .header("Idempotency-Key", id)
            .json(value)
            .send()
    };
    let csrf = session["csrf_token"].as_str().unwrap();
    assert_eq!(
        send(&body, "https://foreign.example", csrf, "bad-origin")?
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        send(&body, &server.origin, "wrong-csrf", "bad-csrf")?
            .status()
            .as_u16(),
        403
    );
    let mut bad = body.clone();
    bad["actor"] = json!("admin");
    assert_eq!(
        send(&bad, &server.origin, csrf, "injected-actor")?
            .status()
            .as_u16(),
        400
    );
    assert!(provider.calls.lock().unwrap().is_empty());
    let response = send(&body, &server.origin, csrf, "http-create")?;
    assert_eq!(response.status().as_u16(), 200);
    let receipt: Value = response.json()?;
    assert_eq!(receipt["version"], 1);
    assert_eq!(receipt["activation_performed"], false);
    let retry = send(&body, &server.origin, csrf, "http-create")?;
    assert_eq!(retry.status().as_u16(), 409);
    let status: Value = client
        .get(format!("{uri}/requests/http-create"))
        .send()?
        .json()?;
    assert_eq!(status, receipt);
    let viewer = Server::start(world.runtime.clone(), "alice", provider.clone())?;
    assert_eq!(
        viewer
            .client()?
            .get(format!("{}{}", viewer.origin, app_secrets::PATH))
            .send()?
            .status()
            .as_u16(),
        403
    );
    assert_eq!(provider.calls.lock().unwrap().len(), 2);
    world.assert_private()?;
    assert!(world.directory.path().exists());
    Ok(())
}
