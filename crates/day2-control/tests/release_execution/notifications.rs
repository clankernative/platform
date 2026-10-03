//! Source-backed Notifications business flow across two native HTTP hosts.
//! IAP and provider observations are explicit fixtures; the Roc apps, codecs,
//! SQLite transactions, imported grant, signatures and release fence are real.
use super::*;

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const OPERATOR: &str = "operator@example.com";

struct Flow {
    _directory: tempfile::TempDir,
    _release: Fixture,
    _receiver: QueryServer,
    caller: QueryServer,
    ownership: Runtime,
    notifications: Runtime,
    iap: Arc<FixtureIap>,
    client: reqwest::blocking::Client,
    at: i64,
}

fn artifact(variable: &str) -> Result<PathBuf> {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .context("run xtask build-delegation-business or verify")
}

impl Drop for Flow {
    fn drop(&mut self) {
        // Preserve real artifact-bound SQLite observations on success and failure.
        // "captured" is evidence storage, never a synthesized passing receipt.
        let preserve = || -> Result<()> {
            use std::os::unix::fs::PermissionsExt;
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../artifacts/delegation-business-evidence");
            fs::create_dir_all(&root)?;
            let directory = tempfile::Builder::new()
                .prefix("notifications-")
                .tempdir_in(root)?
                .keep();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
            for runtime in [&self.ownership, &self.notifications] {
                let state = directory.join(runtime.app());
                fs::create_dir(&state)?;
                fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
                let instance = state.join("instance.json");
                fs::copy(runtime.instance_path(), &instance)?;
                fs::set_permissions(&instance, fs::Permissions::from_mode(0o600))?;
                let database = state.join("observations.sqlite");
                let connection = Connection::open(runtime.db())?;
                connection.busy_timeout(Duration::from_secs(2))?;
                connection.execute(
                    "VACUUM INTO ?1",
                    [database.to_str().context("evidence database")?],
                )?;
                fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
            }
            let manifest = directory.join("capture.json");
            fs::write(
                &manifest,
                serde_json::to_vec_pretty(
                    &json!({"format":1,"profile":"notifications-native-http-fixture","status":"captured","panicking":thread::panicking(),"artifacts":{"app_ownership":self.ownership.artifact().id(),"notifications":self.notifications.artifact().id()}}),
                )?,
            )?;
            fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))?;
            Ok(())
        };
        if let Err(error) = preserve() {
            if thread::panicking() {
                eprintln!("failed to preserve notification evidence: {error:#}");
            } else {
                panic!("failed to preserve notification evidence: {error:#}");
            }
        }
    }
}

impl Flow {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let ownership_artifact = artifact("DAY2_TEST_APP_OWNERSHIP_ARTIFACT")?;
        let notification_artifact = artifact("DAY2_TEST_NOTIFICATIONS_ARTIFACT")?;
        let loaded = day2::artifact::LoadedArtifact::load(&ownership_artifact)?;
        let actors = json!([ALICE, BOB, OPERATOR]);
        let ownership_policy = json!({"version":1,"admins":[OPERATOR],"operations":{
            "app_ownership.check":{"actors":actors,"mode":{"kind":"read"},"models":{"ownerships":{"read":true,"rows":{"kind":"all"}}}},
            "app_ownership.set_owner":{"actors":[OPERATOR],"mode":{"kind":"current_state"},"models":{"ownerships":{"read":true,"create":true,"update_fields":["active"],"rows":{"kind":"all"}}}}
        }});
        let mut read = json!({"actors":actors,"mode":{"kind":"read"},"models":{},"observations":["app.query.v1"]});
        let mut get = read.clone();
        get["models"] = json!({"definitions":{"read":true,"rows":{"kind":"all"}},"contract_versions":{"read":true,"rows":{"kind":"all"}}});
        let save = json!({"actors":actors,"mode":{"kind":"current_state"},"models":{
            "definitions":{"read":true,"create":true,"update_fields":["description","revision"],"rows":{"kind":"all"}},
            "contract_versions":{"read":true,"create":true,"update_fields":["template","template_revision"],"rows":{"kind":"all"}},
            "configuration_changes":{"read":true,"create":true,"rows":{"kind":"all"}}
        },"observations":["app.query.v1"]});
        read["observations"] = json!([]);
        let notification_policy = json!({"version":1,"admins":[OPERATOR],"operations":{
            "notifications.home":read,
            "notifications.get":get,
            "notifications.preview":{"actors":actors,"mode":{"kind":"read"},"models":{},"observations":["app.query.v1"]},
            "notifications.save":save
        }});
        let schema = delegation::schema_digest_for_artifact(&loaded, "app_ownership.check")?;
        let resources = json!({"version":1,"connections":{"ownership":{"revision":1,"provider":"local_delegation"}},"resources":{"ownership":{"revision":1,"connection":{"id":"ownership","revision":1},"target":{"kind":"app_operation","app":"app_ownership","operation":"app_ownership.check","schema_digest":schema}}},"policies":{"ownership":{"revision":1,"owner":OPERATOR,"actors":actors,"allowed_apps":["notifications"],"slots":{"ownership":{"kind":"app_operation","allowed_resources":[{"id":"ownership","revision":1}],"actions":["delegate_query"],"limits":{"max_request_bytes":16384,"max_response_bytes":65536,"max_calls_per_invocation":4},"budgets":[]}}}},"budgets":{}});
        let mut hosts = BTreeMap::new();
        for (app, path, policy) in [
            ("app_ownership", &ownership_artifact, ownership_policy),
            ("notifications", &notification_artifact, notification_policy),
        ] {
            let state = directory.path().join(app);
            fs::create_dir(&state)?;
            let instance_path = state.join("instance.json");
            let mut instance = json!({"installation":"alpha","environment":"production","apps":{app:{"artifact":path,"readers":actors,"writers":actors,"authority":policy}}});
            if app == "notifications" {
                instance["resources"] = resources.clone();
                let attachments: Vec<_> = ["notifications.get", "notifications.preview", "notifications.save"].into_iter().map(|operation| json!({"policy":{"id":"ownership","revision":1},"operation":operation,"bindings":{"ownership":{"id":"ownership","revision":1}}})).collect();
                instance["apps"][app]["resource_policies"] = json!(attachments);
            }
            fs::write(&instance_path, serde_json::to_vec(&instance)?)?;
            let runtime = Runtime::load(&instance_path, app)?;
            runtime.initialize()?;
            hosts.insert(app, runtime);
        }
        let ownership = hosts.remove("app_ownership").unwrap();
        let notifications = hosts.remove("notifications").unwrap();
        let release = Fixture::new_for_app(
            true,
            Some(&ownership.artifact().id().to_owned().try_into()?),
            "app_ownership",
        );
        release.until(ReleasePhase::Active, &mut 0);
        let target = release.provider.approval.target.clone();
        let source = ReleaseTarget {
            app: name("notifications"),
            ..target.clone()
        };
        let snapshot = directory.path().join("serving.json");
        fs::write(
            &snapshot,
            serde_json::to_vec(
                &Journal::open(&release.path)?.serving_snapshot(std::slice::from_ref(&target))?,
            )?,
        )?;
        let probe = Arc::new(release.serving_probe());
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("fixture key"))?;
        let signer = Signer::from_pkcs8("notification-key", key.as_ref())?;
        let verifier = || {
            Verifier::new(BTreeMap::from([(
                "notification-key".into(),
                TrustedKey {
                    source: Scope::from_runtime(&notifications).unwrap(),
                    public_key: signer.public_key(),
                },
            )]))
        };
        let issuer_key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("fixture issuer key"))?;
        let issuer_signer = IssuerSigner::from_pkcs8(
            "notification-issuer",
            "notification-issuer-key",
            issuer_key.as_ref(),
        )?;
        let issuer_verifier = IssuerVerifier::new(
            "notification-issuer",
            BTreeMap::from([("notification-issuer-key".into(), issuer_signer.public_key())]),
            "/projects/123/global/backendServices/target",
        )?;
        let iap = Arc::new(FixtureIap::new()?);
        let email = "notification@project.iam.gserviceaccount.com";
        let issuer = Arc::new(RemoteQueryIssuer::new(
            source.clone(),
            target.clone(),
            email,
            "/projects/123/global/backendServices/issuer",
            iap.verifier("/projects/123/global/backendServices/issuer", email)?,
            verifier()?,
            issuer_signer,
        )?);
        let receiver = Arc::new(RemoteQueryReceiver::new(
            snapshot.clone(),
            probe.clone(),
            target.clone(),
            ownership.clone(),
            verifier()?,
            issuer_verifier,
            iap.verifier("/projects/123/global/backendServices/target", email)?,
        )?);
        let receiver_server = QueryServer::start(
            ownership.clone(),
            target.clone(),
            BTreeMap::from([("notifications".into(), receiver)]),
            BTreeMap::new(),
            iap.clone(),
        )?;
        let at = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let port = RemoteQueryPort::loopback_fixture(
            snapshot,
            probe,
            source.clone(),
            target,
            &format!("{}/_platform/app-query", receiver_server.origin),
            RemoteQueryAuth {
                workload_signer: Signer::from_pkcs8("notification-key", key.as_ref())?,
                issuer: issuer.clone(),
                issuer_assertion: iap.assertion(
                    "/projects/123/global/backendServices/issuer",
                    email,
                    at,
                )?,
                target_assertion: iap.assertion(
                    "/projects/123/global/backendServices/target",
                    email,
                    at,
                )?,
            },
        )?;
        let caller = QueryServer::start(
            notifications.clone().with_app_call_port(Arc::new(port)),
            source,
            BTreeMap::new(),
            BTreeMap::from([("app_ownership".into(), issuer)]),
            iap.clone(),
        )?;
        Ok(Self {
            _directory: directory,
            _release: release,
            _receiver: receiver_server,
            caller,
            ownership,
            notifications,
            iap,
            client: reqwest::blocking::Client::new(),
            at,
        })
    }

    fn get(
        &self,
        origin: &str,
        path: &str,
        actor: &str,
    ) -> Result<reqwest::blocking::RequestBuilder> {
        Ok(self
            .client
            .get(format!("{origin}{path}"))
            .header("Host", "app.fixture.example")
            .header(
                iap::ASSERTION_HEADER,
                self.iap.assertion(
                    "/projects/123/global/backendServices/browser",
                    actor,
                    self.at,
                )?,
            ))
    }

    fn query(
        &self,
        operation: &str,
        actor: &str,
        input: &Value,
    ) -> Result<reqwest::blocking::Response> {
        let fields: Vec<_> = input
            .as_object()
            .context("query record")?
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    value
                        .as_str()
                        .map_or_else(|| value.to_string(), str::to_owned),
                )
            })
            .collect();
        self.get(
            &self.caller.origin,
            &format!("/api/notifications.{operation}"),
            actor,
        )?
        .query(&fields)
        .send()
        .map_err(Into::into)
    }

    fn post(
        &self,
        origin: &str,
        operation: &str,
        actor: &str,
        key: &str,
        input: &Value,
    ) -> Result<reqwest::blocking::Response> {
        let response = self.get(origin, "/api/session", actor)?.send()?;
        let cookie = response.headers()["set-cookie"]
            .to_str()?
            .split(';')
            .next()
            .context("cookie")?
            .to_owned();
        let session: Value = response.json()?;
        Ok(self
            .client
            .post(format!("{origin}/api/{operation}"))
            .header("Host", "app.fixture.example")
            .header(
                iap::ASSERTION_HEADER,
                self.iap.assertion(
                    "/projects/123/global/backendServices/browser",
                    actor,
                    self.at,
                )?,
            )
            .header("Cookie", cookie)
            .header("Origin", "https://app.fixture.example")
            .header(
                "X-CSRF-Token",
                session["csrf_token"].as_str().context("csrf")?,
            )
            .header("Idempotency-Key", key)
            .json(input)
            .send()?)
    }

    fn owner(&self, actor: &str, active: bool, key: &str) -> Result<()> {
        let response = self.post(
            &self._receiver.origin,
            "app_ownership.set_owner",
            OPERATOR,
            key,
            &json!({"app_id":"demo","principal":actor,"active":active}),
        )?;
        assert_eq!(response.status(), StatusCode::OK, "{}", response.text()?);
        Ok(())
    }

    fn counts(&self) -> Result<(i64, i64, i64)> {
        let connection = Connection::open(self.notifications.db())?;
        Ok((
            connection.query_row("SELECT count(*) FROM definitions", [], |row| row.get(0))?,
            connection.query_row("SELECT count(*) FROM contract_versions", [], |row| {
                row.get(0)
            })?,
            connection.query_row("SELECT count(*) FROM configuration_changes", [], |row| {
                row.get(0)
            })?,
        ))
    }
}

fn fields() -> Value {
    json!([{"name":"summary","kind":"text","max_length":1000,"choices":[]}])
}

fn page(items: Value) -> Value {
    json!({"items":items,"has_more":false,"next_after":""})
}

fn output_fields() -> Value {
    page(json!([{"name":"summary","kind":"text","max_length":1000,"choices":page(json!([]))}]))
}
fn save(revision: u64, version: u64, template: &str) -> Value {
    json!({"app_id":"demo","event_key":"build.completed","description":"A build completed.","expected_revision":revision,"version":version,"fields":fields(),"template":template})
}
fn preview(template: &str, text: &str) -> Value {
    json!({"app_id":"demo","fields":fields(),"template":template,"payload":[{"name":"summary","kind":"text","text":text,"integer":0,"boolean":false}]})
}

#[test]
fn notifications_ownership_configuration_and_preview_cross_native_http_hosts() -> Result<()> {
    let flow = Flow::new()?;
    assert_eq!(flow.counts()?, (0, 0, 0));
    assert!(
        !flow
            .query("preview", ALICE, &preview("Build: {{summary}}", "passed"))?
            .status()
            .is_success()
    );
    flow.owner(ALICE, true, "grant-alice")?;
    let check: Value = flow
        .get(
            &flow._receiver.origin,
            "/api/app_ownership.check?app_id=demo",
            BOB,
        )?
        .send()?
        .json()?;
    assert_eq!(check, json!({"app_id":"demo","allowed":false}));
    let denied_admin = flow.post(
        &flow._receiver.origin,
        "app_ownership.set_owner",
        ALICE,
        "self-grant",
        &json!({"app_id":"demo","principal":BOB,"active":true}),
    )?;
    assert!(!denied_admin.status().is_success());

    let input = save(0, 0, "Build: {{summary}}");
    let first = flow.post(
        &flow.caller.origin,
        "notifications.save",
        ALICE,
        "create",
        &input,
    )?;
    assert_eq!(first.status(), StatusCode::OK, "{}", first.text()?);
    let duplicate = flow.post(
        &flow.caller.origin,
        "notifications.save",
        ALICE,
        "create",
        &input,
    )?;
    assert_eq!(duplicate.status(), StatusCode::OK);
    assert_eq!(flow.counts()?, (1, 1, 1));
    assert_eq!(
        duplicate.json::<Value>()?,
        json!({"revision":1,"version":1})
    );
    let query = json!({"app_id":"demo","event_key":"build.completed","version":0});
    let current: Value = flow.query("get", ALICE, &query)?.json()?;
    assert_eq!(current["revision"], 1);
    assert_eq!(current["fields"], output_fields());
    assert_eq!(current["enabled"], false);
    assert!(!flow.query("get", BOB, &query)?.status().is_success());
    let rendered: Value = flow
        .query(
            "preview",
            ALICE,
            &preview("Build: {{summary}}", "{{summary}} <script>"),
        )?
        .json()?;
    assert_eq!(
        rendered,
        json!({"valid":true,"message":"Build: {{summary}} <script>","findings":page(json!([]))})
    );

    let stale = flow.post(
        &flow.caller.origin,
        "notifications.save",
        ALICE,
        "stale",
        &save(0, 1, "Changed"),
    )?;
    assert!(!stale.status().is_success());
    let mut schema_change = save(1, 1, "Changed");
    schema_change["fields"][0]["max_length"] = json!(999);
    assert!(
        !flow
            .post(
                &flow.caller.origin,
                "notifications.save",
                ALICE,
                "schema-change",
                &schema_change
            )?
            .status()
            .is_success()
    );
    assert_eq!(
        flow.counts()?,
        (1, 1, 1),
        "refusals must roll back every row write"
    );
    assert_eq!(
        flow.post(
            &flow.caller.origin,
            "notifications.save",
            ALICE,
            "edit",
            &save(1, 1, "Result: {{summary}}")
        )?
        .json::<Value>()?,
        json!({"revision":2,"version":1})
    );
    assert_eq!(
        flow.post(
            &flow.caller.origin,
            "notifications.save",
            ALICE,
            "new-version",
            &save(2, 0, "New: {{summary}}")
        )?
        .json::<Value>()?,
        json!({"revision":3,"version":2})
    );
    assert_eq!(flow.counts()?, (1, 2, 3));
    let old: Value = flow
        .query(
            "get",
            ALICE,
            &json!({"app_id":"demo","event_key":"build.completed","version":1}),
        )?
        .json()?;
    assert_eq!(old["template"], "Result: {{summary}}");
    assert_eq!(old["template_revision"], 2);

    flow.owner(ALICE, false, "revoke-alice")?;
    for (operation, input) in [
        ("get", query.clone()),
        ("preview", preview("{{summary}}", "private")),
    ] {
        assert!(
            !flow.query(operation, ALICE, &input)?.status().is_success(),
            "ownership must be fresh for {operation}"
        );
    }
    assert!(
        !flow
            .post(
                &flow.caller.origin,
                "notifications.save",
                ALICE,
                "revoked-edit",
                &save(3, 1, "Denied")
            )?
            .status()
            .is_success()
    );
    assert_eq!(flow.counts()?, (1, 2, 3));
    flow.owner(BOB, true, "grant-bob")?;
    assert_eq!(
        flow.query("get", BOB, &query)?.json::<Value>()?["revision"],
        3
    );
    assert_eq!(
        flow.post(
            &flow.caller.origin,
            "notifications.save",
            BOB,
            "bob-edit",
            &save(3, 2, "Bob: {{summary}}")
        )?
        .json::<Value>()?,
        json!({"revision":4,"version":2})
    );
    let connection = Connection::open(flow.notifications.db())?;
    let actors: Vec<String> = connection
        .prepare("SELECT actor FROM configuration_changes ORDER BY revision")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    assert_eq!(actors, [ALICE, ALICE, ALICE, BOB]);
    let owner_rows: i64 = Connection::open(flow.ownership.db())?.query_row(
        "SELECT count(*) FROM ownerships",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(owner_rows, 2, "grant/revoke retain unique assignments");
    Ok(())
}

#[test]
fn notifications_preview_matches_domain_bounds_and_fails_closed() -> Result<()> {
    let flow = Flow::new()?;
    flow.owner(ALICE, true, "grant")?;
    let mut cases = vec![
        (preview("{{unknown}}", "hello"), "unknown_placeholder"),
        (preview("{{summary}", "hello"), "invalid_placeholder"),
        (preview("x}}", "hello"), "invalid_placeholder"),
        (preview("{{summary}}", &"😀".repeat(501)), "too_long"),
        (
            preview(&"{{summary}}".repeat(4), &"x".repeat(1000)),
            "rendered_message_too_long",
        ),
    ];
    let mut missing = preview("{{summary}}", "x");
    missing["payload"] = json!([]);
    cases.push((missing, "required"));
    let mut duplicate = preview("{{summary}}", "x");
    let repeated = duplicate["payload"][0].clone();
    duplicate["payload"].as_array_mut().unwrap().push(repeated);
    cases.push((duplicate, "duplicate_field"));
    let mut wrong = preview("{{summary}}", "x");
    wrong["payload"][0]["kind"] = json!("integer");
    cases.push((wrong, "wrong_type"));
    for (input, code) in cases {
        let response = flow.query("preview", ALICE, &input)?;
        assert_eq!(response.status(), StatusCode::OK);
        let output: Value = response.json()?;
        assert_eq!(output["valid"], false, "{input}");
        assert_eq!(output["message"], "");
        assert!(
            output["findings"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["code"] == code),
            "{output}"
        );
    }
    let mut spoof = preview("{{summary}}", "x");
    spoof["actor"] = json!(OPERATOR);
    assert_eq!(
        flow.query("preview", ALICE, &spoof)?.status(),
        StatusCode::BAD_REQUEST
    );
    let mut wrong_app = preview("{{summary}}", "x");
    wrong_app["app_id"] = json!("other");
    assert!(
        !flow
            .query("preview", ALICE, &wrong_app)?
            .status()
            .is_success()
    );
    assert_eq!(flow.counts()?, (0, 0, 0));
    let typed = json!({"app_id":"demo","fields":[
        {"name":"count","kind":"integer","max_length":0,"choices":[]},
        {"name":"ready","kind":"boolean","max_length":0,"choices":[]},
        {"name":"state","kind":"enum","max_length":0,"choices":["passed","failed"]}
    ],"template":"{{count}} {{ready}} {{state}}","payload":[
        {"name":"count","kind":"integer","text":"","integer":-7,"boolean":false},
        {"name":"ready","kind":"boolean","text":"","integer":0,"boolean":true},
        {"name":"state","kind":"text","text":"passed","integer":0,"boolean":false}
    ]});
    let output: Value = flow.query("preview", ALICE, &typed)?.json()?;
    assert_eq!(
        output,
        json!({"valid":true,"message":"-7 true passed","findings":page(json!([]))})
    );
    let mut invalid_enum = typed.clone();
    invalid_enum["payload"][2]["text"] = json!("unknown");
    let invalid: Value = flow.query("preview", ALICE, &invalid_enum)?.json()?;
    assert_eq!(
        invalid["findings"],
        page(json!([{"field":"state","code":"invalid_enum_choice"}]))
    );
    let boundary: Value = flow
        .query("preview", ALICE, &preview("{{summary}}", &"😀".repeat(500)))?
        .json()?;
    assert_eq!(boundary["valid"], true);
    assert_eq!(boundary["message"], "😀".repeat(500));
    Ok(())
}

#[test]
fn unavailable_ownership_never_reads_or_changes_notification_configuration() -> Result<()> {
    let mut flow = Flow::new()?;
    flow.owner(ALICE, true, "grant")?;
    assert_eq!(
        flow.post(
            &flow.caller.origin,
            "notifications.save",
            ALICE,
            "create",
            &save(0, 0, "{{summary}}")
        )?
        .status(),
        StatusCode::OK
    );
    if let Some(stop) = flow._receiver.stop.take() {
        let _ = stop.send(());
    }
    if let Some(thread) = flow._receiver.thread.take() {
        thread.join().expect("ownership receiver thread")?;
    }
    let before = flow.counts()?;
    assert!(
        !flow
            .query(
                "get",
                ALICE,
                &json!({"app_id":"demo","event_key":"build.completed","version":0})
            )?
            .status()
            .is_success()
    );
    assert!(
        !flow
            .query("preview", ALICE, &preview("{{summary}}", "private"))?
            .status()
            .is_success()
    );
    assert!(
        !flow
            .post(
                &flow.caller.origin,
                "notifications.save",
                ALICE,
                "unavailable",
                &save(1, 1, "No write")
            )?
            .status()
            .is_success()
    );
    assert_eq!(flow.counts()?, before);
    Ok(())
}
