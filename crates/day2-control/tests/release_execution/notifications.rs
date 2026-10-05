//! Source-backed Notifications business flow across two native HTTP hosts.
//! IAP and provider observations are explicit fixtures; the Roc apps, codecs,
//! SQLite transactions, imported grant, signatures and release fence are real.
use super::*;
use day2::integrations::simulated::{
    self, OpenAiWorld, SimulatedFixture, SlackChannelWorld, SlackWorld, SnowflakeWorld,
};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const OPERATOR: &str = "operator@example.com";

struct Flow {
    _receiver: QueryServer,
    caller: QueryServer,
    _release: Fixture,
    ownership: Runtime,
    notifications: Runtime,
    iap: Arc<FixtureIap>,
    client: reqwest::blocking::Client,
    at: i64,
    // Server threads and their release probe must stop before state is removed.
    _directory: tempfile::TempDir,
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
                if runtime.app() == "notifications" {
                    let source = runtime.db().with_file_name(simulated::SLACK_WORLD);
                    let provider = state.join("slack-fixture.sqlite");
                    Connection::open(source)?.execute(
                        "VACUUM INTO ?1",
                        [provider.to_str().context("provider evidence")?],
                    )?;
                    fs::set_permissions(provider, fs::Permissions::from_mode(0o600))?;
                }
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
            "notifications.preview":{"actors":actors,"mode":{"kind":"current_state"},"models":{},"observations":["app.query.v1"]},
            "notifications.save":save,
            "notifications.set_enabled":{"actors":actors,"mode":{"kind":"current_state"},"models":{
                "definitions":{"read":true,"update_fields":["enabled","revision"],"rows":{"kind":"all"}},
                "configuration_changes":{"read":true,"create":true,"rows":{"kind":"all"}}
            },"observations":["app.query.v1"],"effects":["slack.post.v1"]},
            "notifications.publish":{"actors":actors,"mode":{"kind":"current_state"},"models":{
                "definitions":{"read":true,"rows":{"kind":"all"}},
                "contract_versions":{"read":true,"rows":{"kind":"all"}},
                "publications":{"read":true,"create":true,"update_fields":["slack_accepted","channel","timestamp"],"rows":{"kind":"all"}}
            },"observations":["app.query.v1"],"effects":["slack.post.v1"]},
            "notifications.publication":{"actors":actors,"mode":{"kind":"read"},"models":{
                "publications":{"read":true,"rows":{"kind":"all"}}
            },"observations":["app.query.v1"]}
        }});
        let schema = delegation::schema_digest_for_artifact(&loaded, "app_ownership.check")?;
        let mut resources = json!({"version":1,"connections":{"ownership":{"revision":1,"provider":"local_delegation"}},"resources":{"ownership":{"revision":1,"connection":{"id":"ownership","revision":1},"target":{"kind":"app_operation","app":"app_ownership","operation":"app_ownership.check","schema_digest":schema}}},"policies":{"ownership":{"revision":1,"owner":OPERATOR,"actors":actors,"allowed_apps":["notifications"],"slots":{"ownership":{"kind":"app_operation","allowed_resources":[{"id":"ownership","revision":1}],"actions":["delegate_query"],"limits":{"max_request_bytes":16384,"max_response_bytes":65536,"max_calls_per_invocation":4},"budgets":[]}}}},"budgets":{}});
        resources["connections"]["slack"] = json!({"revision":1,"provider":"slack","live":{"provider":"slack","credential_ref":{"id":"day2-bot","revision":1},"workspace_id":"T123","signing_secret_ref":null}});
        resources["resources"]["channel"] = json!({"revision":1,"connection":{"id":"slack","revision":1},"target":{"kind":"slack_channel","channel":{"channel_id":"C123"}}});
        resources["policies"]["channel"] = json!({"revision":1,"owner":OPERATOR,"actors":actors,"allowed_apps":["notifications"],"slots":{"notification_channel":{"kind":"slack_channel","allowed_resources":[{"id":"channel","revision":1}],"actions":["slack_post"],"limits":{"max_request_bytes":16384,"max_response_bytes":16384,"max_calls_per_invocation":2},"budgets":[{"id":"slack-daily","revision":1}]}}});
        resources["budgets"]["slack-daily"] = json!({"revision":1,"scope":"app","period_seconds":86400,"limits":{"calls":200,"bytes":2000000,"cost_microunits":null,"concurrency":2}});
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
                let mut attachments: Vec<_> = ["notifications.get", "notifications.preview", "notifications.save", "notifications.set_enabled", "notifications.publish", "notifications.publication"].into_iter().map(|operation| json!({"policy":{"id":"ownership","revision":1},"operation":operation,"bindings":{"ownership":{"id":"ownership","revision":1}}})).collect();
                attachments.extend(["notifications.set_enabled", "notifications.publish"].into_iter().map(|operation| json!({"policy":{"id":"channel","revision":1},"operation":operation,"bindings":{"notification_channel":{"id":"channel","revision":1}}})));
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
        let providers = SimulatedFixture {
            slack: SlackWorld {
                workspace_id: "T123".into(),
                channels: BTreeMap::from([("C123".into(), SlackChannelWorld::default())]),
                sequence: 0,
            },
            snowflake: SnowflakeWorld {
                account: "offline".into(),
                ..Default::default()
            },
            openai: OpenAiWorld {
                project_id: "offline".into(),
                model: "offline".into(),
                max_input_tokens: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        simulated::seed(notifications.db(), notifications.scope(), &providers)?;
        let simulation = day2::simulation::Simulation::with_remote_app_calls(
            notifications.with_app_call_port(Arc::new(port)),
            [7; 32],
            at * 1000,
        )?;
        let notifications = simulation.runtime().clone();
        let caller = QueryServer::start(
            notifications.clone(),
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

    fn preview(&self, actor: &str, input: &Value) -> Result<reqwest::blocking::Response> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let key = format!(
            "preview-{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        self.post(
            &self.caller.origin,
            "notifications.preview",
            actor,
            &key,
            input,
        )
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

    fn finish(&self, response: reqwest::blocking::Response) -> Result<Value> {
        let status = response.status();
        let mut body: Value = response.json()?;
        ensure!(
            status == StatusCode::OK || status == StatusCode::ACCEPTED,
            "command response {status}: {body}"
        );
        if status == StatusCode::OK {
            return Ok(body);
        }
        let url = body["status_url"]
            .as_str()
            .context("command status URL")?
            .to_owned();
        for _ in 0..200 {
            let response = self.get(&self.caller.origin, &url, ALICE)?.send()?;
            ensure!(response.status() == StatusCode::OK, "status authorization");
            body = response.json()?;
            if body["status"] != "pending" {
                return Ok(body);
            }
            thread::sleep(Duration::from_millis(25));
        }
        anyhow::bail!("command did not settle: {body}")
    }

    fn configure_enabled(&self) -> Result<()> {
        self.owner(ALICE, true, "grant")?;
        assert_eq!(
            self.post(
                &self.caller.origin,
                "notifications.save",
                ALICE,
                "configure",
                &save(0, 0, "Build: {{summary}}")
            )?
            .status(),
            StatusCode::OK
        );
        assert_eq!(self.post(&self.caller.origin, "notifications.set_enabled", ALICE, "enable", &json!({"app_id":"demo","event_key":"build.completed","expected_revision":1,"enabled":true}))?.json::<Value>()?, json!({"revision":2,"enabled":true}));
        Ok(())
    }

    fn successful(&self, response: reqwest::blocking::Response) -> Result<Value> {
        let outcome = self.finish(response)?;
        if let Some(status) = outcome.get("status") {
            ensure!(status == "success", "command failed: {outcome}");
            return Ok(outcome["result"].clone());
        }
        Ok(outcome)
    }

    fn slack(&self) -> Result<simulated::World<SlackWorld>> {
        simulated::update_slack(
            self.notifications.db(),
            self.notifications.scope(),
            |state| Ok(state.clone()),
        )
    }

    fn publication_count(&self) -> Result<i64> {
        Ok(Connection::open(self.notifications.db())?.query_row(
            "SELECT count(*) FROM publications",
            [],
            |row| row.get(0),
        )?)
    }
}

fn publication(id: &str, text: &str) -> Value {
    json!({"app_id":"demo","event_key":"build.completed","version":1,"publication_id":id,"payload":[{"name":"summary","kind":"text","text":text,"integer":0,"boolean":false}]})
}

#[test]
fn notifications_publication_snapshots_version_and_deduplicates_before_disable() -> Result<()> {
    let flow = Flow::new()?;
    flow.configure_enabled()?;
    // A later contract exists, but publishing v1 must use v1's template.
    assert_eq!(
        flow.post(
            &flow.caller.origin,
            "notifications.save",
            ALICE,
            "v2",
            &save(2, 0, "New: {{summary}}")
        )?
        .json::<Value>()?,
        json!({"revision":3,"version":2})
    );
    let input = publication("build-1", "passed <@U123> & {{summary}}");
    let first = flow.successful(flow.post(
        &flow.caller.origin,
        "notifications.publish",
        ALICE,
        "publish-1",
        &input,
    )?)?;
    assert_eq!(first["slack_accepted"], true);
    assert_eq!(first["duplicate"], false);
    assert_eq!(first["channel"], "C123");
    let world = flow.slack()?;
    assert_eq!(world.world.channels["C123"].messages.len(), 1);
    assert_eq!(
        world.world.channels["C123"].messages[0].text,
        "Build: passed &lt;@U123&gt; &amp; {{summary}}"
    );
    assert_eq!(world.calls, vec!["auth.test", "chat.postMessage"]);
    let state = flow.notifications.inspect()?;
    let snapshot: Value = serde_json::from_str(
        state["publications"][0]["data"]
            .as_str()
            .context("publication snapshot")?,
    )?;
    assert_eq!(snapshot["latest_version"], 2);
    assert_eq!(snapshot["template_revision"], 1);
    assert_eq!(snapshot["message"], "Build: passed <@U123> & {{summary}}");
    assert_eq!(snapshot["actor"], ALICE);
    assert_eq!(flow.post(&flow.caller.origin,"notifications.set_enabled",ALICE,"disable",&json!({"app_id":"demo","event_key":"build.completed","expected_revision":3,"enabled":false}))?.status(),StatusCode::OK);
    let duplicate = flow.successful(flow.post(
        &flow.caller.origin,
        "notifications.publish",
        ALICE,
        "fresh-transport-key",
        &input,
    )?)?;
    assert_eq!(duplicate["notification_id"], first["notification_id"]);
    assert_eq!(duplicate["status_url"], first["status_url"]);
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(duplicate["slack_accepted"], true);
    assert_eq!(
        flow.slack()?,
        world,
        "duplicates must not contact Slack at all"
    );
    assert_eq!(flow.publication_count()?, 1);
    let changed = flow.post(
        &flow.caller.origin,
        "notifications.publish",
        ALICE,
        "conflict",
        &publication("build-1", "changed"),
    )?;
    assert_eq!(changed.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        changed.json::<Value>()?["error"]["code"],
        "app:notifications.publication_conflict"
    );
    assert_eq!(
        flow.post(
            &flow.caller.origin,
            "notifications.publish",
            ALICE,
            "disabled",
            &publication("build-2", "passed")
        )?
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(flow.publication_count()?, 1);
    assert_eq!(flow.slack()?, world);
    assert_eq!(
        flow.query(
            "publication",
            ALICE,
            &json!({"app_id":"demo","publication_id":"build-1"})
        )?
        .json::<Value>()?,
        duplicate
    );
    flow.owner(ALICE, false, "revoke")?;
    assert!(
        !flow
            .query(
                "publication",
                ALICE,
                &json!({"app_id":"demo","publication_id":"build-1"})
            )?
            .status()
            .is_success()
    );
    assert!(
        !flow
            .post(
                &flow.caller.origin,
                "notifications.publish",
                ALICE,
                "revoked",
                &input
            )?
            .status()
            .is_success()
    );
    assert_eq!(flow.slack()?, world);
    Ok(())
}

#[test]
fn notification_provider_uncertainty_never_resends_a_retained_publication() -> Result<()> {
    let flow = Flow::new()?;
    flow.configure_enabled()?;
    simulated::schedule_faults(
        flow.notifications.db(),
        flow.notifications.scope(),
        simulated::SLACK_WORLD,
        vec![simulated::ScheduledFault {
            endpoint: "chat.postMessage".into(),
            remaining: 1,
            fault: simulated::SimulatedFault::ConnectionLost,
        }],
    )?;
    let input = publication("uncertain-1", "passed");
    let response = flow.post(
        &flow.caller.origin,
        "notifications.publish",
        ALICE,
        "uncertain",
        &input,
    )?;
    let outcome = flow.finish(response)?;
    assert_ne!(outcome["status"], "success");
    assert_eq!(outcome["error"], "integration_transport_unavailable");
    let world = flow.slack()?;
    assert_eq!(world.calls, vec!["auth.test", "chat.postMessage"]);
    let duplicate = flow.successful(flow.post(
        &flow.caller.origin,
        "notifications.publish",
        ALICE,
        "different-key",
        &input,
    )?)?;
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(duplicate["slack_accepted"], false);
    assert_eq!(duplicate["channel"], "");
    assert_eq!(flow.slack()?, world);
    assert_eq!(flow.publication_count()?, 1);
    // Reopened runtime sees the same durable failed/uncertain command receipt.
    let reopened = Runtime::load(flow.notifications.instance_path(), "notifications")?;
    let id = duplicate["status_url"]
        .as_str()
        .context("status URL")?
        .trim_start_matches("/api/invocations/");
    let receipt = day2::invocations::status(&reopened, id, ALICE)?;
    assert_eq!(receipt.error, "integration_transport_unavailable");
    assert!(day2::invocations::status(&reopened, id, BOB).is_err());
    assert_eq!(
        reopened.execute(id, day2::store::Fault::None)?.error,
        receipt.error
    );
    assert_eq!(flow.slack()?, world);
    Ok(())
}

#[test]
fn invalid_and_unauthorized_publications_never_reach_slack() -> Result<()> {
    let flow = Flow::new()?;
    flow.configure_enabled()?;
    let before = flow.slack()?;
    assert!(
        !flow
            .post(
                &flow.caller.origin,
                "notifications.publish",
                BOB,
                "denied",
                &publication("bob", "passed")
            )?
            .status()
            .is_success()
    );
    let mut cases = vec![
        publication("", "passed"),
        publication("long", &"x".repeat(1001)),
    ];
    let mut unknown = publication("unknown-version", "passed");
    unknown["version"] = json!(99);
    cases.push(unknown);
    let mut wrong = publication("wrong-type", "passed");
    wrong["payload"][0]["kind"] = json!("integer");
    cases.push(wrong);
    let mut repeated = publication("duplicate-field", "passed");
    repeated["payload"] = json!([
        repeated["payload"][0].clone(),
        repeated["payload"][0].clone()
    ]);
    cases.push(repeated);
    for (index, input) in cases.into_iter().enumerate() {
        assert_eq!(
            flow.post(
                &flow.caller.origin,
                "notifications.publish",
                ALICE,
                &format!("invalid-{index}"),
                &input
            )?
            .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let mut forged = publication("forged", "passed");
    forged["actor"] = json!(ALICE);
    assert_eq!(
        flow.post(
            &flow.caller.origin,
            "notifications.publish",
            BOB,
            "forged",
            &forged
        )?
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(flow.publication_count()?, 0);
    assert_eq!(flow.slack()?, before);
    Ok(())
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
            .preview(ALICE, &preview("Build: {{summary}}", "passed"))?
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
        .preview(
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
        let response = if operation == "preview" {
            flow.preview(ALICE, &input)?
        } else {
            flow.query(operation, ALICE, &input)?
        };
        assert!(
            !response.status().is_success(),
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
        let response = flow.preview(ALICE, &input)?;
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
        flow.preview(ALICE, &spoof)?.status(),
        StatusCode::BAD_REQUEST
    );
    let mut wrong_app = preview("{{summary}}", "x");
    wrong_app["app_id"] = json!("other");
    assert!(!flow.preview(ALICE, &wrong_app)?.status().is_success());
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
    let output: Value = flow.preview(ALICE, &typed)?.json()?;
    assert_eq!(
        output,
        json!({"valid":true,"message":"-7 true passed","findings":page(json!([]))})
    );
    let mut invalid_enum = typed.clone();
    invalid_enum["payload"][2]["text"] = json!("unknown");
    let invalid: Value = flow.preview(ALICE, &invalid_enum)?.json()?;
    assert_eq!(
        invalid["findings"],
        page(json!([{"field":"state","code":"invalid_enum_choice"}]))
    );
    let boundary: Value = flow
        .preview(ALICE, &preview("{{summary}}", &"😀".repeat(500)))?
        .json()?;
    assert_eq!(boundary["valid"], true);
    assert_eq!(boundary["message"], "😀".repeat(500));
    Ok(())
}

#[test]
fn maximum_notification_schema_returns_every_field_and_choice() -> Result<()> {
    let flow = Flow::new()?;
    flow.owner(ALICE, true, "grant")?;
    let choices: Vec<_> = (0..50).map(|index| format!("choice_{index:02}")).collect();
    let schema: Vec<_> = (0..20)
        .map(|index| json!({"name":format!("f{index}"),"kind":"enum","max_length":0,"choices":choices}))
        .collect();
    let mut input = save(0, 0, "{{f0}}");
    input["fields"] = json!(schema);
    let saved = flow.post(
        &flow.caller.origin,
        "notifications.save",
        ALICE,
        "maximum",
        &input,
    )?;
    assert_eq!(saved.status(), StatusCode::OK, "{}", saved.text()?);
    let response = flow.query(
        "get",
        ALICE,
        &json!({"app_id":"demo","event_key":"build.completed","version":1}),
    )?;
    assert_eq!(response.status(), StatusCode::OK, "{}", response.text()?);
    let output: Value = response.json()?;
    assert_eq!(output["fields"]["has_more"], false);
    assert_eq!(output["fields"]["next_after"], "");
    let returned = output["fields"]["items"]
        .as_array()
        .context("complete schema")?;
    assert_eq!(returned.len(), 20);
    for (index, field) in returned.iter().enumerate() {
        assert_eq!(field["name"], format!("f{index}"));
        assert_eq!(field["choices"], page(json!(choices)));
    }
    let payload: Vec<_> = (0..20)
        .map(|index| json!({"name":format!("f{index}"),"kind":"text","text":"choice_00","integer":0,"boolean":false}))
        .collect();
    let preview = json!({"app_id":"demo","fields":schema,"template":"{{f0}}","payload":payload});
    let rendered: Value = flow.preview(ALICE, &preview)?.json()?;
    assert_eq!(
        rendered,
        json!({"valid":true,"message":"choice_00","findings":page(json!([]))})
    );
    input["expected_revision"] = json!(1);
    input["fields"][0]["choices"]
        .as_array_mut()
        .unwrap()
        .push(json!("one_too_many"));
    let refused = flow.post(
        &flow.caller.origin,
        "notifications.save",
        ALICE,
        "oversized",
        &input,
    )?;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(flow.counts()?, (1, 1, 1));
    let long_choices: Vec<_> = (0..50)
        .map(|index| format!("{}_{index:02}", "x".repeat(20)))
        .collect();
    let long_schema: Vec<_> = (0..20)
        .map(|index| json!({"name":format!("f{index}"),"kind":"enum","max_length":0,"choices":long_choices}))
        .collect();
    input["fields"] = json!(long_schema);
    let refused = flow.post(
        &flow.caller.origin,
        "notifications.save",
        ALICE,
        "schema_bytes",
        &input,
    )?;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let long_payload: Vec<_> = (0..20)
        .map(|index| json!({"name":format!("f{index}"),"kind":"text","text":long_choices[0],"integer":0,"boolean":false}))
        .collect();
    let rendered: Value = flow.preview(ALICE, &json!({"app_id":"demo","fields":long_schema,"template":"{{f0}}","payload":long_payload}))?.json()?;
    assert_eq!(
        rendered,
        json!({"valid":true,"message":long_choices[0],"findings":page(json!([]))})
    );
    assert_eq!(flow.counts()?, (1, 1, 1));
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
            .preview(ALICE, &preview("{{summary}}", "private"))?
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
