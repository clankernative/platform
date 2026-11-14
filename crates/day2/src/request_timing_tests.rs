use super::*;
use anyhow::{Context, Result};

fn capture() -> (Output, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    (Output::Capture(lines.clone()), lines)
}

fn lines(captured: &Arc<Mutex<Vec<String>>>) -> Vec<Value> {
    captured
        .lock()
        .unwrap()
        .iter()
        .map(|line| serde_json::from_str(line).expect("each line is one JSON object"))
        .collect()
}

fn phases<'a>(line: &'a Value, name: &str) -> Vec<&'a Value> {
    line["phases"]
        .as_array()
        .expect("phases array")
        .iter()
        .filter(|phase| phase["phase"] == name)
        .collect()
}

fn duration(value: &Value) -> f64 {
    value.as_f64().expect("a duration in milliseconds")
}

/// The shape web.rs gives a page with two preparation commands before its
/// read query: the same calls, without an app or a network.
fn page_request(output: Output) -> Recorder {
    let recorder = Recorder::request(output, now());
    let _handler = recorder.handler();
    recorder.attribute("method", json!("GET"));
    recorder.attribute("category", json!("page"));
    drop(recorder.span("admission"));
    drop(recorder.span("body_read"));
    {
        let _entered = recorder.enter();
        drop(span("authenticate"));
        route("launcher_refresh");
        for (operation, endpoints) in [
            (
                "resolve_membership",
                &["metadata_token", "iam_token", "directory_user"][..],
            ),
            ("refresh_directory", &["directory_orgunits"][..]),
        ] {
            let mut command = invocation("preparation", operation);
            command.identifier("invocation", "page-prepare-0-abc");
            {
                let _read = sql_read();
            }
            let wait = writer_wait();
            let hold = {
                let mut wait = wait;
                wait.turned();
                wait.began()
            };
            {
                let _exchange = worker_exchange();
                let mut observe = span("observe");
                observe.name("capability", "WorkspaceDirectory.userPath");
                for endpoint in endpoints {
                    let mut call = provider("workspace_directory", endpoint);
                    call.status(200);
                }
            }
            let mut trace = trace_write();
            trace.bytes(78_000);
            drop(trace);
            drop(hold);
            command.result("success");
        }
        {
            let mut query = invocation("page_query", "launcher");
            query.result("success");
        }
        drop(span("render"));
    }
    recorder.respond(200, "complete");
    recorder
}

#[test]
fn a_request_writes_exactly_one_well_formed_line_with_its_phases() -> Result<()> {
    let (output, captured) = capture();
    let recorder = page_request(output);
    assert!(
        captured.lock().unwrap().is_empty(),
        "nothing is written while the request is still held"
    );
    drop(recorder);
    let written = lines(&captured);
    assert_eq!(written.len(), 1, "exactly one line per request");
    let line = &written[0];
    assert_eq!(line["event"], "day2_request");
    assert_eq!(line["severity"], "INFO");
    assert_eq!(line["method"], "GET");
    assert_eq!(line["category"], "page");
    assert_eq!(line["route"], "launcher_refresh");
    assert_eq!(line["status"], 200);
    assert_eq!(line["outcome"], "complete");
    assert!(line["error"].is_null());
    assert!(line["request"].as_u64().is_some());
    let total = duration(&line["total_ms"]);
    for name in [
        "admission",
        "body_read",
        "authenticate",
        "page_query",
        "render",
    ] {
        let found = phases(line, name);
        assert_eq!(found.len(), 1, "{name} phase");
        assert!(duration(&found[0]["ms"]) <= total);
        assert!(duration(&found[0]["at_ms"]) <= total);
    }
    // Phases are listed in the order they started.
    let starts: Vec<f64> = line["phases"]
        .as_array()
        .context("phases")?
        .iter()
        .map(|phase| duration(&phase["at_ms"]))
        .collect();
    assert!(starts.windows(2).all(|pair| pair[0] <= pair[1]));
    let totals = &line["totals"];
    for key in [
        "sql_reads",
        "sql_read_ms",
        "sql_writes",
        "writer_turns",
        "writer_wait_ms",
        "writer_wait_max_ms",
        "writer_begin_ms",
        "writer_hold_ms",
        "worker_exchanges",
        "worker_exchange_ms",
        "trace_writes",
        "trace_bytes",
        "provider_calls",
        "provider_ms",
    ] {
        assert!(
            totals.get(key).is_some(),
            "request totals always carry {key}"
        );
    }
    assert_eq!(totals["trace_writes"], 2);
    assert_eq!(totals["trace_bytes"], 156_000);
    assert_eq!(totals["writer_turns"], 2);
    assert_eq!(totals["provider_calls"], 4);
    Ok(())
}

#[test]
fn preparation_commands_and_provider_calls_carry_names_statuses_and_durations() -> Result<()> {
    let (output, captured) = capture();
    drop(page_request(output));
    let line = &lines(&captured)[0];
    let commands = phases(line, "preparation");
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0]["operation"], "resolve_membership");
    assert_eq!(commands[1]["operation"], "refresh_directory");
    for command in &commands {
        assert_eq!(command["result"], "success");
        assert_eq!(command["invocation"], "page-prepare-0-abc");
        assert!(duration(&command["ms"]) >= 0.0);
        // Each command carries what it spent inside it.
        assert_eq!(command["totals"]["trace_writes"], 1);
        assert_eq!(command["totals"]["trace_bytes"], 78_000);
        assert_eq!(command["totals"]["writer_turns"], 1);
        assert_eq!(command["totals"]["worker_exchanges"], 1);
        assert!(command["totals"].get("worker_starts").is_none());
    }
    assert_eq!(commands[0]["totals"]["provider_calls"], 3);
    assert_eq!(commands[1]["totals"]["provider_calls"], 1);
    let calls = phases(line, "provider");
    let endpoints: Vec<_> = calls
        .iter()
        .map(|call| {
            (
                call["capability"].as_str().unwrap(),
                call["endpoint"].as_str().unwrap(),
                call["status"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        endpoints,
        [
            ("workspace_directory", "metadata_token", 200),
            ("workspace_directory", "iam_token", 200),
            ("workspace_directory", "directory_user", 200),
            ("workspace_directory", "directory_orgunits", 200),
        ]
    );
    for call in calls {
        assert!(duration(&call["ms"]) >= 0.0);
    }
    assert_eq!(
        phases(line, "observe")[0]["capability"],
        "WorkspaceDirectory.userPath"
    );
    assert_eq!(phases(line, "page_query")[0]["operation"], "launcher");
    Ok(())
}

#[test]
fn an_aborted_request_still_logs_once_with_the_phase_it_reached() -> Result<()> {
    let (output, captured) = capture();
    let recorder = Recorder::request(output, now());
    let handler = recorder.handler();
    // A blocking dispatch keeps its own clone after its caller is gone.
    let dispatch = recorder.clone();
    drop(recorder.span("admission"));
    let entered = dispatch.enter();
    let command = invocation("preparation", "refresh_directory");
    // The client disconnects: the async handler is dropped mid-command.
    drop(handler);
    drop(recorder);
    assert!(
        captured.lock().unwrap().is_empty(),
        "the line waits for the dispatch that is still running"
    );
    {
        let mut call = provider("workspace_directory", "directory_orgunits");
        call.status(200);
    }
    drop(command);
    drop(entered);
    drop(dispatch);
    let written = lines(&captured);
    assert_eq!(written.len(), 1);
    let line = &written[0];
    assert_eq!(line["outcome"], "aborted");
    assert_eq!(line["severity"], "WARNING");
    assert_eq!(line["aborted_in"], "preparation");
    assert!(line["status"].is_null());
    assert!(duration(&line["aborted_at_ms"]) <= duration(&line["total_ms"]));
    // Work that finished after the abort is still attributed.
    assert_eq!(phases(line, "preparation").len(), 1);
    assert_eq!(phases(line, "provider")[0]["status"], 200);
    Ok(())
}

#[test]
fn transport_delivery_and_timeouts_are_reported() -> Result<()> {
    let (output, captured) = capture();
    let started = now();
    let delivered = Recorder::request(output.clone(), started);
    delivered.completed("accept_wait", started, now());
    delivered.respond(200, "complete");
    delivered.delivered("delivered");
    drop(delivered);
    // The connection timed out before the handler answered.
    let timed_out = Recorder::request(output.clone(), now());
    let handler = timed_out.handler();
    drop(timed_out.span("admission"));
    drop(handler);
    timed_out.delivered("connection_timeout");
    drop(timed_out);
    // Busy refusals answer without running anything.
    let busy = Recorder::request(output, now());
    busy.respond(503, "busy");
    busy.respond(503, "complete");
    drop(busy);
    let written = lines(&captured);
    assert_eq!(written.len(), 3);
    assert_eq!(written[0]["delivery"], "delivered");
    assert_eq!(written[0]["outcome"], "complete");
    assert_eq!(phases(&written[0], "accept_wait").len(), 1);
    assert_eq!(phases(&written[0], "respond").len(), 1);
    assert_eq!(written[1]["delivery"], "connection_timeout");
    assert_eq!(written[1]["outcome"], "aborted");
    assert_eq!(written[1]["aborted_in"], "admission");
    assert_eq!(written[2]["outcome"], "busy");
    assert_eq!(written[2]["status"], 503);
    assert_eq!(written[2]["severity"], "WARNING");
    Ok(())
}

#[test]
fn only_declared_identifiers_and_fixed_values_reach_the_line() -> Result<()> {
    let (output, captured) = capture();
    let recorder = Recorder::request(output, now());
    {
        let _entered = recorder.enter();
        // A path, an address or free text is never an app-declared name.
        route("/launcher/refresh?user=ada@example.test");
        let mut command = invocation("preparation", "ada@example.test");
        command.identifier("invocation", "token=secret value");
        drop(command);
        let mut observe = span("observe");
        observe.name("capability", &"x".repeat(MAX_NAME + 1));
        drop(observe);
        failure("storage_busy");
    }
    recorder.suppress();
    let suppressed = recorder.clone();
    drop(recorder);
    drop(suppressed);
    assert!(
        captured.lock().unwrap().is_empty(),
        "suppressed probes write nothing"
    );

    let (output, captured) = capture();
    let recorder = Recorder::request(output, now());
    {
        let _entered = recorder.enter();
        route("/launcher/refresh?user=ada@example.test");
        let mut command = invocation("preparation", "ada@example.test");
        command.identifier("invocation", "token=secret value");
        drop(command);
        failure("storage_busy");
    }
    recorder.respond(503, "complete");
    drop(recorder);
    let raw = captured.lock().unwrap()[0].clone();
    for secret in [
        "ada@example.test",
        "example.test",
        "token=",
        "secret value",
        "/launcher",
    ] {
        assert!(!raw.contains(secret), "{secret} leaked into {raw}");
    }
    let line: Value = serde_json::from_str(&raw)?;
    assert_eq!(line["route"], "<undeclared>");
    assert_eq!(phases(&line, "preparation")[0]["operation"], "<undeclared>");
    assert_eq!(line["error"], "storage_busy");
    Ok(())
}

#[test]
fn instrumentation_without_an_entered_recorder_records_nothing() {
    // Library calls outside a request (CLI, tests, startup) stay inert.
    let mut command = invocation("preparation", "anything");
    command.result("success");
    drop(command);
    let mut call = provider("workspace_directory", "metadata_token");
    call.status(200);
    drop(call);
    let mut wait = writer_wait();
    wait.turned();
    drop(wait.began());
    drop(writer_wait());
    drop(sql_read());
    drop(sql_write());
    let mut trace = trace_write();
    trace.bytes(10);
    drop(trace);
    route("page");
    failure("internal");
    assert!(current().is_none());
}

#[test]
fn entering_restores_the_previous_recorder_and_nested_requests_stay_separate() {
    let (output, captured) = capture();
    let outer = Recorder::request(output.clone(), now());
    let inner = Recorder::request(output, now());
    {
        let _outer = outer.enter();
        {
            let _inner = inner.enter();
            drop(span("inner_only"));
        }
        drop(span("outer_only"));
    }
    assert!(current().is_none());
    drop(inner);
    drop(outer);
    let written = lines(&captured);
    assert_eq!(written.len(), 2);
    assert_eq!(phases(&written[0], "inner_only").len(), 1);
    assert!(phases(&written[0], "outer_only").is_empty());
    assert_eq!(phases(&written[1], "outer_only").len(), 1);
    assert!(phases(&written[1], "inner_only").is_empty());
}

#[test]
fn a_line_keeps_a_bounded_timeline_and_counts_what_it_dropped() {
    let (output, captured) = capture();
    let recorder = Recorder::request(output, now());
    for _ in 0..MAX_PHASES + 7 {
        drop(recorder.span("access_log"));
    }
    drop(recorder);
    let line = &lines(&captured)[0];
    assert_eq!(line["phases"].as_array().unwrap().len(), MAX_PHASES);
    assert_eq!(line["dropped_phases"], 7);
}

#[test]
fn background_runs_log_when_slow_failed_or_waiting_for_the_writer() {
    let (output, captured) = capture();
    // A quick, quiet run only feeds the minute summary.
    drop(Recorder::job(output.clone(), "commands"));
    let failed = Recorder::job(output.clone(), "journal");
    failed.failure("storage_busy");
    drop(failed);
    let waited = Recorder::job(output, "schedules");
    {
        let _entered = waited.enter();
        // A writer wait that never began counts as busy.
        drop(writer_wait());
    }
    drop(waited);
    let runs: Vec<_> = lines(&captured)
        .into_iter()
        .filter(|line| line["event"] == "day2_background")
        .collect();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0]["pump"], "journal");
    assert_eq!(runs[0]["error"], "storage_busy");
    assert_eq!(runs[1]["pump"], "schedules");
    assert_eq!(runs[1]["totals"]["writer_busy"], 1);
}

#[test]
fn the_write_queue_reports_wait_begin_and_hold_for_the_waiting_writer() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("queue.sqlite");
    let mut holder = rusqlite::Connection::open(&path)?;
    holder.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t(x INTEGER);")?;
    let (output, captured) = capture();
    let held = crate::write_queue::immediate(&mut holder)?;
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || -> Result<()> {
        let recorder = Recorder::request(output, now());
        {
            let _entered = recorder.enter();
            let mut connection = rusqlite::Connection::open(&path)?;
            entered_tx.send(())?;
            let tx = crate::write_queue::immediate(&mut connection)?;
            tx.execute("INSERT INTO t VALUES(1)", [])?;
            tx.commit()?;
        }
        drop(recorder);
        Ok(())
    });
    entered.recv()?;
    std::thread::sleep(Duration::from_millis(50));
    held.commit()?;
    waiter.join().expect("waiter")?;
    let line = &lines(&captured)[0];
    assert_eq!(line["totals"]["writer_turns"], 1);
    assert_eq!(line["totals"]["writer_busy"], 0);
    assert!(
        duration(&line["totals"]["writer_wait_ms"]) >= 20.0,
        "the waiter's turn wait is measured: {line}"
    );
    assert!(duration(&line["totals"]["writer_wait_max_ms"]) >= 20.0);
    assert!(line["totals"]["writer_hold_ms"].as_f64().is_some());
    Ok(())
}

mod edge {
    //! The production edge server with a test key set, as in tests/edge.rs.
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
    };

    const ORIGIN: &str = "https://go.v2.exampleco.test";
    const AUTHORITY: &str = "go.v2.exampleco.test";
    const AUDIENCE: &str = "/projects/1234/global/backendServices/5678";
    const READER: &str = "ada@exampleco.test";
    const TRACE: &str = "105445aa7843bc8bf206b12000100000";

    struct Keys(String);

    impl crate::iap::KeySource for Keys {
        fn fetch(&self) -> Result<String> {
            Ok(self.0.clone())
        }
    }

    fn signer() -> Result<EcdsaKeyPair> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("keygen"))?;
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|_| anyhow::anyhow!("key"))
    }

    fn keys(pair: &EcdsaKeyPair) -> String {
        let point = pair.public_key().as_ref();
        json!({"keys":[{"kid":"edge","kty":"EC","crv":"P-256","alg":"ES256",
            "x":URL_SAFE_NO_PAD.encode(&point[1..33]),"y":URL_SAFE_NO_PAD.encode(&point[33..65])}]})
        .to_string()
    }

    fn assertion(pair: &EcdsaKeyPair, email: &str) -> Result<String> {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        )?;
        let claims = json!({"iss":crate::iap::ISSUER,"aud":AUDIENCE,"iat":now,"exp":now + 600,
            "sub":format!("accounts.google.com:{email}"),"email":email,"hd":"exampleco.test"});
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"edge","typ":"JWT"}).to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = pair
            .sign(&SystemRandom::new(), signed.as_bytes())
            .map_err(|_| anyhow::anyhow!("sign"))?;
        Ok(format!(
            "{signed}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }

    fn instance(artifact: &str) -> Value {
        let actors = json!([READER]);
        let read = json!({"actors":actors,"mode":{"kind":"read"},"models":{}});
        let mut forward = read.clone();
        forward["observations"] = json!(["app.query.v1"]);
        json!({"installation":"edgeco","environment":"test",
            "identity":{"scheme":"google_iap","hosted_domain":"exampleco.test"},
            "apps":{"go":{"artifact":artifact,"readers":actors,"writers":actors,
                "edge":{"origin":ORIGIN,"iap_audience":AUDIENCE},
                "authority":{"version":1,"admins":[],"operations":{
                    "delegation.who":read,"delegation.forward":forward,
                    "delegation.send":{"actors":actors,"mode":{"kind":"current_state"},"models":{},"effects":["app.send.v1"]},
                    "delegation.status":{"actors":actors,"mode":{"kind":"read"},"models":{},"observations":["app.status.v1"]},
                    "delegation.history":{"actors":actors,"mode":{"kind":"read"},"models":{},"observations":["audit.history.v1"]},
                    "delegation.record":{"actors":actors,"mode":{"kind":"current_state"},
                        "models":{"entries":{"read":true,"create":true,
                            "rows":{"kind":"owner_or_admin","field":"actor"}}}}}}}}})
    }

    #[test]
    fn edge_requests_write_one_redacted_line_each_through_the_real_server() -> Result<()> {
        let Some(artifact) = std::env::var_os("DAY2_TEST_DELEGATION_ARTIFACT") else {
            eprintln!(
                "skipping edge request timing; set DAY2_TEST_DELEGATION_ARTIFACT to an admitted delegation artifact"
            );
            return Ok(());
        };
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&instance(
                std::path::Path::new(&artifact)
                    .to_str()
                    .context("artifact path")?,
            ))?,
        )?;
        let loaded = crate::artifact::Instance::load(&path)?;
        let edge = loaded.edge("go")?.1.clone();
        let runtime = crate::store::Runtime::load(&path, "go")?;
        runtime.initialize()?;
        let pair = signer()?;
        let verifier =
            crate::iap::Verifier::new(AUDIENCE, "exampleco.test", Box::new(Keys(keys(&pair))))?;
        let (send, receive) = std::sync::mpsc::channel();
        let (stop, done) = tokio::sync::oneshot::channel::<()>();
        let server = std::thread::spawn(move || -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(async move {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let mut server = crate::web::LocalServer::bind_edge_listener(
                        runtime, listener, &edge, verifier, 4,
                    )?;
                    let captured = server.capture_request_timing()?;
                    send.send((format!("http://{address}"), captured))?;
                    server
                        .serve(async {
                            let _ = done.await;
                        })
                        .await
                })
        });
        let (origin, captured) = receive.recv_timeout(Duration::from_secs(30))?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .build()?;
        let signed = assertion(&pair, READER)?;
        let admitted = client
            .get(format!("{origin}/api/delegation.who"))
            .header(reqwest::header::HOST, AUTHORITY)
            .header("x-goog-iap-jwt-assertion", &signed)
            .header("x-cloud-trace-context", format!("{TRACE}/1;o=1"))
            .send()?;
        assert_eq!(admitted.status(), reqwest::StatusCode::OK);
        let cookie = admitted
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .context("session cookie")?
            .to_owned();
        drop(admitted.bytes()?);
        let refused = client
            .get(format!("{origin}/api/session"))
            .header(reqwest::header::HOST, AUTHORITY)
            .header(reqwest::header::COOKIE, &cookie)
            .send()?;
        assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);
        drop(refused.bytes()?);
        let health = client
            .get(format!("{origin}/health/live"))
            .header(reqwest::header::HOST, AUTHORITY)
            .send()?;
        assert_eq!(health.status(), reqwest::StatusCode::OK);
        let _ = stop.send(());
        server.join().expect("edge server")?;

        let raw: Vec<String> = captured.lock().unwrap().clone();
        let requests: Vec<(String, Value)> = raw
            .iter()
            .map(|line| Ok((line.clone(), serde_json::from_str::<Value>(line)?)))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|(_, line)| line["event"] == "day2_request")
            .collect();
        assert_eq!(
            requests.len(),
            2,
            "one line per request, none for health: {raw:?}"
        );
        for (text, _) in &requests {
            for secret in [
                READER,
                "exampleco",
                signed.as_str(),
                cookie.as_str(),
                "/api/",
            ] {
                assert!(!text.contains(secret), "{secret} leaked into {text}");
            }
        }
        let (_, admitted) = &requests[0];
        assert_eq!(admitted["status"], 200);
        assert_eq!(admitted["outcome"], "complete");
        assert_eq!(admitted["method"], "GET");
        assert_eq!(admitted["category"], "api");
        assert_eq!(admitted["route"], "delegation.who");
        assert_eq!(admitted["trace"], TRACE);
        let actor = admitted["actor"].as_str().context("actor digest")?;
        assert!(actor.starts_with("a:") && actor.len() == 18, "{actor}");
        // The digest is the keyed tag, never an encoding of its input.
        assert!(
            !actor.contains(&URL_SAFE_NO_PAD.encode("day2-request")[..8]),
            "{actor}"
        );
        for name in [
            "admission",
            "body_read",
            "dispatch_queue",
            "authenticate",
            "dispatch",
        ] {
            assert_eq!(phases(admitted, name).len(), 1, "{name} in {admitted}");
        }
        assert_eq!(phases(admitted, "access_log").len(), 2);
        let invocation = phases(admitted, "api_invocation");
        assert_eq!(invocation.len(), 1);
        assert_eq!(invocation[0]["operation"], "delegation.who");
        assert_eq!(invocation[0]["result"], "success");
        assert!(invocation[0]["totals"]["worker_exchanges"].as_u64() >= Some(1));
        let totals = &admitted["totals"];
        assert!(totals["sql_reads"].as_u64() >= Some(1));
        assert!(totals["writer_turns"].as_u64() >= Some(1));
        assert!(totals["trace_writes"].as_u64() >= Some(1));
        assert!(totals["trace_bytes"].as_u64() > Some(0));
        let (_, refused) = &requests[1];
        assert_eq!(refused["status"], 401);
        assert_eq!(refused["error"], "invalid_identity_assertion");
        assert!(refused["actor"].is_null());
        assert!(refused["trace"].is_null());
        assert_eq!(phases(refused, "authenticate").len(), 1);
        assert!(phases(refused, "dispatch").is_empty());
        // The same person hashes to the same digest on every request.
        assert_ne!(actor, "a:");
        Ok(())
    }
}
