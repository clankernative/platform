use anyhow::{Context, Result, ensure};
use day2::store::Runtime;
use reqwest::{StatusCode, blocking::Client, redirect::Policy};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server {
    child: Child,
    origin: String,
    login: String,
}

fn apply_desired_authority(runtime: &Runtime) -> Result<()> {
    let active = day2::authority_state::current(&rusqlite::Connection::open(runtime.db())?)?;
    day2::authority_state::apply_desired(
        runtime,
        &day2::authority_state::LocalOperator::assert_local("http-test-operator")?,
        &format!("http-policy-{}", active.stamp.revision),
        Some(active.stamp),
    )?;
    Ok(())
}

/// Wait until every automatic command behind a submit has committed: analysis makes
/// the report ready, and the announcement then records that it was told to someone.
/// Returns the settled revision. Asserting on a revision before both land races a
/// background write, which is how these tests used to pass by luck.
fn settled(runtime: &Runtime, seconds: u64) -> Result<(String, u64)> {
    let started = Instant::now();
    loop {
        let rows = runtime.inspect()?;
        if let Some(row) = rows["reports"].as_array().context("reports")?.first() {
            let data: Value = serde_json::from_str(row["data"].as_str().context("data")?)?;
            if data["ready"] == true && data["announced"] == true {
                return Ok((
                    row["id"].as_str().context("report ID")?.to_string(),
                    row["version"].as_u64().context("revision")?,
                ));
            }
        }
        ensure!(
            started.elapsed() < Duration::from_secs(seconds),
            "automatic local commands did not settle"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn http_durable_acceptance_exposes_actor_scoped_status_and_resumes_without_a_job_api() -> Result<()>
{
    #[path = "support/commands.rs"]
    mod support;
    let world = support::World::new()?;
    let server = Server::start(world.runtime.instance_path(), world.directory.path())?;
    let client = server.client()?;
    let session: Value = serde_json::from_str(
        &client
            .get(format!("{}/api/session", server.origin))
            .send()?
            .text()?,
    )?;
    let response = client
        .post(format!("{}/api/reports.submit", server.origin))
        .header("Origin", &server.origin)
        .header("X-CSRF-Token", session["csrf_token"].as_str().unwrap())
        .header("Idempotency-Key", "async-demo")
        .header("Prefer", "respond-async")
        .header("Content-Type", "application/json")
        .body(json!({"title":"Async report","text":"A\nB"}).to_string())
        .send()?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let location = response.headers()["location"].to_str()?.to_string();
    let accepted: Value = serde_json::from_str(&response.text()?)?;
    assert!(location.ends_with(accepted["invocation_id"].as_str().unwrap()));
    let started = Instant::now();
    let receipt = loop {
        let response = client.get(format!("{}{location}", server.origin)).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        let status: Value = serde_json::from_str(&response.text()?)?;
        if status["status"] == "success" {
            break status;
        }
        ensure!(
            started.elapsed() < Duration::from_secs(10),
            "accepted command did not finish"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(receipt["operation"], "reports.submit");
    assert_eq!(receipt["children"].as_array().unwrap().len(), 1);
    assert!(receipt.get("prepared_facts").is_none());
    let anonymous = Client::builder().redirect(Policy::none()).build()?;
    assert_eq!(
        anonymous
            .get(format!("{}{location}", server.origin))
            .send()?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for operation in ["reports.analyze", "reports.notify"] {
        assert_eq!(
            client
                .post(format!("{}/api/{operation}", server.origin))
                .header("Content-Type", "application/json")
                .body("{}")
                .send()?
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    Ok(())
}
impl Server {
    fn start(path: &Path, directory: &Path) -> Result<Self> {
        Self::start_actor(path, directory, "alice")
    }
    fn start_actor(path: &Path, directory: &Path, actor: &str) -> Result<Self> {
        let log_path = directory.join("server.log");
        let log = fs::File::create(&log_path)?;
        let child = Command::new(env!("CARGO_BIN_EXE_day2"))
            .args([
                "serve-local",
                path.to_str().context("instance path")?,
                "reports",
                actor,
                "0",
            ])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?;
        let mut server = Self {
            child,
            origin: String::new(),
            login: String::new(),
        };
        let started = Instant::now();
        loop {
            for line in fs::read_to_string(&log_path)?.lines() {
                if let Ok(value) = serde_json::from_str::<Value>(line)
                    && let (Some(origin), Some(login)) =
                        (value["origin"].as_str(), value["login_url"].as_str())
                {
                    server.origin = origin.into();
                    server.login = login.into();
                    return Ok(server);
                }
            }
            ensure!(
                server.child.try_wait()?.is_none(),
                "server stopped: {}",
                fs::read_to_string(&log_path)?
            );
            ensure!(
                started.elapsed() < Duration::from_secs(20),
                "server startup timeout"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn client(&self) -> Result<Client> {
        let client = Client::builder()
            .cookie_store(true)
            .redirect(Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?;
        let response = client.get(&self.login).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        let form = fields(&response.text()?, "form")?;
        let login = client
            .post(format!("{}/login", self.origin))
            .header("Origin", &self.origin)
            .form(&form)
            .send()?;
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        Ok(client)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn selector(value: &str) -> Result<Selector> {
    Selector::parse(value).map_err(|_| anyhow::anyhow!("test selector"))
}

fn mcp_request(
    server: &Server,
    client: &Client,
    method: &str,
    mut params: Value,
) -> reqwest::blocking::RequestBuilder {
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":day2::mcp::VERSION,"io.modelcontextprotocol/clientCapabilities":{}});
    let mut request = client
        .post(format!("{}/mcp", server.origin))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", day2::mcp::VERSION)
        .header("Mcp-Method", method);
    if let Some(name) = params["name"].as_str() {
        request = request.header("Mcp-Name", name);
    }
    request.body(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string())
}

fn mcp_result(request: reqwest::blocking::RequestBuilder) -> Result<Value> {
    let response = request.send()?;
    let status = response.status();
    let body: Value = serde_json::from_str(&response.text()?)?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    Ok(body["result"].clone())
}

#[test]
fn mcp_and_http_share_report_contracts_authority_and_durable_command_receipts() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let artifact = std::env::var_os("DAY2_TEST_REPORTS_API_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify or set DAY2_TEST_REPORTS_API_ARTIFACT")?;
    let policy: Value = serde_json::from_str(include_str!(
        "../../../fixtures/authority-policies/reports.json"
    ))?;
    let path = directory.path().join("instance.json");
    let (resources, resource_policies) = day2::development::local_resource_fixture(
        "reports",
        &serde_json::from_value(policy.clone())?,
        Some(day2_capabilities::resources::TopicScope::Any),
        None,
    )?;
    fs::write(
        &path,
        serde_json::to_vec(
            &json!({"installation":"mcpco","environment":"test","resources":resources,"apps":{"reports":{
                "artifact":artifact,"readers":["viewer"],"writers":["alice"],"auditors":["alice"],"authority":policy,"resource_policies":resource_policies
            }}}),
        )?,
    )?;
    // The host resumes internal commands independently of public HTTP requests.
    let runtime = Runtime::load(&path, "reports")?;
    runtime.initialize()?;
    let server = Server::start(&path, directory.path())?;
    let client = server.client()?;
    let anonymous = Client::builder().redirect(Policy::none()).build()?;
    assert_eq!(
        mcp_request(&server, &anonymous, "tools/list", json!({}))
            .send()?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let session: Value = serde_json::from_str(
        &client
            .get(format!("{}/api/session", server.origin))
            .send()?
            .text()?,
    )?;
    let csrf = session["csrf_token"].as_str().context("CSRF token")?;
    let discover = mcp_result(mcp_request(&server, &client, "server/discover", json!({})))?;
    assert_eq!(discover["resultType"], "complete");
    assert_eq!(
        discover["_meta"]["io.modelcontextprotocol/serverInfo"]["version"],
        runtime.artifact().id()
    );
    let listing = mcp_result(mcp_request(&server, &client, "tools/list", json!({})))?;
    let tools = listing["tools"].as_array().context("MCP tools")?;
    assert_eq!(tools.len(), 4);
    assert_eq!(
        runtime
            .artifact()
            .contract()
            .app_contract
            .as_ref()
            .context("required contract")?
            .operations
            .values()
            .filter(|definition| !definition.execution.internal)
            .count(),
        4
    );
    assert!(runtime.artifact().contract().operation_metadata.is_empty());
    let spec: Value = serde_json::from_str(
        &client
            .get(format!("{}/openapi.json", server.origin))
            .send()?
            .text()?,
    )?;
    let docs = client
        .get(format!("{}/docs", server.origin))
        .send()?
        .text()?;
    // OpenAPI retains complete inline schemas alongside its reusable ID refs.
    fn inline(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                fields.remove("$ref");
                for child in fields.values_mut() {
                    inline(child);
                }
            }
            Value::Array(items) => {
                for child in items {
                    inline(child);
                }
            }
            _ => (),
        }
    }
    for tool in tools {
        let name = tool["name"].as_str().context("tool name")?;
        let method = if tool["annotations"]["readOnlyHint"] == true {
            "get"
        } else {
            "post"
        };
        let http = &spec["paths"][format!("/api/{name}")][method];
        assert_eq!(tool["title"], http["summary"]);
        assert_eq!(tool["description"], http["description"]);
        assert_eq!(
            tool["_meta"]["io.day2/operationContract"],
            http["x-day2-operation-contract"]
        );
        let input = http["x-day2-input-schema"].as_str().unwrap();
        let mut input = spec.pointer(input.trim_start_matches('#')).unwrap().clone();
        inline(&mut input);
        assert_eq!(tool["inputSchema"]["properties"]["input"], input);
        let output = http["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
            .as_str()
            .unwrap();
        let mut output = spec
            .pointer(output.trim_start_matches('#'))
            .unwrap()
            .clone();
        inline(&mut output);
        assert_eq!(tool["outputSchema"]["properties"]["result"], output);
        let article = Html::parse_document(&docs);
        let article = article
            .select(&selector(&format!("article[id='{name}']"))?)
            .next()
            .context("operation docs")?;
        assert!(
            article.text().collect::<String>().contains(
                tool["_meta"]["io.day2/operationContract"]["usage"]["purpose"]
                    .as_str()
                    .unwrap()
            )
        );
    }
    let input = json!({"title":"MCP report","text":"First line\nSecond line"});
    let submit =
        json!({"name":"reports.submit","arguments":{"input":input,"idempotency_key":"shared-key"}});
    assert_eq!(
        mcp_request(&server, &client, "tools/call", submit.clone())
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        mcp_request(&server, &client, "tools/call", submit.clone())
            .header("Origin", &server.origin)
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    let write = |params| {
        mcp_request(&server, &client, "tools/call", params)
            .header("Origin", &server.origin)
            .header("X-CSRF-Token", csrf)
    };
    for (index, title) in ["é".repeat(101), "\u{3000}".into()].iter().enumerate() {
        let invalid = json!({"title":title,"text":"Document"});
        assert_eq!(
            mcp_result(write(
                json!({"name":"reports.submit","arguments":{"input":invalid,"idempotency_key":format!("domain-mcp-{index}")}})
            ))?["isError"],
            true
        );
        let response = client
            .post(format!("{}/api/reports.submit", server.origin))
            .header("Origin", &server.origin)
            .header("X-CSRF-Token", csrf)
            .header("Content-Type", "application/json")
            .header("Idempotency-Key", format!("domain-http-{index}"))
            .body(invalid.to_string())
            .send()?;
        assert!(!response.status().is_success());
        assert!(response.text()?.contains("invalid_domain_value"));
    }
    let saved = mcp_result(write(submit.clone()))?;
    assert_eq!(saved["isError"], false);
    let saved_value = &saved["structuredContent"]["result"];
    let report_id = saved_value["id"].as_str().context("created report")?;
    assert_eq!(
        serde_json::from_str::<Value>(saved["content"][0]["text"].as_str().unwrap())?,
        saved["structuredContent"]
    );
    assert_eq!(
        mcp_result(write(submit.clone()))?["structuredContent"],
        saved["structuredContent"]
    );
    // Retry through HTTP: same durable receipt and no extra report or child command.
    let replay = client
        .post(format!("{}/api/reports.submit", server.origin))
        .header("Content-Type", "application/json")
        .header("Origin", &server.origin)
        .header("X-CSRF-Token", csrf)
        .header("Idempotency-Key", "shared-key")
        .body(input.to_string())
        .send()?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        replay.headers()["x-day2-invocation"],
        saved["_meta"]["io.day2/invocation"].as_str().unwrap()
    );
    assert_eq!(
        serde_json::from_str::<Value>(&replay.text()?)?,
        *saved_value
    );
    let mut different = submit.clone();
    different["arguments"]["input"]["text"] = json!("Another intent");
    let conflict = mcp_result(write(different))?;
    assert_eq!(conflict["isError"], true);
    assert!(
        conflict["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("idempotency_key_conflict")
    );
    let (_, current) = settled(&runtime, 10)?;
    let revise = json!({"name":"reports.revise","arguments":{"input":{"report_id":report_id,"expected_version":current,"text":"Updated"},"idempotency_key":"edit-key"}});
    let revised = mcp_result(write(revise.clone()))?;
    assert_eq!(
        revised["structuredContent"]["result"]["version"],
        current + 1
    );
    let mut stale = revise;
    stale["arguments"]["idempotency_key"] = json!("stale-edit");
    assert_eq!(mcp_result(write(stale))?["isError"], true);
    // The revise requests a re-analysis, which requests a fresh announcement.
    let (_, reanalyzed) = settled(&runtime, 10)?;
    ensure!(
        reanalyzed > current + 1,
        "the revision was never re-analyzed"
    );
    let detail = mcp_result(mcp_request(
        &server,
        &client,
        "tools/call",
        json!({"name":"reports.detail","arguments":{"input":{"report_id":report_id}}}),
    ))?;
    assert_eq!(
        detail["structuredContent"]["result"]["text"], "Updated",
        "{detail}"
    );
    assert!(detail["structuredContent"]["result"]["ready"].is_boolean());
    let result = mcp_result(mcp_request(
        &server,
        &client,
        "tools/call",
        json!({"name":"reports.list","arguments":{"input":{"after":"","limit":1}}}),
    ))?;
    assert_eq!(
        result["structuredContent"]["result"]["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(runtime.inspect()?["reports"].as_array().unwrap().len(), 1);

    for input in [
        json!({"report_id":1}),
        json!({}),
        json!({"report_id":report_id,"unexpected":true}),
    ] {
        assert_eq!(
            mcp_result(mcp_request(
                &server,
                &client,
                "tools/call",
                json!({"name":"reports.detail","arguments":{"input":input}})
            ))?["isError"],
            true
        );
    }
    let mut missing_key = submit.clone();
    missing_key["arguments"]
        .as_object_mut()
        .unwrap()
        .remove("idempotency_key");
    assert_eq!(mcp_result(write(missing_key))?["isError"], true);
    assert_eq!(
        mcp_request(
            &server,
            &client,
            "tools/call",
            json!({"name":"jobs.reports.analyze.complete","arguments":{"input":{}}})
        )
        .send()?
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        mcp_request(&server, &client, "tools/list", json!({}))
            .header("Origin", "https://attacker.invalid")
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        mcp_request(&server, &client, "tools/list", json!({}))
            .header("Mcp-Method", "tools/call")
            .send()?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .get(format!("{}/mcp", server.origin))
            .send()?
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    for (body, code) in [
        ("{", -32700),
        ("[]", -32600),
        (
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"tools/list\"}",
            -32600,
        ),
        ("{\"id\":1,\"id\":2}", -32700),
    ] {
        let response = mcp_request(&server, &client, "tools/list", json!({}))
            .body(body)
            .send()?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_str::<Value>(&response.text()?)?["error"]["code"],
            code
        );
    }
    assert_eq!(
        mcp_request(&server, &client, "tools/list", json!({}))
            .body("x".repeat(65_537))
            .send()?
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let legacy = |body: Value| {
        client
            .post(format!("{}/mcp", server.origin))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(body.to_string())
    };
    let initialized = mcp_result(legacy(
        json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":day2::mcp::LEGACY_VERSION,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
    ))?;
    assert_eq!(initialized["protocolVersion"], day2::mcp::LEGACY_VERSION);
    let notification = legacy(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .header("MCP-Protocol-Version", day2::mcp::LEGACY_VERSION)
        .send()?;
    assert_eq!(notification.status(), StatusCode::ACCEPTED);
    assert!(notification.text()?.is_empty());
    assert_eq!(
        mcp_result(
            legacy(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
                .header("MCP-Protocol-Version", day2::mcp::LEGACY_VERSION)
        )?["tools"],
        listing["tools"]
    );

    // Discovery and calls both recheck policy after the server starts.
    let mut instance: Value = serde_json::from_slice(&fs::read(&path)?)?;
    instance["apps"]["reports"]["authority"]["operations"]["reports.submit"]["actors"] =
        json!(["admin"]);
    fs::write(&path, serde_json::to_vec(&instance)?)?;
    apply_desired_authority(&runtime)?;
    assert_eq!(
        mcp_result(mcp_request(&server, &client, "tools/list", json!({})))?["tools"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        write(submit.clone()).send()?.status(),
        StatusCode::FORBIDDEN
    );
    instance["apps"]["reports"]["authority"] = policy;
    fs::write(&path, serde_json::to_vec(&instance)?)?;
    apply_desired_authority(&runtime)?;
    drop(server);
    let restarted = Server::start(&path, directory.path())?;
    let client = restarted.client()?;
    let session: Value = serde_json::from_str(
        &client
            .get(format!("{}/api/session", restarted.origin))
            .send()?
            .text()?,
    )?;
    let replay = mcp_result(
        mcp_request(&restarted, &client, "tools/call", submit)
            .header("Origin", &restarted.origin)
            .header("X-CSRF-Token", session["csrf_token"].as_str().unwrap()),
    )?;
    assert_eq!(replay["isError"], true);
    assert!(replay.get("structuredContent").is_none());
    assert!(replay.to_string().contains("receipt_policy_changed"));
    drop(restarted);
    let viewer = Server::start_actor(&path, directory.path(), "viewer")?;
    let client = viewer.client()?;
    assert_eq!(
        mcp_result(mcp_request(&viewer, &client, "tools/list", json!({})))?["tools"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let denied = mcp_result(mcp_request(
        &viewer,
        &client,
        "tools/call",
        json!({"name":"reports.detail","arguments":{"input":{"report_id":report_id}}}),
    ))?;
    assert_eq!(denied["isError"], true);
    assert!(denied.get("structuredContent").is_none());
    Ok(())
}
fn fields(html: &str, form: &str) -> Result<BTreeMap<String, String>> {
    let parsed = Html::parse_document(html);
    let form = parsed
        .select(&selector(form)?)
        .next()
        .context("form missing")?;
    let mut fields = BTreeMap::new();
    for input in form.select(&selector("input[name], textarea[name]")?) {
        let name = input.value().attr("name").context("field name")?;
        let value = if input.value().name() == "textarea" {
            input.text().collect::<String>()
        } else {
            input.value().attr("value").unwrap_or("").into()
        };
        fields.insert(name.into(), value);
    }
    Ok(fields)
}

#[test]
fn real_http_datastar_form_command_scheduler_html_and_audit_survive_restart() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let artifact = std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify or set DAY2_TEST_REPORTS_ARTIFACT")?;
    let policy: Value = serde_json::from_str(include_str!(
        "../../../fixtures/authority-policies/reports.json"
    ))?;
    let path = directory.path().join("instance.json");
    let (resources, resource_policies) = day2::development::local_resource_fixture(
        "reports",
        &serde_json::from_value(policy.clone())?,
        Some(day2_capabilities::resources::TopicScope::Any),
        None,
    )?;
    fs::write(
        &path,
        serde_json::to_vec(
            &json!({"installation":"httpco","environment":"test","resources":resources,"apps":{"reports":{
                "artifact":artifact,"readers":[],"writers":["alice"],"auditors":["alice"],
                "authority":policy,"resource_policies":resource_policies
            }}}),
        )?,
    )?;
    let runtime = Runtime::load(&path, "reports")?;
    runtime.initialize()?;
    let server = Server::start(&path, directory.path())?;
    let client = server.client()?;
    let spec: Value = serde_json::from_str(
        &client
            .get(format!("{}/openapi.json", server.origin))
            .send()?
            .text()?,
    )?;
    let public: Vec<_> = runtime
        .artifact()
        .contract()
        .operations
        .iter()
        .filter(|op| {
            op.kind != "completion" && !runtime.artifact().contract().internal_command(&op.name)
        })
        .collect();
    assert_eq!(
        runtime
            .artifact()
            .contract()
            .app_contract
            .as_ref()
            .context("required contract")?
            .operations
            .values()
            .filter(|definition| !definition.execution.internal)
            .count(),
        4
    );
    assert!(runtime.artifact().contract().api_docs.is_empty());
    let schema_for = |operation: &str, method: &str| -> &Value {
        let reference = spec["paths"][operation][method]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].as_str().unwrap();
        spec.pointer(reference.trim_start_matches('#')).unwrap()
    };
    let detail_schema = schema_for("/api/reports.detail", "get");
    let id_schema = &detail_schema["properties"]["id"];
    assert_eq!(id_schema["$ref"], "#/components/schemas/Id_rep");
    assert_eq!(id_schema["minLength"], 30);
    assert_eq!(id_schema["maxLength"], 30);
    assert_eq!(
        spec["components"]["schemas"]["Id_rep"]["x-day2-id-prefix"],
        "rep"
    );
    assert!(day2::identity::valid_for(
        id_schema["examples"][0].as_str().unwrap(),
        "rep"
    ));
    assert_eq!(detail_schema["properties"]["version"]["minimum"], 1);
    assert_eq!(detail_schema["properties"]["version"]["format"], "uint64");
    for name in ["bytes", "lines"] {
        assert_eq!(detail_schema["properties"][name]["minimum"], 0);
        assert_eq!(detail_schema["properties"][name]["format"], "uint64");
        assert_eq!(detail_schema["properties"][name]["maximum"], u64::MAX);
    }
    assert_eq!(
        schema_for("/api/reports.list", "get")["properties"]["items"]["items"]["properties"]["version"]
            ["minimum"],
        1
    );
    for operation in ["/api/reports.submit", "/api/reports.revise"] {
        assert_eq!(
            schema_for(operation, "post")["properties"]["version"]["minimum"],
            1
        );
    }
    let revise_input = spec["paths"]["/api/reports.revise"]["post"]["x-day2-input-schema"]
        .as_str()
        .unwrap();
    assert_eq!(
        spec.pointer(revise_input.trim_start_matches('#')).unwrap()["properties"]["expected_version"]
            ["minimum"],
        1
    );
    assert_eq!(
        spec["paths"]["/api/reports.detail"]["get"]["summary"],
        "Get a report"
    );
    assert_eq!(
        spec["paths"]["/api/reports.submit"]["post"]["x-codeSamples"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    assert_eq!(
        spec["paths"]["/api/reports.submit"]["post"]["requestBody"]["content"]["application/json"]
            ["example"]["title"],
        "Weekly report"
    );
    assert_eq!(spec["paths"].as_object().unwrap().len(), public.len() + 4);
    for operation in &public {
        let method = if operation.kind == "query" {
            "get"
        } else {
            "post"
        };
        assert_eq!(
            spec["paths"][format!("/api/{}", operation.name)][method]["operationId"],
            operation.name
        );
    }
    for operation in runtime
        .artifact()
        .contract()
        .operations
        .iter()
        .filter(|op| {
            op.kind == "completion" || runtime.artifact().contract().internal_command(&op.name)
        })
    {
        assert!(
            spec["paths"]
                .get(format!("/api/{}", operation.name))
                .is_none()
        );
        assert_eq!(
            client
                .post(format!("{}/api/{}", server.origin, operation.name))
                .send()?
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    let response = client
        .get(format!(
            "{}/api/reports.list?after=&limit=20",
            server.origin
        ))
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    let reports: Value = serde_json::from_str(&response.text()?)?;
    assert_eq!(reports["items"], json!([]));
    let docs = client.get(format!("{}/docs", server.origin)).send()?;
    assert_eq!(docs.status(), StatusCode::OK);
    let docs = Html::parse_document(&docs.text()?);
    let detail = docs
        .select(&selector("article[id='reports.detail']")?)
        .next()
        .context("report detail documentation")?;
    assert!(
        detail
            .text()
            .collect::<String>()
            .contains("The identifier of the report to retrieve.")
    );
    assert_eq!(detail.select(&selector("[role='tab']")?).count(), 6);
    assert!(detail.select(&selector(".field-type")?).count() >= 8);
    assert!(detail.select(&selector(".required")?).count() >= 8);
    let example = detail
        .select(&selector(".response-sample[data-status='200'] code")?)
        .next()
        .context("documented response example")?
        .text()
        .collect::<String>();
    assert_eq!(
        serde_json::from_str::<Value>(&example)?["title"],
        "Weekly report"
    );
    let page = client.get(&server.origin).send()?;
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()["cache-control"], "no-store");
    assert!(page.headers().contains_key("content-security-policy"));
    let html = page.text()?;
    assert!(html.contains("Document reports"));
    let parsed = Html::parse_document(&html);
    for (field, maximum) in [("title", "200"), ("text", "8000")] {
        let control = parsed
            .select(&selector(&format!("[name='{field}']"))?)
            .next()
            .context("domain control")?;
        assert_eq!(
            control.value().attr("data-day2-max-utf8-bytes"),
            Some(maximum)
        );
        assert_eq!(control.value().attr("data-day2-nonblank"), Some("true"));
        assert!(control.value().attr("maxlength").is_none());
    }
    let parsed = Html::parse_document(&html);
    for image in parsed.select(&selector("img[src]")?) {
        let source = image.value().attr("src").context("image URL")?;
        let image = client
            .get(reqwest::Url::parse(&server.origin)?.join(source)?)
            .send()?;
        assert_eq!(image.status(), StatusCode::OK);
        assert_eq!(image.headers()["content-type"], "image/png");
        assert_eq!(image.headers()["cache-control"], "private, no-cache");
        let etag = image.headers()["etag"].clone();
        assert!(!image.bytes()?.is_empty());
        let cached = client
            .get(reqwest::Url::parse(&server.origin)?.join(source)?)
            .header("If-None-Match", etag)
            .send()?;
        assert_eq!(cached.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(cached.headers()["cache-control"], "private, no-cache");
        assert!(cached.bytes()?.is_empty());
    }
    let mut submit = fields(&html, "form.command")?;
    submit.insert("title".into(), "HTTP report & <x>".into());
    submit.insert("text".into(), "Line one\nLine two".into());
    let response = client
        .post(format!("{}/actions", server.origin))
        .header("Origin", &server.origin)
        .header("Datastar-Request", "true")
        .form(&submit)
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        response.headers()["content-type"]
            .to_str()?
            .contains("text/event-stream")
    );
    let events = response.text()?;
    assert!(events.contains("datastar-patch-elements"));
    let (report_id, revision) = settled(&runtime, 20)?;
    let response = client
        .get(format!(
            "{}/api/reports.list?after=&limit=20",
            server.origin
        ))
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    let reports: Value = serde_json::from_str(&response.text()?)?;
    assert_eq!(
        reports["items"],
        json!([{
            "id": report_id,
            "version": revision,
            "title": "HTTP report & <x>",
            "text": "Line one\nLine two",
            "ready": true,
            "bytes": 17,
            "lines": 2,
        }])
    );
    assert_eq!(reports["has_more"], false);
    let page = client
        .get(format!("{}/reports/{report_id}", server.origin))
        .send()?;
    assert_eq!(page.status(), StatusCode::OK);
    let html = page.text()?;
    assert!(html.contains("HTTP report &amp; &lt;x&gt;"));
    assert!(html.contains("Complete"));
    let parsed = Html::parse_document(&html);
    let statistics: Vec<_> = parsed
        .select(&selector("dd")?)
        .map(|field| field.text().collect::<String>())
        .collect();
    assert_eq!(statistics, ["17", "2"]);
    let audit = parsed
        .select(&selector("a[href]")?)
        .find(|link| link.text().collect::<String>() == "Audit log")
        .and_then(|link| link.value().attr("href"))
        .context("audit route")?;
    assert_eq!(
        client
            .get(reqwest::Url::parse(&server.origin)?.join(audit)?)
            .send()?
            .status(),
        StatusCode::OK
    );
    let connection = rusqlite::Connection::open(runtime.db())?;
    let changes: i64 =
        connection.query_row("SELECT count(*) FROM day2_audit_changes", [], |row| {
            row.get(0)
        })?;
    assert_eq!(changes, 3);
    let analyses: i64 = connection.query_row(
        "SELECT count(*) FROM day2_invocations WHERE operation='reports.analyze' AND status='success'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(analyses, 1);
    drop(client);
    drop(server);
    let server = Server::start(&path, directory.path())?;
    let client = server.client()?;
    assert_eq!(
        client
            .get(format!("{}/reports/{report_id}", server.origin))
            .send()?
            .status(),
        StatusCode::OK
    );
    assert_eq!(runtime.inspect()?["reports"][0]["version"], revision);
    let session: Value = serde_json::from_str(
        &client
            .get(format!("{}/api/session", server.origin))
            .send()?
            .text()?,
    )?;
    let input = json!({"title":"API report","text":"Created through the generated API"});
    let before_invalid = runtime.inspect()?;
    for invalid in [json!(-1), json!(0), json!(u64::MAX)] {
        let response = client
            .post(format!("{}/api/reports.revise", server.origin))
            .header("Origin", &server.origin)
            .header("X-CSRF-Token", session["csrf_token"].as_str().unwrap())
            .header("Idempotency-Key", "invalid-report-version")
            .header("Content-Type", "application/json")
            .body(json!({"report_id":report_id.to_string(),"expected_version":invalid,"text":"must not commit"}).to_string())
            .send()?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(runtime.inspect()?, before_invalid);
    let submit_api = || {
        client
            .post(format!("{}/api/reports.submit", server.origin))
            .header("Origin", &server.origin)
            .header("Content-Type", "application/json")
            .header("X-CSRF-Token", session["csrf_token"].as_str().unwrap())
            .header("Idempotency-Key", "reports-api-submit")
            .body(input.to_string())
            .send()
    };
    let response = submit_api()?;
    assert_eq!(response.status(), StatusCode::OK);
    let saved: Value = serde_json::from_str(&response.text()?)?;
    let operation = runtime.artifact().operation("reports.submit")?;
    runtime.artifact().contract().outputs[&operation.output_type]
        .shape
        .validate_value(&saved)?;
    assert_eq!(
        serde_json::from_str::<Value>(&submit_api()?.text()?)?,
        saved
    );
    assert_eq!(runtime.inspect()?["reports"].as_array().unwrap().len(), 2);
    Ok(())
}
