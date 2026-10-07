#![forbid(unsafe_code)]
use anyhow::{Context, Result, ensure};
use day2_ops::{app_create, backup, infra, local_dev, maintenance, process, projection};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: u32,
    action: String,
    input: String,
}

fn input<T: DeserializeOwned>(request: &Request) -> Result<T> {
    ensure!(
        request.protocol == 1 && request.input.len() <= 65_536,
        "unsupported host protocol or input size"
    );
    day2::json::decode(request.input.as_bytes())
}

fn platform() -> Result<PathBuf> {
    // Source distribution. xtask cli versions and builds the distribution binaries
    // together; an installed/hosted distribution will supply its own pin root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("platform source distribution missing")
}

struct Operations {
    development: Option<day2::development::Campaign>,
    infrastructure: Option<infra::Session>,
    local: Option<local_dev::Session>,
    maintenance: Option<maintenance::Session>,
    creation: Option<app_create::Session>,
}

impl Operations {
    fn maintenance(&mut self) -> Result<&mut maintenance::Session> {
        self.maintenance
            .as_mut()
            .context("maintenance session required")
    }

    fn effect(&mut self, request: Request) -> Result<Value> {
        if request.action == "local-resolve" {
            ensure!(self.local.is_none(), "one local session per workflow");
            let session = local_dev::Session::resolve(&platform()?, input(&request)?)?;
            let options = serde_json::to_value(&session.options)?;
            self.local = Some(session);
            return Ok(options);
        }
        if request.action.starts_with("local-")
            || (request.action.starts_with("dev-") && self.local.is_some())
        {
            return self
                .local
                .as_mut()
                .context("resolved local session required")?
                .effect(day2::automation::Request {
                    protocol: request.protocol,
                    action: request.action,
                    input: request.input,
                });
        }
        if request.action.starts_with("dev-")
            && !["dev-create", "dev-serve"].contains(&request.action.as_str())
        {
            let raw = serde_json::to_vec(
                &json!({"protocol":request.protocol,"action":request.action,"input":request.input}),
            )?;
            return self
                .development
                .as_mut()
                .context("development instance required")?
                .effect(day2::json::decode(&raw)?);
        }
        match request.action.as_str() {
            "app-create-answer" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    question: String,
                }
                app_create::prompt_answer(&input::<Input>(&request)?.question)
            }
            "app-create-begin" => {
                ensure!(self.creation.is_none(), "one creation per workflow");
                let session = app_create::Session::begin(input(&request)?)?;
                let receipt = json!({"source":session.source});
                self.creation = Some(session);
                Ok(receipt)
            }
            "app-create-write" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    files: Vec<app_create::SourceFile>,
                }
                self.creation
                    .as_mut()
                    .context("app creation required")?
                    .write_files(input::<Input>(&request)?.files)?;
                Ok(json!({}))
            }
            "app-create-identity" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    table: String,
                    roc_type: String,
                }
                let parameters: Input = input(&request)?;
                self.creation
                    .as_mut()
                    .context("app creation required")?
                    .identity(&parameters.table, &parameters.roc_type)?;
                Ok(json!({}))
            }
            "app-create-publish" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    artifact: PathBuf,
                }
                self.creation
                    .as_mut()
                    .context("app creation required")?
                    .publish(&input::<Input>(&request)?.artifact)
            }
            "credential-provision-inputs" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    instance: PathBuf,
                    app_name: String,
                    operator: String,
                    plan_file: PathBuf,
                }
                let parameters: Input = input(&request)?;
                Ok(serde_json::to_value(day2::packaging::provisioning_inputs(
                    &parameters.instance,
                    &parameters.app_name,
                    &parameters.operator,
                    &parameters.plan_file,
                )?)?)
            }
            "credential-provision-mount" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    instance: PathBuf,
                    operator: String,
                    input_json: String,
                }
                let parameters: Input = input(&request)?;
                let mount: day2::integration_host::Mount =
                    day2::json::decode(parameters.input_json.as_bytes())?;
                ensure!(
                    mount.expected_fingerprint.is_some(),
                    "provisioning_requires_reviewed_fingerprint"
                );
                day2::integration_host::mount(&parameters.instance, &parameters.operator, &mount)
            }
            "resource-admin-serve" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    instance: PathBuf,
                    operator: String,
                }
                let parameters: Input = input(&request)?;
                tokio::runtime::Runtime::new()?.block_on(async move {
                    let server = day2::admin_web::AdminServer::bind(&parameters.instance, &parameters.operator, 0).await?;
                    println!("{}", json!({"origin":server.origin,"login_url":server.login_url,"mode":"local-operator-resource-administration","stop":"Ctrl-C"}));
                    server.serve(async { let _ = tokio::signal::ctrl_c().await; }).await
                })?;
                Ok(json!({"stopped":true}))
            }
            "resource-admin-operation" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    action: String,
                    instance: PathBuf,
                    app_name: String,
                    operator: String,
                    input_file: String,
                }
                let parameters: Input = input(&request)?;
                day2::resource_admin::authorize(&parameters.instance, &parameters.operator)?;
                let path = &parameters.instance;
                let app = &parameters.app_name;
                let operator = &parameters.operator;
                let raw = if parameters.input_file.is_empty() {
                    Vec::new()
                } else {
                    ensure!(
                        fs::metadata(&parameters.input_file)?.len() <= 1_048_576,
                        "resource input byte budget"
                    );
                    fs::read(&parameters.input_file)?
                };
                match parameters.action.as_str() {
                    "catalog" => Ok(serde_json::to_value(day2::resource_admin::authoring(
                        path, operator,
                    )?)?),
                    "company-setup" => day2::resource_admin::setup_company_budget(path, operator),
                    "company-budget" => day2::resource_admin::company_budget(path, operator),
                    "credential-mount" => {
                        day2::integration_host::mount(path, operator, &day2::json::decode(&raw)?)
                    }
                    "security-review" => day2::security_admission::review_instance(
                        path,
                        app,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    "pool-propose" => day2::resource_admin::propose_pool_reduction(
                        path,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    "pool-return" => day2::resource_admin::return_company_capacity(
                        path,
                        app,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    "pool-decide" => day2::resource_admin::decide_pool_reduction(
                        path,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    "pool-import" => day2::resource_admin::import_pool_reduction(
                        path,
                        app,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    // Retention is the only operator action that destroys
                    // anything, so it is two actions rather than one: a plan is
                    // read, and a sweep is handed back the plan that was read.
                    "retention-plan" => Ok(serde_json::to_value(day2::retention::plan(
                        path,
                        app,
                        operator,
                        day2::resource_admin::now_ms()? / 1000,
                    )?)?),
                    "retention-sweep" => Ok(serde_json::to_value(day2::retention::sweep(
                        path,
                        app,
                        operator,
                        day2::resource_admin::now_ms()? / 1000,
                        &day2::json::decode(&raw)?,
                    )?)?),
                    "preview" => day2::resource_admin::preview(path, app, operator),
                    "reviews" => day2::resource_admin::reviews(path, app, operator),
                    "save" => Ok(serde_json::to_value(day2::resource_admin::save(
                        path,
                        operator,
                        &day2::json::decode(&raw)?,
                    )?)?),
                    "attach" => Ok(serde_json::to_value(day2::resource_admin::attach(
                        path,
                        app,
                        operator,
                        &day2::json::decode(&raw)?,
                    )?)?),
                    "propose" => day2::resource_admin::propose(
                        path,
                        app,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    "decide" => day2::resource_admin::decide(
                        path,
                        app,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    "allocate" => day2::resource_admin::allocate(
                        path,
                        app,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    "recover" => day2::resource_admin::recover_budget(
                        path,
                        app,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    "resolve-overruns" => day2::resource_admin::resolve_overruns(
                        path,
                        app,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    "reconcile-usage" => day2::resource_admin::reconcile_usage(
                        path,
                        app,
                        operator,
                        &day2::json::decode(&raw)?,
                    ),
                    _ => anyhow::bail!("unknown resource administration operation"),
                }
            }
            "authority-inspect" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    instance: PathBuf,
                    app_name: String,
                }
                let parameters: Input = input(&request)?;
                let runtime =
                    day2::store::Runtime::load(&parameters.instance, &parameters.app_name)?;
                let db = rusqlite::Connection::open_with_flags(
                    runtime.db(),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )?;
                let active = if day2::authority_state::exists(&db)? {
                    Some(day2::authority_state::current(&db)?)
                } else {
                    None
                };
                Ok(json!({"scope":runtime.scope(),"active":active,"mode":"local-operator-only"}))
            }
            "authority-apply" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    instance: PathBuf,
                    app_name: String,
                    operator: String,
                    expected: String,
                    request_id: String,
                }
                let parameters: Input = input(&request)?;
                let runtime =
                    day2::store::Runtime::load(&parameters.instance, &parameters.app_name)?;
                let operator =
                    day2::authority_state::LocalOperator::assert_local(&parameters.operator)?;
                let expected = day2::json::decode(parameters.expected.as_bytes())?;
                let receipt = day2::authority_state::apply_desired(
                    &runtime,
                    &operator,
                    &parameters.request_id,
                    expected,
                )?;
                Ok(json!({"receipt":receipt,"mode":"local-operator-only"}))
            }
            "authority-activate" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    instance: PathBuf,
                    app_name: String,
                    target: PathBuf,
                    operator: String,
                    expected: String,
                    request_id: String,
                }
                let parameters: Input = input(&request)?;
                let runtime =
                    day2::store::Runtime::load(&parameters.instance, &parameters.app_name)?;
                let target = day2::artifact::LoadedArtifact::load(&parameters.target)?;
                let operator =
                    day2::authority_state::LocalOperator::assert_local(&parameters.operator)?;
                let expected = day2::json::decode(parameters.expected.as_bytes())?;
                let receipt = day2::migration::activate_checked(
                    &runtime,
                    &target,
                    &operator,
                    &expected,
                    &parameters.request_id,
                )?;
                Ok(json!({"artifact":target.id(),"receipt":receipt,"mode":"local-operator-only"}))
            }
            "build-source" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    source: PathBuf,
                }
                let parameters: Input = input(&request)?;
                let root = platform()?;
                fs::create_dir_all(root.join("artifacts/operations"))?;
                let output = tempfile::Builder::new()
                    .prefix("build-")
                    .tempdir_in(root.join("artifacts/operations"))?
                    .keep();
                let receipt = output.join("build.json");
                if let Some(local) = self.local.as_mut() {
                    local.build_log(&output.join("build.log"))?;
                }
                let mut builder = Command::new(root.join("cli/xtask"));
                builder
                    .arg("build-receipt")
                    .arg(parameters.source.canonicalize()?)
                    .arg(&receipt);
                if let Some(creation) = self.creation.as_mut() {
                    creation.check_build_source(&parameters.source)?;
                    // An approved captured bundle is the only UI executable authority
                    // in this recipe. Ordinary HTML/UI-free builds have no provider.
                    builder.env_remove("DAY2_UI_PROVIDER_PIN_JSON");
                    if let Some(pin) = &creation.provider_pin {
                        builder.env("DAY2_UI_PROVIDER_PIN_JSON", pin);
                    }
                }
                // Required application verification scales with the operation and
                // obligation count, not with source size. A 26-operation app such as
                // People Ops exceeds ten minutes on a developer machine while still
                // succeeding, so the deadline bounds a hung tool rather than pacing a
                // legitimate build.
                let deadline = Duration::from_secs(1800);
                if let Some(local) = self.local.as_ref() {
                    process::run_cancellable(
                        &mut builder,
                        &root,
                        &output.join("build.log"),
                        deadline,
                        &local.cancelled(),
                    )?;
                } else {
                    process::run(&mut builder, &root, &output.join("build.log"), deadline)?;
                }
                let result: Value = serde_json::from_slice(&fs::read(receipt)?)?;
                if let Some(creation) = self.creation.as_mut() {
                    creation.built(Path::new(
                        result["artifact"]
                            .as_str()
                            .context("build artifact receipt")?,
                    ))?;
                }
                Ok(result)
            }
            "dev-create" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    artifact: PathBuf,
                    output: String,
                    example: String,
                    seed: String,
                    count: u64,
                }
                let parameters: Input = input(&request)?;
                ensure!(
                    self.development.is_none(),
                    "one development instance per workflow"
                );
                let output = if parameters.output.is_empty() {
                    let root = platform()?.join("artifacts/operations");
                    fs::create_dir_all(&root)?;
                    tempfile::Builder::new()
                        .prefix("check-")
                        .tempdir_in(root)?
                        .keep()
                        .join("instance")
                } else {
                    PathBuf::from(parameters.output)
                };
                let runtime = day2::development::create(&parameters.artifact, &output, None)?;
                let example =
                    (!parameters.example.is_empty()).then_some(parameters.example.as_str());
                self.development = Some(day2::development::Campaign::new(
                    runtime,
                    example,
                    parameters.seed.parse()?,
                    parameters.count,
                )?);
                Ok(json!({}))
            }
            "dev-serve" => {
                let parameters = self
                    .development
                    .as_ref()
                    .context("seeded development instance required")?;
                ensure!(parameters.is_complete(), "development seeding incomplete");
                let parameters = &parameters.runtime;
                let runtime = day2::store::Runtime::load(parameters.instance_path(), "app")?;
                let instance = day2::artifact::Instance::load(parameters.instance_path())?;
                ensure!(
                    instance.installation == "localdev"
                        && instance.environment == "disposable"
                        && instance.control.is_none(),
                    "local server requires a disposable development instance"
                );
                tokio::runtime::Runtime::new()?.block_on(async move {
                let server = day2::web::LocalServer::bind(runtime.clone(), day2::development::ACTOR, 0).await?;
                println!("{}", json!({"origin":server.origin,"login_url":server.login_url,"instance":runtime.instance_path(),"mode":"local-development","stop":"Ctrl-C"}));
                server.serve(async { let _ = tokio::signal::ctrl_c().await; }).await
            })?;
                Ok(json!({"stopped":true}))
            }
            "instance-project" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    path: PathBuf,
                }
                projection::instance(&input::<Input>(&request)?.path)
            }
            "artifact-version" => Ok(json!({"version":day2::artifact::CURRENT_FORMAT})),
            "artifact-project" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    path: PathBuf,
                }
                projection::artifact(&input::<Input>(&request)?.path)
            }
            "backup-snapshot" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    instance: PathBuf,
                    app_name: String,
                    output: PathBuf,
                }
                let parameters: Input = input(&request)?;
                let manifest = backup::take(
                    &parameters.instance,
                    &parameters.app_name,
                    &parameters.output,
                )?;
                Ok(
                    json!({"backup":parameters.output.canonicalize()?,"scope":manifest.scope,"artifact":manifest.artifact,"database":manifest.database}),
                )
            }
            "backup-restore" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    backup: PathBuf,
                    output: PathBuf,
                }
                let parameters: Input = input(&request)?;
                Ok(
                    json!({"instance":backup::restore(&parameters.backup, &parameters.output)?,"activated":false}),
                )
            }
            "infra-settings" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    configuration: PathBuf,
                }
                infra::settings(&input::<Input>(&request)?.configuration)
            }
            "infra-prepare" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    configuration: PathBuf,
                    configuration_digest: String,
                    output: PathBuf,
                    graph: infra::Graph,
                }
                let parameters: Input = input(&request)?;
                ensure!(
                    self.infrastructure.is_none(),
                    "one infrastructure session per workflow"
                );
                self.infrastructure = Some(infra::Session::prepare(
                    &parameters.configuration,
                    &parameters.configuration_digest,
                    &parameters.graph,
                    &parameters.output,
                )?);
                Ok(json!({}))
            }
            "infra-command" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    operation: String,
                }
                self.infrastructure
                    .as_mut()
                    .context("infrastructure session required")?
                    .command(&input::<Input>(&request)?.operation)
            }
            "infra-receipt" => self
                .infrastructure
                .as_ref()
                .context("infrastructure session required")?
                .receipt(),
            "backup-verify" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    directory: PathBuf,
                }
                let manifest = backup::verify(&input::<Input>(&request)?.directory)?;
                Ok(json!({"artifact":manifest.artifact,"database":manifest.database}))
            }
            "maintenance-open" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    operation: String,
                    request: PathBuf,
                }
                ensure!(
                    self.maintenance.is_none(),
                    "one maintenance session per workflow"
                );
                let parameters: Input = input(&request)?;
                let tools = maintenance::Tools::native(maintenance::interrupt_flag())?;
                self.maintenance = Some(maintenance::Session::open(
                    &parameters.operation,
                    &parameters.request,
                    tools,
                )?);
                Ok(json!({}))
            }
            "maintenance-artifacts" => self.maintenance()?.artifacts(),
            "maintenance-stop" => self.maintenance()?.stop(),
            "maintenance-pod" => self.maintenance()?.start_pod(),
            "maintenance-workflow" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    workflow: String,
                }
                let name = input::<Input>(&request)?.workflow;
                self.maintenance()?.workflow(&name)
            }
            "maintenance-copy-backup" => self.maintenance()?.copy_backup(),
            "maintenance-migration" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    step: String,
                }
                let step = input::<Input>(&request)?.step;
                self.maintenance()?.migration(&step)
            }
            "maintenance-confirm" => self.maintenance()?.confirm(),
            "maintenance-fence" => self.maintenance()?.fence(),
            "maintenance-finish" => self.maintenance()?.finish(),
            _ => anyhow::bail!("unknown private platform capability"),
        }
    }
}

fn run(request: Request) -> Result<Value> {
    ensure!(
        request.protocol == 1 && request.input.len() <= 65_536,
        "unsupported host protocol or input size"
    );
    let mut operations = Operations {
        development: None,
        infrastructure: None,
        local: None,
        maintenance: None,
        creation: None,
    };
    if !["workflow", "local-session"].contains(&request.action.as_str()) {
        ensure!(
            ["instance-project", "artifact-project", "artifact-version"]
                .contains(&request.action.as_str()),
            "operation requires a Roc workflow supervisor"
        );
        return operations.effect(request);
    }
    let arguments: Vec<String> = if request.action == "local-session" {
        let mut local = local_dev::Session::resolve(&platform()?, input(&request)?)?;
        local.detach_output();
        let raw = serde_json::to_string(&local.options)?;
        operations.local = Some(local);
        vec!["local-dev-session".into(), raw]
    } else {
        let input: Vec<String> = input(&request)?;
        ensure!(input.len() <= 128, "workflow argument budget");
        let mut arguments = vec!["platform".to_string()];
        arguments.extend(input);
        arguments
    };
    let interactive = arguments
        .first()
        .is_some_and(|arg| arg == "local-dev-session")
        || arguments.get(1).is_some_and(|arg| arg == "local-dev")
        || arguments.get(1).is_some_and(|arg| arg == "authority")
            && arguments.get(2).is_some_and(|arg| arg == "admin")
        // Maintenance reports progress and waits for the operator's confirmation.
        || arguments.get(1).is_some_and(|arg| arg == "maintain")
        || arguments.get(1).is_some_and(|arg| arg == "app-create");
    let args: Vec<_> = arguments.iter().map(String::as_str).collect();
    let runner = day2::automation::checked_runner(
        &std::env::current_exe()?.with_file_name("day2-workflows"),
    )?;
    let effect = |request: day2::automation::Request| {
        operations.effect(Request {
            protocol: request.protocol,
            action: request.action,
            input: request.input,
        })
    };
    let result = if interactive {
        day2::automation::run_interactive(&runner, &args, effect)
    } else {
        day2::automation::run(&runner, &args, effect)
    };
    if let (Err(error), Some(local)) = (&result, &operations.local) {
        local.failed(error);
    }
    if let Some(campaign) = operations.development.as_mut() {
        campaign.persist(result.as_ref().err().map(|error| format!("{error:#}")))?;
    }
    result
}

fn main() {
    let mut streaming = false;
    let outcome = (|| -> Result<Value> {
        let mut args = std::env::args().skip(1);
        let raw = args
            .next()
            .context("one private JSON request is required")?;
        ensure!(
            raw.len() <= 131_072 && args.next().is_none(),
            "private request count or size"
        );
        let request: Request = day2::json::decode(raw.as_bytes())?;
        streaming = request.action == "local-session";
        if request.action == "workflow" {
            let args = input::<Vec<String>>(&request)?;
            streaming = args.first().is_some_and(|value| value == "local-dev")
                || args.first().is_some_and(|value| value == "authority")
                    && args.get(1).is_some_and(|value| value == "admin")
                || args.first().is_some_and(|value| value == "maintain")
                || args.first().is_some_and(|value| value == "app-create");
        }
        run(request)
    })();
    let failed = outcome.is_err();
    let response = match outcome {
        Ok(value) => json!({"protocol":1,"ok":true,"result":value.to_string(),"error":""}),
        Err(error) => json!({"protocol":1,"ok":false,"result":"","error":format!("{error:#}")}),
    };
    if streaming {
        if failed {
            eprintln!(
                "{}",
                response["error"]
                    .as_str()
                    .unwrap_or("local development failed")
            );
        } else {
            println!("{}", response["result"].as_str().unwrap_or("{}"));
        }
    } else {
        println!("{response}");
    }
    if streaming && failed {
        std::process::exit(1);
    }
}
