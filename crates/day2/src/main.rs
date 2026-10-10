#![forbid(unsafe_code)]
use anyhow::{Context, Result, bail};
use day2::{
    artifact::LoadedArtifact,
    protocol::Trace,
    store::{Fault, Runtime, replay},
};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let output = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["oauth-setup", instance] => day2::deployment::oauth_setup(Path::new(instance))?,
        ["docs-preview", artifact, port] => {
            let artifact = LoadedArtifact::load(Path::new(artifact))?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(day2::web::serve_docs_preview(artifact, port.parse()?))?;
            return Ok(());
        }
        ["serve-local", instance, app, actor, port] => {
            let runtime = Runtime::load(Path::new(instance), app)?;
            tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(async {
                let server = day2::web::LocalServer::bind(runtime,actor,port.parse()?).await?;
                println!("{}",serde_json::json!({"origin":server.origin,"login_url":server.login_url,"mcp_url":format!("{}/mcp",server.origin),"mode":"local-development-only"}));
                server.serve(async { let _ = tokio::signal::ctrl_c().await; }).await
            })?;
            return Ok(());
        }
        ["init", instance, app] => {
            let runtime = Runtime::load(Path::new(instance), app)?;
            runtime.initialize()?;
            serde_json::json!({"scope": runtime.scope(), "database": runtime.db(), "artifact": runtime.artifact().id()})
        }
        // What day2-serve admits about the store before it serves, without
        // serving. Maintenance runs it on a migrated and activated copy.
        ["admit", instance, app] => {
            let runtime = Runtime::load(Path::new(instance), app)?;
            day2::deployment::admit_store(&runtime)?;
            serde_json::json!({"admitted": true, "scope": runtime.scope(), "artifact": runtime.artifact().id()})
        }
        ["invoke", instance, app, operation, actor, id, input] => {
            let runtime = Runtime::load(Path::new(instance), app)?;
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
            serde_json::to_value(runtime.invoke(
                operation,
                actor,
                id,
                &serde_json::from_str(input)?,
                now,
                Fault::None,
            )?)?
        }
        ["import", instance, app, operation, operator, source] => {
            let runtime = Runtime::load(Path::new(instance), app)?;
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
            let source = std::io::BufReader::new(fs::File::open(source)?);
            // The report goes to stdout line by line, so it is the mapping from
            // source keys to new ids; the summary follows it.
            let summary = day2::import::run(
                &runtime,
                operation,
                operator,
                source,
                now,
                std::io::stdout().lock(),
            )?;
            let refused = summary.refused;
            println!("{}", serde_json::to_string(&summary)?);
            if refused > 0 {
                std::process::exit(2);
            }
            return Ok(());
        }
        ["resume", instance, app, id] => serde_json::to_value(
            Runtime::load(Path::new(instance), app)?.execute(id, Fault::None)?,
        )?,
        ["inspect", instance, app] => Runtime::load(Path::new(instance), app)?.inspect()?,
        ["audit-events", instance, app, actor, before] => {
            let mut events = Runtime::load(Path::new(instance), app)?
                .audit_events(actor, before.parse().context("invalid audit cursor")?)?;
            let has_more = events.len() > 50;
            events.truncate(50);
            let next_before = events.last().map_or(0, |event| event.sequence);
            serde_json::json!({"items":events,"has_more":has_more,"next_before":next_before})
        }
        ["check-properties", instance, app, evidence_dir] => {
            let runtime = Runtime::load(Path::new(instance), app)?;
            serde_json::to_value(day2::properties::require(
                runtime.artifact(),
                &runtime.inspect()?,
                Path::new(evidence_dir),
            )?)?
        }
        ["replay-properties", artifact, path] => {
            let artifact = LoadedArtifact::load(Path::new(artifact))?;
            let evidence = serde_json::from_slice(&fs::read(path)?)?;
            serde_json::to_value(day2::properties::replay(&artifact, &evidence)?)?
        }
        ["describe", instance, app] => serde_json::to_value(
            Runtime::load(Path::new(instance), app)?
                .artifact()
                .contract(),
        )?,
        ["migration-plan", instance, app, target, output] => {
            use std::io::Write;
            let runtime = Runtime::load(Path::new(instance), app)?;
            let target = LoadedArtifact::load(Path::new(target))?;
            let plan = day2::migration::plan(&runtime, &target)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            file.write_all(&serde_json::to_vec_pretty(&plan)?)?;
            file.sync_all()?;
            serde_json::json!({"plan":output,"id":plan.id()?})
        }
        ["migration-apply", instance, app, target, input] => {
            let runtime = Runtime::load(Path::new(instance), app)?;
            let target = LoadedArtifact::load(Path::new(target))?;
            let plan = serde_json::from_slice(&fs::read(input)?)?;
            day2::migration::apply(&runtime, &target, &plan)?;
            serde_json::json!({"applied":true,"activation_required":target.id()})
        }
        [
            "activate",
            instance,
            app,
            target,
            operator,
            expected,
            request_id,
        ] => {
            let runtime = Runtime::load(Path::new(instance), app)?;
            let target = LoadedArtifact::load(Path::new(target))?;
            let receipt = day2::migration::activate_checked(
                &runtime,
                &target,
                &day2::authority_state::LocalOperator::assert_local(operator)?,
                &day2::json::decode(expected.as_bytes())?,
                request_id,
            )?;
            serde_json::json!({"activated":target.id(),"receipt":receipt,"mode":"local-operator-only"})
        }
        ["trace", instance, app, id] => {
            serde_json::to_value(Runtime::load(Path::new(instance), app)?.trace(id)?)?
        }
        ["replay", artifact, trace] => {
            let trace: Trace = serde_json::from_slice(&fs::read(trace)?)?;
            replay(&LoadedArtifact::load(Path::new(artifact))?, &trace)?;
            serde_json::json!({"replayed": trace.request.context.invocation_id})
        }
        ["lab-crash", instance, app, id, write] => {
            let write = write.parse().context("write index")?;
            serde_json::to_value(
                Runtime::load(Path::new(instance), app)?
                    .execute(id, Fault::ExitAfterWrite(write))?,
            )?
        }
        _ => bail!(
            "usage: day2 init INSTANCE APP | admit INSTANCE APP | invoke INSTANCE APP OPERATION ACTOR ID JSON | resume INSTANCE APP ID | inspect INSTANCE APP | audit-events INSTANCE APP ACTOR BEFORE | describe INSTANCE APP | check-properties INSTANCE APP EVIDENCE_DIR | replay-properties ARTIFACT EVIDENCE | trace INSTANCE APP ID | replay ARTIFACT TRACE | migration-plan INSTANCE APP TARGET PLAN_FILE | migration-apply INSTANCE APP TARGET PLAN_FILE | activate INSTANCE APP TARGET LOCAL_OPERATOR EXPECTED_STAMP_JSON REQUEST_ID | lab-crash INSTANCE APP ID WRITE_INDEX"
        ),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
