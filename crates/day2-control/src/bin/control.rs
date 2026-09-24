//! Local operator entry point. This is not an authenticated production network service.
use anyhow::{Context, Result, ensure};
use day2::artifact::Instance;
use day2_capabilities::ControlScope;
use day2_control::{
    Digest, GitOid, Name,
    local_build::{BuildRuntime, PreparedBuild},
    local_source::{SourceBundle, SourceChange},
    service::Service,
};
use std::{fs, io::Write, path::Path};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() >= 5 && args[0] == "--local",
        "usage: control --local INSTANCE ACTOR APP OPERATION [ARGS]; local actor assertion only, no production authentication"
    );
    let path = Path::new(&args[1]);
    let actor = &args[2];
    let app = Name::try_from(args[3].clone())?;
    let operation = args[4].as_str();
    let rest = &args[5..];
    let original_instance = fs::read(path)?;
    let mut instance = Instance::load(path)?;
    ensure!(
        fs::read(path)? == original_instance,
        "instance changed while loading"
    );
    let configuration = instance
        .control
        .clone()
        .context("installation has no control capabilities")?;
    let service = Service::open(
        ControlScope {
            installation: Name::try_from(instance.installation.clone())?,
            environment: Name::try_from(instance.environment.clone())?,
        },
        configuration,
        instance.apps.keys().map(String::as_str),
    )?;
    let handle = service.authorize(actor, &app)?;
    match (operation, rest) {
        ("export", [request, directory]) => {
            let status = service.submit(
                &handle,
                Name::try_from(request.clone())?,
                SourceChange::Export {
                    bundle: SourceBundle::capture(Path::new(directory))?,
                },
            )?;
            print_json(&status)?;
        }
        ("propose", [request, base, directory]) => {
            let status = service.submit(
                &handle,
                Name::try_from(request.clone())?,
                SourceChange::Propose {
                    base: GitOid::try_from(base.clone())?,
                    bundle: SourceBundle::capture(Path::new(directory))?,
                },
            )?;
            print_json(&status)?;
        }
        ("status", [id]) => print_json(&service.status(&handle, &Digest::try_from(id.clone())?)?)?,
        ("run", [id]) => print_json(&service.advance(&handle, &Digest::try_from(id.clone())?)?)?,
        ("run-pending", []) => {
            for id in service.pending(&handle)? {
                print_json(&service.advance(&handle, &id)?)?;
            }
        }
        ("build-pin", [builder, runtime]) | ("build-pin", [builder, runtime, _]) => {
            ensure!(
                rest.len() == 2 || rest[2] == "--write",
                "build-pin accepts only optional --write"
            );
            let prepared = PreparedBuild::capture(
                &service,
                &handle,
                &Name::try_from(builder.clone())?,
                &Name::try_from(runtime.clone())?,
            )?;
            if rest.len() == 3 {
                ensure!(
                    !fs::symlink_metadata(path)?.file_type().is_symlink(),
                    "instance config symlink forbidden"
                );
                instance
                    .control
                    .as_mut()
                    .context("control config")?
                    .apps
                    .get_mut(&app)
                    .context("app control config")?
                    .build = Some(prepared.profile().clone());
                instance
                    .control
                    .as_ref()
                    .context("control config")?
                    .validate(instance.apps.keys().map(String::as_str))?;
                let parent = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                let mut output = tempfile::NamedTempFile::new_in(parent)?;
                output.write_all(&serde_json::to_vec_pretty(&instance)?)?;
                output.write_all(b"\n")?;
                output.as_file().sync_all()?;
                ensure!(
                    fs::read(path)? == original_instance,
                    "instance changed during build pinning"
                );
                output.persist(path)?;
                fs::File::open(parent)?.sync_all()?;
            }
            print_json(prepared.profile())?;
        }
        ("build-submit", [request, commit]) => {
            let runtime = BuildRuntime::open(&service, &handle)?;
            let id = service.submit_build(
                &handle,
                &runtime.host,
                Name::try_from(request.clone())?,
                GitOid::try_from(commit.clone())?,
            )?;
            print_json(&serde_json::json!({"execution":id,"state":"accepted"}))?;
        }
        ("build-status", [id]) => {
            let id = Digest::try_from(id.clone())?;
            let execution = service.build_status(&handle, &id)?;
            let accepted_by = service.build_provenance(&handle, &id)?;
            print_json(
                &serde_json::json!({"execution":execution.id,"state":execution.state,"app":execution.plan.app,"commit":execution.plan.commit,"accepted_by":accepted_by}),
            )?;
        }
        ("build-run", [id]) => {
            let id = Digest::try_from(id.clone())?;
            service.build_status(&handle, &id)?;
            let runtime = BuildRuntime::open(&service, &handle)?;
            print_json(&runtime.run(&id).await?)?;
        }
        _ => anyhow::bail!(
            "operations: export REQUEST SOURCE_DIR; propose REQUEST BASE_COMMIT SOURCE_DIR; status ID; run ID; run-pending; build-pin BUILDER RUNTIME [--write]; build-submit REQUEST COMMIT; build-status ID; build-run ID"
        ),
    }
    Ok(())
}
fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
