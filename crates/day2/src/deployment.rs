//! One guarded Linux container per SQLite app. This is development authentication,
//! not an enterprise identity adapter or a high-availability storage profile.

use crate::{artifact::Instance, store::Runtime, web::LocalServer};
use anyhow::{Context, Result, ensure};
use day2_capabilities::runtime::{Resources, RuntimeProfile};
use std::{
    fs::{self, File, OpenOptions},
    num::NonZeroU16,
    path::{Component, Path, PathBuf},
    time::Duration,
};

const PROC_BUDGET: u64 = 1_048_576;

/// Read-only desired metadata for the native OAuth runtime. This emits pins and
/// callback URLs, never readiness and never client or custody secret bytes.
pub fn oauth_setup(instance_path: &Path) -> Result<serde_json::Value> {
    crate::oauth::admission::live::setup(instance_path)
}

const SHELL_RUNNER: &str = "/usr/local/lib/day2/day2-workflows";

fn shell_layout(instance_path: &Path) -> Result<(PathBuf, Resources)> {
    ensure!(
        fs::symlink_metadata(instance_path)?.file_type().is_file(),
        "instance must be a regular file"
    );
    let instance_path = instance_path.canonicalize()?;
    let instance = Instance::load(&instance_path)?;
    instance.security_edge()?;
    crate::oauth::admission::live::validate(&instance)?;
    let resources = instance
        .oauth_runtime
        .as_ref()
        .context("OAuth runtime missing")?
        .shell_resources
        .clone()
        .context("security shell resources missing")?;
    resources.validate()?;
    instance
        .oauth_shell_transport
        .as_ref()
        .context("OAuth shell transport missing")?
        .validate()?;
    ensure!(
        instance
            .apps
            .values()
            .any(|app| !app.oauth_connections.is_empty()),
        "security shell has no selected connections"
    );
    let root = instance_path.parent().context("installation root")?;
    for app in instance
        .apps
        .values()
        .filter(|app| !app.oauth_connections.is_empty())
    {
        artifact_directory(root, &root.join(&app.artifact))?;
    }
    if let Ok(expected) = std::env::var("DAY2_EXPECTED_SHELL_INSTANCE") {
        ensure!(
            expected == crate::digest(&fs::read(&instance_path)?),
            "security shell instance changed"
        );
    }
    Ok((instance_path, resources))
}

fn shell_mount_guards(mounts: &str, instance_path: &Path, runner: &Path) -> Result<()> {
    let root = instance_path.parent().context("installation root")?;
    let runner_root = runner.parent().context("workflow runner directory")?;
    ensure!(
        read_only_tree(mounts, root)? && read_only_tree(mounts, runner_root)?,
        "security shell requires read-only installation and workflow mounts"
    );
    ensure!(
        fs::symlink_metadata(runner)?.file_type().is_file()
            && fs::symlink_metadata(runner.with_extension("json"))?
                .file_type()
                .is_file(),
        "security shell workflows must be regular files"
    );
    Ok(())
}

/// Dedicated stateless GKE shell. No app runtime, database, principal session,
/// custody provider or writable installation volume is mounted by this host.
pub async fn serve_security_shell(instance_path: &Path) -> Result<()> {
    let (instance_path, resources) = shell_layout(instance_path)?;
    ensure!(cfg!(target_os = "linux"), "security shell requires Linux");
    container_cgroup_preflight(&resources)?;
    shell_mount_guards(
        &bounded_text(Path::new("/proc/self/mountinfo"))?,
        &instance_path,
        Path::new(SHELL_RUNNER),
    )?;
    let shell = tokio::task::spawn_blocking(move || {
        crate::oauth::security_shell::SecurityShell::from_gke_runtime(
            &instance_path,
            Path::new(SHELL_RUNNER),
        )
    })
    .await
    .context("security shell startup failed")??
    .shell;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 8080)).await?;
    let admission = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let mut http = tokio::spawn(shell.serve_bounded(
        listener,
        usize::from(resources.http_concurrency()),
        admission.clone(),
        async {
            let _ = shutdown_rx.await;
        },
    ));
    println!(
        "{}",
        serde_json::json!({"mode":"security-shell", "replicas":1})
    );
    let mut finished = false;
    let cause = tokio::select! {
        signal = termination() => signal,
        result = &mut http => {
            finished = true;
            result.context("security shell HTTP supervisor failed").and_then(|result| result)
                .and_then(|()| anyhow::bail!("security shell HTTP server stopped unexpectedly"))
        },
    };
    admission.store(false, std::sync::atomic::Ordering::Release);
    let _ = shutdown_tx.send(());
    if !finished {
        tokio::time::timeout(
            Duration::from_secs(u64::from(resources.shutdown_seconds())),
            &mut http,
        )
        .await
        .context("security shell shutdown grace exceeded")?
        .context("security shell HTTP drain failed")??;
    }
    cause
}

fn bounded_text(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut value = String::new();
    File::open(path)?
        .take(PROC_BUDGET + 1)
        .read_to_string(&mut value)?;
    ensure!(
        value.len() as u64 <= PROC_BUDGET,
        "kernel metadata byte budget"
    );
    Ok(value)
}

fn positive(value: &str) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "finite numeric cgroup limit required"
    );
    let value = value.parse::<u64>()?;
    ensure!(value > 0, "positive cgroup limit required");
    Ok(value)
}

fn validate_cgroups(resources: &Resources, memory: &str, cpu: &str, pids: &str) -> Result<()> {
    ensure!(
        positive(memory.trim())? <= u64::from(resources.memory_mib()) * 1024 * 1024,
        "container memory exceeds admitted profile"
    );
    // By default the container's own bound is the one held to the profile.
    // When the operator has declared that the pod's orchestrator holds the
    // bound, the container's view is not the enforcing limit: the kubelet
    // bounds the pod cgroup above the container's cgroup namespace, and the
    // container runtime may still write its own looser value (containerd 2
    // on GKE writes a node-derived one). It must still read as a limit.
    let pids = pids.trim();
    if resources.process_limit_enforced_by()
        == day2_capabilities::runtime::ProcessLimitEnforcement::Pod
    {
        ensure!(
            pids == "max" || positive(pids).is_ok(),
            "invalid cgroup process limit"
        );
    } else {
        ensure!(
            positive(pids)? <= u64::from(resources.process_limit()),
            "container process limit exceeds admitted profile"
        );
    }
    let cpu: Vec<_> = cpu.split_whitespace().collect();
    ensure!(cpu.len() == 2, "invalid cgroup CPU limit");
    ensure!(
        u128::from(positive(cpu[0])?) * 1000
            <= u128::from(positive(cpu[1])?) * u128::from(resources.cpu_millis()),
        "container CPU exceeds admitted profile"
    );
    Ok(())
}

fn decode_mount_path(value: &str) -> Result<PathBuf> {
    let mut bytes = Vec::new();
    let mut input = value.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        if byte == b'\\' {
            let escape = [input.next(), input.next(), input.next()];
            bytes.push(match escape {
                [Some(b'0'), Some(b'4'), Some(b'0')] => b' ',
                [Some(b'0'), Some(b'1'), Some(b'1')] => b'\t',
                [Some(b'0'), Some(b'1'), Some(b'2')] => b'\n',
                [Some(b'1'), Some(b'3'), Some(b'4')] => b'\\',
                _ => anyhow::bail!("invalid mount path escape"),
            });
        } else {
            bytes.push(byte);
        }
    }
    Ok(PathBuf::from(String::from_utf8(bytes)?))
}

fn read_only_mount(mounts: &str, path: &Path) -> Result<bool> {
    let mut selected = None;
    for line in mounts.lines() {
        let (left, _) = line.split_once(" - ").context("invalid mount metadata")?;
        let fields: Vec<_> = left.split_whitespace().collect();
        ensure!(fields.len() >= 6, "invalid mount metadata fields");
        let mount = decode_mount_path(fields[4])?;
        ensure!(mount.is_absolute(), "invalid mount root");
        if path.starts_with(&mount) {
            let depth = mount.components().count();
            let options: Vec<_> = fields[5].split(',').collect();
            ensure!(
                options.contains(&"ro") != options.contains(&"rw"),
                "ambiguous mount access"
            );
            if selected
                .as_ref()
                .is_none_or(|(previous, _)| depth >= *previous)
            {
                selected = Some((depth, options.contains(&"ro")));
            }
        }
    }
    selected
        .map(|(_, read_only)| read_only)
        .context("path has no mount")
}

fn read_only_tree(mounts: &str, root: &Path) -> Result<bool> {
    if !read_only_mount(mounts, root)? {
        return Ok(false);
    }
    for line in mounts.lines() {
        let (left, _) = line.split_once(" - ").context("invalid mount metadata")?;
        let fields: Vec<_> = left.split_whitespace().collect();
        ensure!(fields.len() >= 6, "invalid mount metadata fields");
        let mount = decode_mount_path(fields[4])?;
        if mount.starts_with(root) && fields[5].split(',').any(|option| option == "rw") {
            return Ok(false);
        }
    }
    Ok(true)
}

fn regular_path(root: &Path, relative: &Path, directory: bool) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    let components: Vec<_> = relative.components().collect();
    ensure!(!components.is_empty(), "empty deployment path");
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            anyhow::bail!("deployment paths must remain below the installation root");
        };
        path.push(component);
        let kind = fs::symlink_metadata(&path)?.file_type();
        ensure!(
            if index + 1 == components.len() && !directory {
                kind.is_file()
            } else {
                kind.is_dir()
            },
            "deployment path must not contain symlinks or special files"
        );
    }
    Ok(path)
}

fn artifact_directory(root: &Path, path: &Path) -> Result<PathBuf> {
    let relative = path
        .strip_prefix(root)
        .context("active deployment artifact must remain below installation root")?;
    let artifact_id = relative
        .to_str()
        .context("deployment artifact path encoding")?
        .strip_prefix("artifacts/")
        .context("deployment artifact path")?;
    ensure!(
        artifact_id.len() == 64
            && artifact_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "deployment artifact must be content-addressed beneath artifacts"
    );
    regular_path(root, relative, true)
}

fn layout(instance_path: &Path, app: &str) -> Result<(PathBuf, RuntimeProfile, PathBuf)> {
    ensure!(
        fs::symlink_metadata(instance_path)?.file_type().is_file(),
        "instance must be a regular file"
    );
    let instance_path = instance_path.canonicalize()?;
    let instance = Instance::load(&instance_path)?;
    let binding = instance.apps.get(app).context("app_not_installed")?;
    let profile = binding
        .runtime
        .clone()
        .context("deployment profile required")?;
    profile.validate()?;
    let root = instance_path.parent().context("installation root")?;
    let state = regular_path(root, Path::new(profile.state_directory()), true)?;
    let database = Path::new(profile.state_directory()).join(format!("{app}.sqlite"));
    let active = if root.join(&database).exists() {
        let database = regular_path(root, &database, false)?;
        let connection = rusqlite::Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        crate::authority_state::exists(&connection)?
            .then(|| crate::authority_state::current(&connection))
            .transpose()?
    } else {
        None
    };
    let artifact = active.as_ref().map_or_else(
        || root.join(&binding.artifact),
        |active| PathBuf::from(&active.artifact_path),
    );
    artifact_directory(root, &artifact)?;
    if let Some(active) = active {
        ensure!(
            artifact.file_name().and_then(|name| name.to_str())
                == Some(crate::assets::hash_part(&active.artifact_id)?),
            "active deployment artifact address mismatch"
        );
    }
    if let Some(branding) = &instance.branding {
        regular_path(root, Path::new(branding), true)?;
    }
    Ok((instance_path, profile, state))
}

fn replica_lock(state: &Path, app: &str) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    crate::schema::identifier(app)?;
    let path = state.join(format!("{app}.serve.lock"));
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        ensure!(metadata.is_file(), "invalid runtime lease file");
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    file.try_lock()
        .context("another server owns this SQLite app")?;
    Ok(file)
}

/// The container's own cgroup, checked against the profile exactly as
/// `day2-serve` checks it before serving. Public so a probe on a real node can
/// run this code rather than a restatement of it.
pub fn container_cgroup_preflight(resources: &Resources) -> Result<()> {
    ensure!(
        bounded_text(Path::new("/proc/self/cgroup"))?.trim() == "0::/",
        "private cgroup v2 namespace required"
    );
    validate_cgroups(
        resources,
        &bounded_text(Path::new("/sys/fs/cgroup/memory.max"))?,
        &bounded_text(Path::new("/sys/fs/cgroup/cpu.max"))?,
        &bounded_text(Path::new("/sys/fs/cgroup/pids.max"))?,
    )
}

fn kernel_guards(instance_path: &Path, state: &Path, resources: &Resources) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "Linux runtime profile requires Linux"
    );
    container_cgroup_preflight(resources)?;
    let mounts = bounded_text(Path::new("/proc/self/mountinfo"))?;
    let root = instance_path.parent().context("installation root")?;
    ensure!(
        read_only_mount(&mounts, instance_path)?
            && read_only_tree(&mounts, &root.join("artifacts"))?
            && !read_only_mount(&mounts, state)?,
        "read-only instance/artifacts and writable state mounts required"
    );
    if let Some(branding) = Instance::load(instance_path)?.branding {
        ensure!(
            read_only_tree(&mounts, &root.join(branding))?,
            "read-only branding required"
        );
    }
    Ok(())
}

async fn termination() -> Result<()> {
    #[cfg(unix)]
    {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = signal.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    anyhow::bail!("Linux runtime profile requires Unix signals")
}

/// How requests to a served container come to be from someone.
pub enum Access<'a> {
    /// A one-use sign-in link for one actor, on a loopback-published port.
    Development {
        actor: &'a str,
        published_port: NonZeroU16,
    },
    /// Behind the installation's identity provider, at the app's edge address.
    Edge,
}

pub async fn serve(instance_path: &Path, app: &str, access: Access<'_>) -> Result<()> {
    serve_with_oauth(instance_path, app, access, None).await
}

/// The enforcing container lifecycle with host-owned adapter installation.
/// Configuration runs after the runtime and its active authority are checked,
/// before either HTTP admission or background execution starts.
pub async fn serve_with(
    instance_path: &Path,
    app: &str,
    access: Access<'_>,
    configure: impl FnOnce(Runtime) -> Result<Runtime> + Send + 'static,
) -> Result<()> {
    serve_configured(instance_path, app, access, None, configure).await
}

/// Native adapters are selected from the typed instance contract only after
/// kernel, artifact and current authority admission. Registration starts empty.
pub(crate) async fn serve_with_oauth(
    instance_path: &Path,
    app: &str,
    access: Access<'_>,
    providers: Option<crate::oauth::host::Providers>,
) -> Result<()> {
    serve_configured(instance_path, app, access, providers, Ok).await
}

async fn serve_configured(
    instance_path: &Path,
    app: &str,
    access: Access<'_>,
    providers: Option<crate::oauth::host::Providers>,
    configure: impl FnOnce(Runtime) -> Result<Runtime> + Send + 'static,
) -> Result<()> {
    // Decided from the instance before anything else. An installation that
    // declares an identity provider has no development mode: if it did, the
    // provider would be one flag away from optional.
    let declared = Instance::load(instance_path)?;
    let oauth = crate::oauth::host::require_providers(
        &declared,
        app,
        matches!(access, Access::Edge),
        providers.as_ref(),
    )?;
    match access {
        Access::Development { .. } => ensure!(
            declared.identity.is_none(),
            "development_auth_refused_with_identity"
        ),
        Access::Edge => {
            declared.edge(app)?;
        }
    }
    let (instance_path, profile, state) = layout(instance_path, app)?;
    kernel_guards(&instance_path, &state, profile.resources())?;
    crate::worker::qualify_sandbox()?;
    let _lease = replica_lock(&state, app)?;
    let runtime = Runtime::load(&instance_path, app)?;
    // Runtime loading samples the active database binding independently. Check
    // the actual selected code too, so activation between layout and load cannot
    // select a writable artifact outside the kernel-guarded read-only tree.
    let root = instance_path.parent().context("installation root")?;
    artifact_directory(root, runtime.artifact().directory())?;
    ensure!(
        runtime
            .artifact()
            .directory()
            .file_name()
            .and_then(|name| name.to_str())
            == Some(crate::assets::hash_part(runtime.artifact().id())?),
        "active deployment artifact address mismatch"
    );
    runtime.initialize()?;
    if let Ok(expected) = std::env::var("DAY2_EXPECTED_ARTIFACT") {
        ensure!(
            expected == runtime.artifact().id(),
            "deployment_artifact_changed"
        );
    }
    let authority = crate::authority_state::current(&crate::store::open(runtime.db())?)?;
    if let Some(requirements) = &authority.document.security {
        requirements.validate(runtime.artifact())?;
        requirements.require_runtime()?;
    }
    let runtime = tokio::task::spawn_blocking(move || configure(runtime)).await??;
    let concurrency = usize::from(profile.resources().http_concurrency());
    let receiver = if oauth {
        let runtime = runtime.clone();
        Some(
            tokio::task::spawn_blocking(move || {
                let providers = match providers {
                    Some(providers) => providers,
                    None => crate::oauth::host::Providers::from_gke_runtime(&runtime)?,
                };
                crate::oauth::host::app_receiver(&runtime, &providers)
            })
            .await
            .context("OAuth host startup failed")??,
        )
    } else {
        None
    };
    let server = match access {
        Access::Development {
            actor,
            published_port,
        } => {
            let server =
                LocalServer::bind_container(runtime, actor, published_port, concurrency).await?;
            println!(
                "{}",
                serde_json::json!({
                    "mode":"container-development-auth", "login_url":server.login_url,
                    "origin":server.origin, "replicas":profile.replicas()
                })
            );
            server
        }
        Access::Edge => {
            let (identity, edge) = declared.edge(app)?;
            let mut server = LocalServer::bind_edge(runtime, identity, edge, concurrency).await?;
            if let Some(receiver) = receiver {
                server.mount_oauth(receiver)?;
            }
            println!(
                "{}",
                serde_json::json!({
                    "mode":"edge", "scheme":identity.scheme,
                    "origin":server.origin, "replicas":profile.replicas()
                })
            );
            server
        }
    };
    let admission = server.admission();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let mut http = tokio::spawn(server.serve(async {
        let _ = shutdown_rx.await;
    }));
    let mut http_finished = false;
    let cause = tokio::select! {
        signal = termination() => signal,
        result = &mut http => {
            http_finished = true;
            result.context("HTTP supervisor failed").and_then(|result| result)
                .and_then(|()| anyhow::bail!("HTTP server stopped unexpectedly"))
        },
    };
    // Stop admission and new claims first. Existing requests/work may finish;
    // pending intents remain in SQLite and are picked up after the next start.
    admission.stop();
    let _ = shutdown_tx.send(());
    let drain = async {
        if !http_finished {
            (&mut http)
                .await
                .context("HTTP drain failed")
                .and_then(|result| result)
        } else {
            Ok(())
        }
    };
    tokio::time::timeout(
        Duration::from_secs(u64::from(profile.resources().shutdown_seconds())),
        drain,
    )
    .await
    .context("shutdown grace exceeded; pending work remains recoverable")??;
    cause
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shell_layout_and_mount_guards_refuse_writable_app_storage_and_missing_bounds() -> Result<()>
    {
        let selected = crate::oauth::admission::live::tests::selected()?;
        let mut instance = selected.instance().clone();
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let artifact = format!("artifacts/{}", "a".repeat(64));
        fs::create_dir_all(root.join(&artifact))?;
        instance.apps.get_mut("workspace").unwrap().artifact = artifact;
        let path = root.join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        assert!(shell_layout(&path).is_err());
        instance.oauth_runtime.as_mut().unwrap().shell_resources =
            Some(profile().resources().clone());
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        assert_eq!(shell_layout(&path)?.1.http_concurrency(), 4);
        let runner_dir = root.join("workflow");
        fs::create_dir(&runner_dir)?;
        let runner = runner_dir.join("day2-workflows");
        fs::write(&runner, b"private runner fixture")?;
        fs::write(runner.with_extension("json"), b"{}")?;
        let mounts = "1 0 0:1 / / ro - rootfs rootfs ro\n";
        shell_mount_guards(mounts, &path, &runner)?;
        for writable in [
            root.to_path_buf(),
            root.join(".state"),
            root.join("artifacts"),
            runner_dir,
        ] {
            let mounts = format!(
                "{mounts}2 1 0:2 / {} rw - tmpfs tmpfs rw\n",
                writable.display()
            );
            assert!(shell_mount_guards(&mounts, &path, &runner).is_err());
        }
        instance.apps.get_mut("workspace").unwrap().artifact = "../outside".into();
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        assert!(shell_layout(&path).is_err());
        Ok(())
    }

    fn profile() -> RuntimeProfile {
        serde_json::from_value(json!({"kind":"linux_sqlite_single_v1","resources":{
            "memory_mib":512,"cpu_millis":1000,"process_limit":64,
            "http_concurrency":4,"shutdown_seconds":30
        }}))
        .unwrap()
    }

    #[test]
    fn cgroup_limits_must_be_finite_and_no_weaker_than_profile() -> Result<()> {
        let profile = profile();
        validate_cgroups(
            profile.resources(),
            "536870912\n",
            "100000 100000\n",
            "64\n",
        )?;
        for (memory, cpu, pids) in [
            ("max", "100000 100000", "64"),
            ("536870913", "100000 100000", "64"),
            ("536870912", "max 100000", "64"),
            ("536870912", "100001 100000", "64"),
            ("536870912", "100000 0", "64"),
            ("536870912", "100000 100000 extra", "64"),
            ("536870912", "100000 100000", "65"),
            ("536870912", "100000 100000", "max"),
        ] {
            assert!(validate_cgroups(profile.resources(), memory, cpu, pids).is_err());
        }
        Ok(())
    }

    #[test]
    fn a_pod_enforced_process_limit_does_not_hold_the_container_view_to_the_profile() -> Result<()>
    {
        let pod: RuntimeProfile = serde_json::from_value(
            json!({"kind":"linux_sqlite_single_v1","resources":{
                "memory_mib":512,"cpu_millis":1000,"process_limit":64,"process_limit_enforced_by":"pod",
                "http_concurrency":4,"shutdown_seconds":30
            }}),
        )?;
        let (memory, cpu) = ("536870912", "100000 100000");
        // Kubernetes bounds the pod above the container's cgroup namespace.
        validate_cgroups(pod.resources(), memory, cpu, "max\n")?;
        // The container runtime's own value is not the enforcing bound.
        validate_cgroups(pod.resources(), memory, cpu, "64")?;
        validate_cgroups(pod.resources(), memory, cpu, "629145\n")?;
        assert!(validate_cgroups(pod.resources(), memory, cpu, "0").is_err());
        assert!(validate_cgroups(pod.resources(), memory, cpu, "").is_err());
        assert!(validate_cgroups(pod.resources(), memory, cpu, "-1").is_err());
        // The declaration covers processes only: memory and CPU stay observed.
        assert!(validate_cgroups(pod.resources(), "max", cpu, "max").is_err());
        assert!(validate_cgroups(pod.resources(), memory, "max 100000", "max").is_err());
        // Without the declaration, the container's bound is held to the profile.
        assert!(validate_cgroups(profile().resources(), memory, cpu, "max").is_err());
        assert!(validate_cgroups(profile().resources(), memory, cpu, "629145").is_err());
        Ok(())
    }

    #[test]
    fn longest_mount_controls_access_and_paths_decode_without_traversal() -> Result<()> {
        let mounts = "1 0 0:1 / / ro - overlay overlay ro\n2 1 0:2 / /srv/app/.state rw - ext4 volume rw\n3 1 0:3 / /srv/with\\040space ro - ext4 source ro\n";
        assert!(read_only_mount(
            mounts,
            Path::new("/srv/app/instance.json")
        )?);
        assert!(!read_only_mount(
            mounts,
            Path::new("/srv/app/.state/app.sqlite")
        )?);
        assert!(read_only_mount(mounts, Path::new("/srv/with space/data"))?);
        assert!(!read_only_tree(mounts, Path::new("/srv/app"))?);
        assert!(read_only_tree(mounts, Path::new("/srv/app/artifacts"))?);
        assert!(decode_mount_path("/bad\\099escape").is_err());
        assert!(read_only_mount("invalid", Path::new("/")).is_err());
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join(".state"))?;
        assert!(regular_path(root.path(), Path::new("../escape"), true).is_err());
        assert!(regular_path(root.path(), Path::new("/absolute"), true).is_err());
        Ok(())
    }

    #[test]
    fn a_second_replica_cannot_open_the_same_state_volume() -> Result<()> {
        let root = tempfile::tempdir()?;
        let first = replica_lock(root.path(), "reports")?;
        assert!(replica_lock(root.path(), "reports").is_err());
        drop(first);
        replica_lock(root.path(), "reports")?;
        assert!(replica_lock(root.path(), "../escape").is_err());
        Ok(())
    }

    #[test]
    fn installation_layout_is_instance_bound_without_path_or_backend_overrides() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        let id = "a".repeat(64);
        fs::create_dir_all(root.join("artifacts").join(&id))?;
        fs::create_dir(root.join(".state"))?;
        let instance = root.join("instance.json");
        let approved = json!({
            "installation":"example", "environment":"development",
            "apps":{"reports":{
                "artifact":format!("artifacts/{id}"),"readers":["demo"],"writers":["demo"],
        "runtime":profile()
            }}
        });
        fs::write(&instance, serde_json::to_vec(&approved)?)?;
        let (actual, selected, state) = layout(&instance, "reports")?;
        assert_eq!(actual, instance.canonicalize()?);
        assert_eq!(selected, profile());
        assert_eq!(state, root.canonicalize()?.join(".state"));
        assert!(layout(&instance, "other_app").is_err());
        for path in [
            "../artifacts/escape",
            "/absolute",
            "artifacts/../escape",
            "artifacts/unpinned",
        ] {
            let mut invalid = approved.clone();
            invalid["apps"]["reports"]["artifact"] = path.into();
            fs::write(&instance, serde_json::to_vec(&invalid)?)?;
            assert!(layout(&instance, "reports").is_err());
        }
        let mut missing = approved.clone();
        missing["apps"]["reports"]
            .as_object_mut()
            .context("app binding")?
            .remove("runtime");
        fs::write(&instance, serde_json::to_vec(&missing)?)?;
        assert!(layout(&instance, "reports").is_err());
        let mut temporal = approved.clone();
        temporal["apps"]["reports"]["background"] = json!({
            "kind":"temporal","endpoint":"http://127.0.0.1:7233",
            "namespace":"default","task_queue":"reports"
        });
        fs::write(&instance, serde_json::to_vec(&temporal)?)?;
        assert!(layout(&instance, "reports").is_err());
        fs::write(&instance, serde_json::to_vec(&approved)?)?;
        fs::remove_dir(root.join(".state"))?;
        assert!(layout(&instance, "reports").is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("artifacts"), root.join(".state"))?;
            assert!(layout(&instance, "reports").is_err());
        }
        Ok(())
    }

    #[test]
    fn deployed_active_artifact_uses_database_binding_and_stays_in_read_only_tree() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let hash = "a".repeat(64);
        let active = root.join("artifacts").join(&hash);
        fs::create_dir_all(&active)?;
        fs::create_dir(root.join(".state"))?;
        let instance = root.join("instance.json");
        fs::write(
            &instance,
            serde_json::to_vec(&json!({
                "installation":"example", "environment":"development",
                "apps":{"reports":{
                    "artifact":"not-yet-activated", "readers":[], "writers":[], "runtime":profile()
                }}
            }))?,
        )?;
        let mut db = rusqlite::Connection::open(root.join(".state/reports.sqlite"))?;
        let tx = db.transaction()?;
        crate::authority_state::upgrade(&tx)?;
        tx.execute(
            "INSERT INTO day2_authority VALUES(1,?1,1,?2,?3,?4)",
            rusqlite::params![
                crate::digest(b"layout-test"),
                json!({"enabled":false,"readers":[],"writers":[],"policy":null}).to_string(),
                format!("sha256:{hash}"),
                active.to_string_lossy()
            ],
        )?;
        tx.commit()?;
        layout(&instance, "reports")?;
        // A content-addressed directory in writable state is still inadmissible.
        let writable = root.join(".state").join(&hash);
        fs::create_dir(&writable)?;
        db.execute(
            "UPDATE day2_authority SET artifact_path=?1",
            [writable.to_string_lossy()],
        )?;
        assert!(layout(&instance, "reports").is_err());
        // A directory name that disagrees with the admitted ID is also rejected.
        db.execute(
            "UPDATE day2_authority SET artifact_path=?1,artifact_id=?2",
            rusqlite::params![
                active.to_string_lossy(),
                format!("sha256:{}", "b".repeat(64))
            ],
        )?;
        assert!(layout(&instance, "reports").is_err());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_cannot_run_the_deployment_profile() {
        assert!(
            kernel_guards(
                Path::new("/instance.json"),
                Path::new("/.state"),
                profile().resources()
            )
            .is_err()
        );
    }
}
