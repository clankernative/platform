//! Atomic export of a selected installation app, never a deployment or data copy.

use crate::{
    artifact::{Instance, LoadedArtifact},
    branding::LoadedBrand,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    num::NonZeroU16,
    path::{Path, PathBuf},
};

const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;

#[path = "packaging_credentials.rs"]
mod credentials;
pub use credentials::{CredentialSource, Provisioning, provisioning_inputs};

fn image_digest(value: &str) -> Result<()> {
    crate::assets::hash_part(value)?;
    Ok(())
}

/// The Linux platform a deployment packaged here runs on: this build's own
/// architecture. Packaging, like qualification, is native, so the worker and
/// image it packages are the ones this host built and qualified.
pub(crate) struct DeploymentPlatform {
    /// `docker --platform` / Compose `platform` value.
    pub docker: &'static str,
    /// ELF `e_machine` of a worker built for it.
    elf_machine: u16,
    label: &'static str,
}

pub(crate) fn deployment_platform() -> Result<DeploymentPlatform> {
    Ok(match std::env::consts::ARCH {
        "aarch64" => DeploymentPlatform {
            docker: "linux/arm64",
            elf_machine: 183,
            label: "ARM64",
        },
        "x86_64" => DeploymentPlatform {
            docker: "linux/amd64",
            elf_machine: 62,
            label: "x86_64",
        },
        other => anyhow::bail!("no Linux deployment platform for {other}"),
    })
}

fn linux_worker(path: &Path, platform: &DeploymentPlatform) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "regular worker required"
    );
    let mut header = [0u8; 64];
    File::open(path)?.read_exact(&mut header)?;
    ensure!(
        &header[..4] == b"\x7fELF"
            && header[4] == 2
            && header[5] == 1
            && header[6] == 1
            && matches!(header[7], 0 | 3)
            && matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
            && u16::from_le_bytes([header[18], header[19]]) == platform.elf_machine,
        "deployment requires a Linux {} ELF worker",
        platform.label
    );
    Ok(())
}

fn write_input(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o444))?;
    file.sync_all()?;
    Ok(())
}

fn copy_tree(
    source: &Path,
    target: &Path,
    count: &mut usize,
    bytes: &mut u64,
    depth: usize,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        depth <= 16 && fs::symlink_metadata(source)?.is_dir(),
        "regular bounded input tree required"
    );
    fs::create_dir(target)?;
    let mut entries: Vec<_> = fs::read_dir(source)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        *count += 1;
        ensure!(*count <= 16_384, "deployment input file budget");
        let kind = entry.file_type()?;
        let output = target.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &output, count, bytes, depth + 1)?;
        } else {
            ensure!(
                kind.is_file(),
                "deployment input symlinks and special files forbidden"
            );
            let remaining = MAX_BUNDLE_BYTES
                .checked_sub(*bytes)
                .context("deployment byte budget")?;
            let mut source = File::open(entry.path())?.take(remaining + 1);
            let mut destination = File::create(&output)?;
            *bytes += std::io::copy(&mut source, &mut destination)?;
            ensure!(*bytes <= MAX_BUNDLE_BYTES, "deployment byte budget");
            destination.set_permissions(fs::Permissions::from_mode(0o444))?;
            destination.sync_all()?;
        }
    }
    // Mounts enforce read-only inputs in the container. Keep owner-writable
    // directories so an interrupted private staging tree can be removed.
    fs::set_permissions(target, fs::Permissions::from_mode(0o755))?;
    File::open(target)?.sync_all()?;
    Ok(())
}

fn compose(
    instance: &Instance,
    app: &str,
    actor: &str,
    image: &str,
    port: NonZeroU16,
) -> Result<Value> {
    image_digest(image)?;
    ensure!(
        !actor.is_empty() && actor.len() <= 256,
        "invalid development actor"
    );
    // Compose interpolates values even in JSON; the actor is literal argv.
    let actor = actor.replace('$', "$$");
    let binding = instance.apps.get(app).context("app not installed")?;
    let profile = binding
        .runtime
        .as_ref()
        .context("runtime profile required")?;
    profile.validate()?;
    let resources = profile.resources();
    let scope = crate::digest(instance.scope(app)?.as_bytes());
    let hash = crate::assets::hash_part(&scope)?;
    let project = format!("day2-{hash}");
    let mut volumes = vec![
        json!({"type":"bind","source":"./instance.json","target":"/srv/day2/instance.json","read_only":true,"bind":{"create_host_path":false}}),
        json!({"type":"bind","source":"./artifacts","target":"/srv/day2/artifacts","read_only":true,"bind":{"create_host_path":false}}),
        json!({"type":"volume","source":"state","target":"/srv/day2/.state"}),
    ];
    if instance.branding.is_some() {
        volumes.push(json!({"type":"bind","source":"./branding","target":"/srv/day2/branding","read_only":true,"bind":{"create_host_path":false}}));
    }
    Ok(json!({
        "name":project,
        "services":{"app":{
            "image":image,"platform":deployment_platform()?.docker,"pull_policy":"never","user":"10001:10001",
            "entrypoint":["/usr/local/bin/day2-serve"],
            "command":["/srv/day2/instance.json",app,"--development-auth",actor,"--published-port",port.to_string()],
            "init":true,"restart":"unless-stopped","read_only":true,"cap_drop":["ALL"],
            "security_opt":["no-new-privileges:true"],"cgroup":"private",
            "ports":[{"target":8080,"published":port.to_string(),"host_ip":"127.0.0.1","protocol":"tcp"}],
            "mem_limit":u64::from(resources.memory_mib())*1024*1024,
            "memswap_limit":u64::from(resources.memory_mib())*1024*1024,
            "cpus":f64::from(resources.cpu_millis())/1000.0,"pids_limit":resources.process_limit(),
            "stop_grace_period":format!("{}s",u32::from(resources.shutdown_seconds())+2),
            "tmpfs":["/tmp:rw,exec,nosuid,nodev,mode=1777,size=64m"],
            "volumes":volumes,
            "healthcheck":{"test":["CMD","/usr/local/bin/day2-health",port.to_string()],"interval":"5s","timeout":"3s","start_period":"10s","retries":3}
        }},
        "volumes":{"state":{"name":format!("day2-state-{hash}"),"driver":"local"}}
    }))
}

fn publish(stage: &Path, destination: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        stage,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .context("deployment output must not exist")?;
    File::open(destination.parent().context("deployment parent")?)?.sync_all()?;
    Ok(())
}

pub fn export(
    instance_path: &Path,
    app: &str,
    actor: &str,
    image: &str,
    port: NonZeroU16,
    output: &Path,
) -> Result<PathBuf> {
    export_with_provisioning(instance_path, app, actor, image, port, output, None)
}

/// Optional explicit credential provisioning is separate from app authority and
/// source installation state. The original export API retains its exact default.
#[allow(clippy::too_many_arguments)]
pub fn export_with_provisioning(
    instance_path: &Path,
    app: &str,
    actor: &str,
    image: &str,
    port: NonZeroU16,
    output: &Path,
    provisioning: Option<&Provisioning>,
) -> Result<PathBuf> {
    image_digest(image)?;
    ensure!(
        fs::symlink_metadata(output)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "deployment output must be new"
    );
    ensure!(
        fs::symlink_metadata(instance_path)?.is_file(),
        "instance must be a regular file"
    );
    let instance_path = instance_path.canonicalize()?;
    let original = Instance::load(&instance_path)?;
    // This bundle signs in with the development link. An installation that
    // declares an identity provider is served behind it or not at all, so it
    // has no development bundle to export.
    ensure!(
        original.identity.is_none(),
        "development_export_refused_with_identity"
    );
    let binding = original.apps.get(app).context("app not installed")?;
    binding
        .runtime
        .as_ref()
        .context("runtime profile required")?
        .validate()?;
    let artifact = LoadedArtifact::load(
        &instance_path
            .parent()
            .context("instance root")?
            .join(&binding.artifact),
    )?;
    artifact.require_current_api()?;
    if let Some(requirements) = &binding.security {
        requirements.validate(&artifact)?;
        requirements.require_image(image)?;
    }
    linux_worker(
        &artifact.directory().join("worker"),
        &deployment_platform()?,
    )?;
    let policy = binding
        .authority
        .as_ref()
        .context("host authority policy required")?;
    policy.validate(&artifact.contract().operations, &artifact.contract().schema)?;
    ensure!(
        artifact
            .contract()
            .operations
            .iter()
            .any(
                |operation| matches!(operation.kind.as_str(), "command" | "query")
                    && original.authorize(app, operation, actor).is_ok()
            ),
        "development actor has no admitted operation"
    );
    let branding = LoadedBrand::for_instance(&instance_path)?;
    let mut selected = binding.clone();
    selected.artifact = format!("artifacts/{}", crate::assets::hash_part(artifact.id())?);
    let selected_branding = branding
        .as_ref()
        .map(|brand| {
            Ok::<_, anyhow::Error>(format!("branding/{}", crate::assets::hash_part(&brand.id)?))
        })
        .transpose()?;
    let instance = Instance {
        installation: original.installation.clone(),
        environment: original.environment.clone(),
        branding: selected_branding,
        control: None,
        resources: original.resources.clone(),
        identity: None,
        security_shell: None,
        oauth_shell_transport: None,
        oauth_clients: None,
        apps: BTreeMap::from([(app.into(), selected)]),
    };
    let instance_bytes = serde_json::to_vec_pretty(&instance)?;
    Instance::from_bytes(&instance_bytes)?;
    ensure!(
        provisioning.is_some() || !credentials::has_live_credentials(&instance, app, &artifact)?,
        "live_provider_provisioning_required"
    );
    let mut compose = compose(&instance, app, actor, image, port)?;
    let provisioning = provisioning
        .map(|request| {
            credentials::prepare(&original, &instance, &artifact, app, &compose, request)
        })
        .transpose()?;
    if let Some(provisioning) = &provisioning {
        compose["services"]["app"]["volumes"]
            .as_array_mut()
            .context("deployment volumes")?
            .extend(provisioning.mounts.clone());
        compose["services"]["provision-credentials"] = provisioning.service.clone();
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent.canonicalize()?;
    let output = parent.join(output.file_name().context("deployment output name")?);
    let stage = tempfile::Builder::new()
        .prefix(".day2-package-")
        .tempdir_in(&parent)?;
    fs::create_dir(stage.path().join("artifacts"))?;
    let mut file_count = 0;
    let mut byte_count = 0;
    copy_tree(
        artifact.directory(),
        &stage.path().join(&instance.apps[app].artifact),
        &mut file_count,
        &mut byte_count,
        0,
    )?;
    ensure!(
        LoadedArtifact::load(&stage.path().join(&instance.apps[app].artifact))?.id()
            == artifact.id(),
        "artifact changed during packaging"
    );
    if let Some(brand) = branding {
        fs::create_dir(stage.path().join("branding"))?;
        let target = stage
            .path()
            .join(instance.branding.as_ref().context("brand binding")?);
        copy_tree(
            &brand.directory,
            &target,
            &mut file_count,
            &mut byte_count,
            0,
        )?;
        ensure!(
            LoadedBrand::load(&target)?.id == brand.id,
            "branding changed during packaging"
        );
    }
    write_input(&stage.path().join("instance.json"), &instance_bytes)?;
    write_input(
        &stage.path().join("compose.json"),
        &serde_json::to_vec_pretty(&compose)?,
    )?;
    let mut deployment = json!({
        "format":1,"mode":"container-development-auth","scope":instance.scope(app)?,
        "app":app,"artifact":artifact.id(),"image":image,
        "instance_digest":crate::digest(&instance_bytes),"compose_digest":crate::digest(&serde_json::to_vec_pretty(&compose)?)
    });
    if let Some(provisioning) = provisioning {
        write_input(
            &stage.path().join("operator-instance.json"),
            &provisioning.operator,
        )?;
        write_input(&stage.path().join("provisioning.json"), &provisioning.plan)?;
        fs::create_dir(stage.path().join("provisioning"))?;
        for (name, input) in provisioning.inputs {
            write_input(&stage.path().join("provisioning").join(name), &input)?;
        }
        File::open(stage.path().join("provisioning"))?.sync_all()?;
        deployment["provisioning_digest"] = json!(crate::digest(&provisioning.plan));
        deployment["operator_instance_digest"] = json!(crate::digest(&provisioning.operator));
    }
    write_input(
        &stage.path().join("deployment.json"),
        &serde_json::to_vec_pretty(&deployment)?,
    )?;
    File::open(stage.path())?.sync_all()?;
    publish(stage.path(), &output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance() -> Instance {
        serde_json::from_value(json!({"installation":"example","environment":"development","apps":{"reports":{
            "artifact":"artifacts/pinned","readers":["reader"],"writers":["operator"],
            "runtime":{"kind":"linux_sqlite_single_v1","resources":{"memory_mib":512,"cpu_millis":1000,"process_limit":64,"http_concurrency":4,"shutdown_seconds":30}}
        }}})).unwrap()
    }

    #[test]
    fn compose_has_exact_image_loopback_resources_and_no_shell() -> Result<()> {
        let instance = instance();
        let image = format!("sha256:{}", "a".repeat(64));
        let value = compose(
            &instance,
            "reports",
            "operator",
            &image,
            NonZeroU16::new(18080).unwrap(),
        )?;
        let app = &value["services"]["app"];
        assert_eq!(app["image"], image);
        assert_eq!(
            app["command"],
            json!([
                "/srv/day2/instance.json",
                "reports",
                "--development-auth",
                "operator",
                "--published-port",
                "18080"
            ])
        );
        assert_eq!(app["ports"][0]["host_ip"], "127.0.0.1");
        assert_eq!(app["mem_limit"], 536870912u64);
        assert_eq!(app["pids_limit"], 64);
        assert_eq!(app["cgroup"], "private");
        assert_eq!(
            app["healthcheck"]["test"],
            json!(["CMD", "/usr/local/bin/day2-health", "18080"])
        );
        assert_eq!(
            compose(
                &instance,
                "reports",
                "account${HOME}",
                &image,
                NonZeroU16::new(1).unwrap()
            )?["services"]["app"]["command"][3],
            "account$${HOME}"
        );
        for image in ["latest", "day2:latest", "sha256:short"] {
            assert!(
                compose(
                    &instance,
                    "reports",
                    "operator",
                    image,
                    NonZeroU16::new(1).unwrap()
                )
                .is_err()
            );
        }
        let mut other = instance.clone();
        other.installation = "other_company".into();
        assert_ne!(
            value["volumes"]["state"]["name"],
            compose(
                &other,
                "reports",
                "operator",
                &image,
                NonZeroU16::new(1).unwrap()
            )?["volumes"]["state"]["name"]
        );
        Ok(())
    }

    #[test]
    fn publish_is_atomic_and_cannot_replace_even_an_empty_directory() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let stage = parent.path().join("stage");
        fs::create_dir(&stage)?;
        fs::write(stage.join("complete"), "approved")?;
        let output = parent.path().join("output");
        fs::create_dir(&output)?;
        assert!(publish(&stage, &output).is_err());
        assert!(stage.join("complete").exists());
        fs::remove_dir(&output)?;
        publish(&stage, &output)?;
        assert_eq!(fs::read(output.join("complete"))?, b"approved");
        Ok(())
    }

    #[test]
    fn worker_platform_gate_rejects_macos_and_wrong_architecture() -> Result<()> {
        let arm = DeploymentPlatform {
            docker: "linux/arm64",
            elf_machine: 183,
            label: "ARM64",
        };
        let x86 = DeploymentPlatform {
            docker: "linux/amd64",
            elf_machine: 62,
            label: "x86_64",
        };
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("worker");
        let mut bytes = [0u8; 64];
        fs::write(&path, bytes)?;
        assert!(linux_worker(&path, &arm).is_err());
        assert!(linux_worker(&path, &x86).is_err());
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16] = 3;
        bytes[18] = 183;
        fs::write(&path, bytes)?;
        linux_worker(&path, &arm)?;
        assert!(linux_worker(&path, &x86).is_err());
        bytes[18] = 62;
        fs::write(&path, bytes)?;
        linux_worker(&path, &x86)?;
        assert!(linux_worker(&path, &arm).is_err());
        Ok(())
    }

    #[test]
    fn the_deployment_platform_is_this_build_s_own() -> Result<()> {
        let expected = match std::env::consts::ARCH {
            "aarch64" => "linux/arm64",
            "x86_64" => "linux/amd64",
            _ => return Ok(()),
        };
        assert_eq!(deployment_platform()?.docker, expected);
        Ok(())
    }
}
