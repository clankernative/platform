//! Disposable fixture construction and read-only evidence for the private
//! Provision.roc container smoke. This module never contacts a provider.
use anyhow::{Context, Result, ensure};
use day2::artifact::{Instance, LoadedArtifact};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    num::NonZeroU16,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

const APP: &str = "reports";
const ACTOR: &str = "alice";
const OPERATOR: &str = "provisioning-smoke-operator";

fn require_identity() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "Linux provisioning smoke required"
    );
    ensure!(
        fs::metadata("/proc/self")?.uid() == 10001,
        "provisioning smoke requires runtime UID"
    );
    Ok(())
}

fn absent_bytes(directory: &Path, secret: &[u8], count: &mut usize) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        *count += 1;
        ensure!(*count <= 20_000, "provisioning smoke file budget");
        if entry.file_type()?.is_dir() {
            absent_bytes(&entry.path(), secret, count)?;
        } else {
            ensure!(
                entry.file_type()?.is_file(),
                "regular package inputs required"
            );
            let bytes = fs::read(entry.path())?;
            ensure!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "credential bytes entered package"
            );
        }
    }
    Ok(())
}

fn desired(
    artifact: &Path,
    root: &Path,
    installation: &str,
    mut policy: day2::authority::Policy,
    mut catalog: Value,
    mut attachments: Value,
) -> Result<Value> {
    // Reports never invokes this slot. Its explicit grant exists only to test
    // packaging and mount selection without provider traffic.
    policy
        .operations
        .get_mut("reports.notify")
        .context("Reports command required")?
        .effects
        .insert("slack.post.v1".into());
    let reference = json!({"id":"smoke-slack-token","revision":1});
    let resource = json!({"id":"smoke-slack","revision":1});
    catalog["connections"]["smoke-slack"] = json!({"revision":1,"provider":"slack","live":{
        "provider":"slack","credential_ref":reference,"workspace_id":"T123"}});
    catalog["resources"]["smoke-slack"] = json!({"revision":1,"connection":resource,
        "target":{"kind":"slack_channel","channel":{"channel_id":"C123"}}});
    catalog["policies"]["smoke-slack"] = json!({"revision":1,"owner":OPERATOR,"actors":[ACTOR],"allowed_apps":[APP],
        "slots":{"provisioning-smoke":{"kind":"slack_channel","allowed_resources":[resource],"actions":["slack_post"],
            "limits":{"max_request_bytes":4096,"max_response_bytes":4096,"max_calls_per_invocation":2},"budgets":[]}}});
    attachments
        .as_array_mut()
        .context("fixture attachments")?
        .push(json!({"policy":resource,"operation":"reports.notify",
        "bindings":{"provisioning-smoke":resource}}));
    Ok(
        json!({"installation":installation,"environment":"disposable","resources":catalog,
        "control":{"version":1,"state_directory":root.join("operator-control"),"operators":[OPERATOR],"sources":{},"apps":{}},
        "apps":{APP:{"artifact":artifact,"readers":[ACTOR],"writers":[ACTOR],"auditors":[ACTOR],
            "authority":policy,"resource_policies":attachments,
            "runtime":{"kind":"linux_sqlite_single_v1","resources":{"memory_mib":512,"cpu_millis":1000,"process_limit":64,"http_concurrency":4,"shutdown_seconds":30}}}}}),
    )
}

/// ROOT is a fresh fixture directory exposed at the same absolute path inside
/// tooling and on the Docker host, preserving literal credential bind sources.
pub fn package(
    artifact_path: &Path,
    root: &Path,
    installation: &str,
    port: u16,
    runtime_image: &str,
    tooling_image: &str,
) -> Result<Value> {
    require_identity()?;
    ensure!(
        root.is_absolute() && !root.exists(),
        "new absolute provisioning fixture root required"
    );
    day2::schema::identifier(installation)?;
    let artifact = LoadedArtifact::load(artifact_path)?;
    artifact.require_current_api()?;
    let policy: day2::authority::Policy = serde_json::from_str(include_str!(
        "../../../fixtures/authority-policies/reports.json"
    ))?;
    let (catalog, attachments) =
        day2::development::resource_fixture_for_artifact(APP, &artifact, &policy)?;
    let desired = desired(
        artifact.directory(),
        root,
        installation,
        policy,
        serde_json::to_value(catalog)?,
        serde_json::to_value(attachments)?,
    )?;
    Instance::from_bytes(&serde_json::to_vec(&desired)?)?;
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    let token_path = root.join("provider-token");
    let token = format!(
        "SYNTHETIC_{}_NOT_A_PROVIDER_CREDENTIAL",
        &day2::digest(root.as_os_str().as_encoded_bytes())[7..]
    );
    let mut token_file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&token_path)?;
    token_file.write_all(token.as_bytes())?;
    token_file.sync_all()?;
    let desired_path = root.join("desired.json");
    fs::write(&desired_path, serde_json::to_vec_pretty(&desired)?)?;
    let provisioning: day2::packaging::Provisioning = serde_json::from_value(json!({
        "tooling_image":tooling_image,"operator":OPERATOR,"credentials":[{"credential_ref":{"id":"smoke-slack-token","revision":1},"source_file":token_path}]}))?;
    let directory = root.join("deployment");
    let missing = day2::packaging::export(
        &desired_path,
        APP,
        ACTOR,
        runtime_image,
        NonZeroU16::new(port).context("provisioning port")?,
        &directory,
    )
    .err()
    .context("live grants require provisioning inputs")?;
    let diagnostic = format!("{missing:#}").replace(&token, "[synthetic token redacted]");
    ensure!(
        missing.to_string() == "live_provider_provisioning_required" && !directory.exists(),
        "live package did not reject missing credential mounts: {diagnostic}"
    );
    day2::packaging::export_with_provisioning(
        &desired_path,
        APP,
        ACTOR,
        runtime_image,
        NonZeroU16::new(port).context("provisioning port")?,
        &directory,
        Some(&provisioning),
    )?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
    let instance = Instance::load(&directory.join("instance.json"))?;
    ensure!(
        instance.control.is_none(),
        "app instance contains operator control"
    );
    let compose: Value = day2::json::decode(&fs::read(directory.join("compose.json"))?)?;
    absent_bytes(&directory, token.as_bytes(), &mut 0)?;
    Ok(
        json!({"directory":directory,"artifact":artifact.id(),"worker":artifact.contract().worker_digest,
        "platform_inventory":day2::security_admission::platform_inventory_digest(&artifact)?,
        "installation":installation,"port":port,"volume":compose["volumes"]["state"]["name"],
        "instance":instance,"credential_bytes_absent":true,"provider_qualified":false,
        "deployment_digest":day2::digest(&fs::read(directory.join("deployment.json"))?)}),
    )
}

/// Run under the runtime UID with the same named state volume and token binds.
/// Only bounded metadata and boolean accessibility evidence leave the helper.
pub fn inspect(instance_path: &Path) -> Result<Value> {
    require_identity()?;
    let instance = Instance::load(instance_path)?;
    ensure!(
        instance.control.is_none(),
        "app instance contains operator control"
    );
    let parent = instance_path.parent().context("instance parent")?;
    let registry = parent.join(".state/provider-credentials.sqlite");
    let connection = Connection::open_with_flags(&registry, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let count: i64 = connection.query_row("SELECT count(*) FROM mounts", [], |row| row.get(0))?;
    ensure!(
        count == 1,
        "exactly one idempotent credential registration required"
    );
    let (profile, path, fingerprint, operator): (String, String, String, String) = connection.query_row(
        "SELECT profile,path,fingerprint,operator FROM mounts WHERE id='smoke-slack-token' AND revision=1", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
    let approved = json!({"provider":"slack","credential_ref":{"id":"smoke-slack-token","revision":1},"workspace_id":"T123"});
    ensure!(
        day2::json::decode::<Value>(profile.as_bytes())? == approved && operator == OPERATOR,
        "registered profile or operator changed"
    );
    let key = day2::digest(&serde_json::to_vec(
        &json!({"id":"smoke-slack-token","revision":1}),
    )?);
    ensure!(
        path == format!("/run/day2/credentials/{}", &key[7..]),
        "runtime credential target changed"
    );
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.uid() == 10001 && metadata.permissions().mode() & 0o077 == 0,
        "credential mount ownership or mode changed"
    );
    let mut token = Vec::new();
    fs::File::open(&path)?
        .take(16_385)
        .read_to_end(&mut token)?;
    ensure!(
        token.len() <= 16_384 && day2::digest(&token) == fingerprint,
        "registered token inaccessible or changed"
    );
    let artifact = LoadedArtifact::load(
        &parent.join(
            &instance
                .apps
                .get(APP)
                .context("Reports instance required")?
                .artifact,
        ),
    )?;
    let document = day2::authority_state::AuthorityDocument::resolve(&instance, APP, &artifact)?;
    let mut database = Connection::open_with_flags(
        parent.join(".state/reports.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let tx = database.transaction()?;
    let active = day2::authority_state::current(&tx)?;
    ensure!(
        active.artifact_id == artifact.id() && active.document == document,
        "active runtime authority differs from packaged fixture"
    );
    let grant = active
        .document
        .resources
        .operations
        .get("reports.notify")
        .and_then(|slots| slots.get("provisioning-smoke"))
        .context("live fixture grant missing")?;
    ensure!(
        serde_json::to_value(&grant.live)? == approved,
        "runtime live profile differs from registration"
    );
    Ok(
        json!({"registered_versions":count,"uid":10001,"registry_accessible":true,
        "credential_accessible":true,"profile_matches_authority":true,"app_control_absent":true,
        "provider_qualified":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_desired_uses_the_instance_and_live_resource_contracts() -> Result<()> {
        let policy: day2::authority::Policy = serde_json::from_str(include_str!(
            "../../../fixtures/authority-policies/reports.json"
        ))?;
        let (catalog, attachments) =
            day2::development::local_resource_fixture(APP, &policy, None, None)?;
        let value = desired(
            Path::new("/fixture/artifact"),
            Path::new("/fixture"),
            "smoke",
            policy,
            serde_json::to_value(catalog)?,
            serde_json::to_value(attachments)?,
        )?;
        let instance = Instance::from_bytes(&serde_json::to_vec(&value)?)?;
        let control = instance
            .control
            .as_ref()
            .context("operator control missing")?;
        assert!(
            control.sources.is_empty()
                && control.apps.is_empty()
                && control.builders.is_empty()
                && control.runtimes.is_empty()
                && control.secrets.is_empty()
        );
        assert!(control.operators.contains(OPERATOR));
        let binding = &instance.apps[APP];
        let catalog = instance
            .resources
            .as_ref()
            .context("live catalog missing")?;
        let resolved = catalog.resolve(APP, &binding.resource_policies, 0)?;
        let grant = &resolved.operations["reports.notify"]["provisioning-smoke"];
        assert_eq!(
            serde_json::to_value(&grant.live)?,
            json!({"provider":"slack",
            "credential_ref":{"id":"smoke-slack-token","revision":1},"workspace_id":"T123"})
        );
        assert_eq!(
            serde_json::to_value(&grant.target)?,
            json!({"kind":"slack_channel","channel":{"channel_id":"C123"}})
        );
        assert_eq!(serde_json::to_value(&grant.actions)?, json!(["slack_post"]));
        for field in ["sources", "apps"] {
            let mut invalid = value.clone();
            invalid["control"].as_object_mut().unwrap().remove(field);
            let error = Instance::from_bytes(&serde_json::to_vec(&invalid)?).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("missing field `{field}`"))
            );
        }
        Ok(())
    }
}
