//! Reviewed credential metadata for a one-shot operator tooling container.
//! Secret files stay outside the package and are mounted read-only at identical
//! paths in tooling and runtime. Registration never contacts the provider.
use super::*;
use day2_capabilities::{InstallationControl, integrations::LiveConnection, resources::VersionRef};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

const ROOT: &str = "/srv/day2";
const MAX_INPUT: u64 = 1_048_576;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSource {
    pub credential_ref: VersionRef,
    pub source_file: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provisioning {
    pub tooling_image: String,
    pub operator: String,
    pub credentials: Vec<CredentialSource>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputPin {
    file: String,
    digest: String,
    credential_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    app: String,
    operator: String,
    instance_digest: String,
    inputs: Vec<InputPin>,
}

pub(super) struct Prepared {
    pub operator: Vec<u8>,
    pub plan: Vec<u8>,
    pub inputs: Vec<(String, Vec<u8>)>,
    pub mounts: Vec<Value>,
    pub service: Value,
}

fn reference_key(reference: &VersionRef) -> Result<String> {
    reference.validate()?;
    Ok(crate::assets::hash_part(&crate::digest(&serde_json::to_vec(reference)?))?.into())
}

fn target(reference: &VersionRef) -> Result<String> {
    Ok(format!(
        "/run/day2/credentials/{}",
        reference_key(reference)?
    ))
}

fn secret_digest(path: &Path) -> Result<String> {
    ensure!(
        path.is_absolute() && path.as_os_str().len() <= 4096,
        "credential_source_requires_absolute_path"
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .context("credential_source_unavailable")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() <= 16_384
            && metadata.permissions().mode() & 0o077 == 0,
        "credential_source_requires_private_regular_file"
    );
    let mut bytes = Vec::new();
    file.take(16_385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16_384, "credential_source_budget");
    let token = String::from_utf8(bytes).context("credential_source_encoding")?;
    let token = token.trim_end_matches(['\r', '\n']);
    crate::integrations::Credentials::bearer(token.to_owned())?;
    Ok(crate::digest(token.as_bytes()))
}

fn input_bytes(path: &Path) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "provisioning_input_must_be_regular"
    );
    let mut bytes = Vec::new();
    file.take(MAX_INPUT + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_INPUT, "provisioning_input_budget");
    Ok(bytes)
}

/// One secret the selected app needs mounted: the connection it belongs to and,
/// for any secret other than that connection's outbound credential, which one.
#[derive(Clone, Debug, PartialEq)]
struct Required {
    connection: LiveConnection,
    reference: Option<VersionRef>,
}

impl Required {
    fn credential_ref(&self) -> &VersionRef {
        self.reference
            .as_ref()
            .unwrap_or(self.connection.credential_ref())
    }
}

fn require(required: &mut BTreeMap<String, Required>, secret: Required) -> Result<()> {
    let key = reference_key(secret.credential_ref())?;
    if let Some(previous) = required.insert(key, secret.clone()) {
        ensure!(
            previous == secret,
            "credential_reference_has_conflicting_profiles"
        );
    }
    Ok(())
}

fn connections(
    instance: &Instance,
    app: &str,
    artifact: &LoadedArtifact,
) -> Result<BTreeMap<String, Required>> {
    let resolved = crate::authority_state::AuthorityDocument::resolve(instance, app, artifact)?;
    let mut required = BTreeMap::new();
    for grant in resolved
        .resources
        .operations
        .values()
        .flat_map(|slots| slots.values())
    {
        if let Some(live) = &grant.live {
            require(
                &mut required,
                Required {
                    connection: live.clone(),
                    reference: None,
                },
            )?;
        }
    }
    // A signed endpoint verifies deliveries with its connection's verification
    // secret, which no grant names, so it is provisioned with the outbound
    // credentials. A paused endpoint keeps its connection and so its secret:
    // resuming it then changes no credential.
    let binding = instance.apps.get(app).context("app_not_installed")?;
    for (name, endpoint) in &binding.ingress {
        let live = instance
            .resources
            .as_ref()
            .and_then(|catalog| catalog.connections.get(&endpoint.connection.id))
            .filter(|definition| definition.revision == endpoint.connection.revision)
            .and_then(|definition| definition.live.as_ref())
            .with_context(|| format!("endpoint_connection_missing_or_stale: {name}"))?;
        let reference = live
            .verification_ref()
            .with_context(|| format!("endpoint_connection_has_no_verification_secret: {name}"))?;
        require(
            &mut required,
            Required {
                connection: live.clone(),
                reference: Some(reference.clone()),
            },
        )?;
    }
    Ok(required)
}

pub(super) fn has_live_credentials(
    instance: &Instance,
    app: &str,
    artifact: &LoadedArtifact,
) -> Result<bool> {
    Ok(!connections(instance, app, artifact)?.is_empty())
}

pub(super) fn prepare(
    original: &Instance,
    exported: &Instance,
    artifact: &LoadedArtifact,
    app: &str,
    compose: &Value,
    request: &Provisioning,
) -> Result<Prepared> {
    prepare_connections(
        original,
        exported,
        app,
        compose,
        request,
        connections(exported, app, artifact)?,
    )
}

fn prepare_connections(
    original: &Instance,
    exported: &Instance,
    app: &str,
    compose: &Value,
    request: &Provisioning,
    mut required: BTreeMap<String, Required>,
) -> Result<Prepared> {
    image_digest(&request.tooling_image)?;
    crate::authority::valid_actor(&request.operator)?;
    ensure!(
        original
            .control
            .as_ref()
            .is_some_and(|c| c.operators.contains(&request.operator)),
        "provisioning_installation_admin_required"
    );
    ensure!(
        !required.is_empty() && required.len() <= 64 && request.credentials.len() == required.len(),
        "provisioning_requires_exact_live_credentials"
    );
    let mut operator = exported.clone();
    operator.control = Some(InstallationControl {
        version: 1,
        state_directory: format!("{ROOT}/.state/operator-control"),
        operators: BTreeSet::from([request.operator.clone()]),
        sources: BTreeMap::new(),
        apps: BTreeMap::new(),
        builders: BTreeMap::new(),
        runtimes: BTreeMap::new(),
        secrets: BTreeMap::new(),
    });
    let operator = serde_json::to_vec_pretty(&operator)?;
    Instance::from_bytes(&operator)?;
    let mut inputs = Vec::new();
    let mut pins = Vec::new();
    let mut mounts = Vec::new();
    for source in &request.credentials {
        let key = reference_key(&source.credential_ref)?;
        let secret = required
            .remove(&key)
            .context("provisioning_credential_not_approved_or_duplicate")?;
        let credential_digest = secret_digest(&source.source_file)?;
        let source_file = source.source_file.canonicalize()?;
        let source_file = source_file
            .to_str()
            .context("credential_source_path_encoding")?;
        ensure!(
            !source_file.chars().any(char::is_control),
            "invalid_credential_source_path"
        );
        let destination = target(&source.credential_ref)?;
        let file = format!("credential-{key}.json");
        let input = serde_json::to_vec_pretty(&crate::integration_host::Mount {
            connection: secret.connection,
            // Absent for the outbound credential; a verification secret names
            // itself so that registration cannot install it as a bearer token.
            reference: secret.reference,
            credential_file: PathBuf::from(&destination),
            expected_fingerprint: Some(credential_digest.clone()),
        })?;
        pins.push(InputPin {
            file: file.clone(),
            digest: crate::digest(&input),
            credential_digest,
        });
        inputs.push((file, input));
        // Compose interpolates JSON string values too. These remain literal file
        // names, not environment-variable expressions or shell arguments.
        mounts.push(json!({"type":"bind","source":source_file.replace('$', "$$"),"target":destination,"read_only":true,"bind":{"create_host_path":false}}));
    }
    ensure!(required.is_empty(), "provisioning_missing_credential");
    let plan = serde_json::to_vec_pretty(&Plan {
        version: 1,
        app: app.into(),
        operator: request.operator.clone(),
        instance_digest: crate::digest(&operator),
        inputs: pins,
    })?;
    let mut volumes = mounts.clone();
    volumes.extend([
        json!({"type":"bind","source":"./operator-instance.json","target":format!("{ROOT}/operator-instance.json"),"read_only":true,"bind":{"create_host_path":false}}),
        json!({"type":"bind","source":"./provisioning.json","target":format!("{ROOT}/provisioning.json"),"read_only":true,"bind":{"create_host_path":false}}),
        json!({"type":"bind","source":"./provisioning","target":format!("{ROOT}/provisioning"),"read_only":true,"bind":{"create_host_path":false}}),
        json!({"type":"bind","source":"./artifacts","target":format!("{ROOT}/artifacts"),"read_only":true,"bind":{"create_host_path":false}}),
        json!({"type":"volume","source":"state","target":format!("{ROOT}/.state")}),
    ]);
    let service = json!({
        "image":request.tooling_image,"platform":crate::packaging::deployment_platform()?.docker,"pull_policy":"never","profiles":["operator"],
        "entrypoint":["/workspace/platform/cli/day2"],
        "command":["platform","provision-credentials",format!("{ROOT}/operator-instance.json"),app,request.operator.replace('$', "$$"),format!("{ROOT}/provisioning.json")],
        "working_dir":"/workspace/platform","user":"10001:10001","network_mode":"none","read_only":true,
        "cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],"init":true,
        "mem_limit":536_870_912_u64,"memswap_limit":536_870_912_u64,"cpus":1,"pids_limit":64,
        "tmpfs":["/tmp:rw,exec,nosuid,nodev,mode=1777,size=64m"],"volumes":volumes,
    });
    ensure!(
        compose["services"]["app"]["user"] == "10001:10001"
            && compose["volumes"]["state"].is_object(),
        "provisioning_runtime_identity_mismatch"
    );
    Ok(Prepared {
        operator,
        plan,
        inputs,
        mounts,
        service,
    })
}

/// Read-only validation inside the target tooling container. A private Roc
/// recipe forwards the returned inline Mount JSON in its reviewed order. It
/// never rereads mutable metadata files between validation and registration.
pub fn provisioning_inputs(
    instance_path: &Path,
    app: &str,
    operator: &str,
    plan_path: &Path,
) -> Result<Vec<String>> {
    let instance_bytes = input_bytes(instance_path)?;
    let instance = Instance::from_bytes(&instance_bytes)?;
    let plan: Plan = crate::json::decode(&input_bytes(plan_path)?)?;
    ensure!(
        plan.version == 1
            && plan.app == app
            && plan.operator == operator
            && plan.instance_digest == crate::digest(&instance_bytes)
            && !plan.inputs.is_empty()
            && plan.inputs.len() <= 64,
        "provisioning_plan_mismatch"
    );
    let control = instance
        .control
        .as_ref()
        .context("provisioning_operator_missing")?;
    ensure!(
        control.operators == BTreeSet::from([operator.into()])
            && control.apps.is_empty()
            && control.sources.is_empty()
            && control.builders.is_empty()
            && control.runtimes.is_empty()
            && control.secrets.is_empty(),
        "provisioning_operator_scope_mismatch"
    );
    let parent = instance_path
        .parent()
        .context("provisioning_instance_directory")?;
    ensure!(
        plan_path.parent() == Some(parent),
        "provisioning_plan_directory_mismatch"
    );
    let binding = instance.apps.get(app).context("app_not_installed")?;
    let artifact = LoadedArtifact::load(&parent.join(&binding.artifact))?;
    let mut required = connections(&instance, app, &artifact)?;
    ensure!(
        required.len() == plan.inputs.len(),
        "provisioning_requires_exact_live_credentials"
    );
    let mut inputs = Vec::new();
    for pin in plan.inputs {
        ensure!(
            pin.file.is_ascii()
                && pin.file.starts_with("credential-")
                && pin.file.ends_with(".json")
                && pin.file.len() == 80
                && pin.file[11..75]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "invalid_provisioning_input_name"
        );
        let path = parent.join("provisioning").join(&pin.file);
        let bytes = input_bytes(&path)?;
        ensure!(
            crate::digest(&bytes) == pin.digest,
            "provisioning_input_changed"
        );
        let mount: crate::integration_host::Mount = crate::json::decode(&bytes)?;
        let secret = Required {
            connection: mount.connection.clone(),
            reference: mount.reference.clone(),
        };
        let key = reference_key(secret.credential_ref())?;
        ensure!(
            pin.file == format!("credential-{key}.json")
                && required.remove(&key).as_ref() == Some(&secret)
                && mount.credential_file == Path::new(&target(secret.credential_ref())?),
            "provisioning_connection_changed"
        );
        ensure!(
            mount.expected_fingerprint.as_ref() == Some(&pin.credential_digest)
                && secret_digest(&mount.credential_file)? == pin.credential_digest,
            "provisioning_credential_changed"
        );
        inputs.push(serde_json::to_string(&mount)?);
    }
    ensure!(required.is_empty(), "provisioning_missing_credential");
    Ok(inputs)
}

#[cfg(test)]
#[path = "packaging_credentials_tests.rs"]
mod tests;
