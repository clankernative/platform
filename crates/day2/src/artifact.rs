pub const CURRENT_FORMAT: u32 = 14;

use crate::{digest, schema::Schema};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub name: String,
    pub kind: String,
    pub input_type: String,
    #[serde(default)]
    pub output_type: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub name: String,
    pub title: String,
    pub operation: String,
    pub defaults: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub template: String,
    #[serde(default)]
    pub input_type: String,
    #[serde(default)]
    pub output_type: String,
    #[serde(default)]
    pub live: bool,
    #[serde(default)]
    pub live_refresh_ms: u64,
}

/// A declared schedule. The artifact records what the author wrote; the occurrence
/// source that will act on it is not built yet, so nothing here runs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub name: String,
    pub operation: String,
    pub input: String,
    #[serde(default)]
    pub input_type: String,
    pub interval_ms: u64,
    pub anchor_hour: i64,
    pub missed: String,
    #[serde(default)]
    pub catch_up_bound: u64,
}

impl Schedule {
    /// Refuse a schedule an author could not have meant, at admission rather than
    /// at the first occurrence -- a schedule that fails only when it fires fails
    /// unobserved, at an hour nobody is watching.
    pub fn validate(&self, artifact: &Artifact) -> Result<()> {
        // The name reaches the invocation id, which accepts a narrow alphabet.
        crate::schema::identifier(&self.name)?;
        ensure!(
            self.interval_ms >= crate::schedules::MINIMUM_INTERVAL_MS as u64,
            "schedule interval is below the platform minimum"
        );
        ensure!(
            self.interval_ms <= 366 * 24 * 60 * 60 * 1_000,
            "schedule interval exceeds the platform maximum"
        );
        // Anything daily or coarser needs an anchor: "every day" measured from the
        // last run drifts after every outage, which makes the occurrence identity
        // unstable and defeats the exactly-once derivation.
        let daily = self.interval_ms >= 24 * 60 * 60 * 1_000;
        ensure!(
            daily == (self.anchor_hour >= 0),
            "a daily schedule requires a UTC anchor hour, and a shorter one cannot take it"
        );
        ensure!(
            (-1..24).contains(&self.anchor_hour),
            "schedule anchor hour is outside the UTC day"
        );
        match self.missed.as_str() {
            "coalesce" => ensure!(
                self.catch_up_bound == 0,
                "a coalescing schedule takes no catch-up bound"
            ),
            "run_each" => ensure!(
                (1..=64).contains(&self.catch_up_bound),
                "a catch-up bound must be between 1 and 64"
            ),
            _ => bail!("schedule requires a declared missed-occurrence policy"),
        }
        let command = artifact
            .operations
            .iter()
            .find(|op| op.name == self.operation && op.kind == "command")
            .context("schedule requires a registered command")?;
        // A schedule has no caller and no request. Binding a publicly reachable
        // command would give it a second, unauthenticated entry point.
        ensure!(
            artifact.internal_command(&command.name),
            "schedule requires an internal command"
        );
        ensure!(
            command.input_type == self.input_type,
            "schedule input type differs from the bound command"
        );
        // The fixed input is checked here because there is no request to check it
        // against later.
        artifact.schema.inputs[&command.input_type]
            .validate_input(&serde_json::from_str(&self.input).context("schedule input")?)?;
        Ok(())
    }
}

/// A declared webhook endpoint. The artifact records what the author wrote; the
/// route that will verify deliveries against it is not built yet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub name: String,
    pub operation: String,
    #[serde(default)]
    pub input_type: String,
    /// The registered provider capability, such as `slack.events.v1`. The provider
    /// owns the signature scheme, the envelope and the rule identifying a delivery.
    pub provider: String,
}

impl Endpoint {
    /// Refuse an endpoint that could not mean what it says, at admission rather
    /// than at the first delivery — a webhook that fails only when it fires fails
    /// against a provider that will retry into the same failure.
    pub fn validate(&self, artifact: &Artifact) -> Result<()> {
        // The name reaches the derived invocation identity, whose alphabet is narrow.
        crate::schema::identifier(&self.name)?;
        ensure!(
            crate::ingress::PROVIDERS.contains(&self.provider.as_str()),
            "endpoint names an unregistered ingress provider: {}",
            self.provider
        );
        let command = artifact
            .operations
            .iter()
            .find(|op| op.name == self.operation && op.kind == "command")
            .context("endpoint requires a registered command")?;
        // A delivery has no caller. Binding a publicly reachable command would give
        // it a second entry point that no request authorised.
        ensure!(
            artifact.internal_command(&command.name),
            "endpoint requires an internal command"
        );
        ensure!(
            command.input_type == self.input_type,
            "endpoint input type differs from the bound command"
        );
        Ok(())
    }
}

impl Page {
    pub fn validate_live(&self) -> Result<()> {
        ensure!(
            self.live || self.live_refresh_ms == 0,
            "live refresh interval requires a live page"
        );
        ensure!(
            self.live_refresh_ms == 0 || (1_000..=60_000).contains(&self.live_refresh_ms),
            "live refresh interval must be between 1000 and 60000 milliseconds"
        );
        ensure!(
            !self.live || !self.template.is_empty(),
            "live page requires an admitted template"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub format: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_contract: Option<crate::app_contract::Definition>,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub declarations: crate::registry::Catalog,
    #[serde(default)]
    pub checked_types_digest: String,
    pub roc_version: String,
    pub worker_digest: String,
    pub schema_digest: String,
    pub schema: Schema,
    #[serde(default)]
    pub identities: crate::identity::Registry,
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub properties: Vec<String>,
    #[serde(default)]
    pub pages: Vec<Page>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schedules: Vec<Schedule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<Endpoint>,
    #[serde(default)]
    pub assets: crate::assets::Catalog,
    #[serde(default)]
    pub web_resources: crate::web_resources::Catalog,
    #[serde(default)]
    pub outputs: crate::output_schema::Catalog,
    #[serde(default)]
    pub templates: crate::web_templates::Catalog,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub api_docs: crate::api_docs::Catalog,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub operation_metadata: crate::operation_metadata::Catalog,
    pub sources: BTreeMap<String, String>,
    pub admission: String,
}

impl Artifact {
    pub fn internal_command(&self, name: &str) -> bool {
        self.app_contract
            .as_ref()
            .and_then(|definition| definition.operations.get(name))
            .is_some_and(|operation| operation.execution.internal)
    }

    pub fn page_context_schema(&self, page: &Page) -> Result<crate::output_schema::Type> {
        page.validate_live()?;
        crate::schema::identifier(&page.name)?;
        ensure!(
            !["company", "asset"].contains(&page.name.as_str())
                && (self.format < 7 || !["routes", "platform"].contains(&page.name.as_str())),
            "reserved page context name"
        );
        crate::schema::identifier(&page.output_type)?;
        if self.format < 7 {
            ensure!(
                page.template == format!("pages/{}.html", page.name),
                "page template path must follow its registered name"
            );
        } else {
            ensure!(
                page.template.starts_with("pages/") && page.template.ends_with(".html"),
                "registered page requires a page template handle"
            );
        }
        let output = self
            .outputs
            .get(&page.output_type)
            .context("page requires registered output contract")?;
        let query = self
            .operations
            .iter()
            .find(|operation| operation.kind == "query" && operation.name == page.operation)
            .context("page requires registered query")?;
        if self.format >= 7 {
            ensure!(
                query.input_type == page.input_type,
                "page and query input handles must match"
            );
        }
        ensure!(
            query.output_type == page.output_type,
            "page and query output handles must match"
        );
        Ok(crate::output_schema::Type::Record(BTreeMap::from([
            (page.name.clone(), output.shape.template_shape()),
            (
                "company".into(),
                crate::output_schema::Type::Record(BTreeMap::from([(
                    "name".into(),
                    crate::output_schema::Type::String,
                )])),
            ),
        ])))
    }
}

#[derive(Clone)]
pub struct LoadedArtifact {
    id: String,
    directory: PathBuf,
    contract: Artifact,
    executable: Arc<Mutex<Option<PrivateWorker>>>,
}

/// The admitted worker bytes, the private copy executed from them, and the
/// identity of the artifact file they were hashed from.
struct PrivateWorker {
    path: Arc<tempfile::TempPath>,
    admitted: Vec<u8>,
    source: Identity,
}

/// Enough of a file's identity to tell "the same file, untouched" from anything
/// else: replacement changes the inode, truncation or extension the size, an
/// in-place write the modification time, and a chmod the mode.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    modified: i64,
    modified_nanoseconds: i64,
}

impl Identity {
    fn of(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            mode: metadata.mode(),
            modified: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }
}

#[cfg(test)]
impl LoadedArtifact {
    /// Host-boundary unit tests supply a contract without launching a compiler.
    /// This constructor is absent from production and is not artifact admission.
    pub(crate) fn from_contract_for_tests(
        id: String,
        directory: PathBuf,
        contract: Artifact,
    ) -> Self {
        Self {
            id,
            directory,
            contract,
            executable: Arc::default(),
        }
    }
}

// Re-derivation prevents manifest drift from retained compiler evidence. Matching
// hashes establish consistency, not a signature proving a trusted build.
fn validate_checked_contracts(directory: &Path, contract: &Artifact) -> Result<()> {
    const MAX_CHECKED_TYPES: u64 = 4 * 1_024 * 1_024;
    let path = directory.join("checked-types.json");
    ensure!(
        fs::symlink_metadata(&path)?.file_type().is_file(),
        "checked compiler metadata must be a regular file"
    );
    let mut checked = Vec::new();
    fs::File::open(&path)?
        .take(MAX_CHECKED_TYPES + 1)
        .read_to_end(&mut checked)?;
    ensure!(
        checked.len() as u64 <= MAX_CHECKED_TYPES,
        "checked compiler metadata byte budget"
    );
    ensure!(
        digest(&checked) == contract.checked_types_digest,
        "checked compiler metadata digest mismatch"
    );
    let mut schema = Schema::from_checked_types(&checked)?;
    let mut outputs = crate::output_schema::from_checked_types(&checked)?;
    if contract.format >= 11 {
        let path = directory.join(crate::identity::REGISTRY_FILE);
        ensure!(
            fs::symlink_metadata(&path)?.file_type().is_file(),
            "invalid_model_registry_file"
        );
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(128_001)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 128_000, "model_registry_budget");
        ensure!(
            contract
                .sources
                .get(&format!("app/{}", crate::identity::REGISTRY_FILE))
                == Some(&digest(&bytes))
                && serde_json::from_slice::<crate::identity::Registry>(&bytes)?
                    == contract.identities,
            "model_registry_evidence_mismatch"
        );
        schema.bind_identities(&contract.identities)?;
        for output in outputs.values_mut() {
            output.shape.bind_identities(&schema)?;
        }
    }
    ensure!(
        schema == contract.schema,
        "schema differs from checked compiler metadata"
    );
    ensure!(
        outputs == contract.outputs,
        "output catalog differs from checked compiler metadata"
    );
    ensure!(
        crate::registry::from_checked_types(&checked)? == contract.declarations,
        "declaration catalog differs from checked compiler metadata"
    );
    Ok(())
}

impl LoadedArtifact {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn contract(&self) -> &Artifact {
        &self.contract
    }

    pub fn require_current_api(&self) -> Result<()> {
        ensure!(
            self.contract.format == CURRENT_FORMAT,
            "artifact_upgrade_required"
        );
        Ok(())
    }

    pub fn load(directory: &Path) -> Result<Self> {
        let directory = directory.canonicalize()?;
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("artifact.json"))?)?;
        let id = digest(&serde_json::to_vec(&value)?);
        ensure!(
            directory.file_name().and_then(|s| s.to_str()) == id.strip_prefix("sha256:"),
            "artifact directory identity mismatch"
        );
        if value.get("format").and_then(serde_json::Value::as_u64)
            == Some(u64::from(CURRENT_FORMAT))
        {
            for field in [
                "app_contract",
                "namespace",
                "declarations",
                "checked_types_digest",
                "roc_version",
                "worker_digest",
                "schema_digest",
                "schema",
                "identities",
                "operations",
                "properties",
                "pages",
                "assets",
                "web_resources",
                "outputs",
                "templates",
                "sources",
                "admission",
            ] {
                ensure!(
                    value.get(field).is_some_and(|value| !value.is_null()),
                    "current artifact requires {field}"
                );
            }
        }
        let contract: Artifact = serde_json::from_value(value)?;
        ensure!(
            matches!(contract.format, 1..=CURRENT_FORMAT)
                && contract.admission == "local-spike-only",
            "unsupported admission contract"
        );
        ensure!(
            contract.schema.hash()? == contract.schema_digest,
            "schema digest mismatch"
        );
        contract.schema.validate()?;
        if contract.format >= 2 {
            contract.schema.validate_typed()?;
            crate::properties::validate_catalog(&contract.properties)?;
        } else {
            ensure!(
                contract.properties.is_empty(),
                "legacy artifact has property catalog"
            );
        }
        ensure!(
            digest(&fs::read(directory.join("worker"))?) == contract.worker_digest,
            "worker digest mismatch"
        );
        let mut names = BTreeSet::new();
        ensure!(
            !contract.operations.is_empty() && contract.operations.len() <= 128,
            "invalid operation count"
        );
        for operation in &contract.operations {
            ensure!(
                operation.name.len() <= 80
                    && operation
                        .name
                        .split('.')
                        .all(|part| crate::schema::identifier(part).is_ok()),
                "invalid operation name"
            );
            ensure!(names.insert(&operation.name), "duplicate operation name");
            ensure!(
                ["query", "command"].contains(&operation.kind.as_str()),
                "unsupported operation kind"
            );
            ensure!(
                contract.schema.inputs.contains_key(&operation.input_type),
                "unknown input contract"
            );
            if !operation.output_type.is_empty() {
                ensure!(
                    (contract.format >= 6 && operation.kind == "query")
                        || (contract.format >= 10 && operation.kind == "command"),
                    "typed output requires a supported query/command contract"
                );
                crate::schema::identifier(&operation.output_type)?;
                ensure!(
                    contract.outputs.contains_key(&operation.output_type),
                    "unknown query output contract"
                );
            }
        }
        if contract.format >= 10 {
            contract.declarations.validate_artifact(&contract)?;
            validate_checked_contracts(&directory, &contract)?;
        } else {
            ensure!(
                contract.namespace.is_empty()
                    && contract.declarations == crate::registry::Catalog::default()
                    && contract.checked_types_digest.is_empty(),
                "legacy artifact has declaration catalog"
            );
        }
        // Establish the compiler-proven core before validating its annotations.
        crate::api_docs::validate(
            &contract.api_docs,
            &contract.operations,
            &contract.schema,
            &contract.outputs,
        )?;
        crate::operation_metadata::validate(
            &contract.operation_metadata,
            &contract.operations,
            &contract.schema,
            &contract.outputs,
        )?;
        if contract.format >= 12 {
            ensure!(
                contract.api_docs.is_empty() && contract.operation_metadata.is_empty(),
                "current artifacts have one application contract, without legacy metadata overlays"
            );
            ensure!(
                contract.declarations.unified,
                "current artifacts require unified operation definitions"
            );
            contract
                .app_contract
                .as_ref()
                .context("complete application contract required")?
                .validate(&contract)?;
        } else {
            ensure!(
                contract.app_contract.is_none(),
                "legacy artifact has current application contract"
            );
        }
        ensure!(
            contract.format >= 3 || contract.pages.is_empty(),
            "legacy artifact has pages"
        );
        ensure!(
            contract.format >= 4 || contract.assets.is_empty(),
            "legacy artifact has assets"
        );
        crate::assets::validate_blobs(&directory, &contract.assets)?;
        ensure!(
            contract.format >= 5 || contract.web_resources.is_empty(),
            "legacy artifact has web resources"
        );
        crate::web_resources::validate_blobs(&directory, &contract.web_resources)?;
        ensure!(
            contract.format >= 6 || (contract.outputs.is_empty() && contract.templates.is_empty()),
            "legacy artifact has template contracts"
        );
        crate::output_schema::validate(&contract.outputs)?;
        if contract.format >= 10 {
            crate::output_schema::validate_api(&contract.outputs)?;
        }
        crate::web_templates::validate_blobs(&directory, &contract.templates)?;
        if contract.format >= 7 {
            crate::web_templates::validate_handles(&contract.templates)?;
        }
        let routes = (contract.format >= 7)
            .then(|| crate::routing::Catalog::from_artifact(&contract))
            .transpose()?;
        ensure!(
            contract.schedules.len() <= crate::schedules::MAXIMUM_SCHEDULES,
            "schedule count budget"
        );
        let mut schedules = BTreeSet::new();
        for schedule in &contract.schedules {
            ensure!(schedules.insert(&schedule.name), "duplicate schedule name");
            schedule.validate(&contract)?;
        }
        ensure!(
            contract.ingress.len() <= crate::ingress::MAXIMUM_ENDPOINTS,
            "endpoint count budget"
        );
        let mut endpoints = BTreeSet::new();
        for endpoint in &contract.ingress {
            ensure!(endpoints.insert(&endpoint.name), "duplicate endpoint name");
            endpoint.validate(&contract)?;
        }
        ensure!(contract.pages.len() <= 32, "page count budget");
        let mut pages = BTreeSet::new();
        for page in &contract.pages {
            page.validate_live()?;
            crate::schema::identifier(&page.name)?;
            ensure!(pages.insert(&page.name), "duplicate page name");
            ensure!(
                !page.title.trim().is_empty() && page.title.len() <= 100,
                "invalid page title"
            );
            let query = contract
                .operations
                .iter()
                .find(|op| op.name == page.operation && op.kind == "query")
                .context("page requires registered query")?;
            ensure!(page.defaults.len() < 65_536, "page defaults budget");
            if contract.format < 7 {
                ensure!(
                    page.path.is_empty() && page.input_type.is_empty(),
                    "legacy page has route metadata"
                );
                contract.schema.inputs[&query.input_type]
                    .validate_input(&serde_json::from_str(&page.defaults)?)?;
            }
            if contract.format >= 6 {
                let context = contract.page_context_schema(page)?;
                if let Some(routes) = &routes {
                    crate::web_templates::validate_routed_page(
                        &directory,
                        &contract.templates,
                        &page.template,
                        &context,
                        &contract.assets,
                        routes,
                    )?;
                    crate::web_templates::validate_routed_bindings(
                        &directory,
                        &contract.templates,
                        &page.template,
                        &context,
                        &contract.assets,
                        routes,
                        &contract,
                    )?;
                } else {
                    crate::web_templates::validate_page(
                        &directory,
                        &contract.templates,
                        &page.template,
                        &context,
                        &contract.assets,
                    )?;
                    crate::web_templates::validate_bindings(
                        &directory,
                        &contract.templates,
                        &page.template,
                        &context,
                        &contract.assets,
                        &contract.operations,
                        &contract.schema,
                    )?;
                }
                if page.live {
                    crate::web_templates::validate_live_page(
                        &directory,
                        &contract.templates,
                        &page.template,
                        &context,
                        &contract.assets,
                        routes.as_ref(),
                    )?;
                }
            } else {
                ensure!(
                    page.template.is_empty() && page.output_type.is_empty(),
                    "legacy page has template metadata"
                );
            }
        }
        let loaded = Self {
            id,
            directory,
            contract,
            executable: Arc::default(),
        };
        if loaded.contract.format == CURRENT_FORMAT {
            let executable = loaded.materialize_worker()?;
            let mut worker = crate::worker::Worker::start(&executable)?;
            let compiled = crate::app_contract::decode(&worker.exchange(b"app-contract")?)?;
            ensure!(
                serde_json::to_value(&compiled)?
                    == serde_json::to_value(&loaded.contract.app_contract)?,
                "application contract differs from compiled App.definition"
            );
            let mut manifest: serde_json::Value =
                serde_json::from_slice(&worker.exchange(b"manifest")?)?;
            // Earlier format-14 workers predate optional live-page metadata.
            // Compare their defaulted page contracts without weakening the
            // exact comparison of any other compiled manifest fields.
            for page in manifest
                .get_mut("pages")
                .and_then(serde_json::Value::as_array_mut)
                .context("compiled manifest pages missing")?
            {
                *page = serde_json::to_value(serde_json::from_value::<Page>(page.clone())?)?;
            }
            let mut expected = serde_json::json!({ "namespace": loaded.contract.namespace, "operations": loaded.contract.operations, "pages": loaded.contract.pages, "properties": loaded.contract.properties });
            // Workers compiled before schedules existed emit no such key. Accept
            // that only when the artifact declares no schedule, so a missing key
            // can never hide a declared one.
            if manifest.get("schedules").is_some() {
                expected["schedules"] = serde_json::to_value(&loaded.contract.schedules)?;
            } else {
                ensure!(
                    loaded.contract.schedules.is_empty(),
                    "compiled manifest omits declared schedules"
                );
            }
            if manifest.get("ingress").is_some() {
                expected["ingress"] = serde_json::to_value(&loaded.contract.ingress)?;
            } else {
                ensure!(
                    loaded.contract.ingress.is_empty(),
                    "compiled manifest omits declared endpoints"
                );
            }
            ensure!(
                manifest == expected,
                "application manifest differs from compiled App.definition"
            );
        }
        Ok(loaded)
    }
    /// Keep one private executable alive across this artifact's worker sessions.
    /// Linux may retain an unlinked executable's tmpfs pages after its worker
    /// exits, so copying for every phase can exhaust bounded temporary storage.
    /// Sharing executable bytes does not share a worker process or its memory.
    pub fn materialize_worker(&self) -> Result<Arc<tempfile::TempPath>> {
        use std::{
            io::Write,
            os::unix::fs::{OpenOptionsExt, PermissionsExt},
        };
        let path = self.directory.join("worker");
        let mut executable = self
            .executable
            .lock()
            .map_err(|_| anyhow::anyhow!("worker executable lock poisoned"))?;
        // Every worker session starts here, so re-reading and re-hashing the
        // artifact's worker each time cost more than all other campaign checks
        // combined. The admitted bytes are retained instead, and the artifact
        // file is re-hashed whenever it is no longer the exact file they came
        // from. The private copy below is still compared byte for byte against
        // those admitted bytes, so an executed worker is always a hashed one.
        let source = Identity::of(&fs::symlink_metadata(&path)?);
        if executable
            .as_ref()
            .is_none_or(|worker| worker.source != source)
        {
            let bytes = fs::read(&path)?;
            ensure!(
                digest(&bytes) == self.contract.worker_digest,
                "worker changed after admission"
            );
            match executable.as_mut() {
                Some(worker) => {
                    worker.admitted = bytes;
                    worker.source = source;
                }
                None => {
                    let mut temporary = tempfile::NamedTempFile::new()?;
                    temporary.write_all(&bytes)?;
                    temporary
                        .as_file()
                        .set_permissions(fs::Permissions::from_mode(0o500))?;
                    let private = Arc::new(temporary.into_temp_path());
                    *executable = Some(PrivateWorker {
                        path: private.clone(),
                        admitted: bytes,
                        source,
                    });
                    return Ok(private);
                }
            }
        }
        let worker = executable.as_ref().context("materialized worker")?;
        let bytes = &worker.admitted;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(worker.path.as_ref())?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.len() == bytes.len() as u64
                && metadata.permissions().mode() & 0o7777 == 0o500,
            "private worker executable changed"
        );
        let mut buffer = [0u8; 16_384];
        for expected in bytes.chunks(buffer.len()) {
            let actual = &mut buffer[..expected.len()];
            file.read_exact(actual)?;
            ensure!(actual == expected, "private worker executable changed");
        }
        ensure!(
            file.read(&mut buffer[..1])? == 0,
            "private worker executable changed"
        );
        Ok(worker.path.clone())
    }
    pub fn operation(&self, name: &str) -> Result<&Operation> {
        self.contract
            .operations
            .iter()
            .find(|op| op.name == name && !self.contract.internal_command(name))
            .context("unknown_operation")
    }
    pub fn page(&self, name: &str) -> Result<&Page> {
        self.contract
            .pages
            .iter()
            .find(|page| page.name == name)
            .context(crate::error::Failure::UnknownPage)
    }
    pub(crate) fn route(&self, name: &str) -> Result<&Operation> {
        match name.strip_prefix("$page.") {
            Some(name) => self.operation(&self.page(name)?.operation),
            None => self
                .contract
                .operations
                .iter()
                .find(|operation| operation.name == name)
                .context("unknown_operation"),
        }
    }
    pub(crate) fn decode_result(&self, route: &str, raw: &str) -> Result<serde_json::Value> {
        let operation = self.route(route)?;
        let output = if let Some(name) = route.strip_prefix("$page.") {
            let page = self.page(name)?;
            if page.template.is_empty() {
                None
            } else {
                Some(page.output_type.as_str())
            }
        } else if operation.output_type.is_empty() {
            None
        } else {
            Some(operation.output_type.as_str())
        };
        if output.is_some() {
            ensure!(
                raw.len() <= crate::output_schema::MAX_JSON_BYTES,
                "page output byte budget"
            );
        }
        let value = serde_json::from_str(raw)?;
        if let Some(name) = output {
            self.contract
                .outputs
                .get(name)
                .context("unknown output contract")?
                .shape
                .validate_value(&value)?;
            if let Some(contract) = &self.contract.app_contract {
                crate::domain::output(
                    &contract.domains,
                    &self.contract.outputs[name].shape,
                    &value,
                )?;
            }
        }
        Ok(value)
    }
}

/// What a schedule runs as. A schedule has no caller, so the application cannot
/// choose this: letting it would let an application grant itself authority by
/// declaring a schedule. A declared schedule with no binding here does not run.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleBinding {
    pub actor: String,
    /// Bound but paused. Absent means enabled, because binding an actor is the act
    /// of turning a schedule on; this exists to stop one without discarding the
    /// actor decision and having to make it again.
    #[serde(default = "enabled", skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

fn enabled() -> bool {
    false
}

/// What an endpoint runs as, and which connection's secret establishes the sender.
///
/// The connection is named directly rather than reached through a resource
/// attachment. Attachments are keyed by operation and express what an application
/// is permitted to do; signature verification happens before any application is
/// involved, so routing it through app authority would invert the order that makes
/// a forged delivery refusable before it can cost anything.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointBinding {
    pub actor: String,
    /// The live connection whose verification secret checks deliveries here.
    pub connection: day2_capabilities::resources::VersionRef,
    /// Bound but paused, so an endpoint can be stopped without discarding the
    /// actor and connection decisions and having to make them again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

/// One application's place in an instance.
///
/// There is no audit grant here. The platform audit log is readable by the
/// application's owners — `authority.admins` — and by nobody else; an app that
/// wants to show its history more widely does so through its own query over
/// `Audit.history`, granted like any other operation. See docs/AUTHORITY.md.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(from = "StoredBinding")]
pub struct AppBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<crate::security_admission::Requirements>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<day2_capabilities::runtime::RuntimeProfile>,
    pub artifact: String,
    pub readers: BTreeSet<String>,
    pub writers: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<crate::authority::Policy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_policies: Vec<day2_capabilities::resources::Attachment>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub schedules: BTreeMap<String, ScheduleBinding>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ingress: BTreeMap<String, EndpointBinding>,
    /// Per model, how long a deleted row stays before an operator sweep may
    /// remove it. Empty — the default — means nothing is ever removed.
    ///
    /// Declared here, in the operator's file, because removal is the one thing
    /// an application is never allowed to do. An artifact cannot ask to be
    /// swept and cannot tell that it will be. See `crate::retention`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub retention: BTreeMap<String, crate::retention::Rule>,
    /// How long completed invocations keep their full traces before compaction to
    /// a receipt. Absent means [`crate::journal::DEFAULT_TRACE_HOURS`]. Compaction
    /// changes no business data: retries and status reads keep working.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal: Option<crate::journal::Policy>,
    /// Where this application is reached, when the installation declares an
    /// identity provider. Absent means the app is not served at an edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<Edge>,
}

/// An app binding as files and snapshots written before owners read the audit
/// may still spell it: with a retired `auditors` list.
///
/// The list is read and dropped; it is never written and never consulted. An
/// operator-authored instance file is held to more than this — a non-empty list
/// there is refused by [`Instance::from_bytes`] with the rule that replaced it —
/// but a backup manifest is historical evidence and must keep loading whatever
/// it recorded. Every other field is exactly [`AppBinding`]'s.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBinding {
    #[serde(default)]
    security: Option<crate::security_admission::Requirements>,
    #[serde(default)]
    runtime: Option<day2_capabilities::runtime::RuntimeProfile>,
    artifact: String,
    readers: BTreeSet<String>,
    writers: BTreeSet<String>,
    #[serde(default, rename = "auditors")]
    _retired_auditors: BTreeSet<String>,
    #[serde(default)]
    authority: Option<crate::authority::Policy>,
    #[serde(default)]
    resource_policies: Vec<day2_capabilities::resources::Attachment>,
    #[serde(default)]
    schedules: BTreeMap<String, ScheduleBinding>,
    #[serde(default)]
    ingress: BTreeMap<String, EndpointBinding>,
    #[serde(default)]
    retention: BTreeMap<String, crate::retention::Rule>,
    #[serde(default)]
    journal: Option<crate::journal::Policy>,
    #[serde(default)]
    edge: Option<Edge>,
}

impl From<StoredBinding> for AppBinding {
    fn from(stored: StoredBinding) -> Self {
        Self {
            security: stored.security,
            runtime: stored.runtime,
            artifact: stored.artifact,
            readers: stored.readers,
            writers: stored.writers,
            authority: stored.authority,
            resource_policies: stored.resource_policies,
            schedules: stored.schedules,
            ingress: stored.ingress,
            retention: stored.retention,
            journal: stored.journal,
            edge: stored.edge,
        }
    }
}

/// Refuse a non-empty retired `auditors` list in an operator-authored instance.
///
/// An empty list is accepted and ignored, so files written before the change —
/// including every deployment that never used it — keep loading unchanged. A
/// non-empty one names people who expected audit access, and that expectation
/// can be met in exactly two ways, both of which are an operator's decision: make
/// them owners (`authority.admins`), or grant them an app query over
/// `Audit.history`. Silently dropping the list would revoke their access without
/// anyone having decided to; silently promoting them to owners would grant far
/// more than they had.
fn refuse_retired_auditors(instance: &serde_json::Value) -> Result<()> {
    let Some(apps) = instance.get("apps").and_then(serde_json::Value::as_object) else {
        return Ok(());
    };
    for (app, binding) in apps {
        match binding.get("auditors") {
            None => {}
            Some(serde_json::Value::Array(actors)) if actors.is_empty() => {}
            Some(_) => anyhow::bail!(
                "apps.{app}.auditors is retired: the platform audit log is readable by the \
                 app's owners (authority.admins) only. Move these actors into \
                 authority.admins if they should own the app, or grant them an app query \
                 that reads Audit.history; then remove the auditors key (an empty list is \
                 accepted and ignored)"
            ),
        }
    }
    Ok(())
}

/// How people prove who they are, for the whole installation.
///
/// One declaration, not one per application: a company signs in with one
/// identity provider, and an app choosing its own would be an app choosing who
/// may reach it. Nothing here can be relaxed per app — an application's only
/// edge setting is its own address.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityProvider {
    pub scheme: IdentityScheme,
    /// The only domain whose people are admitted, checked against both the
    /// assertion's `hd` claim and the address itself.
    pub hosted_domain: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityScheme {
    GoogleIap,
}

/// One application's address at the edge.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    /// `https://<host>`, exactly: what browsers send as `Origin` and the `Host`
    /// every request must name.
    pub origin: String,
    /// The backend service IAP signs this application's assertions for,
    /// `/projects/<number>/global/backendServices/<id>`. An assertion for any
    /// other audience is another application's and is refused.
    pub iap_audience: String,
}

impl Edge {
    /// The `Host` header value requests must carry.
    pub fn authority(&self) -> &str {
        self.origin.trim_start_matches("https://")
    }

    fn validate(&self) -> Result<()> {
        let host = self
            .origin
            .strip_prefix("https://")
            .context("edge_origin_must_be_https")?;
        ensure!(dns_name(host), "invalid_edge_origin");
        let mut parts = self.iap_audience.split('/');
        ensure!(
            matches!(
                (
                    parts.next(), parts.next(), parts.next(), parts.next(),
                    parts.next(), parts.next(), parts.next(),
                ),
                (Some(""), Some("projects"), Some(project), Some("global"),
                 Some("backendServices"), Some(service), None)
                    if digits(project) && digits(service)
            ),
            "invalid_iap_audience"
        );
        Ok(())
    }
}

fn digits(value: &str) -> bool {
    (1..=24).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
}

/// A lowercase DNS name of at least two labels. Lowercase only, because the
/// origin is compared byte for byte and a browser always sends it lowercased.
fn dns_name(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').count() >= 2
        && value.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    pub installation: String,
    pub environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<day2_capabilities::InstallationControl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<day2_capabilities::resources::Catalog>,
    /// Absent means no identity provider: applications are served only with the
    /// development sign-in link. Present means every application is served
    /// behind it and the development sign-in is refused — there is no mode in
    /// which both are available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityProvider>,
    pub apps: BTreeMap<String, AppBinding>,
}

impl Instance {
    pub fn load(path: &Path) -> Result<Self> {
        ensure!(
            fs::metadata(path)?.len() <= 1_048_576,
            "instance byte budget"
        );
        Self::from_bytes(&fs::read(path)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: serde_json::Value = crate::json::decode(bytes)?;
        refuse_retired_auditors(&raw)?;
        let instance: Self = serde_json::from_value(raw)?;
        crate::schema::identifier(&instance.installation)?;
        crate::schema::identifier(&instance.environment)?;
        ensure!(!instance.apps.is_empty(), "instance has no apps");
        for name in instance.apps.keys() {
            crate::schema::identifier(name)?;
        }
        if let Some(control) = &instance.control {
            control.validate(instance.apps.keys().map(String::as_str))?;
        }
        if let Some(resources) = &instance.resources {
            resources.validate()?;
        } else {
            ensure!(
                instance
                    .apps
                    .values()
                    .all(|binding| binding.resource_policies.is_empty()),
                "resource_catalog_missing"
            );
        }
        for binding in instance.apps.values() {
            for (model, rule) in &binding.retention {
                rule.validate(model)?;
            }
            if let Some(journal) = &binding.journal {
                journal.validate()?;
            }
        }
        instance.validate_edges()?;
        let mut queues = BTreeSet::new();
        for binding in instance.apps.values() {
            if let Some(runtime) = &binding.runtime {
                runtime.validate()?;
            }
        }
        if let Some(control) = &instance.control {
            for binding in control.apps.values() {
                if let Some(build) = &binding.build {
                    let day2_capabilities::DurabilityProvider::TemporalLocal {
                        endpoint,
                        namespace,
                        task_queue,
                    } = &control.runtimes[&build.durability.id];
                    let address: std::net::SocketAddr = endpoint.parse()?;
                    ensure!(
                        queues.insert((
                            format!("http://{address}"),
                            namespace.clone(),
                            task_queue.clone()
                        )),
                        "control workers require distinct Temporal task queues"
                    );
                }
            }
        }
        Ok(instance)
    }
    fn validate_edges(&self) -> Result<()> {
        if let Some(identity) = &self.identity {
            ensure!(dns_name(&identity.hosted_domain), "invalid_hosted_domain");
        }
        let (mut origins, mut audiences) = (BTreeSet::new(), BTreeSet::new());
        for binding in self.apps.values() {
            let Some(edge) = &binding.edge else { continue };
            // An address with nothing to verify requests against would be an
            // edge that believes whoever reaches it.
            ensure!(self.identity.is_some(), "edge_requires_identity");
            edge.validate()?;
            ensure!(origins.insert(&edge.origin), "duplicate_edge_origin");
            // Two apps behind one backend service would each accept the
            // other's assertions.
            ensure!(
                audiences.insert(&edge.iap_audience),
                "duplicate_iap_audience"
            );
        }
        Ok(())
    }
    /// The edge an application is served at, with the installation's identity.
    pub fn edge(&self, app: &str) -> Result<(&IdentityProvider, &Edge)> {
        let binding = self.apps.get(app).context("app_not_installed")?;
        let identity = self.identity.as_ref().context("identity_not_declared")?;
        let edge = binding.edge.as_ref().context("edge_not_declared")?;
        Ok((identity, edge))
    }
    pub fn scope(&self, app: &str) -> Result<String> {
        ensure!(self.apps.contains_key(app), "app_not_installed");
        Ok(format!("{}/{}/{app}", self.installation, self.environment))
    }
    pub fn authorize(&self, app: &str, operation: &Operation, actor: &str) -> Result<()> {
        let binding = self.apps.get(app).context("app_not_installed")?;
        let permitted = binding.writers.contains(actor)
            || (operation.kind == "query" && binding.readers.contains(actor));
        ensure!(permitted, crate::error::Failure::Forbidden);
        binding
            .authority
            .as_ref()
            .context("missing_authority_policy")?
            .authorize(&operation.name, actor)?;
        Ok(())
    }
}

#[cfg(test)]
mod retired_audit_grant_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_legacy_instances_load_but_nonempty_grants_require_migration() -> Result<()> {
        let mut value = json!({"installation":"test","environment":"test","apps":{"app":{
            "artifact":"/artifact","readers":[],"writers":[],"auditors":[]
        }}});
        let instance = Instance::from_bytes(&serde_json::to_vec(&value)?)?;
        assert!(
            serde_json::to_value(&instance)?["apps"]["app"]
                .get("auditors")
                .is_none()
        );
        value["apps"]["app"]["auditors"] = json!(["former-auditor"]);
        let error = Instance::from_bytes(&serde_json::to_vec(&value)?)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("apps.app.auditors is retired") && error.contains("authority.admins")
        );
        // Backup manifests are historical evidence, not a fresh desired grant.
        let backup: Instance = serde_json::from_value(value)?;
        assert!(
            serde_json::to_value(backup)?["apps"]["app"]
                .get("auditors")
                .is_none()
        );
        Ok(())
    }
}

#[cfg(test)]
mod worker_executable_tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture() -> Result<(tempfile::TempDir, LoadedArtifact, Vec<u8>)> {
        let directory = tempfile::tempdir()?;
        let bytes = (0..65_539)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(directory.path().join("worker"), &bytes)?;
        let contract = serde_json::from_value(json!({
            "format":1,"roc_version":"fixture","worker_digest":digest(&bytes),
            "schema_digest":"fixture","schema":{"models":{},"inputs":{},"foreign_keys":[]},
            "operations":[],"sources":{},"admission":"local-spike-only"
        }))?;
        let artifact = LoadedArtifact::from_contract_for_tests(
            "fixture".into(),
            directory.path().into(),
            contract,
        );
        Ok((directory, artifact, bytes))
    }

    #[test]
    fn concurrent_sessions_share_one_private_executable_and_retain_its_lifetime() -> Result<()> {
        let (_directory, artifact, bytes) = fixture()?;
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads = (0..8)
            .map(|_| {
                let artifact = artifact.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    artifact.materialize_worker()
                })
            })
            .collect::<Vec<_>>();
        let handles = threads
            .into_iter()
            .map(|thread| thread.join().expect("materialization thread"))
            .collect::<Result<Vec<_>>>()?;
        for handle in &handles {
            assert!(Arc::ptr_eq(&handles[0], handle));
        }
        let retained = handles[0].clone();
        let path: PathBuf = retained.as_ref().to_path_buf();
        assert_ne!(path, artifact.directory().join("worker"));
        assert_eq!(fs::read(&path)?, bytes);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o7777, 0o500);
        drop(handles);
        drop(artifact);
        assert!(
            path.is_file(),
            "a live worker handle retains its executable"
        );
        drop(retained);
        assert!(
            !path.exists(),
            "the last owner removes the private executable"
        );
        Ok(())
    }

    #[test]
    fn source_tampering_is_rejected_even_with_a_valid_private_executable() -> Result<()> {
        let (_directory, artifact, bytes) = fixture()?;
        let handle = artifact.materialize_worker()?;
        let source = artifact.directory().join("worker");
        fs::write(&source, b"changed source")?;
        assert!(artifact.materialize_worker().is_err());
        assert_eq!(fs::read(handle.as_ref())?, bytes);
        fs::write(source, &bytes)?;
        assert!(Arc::ptr_eq(&handle, &artifact.materialize_worker()?));
        Ok(())
    }

    // The artifact's worker is re-checked by file identity rather than re-hashed
    // on every session, so tampering that preserves the file's length must still
    // be caught: an in-place write moves the modification time, and the full
    // re-hash that follows rejects it.
    #[test]
    fn source_tampering_that_preserves_length_is_still_rejected() -> Result<()> {
        let (_directory, artifact, mut bytes) = fixture()?;
        let handle = artifact.materialize_worker()?;
        let source = artifact.directory().join("worker");
        let original = Identity::of(&fs::symlink_metadata(&source)?);
        bytes[32_768] ^= 1;
        fs::write(&source, &bytes)?;
        assert_eq!(fs::symlink_metadata(&source)?.len(), original.size);
        assert!(
            artifact.materialize_worker().is_err(),
            "a same-length source rewrite must not be admitted"
        );
        assert_eq!(fs::read(handle.as_ref())?.len(), original.size as usize);
        Ok(())
    }

    #[test]
    fn private_executable_content_permissions_and_symlinks_are_revalidated() -> Result<()> {
        for alteration in ["content", "permissions", "symlink"] {
            let (_directory, artifact, mut bytes) = fixture()?;
            let handle = artifact.materialize_worker()?;
            match alteration {
                "content" => {
                    fs::set_permissions(handle.as_ref(), fs::Permissions::from_mode(0o600))?;
                    bytes[32_768] ^= 1;
                    fs::write(handle.as_ref(), bytes)?;
                    fs::set_permissions(handle.as_ref(), fs::Permissions::from_mode(0o500))?;
                }
                "permissions" => {
                    fs::set_permissions(handle.as_ref(), fs::Permissions::from_mode(0o700))?;
                }
                "symlink" => {
                    fs::remove_file(handle.as_ref())?;
                    symlink(artifact.directory().join("worker"), handle.as_ref())?;
                }
                _ => unreachable!(),
            }
            assert!(artifact.materialize_worker().is_err(), "{alteration}");
        }
        Ok(())
    }

    #[test]
    fn a_replaced_private_fifo_is_rejected_without_waiting_for_a_writer() -> Result<()> {
        use std::{os::unix::fs::OpenOptionsExt, sync::mpsc, time::Duration};
        let (_directory, artifact, _bytes) = fixture()?;
        let handle = artifact.materialize_worker()?;
        let path = handle.as_ref().to_path_buf();
        fs::remove_file(&path)?;
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()?
                .success()
        );
        let (sender, receiver) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            sender.send(artifact.materialize_worker().is_err()).unwrap();
        });
        let rejected = receiver.recv_timeout(Duration::from_secs(3));
        if rejected.is_err() {
            // Unblock a regressed blocking open so the test can fail and clean
            // up instead of leaving a stuck thread behind.
            let _writer = fs::OpenOptions::new()
                .write(true)
                .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
                .open(&path)?;
        }
        thread.join().expect("FIFO validation thread");
        assert!(rejected.is_ok_and(|rejected| rejected));
        Ok(())
    }
}

#[cfg(test)]
mod output_contract_tests {
    use super::*;
    use serde_json::json;

    fn artifact() -> Result<LoadedArtifact> {
        Ok(LoadedArtifact {
            id: "fixture".into(),
            directory: PathBuf::new(),
            executable: Arc::default(),
            contract: serde_json::from_value(json!({
                "format":6,"roc_version":"fixture","worker_digest":"fixture",
                "schema_digest":"fixture","schema":{"models":{},"inputs":{},"foreign_keys":[]},
                "operations":[{"name":"links.list","kind":"query","input_type":"list_links","output_type":"links"}],
                "pages":[{"name":"links","title":"Links","operation":"links.list","defaults":"{}","template":"pages/links.html","output_type":"links"}],
                "outputs":{"links":{"shape":{"record":{"title":"string"}},"roc_type":"{ title : Str }"}},
                "sources":{},"admission":"local-spike-only"
            }))?,
        })
    }

    #[test]
    fn page_and_query_require_the_same_named_output_handle() -> Result<()> {
        let mut artifact = artifact()?;
        let page = artifact.contract.pages[0].clone();
        artifact.contract.page_context_schema(&page)?;
        artifact.contract.operations[0].output_type = "another_output".into();
        assert!(artifact.contract.page_context_schema(&page).is_err());
        artifact.contract.operations[0].output_type.clear();
        assert!(artifact.contract.page_context_schema(&page).is_err());
        Ok(())
    }

    #[test]
    fn live_metadata_defaults_and_refresh_bounds_are_enforced() -> Result<()> {
        let artifact = artifact()?;
        let mut page = artifact.contract.pages[0].clone();
        assert!(!page.live);
        assert_eq!(page.live_refresh_ms, 0);
        page.validate_live()?;
        page.live_refresh_ms = 5_000;
        assert!(page.validate_live().is_err());
        page.live = true;
        for milliseconds in [0, 1_000, 5_000, 60_000] {
            page.live_refresh_ms = milliseconds;
            page.validate_live()?;
        }
        for milliseconds in [1, 999, 60_001, u64::MAX] {
            page.live_refresh_ms = milliseconds;
            assert!(page.validate_live().is_err());
        }
        page.live_refresh_ms = 0;
        page.template.clear();
        assert!(page.validate_live().is_err());
        Ok(())
    }

    #[test]
    fn explicit_template_handles_do_not_derive_the_filename_from_page_name() -> Result<()> {
        let mut artifact = artifact()?;
        let mut page = artifact.contract.pages[0].clone();
        assert!(page.path.is_empty());
        page.template = "pages/directory.html".into();
        assert!(artifact.contract.page_context_schema(&page).is_err());
        artifact.contract.format = 7;
        page.input_type = "list_links".into();
        page.path = "/".into();
        artifact.contract.page_context_schema(&page)?;
        page.template = "components/directory.html".into();
        assert!(artifact.contract.page_context_schema(&page).is_err());
        page.template = "pages/directory.html".into();
        for name in ["company", "asset", "routes", "platform"] {
            page.name = name.into();
            assert!(artifact.contract.page_context_schema(&page).is_err());
        }
        Ok(())
    }

    #[test]
    fn format_seven_page_and_registered_query_require_the_same_input_handle() -> Result<()> {
        let mut artifact = artifact()?;
        let mut page = artifact.contract.pages[0].clone();
        artifact.contract.format = 7;
        page.path = "/".into();
        assert!(artifact.contract.page_context_schema(&page).is_err());
        page.input_type = "list_links".into();
        artifact.contract.page_context_schema(&page)?;
        page.input_type = "same_wire_shape_different_nominal_type".into();
        let error = artifact.contract.page_context_schema(&page).unwrap_err();
        assert_eq!(error.to_string(), "page and query input handles must match");
        Ok(())
    }

    #[test]
    fn page_and_rpc_results_are_bounded_before_parsing_and_checked_before_completion() -> Result<()>
    {
        let artifact = artifact()?;
        for route in ["$page.links", "links.list"] {
            assert_eq!(
                artifact.decode_result(route, r#"{"title":"Example"}"#)?,
                json!({"title":"Example"})
            );
            assert!(
                artifact
                    .decode_result(route, r#"{"title":"Example","extra":true}"#)
                    .is_err()
            );
            assert!(artifact.decode_result(route, r#"{"title":null}"#).is_err());
            let oversized_invalid_json = "!".repeat(crate::output_schema::MAX_JSON_BYTES + 1);
            let error = artifact
                .decode_result(route, &oversized_invalid_json)
                .unwrap_err();
            assert_eq!(error.to_string(), "page output byte budget");
        }
        Ok(())
    }

    #[test]
    fn command_query_and_page_results_enforce_nested_collection_page_contracts() -> Result<()> {
        use crate::output_schema::{Contract, MAX_PAGE_ITEMS, Type};

        let mut artifact = artifact()?;
        artifact.contract.format = 10;
        artifact.contract.operations.push(Operation {
            name: "links.bulk_update".into(),
            kind: "command".into(),
            input_type: "list_links".into(),
            output_type: "links".into(),
        });
        artifact.contract.outputs.insert(
            "links".into(),
            Contract {
                shape: Type::Record(BTreeMap::from([(
                    "changes".into(),
                    Type::CollectionPage(Box::new(Type::Record(BTreeMap::from([
                        ("title".into(), Type::String),
                        (
                            "revisions".into(),
                            Type::CollectionPage(Box::new(Type::Integer)),
                        ),
                    ])))),
                )])),
                roc_type:
                    "{ changes : CollectionPage({ title : Str, revisions : CollectionPage(I64) }) }"
                        .into(),
            },
        );
        crate::output_schema::validate_api(&artifact.contract.outputs)?;
        let row = json!({"title":"Updated", "revisions":{"items":[1,2],"has_more":false,"next_after":"2"}});
        let valid = json!({"changes":{"items":[row.clone()],"has_more":true,"next_after":"1"}});
        let edge = json!({"changes":{"items":vec![row.clone();MAX_PAGE_ITEMS],"has_more":true,"next_after":"100"}});
        let mut invalid = vec![
            json!([row.clone()]),
            json!({"changes":[row.clone()]}),
            json!({"changes":{"items":vec![row.clone();MAX_PAGE_ITEMS + 1],"has_more":true,"next_after":"101"}}),
        ];
        for (path, replacement) in [
            ("/changes/items/0/revisions", json!([1, 2])),
            (
                "/changes/items/0/revisions/items",
                json!(vec![1; MAX_PAGE_ITEMS + 1]),
            ),
            ("/changes/items/0/revisions/next_after", json!("-1")),
            ("/changes/next_after", json!(1)),
            ("/changes/next_after", json!("01")),
            ("/changes/next_after", json!("9223372036854775808")),
            ("/changes/next_after", json!("0")),
            ("/changes/items", json!([])),
        ] {
            let mut value = valid.clone();
            *value.pointer_mut(path).context("test output pointer")? = replacement;
            invalid.push(value);
        }
        for route in ["links.bulk_update", "links.list", "$page.links"] {
            for value in [&valid, &edge] {
                assert_eq!(
                    artifact.decode_result(route, &serde_json::to_string(value)?)?,
                    *value
                );
            }
            for value in &invalid {
                assert!(
                    artifact
                        .decode_result(route, &serde_json::to_string(value)?)
                        .is_err(),
                    "invalid collection output admitted through {route}: {value}"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod schedule_admission_tests {
    use super::*;
    use serde_json::json;

    /// An application whose only command is internal and takes an empty input,
    /// which is the shape a schedule or an endpoint can legitimately bind.
    pub(super) fn fixture() -> Result<Artifact> {
        Ok(serde_json::from_value(json!({
        "format": 14,
        "roc_version": "fixture",
        "worker_digest": "fixture",
        "schema_digest": "fixture",
        "schema": {
                "models": {},
                "inputs": {
                        "empty": {
                                "fields": {}
                        },
                        "titled": {
                                "fields": {
                                        "title": "text"
                                }
                        }
                },
                "foreign_keys": []
        },
        "operations": [
                {
                        "name": "reports.sweep",
                        "kind": "command",
                        "input_type": "empty",
                        "output_type": "out"
                },
                {
                        "name": "reports.submit",
                        "kind": "command",
                        "input_type": "titled",
                        "output_type": "out"
                },
                {
                        "name": "reports.list",
                        "kind": "query",
                        "input_type": "empty",
                        "output_type": "out"
                }
        ],
        "app_contract": {
                "domains": {},
                "errors": {},
                "identities": "",
                "invariants": {},
                "operations": {
                        "reports.sweep": {
                                "deprecated": false,
                                "errors": [],
                                "execution": {
                                        "effects": [],
                                        "id_field": "",
                                        "internal": true,
                                        "model": "",
                                        "version_field": ""
                                },
                                "intent": {
                                        "follow_ups": [],
                                        "input_sources": [],
                                        "inputs": [],
                                        "outputs": [],
                                        "target": {
                                                "input_type": "empty",
                                                "operation": "reports.sweep",
                                                "output_type": "out"
                                        },
                                        "title": "t",
                                        "usage": {
                                                "avoid_when": [],
                                                "effects": [],
                                                "preconditions": [],
                                                "purpose": "p",
                                                "result": "r",
                                                "use_when": []
                                        }
                                },
                                "request_example": "{}",
                                "required_all_rows": [],
                                "response_example": "{}"
                        },
                        "reports.submit": {
                                "deprecated": false,
                                "errors": [],
                                "execution": {
                                        "effects": [],
                                        "id_field": "",
                                        "internal": false,
                                        "model": "",
                                        "version_field": ""
                                },
                                "intent": {
                                        "follow_ups": [],
                                        "input_sources": [],
                                        "inputs": [],
                                        "outputs": [],
                                        "target": {
                                                "input_type": "titled",
                                                "operation": "reports.submit",
                                                "output_type": "out"
                                        },
                                        "title": "t",
                                        "usage": {
                                                "avoid_when": [],
                                                "effects": [],
                                                "preconditions": [],
                                                "purpose": "p",
                                                "result": "r",
                                                "use_when": []
                                        }
                                },
                                "request_example": "{}",
                                "required_all_rows": [],
                                "response_example": "{}"
                        }
                },
                "presentation": {
                        "script": "",
                        "stylesheet": ""
                }
        },
        "sources": {},
        "admission": "local-spike-only"
        }))?)
    }

    fn sweep() -> Schedule {
        Schedule {
            name: "sweep".into(),
            operation: "reports.sweep".into(),
            input: "{}".into(),
            input_type: "empty".into(),
            interval_ms: 300_000,
            anchor_hour: -1,
            missed: "coalesce".into(),
            catch_up_bound: 0,
        }
    }

    #[test]
    fn the_declaration_reports_uses_is_admitted() -> Result<()> {
        sweep().validate(&fixture()?)
    }

    #[test]
    fn a_schedule_faster_than_the_minimum_is_refused() -> Result<()> {
        let artifact = fixture()?;
        // One second would let an application slam itself with its own work.
        let fast = Schedule {
            interval_ms: 1_000,
            ..sweep()
        };
        assert!(fast.validate(&artifact).is_err());
        // The minimum itself is allowed; the bound is not off by one.
        let least = Schedule {
            interval_ms: crate::schedules::MINIMUM_INTERVAL_MS as u64,
            ..sweep()
        };
        assert!(least.validate(&artifact).is_ok());
        Ok(())
    }

    #[test]
    fn a_daily_schedule_without_an_anchor_is_refused() -> Result<()> {
        let artifact = fixture()?;
        let day = 24 * 60 * 60 * 1_000;
        // Unanchored, "every day" drifts after every outage and the occurrence
        // identity stops being stable, which is what exactly-once rests on.
        let drifting = Schedule {
            interval_ms: day,
            anchor_hour: -1,
            ..sweep()
        };
        assert!(drifting.validate(&artifact).is_err());
        let anchored = Schedule {
            interval_ms: day,
            anchor_hour: 3,
            ..sweep()
        };
        assert!(anchored.validate(&artifact).is_ok());
        // An anchor on a five-minute schedule names an occurrence that does not
        // exist, so it is a mistake rather than a harmless extra.
        let confused = Schedule {
            anchor_hour: 3,
            ..sweep()
        };
        assert!(confused.validate(&artifact).is_err());
        let outside = Schedule {
            interval_ms: day,
            anchor_hour: 24,
            ..sweep()
        };
        assert!(outside.validate(&artifact).is_err());
        Ok(())
    }

    #[test]
    fn a_missing_or_incoherent_missed_policy_is_refused() -> Result<()> {
        let artifact = fixture()?;
        for missed in ["", "drop", "skip"] {
            let undeclared = Schedule {
                missed: missed.into(),
                ..sweep()
            };
            assert!(
                undeclared.validate(&artifact).is_err(),
                "{missed} was admitted as a missed-occurrence policy"
            );
        }
        // Coalescing consumes no backlog, so a bound on it is a contradiction.
        let bounded_coalesce = Schedule {
            catch_up_bound: 5,
            ..sweep()
        };
        assert!(bounded_coalesce.validate(&artifact).is_err());
        // Running each missed occurrence without a bound is the unbounded backlog
        // the policy exists to prevent.
        let unbounded = Schedule {
            missed: "run_each".into(),
            catch_up_bound: 0,
            ..sweep()
        };
        assert!(unbounded.validate(&artifact).is_err());
        let bounded = Schedule {
            missed: "run_each".into(),
            catch_up_bound: 12,
            ..sweep()
        };
        assert!(bounded.validate(&artifact).is_ok());
        Ok(())
    }

    #[test]
    fn a_schedule_cannot_bind_a_public_command_or_a_query() -> Result<()> {
        let artifact = fixture()?;
        // Binding a publicly reachable command would give it a second entry point
        // that no request authorized.
        let public = Schedule {
            operation: "reports.submit".into(),
            input_type: "titled".into(),
            input: json!({"title": "x"}).to_string(),
            ..sweep()
        };
        assert!(public.validate(&artifact).is_err());
        let query = Schedule {
            operation: "reports.list".into(),
            ..sweep()
        };
        assert!(query.validate(&artifact).is_err());
        let missing = Schedule {
            operation: "reports.absent".into(),
            ..sweep()
        };
        assert!(missing.validate(&artifact).is_err());
        Ok(())
    }

    #[test]
    fn the_fixed_input_is_checked_against_the_bound_command() -> Result<()> {
        let artifact = fixture()?;
        // There is no request to check this against later, so it is checked here.
        let wrong_shape = Schedule {
            input: json!({"unexpected": 1}).to_string(),
            ..sweep()
        };
        assert!(wrong_shape.validate(&artifact).is_err());
        let not_json = Schedule {
            input: "{".into(),
            ..sweep()
        };
        assert!(not_json.validate(&artifact).is_err());
        // A declared input type that disagrees with the command's own is a stale
        // declaration, not a coincidence.
        let stale = Schedule {
            input_type: "titled".into(),
            ..sweep()
        };
        assert!(stale.validate(&artifact).is_err());
        Ok(())
    }

    #[test]
    fn a_name_that_cannot_become_an_invocation_id_is_refused() -> Result<()> {
        let artifact = fixture()?;
        // The name reaches the derived invocation identity, which accepts only
        // [A-Za-z0-9_-.]; refusing it here beats failing at the first occurrence.
        for name in ["", "nightly sweep", "sweep:daily", "sweep/daily"] {
            let bad = Schedule {
                name: name.into(),
                ..sweep()
            };
            assert!(
                bad.validate(&artifact).is_err(),
                "{name:?} was admitted as a schedule name"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod endpoint_admission_tests {
    use super::*;

    fn endpoint() -> Endpoint {
        Endpoint {
            name: "submissions".into(),
            operation: "reports.sweep".into(),
            input_type: "empty".into(),
            provider: "slack.events.v1".into(),
        }
    }

    fn artifact() -> Result<Artifact> {
        super::schedule_admission_tests::fixture()
    }

    #[test]
    fn the_declaration_an_application_would_write_is_admitted() -> Result<()> {
        endpoint().validate(&artifact()?)
    }

    #[test]
    fn an_endpoint_cannot_bind_a_public_command_or_a_query() -> Result<()> {
        let artifact = artifact()?;
        // A delivery has no caller. Binding a publicly reachable command would give
        // it a second entry point that no request authorised, which is the whole
        // risk of letting an application point the outside world at its own code.
        let public = Endpoint {
            operation: "reports.submit".into(),
            input_type: "titled".into(),
            ..endpoint()
        };
        assert!(public.validate(&artifact).is_err());
        let query = Endpoint {
            operation: "reports.list".into(),
            ..endpoint()
        };
        assert!(query.validate(&artifact).is_err());
        let missing = Endpoint {
            operation: "reports.absent".into(),
            ..endpoint()
        };
        assert!(missing.validate(&artifact).is_err());
        Ok(())
    }

    #[test]
    fn an_unregistered_provider_is_refused() -> Result<()> {
        let artifact = artifact()?;
        // The provider owns the signature scheme, the envelope and the rule that
        // identifies a delivery. A name nobody implements has nothing to answer
        // those, so it cannot be verified and must not be admitted.
        for provider in ["", "stripe.webhook.v1", "slack.events", "slack.events.v2"] {
            let unknown = Endpoint {
                provider: provider.into(),
                ..endpoint()
            };
            assert!(
                unknown.validate(&artifact).is_err(),
                "{provider:?} was admitted"
            );
        }
        assert!(
            Endpoint {
                provider: "slack.interactivity.v1".into(),
                ..endpoint()
            }
            .validate(&artifact)
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn a_stale_input_type_is_refused() -> Result<()> {
        // The compiler establishes that an endpoint decodes into what its command
        // accepts; this catches an artifact whose recorded type has fallen behind.
        let stale = Endpoint {
            input_type: "titled".into(),
            ..endpoint()
        };
        assert!(stale.validate(&artifact()?).is_err());
        Ok(())
    }

    #[test]
    fn an_endpoint_name_that_cannot_become_an_invocation_id_is_refused() -> Result<()> {
        let artifact = artifact()?;
        for name in ["", "slack submissions", "submissions:v2", "submissions/v2"] {
            let bad = Endpoint {
                name: name.into(),
                ..endpoint()
            };
            assert!(bad.validate(&artifact).is_err(), "{name:?} was admitted");
        }
        Ok(())
    }
}
