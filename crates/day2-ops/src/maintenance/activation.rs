//! Durable activation ownership and pre-fence recovery. Roc orders claim,
//! helper cleanup and restore; each native action checks the owned checkpoint.
use super::{ACTIVATED, Cluster, Operation, Request, Tools, dns_label, hex64};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs, io::Read, path::Path, time::Duration};

pub(super) const ANNOTATION: &str = "day2.dev/activation";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Prepared,
    Stopped,
    Fenced,
    Recovering,
    Restored,
    Activated,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub format: u8,
    pub owner: String,
    pub request_digest: String,
    pub target_instance_digest: String,
    pub controller_uid: String,
    pub template_digest: String,
    pub source_instance_digest: String,
    pub pvc_uid: String,
    pub replicas: u64,
    pub pod: String,
    pub pod_uid: Option<String>,
    pub phase: Phase,
}

impl Intent {
    pub fn active(&self) -> bool {
        !matches!(self.phase, Phase::Restored | Phase::Activated)
    }

    pub fn read(controller: &Value) -> Result<Option<Self>> {
        controller["metadata"]["annotations"][ANNOTATION]
            .as_str()
            .map(|raw| {
                let intent: Self = day2::json::decode(raw.as_bytes())?;
                ensure!(
                    intent.format == 1
                        && dns_label(&intent.pod)
                        && !intent.controller_uid.is_empty()
                        && !intent.pvc_uid.is_empty(),
                    "invalid_activation_checkpoint"
                );
                ensure!(
                    intent.replicas <= 1 && !intent.owner.is_empty() && intent.owner.len() <= 128,
                    "invalid_activation_checkpoint_owner_or_replicas"
                );
                for digest in [
                    &intent.request_digest,
                    &intent.target_instance_digest,
                    &intent.template_digest,
                    &intent.source_instance_digest,
                ] {
                    hex64(
                        digest
                            .strip_prefix("sha256:")
                            .context("activation checkpoint digest prefix")?,
                        "activation checkpoint digest",
                    )?;
                }
                if let Some(uid) = &intent.pod_uid {
                    ensure!(
                        !uid.is_empty() && uid.len() <= 128,
                        "invalid_activation_helper_uid"
                    );
                }
                Ok(intent)
            })
            .transpose()
    }
}

pub(super) fn remove_helper(
    cluster: &mut dyn Cluster,
    request: &Request,
    name: &str,
    request_digest: &str,
    expected_uid: Option<&str>,
) -> Result<()> {
    ensure!(dns_label(name), "invalid_activation_helper_name");
    let invoke = |cluster: &mut dyn Cluster, args: Vec<String>, stdin: Option<&[u8]>| {
        let mut full = vec!["-n".into(), request.namespace.clone()];
        full.extend(args);
        cluster.kubectl(&full, stdin, Duration::from_secs(330))
    };
    let raw = invoke(
        cluster,
        vec![
            "get".into(),
            "pod".into(),
            name.into(),
            "--ignore-not-found".into(),
            "-o".into(),
            "json".into(),
        ],
        None,
    )?;
    if raw.trim().is_empty() {
        return Ok(());
    }
    let pod: Value = serde_json::from_str(&raw)?;
    let uid = pod["metadata"]["uid"].as_str().context("helper UID")?;
    ensure!(
        expected_uid.is_none_or(|expected| expected == uid)
            && pod["metadata"]["annotations"]["day2.dev/rollout-request"] == request_digest
            && pod["spec"]["containers"]
                .as_array()
                .is_some_and(|containers| {
                    containers.len() == 1 && containers[0]["image"] == request.tooling_image
                })
            && pod["spec"]["volumes"].as_array().is_some_and(|volumes| {
                volumes
                    .iter()
                    .any(|volume| volume["persistentVolumeClaim"]["claimName"] == request.pvc)
            }),
        "activation_recovery_helper_changed"
    );
    let path = format!("/api/v1/namespaces/{}/pods/{name}", request.namespace);
    let options = serde_json::to_vec(
        &json!({"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":uid}}),
    )?;
    invoke(
        cluster,
        vec![
            "delete".into(),
            "--raw".into(),
            path,
            "-f".into(),
            "-".into(),
        ],
        Some(&options),
    )?;
    invoke(
        cluster,
        vec![
            "wait".into(),
            "--for=delete".into(),
            format!("pod/{name}"),
            "--timeout=300s".into(),
        ],
        None,
    )?;
    Ok(())
}

pub(super) fn template_digest(controller: &Value) -> Result<String> {
    ensure!(
        controller["spec"]["template"].is_object(),
        "controller template required"
    );
    Ok(day2::digest(&serde_json::to_vec(
        &controller["spec"]["template"],
    )?))
}

/// A single API compare-and-set publishes intent and any replica change.
/// A lost response can be resolved from the controller, never from Drop.
pub(super) fn replace(
    cluster: &mut dyn Cluster,
    request: &Request,
    live: &Value,
    expected: Option<&Intent>,
    intent: &Intent,
    replicas: Option<u64>,
) -> Result<()> {
    replace_impl(cluster, request, live, expected, intent, replicas, None)
}

pub(super) fn activate(
    cluster: &mut dyn Cluster,
    request: &Request,
    live: &Value,
    expected: &Intent,
    intent: &Intent,
    image: &str,
) -> Result<()> {
    ensure!(
        expected.phase == Phase::Fenced
            && intent.phase == Phase::Activated
            && live["spec"]["replicas"] == 0
            && request
                .target
                .as_ref()
                .is_some_and(|target| target.app_image == image),
        "activation_approval_requires_the_fenced_target"
    );
    replace_impl(
        cluster,
        request,
        live,
        Some(expected),
        intent,
        None,
        Some(image),
    )
}

fn replace_impl(
    cluster: &mut dyn Cluster,
    request: &Request,
    live: &Value,
    expected: Option<&Intent>,
    intent: &Intent,
    replicas: Option<u64>,
    activated_image: Option<&str>,
) -> Result<()> {
    ensure!(
        live["metadata"]["uid"] == intent.controller_uid
            && template_digest(live)? == intent.template_digest
            && live["metadata"]["resourceVersion"].is_string()
            && Intent::read(live)?.as_ref() == expected,
        "activation_checkpoint_changed"
    );
    let mut annotations = live["metadata"]["annotations"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    annotations.insert(ANNOTATION.into(), json!(serde_json::to_string(intent)?));
    if let Some(image) = activated_image {
        annotations.insert(ACTIVATED.into(), json!(image));
    }
    let mut patch = vec![
        json!({"op":"test","path":"/metadata/uid","value":intent.controller_uid}),
        json!({"op":"test","path":"/metadata/resourceVersion","value":live["metadata"]["resourceVersion"]}),
        json!({"op":"test","path":"/spec/template","value":live["spec"]["template"]}),
        json!({"op":"test","path":"/spec/replicas","value":live["spec"]["replicas"]}),
        json!({"op":"add","path":"/metadata/annotations","value":annotations}),
    ];
    if expected.is_some() {
        patch.insert(
            4,
            json!({"op":"test","path":"/metadata/annotations/day2.dev~1activation",
            "value":live["metadata"]["annotations"][ANNOTATION]}),
        );
    }
    if let Some(replicas) = replicas {
        patch.push(json!({"op":"replace","path":"/spec/replicas","value":replicas}));
    }
    let mut snapshot = live.clone();
    for attempt in 0..3 {
        patch[1]["value"] = snapshot["metadata"]["resourceVersion"].clone();
        let mut merged = snapshot["metadata"]["annotations"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        merged.insert(ANNOTATION.into(), json!(serde_json::to_string(intent)?));
        if let Some(image) = activated_image {
            merged.insert(ACTIVATED.into(), json!(image));
        }
        for operation in &mut patch {
            if operation["path"] == "/metadata/annotations" {
                operation["value"] = json!(merged);
            }
            if operation["path"] == "/metadata/annotations/day2.dev~1activation" {
                operation["value"] = snapshot["metadata"]["annotations"][ANNOTATION].clone();
            }
        }
        let result = cluster.kubectl(
            &[
                "-n".into(),
                request.namespace.clone(),
                "patch".into(),
                request.workload_kind.resource().into(),
                request.statefulset.clone(),
                "--type=json".into(),
                "-p".into(),
                serde_json::to_string(&patch)?,
            ],
            None,
            Duration::from_secs(60),
        );
        match result {
            Ok(_) => return Ok(()),
            Err(error) => {
                // Only the identical, idempotent metadata/replica transaction
                // can repeat. Business mutations and provider effects cannot.
                let raw = cluster
                    .kubectl(
                        &[
                            "-n".into(),
                            request.namespace.clone(),
                            "get".into(),
                            request.workload_kind.resource().into(),
                            request.statefulset.clone(),
                            "-o".into(),
                            "json".into(),
                        ],
                        None,
                        Duration::from_secs(60),
                    )
                    .with_context(|| {
                        format!("activation checkpoint response unresolved: {error:#}")
                    })?;
                snapshot = serde_json::from_str(&raw)?;
                ensure!(
                    snapshot["metadata"]["uid"] == intent.controller_uid
                        && template_digest(&snapshot)? == intent.template_digest,
                    "activation_checkpoint_changed"
                );
                let observed = Intent::read(&snapshot)?;
                if observed.as_ref() == Some(intent)
                    && replicas.is_none_or(|count| snapshot["spec"]["replicas"] == count)
                    && activated_image
                        .is_none_or(|image| snapshot["metadata"]["annotations"][ACTIVATED] == image)
                {
                    return Ok(());
                }
                ensure!(
                    attempt < 2
                        && observed.as_ref() == expected
                        && snapshot["spec"]["replicas"] == live["spec"]["replicas"],
                    "activation checkpoint was not acknowledged: {error:#}"
                );
            }
        }
    }
    bail!("activation checkpoint attempts exhausted")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: u8,
    session: String,
    request_digest: String,
    request: String,
    target_instance: Option<String>,
    source_controller_uid: Value,
    source_template: Value,
    source_pvc_uid: Option<String>,
    source_pod: Option<Value>,
    original_replicas: u64,
    events: Vec<Value>,
}

/// An explicit recovery never infers a source image or desired replica count
/// from current CI defaults. It is bound to the saved request and checkpoint.
pub struct Recovery {
    tools: Tools,
    request: Request,
    intent: Intent,
    owner: String,
    fenced: bool,
    claimed: bool,
    cleaned: bool,
    finished: bool,
    already_restored: bool,
    activated: bool,
}

impl Recovery {
    pub fn open(path: &Path, mut tools: Tools) -> Result<Self> {
        const LIMIT: u64 = 8 << 20;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.len() <= LIMIT,
            "activation journal size or type"
        );
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(LIMIT + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= LIMIT, "activation journal too large");
        let journal: Journal = day2::json::decode(&bytes)?;
        ensure!(
            journal.format == 2
                && day2::digest(journal.request.as_bytes()) == journal.request_digest,
            "activation_recovery_journal_identity"
        );
        let request: Request = day2::json::decode(journal.request.as_bytes())?;
        request.validate(Operation::Activate)?;
        let target = journal
            .target_instance
            .context("saved target instance required")?;
        let raw = tools.cluster.kubectl(
            &[
                "-n".into(),
                request.namespace.clone(),
                "get".into(),
                request.workload_kind.resource().into(),
                request.statefulset.clone(),
                "-o".into(),
                "json".into(),
            ],
            None,
            Duration::from_secs(60),
        )?;
        let live: Value = serde_json::from_str(&raw)?;
        let intent = Intent::read(&live)?.context("no activation checkpoint")?;
        ensure!(
            intent.request_digest == journal.request_digest
                && intent.pod
                    == format!("day2-maintenance-{}", journal.session.to_ascii_lowercase())
                && intent.target_instance_digest == day2::digest(target.as_bytes())
                && intent.controller_uid == journal.source_controller_uid
                && intent.template_digest
                    == day2::digest(&serde_json::to_vec(&journal.source_template)?)
                && Some(intent.pvc_uid.as_str()) == journal.source_pvc_uid.as_deref()
                && intent.replicas == journal.original_replicas,
            "activation_recovery_request_changed"
        );
        let _ = (journal.source_pod, journal.events);
        ensure!(
            intent.active() || matches!(intent.phase, Phase::Restored | Phase::Activated),
            "activation_already_closed"
        );
        let nonce = tempfile::tempdir()?;
        let owner = day2::digest(nonce.path().as_os_str().as_encoded_bytes());
        let mut recovery = Self {
            tools,
            request,
            owner: format!("recover-{}", &owner[7..39]),
            fenced: matches!(intent.phase, Phase::Fenced | Phase::Activated),
            already_restored: intent.phase == Phase::Restored,
            activated: intent.phase == Phase::Activated,
            intent,
            claimed: false,
            cleaned: false,
            finished: false,
        };
        recovery.validate_source(&live)?;
        Ok(recovery)
    }

    fn kubectl(&mut self, args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
        let mut full = vec!["-n".into(), self.request.namespace.clone()];
        full.extend(args.iter().map(|arg| (*arg).to_owned()));
        self.tools
            .cluster
            .kubectl(&full, stdin, Duration::from_secs(330))
    }

    fn controller(&mut self) -> Result<Value> {
        let kind = self.request.workload_kind.resource();
        let name = self.request.statefulset.clone();
        Ok(serde_json::from_str(
            &self.kubectl(&["get", kind, &name, "-o", "json"], None)?,
        )?)
    }

    fn validate_source(&mut self, live: &Value) -> Result<()> {
        ensure!(
            live["metadata"]["uid"] == self.intent.controller_uid
                && (self.activated || template_digest(live)? == self.intent.template_digest)
                && Intent::read(live)?.as_ref() == Some(&self.intent),
            "activation_recovery_controller_changed"
        );
        let pvc = self.request.pvc.clone();
        let claim: Value =
            serde_json::from_str(&self.kubectl(&["get", "pvc", &pvc, "-o", "json"], None)?)?;
        ensure!(
            claim["metadata"]["uid"] == self.intent.pvc_uid && claim["status"]["phase"] == "Bound",
            "activation_recovery_claim_changed"
        );
        if self.activated {
            return Ok(());
        }
        let name = self.request.configmap.clone();
        let config: Value =
            serde_json::from_str(&self.kubectl(&["get", "configmap", &name, "-o", "json"], None)?)?;
        ensure!(
            config["data"]["instance.json"]
                .as_str()
                .is_some_and(|text| {
                    day2::digest(text.as_bytes()) == self.intent.source_instance_digest
                }),
            "activation_recovery_instance_changed"
        );
        let replicas = live["spec"]["replicas"].as_u64().context("replicas")?;
        ensure!(
            replicas == 0 || (!self.fenced && replicas == self.intent.replicas),
            "activation_recovery_replicas_changed"
        );
        Ok(())
    }

    pub fn claim(&mut self) -> Result<Value> {
        ensure!(!self.claimed, "activation_recovery_already_claimed");
        let live = self.controller()?;
        self.validate_source(&live)?;
        if self.already_restored || self.activated {
            self.claimed = true;
            return Ok(json!({"claimed":true,"already_closed":true}));
        }
        let mut claimed = self.intent.clone();
        claimed.owner = self.owner.clone();
        // Fenced stays fenced: even a second recovery after process death
        // cannot mistake the cleanup claim for permission to start the source.
        if !self.fenced {
            claimed.phase = Phase::Recovering;
        }
        replace(
            self.tools.cluster.as_mut(),
            &self.request,
            &live,
            Some(&self.intent),
            &claimed,
            None,
        )?;
        self.intent = claimed;
        self.claimed = true;
        Ok(json!({"claimed":true,"target_only":self.fenced}))
    }

    pub fn cleanup(&mut self) -> Result<Value> {
        ensure!(
            self.claimed && !self.cleaned,
            "activation_recovery_claim_required"
        );
        let live = self.controller()?;
        self.validate_source(&live)?;
        if self.already_restored {
            self.cleaned = true;
            return Ok(json!({"helpers_removed":true,"already_closed":true}));
        }
        for name in [
            format!("{}-measure", self.intent.pod),
            self.intent.pod.clone(),
        ] {
            remove_helper(
                self.tools.cluster.as_mut(),
                &self.request,
                &name,
                &self.intent.request_digest,
                if name == self.intent.pod {
                    self.intent.pod_uid.as_deref()
                } else {
                    None
                },
            )?;
        }
        self.cleaned = true;
        Ok(json!({"helpers_removed":true}))
    }

    pub fn restore(&mut self) -> Result<Value> {
        ensure!(
            self.claimed && self.cleaned && !self.finished,
            "activation_recovery_cleanup_required"
        );
        let live = self.controller()?;
        self.validate_source(&live)?;
        if self.fenced {
            self.finished = true;
            return Ok(json!({"replicas_restored":false,"target_only":true,
                "request_digest":self.intent.request_digest,
                "activation_approved":self.activated,
                "next":if self.activated {"Release the approved target image if it is not already running; never restart the old source."}
                    else {"Resume the exact saved target activation or mark-activated request. The source remains stopped."}}));
        }
        let mut restored = self.intent.clone();
        restored.phase = Phase::Restored;
        if !self.already_restored {
            replace(
                self.tools.cluster.as_mut(),
                &self.request,
                &live,
                Some(&self.intent),
                &restored,
                if live["spec"]["replicas"] == self.intent.replicas {
                    None
                } else {
                    Some(self.intent.replicas)
                },
            )?;
        }
        self.intent = restored;
        self.finished = true;
        let kind = self.request.workload_kind.resource();
        let resource = format!("{kind}/{}", self.request.statefulset);
        self.kubectl(&["rollout", "status", &resource, "--timeout=300s"], None)?;
        Ok(json!({"replicas_restored":true,"target_only":false,"replicas":self.intent.replicas}))
    }
}
