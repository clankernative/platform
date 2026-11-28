//! Fixed scheduled-workload comparison DATA. The authenticated issuer must
//! collect every response under the same actual original and join it to the
//! kernel/runtime process. Nothing decoded or returned here grants authority.
use super::{Intent, ScheduledSlot, WorkloadUid};
use crate::security_epoch::identity_protocol::ReviewedSubject;
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{AuthorityScope, EpochIam, bootstrap::KubernetesObjectSelection},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const GENERATION: &str = "day2.dev/scheduled-backup-generation";
const CRON_UID: &str = "day2.dev/scheduled-backup-cron-uid";
const SLOT: &str = "batch.kubernetes.io/cronjob-scheduled-timestamp";
const MAX_RESPONSE: usize = 65_536;

// Canonical nested Intent contributes at most MAX_PAYLOAD bytes; this fixed
// wrapper adds only its literal tag/key punctuation (no escaped second copy).
pub(in crate::security_epoch) const MAX_SUBMIT_BYTES: usize =
    super::MAX_PAYLOAD + b"{\"type\":\"submit_backup_v1\",\"intent\":}".len();

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum SubmitData {
    #[serde(rename = "submit_backup_v1")]
    Submit { intent: Intent },
}

// Public comparison handshake only. A successful codec never supplies the
// actual socket, original, process, CREATE proof or admitted requester.
pub(in crate::security_epoch) const MAX_HELLO_BYTES: usize = 512;
pub(in crate::security_epoch) const MAX_OFFER_BYTES: usize = 1_024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum HelloData {
    #[serde(rename = "hello_backup_v1")]
    Hello { requester_nonce: Digest },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct SubmitOfferData {
    pub(in crate::security_epoch) controller: Digest,
    pub(in crate::security_epoch) job: Digest,
    pub(in crate::security_epoch) connection: Digest,
    pub(in crate::security_epoch) requester_nonce: Digest,
    pub(in crate::security_epoch) controller_nonce: Digest,
    pub(in crate::security_epoch) original: Digest,
}

impl SubmitOfferData {
    /// Endpoint-local cookie is comparison DATA, not authentication or a
    /// cross-process socket-pair identity. Native callers retain the socket.
    pub(in crate::security_epoch) fn new_data(
        controller: Digest,
        job: Digest,
        cookie: u64,
        nonces: (Digest, Digest),
        original: Digest,
    ) -> Result<Self> {
        ensure!(
            cookie != 0 && nonces.0 != nonces.1,
            "backup_offer_binding_shape"
        );
        let connection =
            Self::connection_data(cookie, &controller, &job, (&nonces.0, &nonces.1), &original)?;
        Ok(Self {
            controller,
            job,
            connection,
            requester_nonce: nonces.0,
            controller_nonce: nonces.1,
            original,
        })
    }

    fn connection_data(
        cookie: u64,
        controller: &Digest,
        job: &Digest,
        nonces: (&Digest, &Digest),
        original: &Digest,
    ) -> Result<Digest> {
        Digest::of(&(
            "day2-scheduled-backup-accepted-endpoint-v1",
            cookie,
            controller,
            job,
            nonces.0,
            nonces.1,
            original,
        ))
    }

    pub(in crate::security_epoch) fn require_connection_data(&self, cookie: u64) -> Result<()> {
        ensure!(
            cookie != 0
                && self.connection
                    == Self::connection_data(
                        cookie,
                        &self.controller,
                        &self.job,
                        (&self.requester_nonce, &self.controller_nonce),
                        &self.original
                    )?,
            "backup_offer_connection_changed"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum OfferData {
    #[serde(rename = "offer_backup_v1")]
    Offer { offer: SubmitOfferData },
}

pub(in crate::security_epoch) fn encode_hello_data(requester_nonce: Digest) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&HelloData::Hello { requester_nonce })?;
    ensure!(bytes.len() <= MAX_HELLO_BYTES, "backup_hello_bound");
    Ok(bytes)
}

pub(in crate::security_epoch) fn decode_hello_data(bytes: &[u8]) -> Result<Digest> {
    ensure!(bytes.len() <= MAX_HELLO_BYTES, "backup_hello_bound");
    let packet: HelloData =
        crate::json::decode(bytes).map_err(|_| anyhow::anyhow!("backup_hello_encoding"))?;
    ensure!(
        serde_json::to_vec(&packet)? == bytes,
        "backup_hello_noncanonical"
    );
    let HelloData::Hello { requester_nonce } = packet;
    Ok(requester_nonce)
}

pub(in crate::security_epoch) fn encode_offer_data(offer: &SubmitOfferData) -> Result<Vec<u8>> {
    ensure!(
        offer.requester_nonce != offer.controller_nonce,
        "backup_offer_reflected_nonce"
    );
    let bytes = serde_json::to_vec(&OfferData::Offer {
        offer: offer.clone(),
    })?;
    ensure!(bytes.len() <= MAX_OFFER_BYTES, "backup_offer_bound");
    Ok(bytes)
}

pub(in crate::security_epoch) fn decode_offer_data(bytes: &[u8]) -> Result<SubmitOfferData> {
    ensure!(bytes.len() <= MAX_OFFER_BYTES, "backup_offer_bound");
    let packet: OfferData =
        crate::json::decode(bytes).map_err(|_| anyhow::anyhow!("backup_offer_encoding"))?;
    ensure!(
        serde_json::to_vec(&packet)? == bytes,
        "backup_offer_noncanonical"
    );
    let OfferData::Offer { offer } = packet;
    ensure!(
        offer.requester_nonce != offer.controller_nonce,
        "backup_offer_reflected_nonce"
    );
    Ok(offer)
}

/// Complete only public candidate DATA. Actual native admission independently
/// requires the real accepted resources and every current authority boundary.
pub(in crate::security_epoch) fn complete_offer_intent_data(
    candidate: &[u8],
    offer: &SubmitOfferData,
) -> Result<Vec<u8>> {
    ensure!(
        offer.requester_nonce != offer.controller_nonce,
        "backup_offer_reflected_nonce"
    );
    let mut intent = Intent::decode_data(candidate)?;
    intent.requester.process = offer.job.clone();
    intent.transport = super::Transport {
        controller: offer.controller.clone(),
        connection: offer.connection.clone(),
        requester_nonce: offer.requester_nonce.clone(),
        controller_nonce: offer.controller_nonce.clone(),
        original: offer.original.clone(),
    };
    intent.validate_data()?;
    Ok(serde_json::to_vec(&intent)?)
}

pub(in crate::security_epoch) fn require_submit_offer_data(
    intent: &[u8],
    offer: &SubmitOfferData,
) -> Result<()> {
    let intent = Intent::decode_data(intent)?;
    ensure!(
        offer.requester_nonce != offer.controller_nonce
            && intent.requester.process == offer.job
            && intent.transport.controller == offer.controller
            && intent.transport.connection == offer.connection
            && intent.transport.requester_nonce == offer.requester_nonce
            && intent.transport.controller_nonce == offer.controller_nonce
            && intent.transport.original == offer.original,
        "backup_submit_offer_changed"
    );
    Ok(())
}

/// Closed wire DATA, not authenticated admission or an original constructor.
pub(in crate::security_epoch) fn decode_submit_data(bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        bytes.len() <= MAX_SUBMIT_BYTES,
        "backup_submit_payload_bound"
    );
    let packet: SubmitData = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("backup_submit_payload_encoding"))?;
    ensure!(
        serde_json::to_vec(&packet)? == bytes,
        "backup_submit_noncanonical_payload"
    );
    let SubmitData::Submit { intent } = packet;
    intent.validate_data()?;
    Ok(serde_json::to_vec(&intent)?)
}

pub(in crate::security_epoch) fn encode_submit_data(intent: &[u8]) -> Result<Vec<u8>> {
    let intent = Intent::decode_data(intent)?;
    let bytes = serde_json::to_vec(&SubmitData::Submit { intent })?;
    ensure!(
        bytes.len() <= MAX_SUBMIT_BYTES,
        "backup_submit_payload_bound"
    );
    Ok(bytes)
}

/// Compare only the declared request-domain DATA; the real resource guard
/// separately requires the identical retained original observation and clock.
pub(in crate::security_epoch) fn require_submit_original_data(
    intent: &[u8],
    domain: &Digest,
) -> Result<()> {
    ensure!(
        Intent::decode_data(intent)?.transport.original == *domain,
        "backup_submit_intent_original_changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests;

/// Synthetic comparison DATA for sibling codec tests, never native resources.
#[cfg(test)]
pub(in crate::security_epoch) fn comparison_fixture_data()
-> Result<(RequesterPolicy, Value, WorkloadData)> {
    tests::comparison_fixture_data()
}

#[cfg(test)]
pub(in crate::security_epoch) fn fixture_intent_bytes(value: Value) -> Result<Vec<u8>> {
    let intent: Intent = serde_json::from_value(value)?;
    intent.validate_data()?;
    Ok(serde_json::to_vec(&intent)?)
}

/// Reviewed selection, not a producer or an enable switch. Absence from the
/// actual native policy disables this purpose; no incoming request selects it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct RequesterPolicy {
    pub scope: AuthorityScope,
    pub generation: Digest,
    /// Independently reviewed earliest eligible UTC slot for this generation.
    /// This is selection DATA, never a native clock or past VAP witness.
    pub eligible_from: String,
    pub cluster: Digest,
    pub node: Digest,
    pub node_name: String,
    pub namespace: KubernetesObjectSelection,
    pub cron_job: KubernetesObjectSelection,
    pub service_account: KubernetesObjectSelection,
    pub uploader: EpochIam,
    pub container: String,
    pub image: Digest,
    pub executable: Digest,
    pub cron_spec: Digest,
    pub job_pod_spec: Digest,
    pub running_pod_spec: Digest,
    pub admission: KubernetesObjectSelection,
    pub binding: KubernetesObjectSelection,
    /// Actual qualified controller subjects, never guessed standard names.
    pub cron_controller: String,
    pub job_controller: String,
    /// The actual qualified garbage-collector subject for owned cleanup only.
    pub cleanup_controller: String,
    /// Reviewed infrastructure/configuration writers; not the app deployer.
    pub configuration_writers: Vec<String>,
}

impl RequesterPolicy {
    pub(in crate::security_epoch) fn validate_data(&self) -> Result<()> {
        let _: ScheduledSlot = self.eligible_from.clone().try_into()?;
        for object in [
            &self.namespace,
            &self.cron_job,
            &self.service_account,
            &self.admission,
            &self.binding,
        ] {
            ensure!(dns_name(&object.name), "backup_requester_object_name");
            let _: WorkloadUid = object.uid.clone().try_into()?;
        }
        ensure!(
            dns_label(&self.namespace.name)
                && dns_label(&self.cron_job.name)
                && self.cron_job.name.len() <= 52
                && dns_label(&self.service_account.name),
            "backup_requester_namespaced_name"
        );
        self.uploader.validate()?;
        ensure!(
            dns_name(&self.node_name) && dns_label(&self.container),
            "backup_requester_name"
        );
        ensure!(
            (1..=16).contains(&self.configuration_writers.len())
                && self.configuration_writers.windows(2).all(|p| p[0] < p[1]),
            "backup_requester_config_writers"
        );
        for subject in std::iter::once(&self.cron_controller)
            .chain(std::iter::once(&self.job_controller))
            .chain(std::iter::once(&self.cleanup_controller))
            .chain(&self.configuration_writers)
        {
            ensure!(
                !subject.is_empty()
                    && subject.len() <= 512
                    && subject.bytes().all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b':' | b'@' | b'.' | b'_' | b'-' | b'/')),
                "backup_requester_subject"
            );
        }
        ensure!(
            !self.configuration_writers.contains(&self.cron_controller)
                && !self.configuration_writers.contains(&self.job_controller)
                && !self
                    .configuration_writers
                    .contains(&self.cleanup_controller),
            "backup_requester_subject_overlap"
        );
        Ok(())
    }

    pub(in crate::security_epoch) fn admission_generation_data(&self) -> Result<Digest> {
        self.validate_data()?;
        Digest::of(&(
            "day2-scheduled-backup-enforcement-v1",
            &self.admission,
            &self.binding,
            self.policy_spec_data()?,
            self.binding_spec_data(),
        ))
    }

    /// One complete fixed enforcement profile. Caller supplied CEL/specs are
    /// never accepted. Root/admission writers remain explicitly in the TCB.
    pub(in crate::security_epoch) fn policy_spec_data(&self) -> Result<Value> {
        self.validate_data()?;
        let q = |s: &str| serde_json::to_string(s).expect("string serialization");
        let namespace = q(&self.namespace.name);
        let cron = q(&self.cron_job.name);
        let uid = q(&self.cron_job.uid);
        let account = q(&self.service_account.name);
        let generation = q(self.generation.as_str());
        let cron_controller = q(&self.cron_controller);
        let job_controller = q(&self.job_controller);
        let cleanup_controller = q(&self.cleanup_controller);
        let writers = serde_json::to_string(&self.configuration_writers)?;
        let owner = |kind: &str, api: &str| {
            format!(
                "has(object.metadata.ownerReferences) && object.metadata.ownerReferences.size() == 1 && object.metadata.ownerReferences[0].controller == true && object.metadata.ownerReferences[0].kind == {} && object.metadata.ownerReferences[0].apiVersion == {}",
                q(kind),
                q(api)
            )
        };
        let annotation = |key: &str, value: &str| {
            format!(
                "has(object.metadata.annotations) && {} in object.metadata.annotations && object.metadata.annotations[{}] == {value}",
                q(key),
                q(key)
            )
        };
        let generation_check = annotation(GENERATION, &generation);
        let cron_check = annotation(CRON_UID, &uid);
        // The selected KSA is the protected route. A Job using any other KSA
        // cannot pass the independent live workload validator below.
        let selected_job = format!(
            "(object != null && has(object.spec.template.spec.serviceAccountName) && object.spec.template.spec.serviceAccountName == {account}) || (oldObject != null && has(oldObject.spec.template.spec.serviceAccountName) && oldObject.spec.template.spec.serviceAccountName == {account})"
        );
        let selected_pod = format!(
            "(object != null && has(object.spec.serviceAccountName) && object.spec.serviceAccountName == {account}) || (oldObject != null && has(oldObject.spec.serviceAccountName) && oldObject.spec.serviceAccountName == {account})"
        );
        let unchanged = "object.spec == oldObject.spec && object.metadata.ownerReferences == oldObject.metadata.ownerReferences && object.metadata.annotations == oldObject.metadata.annotations";
        // DELETE is a reducing lifecycle operation, not CREATE/mutation or
        // source authority. Permit only the qualified controller and the exact
        // protected old owner chain, so activeDeadlineSeconds can terminate.
        let delete_owner = |kind: &str, api: &str| {
            format!(
                "has(oldObject.metadata.ownerReferences) && oldObject.metadata.ownerReferences.size() == 1 && oldObject.metadata.ownerReferences[0].controller == true && oldObject.metadata.ownerReferences[0].kind == {} && oldObject.metadata.ownerReferences[0].apiVersion == {}",
                q(kind),
                q(api)
            )
        };
        let job_delete = format!(
            "(request.userInfo.username == {cron_controller} || request.userInfo.username == {cleanup_controller}) && {} && oldObject.metadata.ownerReferences[0].uid == {uid} && oldObject.metadata.ownerReferences[0].name == {cron}",
            delete_owner("CronJob", "batch/v1")
        );
        let pod_delete = format!(
            "(request.userInfo.username == {job_controller} || request.userInfo.username == {cleanup_controller}) && {} && has(oldObject.metadata.annotations) && {} in oldObject.metadata.annotations && oldObject.metadata.annotations[{}] == {uid}",
            delete_owner("Job", "batch/v1"),
            q(CRON_UID),
            q(CRON_UID)
        );
        let job_create = format!(
            "request.userInfo.username == {cron_controller} && {} && object.metadata.ownerReferences[0].uid == {uid} && object.metadata.ownerReferences[0].name == {cron} && {generation_check} && {cron_check} && has(object.metadata.annotations) && {} in object.metadata.annotations && object.metadata.annotations[{}].matches('^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}Z$')",
            owner("CronJob", "batch/v1"),
            q(SLOT),
            q(SLOT)
        );
        let pod_create = format!(
            "request.userInfo.username == {job_controller} && {} && {generation_check} && {cron_check}",
            owner("Job", "batch/v1")
        );
        Ok(json!({
            "failurePolicy":"Fail",
            "matchConstraints":{"matchPolicy":"Exact","resourceRules":[
                {"apiGroups":["batch"],"apiVersions":["v1"],"operations":["CREATE","UPDATE","DELETE"],"resources":["cronjobs","jobs"],"scope":"Namespaced"},
                {"apiGroups":[""],"apiVersions":["v1"],"operations":["CREATE","UPDATE","DELETE"],"resources":["pods"],"scope":"Namespaced"}
            ]},
            "matchConditions":[{"name":"selected-namespace","expression":format!("request.namespace == {namespace}")}],
            "validations":[
                {"expression":format!("request.resource.resource != 'cronjobs' || !((object != null && object.metadata.name == {cron}) || (oldObject != null && oldObject.metadata.name == {cron})) || request.userInfo.username in {writers}"),"message":"scheduled backup configuration writer required"},
                {"expression":format!("request.resource.resource != 'jobs' || !({selected_job}) || (request.operation == 'CREATE' ? ({job_create}) : (request.operation == 'UPDATE' ? ({unchanged}) : (request.userInfo.username in {writers} || ({job_delete}))))"),"message":"protected scheduled backup Job required"},
                {"expression":format!("request.resource.resource != 'pods' || !({selected_pod}) || (request.operation == 'CREATE' ? ({pod_create}) : (request.operation == 'UPDATE' ? ({unchanged}) : (request.userInfo.username in {writers} || ({pod_delete}))))"),"message":"protected scheduled backup Pod required"}
            ]
        }))
    }

    pub(in crate::security_epoch) fn binding_spec_data(&self) -> Value {
        json!({"policyName":self.admission.name,"validationActions":["Deny"]})
    }
}

/// Complete bounded provider responses, freshly collected by the fixed issuer.
/// This type cannot authenticate the responses or construct a native owner.
pub(in crate::security_epoch) struct WorkloadResponses<'a> {
    pub namespace: &'a [u8],
    pub service_account: &'a [u8],
    pub cron_job: &'a [u8],
    pub job: &'a [u8],
    pub pod: &'a [u8],
    pub admission: &'a [u8],
    pub binding: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct WorkloadData {
    pub pod_name: String,
    pub pod_uid: String,
    pub job_name: String,
    pub job_uid: String,
    pub scheduled_slot: String,
    pub container_id: String,
    pub restart_count: u64,
    pub admission_generation: Digest,
}

/// Exact mechanical-process commitments only. Authentication and the
/// Controller's actual original remain with the native caller, not this DATA.
#[cfg(any(target_os = "linux", test))]
pub(in crate::security_epoch) fn validate_process_commitments_data(
    bytes: &[u8],
    job: &Digest,
    controller: &Digest,
) -> Result<Digest> {
    let intent = Intent::decode_data(bytes)?;
    ensure!(
        intent.requester.process == *job && intent.transport.controller == *controller,
        "backup_requester_process_commitment"
    );
    intent.commitment_data()
}

#[cfg(any(target_os = "linux", test))]
pub(in crate::security_epoch) fn intent_digest_data(bytes: &[u8]) -> Result<Digest> {
    Intent::decode_data(bytes)?.commitment_data()
}

#[cfg(test)]
pub(in crate::security_epoch) fn policy_fixture_data() -> Result<RequesterPolicy> {
    tests::policy_fixture_data()
}

pub(in crate::security_epoch) fn validate_workload_data(
    selected: &RequesterPolicy,
    runtime_subject: &ReviewedSubject,
    intent_bytes: &[u8],
    responses: WorkloadResponses<'_>,
) -> Result<WorkloadData> {
    selected.validate_data()?;
    let intent = Intent::decode_data(intent_bytes)?;
    let namespace = decode(responses.namespace)?;
    object(&namespace, "v1", "Namespace", &selected.namespace)?;
    let account = decode(responses.service_account)?;
    object(&account, "v1", "ServiceAccount", &selected.service_account)?;
    require_namespace(&account, &selected.namespace.name)?;
    let EpochIam::GkeWorkloadIdentityV1 {
        service_account, ..
    } = &selected.uploader;
    ensure!(
        account
            .pointer("/metadata/annotations/iam.gke.io~1gcp-service-account")
            .and_then(Value::as_str)
            == Some(service_account),
        "backup_requester_mapping"
    );
    let policy = decode(responses.admission)?;
    object(
        &policy,
        "admissionregistration.k8s.io/v1",
        "ValidatingAdmissionPolicy",
        &selected.admission,
    )?;
    let generation = policy
        .pointer("/metadata/generation")
        .and_then(Value::as_u64)
        .context("backup_requester_admission_generation")?;
    ensure!(
        generation > 0
            && policy
                .pointer("/status/observedGeneration")
                .and_then(Value::as_u64)
                == Some(generation)
            && policy
                .pointer("/status/typeChecking/expressionWarnings")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
            && policy.get("spec") == Some(&selected.policy_spec_data()?),
        "backup_requester_enforcement"
    );
    let binding = decode(responses.binding)?;
    object(
        &binding,
        "admissionregistration.k8s.io/v1",
        "ValidatingAdmissionPolicyBinding",
        &selected.binding,
    )?;
    ensure!(
        binding.get("spec") == Some(&selected.binding_spec_data()),
        "backup_requester_enforcement_binding"
    );
    let cron = decode(responses.cron_job)?;
    object(&cron, "batch/v1", "CronJob", &selected.cron_job)?;
    require_namespace(&cron, &selected.namespace.name)?;
    let cron_spec = cron.get("spec").context("backup_requester_cron_spec")?;
    // A reviewed hash cannot authorize unbounded unsuspend catch-up. This
    // fixed profile permits at most one hour to START a scheduled Job; it
    // does not change that Job's deadline or any native original/role bound.
    ensure!(
        cron_spec
            .get("startingDeadlineSeconds")
            .and_then(Value::as_u64)
            .is_some_and(|seconds| (1..=3600).contains(&seconds)),
        "backup_requester_start_deadline"
    );
    ensure!(
        Digest::of(cron_spec)? == selected.cron_spec
            && cron_spec.get("suspend") == Some(&Value::Bool(false))
            && cron_spec.get("timeZone").and_then(Value::as_str) == Some("Etc/UTC")
            && cron_spec.get("concurrencyPolicy").and_then(Value::as_str) == Some("Forbid"),
        "backup_requester_cron_selection"
    );
    let job = decode(responses.job)?;
    let job_meta = metadata(&job, "batch/v1", "Job")?;
    require_namespace(&job, &selected.namespace.name)?;
    let job_uid = text(job_meta, "uid")?;
    let job_name = text(job_meta, "name")?;
    owner(
        &job,
        "batch/v1",
        "CronJob",
        &selected.cron_job.name,
        &selected.cron_job.uid,
    )?;
    let slot = annotation_data(&job, SLOT)?;
    let _: ScheduledSlot = slot.to_owned().try_into()?;
    ensure!(
        slot >= selected.eligible_from.as_str(),
        "backup_requester_pre_eligibility_slot"
    );
    for value in [&job, &cron] {
        ensure!(
            annotation_data(value, GENERATION)? == selected.generation.as_str()
                && annotation_data(value, CRON_UID)? == selected.cron_job.uid,
            "backup_requester_generation"
        );
    }
    ensure!(
        job.pointer("/spec/backoffLimit").and_then(Value::as_u64) == Some(0)
            && job.pointer("/spec/parallelism").and_then(Value::as_u64) == Some(1)
            && job.pointer("/spec/completions").and_then(Value::as_u64) == Some(1)
            && job
                .pointer("/spec/activeDeadlineSeconds")
                .and_then(Value::as_u64)
                .is_some_and(|v| (1..=3600).contains(&v))
            && job
                .pointer("/status/succeeded")
                .is_none_or(|v| v.as_u64() == Some(0))
            && job
                .pointer("/status/failed")
                .is_none_or(|v| v.as_u64() == Some(0)),
        "backup_requester_job_lifecycle"
    );
    let job_spec = job
        .pointer("/spec/template/spec")
        .context("backup_requester_job_spec")?;
    ensure!(
        cron_spec.pointer("/jobTemplate/spec/template/spec") == Some(job_spec),
        "backup_requester_cron_job_template_changed"
    );
    pod_profile(selected, job_spec)?;
    ensure!(
        Digest::of(job_spec)? == selected.job_pod_spec,
        "backup_requester_job_spec"
    );
    let pod = decode(responses.pod)?;
    let pod_meta = metadata(&pod, "v1", "Pod")?;
    require_namespace(&pod, &selected.namespace.name)?;
    let pod_name = text(pod_meta, "name")?;
    let pod_uid = text(pod_meta, "uid")?;
    // Names come from the independently observed runtime selection used for
    // the actual GET route, not from the body it happened to return.
    ensure!(
        pod_name == runtime_subject.pod_name && pod_uid == runtime_subject.pod_uid,
        "backup_requester_runtime_subject"
    );
    owner(&pod, "batch/v1", "Job", job_name, job_uid)?;
    ensure!(
        annotation_data(&pod, GENERATION)? == selected.generation.as_str()
            && annotation_data(&pod, CRON_UID)? == selected.cron_job.uid,
        "backup_requester_pod_generation"
    );
    let spec = pod.get("spec").context("backup_requester_pod_spec")?;
    require_pod_derivation(selected, job_spec, spec)?;
    pod_profile(selected, spec)?;
    ensure!(
        Digest::of(spec)? == selected.running_pod_spec
            && spec.get("nodeName").and_then(Value::as_str) == Some(selected.node_name.as_str())
            && pod.pointer("/status/phase").and_then(Value::as_str) == Some("Running"),
        "backup_requester_pod_current"
    );
    let statuses = pod
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
        .context("backup_requester_container_status")?;
    ensure!(statuses.len() == 1, "backup_requester_container_count");
    let status = &statuses[0];
    let container_id = status
        .get("containerID")
        .and_then(Value::as_str)
        .context("backup_requester_container_id")?;
    let raw_id = container_id
        .strip_prefix("containerd://")
        .context("backup_requester_runtime_kind")?;
    let image = status
        .get("imageID")
        .and_then(Value::as_str)
        .context("backup_requester_current_image")?;
    let restart_count = status
        .get("restartCount")
        .and_then(Value::as_u64)
        .context("backup_requester_restart_count")?;
    ensure!(
        raw_id.len() == 64
            && raw_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && status.get("name").and_then(Value::as_str) == Some(selected.container.as_str())
            && image
                .rsplit_once('@')
                .is_some_and(|(_, d)| d == selected.image.as_str())
            && status
                .get("state")
                .and_then(Value::as_object)
                .is_some_and(|v| v.len() == 1 && v.get("running").is_some_and(Value::is_object))
            && restart_count == 0,
        "backup_requester_container_current"
    );
    let data = WorkloadData {
        pod_name: pod_name.to_owned(),
        pod_uid: pod_uid.to_owned(),
        job_name: job_name.to_owned(),
        job_uid: job_uid.to_owned(),
        scheduled_slot: slot.to_owned(),
        container_id: container_id.to_owned(),
        restart_count,
        admission_generation: selected.admission_generation_data()?,
    };
    require_workload_intent(selected, &intent, &data)?;
    Ok(data)
}

/// The signed receiver uses the SAME comparison join as the actual producer.
/// This checks DATA coherence, not CREATE provenance or source admission.
pub(in crate::security_epoch) fn require_observed_workload_data(
    selected: &RequesterPolicy,
    bytes: &[u8],
    data: &WorkloadData,
) -> Result<()> {
    selected.validate_data()?;
    require_workload_intent(selected, &Intent::decode_data(bytes)?, data)
}

fn require_workload_intent(
    selected: &RequesterPolicy,
    intent: &Intent,
    data: &WorkloadData,
) -> Result<()> {
    let EpochIam::GkeWorkloadIdentityV1 {
        service_account_uid,
        ..
    } = &selected.uploader;
    ensure!(
        intent.policy_generation == selected.generation
            && intent.slot.scope == selected.scope
            && intent.slot.cron_job_uid.0 == selected.cron_job.uid
            && intent.slot.scheduled_at.0 == data.scheduled_slot
            && intent.cron_job_spec == selected.cron_spec
            && intent.admission_generation == selected.admission_generation_data()?
            && intent.requester.cluster == selected.cluster
            && intent.requester.node == selected.node
            && intent.requester.namespace_uid.0 == selected.namespace.uid
            && intent.requester.job_uid.0 == data.job_uid
            && intent.requester.pod_uid.0 == data.pod_uid
            && intent.requester.ksa_uid.0 == selected.service_account.uid
            && intent.requester.uploader_uid == *service_account_uid
            && intent.requester.image == selected.image
            && intent.requester.executable == selected.executable
            && data.admission_generation == selected.admission_generation_data()?
            && data.scheduled_slot.as_str() >= selected.eligible_from.as_str()
            && data.restart_count == 0,
        "backup_requester_intent_join"
    );
    Ok(())
}

fn decode(bytes: &[u8]) -> Result<Value> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_RESPONSE,
        "backup_requester_response_bound"
    );
    crate::json::decode(bytes).map_err(|_| anyhow::anyhow!("backup_requester_response_encoding"))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .context("backup_requester_field")
}

fn metadata<'a>(value: &'a Value, api: &str, kind: &str) -> Result<&'a Value> {
    ensure!(
        value.get("apiVersion").and_then(Value::as_str) == Some(api)
            && value.get("kind").and_then(Value::as_str) == Some(kind),
        "backup_requester_object_kind"
    );
    let meta = value.get("metadata").context("backup_requester_metadata")?;
    ensure!(
        dns_name(text(meta, "name")?) && meta.get("deletionTimestamp").is_none_or(Value::is_null),
        "backup_requester_object_lifecycle"
    );
    let _: WorkloadUid = text(meta, "uid")?.to_owned().try_into()?;
    Ok(meta)
}

fn object(
    value: &Value,
    api: &str,
    kind: &str,
    selected: &KubernetesObjectSelection,
) -> Result<()> {
    let meta = metadata(value, api, kind)?;
    ensure!(
        text(meta, "name")? == selected.name && text(meta, "uid")? == selected.uid,
        "backup_requester_object_selection"
    );
    Ok(())
}

fn require_namespace(value: &Value, namespace: &str) -> Result<()> {
    ensure!(
        value.pointer("/metadata/namespace").and_then(Value::as_str) == Some(namespace),
        "backup_requester_namespace"
    );
    Ok(())
}

fn annotation_data<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .pointer("/metadata/annotations")
        .and_then(|v| v.get(name))
        .and_then(Value::as_str)
        .context("backup_requester_annotation")
}

fn owner(value: &Value, api: &str, kind: &str, name: &str, uid: &str) -> Result<()> {
    let owners = value
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .context("backup_requester_owner")?;
    ensure!(
        owners.len() == 1
            && owners[0].get("apiVersion").and_then(Value::as_str) == Some(api)
            && owners[0].get("kind").and_then(Value::as_str) == Some(kind)
            && owners[0].get("name").and_then(Value::as_str) == Some(name)
            && owners[0].get("uid").and_then(Value::as_str) == Some(uid)
            && owners[0].get("controller") == Some(&Value::Bool(true)),
        "backup_requester_owner_join"
    );
    Ok(())
}

/// Supported Pod admission additions are explicit and exact. They cannot
/// override a selected template field or bless another mutator's output.
fn require_pod_derivation(selected: &RequesterPolicy, template: &Value, pod: &Value) -> Result<()> {
    let mut expected = template.clone();
    let map = expected
        .as_object_mut()
        .context("backup_requester_template_map")?;
    match map.get("nodeName") {
        Some(value) => ensure!(
            value.as_str() == Some(selected.node_name.as_str()),
            "backup_requester_template_node"
        ),
        None => {
            map.insert("nodeName".into(), json!(selected.node_name));
        }
    }
    for (key, value) in [
        ("serviceAccount", json!(selected.service_account.name)),
        ("priority", json!(0)),
        ("preemptionPolicy", json!("PreemptLowerPriority")),
    ] {
        if !map.contains_key(key) && pod.get(key).is_some() {
            ensure!(
                pod.get(key) == Some(&value),
                "backup_requester_pod_default_changed"
            );
            map.insert(key.into(), value);
        }
    }
    if !map.contains_key("tolerations") && pod.get("tolerations").is_some() {
        let value = json!([
            {"key":"node.kubernetes.io/not-ready","operator":"Exists","effect":"NoExecute","tolerationSeconds":300},
            {"key":"node.kubernetes.io/unreachable","operator":"Exists","effect":"NoExecute","tolerationSeconds":300}
        ]);
        ensure!(
            pod.get("tolerations") == Some(&value),
            "backup_requester_pod_tolerations_changed"
        );
        map.insert("tolerations".into(), value);
    }
    ensure!(expected == *pod, "backup_requester_pod_derivation_changed");
    Ok(())
}

fn pod_profile(selected: &RequesterPolicy, spec: &Value) -> Result<()> {
    only_fields(
        spec,
        &[
            "containers",
            "volumes",
            "serviceAccountName",
            "serviceAccount",
            "automountServiceAccountToken",
            "enableServiceLinks",
            "restartPolicy",
            "nodeSelector",
            "nodeName",
            "securityContext",
            "affinity",
            "tolerations",
            "dnsPolicy",
            "schedulerName",
            "terminationGracePeriodSeconds",
            "priority",
            "preemptionPolicy",
            "hostPID",
            "hostIPC",
            "hostNetwork",
            "shareProcessNamespace",
            "initContainers",
            "ephemeralContainers",
            "imagePullSecrets",
        ],
    )?;
    ensure!(
        spec.get("serviceAccountName").and_then(Value::as_str)
            == Some(selected.service_account.name.as_str())
            && spec.get("automountServiceAccountToken") == Some(&Value::Bool(false))
            && spec.get("restartPolicy").and_then(Value::as_str) == Some("Never"),
        "backup_requester_pod_identity"
    );
    for name in ["hostPID", "hostIPC", "hostNetwork", "shareProcessNamespace"] {
        ensure!(
            spec.get(name).is_none_or(|v| v == &Value::Bool(false)),
            "backup_requester_sandbox"
        );
    }
    for name in ["initContainers", "ephemeralContainers", "imagePullSecrets"] {
        ensure!(
            spec.get(name)
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
            "backup_requester_extra_container_or_secret"
        );
    }
    let containers = spec
        .get("containers")
        .and_then(Value::as_array)
        .context("backup_requester_container")?;
    ensure!(
        containers.len() == 1
            && containers[0].get("name").and_then(Value::as_str)
                == Some(selected.container.as_str())
            && containers[0]
                .get("image")
                .and_then(Value::as_str)
                .is_some_and(|image| image
                    .rsplit_once('@')
                    .is_some_and(|(_, d)| d == selected.image.as_str())),
        "backup_requester_container_selection"
    );
    only_fields(
        &containers[0],
        &[
            "name",
            "image",
            "imagePullPolicy",
            "command",
            "args",
            "env",
            "resources",
            "securityContext",
            "volumeMounts",
            "terminationMessagePath",
            "terminationMessagePolicy",
        ],
    )?;
    // The fixed native requester needs no Pod-supplied environment. In
    // particular a complete expected spec hash must not bless SecretRef,
    // token, credential-source or other ambient environment injection.
    ensure!(
        containers[0]
            .get("env")
            .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
        "backup_requester_environment"
    );
    let security = containers[0]
        .get("securityContext")
        .context("backup_requester_security_context")?;
    ensure!(
        security.get("allowPrivilegeEscalation") == Some(&Value::Bool(false))
            && security.get("readOnlyRootFilesystem") == Some(&Value::Bool(true))
            && security.get("runAsNonRoot") == Some(&Value::Bool(true))
            && security
                .get("privileged")
                .is_none_or(|v| v == &Value::Bool(false))
            && security.pointer("/capabilities/drop") == Some(&json!(["ALL"]))
            && security
                .pointer("/capabilities/add")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "backup_requester_privilege"
    );
    only_fields(
        security,
        &[
            "runAsNonRoot",
            "runAsUser",
            "runAsGroup",
            "allowPrivilegeEscalation",
            "readOnlyRootFilesystem",
            "privileged",
            "capabilities",
            "seccompProfile",
        ],
    )?;
    ensure!(
        security
            .get("runAsUser")
            .and_then(Value::as_u64)
            .is_some_and(|v| v > 0)
            && security
                .pointer("/seccompProfile/type")
                .and_then(Value::as_str)
                == Some("RuntimeDefault"),
        "backup_requester_user_or_seccomp"
    );
    let volumes = spec
        .get("volumes")
        .and_then(Value::as_array)
        .context("backup_requester_volumes")?;
    ensure!(
        (1..=8).contains(&volumes.len()),
        "backup_requester_volume_count"
    );
    // Exact complete spec digests above select paths/size/read-only mappings.
    // Independently reject state/host/device/custody and token projections.
    for volume in volumes {
        let map = volume.as_object().context("backup_requester_volume")?;
        ensure!(
            map.len() == 2
                && map.contains_key("name")
                && (map.contains_key("emptyDir")
                    || map.contains_key("configMap")
                    || map.contains_key("hostPath")),
            "backup_requester_volume_kind"
        );
        if let Some(host) = map.get("hostPath") {
            ensure!(
                host.as_object().is_some_and(|v| v.len() == 2)
                    && host.get("path").and_then(Value::as_str)
                        == Some(
                            format!("/run/day2-backup/{}", selected.scope.app.as_str()).as_str()
                        )
                    && host.get("type").and_then(Value::as_str) == Some("Directory"),
                "backup_requester_socket_directory"
            );
            let name = text(volume, "name")?;
            let mounts = containers[0]
                .get("volumeMounts")
                .and_then(Value::as_array)
                .context("backup_requester_mounts")?;
            let matching = mounts
                .iter()
                .filter(|m| m.get("name").and_then(Value::as_str) == Some(name))
                .collect::<Vec<_>>();
            ensure!(
                matching.len() == 1
                    && matching[0].get("readOnly") == Some(&Value::Bool(true))
                    && matching[0].get("mountPath").and_then(Value::as_str)
                        == Some("/run/day2-backup")
                    && matching[0].get("subPath").is_none()
                    && matching[0].get("subPathExpr").is_none(),
                "backup_requester_socket_mount"
            );
        }
    }
    Ok(())
}

fn only_fields(value: &Value, allowed: &[&str]) -> Result<()> {
    let map = value.as_object().context("backup_requester_map")?;
    ensure!(
        map.keys().all(|key| allowed.contains(&key.as_str())),
        "backup_requester_unsupported_field"
    );
    Ok(())
}

fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn dns_name(value: &str) -> bool {
    value.len() <= 253 && value.split('.').all(dns_label)
}
