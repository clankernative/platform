//! Each entry is one native capability selected by Maintain.roc. Kubernetes
//! identities and the canonical SQLite journal are re-read on every retry.
use super::*;
use std::{fs, time::Duration};

impl Session {
    pub(super) fn pair_request(&self) -> Result<RuntimePairRequest> {
        self.request
            .runtime_pair
            .clone()
            .context("runtime_pair_request_required")
    }

    pub(super) fn pair_read(&mut self, kind: &str, name: &str) -> Result<Value> {
        let args = if name.is_empty() {
            vec!["get", kind, "-o", "json"]
        } else {
            vec!["get", kind, name, "-o", "json"]
        };
        let raw = self.kubectl(&args, None, Duration::from_secs(60))?;
        provider::decode(&raw)
    }

    pub(super) fn pair_optional(&mut self, kind: &str, name: &str) -> Result<Option<Value>> {
        let raw = self.kubectl(
            &["get", kind, name, "--ignore-not-found", "-o", "json"],
            None,
            Duration::from_secs(60),
        )?;
        if raw.trim().is_empty() {
            Ok(None)
        } else {
            Ok(Some(provider::decode(&raw)?))
        }
    }

    pub(super) fn pair_cloud(&mut self, read: BackendRead) -> Result<Value> {
        let pair = self.pair_request()?;
        let raw = self
            .tools
            .cluster
            .backend_read(&pair.project, &read, Duration::from_secs(60))?;
        provider::decode(&raw)
    }

    pub(super) fn pair_backend(&mut self) -> Result<(Value, day2::runtime_pair::Backend)> {
        let pair = self.pair_request()?;
        let service = self.pair_read("service", &pair.service)?;
        let raw = self.pair_cloud(BackendRead::Service {
            name: pair.backend_service.clone(),
        })?;
        let preliminary = provider::backend(&pair, &service, &raw)?;
        let check = self.pair_cloud(BackendRead::HealthCheck {
            name: preliminary.health_check.clone(),
        })?;
        let backend = provider::checked_backend(&pair, &service, &raw, &check)?;
        let name = self
            .online_node
            .clone()
            .context("runtime_pair_node_required")?;
        let node = self.pair_read("node", &name)?;
        let neg = self.pair_cloud(BackendRead::Neg {
            name: backend.neg.clone(),
            zone: backend.zone.clone(),
        })?;
        let backend = provider::placed_backend(backend, &node, &neg, &name)?;
        // An unrelated Service with the same NEG annotation must not bind this
        // handoff. Both generations keep the original selector labels.
        let labels = &self.controller["spec"]["template"]["metadata"]["labels"];
        ensure!(
            service["spec"]["selector"]["app.kubernetes.io/name"] == self.request.statefulset
                && service["spec"]["selector"]
                    .as_object()
                    .is_some_and(|selector| !selector.is_empty()
                        && selector
                            .iter()
                            .all(|(key, value)| labels.get(key) == Some(value))),
            "runtime_pair_service_selector_changed"
        );
        Ok((service, backend))
    }

    pub(super) fn pair_state(&mut self) -> Result<Option<Release>> {
        let state = self.rollout_state()?;
        if state.is_null() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_value(state).map_err(|_| {
            anyhow::anyhow!("runtime_pair_journal_invalid")
        })?))
    }

    pub(super) fn pair_current(&mut self) -> Result<Release> {
        self.pair_matching(false)
    }

    pub(super) fn pair_matching(&mut self, allow_aborted: bool) -> Result<Release> {
        let release = self.pair_state()?.context("runtime_pair_not_prepared")?;
        let pair = self.pair_request()?;
        ensure!(
            release.id.as_str()
                == self
                    .request
                    .request_id
                    .as_deref()
                    .context("runtime_pair_id_required")?
                && release.source.image == self.request.app_image
                && release.target.image
                    == self.request.target.as_ref().context("target")?.app_image
                && release.target.artifact == format!("sha256:{}", self.request.artifact_id)
                && release.target_instance_digest
                    == day2::digest(
                        self.target_instance
                            .as_ref()
                            .context("target instance")?
                            .as_bytes()
                    )
                && matches!(&release.kind,ReleaseKind::RuntimePair {admission,..} if admission.receipt_digest==pair.receipt_digest)
                && (allow_aborted || release.phase != Phase::Aborted),
            "runtime_pair_resume_conflict"
        );
        if let Some(placement) = &release.placement {
            ensure!(
                placement.namespace == self.request.namespace
                    && placement.controller_uid == self.controller["metadata"]["uid"]
                    && Some(placement.pvc_uid.as_str()) == self.pvc_uid.as_deref()
                    && Some(placement.node.as_str()) == self.online_node.as_deref()
                    && placement.request_digest == self.request_digest,
                "runtime_pair_placement_changed"
            );
        }
        Ok(release)
    }

    pub(super) fn pair_command(&mut self, action: &str, file: Option<&Value>) -> Result<Release> {
        let app = self.request.app.clone();
        let id = self
            .request
            .request_id
            .clone()
            .context("runtime_pair_id_required")?;
        let operator = self.request.operator.clone();
        let mut args = vec![DAY2, "runtime-pair-handoff", CURRENT, &app, &id, action];
        if let Some(value) = file {
            let path = self.work.path().join("runtime-observation.json");
            fs::write(&path, serde_json::to_vec(value)?)?;
            self.copy_in(&path, "/srv/day2/runtime-observation.json")?;
            args.push("/srv/day2/runtime-observation.json");
        }
        args.push(&operator);
        let raw = self.exec(&args, Duration::from_secs(60))?;
        serde_json::from_str(raw.trim())
            .map_err(|_| anyhow::anyhow!("runtime_pair_observation_result_invalid"))
    }

    pub(super) fn pair_placement(&self) -> Result<Value> {
        let placement = self
            .request
            .placement
            .as_ref()
            .context("runtime_pair_placement_required")?;
        Ok(
            json!({"namespace":self.request.namespace,"controller_uid":placement.controller_uid,
            "pvc_uid":placement.pvc_uid,"node":placement.node,"request_digest":self.request_digest}),
        )
    }

    pub(super) fn pair_inputs(&mut self) -> Result<()> {
        let pair = self.pair_request()?;
        use std::io::Read;
        let mut receipt = Vec::new();
        let mut file = fs::File::open(&pair.receipt)?;
        ensure!(
            file.metadata()?.is_file(),
            "runtime_pair_receipt_regular_file_required"
        );
        std::io::Read::by_ref(&mut file)
            .take(1_048_577)
            .read_to_end(&mut receipt)?;
        ensure!(
            receipt.len() <= 1_048_576 && day2::digest(&receipt) == pair.receipt_digest,
            "runtime_pair_receipt_changed"
        );
        let receipt_path = self.work.path().join("runtime-receipt.json");
        fs::write(&receipt_path, receipt)?;
        self.copy_in(&receipt_path, "/srv/day2/runtime-receipt.json")?;
        let request = json!({"id":self.request.request_id,"source_image":self.request.app_image,
            "target_image":self.request.target.as_ref().context("target")?.app_image,"receipt_digest":pair.receipt_digest});
        for (name, value) in [
            ("runtime-request.json", request),
            ("runtime-placement.json", self.pair_placement()?),
        ] {
            let path = self.work.path().join(name);
            fs::write(&path, serde_json::to_vec(&value)?)?;
            self.copy_in(&path, &format!("{ROOT}/{name}"))?;
        }
        Ok(())
    }

    pub(super) fn pair_prepare_at(&mut self, instance: &str) -> Result<()> {
        let app = self.request.app.clone();
        let operator = self.request.operator.clone();
        self.exec(
            &[
                DAY2,
                "runtime-pair-prepare",
                instance,
                &app,
                TARGET,
                "/srv/day2/runtime-request.json",
                "/srv/day2/runtime-receipt.json",
                &operator,
            ],
            Duration::from_secs(600),
        )?;
        Ok(())
    }

    pub(super) fn pair_bind_at(&mut self, instance: &str) -> Result<()> {
        let app = self.request.app.clone();
        let id = self.request.request_id.clone().context("id")?;
        let operator = self.request.operator.clone();
        self.exec(
            &[
                DAY2,
                "rollout-bind",
                instance,
                &app,
                &id,
                "/srv/day2/runtime-placement.json",
                &operator,
            ],
            Duration::from_secs(60),
        )?;
        Ok(())
    }

    pub(super) fn pair_admit_at(&mut self, instance: &str) -> Result<()> {
        let app = self.request.app.clone();
        let id = self.request.request_id.clone().context("id")?;
        let operator = self.request.operator.clone();
        self.exec(
            &[DAY2, "runtime-pair-admit", instance, &app, &id, &operator],
            Duration::from_secs(60),
        )?;
        Ok(())
    }

    pub(super) fn pair_map(&mut self) -> Result<Value> {
        let name = selection_name(&self.request)?;
        let map = self.pair_read("configmap", &name)?;
        ensure!(
            map["immutable"] == true
                && map["metadata"]["deletionTimestamp"].is_null()
                && map["data"]["request-digest"] == self.request_digest,
            "runtime_pair_selection_changed"
        );
        Ok(map)
    }

    pub(super) fn pair_blueprint(&mut self) -> Result<Value> {
        if let Some(value) = &self.state.runtime.blueprint {
            return Ok(value.clone());
        }
        let map = self.pair_map()?;
        let value: Value = provider::decode(
            map["data"]["blueprint.json"]
                .as_str()
                .context("runtime_pair_blueprint_required")?,
        )?;
        ensure!(
            value["request"] == self.request_digest
                && value["controller"] == self.controller["metadata"]["uid"]
                && value["receipt"] == self.pair_request()?.receipt_digest,
            "runtime_pair_blueprint_changed"
        );
        self.state.runtime.blueprint = Some(value.clone());
        Ok(value)
    }

    /// Compare-and-swap one field set of the exact controller. The template is
    /// always an explicit test, so a concurrent release or operator edit refuses.
    pub(super) fn pair_patch_controller(
        &mut self,
        live: &Value,
        changes: Vec<Value>,
    ) -> Result<()> {
        ensure!(
            live["metadata"]["uid"] == self.controller["metadata"]["uid"],
            "runtime_pair_controller_changed"
        );
        let mut patch = vec![
            json!({"op":"test","path":"/metadata/uid","value":live["metadata"]["uid"]}),
            json!({"op":"test","path":"/metadata/resourceVersion","value":live["metadata"]["resourceVersion"]}),
            json!({"op":"test","path":"/spec/template","value":live["spec"]["template"]}),
            json!({"op":"test","path":"/spec/replicas","value":1}),
        ];
        patch.extend(changes);
        let name = self.request.statefulset.clone();
        self.kubectl(
            &[
                "patch",
                "deployment",
                &name,
                "--type=json",
                "-p",
                &serde_json::to_string(&patch)?,
            ],
            None,
            Duration::from_secs(60),
        )?;
        Ok(())
    }

    pub(super) fn pair_controller(&mut self) -> Result<Value> {
        let name = self.request.statefulset.clone();
        let live = self.pair_read("deployment", &name)?;
        ensure!(
            live["metadata"]["uid"] == self.controller["metadata"]["uid"]
                && live["metadata"]["deletionTimestamp"].is_null()
                && live["spec"]["replicas"] == 1
                && live["spec"]["strategy"]["type"] == "RollingUpdate"
                && live["spec"]["strategy"]["rollingUpdate"]["maxSurge"] == 1
                && live["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] == 0,
            "runtime_pair_controller_changed"
        );
        let map = self.pair_blueprint()?;
        let digest = resources::template_digest(&live["spec"]["template"])?;
        ensure!(
            digest == resources::template_digest(&map["source"])?
                || digest == resources::template_digest(&map["target"])?,
            "runtime_pair_controller_template_changed"
        );
        Ok(live)
    }

    pub fn runtime_rollout(&mut self, step: &str) -> Result<Value> {
        ensure!(
            self.operation == Operation::RuntimeRollout && self.state.pod && !self.state.finished,
            "runtime_pair_session_required"
        );
        if step == "reap-helpers" {
            return self.runtime_reap_helpers();
        }
        if step == "settle-backups" {
            return self.runtime_settle_backups();
        }
        if step == "resume" {
            let current = self.pair_state()?;
            let resuming = current.as_ref().is_some_and(|release| {
                Some(release.id.as_str()) == self.request.request_id.as_deref()
            });
            if resuming {
                self.pair_matching(true)?;
                self.state.resumed = true;
            } else {
                ensure!(
                    current.as_ref().is_none_or(|release| matches!(
                        release.phase,
                        Phase::Complete | Phase::Aborted
                    )),
                    "another_rollout_is_running"
                );
            }
            self.pair_inputs()?;
            return Ok(
                json!({"resuming":resuming,"aborted":current.as_ref().is_some_and(|release|resuming && release.phase==Phase::Aborted)}),
            );
        }
        ensure!(
            self.state.operation_claimed,
            "runtime_pair_operation_lease_required"
        );
        match step {
            "abort-cleanup" => self.runtime_abort_cleanup(),
            "blueprint" => self.runtime_blueprint(),
            "claim" => self.runtime_claim(),
            "confirm" => {
                if !self.state.resumed {
                    ensure!(
                        self.state.runtime.rehearsal_checked,
                        "runtime_pair_rehearsal_required"
                    );
                    let question = format!(
                        "Admit runtime pair {} in {} with artifact {} unchanged? Type rollout: ",
                        self.request.request_id.as_deref().context("id")?,
                        self.request.namespace,
                        self.request.artifact_id
                    );
                    ensure!(
                        self.request.yes || self.tools.prompt.confirm(&question, "rollout")?,
                        "runtime_pair_not_confirmed"
                    );
                }
                self.state.confirmed = true;
                Ok(json!({"confirmed":true}))
            }
            "rehearsal-copy" => self.runtime_rehearsal_copy(),
            "rehearsal-check" => self.runtime_rehearsal_check(),
            "rehearsal-remove" => self.runtime_rehearsal_remove(),
            "prepare" => {
                if !self.state.resumed {
                    ensure!(
                        self.state.runtime.rehearsal_checked && self.state.backup.is_some(),
                        "runtime_pair_rehearsal_required"
                    );
                    self.pair_prepare_at(CURRENT)?;
                }
                self.pair_current()?;
                Ok(json!({"prepared":true}))
            }
            "placement" => {
                let state = self.pair_current()?;
                if state.phase == Phase::Prepared {
                    self.pair_bind_at(CURRENT)?;
                }
                Ok(json!({"bound":true}))
            }
            "executors" => {
                let state = self.pair_current()?;
                if state.phase == Phase::Prepared {
                    self.pair_admit_at(CURRENT)?;
                }
                Ok(json!({"admitted":true}))
            }
            "candidate" => self.runtime_candidate(),
            "bind" => self.runtime_bind(),
            "check" => self.runtime_candidate_check(),
            "promote" => {
                self.pair_current()?;
                self.pair_command("promote", None)?;
                Ok(json!({"promoted":true}))
            }
            "probe" => self.runtime_probe(),
            "withdraw" => self.runtime_withdraw(),
            "drain" => self.runtime_drain(),
            "quiesce" => self.runtime_quiesce(),
            "transport-stop" => self.runtime_transport_stop(),
            "pause" | "retarget" | "adopt" | "unpause" => self.runtime_adoption(step),
            "source-gone" => self.runtime_source_gone(),
            "recover" => self.runtime_recover(),
            "complete" => self.runtime_complete(),
            "backup-select" => self.runtime_backup_select(),
            "release" => self.runtime_release(),
            _ => bail!("runtime_pair_step_invalid"),
        }
    }

    pub(super) fn runtime_blueprint(&mut self) -> Result<Value> {
        if self.state.resumed {
            self.pair_blueprint()?;
            return Ok(json!({"resumed":true}));
        }
        ensure!(
            self.state.offsite_backup.is_some() && self.state.backup.is_some(),
            "runtime_pair_checkpoint_required"
        );
        let source = resources::template(&self.controller["spec"]["template"]);
        let instance = self.target_instance.clone().context("target instance")?;
        let target = resources::candidate(&self.request, &source, &instance)?;
        let (_, backend) = self.pair_backend()?;
        let backup = self
            .request
            .offsite_backup
            .clone()
            .context("runtime_pair_backup_required")?;
        let cron = self.pair_read("cronjob", &backup.cronjob)?;
        let backup_identity = provider::resource(&cron)?;
        let backup_template = &cron["spec"]["jobTemplate"]["spec"]["template"];
        let checkpoint = self
            .state
            .offsite_backup
            .as_ref()
            .context("runtime_pair_checkpoint_required")?;
        ensure!(
            checkpoint["cronjob_uid"] == backup_identity.uid
                && checkpoint["template_digest"]
                    == day2::digest(&serde_json::to_vec(backup_template)?),
            "runtime_pair_backup_changed_since_checkpoint"
        );
        let blueprint = json!({"request":self.request_digest,"controller":self.controller["metadata"]["uid"],
            "receipt":self.pair_request()?.receipt_digest,"source":source,"target":target,"backend":backend,
            "backup":{"identity":backup_identity,"template":backup_template}});
        let selection = |role, image: String| -> Result<Selection> {
            Ok(Selection {
                release: self.request.request_id.clone().context("id")?,
                role,
                placement: serde_json::from_value(self.pair_placement()?)?,
                image,
            })
        };
        let candidate = selection(
            ExecutorRole::Candidate,
            self.request
                .target
                .as_ref()
                .context("target")?
                .app_image
                .clone(),
        )?;
        let source = selection(ExecutorRole::Source, self.request.app_image.clone())?;
        self.immutable_map(&selection_name(&self.request)?,json!({"instance.json":instance,"request-digest":self.request_digest,
            "blueprint.json":serde_json::to_string(&blueprint)?,"candidate.json":serde_json::to_string(&candidate)?,
            "source.json":serde_json::to_string(&source)?}))?;
        self.state.runtime.blueprint = Some(blueprint);
        Ok(json!({"blueprint_bound":true}))
    }

    pub(super) fn runtime_rehearsal_copy(&mut self) -> Result<Value> {
        if self.state.resumed {
            return Ok(json!({"resumed":true}));
        }
        self.prepare_rehearsal()?;
        self.pair_prepare_at(ADMISSION_INSTANCE)?;
        self.pair_bind_at(ADMISSION_INSTANCE)?;
        self.pair_admit_at(ADMISSION_INSTANCE)?;
        let blueprint = self.pair_blueprint()?;
        let name = format!(
            "day2-pair-{}-check-{}",
            suffix(&self.request)?,
            self.stamp.to_ascii_lowercase()
        );
        let mut pod = resources::checkpoint_pod(
            &self.request,
            &blueprint["target"],
            &name,
            self.state.scratch.context("checkpoint scratch bound")?,
        )?;
        pod["metadata"]["annotations"] = json!({"day2.dev/rollout-request":self.request_digest});
        self.state.runtime.temporary_pods.push(name.clone());
        self.kubectl(
            &["create", "-f", "-"],
            Some(&serde_json::to_vec(&pod)?),
            Duration::from_secs(60),
        )?;
        self.kubectl(
            &[
                "wait",
                "--for=jsonpath={.status.initContainerStatuses[0].state.running.startedAt}",
                &format!("pod/{name}"),
                "--timeout=300s",
            ],
            None,
            Duration::from_secs(330),
        )?;
        let observed = self.pair_read("pod", &name)?;
        ensure!(
            observed["spec"]["nodeName"].as_str() == self.online_node.as_deref()
                && observed["spec"]["volumes"]
                    .as_array()
                    .is_some_and(|volumes| volumes
                        .iter()
                        .all(|v| v["persistentVolumeClaim"].is_null()))
                && observed["spec"]["initContainers"][0]["image"] == self.request.tooling_image,
            "runtime_pair_rehearsal_isolation_changed"
        );
        let local = self.work.path().join("runtime-checkpoint");
        let remote = format!("{}:{ADMISSION}/.state", self.pod);
        let theirs = self.remote_sums(&format!("{ADMISSION}/.state"))?;
        self.kubectl(
            &[
                "cp",
                "--retries=5",
                &remote,
                local.to_str().context("checkpoint path")?,
            ],
            None,
            Duration::from_secs(600),
        )?;
        ensure!(
            local_manifest(&local)? == theirs,
            "runtime_pair_checkpoint_copy_changed"
        );
        let destination = format!("{name}:/rehearsal/state");
        self.kubectl(
            &[
                "cp",
                "--retries=5",
                "-c",
                "checkpoint",
                &format!("{}/.", local.display()),
                &destination,
            ],
            None,
            Duration::from_secs(600),
        )?;
        let sums = self.kubectl(
            &[
                "exec",
                &name,
                "-c",
                "checkpoint",
                "--",
                "find",
                "/rehearsal/state",
                "-type",
                "f",
                "-exec",
                "sha256sum",
                "{}",
                "+",
            ],
            None,
            Duration::from_secs(300),
        )?;
        ensure!(
            remote_manifest(&sums, "/rehearsal/state")? == theirs,
            "runtime_pair_checkpoint_staging_changed"
        );
        let ready = self.work.path().join("ready");
        fs::write(&ready, b"1")?;
        self.kubectl(
            &[
                "cp",
                "-c",
                "checkpoint",
                ready.to_str().context("marker path")?,
                &format!("{name}:/rehearsal/ready"),
            ],
            None,
            Duration::from_secs(60),
        )?;
        self.state.runtime.rehearsal = Some(name);
        Ok(json!({"checkpoint_staged":true}))
    }

    pub(super) fn runtime_rehearsal_check(&mut self) -> Result<Value> {
        if self.state.resumed {
            return Ok(json!({"resumed":true}));
        }
        let name = self
            .state
            .runtime
            .rehearsal
            .clone()
            .context("runtime_pair_rehearsal_required")?;
        self.kubectl(
            &[
                "wait",
                "--for=jsonpath={.status.phase}=Succeeded",
                &format!("pod/{name}"),
                "--timeout=600s",
            ],
            None,
            Duration::from_secs(630),
        )?;
        let pod = self.pair_read("pod", &name)?;
        let image = &self.request.target.as_ref().context("target")?.app_image;
        ensure!(
            pod["status"]["phase"] == "Succeeded"
                && provider::stopped(&pod)
                && pod["spec"]["containers"][0]["image"] == *image
                && pod["status"]["containerStatuses"][0]["imageID"]
                    .as_str()
                    .is_some_and(
                        |id| id.ends_with(&format!("@{}", image.split_once('@').unwrap().1))
                    ),
            "runtime_pair_target_rehearsal_failed"
        );
        self.state.runtime.rehearsal_checked = true;
        Ok(json!({"target_checkpoint_checked":true}))
    }

    pub(super) fn runtime_rehearsal_remove(&mut self) -> Result<Value> {
        if let Some(name) = self.state.runtime.rehearsal.take() {
            remove_pod(
                self.tools.cluster.as_mut(),
                &self.request,
                &name,
                &self.request_digest,
                None,
            )?;
            self.state.runtime.temporary_pods.retain(|pod| pod != &name);
        }
        Ok(json!({"rehearsal_removed":true}))
    }
}
