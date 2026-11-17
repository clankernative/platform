use super::*;
use std::{
    fs,
    time::{Duration, Instant},
};

impl Session {
    pub(super) fn runtime_abort_cleanup(&mut self) -> Result<Value> {
        let release = self.pair_matching(true)?;
        ensure!(
            release.phase == Phase::Aborted,
            "runtime_pair_aborted_required"
        );
        self.pair_command("aborted", None)?; // Proves Source is still the active native executor.
        let name = target_name(&self.request)?;
        if let Some(replica) = self.pair_optional("replicaset", &name)? {
            let blueprint = self.pair_blueprint()?;
            let map = self.pair_map()?;
            ensure!(
                owned_candidate(&replica, &self.request, &self.request_digest)
                    && provider::owner(&replica, "ConfigMap")? == map["metadata"]["uid"]
                    && resources::template_digest(&replica["spec"]["template"])?
                        == resources::template_digest(&blueprint["target"])?,
                "runtime_pair_abort_candidate_changed"
            );
            if let Some(handoff) = stage(&release)? {
                ensure!(
                    provider::resource(&replica)? == handoff.binding.candidate_controller
                        && provider::resource(&map)? == handoff.binding.selection,
                    "runtime_pair_abort_identity_changed"
                );
            }
            let path = format!(
                "/apis/apps/v1/namespaces/{}/replicasets/{name}",
                self.request.namespace
            );
            let options = json!({"apiVersion":"v1","kind":"DeleteOptions","propagationPolicy":"Foreground",
                "preconditions":{"uid":replica["metadata"]["uid"],"resourceVersion":replica["metadata"]["resourceVersion"]}});
            self.kubectl(
                &["delete", "--raw", &path, "-f", "-"],
                Some(&serde_json::to_vec(&options)?),
                Duration::from_secs(60),
            )?;
            self.kubectl(
                &[
                    "wait",
                    "--for=delete",
                    &format!("replicaset/{name}"),
                    "--timeout=300s",
                ],
                None,
                Duration::from_secs(330),
            )?;
        }
        let live = self.pair_read("deployment", &self.request.statefulset.clone())?;
        ensure!(
            live["metadata"]["uid"] == self.controller["metadata"]["uid"]
                && live["spec"]["template"]["spec"]["containers"][0]["image"]
                    == release.source.image,
            "runtime_pair_abort_source_changed"
        );
        if let Some(marker) = live["metadata"]["annotations"]["day2.dev/runtime-pair"].as_str() {
            ensure!(
                marker == self.request_digest,
                "runtime_pair_controller_claim_changed"
            );
            self.pair_patch_controller(
                &live,
                vec![json!({"op":"remove","path":"/metadata/annotations/day2.dev~1runtime-pair"})],
            )?;
        }
        self.state.result =
            Some(json!({"release":release.id,"phase":"aborted","source_retained":true}));
        Ok(json!({"aborted":true}))
    }
    pub(super) fn runtime_reap_helpers(&mut self) -> Result<Value> {
        let stale = std::mem::take(&mut self.state.runtime.stale_helpers);
        ensure!(stale.len() <= 128, "runtime_pair_helper_inventory_bound");
        for pod in stale {
            let identity = provider::resource(&pod)?;
            ensure!(
                identity.name != self.pod
                    && pod["metadata"]["annotations"]["day2.dev/rollout-request"]
                        == self.request_digest,
                "runtime_pair_stale_helper_identity_changed"
            );
            if owned_recovery(&pod, &self.request, &self.request_digest) {
                continue;
            }
            if identity
                .name
                .starts_with(&format!("day2-pair-{}-check-", suffix(&self.request)?))
            {
                remove_pod(
                    self.tools.cluster.as_mut(),
                    &self.request,
                    &identity.name,
                    &self.request_digest,
                    Some(&identity.uid),
                )?;
            } else {
                ensure!(
                    identity.name.starts_with("day2-maintenance-")
                        && pod["spec"]["nodeName"].as_str() == self.online_node.as_deref()
                        && pod["spec"]["containers"][0]["image"] == self.request.tooling_image,
                    "runtime_pair_stale_helper_scope_changed"
                );
                // Deletion does not unlock a borrowing child. Its actual FD
                // retains kernel exclusion until the last process releases it.
                activation::remove_helper(
                    self.tools.cluster.as_mut(),
                    &self.request,
                    &identity.name,
                    &self.request_digest,
                    Some(&identity.uid),
                )?;
            }
        }
        Ok(json!({"helpers_recovered":true}))
    }

    pub(super) fn runtime_settle_backups(&mut self) -> Result<Value> {
        let started = Instant::now();
        loop {
            let jobs = self.pair_read("jobs", "")?;
            let jobs = jobs["items"]
                .as_array()
                .context("runtime_pair_backup_inventory_required")?;
            ensure!(jobs.len() <= 1024, "runtime_pair_backup_inventory_bound");
            let mut running = false;
            for job in jobs {
                if job["metadata"]["annotations"]["day2.dev/rollout-request"] != self.request_digest
                {
                    continue;
                }
                let template = &job["spec"]["template"];
                ensure!(
                    backup_participant(template, &self.request.app, &self.request.pvc)
                        && template["spec"]["containers"][0]["image"] == self.request.app_image,
                    "runtime_pair_previous_backup_identity_changed"
                );
                let ended = job["status"]["conditions"]
                    .as_array()
                    .is_some_and(|conditions| {
                        conditions.iter().any(|c| {
                            (c["type"] == "Complete" || c["type"] == "Failed")
                                && c["status"] == "True"
                        })
                    });
                running |= !ended;
            }
            if !running {
                return Ok(json!({"previous_backups_settled":true}));
            }
            ensure!(
                started.elapsed() < Duration::from_secs(1200),
                "runtime_pair_previous_backup_deadline"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    pub(super) fn pair_source_idle(&mut self, health: &HealthObservation) -> Result<bool> {
        let source = health
            .source
            .as_ref()
            .context("runtime_pair_source_observation_required")?;
        let raw = self.kubectl(
            &[
                "exec",
                &source.pod.name,
                "-c",
                "day2",
                "--",
                HEALTH,
                "8080",
                "--drain",
            ],
            None,
            Duration::from_secs(60),
        )?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Status {
            generation: String,
            admitting: bool,
            inflight: u64,
            streams: u64,
            quiesced: bool,
        }
        let value: Status = day2::json::decode(raw.trim().as_bytes())
            .map_err(|_| anyhow::anyhow!("runtime_pair_drain_status_invalid"))?;
        let current = self.pair_current()?;
        let ReleaseKind::RuntimePair {
            execution:
                day2::runtime_pair::Execution::Admitted {
                    source: generation, ..
                },
            ..
        } = &current.kind
        else {
            bail!("runtime_pair_executor_required")
        };
        ensure!(
            value.generation == *generation && !value.quiesced,
            "runtime_pair_source_generation_changed"
        );
        ensure!(value.admitting, "runtime_pair_source_already_stopping");
        Ok(value.inflight == 0 && value.streams == 0)
    }
    pub(super) fn runtime_claim(&mut self) -> Result<Value> {
        ensure!(self.state.confirmed, "runtime_pair_confirmation_required");
        let live = self.pair_controller()?;
        if let Some(marker) = live["metadata"]["annotations"]["day2.dev/runtime-pair"].as_str() {
            ensure!(
                marker == self.request_digest,
                "runtime_pair_controller_claim_changed"
            );
            return Ok(json!({"already_claimed":true}));
        }
        if self.state.resumed && self.pair_current()?.phase == Phase::Complete {
            return Ok(json!({"complete":true}));
        }
        ensure!(
            self.state.runtime.rehearsal_checked || self.state.resumed,
            "runtime_pair_rehearsal_required"
        );
        let mut annotations = live["metadata"]["annotations"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        annotations.insert("day2.dev/runtime-pair".into(), json!(self.request_digest));
        self.pair_patch_controller(
            &live,
            vec![json!({"op":"add","path":"/metadata/annotations","value":annotations})],
        )?;
        Ok(json!({"controller_claimed":true}))
    }

    pub(super) fn pair_inventory(&mut self) -> Result<(Vec<Value>, Vec<Value>)> {
        let pods = self.pair_read("pods", "")?;
        let replicas = self.pair_read("replicasets", "")?;
        let pods = pods["items"]
            .as_array()
            .context("runtime_pair_pod_inventory_required")?;
        let replicas = replicas["items"]
            .as_array()
            .context("runtime_pair_replicaset_inventory_required")?;
        ensure!(
            pods.len() <= 1024 && replicas.len() <= 1024,
            "runtime_pair_kubernetes_inventory_bound"
        );
        Ok((pods.clone(), replicas.clone()))
    }

    pub(super) fn pair_target(&mut self, release: &Release) -> Result<(Value, Value)> {
        let name = target_name(&self.request)?;
        let replica = self.pair_read("replicaset", &name)?;
        let map = self.pair_map()?;
        let owner = provider::owner(
            &replica,
            if replica["metadata"]["ownerReferences"][0]["kind"] == "ConfigMap" {
                "ConfigMap"
            } else {
                "Deployment"
            },
        )?;
        let blueprint = self.pair_blueprint()?;
        ensure!(
            replica["metadata"]["annotations"]["day2.dev/rollout-request"] == self.request_digest
                && replica["metadata"]["deletionTimestamp"].is_null()
                && (owner == map["metadata"]["uid"] || owner == self.controller["metadata"]["uid"])
                && resources::template_digest(&replica["spec"]["template"])?
                    == resources::template_digest(&blueprint["target"])?
                && replica["spec"]["replicas"] == 1,
            "runtime_pair_candidate_controller_changed"
        );
        if let Some(handoff) = stage(release)? {
            ensure!(
                provider::resource(&replica)? == handoff.binding.candidate_controller
                    && provider::resource(&map)? == handoff.binding.selection,
                "runtime_pair_candidate_uid_changed"
            );
        }
        let (pods, _) = self.pair_inventory()?;
        let candidates: Vec<_> = pods
            .iter()
            .filter(|pod| {
                provider::owner(pod, "ReplicaSet").ok().as_deref()
                    == replica["metadata"]["uid"].as_str()
                    && !matches!(
                        pod["status"]["phase"].as_str(),
                        Some("Succeeded" | "Failed")
                    )
            })
            .collect();
        ensure!(
            candidates.len() == 1 && candidates[0]["metadata"]["deletionTimestamp"].is_null(),
            "runtime_pair_one_live_target_required"
        );
        Ok((candidates[0].clone(), replica))
    }

    pub(super) fn pair_sources(&mut self, release: &Release) -> Result<Vec<(Value, Value)>> {
        let (pods, replicas) = self.pair_inventory()?;
        let mut sources = Vec::new();
        for pod in pods {
            let Ok(owner) = provider::owner(&pod, "ReplicaSet") else {
                continue;
            };
            let Some(replica) = replicas.iter().find(|replica| {
                replica["metadata"]["uid"] == owner
                    && provider::owner(replica, "Deployment").ok().as_deref()
                        == self.controller["metadata"]["uid"].as_str()
            }) else {
                continue;
            };
            if replica["metadata"]["name"] == target_name(&self.request)? {
                continue;
            }
            if matches!(
                pod["status"]["phase"].as_str(),
                Some("Succeeded" | "Failed")
            ) {
                continue;
            }
            ensure!(
                pod["spec"]["containers"]
                    .as_array()
                    .is_some_and(|containers| containers.len() == 1
                        && containers[0]["name"] == "day2"
                        && containers[0]["image"] == release.source.image),
                "runtime_pair_unrecognized_source_pod"
            );
            if let Some(handoff) = stage(release)? {
                ensure!(
                    resources::template_digest(&replica["spec"]["template"])?
                        == handoff.binding.source_template,
                    "runtime_pair_source_template_changed"
                );
            }
            sources.push((pod, replica.clone()));
        }
        ensure!(sources.len() <= 1, "runtime_pair_one_source_required");
        Ok(sources)
    }

    pub(super) fn pair_health(&mut self, release: &Release) -> Result<HealthObservation> {
        let claim = self.pair_read("pvc", &self.request.pvc.clone())?;
        ensure!(
            claim["metadata"]["uid"].as_str() == self.pvc_uid.as_deref()
                && claim["status"]["phase"] == "Bound"
                && claim["spec"]["accessModes"] == json!(["ReadWriteOnce"]),
            "runtime_pair_claim_changed"
        );
        let handoff = stage(release)?.context("runtime_pair_handoff_required")?;
        let (service, backend) = self.pair_backend()?;
        ensure!(
            provider::resource(&service)? == handoff.binding.service
                && backend == handoff.binding.backend,
            "runtime_pair_backend_configuration_changed"
        );
        let (target, replica) = self.pair_target(release)?;
        ensure!(
            target["status"]["phase"] == "Running"
                && target["status"]["containerStatuses"][0]["state"]["running"].is_object(),
            "runtime_pair_target_not_running"
        );
        let source = self.pair_sources(release)?;
        let source = source
            .first()
            .map(|(pod, replica)| provider::pod(&self.request, pod, replica, backend.port))
            .transpose()?;
        let healthy = provider::healthy(
            &backend,
            &self.pair_cloud(BackendRead::Health {
                name: backend.service.clone(),
            })?,
            self.online_node
                .as_deref()
                .context("runtime_pair_node_required")?,
        )?;
        let target = provider::pod(&self.request, &target, &replica, backend.port)?;
        ensure!(
            healthy.contains(&target.endpoint),
            "runtime_pair_target_lb_unhealthy"
        );
        Ok(HealthObservation {
            round: handoff.round,
            authority: release.authority.clone(),
            service: provider::resource(&service)?,
            backend,
            target,
            source,
            healthy,
        })
    }

    pub(super) fn pair_fresh_health(&mut self) -> Result<(Release, HealthObservation)> {
        let release = self.pair_command("observe", None)?;
        let observation = self.pair_health(&release)?;
        Ok((release, observation))
    }

    pub(super) fn runtime_candidate(&mut self) -> Result<Value> {
        let state = self.pair_current()?;
        let blueprint = self.pair_blueprint()?;
        let live = self.pair_controller()?;
        let id = self.request.request_id.clone().context("id")?;
        ensure!(
            live["metadata"]["annotations"]["day2.dev/runtime-pair"] == self.request_digest
                || state.phase == Phase::Complete,
            "runtime_pair_controller_claim_changed"
        );
        let name = target_name(&self.request)?;
        if self.pair_optional("replicaset", &name)?.is_none() {
            ensure!(
                state.phase == Phase::Prepared,
                "runtime_pair_missing_admitted_candidate"
            );
            let map = self.pair_map()?;
            let object = json!({"apiVersion":"apps/v1","kind":"ReplicaSet",
                "metadata":{"name":name,"namespace":self.request.namespace,"labels":blueprint["target"]["metadata"]["labels"],
                    "annotations":{"day2.dev/rollout-request":self.request_digest},
                    "ownerReferences":[{"apiVersion":"v1","kind":"ConfigMap","name":selection_name(&self.request)?,
                        "uid":map["metadata"]["uid"],"controller":true,"blockOwnerDeletion":false}]},
                "spec":{"replicas":1,"selector":{"matchLabels":{"day2.dev/runtime-pair":suffix(&self.request)?}},
                    "template":blueprint["target"]}});
            self.kubectl(
                &["create", "-f", "-"],
                Some(&serde_json::to_vec(&object)?),
                Duration::from_secs(60),
            )?;
        }
        // Scheduling and a container start are observations, not admission.
        self.kubectl(
            &[
                "wait",
                "--for=jsonpath={.status.phase}=Running",
                "pod",
                "-l",
                &format!("day2.dev/runtime-pair={}", suffix(&self.request)?),
                "--timeout=300s",
            ],
            None,
            Duration::from_secs(330),
        )?;
        self.pair_target(&state)?;
        self.record("runtime-candidate-running", json!({"release":id}))?;
        Ok(json!({"candidate_running":true}))
    }

    pub(super) fn runtime_bind(&mut self) -> Result<Value> {
        let release = self.pair_current()?;
        if stage(&release)?.is_some() {
            return Ok(json!({"already_bound":true}));
        }
        let blueprint = self.pair_blueprint()?;
        let (service, backend) = self.pair_backend()?;
        ensure!(
            serde_json::to_value(&backend)? == blueprint["backend"],
            "runtime_pair_backend_changed_since_preflight"
        );
        let (_, replica) = self.pair_target(&release)?;
        let map = self.pair_map()?;
        let binding = HandoffBinding {
            service: provider::resource(&service)?,
            candidate_controller: provider::resource(&replica)?,
            selection: provider::resource(&map)?,
            source_template: resources::template_digest(&blueprint["source"])?,
            target_template: resources::template_digest(&replica["spec"]["template"])?,
            backend,
        };
        self.pair_command("bind", Some(&serde_json::to_value(binding)?))?;
        Ok(json!({"handoff_bound":true}))
    }

    pub(super) fn runtime_candidate_check(&mut self) -> Result<Value> {
        let release = self.pair_current()?;
        if release.phase == Phase::Complete {
            return Ok(json!({"complete":true}));
        }
        let started = Instant::now();
        loop {
            let (pod, _) = self.pair_target(&release)?;
            let name = provider::resource(&pod)?.name;
            if self
                .kubectl(
                    &[
                        "exec",
                        &name,
                        "-c",
                        "day2",
                        "--",
                        HEALTH,
                        "8080",
                        "--candidate",
                    ],
                    None,
                    Duration::from_secs(60),
                )
                .is_ok()
            {
                return Ok(json!({"candidate_checked":true}));
            }
            ensure!(
                started.elapsed() < Duration::from_secs(300),
                "runtime_pair_candidate_check_deadline"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    pub(super) fn runtime_probe(&mut self) -> Result<Value> {
        let release = self.pair_current()?;
        if release.phase == Phase::Complete {
            return Ok(json!({"complete":true}));
        }
        let probe = self
            .request
            .target
            .as_ref()
            .and_then(|target| target.probe.as_ref())
            .context("runtime_pair_probe_required")?;
        if let Some(previous) = &release.probe {
            ensure!(previous.definition == *probe, "runtime_pair_probe_changed");
            if previous.status == day2::rollout::ProbeStatus::Verified {
                return Ok(json!({"probe_verified":true}));
            }
        }
        let file = self.work.path().join("runtime-probe.json");
        fs::write(&file, serde_json::to_vec(probe)?)?;
        self.copy_in(&file, "/srv/day2/runtime-probe.json")?;
        let app = self.request.app.clone();
        let operator = self.request.operator.clone();
        self.exec(
            &[
                DAY2,
                "rollout-probe",
                CURRENT,
                &app,
                "/srv/day2/runtime-probe.json",
                &release.id,
                &operator,
            ],
            Duration::from_secs(60),
        )?;
        let started = Instant::now();
        loop {
            let release = self.pair_current()?;
            match release.probe.as_ref().map(|probe| &probe.status) {
                Some(day2::rollout::ProbeStatus::Verified) => {
                    return Ok(json!({"probe_verified":true}));
                }
                Some(day2::rollout::ProbeStatus::Failed) => {
                    bail!("runtime_pair_business_probe_failed")
                }
                _ => ensure!(
                    started.elapsed() < Duration::from_secs(300),
                    "runtime_pair_business_probe_deadline"
                ),
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    pub(super) fn runtime_withdraw(&mut self) -> Result<Value> {
        let release = self.pair_current()?;
        if release.phase != Phase::Serving {
            ensure!(
                matches!(release.phase, Phase::Draining | Phase::Complete),
                "runtime_pair_promotion_required"
            );
            return Ok(json!({"already_withdrawn":true}));
        }
        // Health propagation may lag Pod readiness. Wait only on this exact
        // target endpoint, with a finite deadline; Source stays ready throughout.
        let started = Instant::now();
        loop {
            let (release, health) = match self.pair_fresh_health() {
                Ok(value) => value,
                Err(error)
                    if error.to_string() == "runtime_pair_target_lb_unhealthy"
                        && started.elapsed() < Duration::from_secs(300) =>
                {
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                Err(error) => return Err(error),
            };
            ensure!(
                health.source.is_some(),
                "runtime_pair_source_observation_required"
            );
            self.pair_command("withdraw", Some(&serde_json::to_value(&health)?))?;
            self.record(
                "runtime-source-withdrawn",
                json!({"release":release.id,"target":health.target.pod.uid}),
            )?;
            return Ok(json!({"source_withdrawn":true}));
        }
    }

    pub(super) fn runtime_drain(&mut self) -> Result<Value> {
        let release = self.pair_current()?;
        if matches!(
            stage(&release)?.map(|handoff| &handoff.stage),
            Some(HandoffStage::Quiesced { .. } | HandoffStage::Complete { .. })
        ) {
            return Ok(json!({"already_quiesced":true}));
        }
        let handoff = stage(&release)?.context("runtime_pair_handoff_required")?;
        let HandoffStage::Withdrawing { health } = &handoff.stage else {
            bail!("runtime_pair_withdrawal_required")
        };
        let source = health
            .source
            .as_ref()
            .context("runtime_pair_source_observation_required")?
            .endpoint
            .clone();
        let backend = handoff.binding.backend.clone();
        let started = Instant::now();
        let mut absent_since = None;
        loop {
            let current = self.pair_current()?;
            let _healthy = self.pair_health(&current)?;
            let members = provider::members(&self.pair_cloud(BackendRead::Endpoints {
                name: backend.neg.clone(),
                zone: backend.zone.clone(),
            })?)?;
            if members.contains(&source) {
                absent_since = None;
            } else if absent_since.is_none() {
                absent_since = Some(Instant::now());
            }
            if let Some(since) = absent_since
                && since.elapsed() >= Duration::from_secs(u64::from(backend.drain_seconds))
            {
                let (_, health) = self.pair_fresh_health()?;
                ensure!(
                    !health.healthy.contains(&source),
                    "runtime_pair_source_still_lb_healthy"
                );
                let members = provider::members(&self.pair_cloud(BackendRead::Endpoints {
                    name: backend.neg.clone(),
                    zone: backend.zone.clone(),
                })?)?;
                ensure!(
                    !members.contains(&source),
                    "runtime_pair_source_endpoint_returned"
                );
                if !self.pair_source_idle(&health)? {
                    ensure!(
                        started.elapsed() < Duration::from_secs(660),
                        "runtime_pair_source_requests_deadline"
                    );
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }
                self.state.runtime.drain = Some(DrainObservation {
                    health,
                    absent: vec![source],
                    elapsed_ms: u64::try_from(since.elapsed().as_millis())?,
                    source_inflight: 0,
                    source_streams: 0,
                    source_stopped: false,
                });
                return Ok(json!({"lb_drained":true}));
            }
            ensure!(
                started.elapsed() < Duration::from_secs(660),
                "runtime_pair_lb_drain_deadline"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    pub(super) fn runtime_quiesce(&mut self) -> Result<Value> {
        let release = self.pair_current()?;
        if matches!(
            stage(&release)?.map(|handoff| &handoff.stage),
            Some(HandoffStage::Quiesced { .. } | HandoffStage::Complete { .. })
        ) {
            return Ok(json!({"already_quiesced":true}));
        }
        let observation = self
            .state
            .runtime
            .drain
            .take()
            .context("runtime_pair_fresh_drain_required")?;
        self.pair_command("quiesce", Some(&serde_json::to_value(observation)?))?;
        Ok(json!({"source_quiesced":true}))
    }

    pub(super) fn runtime_transport_stop(&mut self) -> Result<Value> {
        let started = Instant::now();
        loop {
            let release = self.pair_current()?;
            let handoff = stage(&release)?.context("runtime_pair_handoff_required")?;
            let HandoffStage::Quiesced { health, drain } = &handoff.stage else {
                ensure!(
                    release.phase == Phase::Complete,
                    "runtime_pair_source_quiesce_required"
                );
                return Ok(json!({"complete":true}));
            };
            if drain.source_stopped {
                return Ok(json!({"transport_stopped":true}));
            }
            let source = health
                .source
                .as_ref()
                .context("runtime_pair_source_observation_required")?;
            let pod = self.pair_read("pod", &source.pod.name)?;
            ensure!(
                provider::resource(&pod)? == source.pod,
                "runtime_pair_source_pod_changed_before_drain"
            );
            if provider::stopped(&pod) {
                let (_, health) = self.pair_fresh_health()?;
                let mut observation = (**drain).clone();
                observation.health = health;
                observation.source_stopped = true;
                observation.source_inflight = 0;
                observation.source_streams = 0;
                self.pair_command("stopped", Some(&serde_json::to_value(observation)?))?;
                return Ok(json!({"transport_stopped":true}));
            }
            ensure!(
                started.elapsed() < Duration::from_secs(300),
                "runtime_pair_source_transport_deadline"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    pub(super) fn runtime_adoption(&mut self, step: &str) -> Result<Value> {
        let release = self.pair_current()?;
        let handoff = stage(&release)?.context("runtime_pair_handoff_required")?;
        if release.phase == Phase::Complete {
            return Ok(json!({"complete":true}));
        }
        ensure!(
            matches!(&handoff.stage,HandoffStage::Quiesced {drain,..} if drain.source_stopped),
            "runtime_pair_source_transport_stop_required"
        );
        self.pair_health(&release)?;
        let blueprint = self.pair_blueprint()?;
        let live = self.pair_controller()?;
        ensure!(
            live["metadata"]["annotations"]["day2.dev/runtime-pair"] == self.request_digest,
            "runtime_pair_controller_claim_changed"
        );
        let target = resources::template(&blueprint["target"]);
        let retargeted = resources::template_digest(&live["spec"]["template"])?
            == handoff.binding.target_template;
        match step {
            "pause" => {
                if retargeted {
                    return Ok(json!({"already_retargeted":true}));
                }
                if live["spec"]["paused"] != true {
                    self.pair_patch_controller(
                        &live,
                        vec![json!({"op":"add","path":"/spec/paused","value":true})],
                    )?;
                }
            }
            "retarget" => {
                if retargeted {
                    return Ok(json!({"already_retargeted":true}));
                }
                ensure!(
                    live["spec"]["paused"] == true,
                    "runtime_pair_paused_controller_required"
                );
                self.pair_patch_controller(&live,vec![json!({"op":"replace","path":"/spec/template","value":target}),
                    json!({"op":"add","path":"/metadata/annotations/day2.dev~1rollout","value":release.id})])?;
            }
            "adopt" => {
                ensure!(retargeted, "runtime_pair_target_template_required");
                let (_, replica) = self.pair_target(&release)?;
                if provider::owner(&replica, "Deployment").ok().as_deref()
                    == live["metadata"]["uid"].as_str()
                {
                    return Ok(json!({"already_adopted":true}));
                }
                ensure!(
                    live["spec"]["paused"] == true,
                    "runtime_pair_paused_controller_required"
                );
                let map = self.pair_map()?;
                ensure!(
                    provider::owner(&replica, "ConfigMap")? == map["metadata"]["uid"],
                    "runtime_pair_candidate_owner_changed"
                );
                let patch = json!([{"op":"test","path":"/metadata/uid","value":replica["metadata"]["uid"]},
                    {"op":"test","path":"/metadata/resourceVersion","value":replica["metadata"]["resourceVersion"]},
                    {"op":"test","path":"/spec/template","value":replica["spec"]["template"]},
                    {"op":"test","path":"/metadata/ownerReferences","value":replica["metadata"]["ownerReferences"]},
                    {"op":"replace","path":"/metadata/ownerReferences","value":[{"apiVersion":"apps/v1","kind":"Deployment",
                        "name":self.request.statefulset,"uid":live["metadata"]["uid"],"controller":true,"blockOwnerDeletion":false}]}]);
                self.kubectl(
                    &[
                        "patch",
                        "replicaset",
                        &target_name(&self.request)?,
                        "--type=json",
                        "-p",
                        &serde_json::to_string(&patch)?,
                    ],
                    None,
                    Duration::from_secs(60),
                )?;
            }
            "unpause" => {
                ensure!(retargeted, "runtime_pair_target_template_required");
                let (_, replica) = self.pair_target(&release)?;
                ensure!(
                    provider::owner(&replica, "Deployment")? == live["metadata"]["uid"],
                    "runtime_pair_adopted_target_required"
                );
                if live["spec"]["paused"] == true {
                    self.pair_patch_controller(
                        &live,
                        vec![json!({"op":"replace","path":"/spec/paused","value":false})],
                    )?;
                }
            }
            _ => bail!("runtime_pair_adoption_step_invalid"),
        }
        Ok(json!({"adoption_step":step}))
    }

    pub(super) fn runtime_source_gone(&mut self) -> Result<Value> {
        let release = self.pair_current()?;
        if release.phase == Phase::Complete {
            return Ok(json!({"complete":true}));
        }
        let controller = self.pair_controller()?;
        ensure!(
            controller["spec"]["paused"] != true,
            "runtime_pair_controller_still_paused"
        );
        let started = Instant::now();
        loop {
            self.pair_health(&release)?;
            if self.pair_sources(&release)?.is_empty() {
                return Ok(json!({"source_pods":0}));
            }
            ensure!(
                started.elapsed() < Duration::from_secs(300),
                "runtime_pair_source_retirement_deadline"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    pub(super) fn pair_pending(&mut self, release: &Release) -> Result<u64> {
        let app = self.request.app.clone();
        let operator = self.request.operator.clone();
        let raw = self.exec(
            &[
                DAY2,
                "runtime-pair-handoff",
                CURRENT,
                &app,
                &release.id,
                "pending",
                &operator,
            ],
            Duration::from_secs(60),
        )?;
        provider::decode(raw.trim())?["pending"]
            .as_u64()
            .context("runtime_pair_pending_observation_invalid")
    }

    pub(super) fn runtime_recover(&mut self) -> Result<Value> {
        let release = self.pair_current()?;
        if release.phase == Phase::Complete || self.pair_pending(&release)? == 0 {
            return Ok(json!({"remaining":false}));
        }
        ensure!(
            self.pair_sources(&release)?.is_empty(),
            "runtime_pair_source_slot_not_released"
        );
        self.pair_health(&release)?;
        let blueprint = self.pair_blueprint()?;
        let map = self.pair_map()?;
        let name = format!("day2-pair-{}-source", suffix(&self.request)?);
        let mut spec = blueprint["target"]["spec"].clone();
        spec["restartPolicy"] = json!("Never");
        spec["activeDeadlineSeconds"] = json!(300);
        let container = &mut spec["containers"][0];
        container["image"] = json!(release.source.image);
        container["args"] = json!([
            "/srv/day2/instance.json",
            self.request.app,
            "--runtime-source-executor",
            format!("{PAIR_ROOT}/source.json"),
            "1000"
        ]);
        for field in [
            "readinessProbe",
            "livenessProbe",
            "startupProbe",
            "lifecycle",
            "ports",
        ] {
            container.as_object_mut().unwrap().remove(field);
        }
        let object = json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"namespace":self.request.namespace,
            "labels":resources::helper_labels(&self.request),"annotations":{"day2.dev/rollout-request":self.request_digest},
            "ownerReferences":[{"apiVersion":"v1","kind":"ConfigMap","name":selection_name(&self.request)?,"uid":map["metadata"]["uid"],"controller":true,"blockOwnerDeletion":false}]},"spec":spec});
        if let Some(existing) = self.pair_optional("pod", &name)? {
            ensure!(
                existing["metadata"]["annotations"] == object["metadata"]["annotations"]
                    && provider::owner(&existing, "ConfigMap")? == map["metadata"]["uid"]
                    && existing["spec"]["containers"] == object["spec"]["containers"],
                "runtime_pair_source_recovery_conflict"
            );
            if matches!(
                existing["status"]["phase"].as_str(),
                Some("Succeeded" | "Failed")
            ) {
                remove_pod(
                    self.tools.cluster.as_mut(),
                    &self.request,
                    &name,
                    &self.request_digest,
                    existing["metadata"]["uid"].as_str(),
                )?;
                return Ok(json!({"remaining":self.pair_pending(&release)?>0}));
            }
        } else {
            self.kubectl(
                &["create", "-f", "-"],
                Some(&serde_json::to_vec(&object)?),
                Duration::from_secs(60),
            )?;
        }
        // A bounded original executor owns its invocations. A crash never
        // transfers them to Target or deletes their receipts/owner mappings.
        self.kubectl(
            &[
                "wait",
                "--for=jsonpath={.status.phase}=Succeeded",
                &format!("pod/{name}"),
                "--timeout=330s",
            ],
            None,
            Duration::from_secs(350),
        )?;
        let observed = self.pair_read("pod", &name)?;
        ensure!(
            provider::stopped(&observed)
                && observed["spec"]["nodeName"].as_str() == self.online_node.as_deref(),
            "runtime_pair_source_recovery_failed"
        );
        remove_pod(
            self.tools.cluster.as_mut(),
            &self.request,
            &name,
            &self.request_digest,
            observed["metadata"]["uid"].as_str(),
        )?;
        Ok(json!({"remaining":self.pair_pending(&release)?>0}))
    }

    pub(super) fn runtime_complete(&mut self) -> Result<Value> {
        let release = self.pair_current()?;
        if release.phase == Phase::Complete {
            return Ok(json!({"complete":true}));
        }
        ensure!(
            self.pair_pending(&release)? == 0 && self.pair_sources(&release)?.is_empty(),
            "runtime_pair_source_recovery_required"
        );
        let (release, health) = self.pair_fresh_health()?;
        let controller = self.pair_controller()?;
        ensure!(
            controller["spec"]["paused"] != true,
            "runtime_pair_controller_still_paused"
        );
        let adoption = AdoptionObservation {
            health,
            controller: provider::resource(&controller)?,
            template: resources::template_digest(&controller["spec"]["template"])?,
            source_pods: 0,
            source_inflight: 0,
            source_streams: 0,
            source_stopped: true,
        };
        self.pair_command("complete", Some(&serde_json::to_value(adoption)?))?;
        self.record("runtime-handoff-complete", json!({"release":release.id}))?;
        Ok(json!({"complete":true}))
    }

    pub(super) fn runtime_backup_select(&mut self) -> Result<Value> {
        let release = self.pair_current()?;
        ensure!(
            release.phase == Phase::Complete,
            "runtime_pair_completion_required"
        );
        let backup = self.request.offsite_backup.clone().context("backup")?;
        let cron = self.pair_read("cronjob", &backup.cronjob)?;
        let blueprint = self.pair_blueprint()?;
        ensure!(
            serde_json::to_value(provider::resource(&cron)?)? == blueprint["backup"]["identity"],
            "runtime_pair_backup_identity_changed"
        );
        let template = &cron["spec"]["jobTemplate"]["spec"]["template"];
        ensure!(
            backup_participant(template, &self.request.app, &self.request.pvc)
                && template["spec"]["serviceAccountName"] == backup.service_account
                && template["spec"]["containers"][0]["args"][5] == backup.bucket,
            "runtime_pair_backup_selection_changed"
        );
        let image = &template["spec"]["containers"][0]["image"];
        ensure!(
            *image == release.source.image || *image == release.target.image,
            "runtime_pair_backup_image_changed"
        );
        let original = &blueprint["backup"]["template"];
        let mut desired = original.clone();
        desired["spec"]["containers"][0]["image"] = json!(release.target.image);
        for volume in desired["spec"]["volumes"]
            .as_array_mut()
            .context("backup volumes")?
        {
            if volume["name"] == "instance" {
                volume["configMap"]["name"] = json!(selection_name(&self.request)?);
            }
        }
        ensure!(
            *template == *original || *template == desired,
            "runtime_pair_backup_template_changed"
        );
        if desired != *template {
            let patch = json!([{"op":"test","path":"/metadata/uid","value":cron["metadata"]["uid"]},
                {"op":"test","path":"/metadata/resourceVersion","value":cron["metadata"]["resourceVersion"]},
                {"op":"test","path":"/spec/jobTemplate/spec/template","value":template},
                {"op":"replace","path":"/spec/jobTemplate/spec/template","value":desired}]);
            self.kubectl(
                &[
                    "patch",
                    "cronjob",
                    &backup.cronjob,
                    "--type=json",
                    "-p",
                    &serde_json::to_string(&patch)?,
                ],
                None,
                Duration::from_secs(60),
            )?;
        }
        self.state.runtime.backup_selected = true;
        Ok(json!({"backup_runtime_selected":true}))
    }

    pub(super) fn runtime_release(&mut self) -> Result<Value> {
        ensure!(
            self.state.runtime.backup_selected,
            "runtime_pair_backup_selection_required"
        );
        let release = self.pair_current()?;
        ensure!(
            release.phase == Phase::Complete,
            "runtime_pair_completion_required"
        );
        let live = self.pair_controller()?;
        if let Some(marker) = live["metadata"]["annotations"]["day2.dev/runtime-pair"].as_str() {
            ensure!(
                marker == self.request_digest,
                "runtime_pair_controller_claim_changed"
            );
            self.pair_patch_controller(
                &live,
                vec![json!({"op":"remove","path":"/metadata/annotations/day2.dev~1runtime-pair"})],
            )?;
        }
        self.state.result =
            Some(json!({"release":release.id,"runtime_pair":true,"phase":"complete"}));
        Ok(json!({"release_recorded":true}))
    }
}
