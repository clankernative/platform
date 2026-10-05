//! Native, short lived readiness for a selected app. Configuration supplies
//! selectors; Resource Manager, Compute/IAP, TLS, exact secret reads and verified
//! humans supply facts. No receipt or owner lease can be restored from JSON or SQLite.

use super::{
    OutboundReadiness, QualifiedConnections, binding_namespace, instance_identity, profiles,
};
use crate::oauth::approval_registry::{ApprovalKeyProvider, ApprovalKeyPurpose};
use crate::oauth::effects::{Client, Instant, Response};
use crate::{artifact::Instance, iap, oauth::approval_keys::AccessTokenSource};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    BindingRef, Digest, Name,
    oauth::{
        AccountBindingPolicy, ConnectionSlotKey, OutboundConnectionBinding, ProviderAccountPolicy,
        SlotOwner,
    },
};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use rusqlite::OptionalExtension;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::Read,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use url::Url;

const LEASE_SECONDS: i64 = 60;
const HUMAN_SECONDS: i64 = 120;
const MAX_BYTES: usize = 128 * 1024;

pub(crate) fn setup(path: &std::path::Path) -> Result<Value> {
    let mut selected = QualifiedConnections::prepare_instance_file(path)?;
    setup_selected(&mut selected)
}

pub(super) fn setup_selected(selected: &mut QualifiedConnections) -> Result<Value> {
    let shell = shell_selection(&selected.instance)?;
    for ((app, name), connection) in &mut selected.entries {
        connection.binding.security_shell = shell.origin.clone();
        let secret = &selected
            .instance
            .control
            .as_ref()
            .context("OAuth secret catalog missing")?
            .secrets[&connection.binding.shell_attestation_secret];
        connection.binding.shell_attestation.revision =
            super::shell_key_revision(&selected.instance, &shell.origin, secret)?;
        connection.shell_attestation.binding = connection.binding.shell_attestation.clone();
        match connection.requirement.account_policy {
            AccountBindingPolicy::ExplicitExternalAccount => {
                connection.binding.account_binding = connection.binding.shell_attestation.clone()
            }
            AccountBindingPolicy::MappedHuman => {
                connection.binding.account_binding.revision =
                    Facts::mapping_revision(&selected.instance)?
            }
            AccountBindingPolicy::InstallationAccount => {
                anyhow::bail!("installation accounts are not reviewed by this host")
            }
        }
        selected
            .instance
            .apps
            .get_mut(app)
            .context("OAuth app missing")?
            .oauth_connections
            .insert(name.clone(), connection.binding.clone());
    }
    let targets = selected.registration_targets(&shell)?;
    let mut clients = Vec::new();
    for target in targets {
        let registration = target.registration_evidence()?.registration;
        for ((app, name), connection) in &mut selected.entries {
            if target.publication_matches(
                &connection.binding.registration.id,
                &binding_namespace(&connection.binding)?,
            ) {
                connection.binding.registration = registration.clone();
                selected
                    .instance
                    .apps
                    .get_mut(app)
                    .context("OAuth app missing")?
                    .oauth_connections
                    .insert(name.clone(), connection.binding.clone());
            }
        }
        clients.push(target.setup_description()?);
    }
    let bindings: BTreeMap<_, _> = selected
        .instance
        .apps
        .iter()
        .filter(|(_, b)| !b.oauth_connections.is_empty())
        .map(|(app, b)| (app, &b.oauth_connections))
        .collect();
    Ok(
        serde_json::json!({ "mode":"desired-metadata", "security_shell":shell, "oauth_connections":bindings, "registrations":clients, "instance":selected.instance }),
    )
}

pub(crate) fn validate(instance: &Instance) -> Result<()> {
    let Some(runtime) = &instance.oauth_runtime else {
        return Ok(());
    };
    runtime.validate()?;
    instance.security_edge()?;
    ensure!(
        instance.oauth_clients.is_some() && instance.oauth_shell_transport.is_some(),
        "OAuth runtime clients or transport missing"
    );
    for (app, selected) in &runtime.apps {
        let binding = instance
            .apps
            .get(app.as_str())
            .context("OAuth runtime app is not installed")?;
        ensure!(
            selected.accounts.len() == binding.oauth_connections.len()
                && selected
                    .accounts
                    .keys()
                    .all(|name| binding.oauth_connections.contains_key(name.as_str())),
            "OAuth runtime account selection mismatch"
        );
    }
    for (app, binding) in &instance.apps {
        ensure!(
            binding.oauth_connections.is_empty()
                || runtime.apps.keys().any(|name| name.as_str() == app),
            "OAuth runtime app selection missing"
        );
    }
    Ok(())
}

/// Deterministic setup metadata, never evidence. Qualification is minted only
/// by the bounded native edge read below. URLs reuse the selected edge contract.
pub(crate) fn shell_selection(instance: &Instance) -> Result<profiles::SecurityShellEvidence> {
    validate(instance)?;
    let runtime = instance
        .oauth_runtime
        .as_ref()
        .context("OAuth runtime not selected")?;
    let (_, edge) = instance.security_edge()?;
    let client = &instance
        .oauth_clients
        .as_ref()
        .context("OAuth clients missing")?
        .reauthentication;
    let identity = instance_identity(instance)?;
    let qualification = Digest::of(&(
        "oauth-gcp-shell-live-profile-v1",
        &identity,
        &runtime.shell,
        &edge.origin,
        &edge.iap_audience,
        crate::oauth::clients::selected_credential(instance, client)?,
    ))?;
    let origin_url = format!("{}/", edge.origin);
    let revision = Digest::of(&(
        "oauth-security-shell-evidence-v1",
        &identity,
        &origin_url,
        &qualification,
    ))?;
    Ok(profiles::SecurityShellEvidence {
        instance: identity,
        origin: day2_capabilities::oauth::SecurityOriginRef(BindingRef {
            id: Name::try_from("security_shell".to_owned())?,
            revision,
        }),
        origin_url,
        qualification,
    })
}

struct Lease {
    checked_at: i64,
    deadline: Instant,
}

impl Lease {
    fn new(now: i64, start: Instant, seconds: i64) -> Result<Self> {
        ensure!(now >= 0, "invalid OAuth readiness time");
        Ok(Self {
            checked_at: now,
            deadline: start + Duration::from_secs(seconds.try_into()?),
        })
    }

    fn fresh(&self, now: i64, seconds: i64) -> bool {
        now >= self.checked_at && now - self.checked_at < seconds && Instant::now() < self.deadline
    }
}

/// The shell has no app database or custody capability. Desired target pins are
/// assembled at startup; authenticated routes and publication require this
/// independent native edge lease before using them.
pub(crate) struct ShellFacts {
    selection: profiles::SecurityShellEvidence,
    edge: GcpEdge,
    lease: Mutex<Option<Lease>>,
}

impl ShellFacts {
    pub(crate) fn from_gke(
        instance: &Instance,
        tokens: Arc<dyn AccessTokenSource>,
    ) -> Result<Self> {
        Ok(Self {
            selection: shell_selection(instance)?,
            edge: GcpEdge::new(instance, tokens)?,
            lease: Mutex::new(None),
        })
    }

    pub(crate) fn selection(&self) -> &profiles::SecurityShellEvidence {
        &self.selection
    }
}

impl crate::oauth::security_shell::ShellGuard for ShellFacts {
    fn check(&self, now: i64) -> Result<()> {
        let mut lease = self
            .lease
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth shell facts unavailable"))?;
        if lease
            .as_ref()
            .is_some_and(|lease| lease.fresh(now, LEASE_SECONDS))
        {
            return Ok(());
        }
        *lease = None;
        let start = Instant::now();
        self.edge.check()?;
        let current = Lease::new(now, start, LEASE_SECONDS)?;
        ensure!(
            current.fresh(now, LEASE_SECONDS),
            "OAuth shell facts expired during acquisition"
        );
        *lease = Some(current);
        Ok(())
    }
}

struct Human {
    subject: String,
    lease: Lease,
}

struct State {
    humans: BTreeMap<String, Human>,
    connections: BTreeMap<String, Lease>,
}

pub(crate) struct Facts {
    selected: QualifiedConnections,
    db: PathBuf,
    shell: profiles::SecurityShellEvidence,
    edge: GcpEdge,
    keys: Arc<dyn ApprovalKeyProvider>,
    state: Mutex<State>,
}

impl Facts {
    pub(crate) fn from_gke(
        selected: QualifiedConnections,
        db: PathBuf,
        tokens: Arc<dyn AccessTokenSource>,
    ) -> Result<Self> {
        let edge = GcpEdge::new(&selected.instance, tokens.clone())?;
        let keys = Arc::new(crate::oauth::approval_keys::GcpApprovalKeys::new(
            selected.key_bindings.clone(),
            tokens,
        )?);
        Self::new(selected, db, edge, keys)
    }

    fn new(
        selected: QualifiedConnections,
        db: PathBuf,
        edge: GcpEdge,
        keys: Arc<dyn ApprovalKeyProvider>,
    ) -> Result<Self> {
        let shell = shell_selection(&selected.instance)?;
        let runtime = selected
            .instance
            .oauth_runtime
            .as_ref()
            .context("OAuth runtime not selected")?;
        for ((app, registration), connection) in &selected.entries {
            let account = &runtime.apps[&Name::try_from(app.clone())?].accounts
                [&Name::try_from(registration.clone())?];
            ensure!(
                matches!(
                    (&connection.requirement.account_policy, account),
                    (
                        AccountBindingPolicy::MappedHuman,
                        ProviderAccountPolicy::IapSubject
                    ) | (
                        AccountBindingPolicy::ExplicitExternalAccount,
                        ProviderAccountPolicy::ExternalAccounts { .. }
                    )
                ),
                "OAuth runtime account policy mismatch"
            );
            ensure!(
                connection.binding.security_shell == shell.origin,
                "OAuth runtime shell revision mismatch"
            );
            if matches!(account, ProviderAccountPolicy::IapSubject) {
                ensure!(
                    connection.binding.account_binding.revision
                        == Self::mapping_revision(&selected.instance)?,
                    "OAuth IAP account mapping revision mismatch"
                );
            }
        }
        for target in selected.registration_targets(&shell)? {
            let expected = target.registration_evidence()?.registration;
            let mut matched = false;
            for connection in selected.entries.values() {
                if target.publication_matches(
                    &connection.binding.registration.id,
                    &binding_namespace(&connection.binding)?,
                ) {
                    ensure!(
                        connection.binding.registration == expected,
                        "OAuth runtime registration revision mismatch"
                    );
                    matched = true;
                }
            }
            ensure!(matched, "OAuth runtime registration target missing");
        }
        Ok(Self {
            selected,
            db,
            shell,
            edge,
            keys,
            state: Mutex::new(State {
                humans: BTreeMap::new(),
                connections: BTreeMap::new(),
            }),
        })
    }

    pub(crate) fn mapping_revision(instance: &Instance) -> Result<Digest> {
        Digest::of(&(
            "oauth-google-iap-subject-mapping-v1",
            instance_identity(instance)?,
            &instance.security_edge()?.0.hosted_domain,
        ))
    }

    fn subject(&self, email: &str) -> Result<Option<String>> {
        let db = rusqlite::Connection::open_with_flags(
            &self.db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        db.busy_timeout(Duration::from_secs(2))?;
        db.pragma_update(None, "trusted_schema", false)?;
        Ok(db
            .query_row(
                "SELECT subject FROM day2_principals WHERE email=?1",
                [email],
                |r| r.get(0),
            )
            .optional()?)
    }
}

impl OutboundReadiness for Facts {
    fn selected_runtime(&self) -> Result<Option<Digest>> {
        self.selected
            .instance
            .oauth_runtime
            .as_ref()
            .map(Digest::of)
            .transpose()
    }

    fn observe_identity(&self, identity: &iap::Verified, now: i64) -> Result<()> {
        let tenant = &self.selected.instance.security_edge()?.0.hosted_domain;
        ensure!(
            identity
                .email
                .rsplit_once('@')
                .is_some_and(|(_, domain)| domain == tenant)
                && identity
                    .subject
                    .strip_prefix("accounts.google.com:")
                    .is_some_and(|s| !s.is_empty()
                        && s.len() <= 255
                        && s.bytes().all(|b| b.is_ascii_graphic()))
                && self.subject(&identity.email)?.as_deref() == Some(&identity.subject),
            "OAuth current human does not match immutable IAP subject"
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth live facts lock poisoned"))?;
        state
            .humans
            .retain(|_, human| human.lease.fresh(now, HUMAN_SECONDS));
        ensure!(
            state.humans.contains_key(&identity.email) || state.humans.len() < 1024,
            "OAuth live human budget"
        );
        state.humans.insert(
            identity.email.clone(),
            Human {
                subject: identity.subject.clone(),
                lease: Lease::new(now, Instant::now(), HUMAN_SECONDS)?,
            },
        );
        Ok(())
    }

    fn current(
        &self,
        binding: &OutboundConnectionBinding,
        slot: &ConnectionSlotKey,
        now: i64,
    ) -> Result<Option<profiles::OutboundInstanceEvidence>> {
        let Some(((app, registration), connection)) = self
            .selected
            .entries
            .iter()
            .find(|(_, c)| c.binding == *binding)
        else {
            return Ok(None);
        };
        ensure!(
            slot.installation == binding.namespace.installation
                && slot.environment == binding.namespace.environment
                && slot.app == binding.namespace.app
                && slot.requirement == connection.requirement.logical_id,
            "OAuth live slot mismatch"
        );
        let SlotOwner::Human { subject: owner } = &slot.owner else {
            return Ok(None);
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth live facts lock poisoned"))?;
        let Some(human) = state.humans.get(owner) else {
            return Ok(None);
        };
        if !human.lease.fresh(now, HUMAN_SECONDS)
            || self.subject(owner)?.as_deref() != Some(&human.subject)
        {
            return Ok(None);
        }
        let namespace = binding_namespace(binding)?;
        if !state
            .connections
            .get(&namespace)
            .is_some_and(|lease| lease.fresh(now, LEASE_SECONDS))
        {
            state.connections.remove(&namespace);
            let start = Instant::now();
            // These are mandatory admission guards, not an operational campaign.
            self.edge.check()?;
            for (reference, purpose) in [
                (
                    &connection.custody_verifier,
                    ApprovalKeyPurpose::CustodyVerifier,
                ),
                (
                    &connection.custody_encryption,
                    ApprovalKeyPurpose::CustodyEncryption,
                ),
                (
                    &connection.shell_attestation,
                    ApprovalKeyPurpose::ShellAttestation,
                ),
            ] {
                let mut key = self.keys.load(reference, purpose)?;
                ensure!(
                    key.binding == reference.binding
                        && key.version == reference.version
                        && key.purpose == purpose,
                    "OAuth live key identity mismatch"
                );
                key.bytes.fill(0);
            }
            let lease = Lease::new(now, start, LEASE_SECONDS)?;
            if !lease.fresh(now, LEASE_SECONDS) {
                return Ok(None);
            }
            state.connections.insert(namespace.clone(), lease);
        }
        if !state.humans[owner].lease.fresh(now, HUMAN_SECONDS)
            || self.subject(owner)?.as_deref() != Some(&state.humans[owner].subject)
        {
            return Ok(None);
        }
        let account = &self
            .selected
            .instance
            .oauth_runtime
            .as_ref()
            .context("OAuth runtime missing")?
            .apps[&Name::try_from(app.clone())?]
            .accounts[&Name::try_from(registration.clone())?];
        let instance = instance_identity(&self.selected.instance)?;
        let account = match account {
            ProviderAccountPolicy::IapSubject => profiles::AccountBindingEvidence::MappedHuman {
                instance: instance.clone(),
                mapping: binding.account_binding.clone(),
                owner: owner.clone(),
            },
            ProviderAccountPolicy::ExternalAccounts {
                allowed_tenants,
                allowed_subjects,
            } => {
                let id = Name::try_from(format!("{}_accounts", registration))?;
                let issuer = connection.reviewed.issuer_url.clone();
                let constraints = profiles::ExternalAccountConstraints {
                    binding: BindingRef {
                        revision: Digest::of(&(
                            "oauth-external-account-constraints-v1",
                            &id,
                            &issuer,
                            allowed_tenants,
                            allowed_subjects,
                        ))?,
                        id,
                    },
                    issuer_url: issuer,
                    allowed_tenants: allowed_tenants.clone(),
                    allowed_subjects: allowed_subjects.clone(),
                };
                constraints.verify(&connection.reviewed.issuer_url)?;
                profiles::AccountBindingEvidence::ExplicitExternal {
                    instance: instance.clone(),
                    approval: binding.account_binding.clone(),
                    constraints,
                    owner: owner.clone(),
                }
            }
        };
        let target = self
            .selected
            .registration_targets(&self.shell)?
            .into_iter()
            .find(|t| t.publication_matches(&binding.registration.id, &namespace))
            .context("OAuth live registration target missing")?;
        Ok(Some(profiles::OutboundInstanceEvidence {
            instance,
            binding_namespace: namespace,
            app_origin_url: format!(
                "{}/",
                self.selected.instance.apps[app]
                    .edge
                    .as_ref()
                    .context("OAuth app edge missing")?
                    .origin
            ),
            shell: self.shell.clone(),
            registration: target.registration_evidence()?,
            custody: binding.custody.clone(),
            account,
            product_return: binding.product_return.clone(),
        }))
    }
}

struct GcpEdge {
    client: Client,
    endpoint: Url,
    project_endpoint: Url,
    tls: Url,
    project: String,
    backend: String,
    map: String,
    proxy: String,
    forwarding: String,
    service: String,
    audience: String,
    host: String,
    tokens: Arc<dyn AccessTokenSource>,
    #[cfg(test)]
    fixture: bool,
}

impl GcpEdge {
    fn new(instance: &Instance, tokens: Arc<dyn AccessTokenSource>) -> Result<Self> {
        validate(instance)?;
        let selection = &instance
            .oauth_runtime
            .as_ref()
            .context("OAuth runtime missing")?
            .shell;
        let (_, edge) = instance.security_edge()?;
        Ok(Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(5))
                .build()?,
            endpoint: Url::parse("https://compute.googleapis.com/compute/v1/")?,
            project_endpoint: Url::parse(
                "https://cloudresourcemanager.googleapis.com/v1/projects/",
            )?,
            tls: Url::parse(&format!("{}/health/ready", edge.origin))?,
            project: selection.project.clone(),
            backend: selection.backend_service.clone(),
            map: selection.url_map.clone(),
            proxy: selection.https_proxy.clone(),
            forwarding: selection.forwarding_rule.clone(),
            service: selection.kubernetes_service.clone(),
            audience: edge.iap_audience.clone(),
            host: edge.authority().into(),
            tokens,
            #[cfg(test)]
            fixture: false,
        })
    }

    fn get(&self, path: &str) -> Result<Value> {
        self.read(self.endpoint.join(path)?)
    }

    fn read(&self, url: Url) -> Result<Value> {
        let token = self.tokens.access_token()?;
        ensure!(
            !token.is_empty() && token.len() <= 8192 && token.bytes().all(|b| b.is_ascii_graphic()),
            "invalid OAuth Compute access token"
        );
        let mut auth = HeaderValue::from_str(&format!("Bearer {token}"))?;
        auth.set_sensitive(true);
        let response = self.client.get(url).header(AUTHORIZATION, auth).send()?;
        ensure!(
            response.status().is_success()
                && response
                    .content_length()
                    .is_none_or(|n| n <= MAX_BYTES as u64),
            "OAuth cloud fact unavailable"
        );
        let mut bytes = Vec::new();
        response
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_BYTES, "OAuth cloud fact byte budget");
        crate::json::decode(&bytes).map_err(|_| anyhow::anyhow!("invalid OAuth cloud fact"))
    }

    fn check(&self) -> Result<()> {
        let project_path = format!("projects/{}", self.project);
        // Compute Project.id is a Compute resource identifier, not the project
        // number in an IAP audience. Resource Manager binds that number to the
        // selected project ID without relying on configuration or email names.
        let project = self.read(self.project_endpoint.join(&self.project)?)?;
        let backend_path = format!("{project_path}/global/backendServices/{}", self.backend);
        let map_path = format!("{project_path}/global/urlMaps/{}", self.map);
        let proxy_path = format!("{project_path}/global/targetHttpsProxies/{}", self.proxy);
        let forwarding_path = format!("{project_path}/global/forwardingRules/{}", self.forwarding);
        let backend = self.get(&backend_path)?;
        let map = self.get(&map_path)?;
        let proxy = self.get(&proxy_path)?;
        let forwarding = self.get(&forwarding_path)?;
        self.verify(&project, &backend, &map)?;
        let address = self.verify_frontend(&proxy, &forwarding)?;
        // TLS checks the selected host with system roots. No cloud bearer or
        // human assertion is sent, and an IAP redirect is never followed.
        let response = self.tls_probe(address)?;
        ensure!(
            response.status().as_u16() < 500,
            "OAuth shell TLS edge unavailable"
        );
        ensure!(
            backend == self.get(&backend_path)?
                && map == self.get(&map_path)?
                && proxy == self.get(&proxy_path)?
                && forwarding == self.get(&forwarding_path)?,
            "OAuth shell edge changed during admission"
        );
        Ok(())
    }

    fn verify_frontend(&self, proxy: &Value, forwarding: &Value) -> Result<IpAddr> {
        let root = format!(
            "https://www.googleapis.com/compute/v1/projects/{}/global",
            self.project
        );
        let proxy_link = format!("{root}/targetHttpsProxies/{}", self.proxy);
        ensure!(
            proxy["name"] == self.proxy
                && proxy["selfLink"] == proxy_link
                && proxy["urlMap"] == format!("{root}/urlMaps/{}", self.map)
                && proxy["sslCertificates"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()
                        && a.len() <= 15
                        && a.iter().all(|v| v
                            .as_str()
                            .is_some_and(|s| s.starts_with(&format!("{root}/sslCertificates/")))))
                && proxy.get("certificateMap").is_none_or(|v| v == ""),
            "OAuth shell HTTPS proxy mismatch"
        );
        ensure!(
            forwarding["name"] == self.forwarding
                && forwarding["selfLink"] == format!("{root}/forwardingRules/{}", self.forwarding)
                && forwarding["target"] == proxy_link
                && forwarding["IPProtocol"] == "TCP"
                && forwarding["portRange"] == "443-443"
                && forwarding["loadBalancingScheme"] == "EXTERNAL",
            "OAuth shell HTTPS forwarding rule mismatch"
        );
        let address: IpAddr = forwarding["IPAddress"]
            .as_str()
            .context("OAuth shell frontend address missing")?
            .parse()?;
        ensure!(
            !address.is_loopback() && !address.is_unspecified(),
            "invalid OAuth shell frontend address"
        );
        Ok(address)
    }

    fn tls_probe(&self, address: IpAddr) -> Result<Response> {
        #[cfg(test)]
        if self.fixture {
            return self.client.get(self.tls.clone()).send();
        }
        let response = self.client.get(self.tls.clone()).send()?;
        ensure!(
            response
                .remote_addr()
                .is_some_and(|peer| peer.ip() == address),
            "OAuth shell DNS/TLS peer does not select the qualified frontend"
        );
        Ok(response)
    }

    fn verify(&self, project: &Value, backend: &Value, map: &Value) -> Result<()> {
        let number = project["projectNumber"]
            .as_str()
            .context("OAuth Resource Manager project identity missing")?;
        let id = backend["id"]
            .as_str()
            .context("OAuth Compute backend identity missing")?;
        ensure!(
            !number.is_empty()
                && number.bytes().all(|b| b.is_ascii_digit())
                && !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_digit())
                && project["projectId"] == self.project
                && project["lifecycleState"] == "ACTIVE"
                && self.audience == format!("/projects/{number}/global/backendServices/{id}"),
            "OAuth shell IAP audience mismatch"
        );
        let backend_link = format!(
            "https://www.googleapis.com/compute/v1/projects/{}/global/backendServices/{}",
            self.project, self.backend
        );
        let map_link = format!(
            "https://www.googleapis.com/compute/v1/projects/{}/global/urlMaps/{}",
            self.project, self.map
        );
        let description: Value = crate::json::decode(
            backend["description"]
                .as_str()
                .context("OAuth GKE backend description missing")?
                .as_bytes(),
        )?;
        ensure!(
            backend["name"] == self.backend
                && backend["selfLink"] == backend_link
                && backend["iap"]["enabled"] == true
                && description["kubernetes.io/service-name"] == self.service
                && map["name"] == self.map
                && map["selfLink"] == map_link,
            "OAuth dedicated shell backend mismatch"
        );
        for key in ["customRequestHeaders", "customResponseHeaders"] {
            ensure!(
                backend
                    .get(key)
                    .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
                "OAuth shell backend header overrides unsupported"
            );
        }
        object_keys(
            map,
            &[
                "kind",
                "id",
                "creationTimestamp",
                "name",
                "description",
                "selfLink",
                "fingerprint",
                "defaultService",
                "hostRules",
                "pathMatchers",
                "tests",
            ],
        )?;
        ensure!(
            map["defaultService"] == backend_link,
            "OAuth shell default route mismatch"
        );
        let rules = map["hostRules"]
            .as_array()
            .context("OAuth shell host rules missing")?;
        ensure!(rules.len() == 1, "OAuth shell host rule budget");
        object_keys(&rules[0], &["description", "hosts", "pathMatcher"])?;
        ensure!(
            rules[0]["hosts"] == serde_json::json!([self.host]),
            "OAuth shell host rule mismatch"
        );
        let matchers = map["pathMatchers"]
            .as_array()
            .context("OAuth shell path matchers missing")?;
        ensure!(matchers.len() == 1, "OAuth shell path matcher budget");
        let matcher = &matchers[0];
        object_keys(
            matcher,
            &["name", "description", "defaultService", "pathRules"],
        )?;
        ensure!(
            matcher["name"].as_str().is_some()
                && matcher["name"] == rules[0]["pathMatcher"]
                && matcher["defaultService"] == backend_link,
            "OAuth shell path matcher mismatch"
        );
        if let Some(paths) = matcher.get("pathRules") {
            let paths = paths.as_array().context("invalid OAuth shell path rules")?;
            ensure!(paths.len() <= 64, "OAuth shell path rule budget");
            for path in paths {
                object_keys(path, &["paths", "service"])?;
                ensure!(
                    path["service"] == backend_link
                        && path["paths"].as_array().is_some_and(|p| !p.is_empty()
                            && p.len() <= 64
                            && p.iter().all(|v| v
                                .as_str()
                                .is_some_and(|s| s.starts_with('/') && s.len() <= 1024))),
                    "OAuth shell path route mismatch"
                );
            }
        }
        Ok(())
    }
}

fn object_keys(value: &Value, allowed: &[&str]) -> Result<()> {
    ensure!(
        value
            .as_object()
            .is_some_and(|object| object.keys().all(|k| allowed.contains(&k.as_str()))),
        "unsupported OAuth shell routing shape"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::oauth::approval_registry::{ApprovalKeyMaterial, ApprovalKeyRef};
    use serde_json::json;
    use std::{
        io::Write,
        net::TcpListener,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        thread,
    };

    #[test]
    fn app_deployment_plan_oracle_uses_the_native_closed_instance_contract() -> Result<()> {
        // OpenTofu asserts that its rendered instance equals this same oracle.
        // Synthetic revisions exercise schema composition, not artifact admission.
        let bytes =
            include_bytes!("../../../../deploy/gke/stacks/day2-app/tests/oauth-instance.json");
        let instance = Instance::from_bytes(bytes)?;
        let app = &instance.apps["example_app"];
        assert_eq!(app.oauth_connections.len(), 1);
        assert_eq!(
            instance.oauth_runtime.as_ref().unwrap().apps
                [&Name::try_from("example_app".to_owned())?]
                .service_account,
            "app-native@example-tools.iam.gserviceaccount.com"
        );
        assert!(instance.control.as_ref().unwrap().secrets.len() == 5);
        for (path, value) in [
            ("/oauth_runtime/apps/example_app/ready", json!(true)),
            (
                "/apps/example_app/oauth_connections/calendar/provider_scopes",
                json!([]),
            ),
            ("/control/secrets/verifier/version", json!("latest")),
            ("/control/apps", json!({})),
        ] {
            let mut invalid: serde_json::Value = serde_json::from_slice(bytes)?;
            let (parent, key) = path.rsplit_once('/').unwrap();
            invalid.pointer_mut(parent).unwrap()[key] = value;
            assert!(Instance::from_bytes(&serde_json::to_vec(&invalid)?).is_err());
        }
        Ok(())
    }

    struct Tokens;
    impl AccessTokenSource for Tokens {
        fn access_token(&self) -> Result<String> {
            Ok("native-workload-token".into())
        }
    }

    #[derive(Default)]
    struct Keys {
        calls: AtomicUsize,
        wrong: AtomicBool,
        swap_owner: Option<PathBuf>,
    }
    impl ApprovalKeyProvider for Keys {
        fn load(
            &self,
            reference: &ApprovalKeyRef,
            purpose: ApprovalKeyPurpose,
        ) -> Result<ApprovalKeyMaterial> {
            let sequence = self.calls.fetch_add(1, Ordering::SeqCst);
            if sequence == 2
                && let Some(path) = &self.swap_owner
            {
                let db = rusqlite::Connection::open(path)?;
                db.execute(
                    "UPDATE day2_principals SET subject='accounts.google.com:replacement'",
                    [],
                )?;
            }
            Ok(ApprovalKeyMaterial {
                binding: reference.binding.clone(),
                version: if self.wrong.load(Ordering::SeqCst) {
                    "substituted".into()
                } else {
                    reference.version.clone()
                },
                purpose,
                bytes: [37; 32],
            })
        }
    }

    pub(crate) fn selected() -> Result<QualifiedConnections> {
        let (mut selected, _) = super::super::tests::publication_fixture()?;
        selected.instance.oauth_shell_transport = Some(day2_capabilities::oauth::ShellTransport {
            service_account: "shell@company-tools.iam.gserviceaccount.com".into(),
        });
        selected.instance.oauth_runtime = Some(serde_json::from_value(json!({
            "version":1,"shell":{"project":"company-tools","backend_service":"shell-backend","url_map":"shell-map","https_proxy":"shell-proxy","forwarding_rule":"shell-https","kubernetes_service":"tools/security-shell"},
            "apps":{"workspace":{"service_account":"app@company-tools.iam.gserviceaccount.com","accounts":{"calendar":{"kind":"external_accounts","allowed_tenants":["example.com"],"allowed_subjects":null}}}}
        }))?);
        let shell = shell_selection(&selected.instance)?;
        let attestation = selected.instance.control.as_ref().unwrap().secrets[&selected
            .entries
            .values()
            .next()
            .unwrap()
            .binding
            .shell_attestation_secret]
            .clone();
        let revision =
            super::super::shell_key_revision(&selected.instance, &shell.origin, &attestation)?;
        for connection in selected.entries.values_mut() {
            connection.binding.security_shell = shell.origin.clone();
            connection.binding.shell_attestation.revision = revision.clone();
            connection.binding.account_binding = connection.binding.shell_attestation.clone();
            connection.shell_attestation.binding = connection.binding.shell_attestation.clone();
        }
        let target = selected.registration_targets(&shell)?.remove(0);
        let connection = selected.entries.values_mut().next().unwrap();
        connection.binding.registration = target.registration_evidence()?.registration;
        selected
            .instance
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .insert("calendar".into(), connection.binding.clone());
        Ok(selected)
    }

    fn documents(edge: &GcpEdge) -> (Value, Value, Value) {
        let parts: Vec<_> = edge.audience.split('/').collect();
        let backend = format!(
            "https://www.googleapis.com/compute/v1/projects/{}/global/backendServices/{}",
            edge.project, edge.backend
        );
        (
            json!({"projectId":edge.project,"projectNumber":parts[2],"lifecycleState":"ACTIVE"}),
            json!({"name":edge.backend,"id":parts[5],"selfLink":backend,"iap":{"enabled":true},"description":json!({"kubernetes.io/service-name":edge.service}).to_string()}),
            json!({"name":edge.map,"selfLink":format!("https://www.googleapis.com/compute/v1/projects/{}/global/urlMaps/{}",edge.project,edge.map),"fingerprint":"stable","defaultService":backend,"hostRules":[{"hosts":[edge.host],"pathMatcher":"shell"}],"pathMatchers":[{"name":"shell","defaultService":backend,"pathRules":[{"paths":["/*"],"service":backend}]}]}),
        )
    }

    #[test]
    fn cloud_edge_and_readiness_lease_faults_replay_with_virtual_clocks() -> Result<()> {
        use crate::oauth::security_shell::ShellGuard;
        use crate::oauth::{effects, simulation::World};
        for seed in 0..8 {
            for fault in std::iter::once(None).chain((0..10).map(Some)) {
                let run = || -> Result<_> {
                    let world = World::new(seed);
                    effects::scope(world.clone(), || {
                        let selected = selected()?;
                        let facts = ShellFacts::from_gke(selected.instance(), Arc::new(Tokens))?;
                        let (project, backend, map) = documents(&facts.edge);
                        let (proxy, forwarding) = frontend(&facts.edge);
                        let replies = vec![
                            (200, project),
                            (200, backend.clone()),
                            (200, map.clone()),
                            (200, proxy.clone()),
                            (200, forwarding.clone()),
                            (302, json!("IAP login")),
                            (200, backend),
                            (200, map),
                            (200, proxy),
                            (200, forwarding),
                        ];
                        world.script(
                            replies
                                .into_iter()
                                .map(|(status, value)| (status, value.to_string()))
                                .collect(),
                            fault,
                        );
                        assert!(facts.lease.lock().unwrap().is_none());
                        let accepted = facts.check(100).is_ok();
                        assert_eq!(accepted, fault.is_none());
                        assert_eq!(facts.lease.lock().unwrap().is_some(), accepted);
                        if accepted {
                            facts.check(159)?;
                            assert_eq!(world.requests().len(), 10);
                            world.advance(60);
                            world.script(vec![(403, json!({"error":"retired"}).to_string())], None);
                            assert!(facts.check(100).is_err());
                            assert!(facts.lease.lock().unwrap().is_none());
                        }
                        Ok((
                            accepted,
                            facts.lease.lock().unwrap().is_some(),
                            world.requests(),
                        ))
                    })
                };
                assert_eq!(run()?, run()?);
            }
        }
        Ok(())
    }

    struct Wire {
        endpoint: Url,
        worker: thread::JoinHandle<Vec<String>>,
    }

    fn frontend(edge: &GcpEdge) -> (Value, Value) {
        let root = format!(
            "https://www.googleapis.com/compute/v1/projects/{}/global",
            edge.project
        );
        let proxy = format!("{root}/targetHttpsProxies/{}", edge.proxy);
        (
            json!({"name":edge.proxy,"selfLink":proxy,"urlMap":format!("{root}/urlMaps/{}",edge.map),"sslCertificates":[format!("{root}/sslCertificates/shell-certificate")]}),
            json!({"name":edge.forwarding,"selfLink":format!("{root}/forwardingRules/{}",edge.forwarding),"target":proxy,"IPProtocol":"TCP","portRange":"443-443","loadBalancingScheme":"EXTERNAL","IPAddress":"203.0.113.42"}),
        )
    }
    impl Wire {
        fn new(responses: Vec<(u16, Value)>) -> Result<Self> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let endpoint = Url::parse(&format!("http://{}/", listener.local_addr()?))?;
            let worker = thread::spawn(move || {
                let mut requests = Vec::new();
                for (status, body) in responses {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let mut stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error)
                                if error.kind() == std::io::ErrorKind::WouldBlock
                                    && Instant::now() < deadline =>
                            {
                                thread::sleep(Duration::from_millis(5))
                            }
                            Err(error) => panic!("fixture request missing: {error}"),
                        }
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        stream.read_exact(&mut byte).unwrap();
                        request.push(byte[0]);
                        assert!(request.len() < 8192);
                    }
                    requests.push(String::from_utf8(request).unwrap().to_ascii_lowercase());
                    let body = body.to_string();
                    write!(stream,"HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:1/never\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                }
                requests
            });
            Ok(Self { endpoint, worker })
        }
    }

    fn successful_wire(edge: &mut GcpEdge) -> Result<Wire> {
        let (project, backend, map) = documents(edge);
        let (proxy, forwarding) = frontend(edge);
        let wire = Wire::new(vec![
            (200, project),
            (200, backend.clone()),
            (200, map.clone()),
            (200, proxy.clone()),
            (200, forwarding.clone()),
            (302, json!("IAP login")),
            (200, backend),
            (200, map),
            (200, proxy),
            (200, forwarding),
        ])?;
        edge.endpoint = wire.endpoint.clone();
        edge.project_endpoint = wire.endpoint.join("resource-manager/v1/projects/")?;
        edge.tls = wire.endpoint.join("health/ready")?;
        edge.fixture = true;
        Ok(wire)
    }

    #[test]
    fn native_edge_reads_exact_resources_refuses_routing_substitution_and_never_forwards_bearer_to_tls()
    -> Result<()> {
        let selected = selected()?;
        let mut edge = GcpEdge::new(&selected.instance, Arc::new(Tokens))?;
        let (project, backend, map) = documents(&edge);
        edge.verify(&project, &backend, &map)?;
        let mut wrong = backend.clone();
        wrong["iap"]["enabled"] = json!(false);
        assert!(edge.verify(&project, &wrong, &map).is_err());
        wrong = backend.clone();
        wrong["id"] = json!("999");
        assert!(edge.verify(&project, &wrong, &map).is_err());
        wrong = backend.clone();
        wrong["description"] = json!("{\"kubernetes.io/service-name\":\"tools/app\"}");
        assert!(edge.verify(&project, &wrong, &map).is_err());
        for field in [
            "defaultRouteAction",
            "defaultUrlRedirect",
            "headerAction",
            "routeRules",
        ] {
            let mut wrong = map.clone();
            wrong["pathMatchers"][0][field] = json!({});
            assert!(edge.verify(&project, &backend, &wrong).is_err());
        }
        let mut wrong = map.clone();
        wrong["hostRules"][0]["hosts"] = json!(["*.example.com"]);
        assert!(edge.verify(&project, &backend, &wrong).is_err());
        wrong = map.clone();
        wrong["pathMatchers"][0]["pathRules"][0]["service"] = json!("another-backend");
        assert!(edge.verify(&project, &backend, &wrong).is_err());
        let wire = successful_wire(&mut edge)?;
        edge.check()?;
        let requests = wire.worker.join().unwrap();
        assert_eq!(requests.len(), 10);
        assert!(
            requests[0].starts_with("get /resource-manager/v1/projects/company-tools http/1.1")
        );
        assert!(requests[1].starts_with(
            "get /projects/company-tools/global/backendservices/shell-backend http/1.1"
        ));
        assert!(
            requests[2]
                .starts_with("get /projects/company-tools/global/urlmaps/shell-map http/1.1")
        );
        for index in [0, 1, 2, 3, 4, 6, 7, 8, 9] {
            assert!(requests[index].contains("authorization: bearer native-workload-token\r\n"));
        }
        assert!(!requests[5].contains("authorization:"));
        assert!(requests[5].starts_with("get /health/ready http/1.1"));
        Ok(())
    }

    #[test]
    fn native_edge_uses_resource_manager_project_number_and_rejects_compute_resource_ids()
    -> Result<()> {
        let selected = selected()?;
        let edge = GcpEdge::new(&selected.instance, Arc::new(Tokens))?;
        assert_eq!(
            edge.project_endpoint.as_str(),
            "https://cloudresourcemanager.googleapis.com/v1/projects/"
        );
        let (project, backend, map) = documents(&edge);
        edge.verify(&project, &backend, &map)?;
        let compute = json!({"name":edge.project,"id":"9876543210987654321"});
        assert!(edge.verify(&compute, &backend, &map).is_err());
        for (field, value) in [
            ("projectNumber", json!("9876543210987654321")),
            ("projectNumber", json!(123)),
            ("projectNumber", Value::Null),
            ("projectId", json!("another-project")),
            ("lifecycleState", json!("DELETE_REQUESTED")),
        ] {
            let mut wrong = project.clone();
            wrong[field] = value;
            assert!(edge.verify(&wrong, &backend, &map).is_err());
        }
        let mut wrong = edge;
        wrong.audience = format!(
            "/projects/9876543210987654321/global/backendServices/{}",
            backend["id"].as_str().unwrap()
        );
        assert!(wrong.verify(&project, &backend, &map).is_err());
        Ok(())
    }

    #[test]
    fn native_edge_rejects_cloud_redirects_duplicate_json_and_mid_read_changes() -> Result<()> {
        let selected = selected()?;
        let mut edge = GcpEdge::new(&selected.instance, Arc::new(Tokens))?;
        let wire = Wire::new(vec![(302, json!({}))])?;
        edge.endpoint = wire.endpoint.clone();
        edge.project_endpoint = wire.endpoint.join("resource-manager/v1/projects/")?;
        assert!(edge.check().is_err());
        wire.worker.join().unwrap();
        let (project, backend, map) = documents(&edge);
        let (proxy, forwarding) = frontend(&edge);
        let mut changed = map.clone();
        changed["fingerprint"] = json!("changed");
        let wire = Wire::new(vec![
            (200, project),
            (200, backend.clone()),
            (200, map),
            (200, proxy),
            (200, forwarding),
            (200, json!({})),
            (200, backend),
            (200, changed),
        ])?;
        edge.endpoint = wire.endpoint.clone();
        edge.project_endpoint = wire.endpoint.join("resource-manager/v1/projects/")?;
        edge.tls = wire.endpoint.join("health/ready")?;
        edge.fixture = true;
        assert!(edge.check().is_err());
        wire.worker.join().unwrap();
        let duplicate = b"{\"name\":\"shell-map\",\"name\":\"other\"}";
        assert!(crate::json::decode::<Value>(duplicate).is_err());
        Ok(())
    }

    #[test]
    fn frontend_substitution_and_wrong_tls_peer_are_refused() -> Result<()> {
        let selected = selected()?;
        let mut edge = GcpEdge::new(&selected.instance, Arc::new(Tokens))?;
        let (proxy, forwarding) = frontend(&edge);
        let address = edge.verify_frontend(&proxy, &forwarding)?;
        let mut wrong = proxy.clone();
        wrong["urlMap"] = json!("another-map");
        assert!(edge.verify_frontend(&wrong, &forwarding).is_err());
        let mut wrong = forwarding.clone();
        wrong["target"] = json!("another-proxy");
        assert!(edge.verify_frontend(&proxy, &wrong).is_err());
        wrong = forwarding.clone();
        wrong["portRange"] = json!("80-443");
        assert!(edge.verify_frontend(&proxy, &wrong).is_err());
        wrong = forwarding;
        wrong["IPAddress"] = json!("127.0.0.1");
        assert!(edge.verify_frontend(&proxy, &wrong).is_err());
        let wire = Wire::new(vec![(200, json!({}))])?;
        edge.tls = wire.endpoint.join("health/ready")?;
        assert!(edge.tls_probe(address).is_err());
        let requests = wire.worker.join().unwrap();
        assert!(!requests[0].contains("authorization:"));
        Ok(())
    }

    #[test]
    fn setup_metadata_recomputes_dependent_pins_without_issuing_readiness() -> Result<()> {
        let mut selected = selected()?;
        let first = setup_selected(&mut selected)?;
        assert_eq!(first["mode"], "desired-metadata");
        assert_eq!(first, setup_selected(&mut selected)?);
        assert_eq!(
            first["oauth_connections"]["workspace"]["calendar"]["registration"],
            first["registrations"][0]["registration_selection"]
        );
        selected
            .instance
            .oauth_runtime
            .as_mut()
            .unwrap()
            .shell
            .url_map = "replacement-map".into();
        let changed = setup_selected(&mut selected)?;
        assert_ne!(first["security_shell"], changed["security_shell"]);
        assert_ne!(
            first["registrations"][0]["callback_url"],
            changed["registrations"][0]["callback_url"]
        );
        assert_ne!(
            first["registrations"][0]["registration_selection"],
            changed["registrations"][0]["registration_selection"]
        );
        assert_ne!(
            first["oauth_connections"]["workspace"]["calendar"]["shell_attestation"],
            changed["oauth_connections"]["workspace"]["calendar"]["shell_attestation"]
        );
        let output = changed.to_string();
        assert!(
            !output.contains("access_token")
                && !output.contains("ready\"")
                && !output.contains("receipt")
        );
        Ok(())
    }

    #[test]
    fn current_facts_require_fresh_verified_immutable_owner_exact_keys_and_nonrestorable_leases()
    -> Result<()> {
        let selected = selected()?;
        let binding = selected.entries.values().next().unwrap().binding.clone();
        let slot = ConnectionSlotKey {
            installation: binding.namespace.installation.clone(),
            environment: binding.namespace.environment.clone(),
            app: binding.namespace.app.clone(),
            requirement: selected
                .entries
                .values()
                .next()
                .unwrap()
                .requirement
                .logical_id
                .clone(),
            owner: SlotOwner::Human {
                subject: "human@example.com".into(),
            },
        };
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("app.sqlite");
        let db = rusqlite::Connection::open(&path)?;
        db.execute_batch("CREATE TABLE day2_principals(email TEXT PRIMARY KEY, subject TEXT NOT NULL, first_seen INTEGER NOT NULL);")?;
        let identity = iap::Verified {
            email: "human@example.com".into(),
            subject: "accounts.google.com:immutable-human".into(),
        };
        iap::bind_subject(&db, &identity, 100)?;
        let mut edge = GcpEdge::new(&selected.instance, Arc::new(Tokens))?;
        let wire = successful_wire(&mut edge)?;
        let keys = Arc::new(Keys::default());
        let mut facts = Facts::new(selected, path, edge, keys.clone())?;
        assert!(facts.current(&binding, &slot, 100)?.is_none());
        facts.observe_identity(&identity, 100)?;
        let evidence = facts.current(&binding, &slot, 100)?.unwrap();
        assert_eq!(evidence.registration.registration, binding.registration);
        let connection = facts.selected.entries.values().next().unwrap();
        let intent = crate::oauth::connect::ConnectIntent {
            attempt: "native-google-attempt".into(),
            slot: slot.id(&connection.requirement)?.as_str().into(),
            expected_generation: None,
            expected_epoch: 1,
            proposed_generation: 1,
            owner: identity.email.clone(),
            profile: binding.profile.id.as_str().into(),
            registration: Digest::of(&binding.registration)?.as_str().into(),
            callback: Digest::of(&evidence.registration.callback)?.as_str().into(),
            consent: connection
                .permission
                .consent_digest(&connection.requirement)?
                .as_str()
                .into(),
            expires_at: 300,
        };
        let callback = crate::oauth::connect::CallbackBinding::from_secret_state(
            b"native-secret-state-with-at-least-thirty-two-bytes",
            crate::oauth::connect::CallbackBindingSpec {
                issuer: connection.reviewed.issuer.clone(),
                issuer_url: connection.reviewed.issuer_url.clone(),
                security_origin: evidence.shell.origin.clone(),
                profile: binding.profile.clone(),
                callback: evidence.registration.callback.clone(),
                binding_namespace: evidence.binding_namespace.clone(),
                session: Digest::of(&"native-shell-session")?,
                product_return: binding.product_return.clone(),
            },
        )?;
        profiles::qualify_outbound_connect(
            &intent,
            &callback,
            &connection.requirement,
            &connection.permission,
            &connection.reviewed,
            &evidence,
        )?;
        assert_eq!(keys.calls.load(Ordering::SeqCst), 3);
        assert!(facts.current(&binding, &slot, 159)?.is_some());
        assert_eq!(keys.calls.load(Ordering::SeqCst), 3);
        assert!(facts.current(&binding, &slot, 99)?.is_none());
        assert!(facts.current(&binding, &slot, 220)?.is_none());
        let requests = wire.worker.join().unwrap();
        assert_eq!(requests.len(), 10);
        let unavailable = Wire::new(vec![(403, json!({"error":"retired"}))])?;
        facts.edge.endpoint = unavailable.endpoint.clone();
        facts.edge.project_endpoint = unavailable.endpoint.join("resource-manager/v1/projects/")?;
        assert!(facts.current(&binding, &slot, 160).is_err());
        assert!(facts.state.lock().unwrap().connections.is_empty());
        unavailable.worker.join().unwrap();
        let mut substitute = identity.clone();
        substitute.subject = "accounts.google.com:replacement".into();
        assert!(facts.observe_identity(&substitute, 100).is_err());
        db.execute(
            "UPDATE day2_principals SET subject='accounts.google.com:replacement'",
            [],
        )?;
        assert!(facts.current(&binding, &slot, 100)?.is_none());
        // Removing the native lease cannot be repaired by a durable principal row.
        facts.state.lock().unwrap().humans.clear();
        assert!(facts.current(&binding, &slot, 100)?.is_none());
        Ok(())
    }

    #[test]
    fn shell_edge_leases_start_empty_expire_and_failed_renewal_cannot_retain_authority()
    -> Result<()> {
        use crate::oauth::security_shell::ShellGuard;
        let selected = selected()?;
        let mut facts = ShellFacts::from_gke(selected.instance(), Arc::new(Tokens))?;
        assert!(facts.lease.lock().unwrap().is_none());
        let wire = successful_wire(&mut facts.edge)?;
        facts.check(100)?;
        facts.check(159)?;
        assert_eq!(wire.worker.join().unwrap().len(), 10);
        facts.lease.lock().unwrap().as_mut().unwrap().deadline = Instant::now();
        let unavailable = Wire::new(vec![(403, json!({"error":"retired"}))])?;
        facts.edge.endpoint = unavailable.endpoint.clone();
        facts.edge.project_endpoint = unavailable.endpoint.join("resource-manager/v1/projects/")?;
        assert!(facts.check(159).is_err());
        assert!(facts.lease.lock().unwrap().is_none());
        unavailable.worker.join().unwrap();
        Ok(())
    }

    #[test]
    fn expiry_and_key_substitution_do_not_issue_or_renew_a_fact_lease() -> Result<()> {
        let mut lease = Lease::new(100, Instant::now(), LEASE_SECONDS)?;
        assert!(lease.fresh(159, LEASE_SECONDS));
        assert!(!lease.fresh(160, LEASE_SECONDS));
        assert!(!lease.fresh(99, LEASE_SECONDS));
        lease.deadline = Instant::now();
        assert!(!lease.fresh(100, LEASE_SECONDS));
        let selected = selected()?;
        let binding = selected.entries.values().next().unwrap().binding.clone();
        let slot = ConnectionSlotKey {
            installation: binding.namespace.installation.clone(),
            environment: binding.namespace.environment.clone(),
            app: binding.namespace.app.clone(),
            requirement: selected
                .entries
                .values()
                .next()
                .unwrap()
                .requirement
                .logical_id
                .clone(),
            owner: SlotOwner::Human {
                subject: "human@example.com".into(),
            },
        };
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("app.sqlite");
        let db = rusqlite::Connection::open(&path)?;
        db.execute_batch("CREATE TABLE day2_principals(email TEXT PRIMARY KEY, subject TEXT NOT NULL, first_seen INTEGER NOT NULL);")?;
        let identity = iap::Verified {
            email: "human@example.com".into(),
            subject: "accounts.google.com:immutable-human".into(),
        };
        iap::bind_subject(&db, &identity, 100)?;
        let mut edge = GcpEdge::new(&selected.instance, Arc::new(Tokens))?;
        let wire = successful_wire(&mut edge)?;
        let keys = Arc::new(Keys::default());
        keys.wrong.store(true, Ordering::SeqCst);
        let facts = Facts::new(selected, path, edge, keys.clone())?;
        facts.observe_identity(&identity, 100)?;
        let error = facts.current(&binding, &slot, 100).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("OAuth live key identity mismatch")
        );
        assert_eq!(keys.calls.load(Ordering::SeqCst), 1);
        assert!(facts.state.lock().unwrap().connections.is_empty());
        wire.worker.join().unwrap();
        Ok(())
    }

    #[test]
    fn owner_subject_is_rechecked_after_external_fact_reads() -> Result<()> {
        let selected = selected()?;
        let connection = selected.entries.values().next().unwrap();
        let binding = connection.binding.clone();
        let slot = ConnectionSlotKey {
            installation: binding.namespace.installation.clone(),
            environment: binding.namespace.environment.clone(),
            app: binding.namespace.app.clone(),
            requirement: connection.requirement.logical_id.clone(),
            owner: SlotOwner::Human {
                subject: "human@example.com".into(),
            },
        };
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("owner-race.sqlite");
        let db = rusqlite::Connection::open(&path)?;
        db.execute_batch("CREATE TABLE day2_principals(email TEXT PRIMARY KEY, subject TEXT NOT NULL, first_seen INTEGER NOT NULL);")?;
        let identity = iap::Verified {
            email: "human@example.com".into(),
            subject: "accounts.google.com:immutable-human".into(),
        };
        iap::bind_subject(&db, &identity, 100)?;
        let mut edge = GcpEdge::new(&selected.instance, Arc::new(Tokens))?;
        let wire = successful_wire(&mut edge)?;
        let keys = Arc::new(Keys {
            swap_owner: Some(path.clone()),
            ..Keys::default()
        });
        let facts = Facts::new(selected, path, edge, keys.clone())?;
        facts.observe_identity(&identity, 100)?;
        assert!(facts.current(&binding, &slot, 100)?.is_none());
        assert_eq!(keys.calls.load(Ordering::SeqCst), 3);
        wire.worker.join().unwrap();
        Ok(())
    }
}
