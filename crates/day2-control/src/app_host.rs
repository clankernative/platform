//! Bootstrap the normal app host with its private, operator-owned call adapters.
//! Company policy stays in the instance and activated authority. This file only
//! binds admitted peers, transport audiences, provider observations and host keys.

use crate::{
    iap_service_jwt::{GkeMetadataAccessTokens, IapServiceJwt},
    kubernetes_conformance::{GkeServingBinding, GkeServingProbe},
    release::ReleaseTarget,
    release_execution::ServingProbe,
    remote_query::{RemoteQueryIssuer, RemoteQueryPort, RemoteQueryReceiver},
    secrets::AccessTokenProvider,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2::{
    delegation::{AppCallPort, Call},
    delegation_wire::{IssuerSigner, IssuerVerifier, Scope, Signer, TrustedKey, Verifier},
    iap,
    store::Runtime,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFile {
    pub id: String,
    pub path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerKey {
    pub issuer: String,
    pub key: KeyFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outgoing {
    pub issuer_url: String,
    pub receiver_url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Incoming {
    pub workload_email: String,
    pub workload_keys: BTreeMap<String, String>,
    pub issuer: String,
    pub issuer_keys: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub version: u32,
    pub own: ReleaseTarget,
    pub serving_snapshot: PathBuf,
    pub workload_email: String,
    pub workload_key: KeyFile,
    pub issuer_key: IssuerKey,
    pub issuer_audience: String,
    pub receiver_audience: String,
    pub serving: BTreeMap<String, GkeServingBinding>,
    pub outgoing: BTreeMap<String, Outgoing>,
    pub incoming: BTreeMap<String, Incoming>,
}

fn scope(target: &ReleaseTarget) -> Scope {
    Scope {
        installation: target.company.as_str().into(),
        environment: target.environment.as_str().into(),
        app: target.app.as_str().into(),
    }
}

fn bounded_file(path: &Path, maximum: u64, private: bool) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum,
        "invalid_app_host_file"
    );
    if private {
        ensure!(
            metadata.mode() & 0o077 == 0 && metadata.mode() & 0o222 == 0,
            "app_signing_key_not_protected"
        );
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "app_host_file_budget");
    Ok(bytes)
}

fn keys(values: &BTreeMap<String, String>) -> Result<BTreeMap<String, Vec<u8>>> {
    ensure!(
        !values.is_empty() && values.len() <= 8,
        "app_host_key_budget"
    );
    values
        .iter()
        .map(|(id, value)| Ok((id.clone(), URL_SAFE_NO_PAD.decode(value)?)))
        .collect()
}

pub struct HostAppCalls {
    own: ReleaseTarget,
    outgoing: BTreeMap<String, Arc<RemoteQueryPort>>,
    issuers: BTreeMap<String, Arc<RemoteQueryIssuer>>,
    incoming: BTreeMap<String, Arc<RemoteQueryReceiver>>,
}

impl HostAppCalls {
    /// Also used by native HTTP conformance with explicit test adapters. Product
    /// code cannot construct or select a port; the runtime owns this boundary.
    pub fn new(
        own: ReleaseTarget,
        outgoing: BTreeMap<String, Arc<RemoteQueryPort>>,
        issuers: BTreeMap<String, Arc<RemoteQueryIssuer>>,
        incoming: BTreeMap<String, Arc<RemoteQueryReceiver>>,
    ) -> Result<Self> {
        ensure!(
            outgoing.len() <= 32 && issuers.len() <= 32 && incoming.len() <= 32,
            "app_host_peer_budget"
        );
        Ok(Self {
            own,
            outgoing,
            issuers,
            incoming,
        })
    }
}

impl AppCallPort for HostAppCalls {
    fn query(&self, runtime: &Runtime, call: &Call) -> Result<String> {
        ensure!(
            Scope::from_runtime(runtime)? == scope(&self.own),
            "app_host_scope_changed"
        );
        self.outgoing
            .get(&call.app)
            .context("app_call_target_unbound")?
            .query(runtime, call)
    }

    fn receive(
        &self,
        runtime: &Runtime,
        path: &str,
        wire: &[u8],
        assertion: &str,
        at: i64,
    ) -> Result<Vec<u8>> {
        ensure!(
            Scope::from_runtime(runtime)? == scope(&self.own),
            "app_host_scope_changed"
        );
        match path {
            "/_platform/app-issue" => {
                let target = RemoteQueryIssuer::request_target(wire)?;
                self.issuers
                    .get(&target.app)
                    .context("app_issuer_target_unbound")?
                    .handle(runtime, wire, assertion, at)
            }
            "/_platform/app-query" => {
                let source = day2::delegation_wire::claimed_source(wire)?;
                let receiver = self
                    .incoming
                    .get(&source.app)
                    .context("app_call_workload_unbound")?;
                Ok(receiver
                    .handle_for(runtime, wire, assertion, at)?
                    .into_bytes())
            }
            _ => anyhow::bail!("app_call_route_unknown"),
        }
    }
}

pub fn configure(runtime: Runtime, path: &Path) -> Result<Runtime> {
    let config: Configuration = day2::json::decode(&bounded_file(path, 1_048_576, false)?)?;
    ensure!(
        config.version == 1 && Scope::from_runtime(&runtime)? == scope(&config.own),
        "app_host_configuration_scope_changed"
    );
    let human = day2::artifact::Instance::load(runtime.instance_path())?
        .edge(runtime.app())?
        .1
        .iap_audience
        .clone();
    ensure!(
        config.issuer_audience != config.receiver_audience
            && config.issuer_audience != human
            && config.receiver_audience != human,
        "app_host_iap_gates_not_distinct"
    );
    ensure!(
        config.serving.contains_key(runtime.app())
            && config.outgoing.len() <= 32
            && config.incoming.len() <= 32,
        "app_host_peer_budget"
    );
    for binding in config.serving.values() {
        ensure!(
            binding.target.company == config.own.company
                && binding.target.environment == config.own.environment,
            "app_host_peer_scope_changed"
        );
    }
    ensure!(
        config.serving[runtime.app()].workload_email == config.workload_email,
        "app_host_workload_identity_changed"
    );
    let tokens: Arc<dyn AccessTokenProvider> = Arc::new(GkeMetadataAccessTokens::new()?);
    let probe: Arc<dyn ServingProbe + Send + Sync> = Arc::new(GkeServingProbe::new(
        config.serving.clone(),
        tokens.clone(),
    )?);
    let workload_bytes = bounded_file(&config.workload_key.path, 8192, true)?;
    let issuer_bytes = bounded_file(&config.issuer_key.key.path, 8192, true)?;
    let own_key = Signer::from_pkcs8(&config.workload_key.id, &workload_bytes)?.public_key();
    ensure!(
        own_key
            != IssuerSigner::from_pkcs8(
                &config.issuer_key.issuer,
                &config.issuer_key.key.id,
                &issuer_bytes
            )?
            .public_key(),
        "app_host_signing_keys_not_distinct"
    );
    let mut outgoing = BTreeMap::new();
    let mut issuers = BTreeMap::new();
    for (app, peer) in &config.outgoing {
        let target = &config
            .serving
            .get(app)
            .context("app_host_peer_unbound")?
            .target;
        let credentials = Arc::new(IapServiceJwt::new(
            &config.workload_email,
            &peer.issuer_url,
            &peer.receiver_url,
            tokens.clone(),
        )?);
        let verifier = Verifier::new(BTreeMap::from([(
            config.workload_key.id.clone(),
            TrustedKey {
                source: scope(&config.own),
                public_key: own_key.clone(),
            },
        )]))?;
        issuers.insert(
            app.clone(),
            Arc::new(RemoteQueryIssuer::new(
                config.own.clone(),
                target.clone(),
                &config.workload_email,
                &config.issuer_audience,
                iap::Verifier::for_workload(
                    &config.issuer_audience,
                    &config.workload_email,
                    Box::new(iap::GoogleKeys),
                )?,
                verifier,
                IssuerSigner::from_pkcs8(
                    &config.issuer_key.issuer,
                    &config.issuer_key.key.id,
                    &issuer_bytes,
                )?,
            )?),
        );
        outgoing.insert(
            app.clone(),
            Arc::new(RemoteQueryPort::iap_http(
                config.serving_snapshot.clone(),
                probe.clone(),
                config.own.clone(),
                target.clone(),
                Signer::from_pkcs8(&config.workload_key.id, &workload_bytes)?,
                credentials,
            )?),
        );
    }
    let mut incoming = BTreeMap::new();
    for (app, peer) in &config.incoming {
        let source = &config
            .serving
            .get(app)
            .context("app_host_peer_unbound")?
            .target;
        ensure!(
            config.serving[app].workload_email == peer.workload_email && app != runtime.app(),
            "app_host_peer_identity_changed"
        );
        let verifier = Verifier::new(
            keys(&peer.workload_keys)?
                .into_iter()
                .map(|(id, public_key)| {
                    (
                        id,
                        TrustedKey {
                            source: scope(source),
                            public_key,
                        },
                    )
                })
                .collect(),
        )?;
        incoming.insert(
            app.clone(),
            Arc::new(RemoteQueryReceiver::new(
                config.serving_snapshot.clone(),
                probe.clone(),
                config.own.clone(),
                runtime.clone(),
                verifier,
                IssuerVerifier::new(
                    &peer.issuer,
                    keys(&peer.issuer_keys)?,
                    &config.receiver_audience,
                )?,
                iap::Verifier::for_workload(
                    &config.receiver_audience,
                    &peer.workload_email,
                    Box::new(iap::GoogleKeys),
                )?,
            )?),
        );
    }
    Ok(runtime.with_app_call_port(Arc::new(HostAppCalls::new(
        config.own, outgoing, issuers, incoming,
    )?)))
}
