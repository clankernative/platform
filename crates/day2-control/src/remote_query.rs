//! Loopback qualification adapter for authenticated separate-host queries.
//!
//! Production exposure still requires the platform issuer/IAP gates and a
//! provider-backed serving probe. No app-selected endpoint or unsigned identity
//! reaches this port. The loopback transport lets two independent hosts exercise
//! the same signed receiver boundary without claiming cloud qualification.

use crate::{
    journal::Journal,
    release::ReleaseTarget,
    release_execution::{ObservedServingBinding, ServingProbe},
};
use anyhow::{Result, ensure};
use day2::{
    delegation::{AppCallPort, Call},
    delegation_wire::{Query, Scope, Signer, Verifier},
    store::Runtime,
};
use reqwest::{blocking::Client, redirect::Policy};
use serde_json::Value;
use std::{
    io::Read,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

const MAX_RESULT_BYTES: u64 = 65_536;

fn scope(target: &ReleaseTarget) -> Scope {
    Scope {
        installation: target.company.as_str().to_owned(),
        environment: target.environment.as_str().to_owned(),
        app: target.app.as_str().to_owned(),
    }
}

fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

/// A fixed, loopback-only transport fixture. The endpoint is selected by the
/// host, never by the app, and redirects are always refused.
pub struct RemoteQueryPort {
    journal: PathBuf,
    probe: Arc<dyn ServingProbe + Send + Sync>,
    source: ReleaseTarget,
    target: ReleaseTarget,
    endpoint: Url,
    signer: Signer,
    client: Client,
}

impl RemoteQueryPort {
    pub fn loopback_fixture(
        journal: PathBuf,
        probe: Arc<dyn ServingProbe + Send + Sync>,
        source: ReleaseTarget,
        target: ReleaseTarget,
        endpoint: &str,
        signer: Signer,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint)?;
        ensure!(
            endpoint.scheme() == "http"
                && matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost"))
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && endpoint.path() == "/_platform/app-query",
            "invalid_app_call_fixture_endpoint"
        );
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            journal,
            probe,
            source,
            target,
            endpoint,
            signer,
            client,
        })
    }
}

impl AppCallPort for RemoteQueryPort {
    fn query(&self, caller: &Runtime, call: &Call) -> Result<String> {
        ensure!(
            Scope::from_runtime(caller)? == scope(&self.source)
                && call.caller == self.source.app.as_str()
                && call.app == self.target.app.as_str()
                && self.source.company == self.target.company
                && self.source.environment == self.target.environment,
            "app_call_scope_changed"
        );
        day2::delegation::verify_origin(caller, call)?;
        let input: Value = serde_json::from_str(&call.input)?;
        let journal = Journal::open(&self.journal)?;
        journal.with_serving_selection(&self.target, self.probe.as_ref(), |selection| {
            let issued_at = now()?;
            let request = Query {
                version: 1,
                source: scope(&self.source),
                target: scope(&self.target),
                operation: call.operation.clone(),
                schema_digest: call.schema_digest.clone(),
                contract_digest: call.contract_digest.clone(),
                input,
                actor: call.actor.clone(),
                origin: call.origin.clone(),
                step: call.step.clone(),
                chain: call.chain.clone(),
                now: call.now,
                issued_at,
                expires_at: issued_at + 30,
                activation: selection.activation.clone(),
                generation: selection.generation,
                serving: serde_json::to_value(&selection.binding)?,
            };
            let wire = self.signer.sign(&request)?;
            let response = self
                .client
                .post(self.endpoint.clone())
                .header("Content-Type", "application/vnd.day2.app-query+json")
                .body(wire)
                .send()?;
            ensure!(response.status().is_success(), "remote_app_query_refused");
            let mut body = Vec::new();
            response.take(MAX_RESULT_BYTES + 1).read_to_end(&mut body)?;
            ensure!(
                body.len() as u64 <= MAX_RESULT_BYTES,
                "app_call_result_too_large"
            );
            let result: Value = serde_json::from_slice(&body)?;
            Ok(serde_json::to_string(&result)?)
        })
    }
}

/// The receiver's host-owned boundary. Its caller must pass the raw wire bytes;
/// neither a claimed caller nor actor is accepted separately from the proof.
pub struct RemoteQueryReceiver {
    journal: PathBuf,
    probe: Arc<dyn ServingProbe + Send + Sync>,
    target: ReleaseTarget,
    runtime: Runtime,
    verifier: Verifier,
}

impl RemoteQueryReceiver {
    pub fn new(
        journal: PathBuf,
        probe: Arc<dyn ServingProbe + Send + Sync>,
        target: ReleaseTarget,
        runtime: Runtime,
        verifier: Verifier,
    ) -> Result<Self> {
        ensure!(
            Scope::from_runtime(&runtime)? == scope(&target),
            "app_call_receiver_scope_changed"
        );
        Ok(Self {
            journal,
            probe,
            target,
            runtime,
            verifier,
        })
    }

    pub fn handle(&self, wire: &[u8], at: i64) -> Result<String> {
        let verified = self.verifier.verify(wire, at)?;
        ensure!(
            verified.query().target == scope(&self.target),
            "app_call_wrong_audience"
        );
        let claimed: ObservedServingBinding =
            serde_json::from_value(verified.query().serving.clone())?;
        let journal = Journal::open(&self.journal)?;
        journal.with_serving_selection(&self.target, self.probe.as_ref(), |selection| {
            ensure!(
                claimed == selection.binding
                    && verified.query().activation == selection.activation
                    && verified.query().generation == selection.generation,
                "app_call_serving_binding_changed"
            );
            ensure!(
                selection.binding.artifact.as_str() == self.runtime.artifact().id(),
                "app_call_receiver_artifact_changed"
            );
            day2::delegation::receive_verified(&self.runtime, &verified)
        })
    }
}
