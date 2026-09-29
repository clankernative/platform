//! Loopback qualification adapter for authenticated separate-host queries.
//!
//! The fixture exercises issuer and target IAP checks with signed assertions.
//! Production exposure still requires independently deployed gates, per-request
//! workload tokens, managed keys and a provider-backed serving probe. No
//! app-selected endpoint or unsigned identity reaches this port.

use crate::{
    journal::Journal,
    release::ReleaseTarget,
    release_execution::{ObservedServingBinding, ServingProbe},
};
use anyhow::{Result, ensure};
use day2::{
    delegation::{self, AppCallPort, Call},
    delegation_wire::{
        IssuerClaims, IssuerSigner, IssuerVerifier, Query, Scope, Signer, Verifier, issued_query,
    },
    iap,
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
    auth: RemoteQueryAuth,
    client: Client,
}

/// Fixture credentials stand in for the two IAP deliveries. Production tokens
/// must be acquired per request by the platform-managed workload.
pub struct RemoteQueryAuth {
    pub workload_signer: Signer,
    pub issuer: Arc<RemoteQueryIssuer>,
    pub issuer_assertion: String,
    pub target_assertion: String,
}

/// Issuance is a separate host boundary with its own key and IAP audience. It
/// reopens current invocation evidence instead of trusting caller-supplied actor
/// claims, and checks the exact workload-signed request it cosigns.
pub struct RemoteQueryIssuer {
    source: ReleaseTarget,
    target: ReleaseTarget,
    workload_email: String,
    issuer_audience: String,
    iap: iap::Verifier,
    workload_verifier: Verifier,
    signer: IssuerSigner,
}

impl RemoteQueryIssuer {
    pub fn new(
        source: ReleaseTarget,
        target: ReleaseTarget,
        workload_email: &str,
        issuer_audience: &str,
        iap: iap::Verifier,
        workload_verifier: Verifier,
        signer: IssuerSigner,
    ) -> Result<Self> {
        ensure!(
            source.company == target.company
                && source.environment == target.environment
                && source.app != target.app
                && workload_email.ends_with(".gserviceaccount.com")
                && !issuer_audience.is_empty(),
            "invalid_app_issuer_binding"
        );
        Ok(Self {
            source,
            target,
            workload_email: workload_email.to_ascii_lowercase(),
            issuer_audience: issuer_audience.to_owned(),
            iap,
            workload_verifier,
            signer,
        })
    }

    pub fn issue(
        &self,
        caller: &Runtime,
        call: &Call,
        query: &Query,
        workload_wire: &[u8],
        assertion: &str,
        at: i64,
    ) -> Result<Vec<u8>> {
        let workload = self.iap.verify_workload(assertion, at)?;
        ensure!(
            workload.email() == self.workload_email && workload.audience() == self.issuer_audience,
            "app_issuer_workload_changed"
        );
        let signed = self.workload_verifier.verify(workload_wire, at)?;
        ensure!(
            signed.query() == query
                && query.source == scope(&self.source)
                && query.source == Scope::from_runtime(caller)?
                && query.target == scope(&self.target)
                && call.caller == self.source.app.as_str()
                && call.app == self.target.app.as_str()
                && query.operation == call.operation
                && query.schema_digest == call.schema_digest
                && query.contract_digest == call.contract_digest
                && query.input == serde_json::from_str::<Value>(&call.input)?
                && query.actor == call.actor
                && query.origin == call.origin
                && query.step == call.step
                && query.chain == call.chain
                && query.now == call.now,
            "app_issuer_query_changed"
        );
        let origin = delegation::verify_origin(caller, call)?;
        self.signer.sign(&IssuerClaims {
            version: 1,
            issuer: self.signer.issuer().to_owned(),
            key_id: self.signer.key_id().to_owned(),
            source: query.source.clone(),
            target: query.target.clone(),
            root: origin.root,
            principal: origin.principal,
            subject_digest: day2::digest(origin.subject.as_bytes()),
            workload_email: workload.email().to_owned(),
            workload_subject_digest: day2::digest(workload.subject().as_bytes()),
            actor: query.actor.clone(),
            origin: query.origin.clone(),
            query_digest: day2::digest(workload_wire),
            issued_at: at,
            expires_at: query.expires_at,
        })
    }
}

impl RemoteQueryPort {
    pub fn loopback_fixture(
        journal: PathBuf,
        probe: Arc<dyn ServingProbe + Send + Sync>,
        source: ReleaseTarget,
        target: ReleaseTarget,
        endpoint: &str,
        auth: RemoteQueryAuth,
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
            auth,
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
            let workload = self.auth.workload_signer.sign(&request)?;
            let issuer = self.auth.issuer.issue(
                caller,
                call,
                &request,
                &workload,
                &self.auth.issuer_assertion,
                issued_at,
            )?;
            let wire = issued_query(&workload, &issuer)?;
            let response = self
                .client
                .post(self.endpoint.clone())
                .header("Content-Type", "application/vnd.day2.app-query+json")
                .header(iap::ASSERTION_HEADER, &self.auth.target_assertion)
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
    issuer_verifier: IssuerVerifier,
    target_iap: iap::Verifier,
}

impl RemoteQueryReceiver {
    pub fn new(
        journal: PathBuf,
        probe: Arc<dyn ServingProbe + Send + Sync>,
        target: ReleaseTarget,
        runtime: Runtime,
        verifier: Verifier,
        issuer_verifier: IssuerVerifier,
        target_iap: iap::Verifier,
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
            issuer_verifier,
            target_iap,
        })
    }

    pub fn handle(&self, wire: &[u8], assertion: &str, at: i64) -> Result<String> {
        let workload = self.target_iap.verify_workload(assertion, at)?;
        let verified = self
            .issuer_verifier
            .verify(wire, at, &workload, &self.verifier)?;
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
