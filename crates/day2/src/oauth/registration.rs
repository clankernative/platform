//! Live reviewed-provider registration qualification. Desired metadata is portable; only
//! this native wire campaign can issue the non-serializable readiness receipt.
//! Roc owns probe order. Every native step is one-shot, bounded and redacted.

use super::{admission, approval_keys, catalog, profiles};
use crate::oauth::effects::{self, Client, Instant, Response};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    BindingRef, Digest, Name, SecretProvider,
    oauth::{
        ConnectionRequirement, ConnectionSlotKey, OutboundConnectionBinding, ProviderCallbackRef,
    },
};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::Read,
    path::Path,
    sync::{Arc, RwLock},
    time::Duration,
};
use url::Url;

const MAX_RESPONSE: usize = 32 * 1024;
const VALID_SECONDS: i64 = 300;

/// Closed operator diagnostics, never provider bodies or an arbitrary error chain.
/// These facts explain a refusal; they cannot establish registration readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::oauth) enum QualificationStage {
    Setup,
    Callback,
    CredentialLoad,
    RejectPkce,
    VerifyPkce,
    RejectCredential,
    Exchange,
    Account,
    Refresh,
    RefreshedAccount,
    CredentialRecheck,
    Workflow,
    Selection,
    ShellReadiness,
    Publication,
    Receipt,
}

impl QualificationStage {
    pub(in crate::oauth) fn code(self) -> &'static str {
        match self {
            Self::Setup => "campaign_setup",
            Self::Callback => "callback_validation",
            Self::CredentialLoad => "client_credential_load",
            Self::RejectPkce => "reject_incorrect_pkce",
            Self::VerifyPkce => "verify_correct_pkce",
            Self::RejectCredential => "reject_missing_client_credential",
            Self::Exchange => "authorization_code_exchange",
            Self::Account => "account_identity",
            Self::Refresh => "token_refresh",
            Self::RefreshedAccount => "refreshed_account_identity",
            Self::CredentialRecheck => "client_credential_recheck",
            Self::Workflow => "native_workflow",
            Self::Selection => "current_selection",
            Self::ShellReadiness => "shell_readiness",
            Self::Publication => "owning_app_publication",
            Self::Receipt => "registration_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObservationFailure {
    Refused,
    Network,
    Response,
    ProviderStatus(u16, ProviderDenial),
    Contract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderDenial {
    InvalidGrant,
    InvalidClient,
    InvalidRequest,
    UnauthorizedClient,
    InvalidScope,
    AccessDenied,
    AdminPolicy,
    Other,
}

impl ProviderDenial {
    fn from_code(code: &str) -> Self {
        match code {
            "invalid_grant" => Self::InvalidGrant,
            "invalid_client" => Self::InvalidClient,
            "invalid_request" => Self::InvalidRequest,
            "unauthorized_client" => Self::UnauthorizedClient,
            "invalid_scope" => Self::InvalidScope,
            "access_denied" => Self::AccessDenied,
            "admin_policy_enforced" => Self::AdminPolicy,
            _ => Self::Other,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidClient => "invalid_client",
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::AdminPolicy => "admin_policy_enforced",
            Self::Other => "other",
        }
    }
}

impl ObservationFailure {
    fn provider(response: Response) -> Self {
        let status = response.status().as_u16();
        #[derive(Deserialize)]
        struct DenialCode {
            error: String,
        }
        let denial = if status >= 400 {
            bounded_body(response)
                .ok()
                .and_then(|bytes| crate::json::decode::<DenialCode>(&bytes).ok())
                .map(|denial| ProviderDenial::from_code(&denial.error))
                .unwrap_or(ProviderDenial::Other)
        } else {
            ProviderDenial::Other
        };
        Self::ProviderStatus(status, denial)
    }
}

impl std::fmt::Display for ObservationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused => formatter.write_str("refused"),
            Self::Network => formatter.write_str("network_unavailable"),
            Self::Response => formatter.write_str("invalid_provider_response"),
            Self::ProviderStatus(status, denial) => {
                write!(formatter, "provider_http_{status}_{}", denial.code())
            }
            Self::Contract => formatter.write_str("provider_contract_mismatch"),
        }
    }
}

impl std::error::Error for ObservationFailure {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::oauth) struct QualificationFailure {
    stage: QualificationStage,
    observation: ObservationFailure,
}

impl QualificationFailure {
    pub(in crate::oauth) fn at(stage: QualificationStage, error: anyhow::Error) -> anyhow::Error {
        if let Some(failure) = error.downcast_ref::<Self>() {
            return (*failure).into();
        }
        Self {
            stage,
            observation: error
                .downcast_ref::<ObservationFailure>()
                .copied()
                .unwrap_or(ObservationFailure::Refused),
        }
        .into()
    }

    pub(in crate::oauth) fn stage(&self) -> &'static str {
        self.stage.code()
    }

    pub(in crate::oauth) fn outcome(&self) -> String {
        self.observation.to_string()
    }
}

impl std::fmt::Display for QualificationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "OAuth qualification failed at {}: {}",
            self.stage(),
            self.observation
        )
    }
}

impl std::error::Error for QualificationFailure {}

/// Public metadata for one exact registration canary. It cannot assert that a
/// redirect is registered or that any key, shell, account mapping or host is ready.
#[derive(Clone)]
pub(crate) struct Target {
    instance: BindingRef,
    namespace: String,
    shell: profiles::SecurityShellEvidence,
    permission: day2_capabilities::oauth::ProviderPermissionContract,
    reviewed: profiles::ReviewedBrowserCodeProfile,
    adapter: catalog::Adapter,
    registration: Name,
    callback: ProviderCallbackRef,
    callback_url: String,
    client_id: String,
    secret: approval_keys::GcpSecretVersion,
    credential: BindingRef,
    canary_subject: String,
    canary_tenant: String,
    qualification_subject: String,
    logical_id: String,
}

pub(crate) struct ClientSelection {
    pub registration: Name,
    pub client: day2_capabilities::oauth::ProviderClient,
    pub secret: SecretProvider,
    pub canary: day2_capabilities::oauth::RegistrationCanary,
}

impl Target {
    #[cfg(test)]
    pub(in crate::oauth) fn reviewed(&self) -> &profiles::ReviewedBrowserCodeProfile {
        &self.reviewed
    }

    pub(super) fn publication_matches(&self, registration: &Name, namespace: &str) -> bool {
        self.registration == *registration && self.namespace == namespace
    }

    pub(super) fn setup_description(&self) -> Result<serde_json::Value> {
        let mut description = self.description();
        description["registration_selection"] =
            serde_json::to_value(self.registration_evidence()?.registration)?;
        description["credential_version"] = serde_json::to_value(&self.secret)?;
        Ok(description)
    }

    pub(crate) fn new(
        requirement: &ConnectionRequirement,
        profile: &BindingRef,
        instance: BindingRef,
        namespace: String,
        shell: profiles::SecurityShellEvidence,
        selected: ClientSelection,
    ) -> Result<Self> {
        let (reviewed, permission) = catalog::reviewed()?.resolve(requirement, profile)?;
        let adapter = catalog::Adapter::selected(&reviewed)?;
        adapter.validate_client(&selected.client)?;
        ensure!(
            instance == shell.instance
                && shell.origin.0.revision
                    == Digest::of(&(
                        "oauth-security-shell-evidence-v1",
                        &shell.instance,
                        &shell.origin_url,
                        &shell.qualification,
                    ))?,
            "Provider registration shell selection mismatch"
        );
        ensure!(
            !namespace.is_empty()
                && namespace.len() <= 256
                && namespace.bytes().all(|byte| byte.is_ascii_graphic()),
            "invalid provider binding namespace"
        );
        subject(&selected.canary.provider_subject)?;
        let human = selected
            .canary
            .qualification_subject
            .strip_prefix("accounts.google.com:");
        ensure!(
            human.is_some_and(|s| subject(s).is_ok()),
            "invalid qualification human"
        );
        ensure!(
            crate::artifact::dns_name(&selected.canary.provider_tenant)
                && selected.canary.provider_tenant
                    == selected.canary.provider_tenant.to_ascii_lowercase(),
            "invalid provider canary tenant"
        );
        adapter.validate_canary(&selected.canary)?;
        let callback = ProviderCallbackRef::derive(&shell.origin, &permission.profile, &namespace)?;
        let callback_url = profiles::derived_callback_url(&shell.origin_url, &callback)?;
        let SecretProvider::GcpVersion {
            project_number,
            secret,
            version,
        } = selected.secret;
        let secret = approval_keys::GcpSecretVersion {
            project_number: project_number.get(),
            secret: secret.as_str().into(),
            version: version.get(),
        };
        secret.validate()?;
        let credential =
            super::clients::provider_credential_reference(&instance, &selected.client, &secret)?;
        let client_id = selected.client.client_id().to_owned();
        Ok(Self {
            instance,
            namespace,
            shell,
            permission,
            reviewed,
            adapter,
            registration: selected.registration,
            callback,
            callback_url,
            client_id,
            secret,
            credential,
            canary_subject: selected.canary.provider_subject,
            canary_tenant: selected.canary.provider_tenant,
            qualification_subject: selected.canary.qualification_subject,
            logical_id: requirement.logical_id.clone(),
        })
    }

    /// Setup output contains no secret or readiness claim. The native shell
    /// uses this exact callback, never the separate reauthentication callback.
    pub(crate) fn description(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "registration":self.registration, "profile":self.permission.profile,
            "client_id":self.client_id, "client_credential":self.credential,
            "callback_url":self.callback_url, "scopes":self.scopes(),
            "registration_class":"confidential_pkce_s256",
        });
        self.adapter.describe(&mut value);
        value
    }

    fn scopes(&self) -> std::collections::BTreeSet<String> {
        self.permission
            .action_scopes
            .values()
            .flatten()
            .cloned()
            .collect()
    }

    pub(super) fn registration_evidence(&self) -> Result<profiles::ProviderRegistrationEvidence> {
        // Stable across renewed probes; clock and secret/token bytes never
        // participate. A receipt is still issuable only after the live campaign.
        let confirmation = Digest::of(&(
            "oauth-google-registration-canary-v1",
            &self.instance,
            &self.namespace,
            &self.permission,
            &self.reviewed.adapter,
            &self.reviewed.simulator,
            &self.reviewed.conformance,
            &self.shell,
            &self.callback,
            &self.callback_url,
            &self.client_id,
            &self.credential,
            &self.canary_subject,
            &self.canary_tenant,
        ))?;
        // Preserve historical Google evidence pins when its selected human is
        // the same canary. Other selections bind both independently named IDs.
        let confirmation = if self.adapter == catalog::Adapter::GoogleCalendar
            && self.qualification_subject == format!("accounts.google.com:{}", self.canary_subject)
        {
            confirmation
        } else {
            Digest::of(&(
                "oauth-provider-registration-canary-v2",
                confirmation,
                &self.qualification_subject,
            ))?
        };
        let revision = Digest::of(&(
            "oauth-provider-registration-evidence-v1",
            &self.instance,
            &self.permission.profile,
            &self.reviewed.issuer,
            &self.shell.origin,
            &self.callback,
            &self.callback_url,
            &confirmation,
            &self.credential,
            profiles::ClientRegistrationClass::ConfidentialPkceS256,
        ))?;
        Ok(profiles::ProviderRegistrationEvidence {
            instance: self.instance.clone(),
            registration: BindingRef {
                id: self.registration.clone(),
                revision,
            },
            profile: self.permission.profile.clone(),
            issuer: self.reviewed.issuer.clone(),
            security_origin: self.shell.origin.clone(),
            callback: self.callback.clone(),
            callback_url: self.callback_url.clone(),
            provider_confirmation: confirmation,
            client_credential: self.credential.clone(),
            class: profiles::ClientRegistrationClass::ConfidentialPkceS256,
        })
    }
}

#[path = "qualification_shell.rs"]
pub(super) mod shell;

fn subject(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 255
            && value.bytes().all(|byte| byte.is_ascii_graphic()),
        "invalid provider account subject"
    );
    Ok(())
}

/// Neither Clone, Debug, Serialize nor Deserialize. Native callback handling
/// supplies this one-use material after its own state/session/PKCE checks.
pub(crate) struct Code {
    code: String,
    verifier: String,
    target: Digest,
    purpose: Purpose,
    session: Digest,
    deadline: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    Positive,
    RejectPkce,
    RejectCredential,
}

/// A separate one-use, session-bound authorization for each canary obligation.
/// Host routing supplies the already verified shell/session identity; neither
/// workflow JSON nor a pasted code can create a Code value.
pub(crate) struct Authorization {
    state: String,
    verifier: String,
    target: Digest,
    purpose: Purpose,
    session: Digest,
    started: Instant,
    issuer: String,
    adapter: catalog::Adapter,
}

impl Authorization {
    pub(crate) fn begin(
        target: &Target,
        purpose: Purpose,
        session: Digest,
    ) -> Result<(Self, String)> {
        let state = effects::random()?;
        let verifier = effects::random()?;
        let mut authorization = Url::parse(&target.reviewed.authorization_endpoint)?;
        authorization.query_pairs_mut().extend_pairs([
            ("client_id", target.client_id.as_str()),
            ("redirect_uri", target.callback_url.as_str()),
            ("response_type", "code"),
            (
                "scope",
                &target.scopes().into_iter().collect::<Vec<_>>().join(" "),
            ),
            ("state", &state),
            (
                "code_challenge",
                &super::custody::pkce_challenge(&verifier)?,
            ),
            ("code_challenge_method", "S256"),
        ]);
        authorization
            .query_pairs_mut()
            .extend_pairs(target.adapter.authorization_extras().iter().copied());
        Ok((
            Self {
                state,
                verifier,
                target: Digest::of(&target.setup_description()?)?,
                purpose,
                session,
                started: Instant::now(),
                issuer: target.reviewed.issuer_url.clone(),
                adapter: target.adapter,
            },
            authorization.into(),
        ))
    }

    pub(crate) fn complete(self, query: &[u8], session: &Digest) -> Result<Code> {
        ensure!(
            &self.session == session
                && self.started.elapsed() < Duration::from_secs(VALID_SECONDS as u64),
            "Provider canary session expired or changed"
        );
        let parsed = super::protocol::parse_callback(
            query,
            &super::protocol::CallbackParameters {
                require_issuer: false,
                allowed_extras: self.adapter.callback_extras(),
            },
        )?;
        let super::protocol::ParsedCallback::Code {
            code,
            state,
            issuer,
        } = parsed
        else {
            anyhow::bail!("Provider canary authorization denied");
        };
        ensure!(
            state.as_str() == self.state
                && issuer.as_deref().is_none_or(|value| value == self.issuer),
            "Provider canary callback binding mismatch"
        );
        Ok(Code {
            code: code.as_str().into(),
            verifier: self.verifier,
            target: self.target,
            purpose: self.purpose,
            session: self.session,
            deadline: self.started + Duration::from_secs(VALID_SECONDS as u64),
        })
    }
}

pub(crate) struct Codes {
    pub positive: Code,
    pub reject_pkce: Code,
    pub reject_credential: Code,
}

use super::catalog::Tokens;

pub(super) struct Wire {
    client: Client,
    token: Url,
    userinfo: Url,
    adapter: catalog::Adapter,
}

impl Wire {
    fn new(target: &Target) -> Result<Self> {
        let userinfo = target.adapter.userinfo();
        Self::at(
            Url::parse(&target.reviewed.token_endpoint)?,
            Url::parse(userinfo)?,
            target.adapter,
        )
    }

    fn at(token: Url, userinfo: Url, adapter: catalog::Adapter) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(8))
                .build()?,
            token,
            userinfo,
            adapter,
        })
    }

    fn token(&self, form: &[(&str, &str)], target: &Target, refresh: bool) -> Result<Tokens> {
        ensure!(
            self.adapter == target.adapter,
            "OAuth wire profile mismatch"
        );
        let response = self
            .client
            .post(self.token.clone())
            .form(form)
            .send()
            .map_err(|_| ObservationFailure::Network)?;
        self.adapter
            .tokens(
                &body(response)?,
                catalog::TokenContext {
                    reviewed: &target.reviewed,
                    permission: &target.permission,
                    client_id: &target.client_id,
                    subject: &target.canary_subject,
                },
                refresh,
                self,
            )
            .map_err(|error| {
                if error.downcast_ref::<ObservationFailure>().is_some() {
                    error
                } else {
                    ObservationFailure::Contract.into()
                }
            })
    }

    pub(super) fn token_info(&self, access: &str) -> Result<Vec<u8>> {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {access}"))?;
        authorization.set_sensitive(true);
        let info = self
            .client
            .get(self.adapter.token_info(&self.token)?)
            .header(AUTHORIZATION, authorization)
            .send()
            .map_err(|_| ObservationFailure::Network)?;
        body(info)
    }

    fn reject(&self, form: &[(&str, &str)], purpose: Purpose) -> Result<()> {
        let response = self
            .client
            .post(self.token.clone())
            .form(form)
            .send()
            .map_err(|_| ObservationFailure::Network)?;
        let allowed_status = match purpose {
            Purpose::RejectPkce => response.status().as_u16() == 400,
            Purpose::RejectCredential => matches!(response.status().as_u16(), 400 | 401),
            Purpose::Positive => false,
        };
        if !allowed_status {
            return Err(ObservationFailure::provider(response).into());
        }
        let status = response.status().as_u16();
        let raw = bounded_body(response).map_err(|_| ObservationFailure::Response)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Denial {
            error: String,
            #[serde(rename = "error_description")]
            description: Option<String>,
            #[serde(rename = "error_uri")]
            _uri: Option<String>,
        }
        let denial: Denial = crate::json::decode(&raw).map_err(|_| ObservationFailure::Response)?;
        let classified = match purpose {
            Purpose::RejectPkce => denial.error == "invalid_grant",
            Purpose::RejectCredential => {
                matches!(denial.error.as_str(), "invalid_client" | "unauthorized_client")
                    // Google's confidential web client rejects an omitted
                    // secret with this specific invalid_request response.
                    // Other invalid requests do not prove client authentication.
                    || (self.adapter == catalog::Adapter::GoogleCalendar
                        && status == 400
                        && denial.error == "invalid_request"
                        && denial.description.as_deref() == Some("client_secret is missing."))
            }
            Purpose::Positive => false,
        };
        if !classified {
            return Err(ObservationFailure::ProviderStatus(
                status,
                ProviderDenial::from_code(&denial.error),
            )
            .into());
        }
        Ok(())
    }

    fn account(&self, access: &str, target: &Target) -> Result<()> {
        ensure!(
            self.adapter == target.adapter,
            "OAuth wire profile mismatch"
        );
        let mut authorization = HeaderValue::from_str(&format!("Bearer {access}"))?;
        authorization.set_sensitive(true);
        let response = self
            .client
            .get(self.userinfo.clone())
            .header(AUTHORIZATION, authorization)
            .send()
            .map_err(|_| ObservationFailure::Network)?;
        self.adapter
            .account(
                &body(response)?,
                &target.canary_subject,
                &target.canary_tenant,
            )
            .map_err(|_| ObservationFailure::Contract.into())
    }

    #[cfg(test)]
    fn fixture(origin: &str, adapter: catalog::Adapter) -> Result<Self> {
        let origin = Url::parse(origin)?;
        ensure!(
            origin.scheme() == "http"
                && matches!(origin.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.path() == "/",
            "invalid provider wire fixture"
        );
        Self::at(origin.join("token")?, origin.join("userinfo")?, adapter)
    }
}

fn body(response: Response) -> Result<Vec<u8>> {
    if response.status().as_u16() != 200 {
        return Err(ObservationFailure::provider(response).into());
    }
    bounded_body(response).map_err(|_| ObservationFailure::Response.into())
}

fn bounded_body(response: Response) -> Result<Vec<u8>> {
    ensure!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(';').next() == Some("application/json")),
        "invalid provider response content type"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= MAX_RESPONSE as u64),
        "Provider response too large"
    );
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("Provider response unavailable; do not retry"))?;
    ensure!(bytes.len() <= MAX_RESPONSE, "Provider response too large");
    Ok(bytes)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Open,
    RejectPkce,
    VerifyPkce,
    RejectCredential,
    Exchange,
    Account,
    Refresh,
    RefreshedAccount,
    Seal,
    Complete,
    Failed,
}

impl Step {
    fn diagnostic(self) -> QualificationStage {
        match self {
            Self::Open => QualificationStage::CredentialLoad,
            Self::RejectPkce => QualificationStage::RejectPkce,
            Self::VerifyPkce => QualificationStage::VerifyPkce,
            Self::RejectCredential => QualificationStage::RejectCredential,
            Self::Exchange => QualificationStage::Exchange,
            Self::Account => QualificationStage::Account,
            Self::Refresh => QualificationStage::Refresh,
            Self::RefreshedAccount => QualificationStage::RefreshedAccount,
            Self::Seal => QualificationStage::CredentialRecheck,
            Self::Complete | Self::Failed => QualificationStage::Workflow,
        }
    }
}

pub(crate) struct Session {
    target: Target,
    wire: Wire,
    reader: approval_keys::GcpSecretReader,
    codes: Option<Codes>,
    secret: Option<String>,
    tokens: Option<Tokens>,
    started: Instant,
    step: Step,
    receipt: Option<Receipt>,
}

impl Session {
    pub(crate) fn new(
        target: Target,
        codes: Codes,
        tokens: Arc<dyn approval_keys::AccessTokenSource>,
    ) -> Result<Self> {
        let wire = Wire::new(&target)?;
        Self::at(
            target,
            codes,
            wire,
            approval_keys::GcpSecretReader::new(tokens)?,
        )
    }

    fn at(
        target: Target,
        codes: Codes,
        wire: Wire,
        reader: approval_keys::GcpSecretReader,
    ) -> Result<Self> {
        ensure!(
            wire.adapter == target.adapter,
            "OAuth wire profile mismatch"
        );
        let identity = Digest::of(&target.setup_description()?)?;
        for (code, purpose) in [
            (&codes.positive, Purpose::Positive),
            (&codes.reject_pkce, Purpose::RejectPkce),
            (&codes.reject_credential, Purpose::RejectCredential),
        ] {
            ensure!(
                !code.code.is_empty()
                    && code.code.len() <= 2048
                    && code.code.bytes().all(|byte| byte.is_ascii_graphic())
                    && code.target == identity
                    && code.purpose == purpose
                    && code.session == codes.positive.session
                    && Instant::now() < code.deadline,
                "invalid provider canary code binding"
            );
            super::custody::pkce_challenge(&code.verifier)?;
        }
        ensure!(
            codes.positive.code != codes.reject_pkce.code
                && codes.positive.code != codes.reject_credential.code
                && codes.reject_pkce.code != codes.reject_credential.code,
            "Provider canaries must use distinct one-time codes"
        );
        Ok(Self {
            target,
            wire,
            reader,
            codes: Some(codes),
            secret: None,
            tokens: None,
            started: Instant::now(),
            step: Step::Open,
            receipt: None,
        })
    }

    /// Native errors contain no wire bodies, account values or credential bytes.
    /// A failed step permanently closes this session, including unsent fences.
    pub(crate) fn call(
        &mut self,
        request: crate::automation::Request,
    ) -> Result<serde_json::Value> {
        let stage = self.step.diagnostic();
        let result = self.step(request);
        if result.is_err() {
            self.step = Step::Failed;
            self.codes = None;
            self.secret = None;
            self.tokens = None;
            self.receipt = None;
        }
        result.map_err(|error| QualificationFailure::at(stage, error))
    }

    fn step(&mut self, request: crate::automation::Request) -> Result<serde_json::Value> {
        ensure!(
            request.decode::<serde_json::Value>()? == serde_json::json!({}),
            "Provider probe does not accept workflow-selected arguments"
        );
        ensure!(
            self.started.elapsed() < Duration::from_secs(VALID_SECONDS as u64),
            "Provider probe expired"
        );
        let expected = match request.action.as_str() {
            "oauth-registration-open" => Step::Open,
            "oauth-registration-reject-pkce" => Step::RejectPkce,
            "oauth-registration-verify-pkce" => Step::VerifyPkce,
            "oauth-registration-reject-credential" => Step::RejectCredential,
            "oauth-registration-exchange" => Step::Exchange,
            "oauth-registration-account" => Step::Account,
            "oauth-registration-refresh" => Step::Refresh,
            "oauth-registration-refresh-account" => Step::RefreshedAccount,
            "oauth-registration-seal" => Step::Seal,
            _ => anyhow::bail!("unknown provider probe operation"),
        };
        ensure!(
            self.step == expected,
            "Provider probe order or replay refused"
        );
        self.step = Step::Failed; // fence before credential/network operations
        match expected {
            Step::Open => {
                let raw = self.reader.load(&self.target.secret)?;
                let secret = super::clients::credential(raw)?;
                self.secret = Some(secret);
                self.step = Step::RejectPkce;
            }
            Step::RejectPkce | Step::RejectCredential => {
                let codes = self
                    .codes
                    .as_ref()
                    .context("Provider canary codes missing")?;
                let (code, purpose) = if expected == Step::RejectPkce {
                    (&codes.reject_pkce, Purpose::RejectPkce)
                } else {
                    (&codes.reject_credential, Purpose::RejectCredential)
                };
                let mut wrong_verifier = code.verifier.clone();
                wrong_verifier.replace_range(
                    ..1,
                    if wrong_verifier.starts_with('A') {
                        "B"
                    } else {
                        "A"
                    },
                );
                let mut form = vec![
                    ("grant_type", "authorization_code"),
                    ("code", &code.code),
                    ("client_id", &self.target.client_id),
                    ("redirect_uri", &self.target.callback_url),
                    (
                        "code_verifier",
                        if purpose == Purpose::RejectPkce {
                            &wrong_verifier
                        } else {
                            &code.verifier
                        },
                    ),
                ];
                if purpose == Purpose::RejectPkce {
                    form.push((
                        "client_secret",
                        self.secret
                            .as_deref()
                            .context("Provider credential missing")?,
                    ));
                }
                self.wire.reject(&form, purpose)?;
                self.step = if expected == Step::RejectPkce {
                    Step::VerifyPkce
                } else {
                    Step::Exchange
                };
            }
            Step::VerifyPkce => {
                // A generic invalid_grant could mean an invalid/expired code.
                // Prove the very same code succeeds when only its verifier is
                // corrected. A provider that consumes rejected codes cannot
                // pass this conservative campaign. This is an explicit canary
                // obligation, never an automatic product exchange retry.
                let code = &self
                    .codes
                    .as_ref()
                    .context("Provider canary codes missing")?
                    .reject_pkce;
                self.wire.token(
                    &[
                        ("grant_type", "authorization_code"),
                        ("code", &code.code),
                        ("client_id", &self.target.client_id),
                        (
                            "client_secret",
                            self.secret
                                .as_deref()
                                .context("Provider credential missing")?,
                        ),
                        ("redirect_uri", &self.target.callback_url),
                        ("code_verifier", &code.verifier),
                    ],
                    &self.target,
                    false,
                )?;
                self.step = Step::RejectCredential;
            }
            Step::Exchange => {
                let code = self.codes.take().context("Provider code missing")?.positive;
                self.tokens = Some(
                    self.wire.token(
                        &[
                            ("grant_type", "authorization_code"),
                            ("code", &code.code),
                            ("client_id", &self.target.client_id),
                            (
                                "client_secret",
                                self.secret
                                    .as_deref()
                                    .context("Provider credential missing")?,
                            ),
                            ("redirect_uri", &self.target.callback_url),
                            ("code_verifier", &code.verifier),
                        ],
                        &self.target,
                        false,
                    )?,
                );
                self.step = Step::Account;
            }
            Step::Account => {
                self.wire.account(
                    &self
                        .tokens
                        .as_ref()
                        .context("Provider tokens missing")?
                        .access,
                    &self.target,
                )?;
                self.step = Step::Refresh;
            }
            Step::Refresh => {
                let tokens = self.tokens.take().context("Provider tokens missing")?;
                let refresh = tokens.refresh.context("Provider refresh missing")?;
                let mut replacement = self.wire.token(
                    &[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", &refresh),
                        ("client_id", &self.target.client_id),
                        ("redirect_uri", &self.target.callback_url),
                        (
                            "client_secret",
                            self.secret
                                .as_deref()
                                .context("Provider credential missing")?,
                        ),
                    ],
                    &self.target,
                    true,
                )?;
                match &self.target.reviewed.protocol {
                    profiles::ConfidentialPkceProfile::Reusable { .. } => {
                        ensure!(
                            replacement
                                .refresh
                                .as_ref()
                                .is_none_or(|value| value == &refresh),
                            "reusable refresh unexpectedly rotated"
                        );
                        replacement.refresh = Some(refresh);
                    }
                    profiles::ConfidentialPkceProfile::Rotating { .. } => {
                        ensure!(
                            replacement
                                .refresh
                                .as_ref()
                                .is_some_and(|value| value != &refresh)
                                && replacement.access != tokens.access,
                            "rotating refresh did not replace its token pair"
                        );
                    }
                    profiles::ConfidentialPkceProfile::NoRefresh(_) => {
                        anyhow::bail!("refresh campaign requires a refresh profile")
                    }
                }
                self.tokens = Some(replacement);
                self.step = Step::RefreshedAccount;
            }
            Step::RefreshedAccount => {
                self.wire.account(
                    &self
                        .tokens
                        .as_ref()
                        .context("Provider tokens missing")?
                        .access,
                    &self.target,
                )?;
                self.step = Step::Seal;
            }
            Step::Seal => {
                // Check the selected version again after the wire campaign. A
                // disabled, deleted, replaced or inaccessible secret cannot seal.
                let raw = self.reader.load(&self.target.secret)?;
                ensure!(
                    Some(raw.as_slice()) == self.secret.as_ref().map(|value| value.as_bytes()),
                    "Provider client credential changed"
                );
                let checked_at = effects::wall_time()?;
                self.receipt = Some(Receipt {
                    registration: self.target.registration_evidence()?,
                    target: self.target_identity()?,
                    checked_at,
                    deadline: Instant::now() + Duration::from_secs(VALID_SECONDS as u64),
                });
                self.secret = None;
                self.tokens = None;
                self.step = Step::Complete;
            }
            _ => unreachable!(),
        }
        Ok(serde_json::json!({}))
    }

    fn target_identity(&self) -> Result<TargetIdentity> {
        Ok(TargetIdentity {
            instance: self.target.instance.clone(),
            namespace: self.target.namespace.clone(),
            shell: self.target.shell.clone(),
            requirement: self.target.permission.requirement.clone(),
            logical_id: self.target.logical_id.clone(),
        })
    }

    pub(crate) fn finish(mut self) -> Result<Receipt> {
        ensure!(self.step == Step::Complete, "Provider canary incomplete");
        self.receipt
            .take()
            .context("Provider qualification receipt missing")
    }

    pub(crate) fn run(mut self, runner: &Path) -> Result<Receipt> {
        let runner = crate::automation::checked_runner(runner)
            .map_err(|error| QualificationFailure::at(QualificationStage::Workflow, error))?;
        // The Roc transport carries text, not native error types. Keep only the
        // closed diagnostic locally so that workflow failure cannot erase it.
        let mut failure = None;
        let result = crate::automation::run(&runner, &["oauth-registration"], |request| {
            let result = self.call(request);
            if failure.is_none()
                && let Err(error) = &result
            {
                failure = error.downcast_ref::<QualificationFailure>().copied();
            }
            result
        });
        result.map_err(|error| match failure {
            Some(failure) => failure.into(),
            None => QualificationFailure::at(QualificationStage::Workflow, error),
        })?;
        self.finish()
            .map_err(|error| QualificationFailure::at(QualificationStage::Receipt, error))
    }
}

struct TargetIdentity {
    instance: BindingRef,
    namespace: String,
    shell: profiles::SecurityShellEvidence,
    requirement: Digest,
    logical_id: String,
}

/// No serialization or public constructor: a desired JSON revision, restored
/// database or simulator transcript cannot produce live registration readiness.
pub(crate) struct Receipt {
    registration: profiles::ProviderRegistrationEvidence,
    target: TargetIdentity,
    checked_at: i64,
    deadline: Instant,
}

impl Receipt {
    pub(crate) fn registration(&self) -> &profiles::ProviderRegistrationEvidence {
        &self.registration
    }

    pub(in crate::oauth) fn fresh(&self, now: i64) -> bool {
        now >= self.checked_at
            && now - self.checked_at < VALID_SECONDS
            && Instant::now() < self.deadline
    }
}

/// Registration readiness augments, never replaces, the independent live
/// shell, custody and account-mapping source. Every host starts with no receipts.
pub(crate) struct ProviderReadiness {
    facts: Arc<dyn admission::OutboundReadiness>,
    receipts: RwLock<BTreeMap<String, Receipt>>,
}

impl ProviderReadiness {
    pub(crate) fn new(facts: Arc<dyn admission::OutboundReadiness>) -> Self {
        Self {
            facts,
            receipts: RwLock::new(BTreeMap::new()),
        }
    }

    pub(crate) fn publish(&self, receipt: Receipt) -> Result<()> {
        let mut receipts = self
            .receipts
            .write()
            .map_err(|_| anyhow::anyhow!("Provider readiness lock poisoned"))?;
        let id = receipt.registration.registration.id.as_str().to_owned();
        ensure!(
            receipts.contains_key(&id) || receipts.len() < 128,
            "Provider readiness budget"
        );
        // Republishing the same wire proof cannot reset its monotonic lease.
        // A newly completed campaign has a later source qualification time.
        if let Some(previous) = receipts.get_mut(&id)
            && previous.registration == receipt.registration
            && previous.checked_at >= receipt.checked_at
        {
            if previous.checked_at == receipt.checked_at {
                ensure!(
                    previous.deadline.partial_cmp(&receipt.deadline).is_some(),
                    "OAuth receipt clock domain mismatch"
                );
                if receipt.deadline < previous.deadline {
                    previous.deadline = receipt.deadline;
                }
            }
            return Ok(());
        }
        receipts.insert(id, receipt);
        Ok(())
    }

    pub(crate) fn retire(&self, registration: &Name) -> Result<()> {
        self.receipts
            .write()
            .map_err(|_| anyhow::anyhow!("Provider readiness lock poisoned"))?
            .remove(registration.as_str());
        Ok(())
    }
}

#[path = "registration_publication.rs"]
pub(super) mod publication;

impl admission::OutboundReadiness for ProviderReadiness {
    fn selected_runtime(&self) -> Result<Option<Digest>> {
        self.facts.selected_runtime()
    }

    fn observe_identity(&self, identity: &crate::iap::Verified, now: i64) -> Result<()> {
        self.facts.observe_identity(identity, now)
    }

    fn current(
        &self,
        binding: &OutboundConnectionBinding,
        slot: &ConnectionSlotKey,
        now: i64,
    ) -> Result<Option<profiles::OutboundInstanceEvidence>> {
        let receipts = self
            .receipts
            .read()
            .map_err(|_| anyhow::anyhow!("Provider readiness lock poisoned"))?;
        let Some(receipt) = receipts.get(binding.registration.id.as_str()) else {
            return Ok(None);
        };
        if !receipt.fresh(now)
            || receipt.registration.registration != binding.registration
            || receipt.registration.profile != binding.profile
            || receipt.target.requirement != binding.requirement
            || receipt.registration.security_origin != binding.security_shell
            || slot.installation != binding.namespace.installation
            || slot.environment != binding.namespace.environment
            || slot.app != binding.namespace.app
            || slot.requirement != receipt.target.logical_id
            || !matches!(&slot.owner, day2_capabilities::oauth::SlotOwner::Human { subject } if !subject.is_empty())
            || admission::binding_namespace(binding)? != receipt.target.namespace
        {
            return Ok(None);
        }
        let Some(evidence) = self.facts.current(binding, slot, now)? else {
            return Ok(None);
        };
        if !receipt.fresh(now) {
            return Ok(None);
        }
        ensure!(
            evidence.registration == receipt.registration
                && evidence.instance == receipt.target.instance
                && evidence.binding_namespace == receipt.target.namespace
                && evidence.shell == receipt.target.shell,
            "Provider registration readiness evidence mismatch"
        );
        Ok(Some(evidence))
    }
}

#[cfg(test)]
#[path = "registration_tests.rs"]
pub(super) mod tests;
