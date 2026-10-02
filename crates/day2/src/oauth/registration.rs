//! Live Google registration qualification. Desired metadata is portable; only
//! this native wire campaign can issue the non-serializable readiness receipt.
//! Roc owns probe order. Every native step is one-shot, bounded and redacted.

use super::{admission, approval_keys, google, profiles};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    BindingRef, Digest, Name, SecretProvider,
    oauth::{
        ConnectionRequirement, ConnectionSlotKey, OutboundConnectionBinding, ProviderCallbackRef,
    },
};
use reqwest::{
    blocking::{Client, Response},
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::Read,
    path::Path,
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;

const MAX_RESPONSE: usize = 32 * 1024;
const VALID_SECONDS: i64 = 300;

/// Public metadata for one exact registration canary. It cannot assert that a
/// redirect is registered or that any key, shell, account mapping or host is ready.
#[derive(Clone)]
pub(crate) struct Target {
    instance: BindingRef,
    namespace: String,
    shell: profiles::SecurityShellEvidence,
    permission: day2_capabilities::oauth::ProviderPermissionContract,
    reviewed: profiles::ReviewedBrowserCodeProfile,
    registration: Name,
    callback: ProviderCallbackRef,
    callback_url: String,
    client_id: String,
    secret: approval_keys::GcpSecretVersion,
    credential: BindingRef,
    canary_subject: String,
    canary_tenant: String,
    logical_id: String,
}

pub(crate) struct ClientSelection {
    pub registration: Name,
    pub client_id: String,
    pub secret: SecretProvider,
    /// Exact Google subject, not email, of the explicitly selected canary user.
    pub canary_subject: String,
    pub canary_tenant: String,
}

impl Target {
    pub(super) fn setup_description(&self) -> Result<serde_json::Value> {
        let mut description = self.description();
        description["registration_selection"] =
            serde_json::to_value(self.registration_evidence()?.registration)?;
        description["credential_version"] = serde_json::to_value(&self.secret)?;
        Ok(description)
    }

    pub(crate) fn new(
        requirement: &ConnectionRequirement,
        instance: BindingRef,
        namespace: String,
        shell: profiles::SecurityShellEvidence,
        selected: ClientSelection,
    ) -> Result<Self> {
        let profile = google::reviewed(&requirement.account_policy)?.profile;
        let (reviewed, permission) =
            google::catalog()?.resolve(requirement, &profile.protocol.identity().binding)?;
        ensure!(
            instance == shell.instance
                && shell.origin.0.revision
                    == Digest::of(&(
                        "oauth-security-shell-evidence-v1",
                        &shell.instance,
                        &shell.origin_url,
                        &shell.qualification,
                    ))?,
            "Google registration shell selection mismatch"
        );
        ensure!(
            !namespace.is_empty()
                && namespace.len() <= 256
                && namespace.bytes().all(|byte| byte.is_ascii_graphic()),
            "invalid Google binding namespace"
        );
        client_id(&selected.client_id)?;
        subject(&selected.canary_subject)?;
        ensure!(
            crate::artifact::dns_name(&selected.canary_tenant)
                && selected.canary_tenant == selected.canary_tenant.to_ascii_lowercase(),
            "invalid Google canary tenant"
        );
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
            super::clients::credential_reference(&instance, &selected.client_id, &secret)?;
        Ok(Self {
            instance,
            namespace,
            shell,
            permission,
            reviewed,
            registration: selected.registration,
            callback,
            callback_url,
            client_id: selected.client_id,
            secret,
            credential,
            canary_subject: selected.canary_subject,
            canary_tenant: selected.canary_tenant,
            logical_id: requirement.logical_id.clone(),
        })
    }

    /// Setup output contains no secret or readiness claim. The native shell
    /// uses this exact callback, never the separate reauthentication callback.
    pub(crate) fn description(&self) -> serde_json::Value {
        serde_json::json!({
            "registration":self.registration, "profile":self.permission.profile,
            "client_id":self.client_id, "client_credential":self.credential,
            "callback_url":self.callback_url, "scopes":self.scopes(),
            "registration_class":"confidential_pkce_s256", "access_type":"offline",
            "include_granted_scopes":false, "prompt":"consent select_account",
        })
    }

    fn scopes(&self) -> std::collections::BTreeSet<String> {
        self.permission
            .action_scopes
            .values()
            .flatten()
            .cloned()
            .collect()
    }

    fn registration_evidence(&self) -> Result<profiles::ProviderRegistrationEvidence> {
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

fn client_id(value: &str) -> Result<()> {
    let local = value
        .strip_suffix(".apps.googleusercontent.com")
        .context("invalid Google web client")?;
    ensure!(
        value.len() <= 255
            && !local.is_empty()
            && local
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "invalid Google web client"
    );
    Ok(())
}

#[path = "qualification_shell.rs"]
pub(super) mod shell;

fn subject(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 255
            && value.bytes().all(|byte| byte.is_ascii_graphic()),
        "invalid Google account subject"
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
}

impl Authorization {
    pub(crate) fn begin(
        target: &Target,
        purpose: Purpose,
        session: Digest,
    ) -> Result<(Self, String)> {
        let state = crate::web_security::random()?;
        let verifier = crate::web_security::random()?;
        let mut authorization = Url::parse(google::AUTHORIZATION)?;
        authorization.query_pairs_mut().extend_pairs([
            ("client_id", target.client_id.as_str()),
            ("redirect_uri", target.callback_url.as_str()),
            ("response_type", "code"),
            (
                "scope",
                &target.scopes().into_iter().collect::<Vec<_>>().join(" "),
            ),
            ("access_type", "offline"),
            ("include_granted_scopes", "false"),
            ("prompt", "consent select_account"),
            ("state", &state),
            (
                "code_challenge",
                &super::custody::pkce_challenge(&verifier)?,
            ),
            ("code_challenge_method", "S256"),
        ]);
        Ok((
            Self {
                state,
                verifier,
                target: Digest::of(&target.description())?,
                purpose,
                session,
                started: Instant::now(),
            },
            authorization.into(),
        ))
    }

    pub(crate) fn complete(self, query: &[u8], session: &Digest) -> Result<Code> {
        ensure!(
            &self.session == session
                && self.started.elapsed() < Duration::from_secs(VALID_SECONDS as u64),
            "Google canary session expired or changed"
        );
        let parsed = super::protocol::parse_callback(
            query,
            &super::protocol::CallbackParameters {
                require_issuer: false,
                allowed_extras: std::collections::BTreeSet::from([
                    "scope".into(),
                    "authuser".into(),
                    "prompt".into(),
                    "hd".into(),
                ]),
            },
        )?;
        let super::protocol::ParsedCallback::Code {
            code,
            state,
            issuer,
        } = parsed
        else {
            anyhow::bail!("Google canary authorization denied");
        };
        ensure!(
            state.as_str() == self.state
                && issuer
                    .as_deref()
                    .is_none_or(|value| value == google::ISSUER),
            "Google canary callback binding mismatch"
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

struct Tokens {
    access: String,
    refresh: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleTokens {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_in: u64,
    scope: String,
    // Google returns this for the reviewed identity scopes. Account evidence
    // comes from the fixed TLS UserInfo endpoint using the same access token.
    id_token: Option<String>,
    refresh_token_expires_in: Option<u64>,
}

#[derive(Serialize)]
struct NormalizedTokens<'a> {
    access_token: &'a str,
    refresh_token: Option<&'a str>,
    token_type: &'a str,
    expires_in: u64,
    scope: String,
}

#[derive(Deserialize)]
struct UserInfo {
    sub: String,
    email: String,
    email_verified: bool,
    hd: String,
}

struct Wire {
    client: Client,
    token: Url,
    userinfo: Url,
}

impl Wire {
    fn new() -> Result<Self> {
        Self::at(Url::parse(google::TOKEN)?, Url::parse(google::USERINFO)?)
    }

    fn at(token: Url, userinfo: Url) -> Result<Self> {
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
        })
    }

    fn token(&self, form: &[(&str, &str)], target: &Target, refresh: bool) -> Result<Tokens> {
        let response = self
            .client
            .post(self.token.clone())
            .form(form)
            .send()
            .map_err(|_| anyhow::anyhow!("Google token observation unavailable; do not retry"))?;
        let raw: GoogleTokens = crate::json::decode(&body(response)?)
            .map_err(|_| anyhow::anyhow!("invalid Google token response"))?;
        if let Some(id_token) = &raw.id_token {
            ensure!(
                !id_token.is_empty()
                    && id_token.len() <= 16_384
                    && id_token.bytes().all(|byte| byte.is_ascii_graphic()),
                "invalid Google identity token material"
            );
        }
        ensure!(
            raw.refresh_token_expires_in
                .is_none_or(|seconds| seconds > 0),
            "invalid Google refresh lifetime"
        );
        let normalized = serde_json::to_vec(&NormalizedTokens {
            access_token: &raw.access_token,
            refresh_token: if refresh {
                None
            } else {
                raw.refresh_token.as_deref()
            },
            token_type: &raw.token_type,
            expires_in: raw.expires_in,
            scope: google::normalize_scope(&raw.scope)?,
        })?;
        let protocol = if refresh {
            profiles::ConfidentialPkceProfile::NoRefresh(
                target.reviewed.protocol.identity().clone(),
            )
        } else {
            target.reviewed.protocol.clone()
        };
        protocol.validate_token_response(&normalized, &target.permission)?;
        ensure!(
            raw.access_token.bytes().all(|byte| byte.is_ascii_graphic())
                && raw
                    .refresh_token
                    .as_ref()
                    .is_none_or(|token| !token.is_empty()
                        && token.len() <= 8192
                        && token.bytes().all(|byte| byte.is_ascii_graphic())),
            "invalid Google token material"
        );
        Ok(Tokens {
            access: raw.access_token,
            refresh: raw.refresh_token,
        })
    }

    fn reject(&self, form: &[(&str, &str)], purpose: Purpose) -> Result<()> {
        let response = self
            .client
            .post(self.token.clone())
            .form(form)
            .send()
            .map_err(|_| anyhow::anyhow!("Google negative canary unavailable; do not retry"))?;
        let allowed_status = match purpose {
            Purpose::RejectPkce => response.status().as_u16() == 400,
            Purpose::RejectCredential => matches!(response.status().as_u16(), 400 | 401),
            Purpose::Positive => false,
        };
        ensure!(
            allowed_status,
            "Google accepted or failed to classify a negative canary"
        );
        let raw = bounded_body(response)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Denial {
            error: String,
            #[serde(rename = "error_description")]
            _description: Option<String>,
            #[serde(rename = "error_uri")]
            _uri: Option<String>,
        }
        let denial: Denial = crate::json::decode(&raw)
            .map_err(|_| anyhow::anyhow!("invalid Google negative canary"))?;
        ensure!(
            match purpose {
                Purpose::RejectPkce => denial.error == "invalid_grant",
                Purpose::RejectCredential => matches!(
                    denial.error.as_str(),
                    "invalid_client" | "unauthorized_client"
                ),
                Purpose::Positive => false,
            },
            "Google negative canary did not establish the required obligation"
        );
        Ok(())
    }

    fn account(&self, access: &str, target: &Target) -> Result<()> {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {access}"))?;
        authorization.set_sensitive(true);
        let response = self
            .client
            .get(self.userinfo.clone())
            .header(AUTHORIZATION, authorization)
            .send()
            .map_err(|_| anyhow::anyhow!("Google account observation unavailable"))?;
        let account: UserInfo = crate::json::decode(&body(response)?)
            .map_err(|_| anyhow::anyhow!("invalid Google account response"))?;
        subject(&account.sub)?;
        ensure!(
            account.sub == target.canary_subject
                && account.hd == target.canary_tenant
                && account.email_verified
                && !account.email.is_empty()
                && account.email.len() <= 320
                && account.email.bytes().all(|byte| byte.is_ascii_graphic())
                && account.email.contains('@'),
            "Google canary account mismatch"
        );
        Ok(())
    }

    #[cfg(test)]
    fn fixture(origin: &str) -> Result<Self> {
        let origin = Url::parse(origin)?;
        ensure!(
            origin.scheme() == "http"
                && matches!(origin.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.path() == "/",
            "invalid Google wire fixture"
        );
        Self::at(origin.join("token")?, origin.join("userinfo")?)
    }
}

fn body(response: Response) -> Result<Vec<u8>> {
    ensure!(
        response.status().as_u16() == 200,
        "Google qualification rejected; do not retry"
    );
    bounded_body(response)
}

fn bounded_body(response: Response) -> Result<Vec<u8>> {
    ensure!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(';').next() == Some("application/json")),
        "invalid Google response content type"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= MAX_RESPONSE as u64),
        "Google response too large"
    );
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("Google response unavailable; do not retry"))?;
    ensure!(bytes.len() <= MAX_RESPONSE, "Google response too large");
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
        Self::at(
            target,
            codes,
            Wire::new()?,
            approval_keys::GcpSecretReader::new(tokens)?,
        )
    }

    fn at(
        target: Target,
        codes: Codes,
        wire: Wire,
        reader: approval_keys::GcpSecretReader,
    ) -> Result<Self> {
        let identity = Digest::of(&target.description())?;
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
                "invalid Google canary code binding"
            );
            super::custody::pkce_challenge(&code.verifier)?;
        }
        ensure!(
            codes.positive.code != codes.reject_pkce.code
                && codes.positive.code != codes.reject_credential.code
                && codes.reject_pkce.code != codes.reject_credential.code,
            "Google canaries must use distinct one-time codes"
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
        let result = self.step(request);
        if result.is_err() {
            self.step = Step::Failed;
            self.codes = None;
            self.secret = None;
            self.tokens = None;
            self.receipt = None;
        }
        result.map_err(|_| {
            anyhow::anyhow!("Google registration qualification failed; start a new canary")
        })
    }

    fn step(&mut self, request: crate::automation::Request) -> Result<serde_json::Value> {
        ensure!(
            request.decode::<serde_json::Value>()? == serde_json::json!({}),
            "Google probe does not accept workflow-selected arguments"
        );
        ensure!(
            self.started.elapsed() < Duration::from_secs(VALID_SECONDS as u64),
            "Google probe expired"
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
            _ => anyhow::bail!("unknown Google probe operation"),
        };
        ensure!(
            self.step == expected,
            "Google probe order or replay refused"
        );
        self.step = Step::Failed; // fence before credential/network operations
        match expected {
            Step::Open => {
                let raw = self.reader.load(&self.target.secret)?;
                let secret = String::from_utf8(raw)
                    .map_err(|_| anyhow::anyhow!("invalid Google client secret"))?;
                ensure!(
                    !secret.is_empty()
                        && secret.len() <= 2048
                        && secret.bytes().all(|byte| byte.is_ascii_graphic()),
                    "invalid Google client secret"
                );
                self.secret = Some(secret);
                self.step = Step::RejectPkce;
            }
            Step::RejectPkce | Step::RejectCredential => {
                let codes = self.codes.as_ref().context("Google canary codes missing")?;
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
                            .context("Google credential missing")?,
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
                    .context("Google canary codes missing")?
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
                                .context("Google credential missing")?,
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
                let code = self.codes.take().context("Google code missing")?.positive;
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
                                    .context("Google credential missing")?,
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
                        .context("Google tokens missing")?
                        .access,
                    &self.target,
                )?;
                self.step = Step::Refresh;
            }
            Step::Refresh => {
                let tokens = self.tokens.take().context("Google tokens missing")?;
                let refresh = tokens.refresh.context("Google refresh missing")?;
                let mut replacement = self.wire.token(
                    &[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", &refresh),
                        ("client_id", &self.target.client_id),
                        (
                            "client_secret",
                            self.secret
                                .as_deref()
                                .context("Google credential missing")?,
                        ),
                    ],
                    &self.target,
                    true,
                )?;
                ensure!(
                    replacement
                        .refresh
                        .as_ref()
                        .is_none_or(|value| value == &refresh),
                    "Google reusable refresh unexpectedly rotated"
                );
                replacement.refresh = Some(refresh);
                self.tokens = Some(replacement);
                self.step = Step::RefreshedAccount;
            }
            Step::RefreshedAccount => {
                self.wire.account(
                    &self
                        .tokens
                        .as_ref()
                        .context("Google tokens missing")?
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
                    "Google client credential changed"
                );
                let checked_at =
                    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
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
        ensure!(self.step == Step::Complete, "Google canary incomplete");
        self.receipt
            .take()
            .context("Google qualification receipt missing")
    }

    pub(crate) fn run(mut self, runner: &Path) -> Result<Receipt> {
        let runner = crate::automation::checked_runner(runner)?;
        crate::automation::run(&runner, &["oauth-registration"], |request| {
            self.call(request)
        })?;
        self.finish()
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

    fn fresh(&self, now: i64) -> bool {
        now >= self.checked_at
            && now - self.checked_at < VALID_SECONDS
            && Instant::now() < self.deadline
    }
}

/// Registration readiness augments, never replaces, the independent live
/// shell, custody and account-mapping source. Every host starts with no receipts.
pub(crate) struct GoogleReadiness {
    facts: Arc<dyn admission::OutboundReadiness>,
    receipts: RwLock<BTreeMap<String, Receipt>>,
}

impl GoogleReadiness {
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
            .map_err(|_| anyhow::anyhow!("Google readiness lock poisoned"))?;
        let id = receipt.registration.registration.id.as_str().to_owned();
        ensure!(
            receipts.contains_key(&id) || receipts.len() < 128,
            "Google readiness budget"
        );
        receipts.insert(id, receipt);
        Ok(())
    }

    pub(crate) fn retire(&self, registration: &Name) -> Result<()> {
        self.receipts
            .write()
            .map_err(|_| anyhow::anyhow!("Google readiness lock poisoned"))?
            .remove(registration.as_str());
        Ok(())
    }
}

impl admission::OutboundReadiness for GoogleReadiness {
    fn current(
        &self,
        binding: &OutboundConnectionBinding,
        slot: &ConnectionSlotKey,
        now: i64,
    ) -> Result<Option<profiles::OutboundInstanceEvidence>> {
        let receipts = self
            .receipts
            .read()
            .map_err(|_| anyhow::anyhow!("Google readiness lock poisoned"))?;
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
        ensure!(
            evidence.registration == receipt.registration
                && evidence.instance == receipt.target.instance
                && evidence.binding_namespace == receipt.target.namespace
                && evidence.shell == receipt.target.shell,
            "Google registration readiness evidence mismatch"
        );
        Ok(Some(evidence))
    }
}

#[cfg(test)]
#[path = "registration_tests.rs"]
pub(super) mod tests;
