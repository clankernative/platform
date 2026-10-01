//! Closed confidential-client PKCE browser-code exchange contracts. Only reviewed adapters may supply
//! these host values; instance registration and external readiness are separate
//! admission evidence, not inferred from a successfully parsed response.

use anyhow::{Result, ensure};
use day2_capabilities::oauth::{
    AccountBindingPolicy, ConnectionRequirement, ProductReturnRef, ProviderCallbackRef,
    ProviderIssuerRef, ProviderPermissionContract, SecurityOriginRef,
};
use day2_capabilities::{BindingRef, Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_TOKEN_RESPONSE_BYTES: usize = 32 * 1024;
const MAX_TOKEN_BYTES: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserCodeIdentity {
    pub binding: BindingRef,
    pub scope_interpretation: Digest,
}

/// No refresh, reusable refresh and rotating refresh have different required
/// recovery evidence. Unsupported combinations have no variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfidentialPkceProfile {
    NoRefresh(BrowserCodeIdentity),
    Reusable {
        identity: BrowserCodeIdentity,
        retry: ReusableRetry,
    },
    Rotating {
        identity: BrowserCodeIdentity,
        recovery: RotatingRecovery,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ReusableRetry {
    NoAutomaticRetry,
    QualifiedBoundedRetry { evidence: Digest },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum RotatingRecovery {
    ReauthorizeOnUncertainty,
    QualifiedReconciliation { evidence: Digest },
}

impl ConfidentialPkceProfile {
    pub(super) fn identity(&self) -> &BrowserCodeIdentity {
        match self {
            Self::NoRefresh(identity)
            | Self::Reusable { identity, .. }
            | Self::Rotating { identity, .. } => identity,
        }
    }

    /// A token response is usable only under the same reviewed profile and
    /// semantic scope interpretation that produced the consent contract.
    pub fn validate_token_response(
        &self,
        raw: &[u8],
        permission: &ProviderPermissionContract,
    ) -> Result<ValidatedTokenResponse> {
        ensure!(
            self.identity().binding == permission.profile
                && self.identity().scope_interpretation == permission.interpretation,
            "token response profile does not match consent"
        );
        ensure!(
            !raw.is_empty() && raw.len() <= MAX_TOKEN_RESPONSE_BYTES,
            "invalid provider token response size"
        );
        let parsed: TokenResponse = serde_json::from_slice(raw)
            .map_err(|_| anyhow::anyhow!("invalid provider token response"))?;
        ensure!(
            parsed.token_type == "Bearer" && (1..=86_400 * 366).contains(&parsed.expires_in),
            "unsupported provider token response"
        );
        secret(&parsed.access_token)?;
        if let Some(refresh) = &parsed.refresh_token {
            secret(refresh)?;
        }
        ensure!(
            matches!(
                (self, parsed.refresh_token.as_ref()),
                (Self::NoRefresh(_), None)
                    | (Self::Reusable { .. }, Some(_))
                    | (Self::Rotating { .. }, Some(_))
            ),
            "refresh response violates reviewed profile"
        );
        let scopes = parse_scopes(&parsed.scope)?;
        let required = permission
            .action_scopes
            .values()
            .flat_map(|scopes| scopes.iter().cloned())
            .collect::<BTreeSet<_>>();
        ensure!(
            !required.is_empty() && scopes == required,
            "provider returned missing or unreviewed scopes"
        );
        Ok(ValidatedTokenResponse {
            access_token: parsed.access_token,
            refresh_token: parsed.refresh_token,
            expires_in: parsed.expires_in,
            scopes,
            profile: permission.profile.clone(),
            interpretation: permission.interpretation.clone(),
        })
    }
}

/// This reviewed host profile pins the provider addresses and account-evidence
/// contract as well as the wire implementation. A caller must obtain it from
/// the reviewed profile catalog, not from app or provider callback input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedBrowserCodeProfile {
    pub protocol: ConfidentialPkceProfile,
    pub issuer: ProviderIssuerRef,
    pub issuer_url: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub adapter: BindingRef,
    pub simulator: BindingRef,
    pub conformance: BindingRef,
    pub account_evidence: AccountEvidenceContract,
}

impl ReviewedBrowserCodeProfile {
    /// The catalog pins this digest in the profile reference. A wire or
    /// account-evidence change therefore requires a new profile revision.
    pub fn review_revision(&self) -> Result<Digest> {
        let mode = match &self.protocol {
            ConfidentialPkceProfile::NoRefresh(_) => Digest::of(&"no-refresh")?,
            ConfidentialPkceProfile::Reusable { retry, .. } => {
                Digest::of(&("reusable-refresh", retry))?
            }
            ConfidentialPkceProfile::Rotating { recovery, .. } => {
                Digest::of(&("rotating-refresh", recovery))?
            }
        };
        Digest::of(&(
            "oauth-reviewed-browser-code-profile-v1",
            mode,
            &self.protocol.identity().scope_interpretation,
            &self.issuer,
            &self.issuer_url,
            &self.authorization_endpoint,
            &self.token_endpoint,
            &self.adapter,
            &self.simulator,
            &self.conformance,
            self.account_evidence,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum AccountEvidenceContract {
    MappedHuman,
    ExternalAccount,
    Installation,
}

/// Instance evidence is supplied by the private admission registry. These
/// values alone do not prove that a provider accepted the registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutboundInstanceEvidence {
    pub instance: BindingRef,
    pub binding_namespace: String,
    pub app_origin_url: String,
    pub shell: SecurityShellEvidence,
    pub registration: ProviderRegistrationEvidence,
    pub custody: BindingRef,
    pub account: AccountBindingEvidence,
    pub product_return: ProductReturnRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SecurityShellEvidence {
    pub instance: BindingRef,
    pub origin: SecurityOriginRef,
    pub origin_url: String,
    pub qualification: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProviderRegistrationEvidence {
    pub instance: BindingRef,
    pub registration: BindingRef,
    pub profile: BindingRef,
    pub issuer: ProviderIssuerRef,
    pub security_origin: SecurityOriginRef,
    pub callback: ProviderCallbackRef,
    pub callback_url: String,
    pub provider_confirmation: Digest,
    pub client_credential: BindingRef,
    pub class: ClientRegistrationClass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ClientRegistrationClass {
    ConfidentialPkceS256,
    PublicPkceS256,
}

/// Reviewed issuer, tenant, and optional subject ceiling for an external
/// account. The nominal revision covers every allowed identity value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExternalAccountConstraints {
    pub binding: BindingRef,
    pub issuer_url: String,
    pub allowed_tenants: BTreeSet<String>,
    pub allowed_subjects: Option<BTreeSet<String>>,
}

impl ExternalAccountConstraints {
    pub fn verify(&self, reviewed_issuer: &str) -> Result<()> {
        ensure!(
            self.issuer_url == reviewed_issuer
                && https_url(&self.issuer_url, true).is_ok()
                && !self.allowed_tenants.is_empty()
                && self.allowed_tenants.len() <= 64
                && self
                    .allowed_subjects
                    .as_ref()
                    .is_none_or(|subjects| !subjects.is_empty() && subjects.len() <= 64),
            "invalid external account constraints"
        );
        for value in self
            .allowed_tenants
            .iter()
            .chain(self.allowed_subjects.iter().flatten())
        {
            ensure!(
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
                "invalid external account constraint value"
            );
        }
        ensure!(
            self.binding.revision
                == Digest::of(&(
                    "oauth-external-account-constraints-v1",
                    &self.binding.id,
                    &self.issuer_url,
                    &self.allowed_tenants,
                    &self.allowed_subjects,
                ))?,
            "external account constraints revision mismatch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum AccountBindingEvidence {
    MappedHuman {
        instance: BindingRef,
        mapping: BindingRef,
        owner: String,
    },
    ExplicitExternal {
        instance: BindingRef,
        approval: BindingRef,
        constraints: ExternalAccountConstraints,
        owner: String,
    },
    Installation {
        instance: BindingRef,
        organization: BindingRef,
        owner: String,
    },
}

/// Current host-side inputs for one durable connect begin. The begin API
/// qualifies them together before it opens the attempt transaction.
pub struct OutboundQualification<'a> {
    pub intent: &'a super::connect::ConnectIntent,
    pub binding: &'a super::connect::CallbackBinding,
    pub requirement: &'a ConnectionRequirement,
    pub permission: &'a ProviderPermissionContract,
    pub reviewed: &'a ReviewedBrowserCodeProfile,
    pub instance: &'a OutboundInstanceEvidence,
}

/// Only qualification can construct this value; it carries the exact attempt
/// and callback evidence through the public durable begin entry point.
pub(super) struct QualifiedOutboundConnect {
    intent: super::connect::ConnectIntent,
    binding: super::connect::CallbackBinding,
}

impl QualifiedOutboundConnect {
    pub(super) fn intent(&self) -> &super::connect::ConnectIntent {
        &self.intent
    }

    pub(super) fn binding(&self) -> &super::connect::CallbackBinding {
        &self.binding
    }
}

pub(super) fn qualify_outbound_connect(
    intent: &super::connect::ConnectIntent,
    binding: &super::connect::CallbackBinding,
    requirement: &ConnectionRequirement,
    permission: &ProviderPermissionContract,
    reviewed: &ReviewedBrowserCodeProfile,
    instance: &OutboundInstanceEvidence,
) -> Result<QualifiedOutboundConnect> {
    binding.verify(intent)?;
    let profile_revision = reviewed.review_revision()?;
    ensure!(
        reviewed.protocol.identity().binding.revision == profile_revision,
        "reviewed provider profile revision mismatch"
    );
    ensure!(
        intent.consent == permission.consent_digest(requirement)?.as_str(),
        "connect consent does not match the admitted requirement"
    );
    ensure!(
        reviewed.protocol.identity().binding == permission.profile
            && reviewed.protocol.identity().scope_interpretation == permission.interpretation
            && instance.registration.profile == permission.profile
            && binding.profile() == &permission.profile,
        "outbound profile revision or scope interpretation mismatch"
    );
    ensure!(
        reviewed.issuer == instance.registration.issuer
            && reviewed.issuer == *binding.issuer()
            && reviewed.issuer_url == binding.issuer_url(),
        "provider issuer binding mismatch"
    );
    let issuer_url = https_url(&reviewed.issuer_url, true)?;
    let authorization_endpoint = https_url(&reviewed.authorization_endpoint, true)?;
    let token_endpoint = https_url(&reviewed.token_endpoint, true)?;
    let shell_url = https_url(&instance.shell.origin_url, false)?;
    let app_url = https_url(&instance.app_origin_url, false)?;
    ensure!(
        issuer_url.origin() != shell_url.origin()
            && issuer_url.origin() != app_url.origin()
            && shell_url.origin() != app_url.origin()
            && authorization_endpoint.origin() != shell_url.origin()
            && authorization_endpoint.origin() != app_url.origin()
            && token_endpoint.origin() != shell_url.origin()
            && token_endpoint.origin() != app_url.origin(),
        "provider, security shell and app origins must be isolated"
    );
    ensure!(
        instance.instance == instance.shell.instance
            && instance.instance == instance.registration.instance
            && instance.shell.origin == instance.registration.security_origin
            && instance.shell.origin == *binding.security_origin(),
        "cross-instance security or registration binding"
    );
    ensure!(
        instance.shell.origin.0.revision
            == Digest::of(&(
                "oauth-security-shell-evidence-v1",
                &instance.shell.instance,
                &instance.shell.origin_url,
                &instance.shell.qualification,
            ))?,
        "security shell evidence revision mismatch"
    );
    ensure!(
        instance.registration.class == ClientRegistrationClass::ConfidentialPkceS256,
        "unsupported provider registration class"
    );
    ensure!(
        Digest::of(&instance.registration.registration)?.as_str() == intent.registration,
        "connect attempt uses another registration revision"
    );
    let derived = ProviderCallbackRef::derive(
        &instance.shell.origin,
        &permission.profile,
        &instance.binding_namespace,
    )?;
    ensure!(
        binding.binding_namespace() == instance.binding_namespace
            && *binding.callback() == derived
            && instance.registration.callback == derived
            && instance.registration.callback_url
                == derived_callback_url(&instance.shell.origin_url, &derived)?,
        "provider registration does not contain the derived callback"
    );
    ensure!(
        instance.registration.registration.revision
            == Digest::of(&(
                "oauth-provider-registration-evidence-v1",
                &instance.registration.instance,
                &instance.registration.profile,
                &instance.registration.issuer,
                &instance.registration.security_origin,
                &instance.registration.callback,
                &instance.registration.callback_url,
                &instance.registration.provider_confirmation,
                &instance.registration.client_credential,
                instance.registration.class,
            ))?,
        "provider registration evidence revision mismatch"
    );
    ensure!(
        instance.product_return == *binding.product_return(),
        "product return is not approved for this binding"
    );
    let (account_instance, account_owner) = match &instance.account {
        AccountBindingEvidence::MappedHuman {
            instance, owner, ..
        }
        | AccountBindingEvidence::ExplicitExternal {
            instance, owner, ..
        }
        | AccountBindingEvidence::Installation {
            instance, owner, ..
        } => (instance, owner),
    };
    ensure!(
        account_instance == &instance.instance && account_owner == &intent.owner,
        "cross-instance account binding"
    );
    ensure!(
        matches!(
            (
                &requirement.account_policy,
                reviewed.account_evidence,
                &instance.account,
            ),
            (
                AccountBindingPolicy::MappedHuman,
                AccountEvidenceContract::MappedHuman,
                AccountBindingEvidence::MappedHuman { .. },
            ) | (
                AccountBindingPolicy::ExplicitExternalAccount,
                AccountEvidenceContract::ExternalAccount,
                AccountBindingEvidence::ExplicitExternal { .. },
            ) | (
                AccountBindingPolicy::InstallationAccount,
                AccountEvidenceContract::Installation,
                AccountBindingEvidence::Installation { .. },
            )
        ),
        "profile account evidence does not match the required owner policy"
    );
    if let AccountBindingEvidence::ExplicitExternal { constraints, .. } = &instance.account {
        constraints.verify(&reviewed.issuer_url)?;
    }
    Ok(QualifiedOutboundConnect {
        intent: intent.clone(),
        binding: binding.clone(),
    })
}

/// The registration must contain this exact URL; an app return page is never
/// accepted as a provider callback. The symbolic callback is already derived
/// from the shell, profile and full namespace before this function is called.
pub fn derived_callback_url(origin_url: &str, callback: &ProviderCallbackRef) -> Result<String> {
    https_url(origin_url, false)?;
    let digest = Digest::of(callback)?;
    let suffix = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("invalid provider callback digest"))?;
    Ok(format!("{origin_url}_day2/oauth/callback/{suffix}"))
}

fn https_url(raw: &str, allow_path: bool) -> Result<url::Url> {
    let parsed = url::Url::parse(raw)?;
    ensure!(
        raw.len() <= 1024
            && parsed.scheme() == "https"
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && parsed.as_str() == raw
            && (allow_path || parsed.path() == "/"),
        "invalid admitted OAuth address"
    );
    Ok(parsed)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: String,
}

/// Private exchange material. It has no Debug, Clone or Serialize path.
pub struct ValidatedTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
    scopes: BTreeSet<String>,
    profile: BindingRef,
    interpretation: Digest,
}

impl ValidatedTokenResponse {
    pub fn scopes(&self) -> &BTreeSet<String> {
        &self.scopes
    }

    pub fn matches_permission(&self, permission: &ProviderPermissionContract) -> bool {
        self.profile == permission.profile && self.interpretation == permission.interpretation
    }

    /// Only the private custody adapter should consume the secret bytes.
    pub fn into_private_tokens(self) -> (String, Option<String>, u64) {
        (self.access_token, self.refresh_token, self.expires_in)
    }
}

fn secret(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= MAX_TOKEN_BYTES && !value.chars().any(char::is_control),
        "invalid provider token material"
    );
    Ok(())
}

fn parse_scopes(raw: &str) -> Result<BTreeSet<String>> {
    ensure!(
        !raw.is_empty() && raw.len() <= 8192,
        "invalid provider scope response"
    );
    let mut scopes = BTreeSet::new();
    for scope in raw.split(' ') {
        ensure!(
            !scope.is_empty()
                && scope.len() <= 256
                && scope.bytes().all(|byte| {
                    byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
                })
                && scopes.insert(scope.to_owned())
                && scopes.len() <= 32,
            "invalid provider scope response"
        );
    }
    Ok(scopes)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::managed_credentials::crypto::KeyLease;
    use crate::oauth::account::{MappedHumanEvidence, ProviderAccount};
    use crate::oauth::approval_registry::{
        AdmittedApproval, ApprovalAuthority, ApprovalKeyMaterial, ApprovalKeyProvider,
        ApprovalKeyPurpose, ApprovalKeyRef, ApprovalTerms, SelectedApprovalAuthority,
        StoredApprovalRegistry,
    };
    use crate::oauth::connect::{
        self, CallbackBinding, CallbackBindingSpec, ConnectIntent, ConnectState,
    };
    use crate::oauth::exchange::{self, ExchangeObservation, TokenHttpResponse};
    use crate::oauth::external::{self, FreshExternalApproval, ShellApprovalKeyLease};
    use crate::oauth::outbound::{CallbackIngress, CallbackOutcome};
    use crate::oauth::security_shell::{
        ApprovalRegistry, FreshAuthenticator, FreshHuman, ReauthStart, SecurityShell,
    };
    use axum::http::{HeaderMap, Method, StatusCode, header};
    use day2_capabilities::Name;
    use day2_capabilities::oauth::{ConnectionOwner, ProductReturnRef};
    use std::collections::BTreeMap;

    fn pin(name: &str) -> BindingRef {
        BindingRef::pin(Name::try_from(name.to_owned()).unwrap(), &name).unwrap()
    }

    #[derive(Clone)]
    pub(in crate::oauth) struct QualificationFixture {
        pub(in crate::oauth) intent: ConnectIntent,
        pub(in crate::oauth) binding: CallbackBinding,
        pub(in crate::oauth) requirement: ConnectionRequirement,
        pub(in crate::oauth) permission: ProviderPermissionContract,
        pub(in crate::oauth) reviewed: ReviewedBrowserCodeProfile,
        pub(in crate::oauth) instance: OutboundInstanceEvidence,
    }

    impl QualificationFixture {
        pub(in crate::oauth) fn input(&self) -> OutboundQualification<'_> {
            OutboundQualification {
                intent: &self.intent,
                binding: &self.binding,
                requirement: &self.requirement,
                permission: &self.permission,
                reviewed: &self.reviewed,
                instance: &self.instance,
            }
        }

        fn qualify(&self) -> Result<QualifiedOutboundConnect> {
            qualify_outbound_connect(
                &self.intent,
                &self.binding,
                &self.requirement,
                &self.permission,
                &self.reviewed,
                &self.instance,
            )
        }

        fn begin(&self, db: &mut rusqlite::Connection) -> Result<bool> {
            connect::begin_qualified(
                db,
                OutboundQualification {
                    intent: &self.intent,
                    binding: &self.binding,
                    requirement: &self.requirement,
                    permission: &self.permission,
                    reviewed: &self.reviewed,
                    instance: &self.instance,
                },
                1,
            )
        }
    }

    fn qualification_fixture() -> QualificationFixture {
        qualification_fixture_for(AccountBindingPolicy::MappedHuman)
    }

    pub(in crate::oauth) fn external_fixture() -> QualificationFixture {
        qualification_fixture_for(AccountBindingPolicy::ExplicitExternalAccount)
    }

    fn qualification_fixture_for(policy: AccountBindingPolicy) -> QualificationFixture {
        let requirement = ConnectionRequirement {
            logical_id: "workspace.calendar".into(),
            revision: 1,
            capability: "calendar.events".into(),
            actions: BTreeSet::from(["read".into()]),
            owner: ConnectionOwner::CurrentHuman,
            account_policy: policy.clone(),
            usage: "Read calendar events".into(),
        };
        let mut permission = ProviderPermissionContract {
            requirement: requirement.nominal_identity().unwrap(),
            profile: pin("calendar_profile"),
            action_scopes: BTreeMap::from([(
                "read".into(),
                BTreeSet::from(["calendar.read".into()]),
            )]),
            interpretation: Digest::of(&"calendar-scope-v1").unwrap(),
        };
        let issuer = ProviderIssuerRef(pin("calendar_issuer"));
        let mut reviewed = ReviewedBrowserCodeProfile {
            protocol: ConfidentialPkceProfile::NoRefresh(BrowserCodeIdentity {
                binding: permission.profile.clone(),
                scope_interpretation: permission.interpretation.clone(),
            }),
            issuer: issuer.clone(),
            issuer_url: "https://issuer.example/tenant".into(),
            authorization_endpoint: "https://issuer.example/authorize".into(),
            token_endpoint: "https://tokens.example/token".into(),
            adapter: pin("calendar_adapter"),
            simulator: pin("calendar_simulator"),
            conformance: pin("calendar_conformance"),
            account_evidence: match &policy {
                AccountBindingPolicy::MappedHuman => AccountEvidenceContract::MappedHuman,
                AccountBindingPolicy::ExplicitExternalAccount => {
                    AccountEvidenceContract::ExternalAccount
                }
                AccountBindingPolicy::InstallationAccount => AccountEvidenceContract::Installation,
            },
        };
        let revision = reviewed.review_revision().unwrap();
        permission.profile.revision = revision.clone();
        if let ConfidentialPkceProfile::NoRefresh(identity) = &mut reviewed.protocol {
            identity.binding.revision = revision;
        }
        let instance_ref = pin("installation_production");
        let shell_qualification = Digest::of(&"security-shell-ready").unwrap();
        let shell_url = "https://security.example/".to_owned();
        let shell_revision = Digest::of(&(
            "oauth-security-shell-evidence-v1",
            &instance_ref,
            &shell_url,
            &shell_qualification,
        ))
        .unwrap();
        let security_origin = SecurityOriginRef(BindingRef {
            id: Name::try_from("security_origin".to_owned()).unwrap(),
            revision: shell_revision,
        });
        let slot = "installation.production.workspace.calendar.human_1";
        let callback =
            ProviderCallbackRef::derive(&security_origin, &permission.profile, slot).unwrap();
        let callback_url = derived_callback_url(&shell_url, &callback).unwrap();
        let confirmation = Digest::of(&"provider-accepted-redirect").unwrap();
        let client_credential = pin("calendar_client_credential");
        let class = ClientRegistrationClass::ConfidentialPkceS256;
        let registration_revision = Digest::of(&(
            "oauth-provider-registration-evidence-v1",
            &instance_ref,
            &permission.profile,
            &issuer,
            &security_origin,
            &callback,
            &callback_url,
            &confirmation,
            &client_credential,
            class,
        ))
        .unwrap();
        let registration = BindingRef {
            id: Name::try_from("calendar_registration".to_owned()).unwrap(),
            revision: registration_revision,
        };
        let product_return = ProductReturnRef(pin("calendar_return"));
        let intent = ConnectIntent {
            attempt: "attempt_1".into(),
            slot: slot.into(),
            expected_generation: None,
            expected_epoch: 1,
            proposed_generation: 1,
            owner: "human_1".into(),
            profile: permission.profile.id.as_str().into(),
            registration: Digest::of(&registration).unwrap().as_str().into(),
            callback: Digest::of(&callback).unwrap().as_str().into(),
            consent: permission
                .consent_digest(&requirement)
                .unwrap()
                .as_str()
                .into(),
            expires_at: 100,
        };
        let binding = CallbackBinding::from_secret_state(
            b"0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
            CallbackBindingSpec {
                issuer: issuer.clone(),
                issuer_url: reviewed.issuer_url.clone(),
                security_origin: security_origin.clone(),
                profile: permission.profile.clone(),
                callback: callback.clone(),
                binding_namespace: slot.into(),
                session: Digest::of(&"private-session").unwrap(),
                product_return: product_return.clone(),
            },
        )
        .unwrap();
        let instance = OutboundInstanceEvidence {
            instance: instance_ref.clone(),
            binding_namespace: slot.into(),
            app_origin_url: "https://app.example/".into(),
            shell: SecurityShellEvidence {
                instance: instance_ref.clone(),
                origin: security_origin.clone(),
                origin_url: shell_url,
                qualification: shell_qualification,
            },
            registration: ProviderRegistrationEvidence {
                instance: instance_ref.clone(),
                registration,
                profile: permission.profile.clone(),
                issuer,
                security_origin,
                callback,
                callback_url,
                provider_confirmation: confirmation,
                client_credential,
                class,
            },
            custody: pin("private_oauth_custody"),
            account: match policy {
                AccountBindingPolicy::MappedHuman => AccountBindingEvidence::MappedHuman {
                    instance: instance_ref,
                    mapping: pin("human_subject_map"),
                    owner: "human_1".into(),
                },
                AccountBindingPolicy::ExplicitExternalAccount => {
                    AccountBindingEvidence::ExplicitExternal {
                        instance: instance_ref,
                        approval: pin("security_shell_account_approval"),
                        constraints: external_constraints(),
                        owner: "human_1".into(),
                    }
                }
                AccountBindingPolicy::InstallationAccount => unreachable!("test fixture policy"),
            },
            product_return,
        };
        QualificationFixture {
            intent,
            binding,
            requirement,
            permission,
            reviewed,
            instance,
        }
    }

    pub(in crate::oauth) fn exchange_key() -> KeyLease {
        KeyLease::new(&[7; 32], &[9; 32], "verify_v1".into(), "encrypt_v1".into()).unwrap()
    }

    fn private_callback(
        db: &mut rusqlite::Connection,
        fixture: &QualificationFixture,
        code_ref: &str,
        key: &KeyLease,
    ) {
        let raw = b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&code=secret_code&iss=https%3A%2F%2Fissuer.example%2Ftenant";
        let outcome = exchange::handle_qualified_callback(
            db,
            fixture.input(),
            CallbackIngress {
                attempt: &fixture.intent.attempt,
                raw_query: raw,
                route: &fixture.instance.registration.callback,
                session: fixture.binding.session(),
                issuer_binding: &fixture.reviewed.issuer,
                code_ref,
                now: 2,
            },
            key,
        )
        .unwrap();
        assert!(matches!(outcome, CallbackOutcome::CodeAccepted { .. }));
    }

    pub(in crate::oauth) fn quarantine_external_fixture(
        db: &mut rusqlite::Connection,
        fixture: &QualificationFixture,
        key: &KeyLease,
    ) {
        connect::install_schema(db).unwrap();
        let prepared = exchange::prepare_authorization(
            fixture.input(),
            key,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )
        .unwrap();
        let code_ref = prepared.code_ref().to_owned();
        assert!(prepared.begin(db, 1).unwrap());
        private_callback(db, fixture, &code_ref, key);
        let permit = exchange::authorize_and_commit_qualified_exchange(db, fixture.input(), 3)
            .unwrap()
            .unwrap();
        let response = match permit.send(|_| Ok(TokenHttpResponse {
            status: 200,
            content_type: "application/json".into(),
            body: br#"{"access_token":"secret_external_access","token_type":"Bearer","expires_in":3600,"scope":"calendar.read"}"#.to_vec(),
        })) {
            ExchangeObservation::Response(response) => response,
            ExchangeObservation::Uncertain(_) => panic!("external response lost"),
        };
        let (_, observed) = mapped_account(fixture);
        let prepared = response
            .validate_external(fixture.input(), &observed)
            .unwrap()
            .prepare_quarantine(key, 4)
            .unwrap();
        assert!(external::quarantine_external(db, prepared, fixture.input(), 4).unwrap());
    }

    fn shell_key(pending: &external::PendingExternalApproval) -> ShellApprovalKeyLease {
        ShellApprovalKeyLease::new(
            &[12; 32],
            "shell_v1".into(),
            pending.security_origin().clone(),
            pending.approval_binding().clone(),
        )
        .unwrap()
    }

    fn fresh_approval(
        pending: &external::PendingExternalApproval,
        shell: &ShellApprovalKeyLease,
    ) -> FreshExternalApproval {
        shell
            .attest(
                pending,
                Digest::of(&"fresh-security-session").unwrap(),
                5,
                5,
            )
            .unwrap()
    }

    struct TestApprovalAuthority {
        app: &'static str,
        fixture: QualificationFixture,
    }

    impl ApprovalAuthority for TestApprovalAuthority {
        fn with_current(
            &self,
            app: &str,
            intent: &ConnectIntent,
            binding: &CallbackBinding,
            now: i64,
            commit: &mut dyn FnMut(ApprovalTerms) -> Result<bool>,
        ) -> Result<bool> {
            let Some(terms) = self.current(app, intent, binding, now)? else {
                return Ok(false);
            };
            commit(terms)
        }

        fn current(
            &self,
            app: &str,
            intent: &ConnectIntent,
            binding: &CallbackBinding,
            _: i64,
        ) -> Result<Option<ApprovalTerms>> {
            if app != self.app || intent != &self.fixture.intent || binding != &self.fixture.binding
            {
                return Ok(None);
            }
            let fixture = self.fixture.clone();
            let AccountBindingEvidence::ExplicitExternal { approval, .. } =
                &fixture.instance.account
            else {
                unreachable!()
            };
            let shell_key = ShellApprovalKeyLease::new(
                &[12; 32],
                "shell_v1".into(),
                fixture.instance.shell.origin.clone(),
                approval.clone(),
            )?;
            Ok(Some(ApprovalTerms {
                requirement: fixture.requirement,
                permission: fixture.permission,
                reviewed: fixture.reviewed,
                instance: fixture.instance,
                custody_key: exchange_key(),
                shell_key,
            }))
        }
    }

    fn test_registry(
        path: std::path::PathBuf,
        fixture: QualificationFixture,
    ) -> std::sync::Arc<StoredApprovalRegistry> {
        std::sync::Arc::new(
            StoredApprovalRegistry::new(
                BTreeMap::from([("app".into(), path)]),
                std::sync::Arc::new(TestApprovalAuthority {
                    app: "app",
                    fixture,
                }),
            )
            .unwrap(),
        )
    }

    pub(in crate::oauth) struct TestApprovalKeys(pub(in crate::oauth) std::sync::atomic::AtomicU8);

    impl ApprovalKeyProvider for TestApprovalKeys {
        fn load(
            &self,
            reference: &ApprovalKeyRef,
            purpose: ApprovalKeyPurpose,
        ) -> Result<ApprovalKeyMaterial> {
            use std::sync::atomic::Ordering;
            let mode = self.0.load(Ordering::SeqCst);
            ensure!(mode != 2, "selected key unavailable");
            Ok(ApprovalKeyMaterial {
                binding: reference.binding.clone(),
                version: if mode == 1 {
                    "substituted_version".into()
                } else {
                    reference.version.clone()
                },
                purpose,
                bytes: match purpose {
                    ApprovalKeyPurpose::CustodyVerifier => [7; 32],
                    ApprovalKeyPurpose::CustodyEncryption => [9; 32],
                    ApprovalKeyPurpose::ShellAttestation => [12; 32],
                },
            })
        }
    }

    pub(in crate::oauth) fn selected_approval(fixture: &QualificationFixture) -> AdmittedApproval {
        let AccountBindingEvidence::ExplicitExternal { approval, .. } = &fixture.instance.account
        else {
            unreachable!()
        };
        AdmittedApproval {
            requirement: fixture.requirement.clone(),
            permission: fixture.permission.clone(),
            reviewed: fixture.reviewed.clone(),
            instance: fixture.instance.clone(),
            custody_verifier: ApprovalKeyRef {
                binding: fixture.instance.custody.clone(),
                version: "verify_v1".into(),
            },
            custody_encryption: ApprovalKeyRef {
                binding: fixture.instance.custody.clone(),
                version: "encrypt_v1".into(),
            },
            shell_attestation: ApprovalKeyRef {
                binding: approval.clone(),
                version: "shell_v1".into(),
            },
        }
    }

    pub(in crate::oauth) fn selected_instance() -> crate::artifact::Instance {
        crate::artifact::Instance::from_bytes(
            br#"{
                "installation":"installation","environment":"production",
                "identity":{"scheme":"google_iap","hosted_domain":"example.com"},
                "security_shell":{"origin":"https://security.example",
                    "iap_audience":"/projects/1/global/backendServices/1"},
                "apps":{"app":{"artifact":"sha256:fixture","readers":[],"writers":[],
                    "edge":{"origin":"https://app.example",
                        "iap_audience":"/projects/1/global/backendServices/2"}}}
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn selected_approval_rechecks_admission_and_exact_keys_on_each_lookup() {
        use std::sync::{Arc, atomic::Ordering};
        let fixture = external_fixture();
        let keys = Arc::new(TestApprovalKeys(std::sync::atomic::AtomicU8::new(0)));
        let selected = selected_approval(&fixture);
        let entries = BTreeMap::from([(("app".into(), fixture.intent.slot.clone()), selected)]);
        let authority =
            SelectedApprovalAuthority::new(&selected_instance(), entries.clone(), keys.clone())
                .unwrap();
        assert!(
            authority
                .current("app", &fixture.intent, &fixture.binding, 5)
                .unwrap()
                .is_some()
        );
        assert!(
            authority
                .current("other", &fixture.intent, &fixture.binding, 5)
                .unwrap()
                .is_none()
        );
        keys.0.store(1, Ordering::SeqCst);
        assert!(
            authority
                .current("app", &fixture.intent, &fixture.binding, 5)
                .is_err()
        );
        keys.0.store(2, Ordering::SeqCst);
        assert!(
            authority
                .current("app", &fixture.intent, &fixture.binding, 5)
                .is_err()
        );
        keys.0.store(0, Ordering::SeqCst);
        authority.replace(BTreeMap::new()).unwrap();
        assert!(
            authority
                .current("app", &fixture.intent, &fixture.binding, 5)
                .unwrap()
                .is_none()
        );
        let mut wrong_origin = entries;
        wrong_origin
            .values_mut()
            .next()
            .unwrap()
            .instance
            .shell
            .origin_url = "https://app.example/".into();
        assert!(authority.replace(wrong_origin).is_err());
        assert!(
            authority
                .current("app", &fixture.intent, &fixture.binding, 5)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn stored_approval_registry_uses_only_current_durable_pending_state() {
        let fixture = external_fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval-registry.sqlite");
        let mut db = rusqlite::Connection::open(&path).unwrap();
        quarantine_external_fixture(&mut db, &fixture, &exchange_key());
        let registry = test_registry(path, fixture.clone());
        assert!(registry.resolve("other", 5).unwrap().is_none());
        assert!(registry.resolve("attempt_1", 100).unwrap().is_none());
        assert!(registry.resolve("attempt_1", 5).unwrap().is_some());

        db.execute(
            "UPDATE oauth_callback_bindings SET binding = '{}' WHERE attempt = 'attempt_1'",
            [],
        )
        .unwrap();
        assert!(registry.resolve("attempt_1", 5).is_err());
        db.execute(
            "UPDATE oauth_callback_bindings SET binding = ?1 WHERE attempt = 'attempt_1'",
            [serde_json::to_string(&fixture.binding).unwrap()],
        )
        .unwrap();
        db.execute(
            "UPDATE oauth_connect_attempts SET state = 'denied',
                    account = NULL, scope_evidence = NULL WHERE attempt = 'attempt_1'",
            [],
        )
        .unwrap();
        assert!(registry.resolve("attempt_1", 5).unwrap().is_none());
    }

    #[test]
    fn shared_shell_routes_to_one_installed_app_and_refuses_duplicate_attempts() {
        let fixture = external_fixture();
        let dir = tempfile::tempdir().unwrap();
        let first_path = dir.path().join("first.sqlite");
        let second_path = dir.path().join("second.sqlite");
        let mut first = rusqlite::Connection::open(&first_path).unwrap();
        connect::install_schema(&first).unwrap();
        let mut second = rusqlite::Connection::open(&second_path).unwrap();
        quarantine_external_fixture(&mut second, &fixture, &exchange_key());
        let registry = StoredApprovalRegistry::new(
            BTreeMap::from([
                ("aempty".into(), first_path),
                ("zapp".into(), second_path.clone()),
            ]),
            std::sync::Arc::new(TestApprovalAuthority {
                app: "zapp",
                fixture: fixture.clone(),
            }),
        )
        .unwrap();
        assert_eq!(
            registry.resolve("attempt_1", 5).unwrap().unwrap().db,
            second_path.canonicalize().unwrap()
        );
        quarantine_external_fixture(&mut first, &fixture, &exchange_key());
        assert!(registry.resolve("attempt_1", 5).is_err());
        first
            .execute(
                "UPDATE oauth_connect_attempts SET state = 'denied',
                        account = NULL, scope_evidence = NULL WHERE attempt = 'attempt_1'",
                [],
            )
            .unwrap();
        assert!(registry.resolve("attempt_1", 5).is_err());
    }

    struct TestFreshAuth {
        human: &'static str,
        authenticated_at: i64,
    }

    impl FreshAuthenticator for TestFreshAuth {
        fn identify(&self, _: &HeaderMap, _: i64) -> Result<crate::iap::Verified> {
            Ok(crate::iap::Verified {
                email: self.human.into(),
                subject: "accounts.google.com:test-human".into(),
            })
        }

        fn begin(
            &self,
            identity: &crate::iap::Verified,
            _: &str,
            _: &Digest,
            _: i64,
        ) -> Result<ReauthStart> {
            Ok(ReauthStart::Authenticated(FreshHuman {
                human: identity.email.clone(),
                subject: identity.subject.clone(),
                authenticated_at: self.authenticated_at,
            }))
        }
    }

    struct TestCallbackAuth(Digest);

    impl FreshAuthenticator for TestCallbackAuth {
        fn identify(&self, _: &HeaderMap, _: i64) -> Result<crate::iap::Verified> {
            Ok(crate::iap::Verified {
                email: "human_1".into(),
                subject: "accounts.google.com:test-human".into(),
            })
        }

        fn begin(
            &self,
            _: &crate::iap::Verified,
            _: &str,
            _: &Digest,
            _: i64,
        ) -> Result<ReauthStart> {
            Ok(ReauthStart::Redirect(
                "https://accounts.google.com/o/oauth2/v2/auth?state=opaque".into(),
            ))
        }

        fn complete(
            &self,
            _: &str,
            _: &crate::iap::Verified,
            _: i64,
        ) -> Result<crate::oauth::shell_oidc::Reauthenticated> {
            Ok(crate::oauth::shell_oidc::Reauthenticated {
                attempt: "attempt_1".into(),
                challenge: self.0.clone(),
                human: "human_1".into(),
                authenticated_at: 5,
            })
        }
    }

    #[test]
    fn security_shell_oidc_callback_issues_bound_session_then_page() {
        let fixture = external_fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shell-oidc.sqlite");
        let mut db = rusqlite::Connection::open(&path).unwrap();
        quarantine_external_fixture(&mut db, &fixture, &exchange_key());
        db.execute_batch(crate::audit::PRINCIPALS_DDL).unwrap();
        let pending = external::load_pending_external(&db, fixture.input(), &exchange_key(), 5)
            .unwrap()
            .unwrap();
        let shell = SecurityShell::new(
            fixture.instance.shell.origin_url.clone(),
            test_registry(path, fixture),
            std::sync::Arc::new(TestCallbackAuth(pending.challenge().clone())),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "security.example".parse().unwrap());
        let redirect = shell
            .dispatch(
                &Method::GET,
                "/oauth/approvals/attempt_1",
                None,
                &headers,
                &[],
                5,
            )
            .unwrap();
        assert_eq!(redirect.status(), StatusCode::SEE_OTHER);
        assert!(
            redirect.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .starts_with("https://accounts.google.com/")
        );
        let callback = shell
            .dispatch(
                &Method::GET,
                "/_day2/reauth/callback",
                Some("state=opaque&code=secret-code&iss=https%3A%2F%2Faccounts.google.com"),
                &headers,
                &[],
                5,
            )
            .unwrap();
        assert_eq!(callback.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            callback.headers()[header::LOCATION],
            "/oauth/approvals/attempt_1"
        );
        assert!(
            !callback.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("secret-code")
        );
        headers.insert(
            header::COOKIE,
            callback.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .parse()
                .unwrap(),
        );
        let page = shell
            .dispatch(
                &Method::GET,
                "/oauth/approvals/attempt_1",
                None,
                &headers,
                &[],
                5,
            )
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
    }

    #[test]
    fn security_shell_form_activates_only_after_fresh_session_and_exact_confirmation() {
        let fixture = external_fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shell.sqlite");
        let mut db = rusqlite::Connection::open(&path).unwrap();
        quarantine_external_fixture(&mut db, &fixture, &exchange_key());
        db.execute_batch(crate::audit::PRINCIPALS_DDL).unwrap();
        let pending = external::load_pending_external(&db, fixture.input(), &exchange_key(), 5)
            .unwrap()
            .unwrap();
        let shell = SecurityShell::new(
            fixture.instance.shell.origin_url.clone(),
            test_registry(path, fixture.clone()),
            std::sync::Arc::new(TestFreshAuth {
                human: "human_1",
                authenticated_at: 5,
            }),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "security.example".parse().unwrap());
        let response = shell
            .dispatch(
                &Method::GET,
                "/oauth/approvals/attempt_1",
                None,
                &headers,
                &[],
                5,
            )
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body = tokio::runtime::Runtime::new().unwrap().block_on(async {
            axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap()
        });
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("subject_1"));
        assert!(body.contains("Read calendar events"));
        assert!(body.contains("calendar.read"));
        assert!(!body.contains("secret_external_access"));
        let csrf = body
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let form = format!("csrf={csrf}&challenge={}", pending.challenge().as_str());
        let mut post_headers = headers.clone();
        post_headers.insert(header::COOKIE, cookie.parse().unwrap());
        post_headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        post_headers.insert(header::ORIGIN, "https://app.example".parse().unwrap());
        assert!(
            shell
                .dispatch(
                    &Method::POST,
                    "/oauth/approvals/attempt_1",
                    None,
                    &post_headers,
                    form.as_bytes(),
                    5
                )
                .is_err()
        );
        assert!(matches!(
            connect::state(&db, "attempt_1").unwrap(),
            Some(ConnectState::AwaitingAccountApproval)
        ));
        post_headers.insert(header::ORIGIN, "https://security.example".parse().unwrap());
        let wrong_csrf = format!("csrf=wrong&challenge={}", pending.challenge().as_str());
        assert!(
            shell
                .dispatch(
                    &Method::POST,
                    "/oauth/approvals/attempt_1",
                    None,
                    &post_headers,
                    wrong_csrf.as_bytes(),
                    5
                )
                .is_err()
        );
        assert!(matches!(
            connect::state(&db, "attempt_1").unwrap(),
            Some(ConnectState::AwaitingAccountApproval)
        ));
        assert_eq!(
            shell
                .dispatch(
                    &Method::POST,
                    "/oauth/approvals/attempt_1",
                    None,
                    &post_headers,
                    form.as_bytes(),
                    5
                )
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(matches!(
            connect::state(&db, "attempt_1").unwrap(),
            Some(ConnectState::Activated { .. })
        ));
        assert_eq!(
            shell
                .dispatch(
                    &Method::POST,
                    "/oauth/approvals/attempt_1",
                    None,
                    &post_headers,
                    form.as_bytes(),
                    6
                )
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn security_shell_refuses_stale_or_different_human_authentication() {
        let fixture = external_fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shell-refusal.sqlite");
        let mut db = rusqlite::Connection::open(&path).unwrap();
        quarantine_external_fixture(&mut db, &fixture, &exchange_key());
        db.execute_batch(crate::audit::PRINCIPALS_DDL).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "security.example".parse().unwrap());
        for (human, authenticated_at) in [("human_1", 4), ("another_human", 5)] {
            let shell = SecurityShell::new(
                fixture.instance.shell.origin_url.clone(),
                test_registry(path.clone(), fixture.clone()),
                std::sync::Arc::new(TestFreshAuth {
                    human,
                    authenticated_at,
                }),
            )
            .unwrap();
            assert!(
                shell
                    .dispatch(
                        &Method::GET,
                        "/oauth/approvals/attempt_1",
                        None,
                        &headers,
                        &[],
                        5
                    )
                    .is_err()
            );
        }
        assert!(matches!(
            connect::state(&db, "attempt_1").unwrap(),
            Some(ConnectState::AwaitingAccountApproval)
        ));
    }

    #[test]
    fn external_approval_survives_reopen_and_activates_exact_quarantine_once() {
        let fixture = external_fixture();
        let key = exchange_key();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("external-approval.sqlite");
        {
            let mut db = rusqlite::Connection::open(&path).unwrap();
            quarantine_external_fixture(&mut db, &fixture, &key);
            assert!(matches!(
                connect::state(&db, &fixture.intent.attempt).unwrap(),
                Some(ConnectState::AwaitingAccountApproval)
            ));
            let active: i64 = db
                .query_row("SELECT COUNT(*) FROM oauth_private_tokens", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(active, 0);
        }
        let mut db = rusqlite::Connection::open(&path).unwrap();
        connect::install_schema(&db).unwrap();
        let pending = external::load_pending_external(&db, fixture.input(), &key, 5)
            .unwrap()
            .unwrap();
        assert_eq!(pending.observed_account().subject, "subject_1");
        let shell = shell_key(&pending);
        let approval = fresh_approval(&pending, &shell);
        assert!(
            external::approve_external(&mut db, fixture.input(), &key, &shell, approval, 5)
                .unwrap()
        );
        assert!(matches!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::Activated { .. })
        ));
        assert!(
            external::load_pending_external(&db, fixture.input(), &key, 6)
                .unwrap()
                .is_none()
        );
        let ciphertext: Vec<u8> = db
            .query_row("SELECT ciphertext FROM oauth_private_tokens", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(
            !ciphertext
                .windows(b"secret_external_access".len())
                .any(|part| part == b"secret_external_access")
        );
        let pending_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM oauth_external_quarantine",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_count, 0);
        assert!(
            !external::approve_external(
                &mut db,
                fixture.input(),
                &key,
                &shell,
                fresh_approval(&pending, &shell),
                6
            )
            .unwrap()
        );
    }

    #[test]
    fn external_approval_rejects_changed_account_scope_and_stale_session() {
        let fixture = external_fixture();
        let key = exchange_key();
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        quarantine_external_fixture(&mut db, &fixture, &key);
        let pending = external::load_pending_external(&db, fixture.input(), &key, 5)
            .unwrap()
            .unwrap();
        let shell = shell_key(&pending);
        let mut wrong_account = fresh_approval(&pending, &shell);
        wrong_account.account = Digest::of(&"another-account").unwrap().as_str().into();
        assert!(
            external::approve_external(&mut db, fixture.input(), &key, &shell, wrong_account, 5)
                .is_err()
        );
        let mut wrong_scope = fresh_approval(&pending, &shell);
        wrong_scope.scope_evidence = Digest::of(&"another-scope").unwrap().as_str().into();
        assert!(
            external::approve_external(&mut db, fixture.input(), &key, &shell, wrong_scope, 5)
                .is_err()
        );
        let mut wrong_generation = fresh_approval(&pending, &shell);
        wrong_generation.generation += 1;
        assert!(
            external::approve_external(&mut db, fixture.input(), &key, &shell, wrong_generation, 5)
                .is_err()
        );
        let mut wrong_challenge = fresh_approval(&pending, &shell);
        wrong_challenge.challenge = Digest::of(&"another-challenge").unwrap();
        assert!(
            external::approve_external(&mut db, fixture.input(), &key, &shell, wrong_challenge, 5)
                .is_err()
        );
        let stale = shell
            .attest(
                &pending,
                Digest::of(&"fresh-security-session").unwrap(),
                3,
                5,
            )
            .unwrap();
        assert!(
            external::approve_external(&mut db, fixture.input(), &key, &shell, stale, 5).is_err()
        );
        let reused_session = shell
            .attest(&pending, fixture.binding.session().clone(), 5, 5)
            .unwrap();
        assert!(
            external::approve_external(&mut db, fixture.input(), &key, &shell, reused_session, 5)
                .is_err()
        );
        let other_shell = ShellApprovalKeyLease::new(
            &[13; 32],
            "shell_v1".into(),
            pending.security_origin().clone(),
            pending.approval_binding().clone(),
        )
        .unwrap();
        assert!(
            external::approve_external(
                &mut db,
                fixture.input(),
                &key,
                &other_shell,
                fresh_approval(&pending, &shell),
                5,
            )
            .is_err()
        );
        let mut changed = fixture.clone();
        if let AccountBindingEvidence::ExplicitExternal { constraints, .. } =
            &mut changed.instance.account
        {
            constraints
                .allowed_tenants
                .insert("unreviewed-tenant".into());
        }
        assert!(external::load_pending_external(&db, changed.input(), &key, 5).is_err());
        assert!(matches!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::AwaitingAccountApproval)
        ));
        let active: i64 = db
            .query_row("SELECT COUNT(*) FROM oauth_private_tokens", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(active, 0);
    }

    #[test]
    fn external_quarantine_tamper_rolls_back_and_expiry_cleans_custody() {
        let fixture = external_fixture();
        let key = exchange_key();
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        quarantine_external_fixture(&mut db, &fixture, &key);
        let pending = external::load_pending_external(&db, fixture.input(), &key, 5)
            .unwrap()
            .unwrap();
        let shell = shell_key(&pending);
        db.execute(
            "UPDATE oauth_external_quarantine SET token_ciphertext = x'00'",
            [],
        )
        .unwrap();
        assert!(
            external::approve_external(
                &mut db,
                fixture.input(),
                &key,
                &shell,
                fresh_approval(&pending, &shell),
                5
            )
            .is_err()
        );
        assert!(matches!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::AwaitingAccountApproval)
        ));
        let active: i64 = db
            .query_row("SELECT COUNT(*) FROM oauth_private_tokens", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(active, 0);
        assert!(connect::expire(&mut db, &fixture.intent.attempt, 101, |_| Ok(())).unwrap());
        let pending_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM oauth_external_quarantine",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_count, 0);
    }

    #[test]
    fn external_quarantine_write_failure_keeps_exchange_fence_and_private_code() {
        let fixture = external_fixture();
        let key = exchange_key();
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        connect::install_schema(&db).unwrap();
        let prepared = exchange::prepare_authorization(
            fixture.input(),
            &key,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )
        .unwrap();
        let code_ref = prepared.code_ref().to_owned();
        assert!(prepared.begin(&mut db, 1).unwrap());
        private_callback(&mut db, &fixture, &code_ref, &key);
        let _permit =
            exchange::authorize_and_commit_qualified_exchange(&mut db, fixture.input(), 3)
                .unwrap()
                .unwrap();
        let (_, observed) = mapped_account(&fixture);
        let response = fixture.reviewed.protocol.validate_token_response(
            br#"{"access_token":"secret_external_access","token_type":"Bearer","expires_in":3600,"scope":"calendar.read"}"#,
            &fixture.permission,
        ).unwrap();
        let verified = crate::oauth::account::VerifiedExternalAccount::verify(
            &fixture.intent,
            &fixture.requirement,
            &fixture.permission,
            &fixture.instance,
            &observed,
            &response,
        )
        .unwrap();
        let binding = exchange::load_binding(&db, &fixture.intent.attempt)
            .unwrap()
            .unwrap();
        assert!(
            connect::quarantine_external_bound(&mut db, &verified, &binding, 4, |_| anyhow::bail!(
                "custody write rejected"
            ),)
            .is_err()
        );
        assert_eq!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::ExchangeMayHaveBeenSent)
        );
        let codes: i64 = db
            .query_row("SELECT COUNT(*) FROM oauth_private_codes", [], |row| {
                row.get(0)
            })
            .unwrap();
        let verifiers: i64 = db
            .query_row("SELECT COUNT(*) FROM oauth_private_verifiers", [], |row| {
                row.get(0)
            })
            .unwrap();
        let pending: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM oauth_external_quarantine",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((codes, verifiers, pending), (1, 1, 0));
    }

    #[test]
    fn external_constraints_reject_wrong_tenant_and_subject() {
        let fixture = external_fixture();
        fixture.qualify().unwrap();
        let raw = br#"{"access_token":"secret_external_access","token_type":"Bearer","expires_in":3600,"scope":"calendar.read"}"#;
        let response = fixture
            .reviewed
            .protocol
            .validate_token_response(raw, &fixture.permission)
            .unwrap();
        let (_, mut observed) = mapped_account(&fixture);
        observed.tenant = "other-tenant".into();
        assert!(
            crate::oauth::account::VerifiedExternalAccount::verify(
                &fixture.intent,
                &fixture.requirement,
                &fixture.permission,
                &fixture.instance,
                &observed,
                &response,
            )
            .is_err()
        );
        observed.tenant = "tenant_1".into();
        observed.subject = "other-subject".into();
        assert!(
            crate::oauth::account::VerifiedExternalAccount::verify(
                &fixture.intent,
                &fixture.requirement,
                &fixture.permission,
                &fixture.instance,
                &observed,
                &response,
            )
            .is_err()
        );
    }

    fn mapped_account(fixture: &QualificationFixture) -> (MappedHumanEvidence, ProviderAccount) {
        let mapping = MappedHumanEvidence {
            human: fixture.intent.owner.clone(),
            issuer: fixture.reviewed.issuer_url.clone(),
            provider_subject: "subject_1".into(),
            tenant: "tenant_1".into(),
            mapping_revision: Digest::of(&"mapping-v1").unwrap(),
        };
        let account = ProviderAccount {
            issuer: mapping.issuer.clone(),
            subject: mapping.provider_subject.clone(),
            tenant: mapping.tenant.clone(),
            display_email: "display@example.com".into(),
        };
        (mapping, account)
    }

    fn external_constraints() -> ExternalAccountConstraints {
        let issuer_url = "https://issuer.example/tenant".to_owned();
        let allowed_tenants = BTreeSet::from(["tenant_1".to_owned()]);
        let allowed_subjects = Some(BTreeSet::from(["subject_1".to_owned()]));
        let name = Name::try_from("external_constraints".to_owned()).unwrap();
        let revision = Digest::of(&(
            "oauth-external-account-constraints-v1",
            &name,
            &issuer_url,
            &allowed_tenants,
            &allowed_subjects,
        ))
        .unwrap();
        ExternalAccountConstraints {
            binding: BindingRef { id: name, revision },
            issuer_url,
            allowed_tenants,
            allowed_subjects,
        }
    }

    #[test]
    fn qualified_exchange_encrypts_code_verifier_and_tokens_then_activates_once() {
        let fixture = qualification_fixture();
        let key = exchange_key();
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        connect::install_schema(&db).unwrap();
        let prepared = exchange::prepare_authorization(
            fixture.input(),
            &key,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )
        .unwrap();
        let code_ref = prepared.code_ref().to_owned();
        assert!(prepared.begin(&mut db, 1).unwrap());
        private_callback(&mut db, &fixture, &code_ref, &key);
        let code_ciphertext: Vec<u8> = db
            .query_row("SELECT ciphertext FROM oauth_private_codes", [], |row| {
                row.get(0)
            })
            .unwrap();
        let verifier_ciphertext: Vec<u8> = db
            .query_row(
                "SELECT ciphertext FROM oauth_private_verifiers",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !code_ciphertext
                .windows(b"secret_code".len())
                .any(|w| w == b"secret_code")
        );
        assert!(
            !verifier_ciphertext
                .windows(b"abcdefghij".len())
                .any(|w| w == b"abcdefghij")
        );
        let permit = exchange::authorize_and_commit_qualified_exchange(&mut db, fixture.input(), 3)
            .unwrap()
            .unwrap();
        assert!(
            exchange::authorize_and_commit_qualified_exchange(&mut db, fixture.input(), 3)
                .unwrap()
                .is_none()
        );
        let response = match permit.send(|request| {
            assert_eq!(request.token_endpoint(), fixture.reviewed.token_endpoint);
            assert_eq!(request.code_ref(), code_ref);
            assert_eq!(request.load_code(&db, &key)?, "secret_code");
            assert_eq!(request.load_verifier(&db, &key)?,
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~");
            Ok(TokenHttpResponse {
                status: 200,
                content_type: "application/json".into(),
                body: br#"{"access_token":"secret_access","token_type":"Bearer","expires_in":3600,"scope":"calendar.read"}"#.to_vec(),
            })
        }) {
            ExchangeObservation::Response(response) => response,
            ExchangeObservation::Uncertain(_) => panic!("response lost"),
        };
        let (mapping, observed) = mapped_account(&fixture);
        let verified = response
            .validate_mapped(fixture.input(), &mapping, &observed)
            .unwrap();
        let settlement = verified.prepare_tokens(&key).unwrap();
        assert!(
            exchange::settle_mapped(
                &mut db,
                settlement,
                fixture.input(),
                &mapping.mapping_revision,
                4
            )
            .unwrap()
        );
        assert!(matches!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::Activated { .. })
        ));
        let ciphertext: Vec<u8> = db
            .query_row("SELECT ciphertext FROM oauth_private_tokens", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(
            !ciphertext
                .windows(b"secret_access".len())
                .any(|w| w == b"secret_access")
        );
        let code_count: i64 = db
            .query_row("SELECT COUNT(*) FROM oauth_private_codes", [], |row| {
                row.get(0)
            })
            .unwrap();
        let verifier_count: i64 = db
            .query_row("SELECT COUNT(*) FROM oauth_private_verifiers", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((code_count, verifier_count), (0, 0));
    }

    #[test]
    fn changed_registration_and_lost_response_never_issue_another_permit() {
        let fixture = qualification_fixture();
        let key = exchange_key();
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        connect::install_schema(&db).unwrap();
        let prepared = exchange::prepare_authorization(
            fixture.input(),
            &key,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )
        .unwrap();
        let code_ref = prepared.code_ref().to_owned();
        assert!(prepared.begin(&mut db, 1).unwrap());
        private_callback(&mut db, &fixture, &code_ref, &key);
        let mut changed = fixture.clone();
        changed.instance.registration.client_credential = pin("different_credential");
        assert!(
            exchange::authorize_and_commit_qualified_exchange(&mut db, changed.input(), 3).is_err()
        );
        let permit = exchange::authorize_and_commit_qualified_exchange(&mut db, fixture.input(), 3)
            .unwrap()
            .unwrap();
        let uncertain = match permit.send(|_| Err(anyhow::anyhow!("transport lost response"))) {
            ExchangeObservation::Uncertain(uncertain) => uncertain,
            ExchangeObservation::Response(_) => panic!("unexpected response"),
        };
        assert!(uncertain.record(&db).unwrap());
        assert!(
            exchange::authorize_and_commit_qualified_exchange(&mut db, fixture.input(), 4)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::ExchangeUncertain)
        );
        assert!(connect::expire(&mut db, &fixture.intent.attempt, 101, |_| Ok(())).unwrap());
        let codes: i64 = db
            .query_row("SELECT COUNT(*) FROM oauth_private_codes", [], |row| {
                row.get(0)
            })
            .unwrap();
        let verifiers: i64 = db
            .query_row("SELECT COUNT(*) FROM oauth_private_verifiers", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((codes, verifiers), (0, 0));
    }

    #[test]
    fn failed_private_token_publication_rolls_back_activation() {
        let fixture = qualification_fixture();
        let key = exchange_key();
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        connect::install_schema(&db).unwrap();
        let prepared = exchange::prepare_authorization(
            fixture.input(),
            &key,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )
        .unwrap();
        let code_ref = prepared.code_ref().to_owned();
        assert!(prepared.begin(&mut db, 1).unwrap());
        private_callback(&mut db, &fixture, &code_ref, &key);
        let permit = exchange::authorize_and_commit_qualified_exchange(&mut db, fixture.input(), 3)
            .unwrap()
            .unwrap();
        let response = match permit.send(|_| Ok(TokenHttpResponse {
            status: 200,
            content_type: "application/json".into(),
            body: br#"{"access_token":"secret_access","token_type":"Bearer","expires_in":3600,"scope":"calendar.read"}"#.to_vec(),
        })) {
            ExchangeObservation::Response(response) => response,
            ExchangeObservation::Uncertain(_) => panic!("response lost"),
        };
        let (mapping, observed) = mapped_account(&fixture);
        let settlement = response
            .validate_mapped(fixture.input(), &mapping, &observed)
            .unwrap()
            .prepare_tokens(&key)
            .unwrap();
        db.execute_batch(
            "CREATE TRIGGER reject_oauth_token BEFORE INSERT ON oauth_private_tokens
             BEGIN SELECT RAISE(ABORT, 'token write rejected'); END;",
        )
        .unwrap();
        assert!(
            exchange::settle_mapped(
                &mut db,
                settlement,
                fixture.input(),
                &mapping.mapping_revision,
                4
            )
            .is_err()
        );
        assert_eq!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::ExchangeMayHaveBeenSent)
        );
        let tokens: i64 = db
            .query_row("SELECT COUNT(*) FROM oauth_private_tokens", [], |row| {
                row.get(0)
            })
            .unwrap();
        let codes: i64 = db
            .query_row("SELECT COUNT(*) FROM oauth_private_codes", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((tokens, codes), (0, 1));
    }

    fn rejects(fixture: &QualificationFixture, reason: &str) {
        let error = fixture.qualify().err().unwrap().to_string();
        assert!(error.contains(reason), "unexpected rejection: {error}");
    }

    #[test]
    fn qualified_instance_can_begin_one_exact_attempt() {
        let fixture = qualification_fixture();
        fixture.qualify().unwrap();
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        connect::install_schema(&db).unwrap();
        assert!(fixture.begin(&mut db).unwrap());
        assert_eq!(
            connect::state(&db, &fixture.intent.attempt).unwrap(),
            Some(ConnectState::AwaitingProviderAuthorization)
        );
        assert!(!fixture.begin(&mut db).unwrap());
    }

    #[test]
    fn substitution_of_instance_profile_registration_or_origin_fails() {
        let fixture = qualification_fixture();
        let mut changed = fixture.clone();
        changed.instance.registration.instance = pin("other_installation");
        rejects(&changed, "cross-instance security or registration binding");
        let mut changed = fixture.clone();
        changed.instance.registration.profile = pin("other_profile");
        assert!(changed.qualify().is_err());
        let mut changed = fixture.clone();
        changed.instance.registration.class = ClientRegistrationClass::PublicPkceS256;
        rejects(&changed, "unsupported provider registration class");
        let mut changed = fixture.clone();
        changed.instance.registration.issuer = ProviderIssuerRef(pin("other_issuer"));
        assert!(changed.qualify().is_err());
        let mut changed = fixture.clone();
        changed.instance.app_origin_url = changed.instance.shell.origin_url.clone();
        rejects(&changed, "origins must be isolated");
        let mut changed = fixture.clone();
        changed.instance.registration.callback_url = "https://app.example/return".into();
        rejects(&changed, "derived callback");
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        connect::install_schema(&db).unwrap();
        assert!(changed.begin(&mut db).is_err());
        assert_eq!(connect::state(&db, &changed.intent.attempt).unwrap(), None);
        let mut changed = fixture.clone();
        changed.intent.registration = Digest::of(&pin("new_registration"))
            .unwrap()
            .as_str()
            .into();
        assert!(changed.qualify().is_err());
        let mut changed = fixture.clone();
        changed.instance.product_return = ProductReturnRef(pin("unapproved_return"));
        assert!(changed.qualify().is_err());
        let mut changed = fixture.clone();
        changed.instance.shell.instance = pin("other_installation");
        assert!(changed.qualify().is_err());
        let mut changed = fixture.clone();
        changed.instance.account = AccountBindingEvidence::ExplicitExternal {
            instance: fixture.instance.instance.clone(),
            approval: pin("approval"),
            constraints: external_constraints(),
            owner: fixture.intent.owner.clone(),
        };
        rejects(&changed, "account evidence does not match");
    }

    #[test]
    fn changed_review_or_registration_evidence_needs_a_new_revision() {
        let fixture = qualification_fixture();
        let mut changed = fixture.clone();
        changed.reviewed.token_endpoint = "https://tokens.example/v2/token".into();
        rejects(&changed, "profile revision mismatch");
        let mut changed = fixture.clone();
        changed.reviewed.account_evidence = AccountEvidenceContract::ExternalAccount;
        assert!(changed.qualify().is_err());
        let mut changed = fixture.clone();
        changed.instance.registration.provider_confirmation = Digest::of(&"revoked").unwrap();
        rejects(&changed, "registration evidence revision mismatch");
        let mut changed = fixture.clone();
        changed.instance.shell.qualification = Digest::of(&"shell-replaced").unwrap();
        rejects(&changed, "security shell evidence revision mismatch");
        for invalid in [
            "http://issuer.example/",
            "https://user:pass@issuer.example/",
            "https://issuer.example/#fragment",
            "https://issuer.example/?query=1",
        ] {
            assert!(https_url(invalid, true).is_err());
        }
    }

    fn permission() -> ProviderPermissionContract {
        ProviderPermissionContract {
            requirement: Digest::of(&"requirement").unwrap(),
            profile: BindingRef::pin(
                Name::try_from("browser_code_v1".to_owned()).unwrap(),
                &"profile",
            )
            .unwrap(),
            action_scopes: BTreeMap::from([(
                "read".into(),
                BTreeSet::from(["calendar.read".into()]),
            )]),
            interpretation: Digest::of(&"scope-map-v1").unwrap(),
        }
    }

    fn profile(permission: &ProviderPermissionContract) -> ConfidentialPkceProfile {
        ConfidentialPkceProfile::Rotating {
            identity: BrowserCodeIdentity {
                binding: permission.profile.clone(),
                scope_interpretation: permission.interpretation.clone(),
            },
            recovery: RotatingRecovery::ReauthorizeOnUncertainty,
        }
    }

    #[test]
    fn exact_rotating_exchange_is_accepted_without_exposing_secrets_in_debug() {
        let permission = permission();
        let response = profile(&permission)
            .validate_token_response(
                br#"{"access_token":"secret_access","token_type":"Bearer","expires_in":3600,"refresh_token":"secret_refresh","scope":"calendar.read"}"#,
                &permission,
            )
            .unwrap();
        assert!(response.matches_permission(&permission));
        assert_eq!(response.scopes(), &BTreeSet::from(["calendar.read".into()]));
        let (access, refresh, expires) = response.into_private_tokens();
        assert_eq!(
            (access.as_str(), refresh.as_deref(), expires),
            ("secret_access", Some("secret_refresh"), 3600)
        );
    }

    #[test]
    fn response_rejects_missing_extra_duplicate_and_malformed_fields() {
        let permission = permission();
        let profile = profile(&permission);
        for raw in [
            br#"{"access_token":"a","token_type":"Bearer","expires_in":3600,"scope":"calendar.read"}"#.as_slice(),
            br#"{"access_token":"a","token_type":"Bearer","expires_in":3600,"refresh_token":"r","scope":"calendar.write"}"#,
            br#"{"access_token":"a","token_type":"Bearer","expires_in":3600,"refresh_token":"r","scope":"calendar.read calendar.read"}"#,
            br#"{"access_token":"a","token_type":"Bearer","expires_in":3600,"refresh_token":"r","scope":"calendar.read","id_token":"unreviewed"}"#,
            br#"{"access_token":"a","access_token":"b","token_type":"Bearer","expires_in":3600,"refresh_token":"r","scope":"calendar.read"}"#,
            br#"{"access_token":"a","token_type":"MAC","expires_in":3600,"refresh_token":"r","scope":"calendar.read"}"#,
        ] {
            assert!(profile.validate_token_response(raw, &permission).is_err());
        }
    }

    #[test]
    fn refresh_contract_and_profile_identity_are_exact() {
        let permission = permission();
        let rotating = profile(&permission);
        let no_refresh = ConfidentialPkceProfile::NoRefresh(rotating.identity().clone());
        let reusable = ConfidentialPkceProfile::Reusable {
            identity: rotating.identity().clone(),
            retry: ReusableRetry::NoAutomaticRetry,
        };
        let without_refresh = br#"{"access_token":"a","token_type":"Bearer","expires_in":3600,"scope":"calendar.read"}"#;
        let with_refresh = br#"{"access_token":"a","token_type":"Bearer","expires_in":3600,"refresh_token":"r","scope":"calendar.read"}"#;
        assert!(
            no_refresh
                .validate_token_response(without_refresh, &permission)
                .is_ok()
        );
        assert!(
            no_refresh
                .validate_token_response(with_refresh, &permission)
                .is_err()
        );
        assert!(
            reusable
                .validate_token_response(without_refresh, &permission)
                .is_err()
        );
        let mut changed = permission;
        changed.interpretation = Digest::of(&"new-map").unwrap();
        assert!(
            rotating
                .validate_token_response(with_refresh, &changed)
                .is_err()
        );
    }
}
