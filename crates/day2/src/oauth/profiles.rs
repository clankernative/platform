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
    fn identity(&self) -> &BrowserCodeIdentity {
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundInstanceEvidence {
    pub instance: BindingRef,
    pub app_origin_url: String,
    pub shell: SecurityShellEvidence,
    pub registration: ProviderRegistrationEvidence,
    pub account: AccountBindingEvidence,
    pub product_return: ProductReturnRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityShellEvidence {
    pub instance: BindingRef,
    pub origin: SecurityOriginRef,
    pub origin_url: String,
    pub qualification: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRegistrationEvidence {
    pub instance: BindingRef,
    pub registration: BindingRef,
    pub profile: BindingRef,
    pub issuer: ProviderIssuerRef,
    pub security_origin: SecurityOriginRef,
    pub callback: ProviderCallbackRef,
    pub callback_url: String,
    pub provider_confirmation: Digest,
    pub class: ClientRegistrationClass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ClientRegistrationClass {
    ConfidentialPkceS256,
    PublicPkceS256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountBindingEvidence {
    MappedHuman {
        instance: BindingRef,
        mapping: BindingRef,
        owner: String,
    },
    ExplicitExternal {
        instance: BindingRef,
        approval: BindingRef,
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
    let derived =
        ProviderCallbackRef::derive(&instance.shell.origin, &permission.profile, &intent.slot)?;
    ensure!(
        binding.binding_namespace() == intent.slot
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
mod tests {
    use super::*;
    use crate::oauth::connect::{
        self, CallbackBinding, CallbackBindingSpec, ConnectIntent, ConnectState,
    };
    use day2_capabilities::Name;
    use day2_capabilities::oauth::{ConnectionOwner, ProductReturnRef};
    use std::collections::BTreeMap;

    fn pin(name: &str) -> BindingRef {
        BindingRef::pin(Name::try_from(name.to_owned()).unwrap(), &name).unwrap()
    }

    #[derive(Clone)]
    struct QualificationFixture {
        intent: ConnectIntent,
        binding: CallbackBinding,
        requirement: ConnectionRequirement,
        permission: ProviderPermissionContract,
        reviewed: ReviewedBrowserCodeProfile,
        instance: OutboundInstanceEvidence,
    }

    impl QualificationFixture {
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
        let requirement = ConnectionRequirement {
            logical_id: "workspace.calendar".into(),
            revision: 1,
            capability: "calendar.events".into(),
            actions: BTreeSet::from(["read".into()]),
            owner: ConnectionOwner::CurrentHuman,
            account_policy: AccountBindingPolicy::MappedHuman,
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
            account_evidence: AccountEvidenceContract::MappedHuman,
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
                class,
            },
            account: AccountBindingEvidence::MappedHuman {
                instance: instance_ref,
                mapping: pin("human_subject_map"),
                owner: "human_1".into(),
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
