//! Reviewed GitLab.com confidential PKCE adapter: explicit external accounts,
//! exact read-only scopes, rotating refresh, reauthorization after uncertainty.
//! No arbitrary self-hosted endpoint or account-to-shell identity inference.
use super::{admission, profiles};
use anyhow::{Result, ensure};
use day2_capabilities::{BindingRef, Digest, Name};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const ISSUER: &str = "https://gitlab.com";
pub(super) const AUTHORIZATION: &str = "https://gitlab.com/oauth/authorize";
pub(super) const TOKEN: &str = "https://gitlab.com/oauth/token";
pub(super) const TOKEN_INFO: &str = "https://gitlab.com/oauth/token/info";
pub(super) const USERINFO: &str = "https://gitlab.com/api/v4/user";
pub(super) const CAPABILITY: &str = "gitlab_projects";

pub(super) fn validate_canary(canary: &day2_capabilities::oauth::RegistrationCanary) -> Result<()> {
    ensure!(
        canary
            .provider_subject
            .parse::<u64>()
            .is_ok_and(|id| id > 0 && id.to_string() == canary.provider_subject)
            && canary.provider_tenant == "gitlab.com",
        "invalid GitLab canary identity"
    );
    Ok(())
}

pub(super) fn tokens(
    raw: &[u8],
    context: super::catalog::TokenContext<'_>,
    wire: &super::registration::Wire,
) -> Result<super::catalog::Tokens> {
    let raw: Tokens =
        crate::json::decode(raw).map_err(|_| anyhow::anyhow!("invalid GitLab token response"))?;
    ensure!(
        !raw.access_token.is_empty()
            && raw.access_token.len() <= 8192
            && raw.access_token.bytes().all(|b| b.is_ascii_graphic()),
        "invalid GitLab access token"
    );
    let normalized = raw.normalized(
        &wire.token_info(&raw.access_token)?,
        context.client_id,
        context.subject,
    )?;
    context
        .reviewed
        .protocol
        .validate_token_response(&normalized, context.permission)?;
    ensure!(
        raw.refresh_token.bytes().all(|b| b.is_ascii_graphic()),
        "invalid GitLab refresh token"
    );
    Ok(super::catalog::Tokens {
        access: raw.access_token,
        refresh: Some(raw.refresh_token),
    })
}

pub(super) fn reviewed() -> Result<admission::ReviewedAccess> {
    let pin = |name: &str, value: &str| BindingRef::pin(Name::try_from(name.to_owned())?, &value);
    let action_scopes = BTreeMap::from([(
        "list_projects".into(),
        BTreeSet::from(["read_api".into(), "read_user".into()]),
    )]);
    let identity = profiles::BrowserCodeIdentity {
        binding: pin("gitlab_projects_external_v1", "pending-profile-revision")?,
        scope_interpretation: Digest::of(&(
            "oauth-semantic-scope-map-v1",
            CAPABILITY,
            &action_scopes,
        ))?,
    };
    let mut profile = profiles::ReviewedBrowserCodeProfile {
        protocol: profiles::ConfidentialPkceProfile::Rotating {
            identity,
            recovery: profiles::RotatingRecovery::ReauthorizeOnUncertainty,
        },
        issuer: day2_capabilities::oauth::ProviderIssuerRef(pin("gitlab_issuer", ISSUER)?),
        issuer_url: ISSUER.into(),
        authorization_endpoint: AUTHORIZATION.into(),
        token_endpoint: TOKEN.into(),
        adapter: BindingRef::pin(
            Name::try_from("gitlab_projects_wire_v1".to_owned())?,
            &(
                "gitlab-projects-wire-v1",
                TOKEN,
                TOKEN_INFO,
                USERINFO,
                "confidential-pkce-s256;exact-token-info-scopes-client-subject;numeric-active-account;rotating;reauthorize-on-uncertainty;no-retry",
            ),
        )?,
        simulator: pin(
            "gitlab_projects_simulator_v1",
            "gitlab-projects-registration-reference-v1",
        )?,
        conformance: pin(
            "gitlab_projects_conformance_v1",
            "gitlab-projects-registration-wire-campaign-v1",
        )?,
        account_evidence: profiles::AccountEvidenceContract::ExternalAccount,
    };
    let revision = profile.review_revision()?;
    let profiles::ConfidentialPkceProfile::Rotating { identity, .. } = &mut profile.protocol else {
        unreachable!()
    };
    identity.binding.revision = revision;
    Ok(admission::ReviewedAccess {
        profile,
        capability: CAPABILITY.into(),
        action_scopes,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    token_type: String,
    expires_in: u64,
    created_at: u64,
    scope: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenInfo {
    resource_owner_id: u64,
    scope: Vec<String>,
    scopes: Option<Vec<String>>,
    expires_in: u64,
    expires_in_seconds: Option<u64>,
    application: Application,
    created_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Application {
    uid: String,
}

impl Tokens {
    /// Scope omission never means requested scopes were granted. The fixed TLS
    /// token-info endpoint must establish exact client, owner and scope evidence.
    pub(super) fn normalized(&self, info: &[u8], client: &str, subject: &str) -> Result<Vec<u8>> {
        let info: TokenInfo = crate::json::decode(info)
            .map_err(|_| anyhow::anyhow!("invalid GitLab token evidence"))?;
        let scopes = info.scope.iter().cloned().collect::<BTreeSet<_>>();
        ensure!(
            matches!(self.token_type.as_str(), "bearer" | "Bearer")
                && info.application.uid == client
                && info.resource_owner_id > 0
                && info.resource_owner_id.to_string() == subject
                && info.expires_in > 0
                && info.expires_in <= self.expires_in
                && info.created_at == self.created_at
                && scopes.len() == info.scope.len()
                && info
                    .scopes
                    .as_ref()
                    .is_none_or(|alias| alias == &info.scope)
                && info
                    .expires_in_seconds
                    .is_none_or(|alias| alias == info.expires_in)
                && !scopes.is_empty()
                && scopes.len() <= 32,
            "GitLab token evidence mismatch"
        );
        if let Some(scope) = &self.scope {
            let values = scope.split(' ').map(str::to_owned).collect::<Vec<_>>();
            ensure!(
                values.len() == scopes.len()
                    && values.into_iter().collect::<BTreeSet<_>>() == scopes,
                "GitLab scope evidence mismatch"
            );
        }
        #[derive(Serialize)]
        struct Normalized<'a> {
            access_token: &'a str,
            refresh_token: &'a str,
            token_type: &'a str,
            expires_in: u64,
            scope: String,
        }
        Ok(serde_json::to_vec(&Normalized {
            access_token: &self.access_token,
            refresh_token: &self.refresh_token,
            token_type: "Bearer",
            expires_in: self.expires_in,
            scope: scopes.into_iter().collect::<Vec<_>>().join(" "),
        })?)
    }
}

pub(super) fn account(raw: &[u8], subject: &str, tenant: &str) -> Result<()> {
    // GitLab's user resource has additional public profile fields; consume only
    // the reviewed identity fields, never accept those fields as configuration.
    #[derive(Deserialize)]
    struct User {
        id: u64,
        state: String,
        locked: bool,
    }
    let account: User =
        crate::json::decode(raw).map_err(|_| anyhow::anyhow!("invalid GitLab account evidence"))?;
    ensure!(
        account.id > 0
            && account.id.to_string() == subject
            && tenant == "gitlab.com"
            && account.state == "active"
            && !account.locked,
        "GitLab account mismatch"
    );
    Ok(())
}
