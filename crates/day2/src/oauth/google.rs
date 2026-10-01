//! Reviewed Google Calendar browser-code profiles. These are native host
//! contracts, not an instance-authored scope map or an app token API.

use super::{admission, profiles};
use anyhow::{Result, ensure};
use day2_capabilities::{BindingRef, Digest, Name, oauth::AccountBindingPolicy};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const ISSUER: &str = "https://accounts.google.com";
pub(super) const AUTHORIZATION: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub(super) const TOKEN: &str = "https://oauth2.googleapis.com/token";
pub(super) const USERINFO: &str = "https://openidconnect.googleapis.com/v1/userinfo";
pub(super) const CAPABILITY: &str = "google_calendar_events";
const EMAIL: &str = "https://www.googleapis.com/auth/userinfo.email";

fn pin(id: &str, contract: impl serde::Serialize) -> Result<BindingRef> {
    BindingRef::pin(Name::try_from(id.to_owned())?, &contract)
}

fn scopes() -> BTreeMap<String, BTreeSet<String>> {
    [
        (
            "list_events",
            "https://www.googleapis.com/auth/calendar.events.readonly",
        ),
        (
            "create_event",
            "https://www.googleapis.com/auth/calendar.events",
        ),
    ]
    .into_iter()
    .map(|(action, permission)| {
        (
            action.to_owned(),
            BTreeSet::from(["openid".into(), EMAIL.into(), permission.into()]),
        )
    })
    .collect()
}

pub(super) fn reviewed(policy: &AccountBindingPolicy) -> Result<admission::ReviewedAccess> {
    let (id, account_evidence) = match policy {
        AccountBindingPolicy::MappedHuman => (
            "google_calendar_mapped_v1",
            profiles::AccountEvidenceContract::MappedHuman,
        ),
        AccountBindingPolicy::ExplicitExternalAccount => (
            "google_calendar_external_v1",
            profiles::AccountEvidenceContract::ExternalAccount,
        ),
        AccountBindingPolicy::InstallationAccount => {
            anyhow::bail!("Google Calendar installation OAuth is not reviewed")
        }
    };
    let action_scopes = scopes();
    let identity = profiles::BrowserCodeIdentity {
        binding: pin(id, "pending-profile-revision")?,
        scope_interpretation: Digest::of(&(
            "oauth-semantic-scope-map-v1",
            CAPABILITY,
            &action_scopes,
        ))?,
    };
    let mut profile = profiles::ReviewedBrowserCodeProfile {
        protocol: profiles::ConfidentialPkceProfile::Reusable {
            identity,
            retry: profiles::ReusableRetry::NoAutomaticRetry,
        },
        issuer: day2_capabilities::oauth::ProviderIssuerRef(pin(
            "google_issuer",
            ("google-issuer-v1", ISSUER),
        )?),
        issuer_url: ISSUER.into(),
        authorization_endpoint: AUTHORIZATION.into(),
        token_endpoint: TOKEN.into(),
        adapter: pin(
            "google_calendar_wire_v1",
            (
                "google-calendar-wire-v1",
                TOKEN,
                USERINFO,
                "confidential-pkce-s256;offline;exact-scopes;verified-sub-hd-email;no-retry;grant-wide-revoke",
            ),
        )?,
        simulator: pin(
            "google_calendar_simulator_v1",
            "google-calendar-registration-reference-v1",
        )?,
        conformance: pin(
            "google_calendar_conformance_v1",
            "google-calendar-registration-wire-campaign-v1",
        )?,
        account_evidence,
    };
    let revision = profile.review_revision()?;
    let profiles::ConfidentialPkceProfile::Reusable { identity, .. } = &mut profile.protocol else {
        unreachable!()
    };
    identity.binding.revision = revision;
    Ok(admission::ReviewedAccess {
        profile,
        capability: CAPABILITY.into(),
        action_scopes,
    })
}

pub(crate) fn catalog() -> Result<admission::ReviewedCatalog> {
    admission::ReviewedCatalog::new(vec![
        reviewed(&AccountBindingPolicy::MappedHuman)?,
        reviewed(&AccountBindingPolicy::ExplicitExternalAccount)?,
    ])
}

/// Google canonicalizes the documented `email` alias in token scope responses.
/// Only that reviewed identity alias is normalized; Calendar scopes stay exact.
pub(super) fn normalize_scope(raw: &str) -> Result<String> {
    ensure!(
        !raw.is_empty() && raw.len() <= 8192,
        "invalid Google scope response"
    );
    let mut scopes = BTreeSet::new();
    for scope in raw.split(' ') {
        let scope = if scope == "email" { EMAIL } else { scope };
        ensure!(
            !scope.is_empty()
                && scope.len() <= 256
                && scope
                    .bytes()
                    .all(|b| b == b'!' || (b'#'..=b'[').contains(&b) || (b']'..=b'~').contains(&b))
                && scopes.insert(scope),
            "invalid Google scope response"
        );
    }
    ensure!(scopes.len() <= 32, "Google scope budget");
    Ok(scopes.into_iter().collect::<Vec<_>>().join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2_capabilities::oauth::{ConnectionOwner, ConnectionRequirement};

    #[test]
    fn reviewed_google_profiles_bind_semantics_endpoints_and_account_policy() -> Result<()> {
        let catalog = catalog()?;
        let mut requirement = ConnectionRequirement {
            logical_id: "work_calendar".into(),
            revision: 1,
            capability: CAPABILITY.into(),
            actions: BTreeSet::from(["list_events".into()]),
            owner: ConnectionOwner::CurrentHuman,
            account_policy: AccountBindingPolicy::MappedHuman,
            usage: "Read work availability.".into(),
        };
        let mapped = reviewed(&requirement.account_policy)?.profile;
        let binding = mapped.protocol.identity().binding.clone();
        let (_, permission) = catalog.resolve(&requirement, &binding)?;
        assert_eq!(
            permission.action_scopes["list_events"],
            BTreeSet::from([
                "openid".into(),
                EMAIL.into(),
                "https://www.googleapis.com/auth/calendar.events.readonly".into(),
            ])
        );
        requirement.actions.insert("create_event".into());
        let (_, write) = catalog.resolve(&requirement, &binding)?;
        assert!(
            write.action_scopes["create_event"]
                .contains("https://www.googleapis.com/auth/calendar.events")
        );
        assert_ne!(
            permission.consent_digest(&ConnectionRequirement {
                actions: BTreeSet::from(["list_events".into()]),
                ..requirement.clone()
            })?,
            write.consent_digest(&requirement)?
        );
        requirement.account_policy = AccountBindingPolicy::ExplicitExternalAccount;
        assert!(catalog.resolve(&requirement, &binding).is_err());
        let external = reviewed(&requirement.account_policy)?.profile;
        assert_ne!(external.protocol.identity().binding, binding);
        catalog.resolve(&requirement, &external.protocol.identity().binding)?;
        requirement.actions.insert("delete_event".into());
        assert!(
            catalog
                .resolve(&requirement, &external.protocol.identity().binding)
                .is_err()
        );
        assert!(reviewed(&AccountBindingPolicy::InstallationAccount).is_err());
        assert_eq!(mapped.issuer_url, ISSUER);
        assert_eq!(mapped.token_endpoint, TOKEN);
        assert_eq!(mapped.authorization_endpoint, AUTHORIZATION);
        Ok(())
    }

    #[test]
    fn scope_alias_does_not_accept_duplicate_or_broader_scopes() -> Result<()> {
        assert_eq!(normalize_scope("openid email")?, format!("{EMAIL} openid"));
        for raw in [
            "email email",
            "email https://www.googleapis.com/auth/userinfo.email",
            "openid  email",
            "openid\temail",
        ] {
            assert!(normalize_scope(raw).is_err());
        }
        assert_eq!(
            normalize_scope("https://www.googleapis.com/auth/calendar")?,
            "https://www.googleapis.com/auth/calendar"
        );
        Ok(())
    }
}
