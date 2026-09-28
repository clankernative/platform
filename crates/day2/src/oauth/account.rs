//! Stable provider account verification for the mapped-human policy. Display
//! email and provider list order never participate in account selection.

use super::connect::ConnectIntent;
use super::profiles::ValidatedTokenResponse;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use day2_capabilities::oauth::{
    AccountBindingPolicy, ConnectionRequirement, ProviderPermissionContract,
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderAccount {
    pub issuer: String,
    pub subject: String,
    pub tenant: String,
    /// Presentation only; never compared for linkage or account identity.
    pub display_email: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedHumanEvidence {
    pub human: String,
    pub issuer: String,
    pub provider_subject: String,
    pub tenant: String,
    pub mapping_revision: Digest,
}

#[derive(Clone, Debug)]
pub struct VerifiedMappedAccount {
    intent: ConnectIntent,
    mapping_revision: Digest,
    account: String,
    scope_evidence: String,
}

impl VerifiedMappedAccount {
    pub fn verify(
        intent: &ConnectIntent,
        requirement: &ConnectionRequirement,
        permission: &ProviderPermissionContract,
        mapping: &MappedHumanEvidence,
        observed: &ProviderAccount,
        response: &ValidatedTokenResponse,
    ) -> Result<Self> {
        ensure!(
            response.matches_permission(permission),
            "token response does not match account consent"
        );
        Self::verify_scopes(
            intent,
            requirement,
            permission,
            mapping,
            observed,
            response.scopes(),
        )
    }

    fn verify_scopes(
        intent: &ConnectIntent,
        requirement: &ConnectionRequirement,
        permission: &ProviderPermissionContract,
        mapping: &MappedHumanEvidence,
        observed: &ProviderAccount,
        returned_scopes: &BTreeSet<String>,
    ) -> Result<Self> {
        ensure!(
            requirement.account_policy == AccountBindingPolicy::MappedHuman,
            "mapped human evidence used for another account policy"
        );
        let consent = permission.consent_digest(requirement)?;
        ensure!(
            intent.consent == consent.as_str() && intent.profile == permission.profile.id.as_str(),
            "account verification does not match the consented profile"
        );
        ensure!(
            mapping.human == intent.owner
                && observed.issuer == mapping.issuer
                && observed.subject == mapping.provider_subject
                && observed.tenant == mapping.tenant,
            "provider account does not match the admitted human mapping"
        );
        stable_part(&observed.issuer)?;
        stable_part(&observed.subject)?;
        stable_part(&observed.tenant)?;
        let required = permission
            .action_scopes
            .values()
            .flat_map(|scopes| scopes.iter().cloned())
            .collect::<BTreeSet<_>>();
        ensure!(
            returned_scopes == &required,
            "provider returned missing or unreviewed scopes"
        );
        let account = Digest::of(&(
            "oauth-provider-account-v1",
            &observed.issuer,
            &observed.subject,
            &observed.tenant,
        ))?;
        let scope_evidence = Digest::of(&("oauth-accepted-scopes-v1", &consent, returned_scopes))?;
        Ok(Self {
            intent: intent.clone(),
            mapping_revision: mapping.mapping_revision.clone(),
            account: account.as_str().to_owned(),
            scope_evidence: scope_evidence.as_str().to_owned(),
        })
    }

    pub fn matches_attempt(&self, intent: &ConnectIntent) -> bool {
        &self.intent == intent
    }

    pub fn matches_current_mapping(&self, revision: &Digest) -> bool {
        &self.mapping_revision == revision
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn scope_evidence(&self) -> &str {
        &self.scope_evidence
    }

    pub fn attempt(&self) -> &str {
        &self.intent.attempt
    }

    pub(super) fn intent(&self) -> &ConnectIntent {
        &self.intent
    }
}

fn stable_part(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
        "invalid stable provider account identity"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::profiles::{BrowserCodeIdentity, ConfidentialPkceProfile};
    use day2_capabilities::oauth::ConnectionOwner;
    use day2_capabilities::{BindingRef, Name};
    use std::collections::BTreeMap;

    fn fixture() -> (
        ConnectIntent,
        ConnectionRequirement,
        ProviderPermissionContract,
        MappedHumanEvidence,
        ProviderAccount,
        BTreeSet<String>,
    ) {
        let requirement = ConnectionRequirement {
            logical_id: "workspace.calendar".into(),
            revision: 1,
            capability: "google.calendar.events".into(),
            actions: BTreeSet::from(["list".into()]),
            owner: ConnectionOwner::CurrentHuman,
            account_policy: AccountBindingPolicy::MappedHuman,
            usage: "Find meetings".into(),
        };
        let permission = ProviderPermissionContract {
            requirement: requirement.nominal_identity().unwrap(),
            profile: BindingRef::pin(
                Name::try_from("google_calendar_v1".to_owned()).unwrap(),
                &"profile",
            )
            .unwrap(),
            action_scopes: BTreeMap::from([(
                "list".into(),
                BTreeSet::from(["calendar.read".into()]),
            )]),
            interpretation: Digest::of(&"google-calendar-scope-v1").unwrap(),
        };
        let intent = ConnectIntent {
            attempt: "attempt_1".into(),
            slot: "slot_1".into(),
            expected_generation: None,
            expected_epoch: 1,
            proposed_generation: 1,
            owner: "human_1".into(),
            profile: permission.profile.id.as_str().into(),
            registration: "registration_1".into(),
            callback: "callback_1".into(),
            consent: permission
                .consent_digest(&requirement)
                .unwrap()
                .as_str()
                .into(),
            expires_at: 100,
        };
        let mapping = MappedHumanEvidence {
            human: "human_1".into(),
            issuer: "https://accounts.google.com".into(),
            provider_subject: "stable-subject-1".into(),
            tenant: "company-tenant".into(),
            mapping_revision: Digest::of(&"mapping-v1").unwrap(),
        };
        let observed = ProviderAccount {
            issuer: mapping.issuer.clone(),
            subject: mapping.provider_subject.clone(),
            tenant: mapping.tenant.clone(),
            display_email: "person@example.com".into(),
        };
        (
            intent,
            requirement,
            permission,
            mapping,
            observed,
            BTreeSet::from(["calendar.read".into()]),
        )
    }

    #[test]
    fn first_account_requires_exact_stable_mapping_not_email() {
        let (intent, requirement, permission, mapping, observed, scopes) = fixture();
        let profile = ConfidentialPkceProfile::NoRefresh(BrowserCodeIdentity {
            binding: permission.profile.clone(),
            scope_interpretation: permission.interpretation.clone(),
        });
        let response = profile
            .validate_token_response(
                br#"{"access_token":"secret_access","token_type":"Bearer","expires_in":3600,"scope":"calendar.read"}"#,
                &permission,
            )
            .unwrap();
        let verified = VerifiedMappedAccount::verify(
            &intent,
            &requirement,
            &permission,
            &mapping,
            &observed,
            &response,
        )
        .unwrap();
        let mut different_registration = intent.clone();
        different_registration.registration = "registration_2".into();
        assert!(!verified.matches_attempt(&different_registration));
        let mut different_epoch = intent.clone();
        different_epoch.expected_epoch += 1;
        assert!(!verified.matches_attempt(&different_epoch));
        let mut colliding_email = observed.clone();
        colliding_email.subject = "personal-subject".into();
        assert_eq!(colliding_email.display_email, observed.display_email);
        assert!(
            VerifiedMappedAccount::verify_scopes(
                &intent,
                &requirement,
                &permission,
                &mapping,
                &colliding_email,
                &scopes,
            )
            .is_err()
        );
        let mut changed_display = observed.clone();
        changed_display.display_email = "renamed@example.com".into();
        let same = VerifiedMappedAccount::verify_scopes(
            &intent,
            &requirement,
            &permission,
            &mapping,
            &changed_display,
            &scopes,
        )
        .unwrap();
        assert_eq!(verified.account(), same.account());
    }

    #[test]
    fn missing_or_extra_scopes_and_wrong_owner_fail_verification() {
        let (intent, requirement, permission, mapping, observed, scopes) = fixture();
        assert!(
            VerifiedMappedAccount::verify_scopes(
                &intent,
                &requirement,
                &permission,
                &mapping,
                &observed,
                &BTreeSet::new(),
            )
            .is_err()
        );
        let mut excess = scopes.clone();
        excess.insert("calendar.write".into());
        assert!(
            VerifiedMappedAccount::verify_scopes(
                &intent,
                &requirement,
                &permission,
                &mapping,
                &observed,
                &excess,
            )
            .is_err()
        );
        let mut wrong_owner = mapping;
        wrong_owner.human = "human_2".into();
        assert!(
            VerifiedMappedAccount::verify_scopes(
                &intent,
                &requirement,
                &permission,
                &wrong_owner,
                &observed,
                &scopes,
            )
            .is_err()
        );
    }

    #[test]
    fn mapped_activation_uses_verified_binding() {
        let (intent, requirement, permission, mapping, observed, scopes) = fixture();
        let verified = VerifiedMappedAccount::verify_scopes(
            &intent,
            &requirement,
            &permission,
            &mapping,
            &observed,
            &scopes,
        )
        .unwrap();
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        crate::oauth::connect::install_schema(&db).unwrap();
        assert!(crate::oauth::connect::begin(&mut db, &intent, 1).unwrap());
        assert!(
            crate::oauth::connect::claim_callback(
                &mut db,
                &intent.attempt,
                "private_code_1",
                2,
                |_| Ok(()),
            )
            .unwrap()
        );
        crate::oauth::connect::authorize_and_commit_exchange(&mut db, &intent.attempt, 3)
            .unwrap()
            .unwrap()
            .send(|_, _| ());
        assert!(
            !crate::oauth::connect::activate_mapped(
                &mut db,
                &verified,
                &Digest::of(&"new-mapping").unwrap(),
                4,
                |_| Ok(())
            )
            .unwrap()
        );
        assert!(
            crate::oauth::connect::activate_mapped(
                &mut db,
                &verified,
                &mapping.mapping_revision,
                4,
                |_| Ok(())
            )
            .unwrap()
        );
        let account: String = db
            .query_row("SELECT account FROM oauth_connection_slots", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(account, verified.account());
    }
}
