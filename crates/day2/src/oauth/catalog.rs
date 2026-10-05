//! Explicit reviewed extension registry. Instances select these contracts;
//! neither configuration nor callback input can supply adapter code or scopes.
use super::{admission, gitlab, google, profiles};
use anyhow::{Result, ensure};
use day2_capabilities::{
    BindingRef,
    oauth::{ConnectionRequirement, ProviderClient},
};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Adapter {
    GoogleCalendar,
    GitlabProjects,
}

/// Private adapter result; no serialization, debug formatting or app token API.
pub(super) struct Tokens {
    pub access: String,
    pub refresh: Option<String>,
}

pub(super) struct TokenContext<'a> {
    pub reviewed: &'a profiles::ReviewedBrowserCodeProfile,
    pub permission: &'a day2_capabilities::oauth::ProviderPermissionContract,
    pub client_id: &'a str,
    pub subject: &'a str,
}

pub(crate) fn reviewed() -> Result<admission::ReviewedCatalog> {
    use day2_capabilities::oauth::AccountBindingPolicy::{ExplicitExternalAccount, MappedHuman};
    admission::ReviewedCatalog::new(vec![
        google::reviewed(&MappedHuman)?,
        google::reviewed(&ExplicitExternalAccount)?,
        gitlab::reviewed()?,
    ])
}

/// These semantic sets mirror the explicit SDK modules. A new provider for an
/// existing semantic contract does not change declaration admission or kernels.
pub(super) fn validate_access(requirement: &ConnectionRequirement) -> Result<()> {
    let actions = &requirement.actions;
    let accepted = match requirement.capability.as_str() {
        google::CAPABILITY => {
            actions == &BTreeSet::from(["list_events".into()])
                || actions == &BTreeSet::from(["list_events".into(), "create_event".into()])
        }
        gitlab::CAPABILITY => actions == &BTreeSet::from(["list_projects".into()]),
        _ => false,
    };
    ensure!(accepted, "unsupported semantic connection access");
    Ok(())
}

impl Adapter {
    pub(super) fn validate_canary(
        self,
        canary: &day2_capabilities::oauth::RegistrationCanary,
    ) -> Result<()> {
        match self {
            Self::GoogleCalendar => Ok(()),
            Self::GitlabProjects => gitlab::validate_canary(canary),
        }
    }

    pub(super) fn authorization_extras(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::GoogleCalendar => &[
                ("access_type", "offline"),
                ("include_granted_scopes", "false"),
                ("prompt", "consent select_account"),
            ],
            Self::GitlabProjects => &[],
        }
    }

    pub(super) fn describe(self, value: &mut serde_json::Value) {
        match self {
            Self::GoogleCalendar => {
                value["access_type"] = "offline".into();
                value["include_granted_scopes"] = false.into();
                value["prompt"] = "consent select_account".into();
            }
            Self::GitlabProjects => value["refresh_recovery"] = "reauthorize_on_uncertainty".into(),
        }
    }

    pub(super) fn userinfo(self) -> &'static str {
        match self {
            Self::GoogleCalendar => google::USERINFO,
            Self::GitlabProjects => gitlab::USERINFO,
        }
    }

    pub(super) fn token_info(self, token: &url::Url) -> Result<url::Url> {
        match self {
            Self::GoogleCalendar => anyhow::bail!("no reviewed Google token-info request"),
            Self::GitlabProjects => Ok(token.join("token/info")?),
        }
    }

    pub(super) fn tokens(
        self,
        raw: &[u8],
        context: TokenContext<'_>,
        refresh: bool,
        wire: &super::registration::Wire,
    ) -> Result<Tokens> {
        match self {
            Self::GoogleCalendar => google::tokens(raw, context, refresh),
            Self::GitlabProjects => gitlab::tokens(raw, context, wire),
        }
    }

    pub(super) fn account(self, raw: &[u8], subject: &str, tenant: &str) -> Result<()> {
        match self {
            Self::GoogleCalendar => google::account(raw, subject, tenant),
            Self::GitlabProjects => gitlab::account(raw, subject, tenant),
        }
    }

    pub(super) fn selected(profile: &profiles::ReviewedBrowserCodeProfile) -> Result<Self> {
        use day2_capabilities::oauth::AccountBindingPolicy::{
            ExplicitExternalAccount, MappedHuman,
        };
        for entry in [
            google::reviewed(&MappedHuman)?,
            google::reviewed(&ExplicitExternalAccount)?,
        ] {
            if entry.profile == *profile {
                return Ok(Self::GoogleCalendar);
            }
        }
        if gitlab::reviewed()?.profile == *profile {
            return Ok(Self::GitlabProjects);
        }
        anyhow::bail!("no reviewed wire adapter for OAuth profile")
    }

    pub(super) fn validate_client(self, client: &ProviderClient) -> Result<()> {
        client.validate()?;
        ensure!(
            matches!(
                (self, client),
                (Self::GoogleCalendar, ProviderClient::Google { .. })
                    | (Self::GitlabProjects, ProviderClient::Gitlab { .. })
            ),
            "OAuth client provider does not match reviewed profile"
        );
        Ok(())
    }

    pub(super) fn validate_account(
        self,
        requirement: &ConnectionRequirement,
        policy: &day2_capabilities::oauth::ProviderAccountPolicy,
    ) -> Result<()> {
        use day2_capabilities::oauth::{AccountBindingPolicy, ProviderAccountPolicy};
        ensure!(
            matches!(
                (&requirement.account_policy, policy),
                (
                    AccountBindingPolicy::MappedHuman,
                    ProviderAccountPolicy::IapSubject
                ) | (
                    AccountBindingPolicy::ExplicitExternalAccount,
                    ProviderAccountPolicy::ExternalAccounts { .. }
                )
            ),
            "OAuth runtime account policy does not match declaration"
        );
        if self == Self::GitlabProjects {
            let ProviderAccountPolicy::ExternalAccounts {
                allowed_tenants,
                allowed_subjects,
            } = policy
            else {
                anyhow::bail!("GitLab requires explicit external account approval");
            };
            ensure!(
                allowed_tenants == &BTreeSet::from(["gitlab.com".into()])
                    && allowed_subjects
                        .as_ref()
                        .is_none_or(|values| values.iter().all(|s| s
                            .parse::<u64>()
                            .is_ok_and(|id| id > 0 && id.to_string() == *s))),
                "unsupported GitLab account ceiling"
            );
        }
        Ok(())
    }

    pub(super) fn callback_extras(self) -> BTreeSet<String> {
        match self {
            Self::GoogleCalendar => ["scope", "authuser", "prompt", "hd"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            Self::GitlabProjects => BTreeSet::new(),
        }
    }
}

pub(super) fn current(
    requirement: &ConnectionRequirement,
    selected: &BindingRef,
) -> Result<(
    profiles::ReviewedBrowserCodeProfile,
    day2_capabilities::oauth::ProviderPermissionContract,
)> {
    reviewed()?.current(requirement, &selected.id)
}
