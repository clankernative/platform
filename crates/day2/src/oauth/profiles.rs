//! Closed confidential-client PKCE browser-code exchange contracts. Only reviewed adapters may supply
//! these host values; instance registration and external readiness are separate
//! admission evidence, not inferred from a successfully parsed response.

use anyhow::{Result, ensure};
use day2_capabilities::oauth::ProviderPermissionContract;
use day2_capabilities::{BindingRef, Digest};
use serde::Deserialize;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReusableRetry {
    NoAutomaticRetry,
    QualifiedBoundedRetry { evidence: Digest },
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
    use day2_capabilities::Name;
    use std::collections::BTreeMap;

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
