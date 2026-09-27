//! Bounded outbound callback parsing. Protocol handlers must bind the parsed
//! state, issuer and callback to an existing attempt before custody receives
//! the code. Error descriptions and raw callback bodies are never returned.

use anyhow::{Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CALLBACK_BYTES: usize = 8192;
const MAX_PARAMETERS: usize = 12;

pub struct SecretCode(String);

impl SecretCode {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct SecretState(String);

impl SecretState {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderDenial {
    AccessDenied,
    TemporarilyUnavailable,
    InvalidScope,
    Other,
}

pub enum ParsedCallback {
    Code {
        code: SecretCode,
        state: SecretState,
        issuer: Option<String>,
    },
    Denied {
        reason: ProviderDenial,
        state: SecretState,
        issuer: Option<String>,
    },
}

/// Closed provider profile additions. `iss` is mandatory when the reviewed
/// profile supports it, and unknown fields fail instead of being ignored.
pub struct CallbackParameters {
    pub require_issuer: bool,
    pub allowed_extras: BTreeSet<String>,
}

pub fn parse_callback(raw: &[u8], profile: &CallbackParameters) -> Result<ParsedCallback> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_CALLBACK_BYTES,
        "invalid provider callback size"
    );
    ensure!(
        !raw.iter().any(|byte| *byte == b'#' || *byte == 0),
        "invalid provider callback syntax"
    );
    validate_percent_encoding(raw)?;
    ensure!(
        percent_encoding::percent_decode(raw).decode_utf8().is_ok(),
        "invalid provider callback UTF-8"
    );
    let mut fields = BTreeMap::new();
    let mut count = 0;
    for (key, value) in url::form_urlencoded::parse(raw) {
        count += 1;
        ensure!(
            count <= MAX_PARAMETERS,
            "provider callback parameter budget"
        );
        ensure!(
            key.len() <= 64 && value.len() <= 4096,
            "provider callback field budget"
        );
        ensure!(
            !key.is_empty()
                && !key.chars().any(char::is_control)
                && !value.chars().any(char::is_control),
            "invalid provider callback field"
        );
        ensure!(
            fields
                .insert(key.into_owned(), value.into_owned())
                .is_none(),
            "duplicate provider callback parameter"
        );
    }
    for key in fields.keys() {
        ensure!(
            matches!(
                key.as_str(),
                "state" | "code" | "iss" | "error" | "error_description" | "error_uri"
            ) || profile.allowed_extras.contains(key),
            "unknown provider callback parameter"
        );
    }
    let state = fields
        .remove("state")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing provider callback state"))?;
    ensure!(state.len() <= 512, "invalid provider callback state");
    let issuer = fields.remove("iss").filter(|value| !value.is_empty());
    ensure!(
        !profile.require_issuer || issuer.is_some(),
        "missing provider callback issuer"
    );
    if let Some(issuer) = &issuer {
        ensure!(issuer.len() <= 512, "invalid provider callback issuer");
    }
    let code = fields.remove("code");
    let error = fields.remove("error");
    // Provider descriptions can contain secrets or attacker text. Discard them
    // before any error or diagnostic is constructed.
    fields.remove("error_description");
    fields.remove("error_uri");
    match (code, error) {
        (Some(code), None) if !code.is_empty() && code.len() <= 2048 => Ok(ParsedCallback::Code {
            code: SecretCode(code),
            state: SecretState(state),
            issuer,
        }),
        (None, Some(error)) if !error.is_empty() && error.len() <= 128 => {
            let reason = match error.as_str() {
                "access_denied" => ProviderDenial::AccessDenied,
                "temporarily_unavailable" => ProviderDenial::TemporarilyUnavailable,
                "invalid_scope" => ProviderDenial::InvalidScope,
                _ => ProviderDenial::Other,
            };
            Ok(ParsedCallback::Denied {
                reason,
                state: SecretState(state),
                issuer,
            })
        }
        _ => anyhow::bail!("invalid provider callback outcome"),
    }
}

fn validate_percent_encoding(raw: &[u8]) -> Result<()> {
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%' {
            ensure!(
                index + 2 < raw.len()
                    && raw[index + 1].is_ascii_hexdigit()
                    && raw[index + 2].is_ascii_hexdigit(),
                "invalid callback percent encoding"
            );
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> CallbackParameters {
        CallbackParameters {
            require_issuer: true,
            allowed_extras: BTreeSet::from(["scope".into()]),
        }
    }

    #[test]
    fn code_callback_requires_exact_single_fields() {
        let parsed = parse_callback(
            b"state=opaque_state&code=secret_code&iss=https%3A%2F%2Fprovider.example&scope=read",
            &profile(),
        )
        .unwrap();
        match parsed {
            ParsedCallback::Code {
                code,
                state,
                issuer,
            } => {
                assert_eq!(code.as_str(), "secret_code");
                assert_eq!(state.as_str(), "opaque_state");
                assert_eq!(issuer.as_deref(), Some("https://provider.example"));
            }
            ParsedCallback::Denied { .. } => panic!("expected code"),
        }
        for raw in [
            b"state=a&state=b&code=x&iss=y".as_slice(),
            b"state=a&code=x&code=y&iss=y",
            b"state=a&code=x&error=access_denied&iss=y",
            b"state=a&code=x",
            b"state=a&code=x&iss=y&unexpected=yes",
            b"state=a&code=%ZZ&iss=y",
            b"state=a&code=x&iss=%FF",
            b"state=a&code=x#fragment&iss=y",
        ] {
            assert!(parse_callback(raw, &profile()).is_err());
        }
    }

    #[test]
    fn provider_error_description_is_never_projected() {
        let raw = b"state=opaque&error=access_denied&error_description=SECRET_CANARY&iss=issuer";
        let result = parse_callback(raw, &profile()).unwrap();
        match result {
            ParsedCallback::Denied {
                reason,
                state,
                issuer,
            } => {
                assert_eq!(reason, ProviderDenial::AccessDenied);
                assert_eq!(state.as_str(), "opaque");
                assert_eq!(issuer.as_deref(), Some("issuer"));
            }
            ParsedCallback::Code { .. } => panic!("expected denial"),
        }
        let failure = parse_callback(
            b"state=opaque&error=access_denied&code=SECRET_CANARY&iss=issuer",
            &profile(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(!failure.contains("SECRET_CANARY"));
    }
}
