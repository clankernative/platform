//! Public native-client registration metadata, never identity or access authority.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// One complete company-owned Desktop registration selected for public bootstrap.
/// Google's installed-app registration value is public-client metadata; it is
/// never a human token or authority to use an application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopClient {
    pub client_id: DesktopClientId,
    pub client_secret: DesktopRegistrationValue,
}

/// A bounded Google Desktop registration value, intentionally published with
/// the client identifier. Confidential web-client secrets must never be used.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DesktopRegistrationValue(String);

impl std::fmt::Debug for DesktopRegistrationValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[redacted desktop registration]")
    }
}

impl TryFrom<String> for DesktopRegistrationValue {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        ensure!(
            (16..=256).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "invalid_cli_desktop_registration_value"
        );
        Ok(Self(value))
    }
}

impl From<DesktopRegistrationValue> for String {
    fn from(value: DesktopRegistrationValue) -> Self {
        value.0
    }
}

/// A company-owned Google Desktop OAuth client. Its identifier is public;
/// possession of it proves neither a user identity nor permission to use an app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DesktopClientId(String);

impl DesktopClientId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DesktopClientId {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        ensure!(
            value
                .strip_suffix(".apps.googleusercontent.com")
                .is_some_and(|prefix| {
                    !prefix.is_empty()
                        && prefix.len() <= 200
                        && prefix
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                }),
            "invalid_cli_desktop_client_id"
        );
        Ok(Self(value))
    }
}

impl From<DesktopClientId> for String {
    fn from(value: DesktopClientId) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_registrations_require_both_bounded_public_fields() -> Result<()> {
        let value = "synthetic-desktop-registration-value";
        let registration = format!(
            r#"{{"client_id":"123-desktop.apps.googleusercontent.com","client_secret":"{value}"}}"#
        );
        let parsed: DesktopClient = serde_json::from_str(&registration)?;
        assert_eq!(serde_json::to_string(&parsed)?, registration);
        assert!(!format!("{parsed:?}").contains(value));
        for invalid in [
            String::new(),
            "short".into(),
            "x".repeat(257),
            "contains spaces and punctuation!".into(),
        ] {
            assert!(DesktopRegistrationValue::try_from(invalid).is_err());
        }
        for invalid in [
            r#"{"client_id":"123-desktop.apps.googleusercontent.com"}"#,
            r#"{"client_secret":"synthetic-desktop-registration-value"}"#,
        ] {
            assert!(serde_json::from_str::<DesktopClient>(invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn desktop_client_ids_are_bounded_google_identifiers() -> Result<()> {
        let client = "123-desktop.apps.googleusercontent.com";
        assert_eq!(
            DesktopClientId::try_from(client.to_owned())?.as_str(),
            client
        );
        for value in [
            "",
            ".apps.googleusercontent.com",
            "client.example.com",
            "https://123.apps.googleusercontent.com",
            "123.apps.googleusercontent.com/",
            "123_abc.apps.googleusercontent.com",
        ] {
            assert!(
                DesktopClientId::try_from(value.to_owned()).is_err(),
                "{value}"
            );
        }
        assert!(
            DesktopClientId::try_from(format!("{}.apps.googleusercontent.com", "a".repeat(201)))
                .is_err()
        );
        Ok(())
    }
}
