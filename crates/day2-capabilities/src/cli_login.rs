//! Public native-client registration metadata, never identity or access authority.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

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
