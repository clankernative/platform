//! Installation-owned Google client selection. This is desired configuration,
//! never registration readiness. Credentials are resolved only by native code.

use super::approval_keys::{AccessTokenSource, GcpSecretReader, GcpSecretVersion};
use crate::artifact::Instance;
use anyhow::{Context, Result, ensure};
use day2_capabilities::{BindingRef, Name, SecretProvider, oauth::GoogleWebClient};
use std::sync::Arc;

pub(crate) fn validate(instance: &Instance) -> Result<()> {
    let Some(catalog) = &instance.oauth_clients else {
        return Ok(());
    };
    catalog.validate()?;
    instance.security_edge()?;
    let control = instance
        .control
        .as_ref()
        .context("OAuth client secret catalog missing")?;
    let reauthentication = control
        .secrets
        .get(&catalog.reauthentication.credential)
        .context("OAuth reauthentication credential missing")?;
    for selected in catalog.registrations.values() {
        let secret = control
            .secrets
            .get(&selected.client.credential)
            .context("OAuth provider client credential missing")?;
        ensure!(
            secret != reauthentication,
            "OAuth client roles must use distinct secret versions"
        );
    }
    for binding in instance
        .apps
        .values()
        .flat_map(|app| app.oauth_connections.values())
    {
        ensure!(
            catalog.registrations.contains_key(&binding.registration.id),
            "OAuth registration client missing"
        );
        for role in [
            &binding.custody_verifier_secret,
            &binding.custody_encryption_secret,
            &binding.shell_attestation_secret,
        ] {
            let key = control
                .secrets
                .get(role)
                .context("OAuth key provider missing")?;
            ensure!(
                key != reauthentication
                    && catalog
                        .registrations
                        .values()
                        .all(|client| control.secrets.get(&client.client.credential) != Some(key)),
                "OAuth client credentials cannot be custody or attestation keys"
            );
        }
    }
    Ok(())
}

pub(super) fn version(instance: &Instance, client: &GoogleWebClient) -> Result<GcpSecretVersion> {
    client.validate()?;
    let provider = instance
        .control
        .as_ref()
        .context("OAuth client secret catalog missing")?
        .secrets
        .get(&client.credential)
        .context("OAuth client credential missing")?;
    let SecretProvider::GcpVersion {
        project_number,
        secret,
        version,
    } = provider;
    let version = GcpSecretVersion {
        project_number: project_number.get(),
        secret: secret.as_str().into(),
        version: version.get(),
    };
    version.validate()?;
    Ok(version)
}

pub(super) fn reauthentication(
    instance: &Instance,
    tokens: Arc<dyn AccessTokenSource>,
) -> Result<(String, Box<dyn super::shell_oidc::CodeExchange>)> {
    validate(instance)?;
    let client = &instance
        .oauth_clients
        .as_ref()
        .context("OAuth clients not selected")?
        .reauthentication;
    Ok((
        client.client_id.clone(),
        Box::new(super::shell_oidc::GoogleCodeExchange::new(
            GcpSecretReader::new(tokens)?,
            version(instance, client)?,
        )?),
    ))
}

pub(super) fn credential(raw: Vec<u8>) -> Result<String> {
    let value =
        String::from_utf8(raw).map_err(|_| anyhow::anyhow!("invalid Google client credential"))?;
    ensure!(
        !value.is_empty()
            && value.len() <= 2048
            && value.bytes().all(|byte| byte.is_ascii_graphic()),
        "invalid Google client credential"
    );
    Ok(value)
}

pub(super) fn credential_reference(
    instance: &BindingRef,
    client_id: &str,
    secret: &GcpSecretVersion,
) -> Result<BindingRef> {
    BindingRef::pin(
        Name::try_from("google_client_credential".to_owned())?,
        &(
            "oauth-google-client-credential-v1",
            instance,
            client_id,
            secret,
        ),
    )
}

pub(super) fn selected_credential(
    instance: &Instance,
    client: &GoogleWebClient,
) -> Result<BindingRef> {
    credential_reference(
        &super::admission::instance_identity(instance)?,
        &client.client_id,
        &version(instance, client)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn document() -> Value {
        json!({
            "installation":"company","environment":"production",
            "identity":{"scheme":"google_iap","hosted_domain":"example.com"},
            "security_shell":{"origin":"https://security.example.com","iap_audience":"/projects/12345/global/backendServices/2"},
            "apps":{"workspace":{"artifact":"artifacts/selected","readers":[],"writers":[]}},
            "control":{"version":1,"state_directory":"/srv/control","operators":["operator@example.com"],
                "sources":{"workspace_source":{"kind":"local_git","repository":"/srv/workspace"}},
                "apps":{"workspace":{"source":"workspace_source"}},
                "secrets":{
                    "reauth":{"kind":"gcp_version","project_number":12345,"secret":"reauth_client","version":3},
                    "calendar":{"kind":"gcp_version","project_number":12345,"secret":"calendar_client","version":7}
                }},
            "oauth_clients":{"version":1,
                "reauthentication":{"client_id":"123-reauth.apps.googleusercontent.com","credential":"reauth"},
                "registrations":{"calendar_registration":{"client":{"client_id":"123-calendar.apps.googleusercontent.com","credential":"calendar"},
                    "canary_subject":"112233","canary_tenant":"example.com"}}}
        })
    }

    #[test]
    fn instance_selects_public_clients_and_existing_exact_secret_versions() -> Result<()> {
        let document = document();
        let instance = Instance::from_bytes(&serde_json::to_vec(&document)?)?;
        assert_eq!(
            serde_json::to_value(&instance)?["oauth_clients"],
            document["oauth_clients"]
        );
        let selected = &instance.oauth_clients.as_ref().unwrap().reauthentication;
        assert_eq!(
            version(&instance, selected)?.resource_name(),
            "projects/12345/secrets/reauth_client/versions/3"
        );
        // Different installations own their addresses without changing a client
        // contract or introducing an authored redirect in desired metadata.
        let mut other = document;
        other["security_shell"]["origin"] = json!("https://security.other-company.example");
        assert!(Instance::from_bytes(&serde_json::to_vec(&other)?).is_ok());
        Ok(())
    }

    #[test]
    fn malformed_unknown_aliased_missing_or_shared_client_selections_are_refused() -> Result<()> {
        for (path, value) in [
            ("/oauth_clients/version", json!(2)),
            (
                "/oauth_clients/reauthentication/client_id",
                json!("client.apps.googleusercontent.com/attack"),
            ),
            (
                "/oauth_clients/reauthentication/credential",
                json!("missing"),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/canary_subject",
                json!(""),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/canary_tenant",
                json!("EXAMPLE.com"),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/client/client_id",
                json!("123-reauth.apps.googleusercontent.com"),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/client/credential",
                json!("reauth"),
            ),
            ("/control/secrets/calendar/version", json!("latest")),
            ("/control/secrets/calendar/version", json!(0)),
            (
                "/control/secrets/calendar",
                json!({"kind":"gcp_version","project_number":12345,"secret":"reauth_client","version":3}),
            ),
            ("/security_shell", Value::Null),
        ] {
            let mut document = document();
            *document.pointer_mut(path).unwrap() = value;
            assert!(
                Instance::from_bytes(&serde_json::to_vec(&document)?).is_err(),
                "{path}"
            );
        }
        for field in ["client_secret", "callback_url", "ready"] {
            let mut document = document();
            document["oauth_clients"]["reauthentication"][field] = json!("untrusted");
            assert!(Instance::from_bytes(&serde_json::to_vec(&document)?).is_err());
        }
        for raw in [
            vec![],
            b"secret\n".to_vec(),
            b"secret value".to_vec(),
            vec![0xff],
            vec![b'x'; 2049],
        ] {
            assert!(credential(raw).is_err());
        }
        assert_eq!(credential(b"fixture-secret".to_vec())?, "fixture-secret");
        Ok(())
    }
}
