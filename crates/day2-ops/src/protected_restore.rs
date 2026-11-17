//! Navigation DATA only. The CLI does not authenticate an administrator,
//! create approval evidence, send a restore request or observe completion.
use anyhow::Result;
use day2::artifact::Instance;
use serde_json::{Value, json};
use std::path::Path;

pub fn browser_entry(instance_path: &Path, app: &str) -> Result<Value> {
    let instance = Instance::load(instance_path)?;
    selected_entry(&instance, app)
}

fn selected_entry(instance: &Instance, app: &str) -> Result<Value> {
    let scope = instance.scope(app)?;
    let (_, edge) = instance.security_edge()?;
    // security_edge validates the configured HTTPS origin and its separation
    // from application edges. No caller-supplied URL, path, token or actor is
    // accepted, and no network or browser action occurs here.
    Ok(json!({
        "kind": "protected_restore_browser_navigation_v1",
        "scope": scope,
        "url": format!("{}/restore/protected", edge.origin),
        "instruction": "Open this security origin, select the application and upload the operator input there. IAP and registered passkeys authorize each ceremony.",
        "execution": "not_started",
        "notice": "Navigation only. No approval or restore completion is supplied by this command."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance() -> Result<Instance> {
        Instance::from_bytes(&serde_json::to_vec(&json!({
            "installation":"example", "environment":"sandbox",
            "identity":{"scheme":"google_iap","hosted_domain":"example.com"},
            "security_shell":{"origin":"https://security.example.com","iap_audience":"/projects/123456789/global/backendServices/987654321"},
            "apps":{"calendar":{"artifact":"artifacts/calendar","readers":[],"writers":[]}}
        }))?)
    }

    #[test]
    fn navigation_uses_only_the_current_selected_scope_and_security_origin() -> Result<()> {
        let instance = instance()?;
        let data = selected_entry(&instance, "calendar")?;
        assert_eq!(data["scope"], "example/sandbox/calendar");
        assert_eq!(
            data["url"],
            "https://security.example.com/restore/protected"
        );
        assert_eq!(data["kind"], "protected_restore_browser_navigation_v1");
        assert_eq!(data["execution"], "not_started");
        assert!(!data.as_object().unwrap().contains_key("approval"));
        assert!(!data.as_object().unwrap().contains_key("completed"));
        for app in ["missing", "calendar?adopt=old", "../calendar"] {
            assert!(selected_entry(&instance, app).is_err());
        }
        Ok(())
    }

    #[test]
    fn undeclared_or_noncanonical_security_origins_refuse_without_a_redirect_fallback() -> Result<()>
    {
        let original = instance()?;
        let mut missing = original.clone();
        missing.security_shell = None;
        assert!(selected_entry(&missing, "calendar").is_err());
        for origin in [
            "http://security.example.com",
            "https://security.example.com/foreign",
            "https://security.example.com?token=foreign",
            "https://actor@security.example.com",
        ] {
            let mut changed = original.clone();
            changed.security_shell.as_mut().unwrap().origin = origin.into();
            assert!(selected_entry(&changed, "calendar").is_err());
        }
        Ok(())
    }
}
