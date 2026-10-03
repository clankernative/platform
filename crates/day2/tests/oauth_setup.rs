use anyhow::{Context, Result, ensure};
use day2::{
    artifact::{Instance, LoadedArtifact},
    deployment::oauth_setup,
    store::{Fault, Runtime},
};
use day2_capabilities::oauth::AccountBindingPolicy;
use serde_json::{Value, json};
use std::{fs, path::Path};

#[test]
fn admitted_calendar_canary_prepares_reproducible_selection_without_live_authority() -> Result<()> {
    let artifact = std::env::var_os("DAY2_TEST_OAUTH_CALENDAR_ARTIFACT")
        .context("build oauth-calendar-canary or run xtask verify")?;
    let artifact = LoadedArtifact::load(Path::new(&artifact))?;
    let declarations = &artifact.contract().connection_declarations;
    ensure!(
        declarations.len() == 1,
        "canary must declare one connection"
    );
    let requirement = &declarations[0].requirement;
    assert_eq!(declarations[0].registration.as_str(), "calendar");
    assert_eq!(
        requirement.account_policy,
        AccountBindingPolicy::MappedHuman
    );
    assert_eq!(
        requirement
            .actions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["list_events"]
    );

    // Synthetic deployment selectors test preparation, never cloud readiness.
    let mut draft: Value = serde_json::from_slice(include_bytes!(
        "../../../deploy/gke/stacks/day2-app/tests/oauth-instance.json"
    ))?;
    for pointer in ["/apps", "/oauth_runtime/apps", "/control/apps"] {
        let entries = draft.pointer_mut(pointer).unwrap().as_object_mut().unwrap();
        let selected = entries.remove("example_app").unwrap();
        entries.insert("oauthcalendar".into(), selected);
    }
    draft["apps"]["oauthcalendar"]["artifact"] = json!(artifact.directory());
    draft["apps"]["oauthcalendar"]["oauth_connections"]["calendar"]["namespace"]["app"] =
        json!("oauthcalendar");
    draft["apps"]["oauthcalendar"]["authority"]["operations"] = json!({
        "oauthcalendar.inspect": {"actors":["qa@example.com"], "mode":{"kind":"read"}, "models":{}}
    });
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("instance.json");
    let bytes = serde_json::to_vec(&draft)?;
    fs::write(&path, &bytes)?;
    let prepared = oauth_setup(&path)?;
    assert_eq!(fs::read(&path)?, bytes, "setup must not edit the instance");
    assert_eq!(prepared["mode"], "desired-metadata");
    assert_eq!(
        prepared["oauth_connections"]["oauthcalendar"]["calendar"]["requirement"],
        json!(requirement.nominal_identity()?)
    );
    assert_eq!(
        prepared["registrations"][0]["scopes"],
        json!([
            "https://www.googleapis.com/auth/calendar.events.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid"
        ])
    );
    let callback = prepared["registrations"][0]["callback_url"]
        .as_str()
        .context("callback missing")?;
    ensure!(
        callback.starts_with("https://security.tools.example.com/_day2/oauth/callback/"),
        "wrong callback origin"
    );
    let instance = Instance::from_bytes(&serde_json::to_vec(&prepared["instance"])?)?;
    assert_eq!(
        instance.apps["oauthcalendar"].artifact,
        artifact.directory().to_string_lossy()
    );
    fs::write(&path, serde_json::to_vec(&prepared["instance"])?)?;
    assert_eq!(prepared, oauth_setup(&path)?, "setup must be idempotent");

    let mut rotated = prepared["instance"].clone();
    rotated["control"]["secrets"]["verifier"]["version"] = json!(8);
    let rotated_bytes = serde_json::to_vec(&rotated)?;
    fs::write(&path, &rotated_bytes)?;
    let replacement = oauth_setup(&path)?;
    assert_eq!(fs::read(&path)?, rotated_bytes);
    assert_ne!(
        replacement["registrations"][0]["callback_url"],
        prepared["registrations"][0]["callback_url"]
    );
    assert_eq!(
        replacement["registrations"][0]["scopes"],
        prepared["registrations"][0]["scopes"]
    );
    assert_eq!(replacement["instance"]["control"], rotated["control"]);
    fs::write(&path, serde_json::to_vec(&prepared["instance"])?)?;

    let runtime = Runtime::load(&path, "oauthcalendar")?;
    runtime.initialize()?;
    let reply = runtime.invoke(
        "oauthcalendar.inspect",
        "qa@example.com",
        "inspect_canary",
        &json!({}),
        1,
        Fault::None,
    )?;
    assert_eq!(reply.status, "success");
    assert_eq!(
        reply.result,
        json!({"connection":"calendar", "usage":requirement.usage})
    );
    Ok(())
}
