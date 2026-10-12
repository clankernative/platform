use anyhow::{Context, Result, ensure};
use day2::{
    artifact::{Instance, LoadedArtifact},
    deployment::oauth_setup,
    store::{Fault, Runtime},
};
use day2_capabilities::oauth::AccountBindingPolicy;
use serde_json::{Value, json};
use std::{fs, path::Path};

/// Re-pin desired DATA after this fixture renames an installation/app/client.
/// The synthetic provider UID stays unchanged; this supplies no live authority.
fn select_fixture_epoch(draft: &mut Value, app: &str) -> Result<()> {
    use day2_capabilities::security_epoch::AuthorityScope;
    let instance: Instance = serde_json::from_value(draft.clone())?;
    let alias = day2_capabilities::Name::try_from("app_epoch".to_owned())?;
    let mut epoch = instance
        .control
        .as_ref()
        .context("fixture control missing")?
        .security_epochs[&alias]
        .clone();
    epoch.scope = AuthorityScope {
        installation: instance.installation.clone().try_into()?,
        environment: instance.environment.clone().try_into()?,
        app: app.to_owned().try_into()?,
    };
    epoch.key_set = instance.security_key_set(app)?;
    epoch.validate()?;
    draft["control"]["security_epochs"] = json!({"app_epoch": epoch});
    Ok(())
}

#[test]
fn admitted_gitlab_declaration_selects_company_client_and_external_ceiling() -> Result<()> {
    let path = std::env::var_os("DAY2_TEST_OAUTH_GITLAB_ARTIFACT")
        .context("build oauth-gitlab-canary or run xtask verify")?;
    let artifact = LoadedArtifact::load(Path::new(&path))?;
    let declarations = &artifact.contract().connection_declarations;
    assert_eq!(declarations.len(), 1);
    assert_eq!(declarations[0].registration.as_str(), "projects");
    let requirement = &declarations[0].requirement;
    assert_eq!(requirement.capability, "gitlab_projects");
    assert_eq!(
        requirement.account_policy,
        AccountBindingPolicy::ExplicitExternalAccount
    );
    let directory = tempfile::tempdir()?;
    let mut outcomes = Vec::new();
    for (company, client, allowed) in [
        ("company_a", "a".repeat(64), vec!["42"]),
        ("company_b", "b".repeat(64), vec!["42", "43"]),
    ] {
        let company_directory = directory.path().join(company);
        fs::create_dir(&company_directory)?;
        let path = company_directory.join("instance.json");
        let mut draft: Value = serde_json::from_slice(include_bytes!(
            "../../../deploy/gke/stacks/day2-app/tests/oauth-instance.json"
        ))?;
        draft["installation"] = json!(company);
        for pointer in ["/apps", "/oauth_runtime/apps", "/control/apps"] {
            let map = draft.pointer_mut(pointer).unwrap().as_object_mut().unwrap();
            let app = map.remove("example_app").unwrap();
            map.insert("oauthgitlab".into(), app);
        }
        draft["apps"]["oauthgitlab"]["artifact"] = json!(artifact.directory());
        draft["apps"]["oauthgitlab"]["authority"]["operations"] = json!({
            "oauthgitlab.inspect":{"actors":["qa@example.com"],"mode":{"kind":"read"},"models":{}}
        });
        let connections = draft["apps"]["oauthgitlab"]["oauth_connections"]
            .as_object_mut()
            .unwrap();
        let mut binding = connections.remove("calendar").unwrap();
        binding["namespace"]["installation"] = json!(company);
        binding["namespace"]["app"] = json!("oauthgitlab");
        binding["profile"]["id"] = json!("gitlab_projects_external_v1");
        connections.insert("projects".into(), binding);
        draft["oauth_runtime"]["apps"]["oauthgitlab"]["accounts"] = json!({
            "projects":{"kind":"external_accounts","allowed_tenants":["gitlab.com"],"allowed_subjects":allowed}
        });
        draft["oauth_clients"]["version"] = json!(2);
        draft["oauth_clients"]["registrations"] = json!({"calendar_client":{
            "client":{"kind":"gitlab","client_id":client,"credential":"calendar"},
            "canary":{"qualification_subject":"accounts.google.com:112233","provider_subject":"42","provider_tenant":"gitlab.com"}
        }});
        select_fixture_epoch(&mut draft, "oauthgitlab")?;
        let bytes = serde_json::to_vec(&draft)?;
        fs::write(&path, &bytes)?;
        let prepared = oauth_setup(&path)?;
        assert_eq!(fs::read(&path)?, bytes);
        assert_eq!(prepared["registrations"][0]["client_id"], client);
        assert_eq!(
            prepared["registrations"][0]["scopes"],
            json!(["read_api", "read_user"])
        );
        assert_eq!(
            prepared["instance"]["oauth_runtime"]["apps"]["oauthgitlab"]["accounts"]["projects"]["allowed_subjects"],
            json!(allowed)
        );
        assert_eq!(
            prepared["oauth_connections"]["oauthgitlab"]["projects"]["requirement"],
            json!(requirement.nominal_identity()?)
        );
        fs::write(&path, serde_json::to_vec(&prepared["instance"])?)?;
        assert_eq!(prepared, oauth_setup(&path)?);
        // Serving uses the same ordinary runtime and current artifact. Static
        // configuration does not supply a registration receipt or grant tokens.
        let runtime = Runtime::load(&path, "oauthgitlab")?;
        runtime.initialize()?;
        let reply = runtime.invoke(
            "oauthgitlab.inspect",
            "qa@example.com",
            "inspect_projects",
            &json!({}),
            1,
            Fault::None,
        )?;
        assert_eq!(reply.status, "success");
        assert_eq!(
            reply.result,
            json!({"connection":"projects", "usage":requirement.usage})
        );
        let mut mismatched = prepared["instance"].clone();
        mismatched["oauth_clients"]["registrations"]["calendar_client"]["client"] = json!({"kind":"google","client_id":"123-calendar.apps.googleusercontent.com","credential":"calendar"});
        fs::write(&path, serde_json::to_vec(&mismatched)?)?;
        assert!(oauth_setup(&path).is_err());
        outcomes.push(prepared);
    }
    assert_ne!(
        outcomes[0]["registrations"][0]["callback_url"],
        outcomes[1]["registrations"][0]["callback_url"]
    );
    assert_ne!(
        outcomes[0]["registrations"][0]["registration_selection"],
        outcomes[1]["registrations"][0]["registration_selection"]
    );
    Ok(())
}

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
    select_fixture_epoch(&mut draft, "oauthcalendar")?;
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
    let replacement_instance =
        Instance::from_bytes(&serde_json::to_vec(&replacement["instance"])?)?;
    let expected_key_set = replacement_instance.security_key_set("oauthcalendar")?;
    let epoch_alias = day2_capabilities::Name::try_from("app_epoch".to_owned())?;
    let selected_epoch = &replacement_instance
        .control
        .as_ref()
        .context("prepared control missing")?
        .security_epochs[&epoch_alias];
    assert_eq!(selected_epoch.key_set, expected_key_set);
    assert_ne!(
        expected_key_set,
        instance.security_key_set("oauthcalendar")?
    );
    let mut expected_control = rotated["control"].clone();
    let expected_epoch_key = expected_control
        .pointer_mut("/security_epochs/app_epoch/key_set")
        .context("existing desired epoch key-set missing")?;
    *expected_epoch_key = serde_json::to_value(&expected_key_set)?;
    assert_eq!(replacement["instance"]["control"], expected_control);
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
