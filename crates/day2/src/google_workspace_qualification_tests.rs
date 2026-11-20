use super::*;
use crate::integrations::simulated::{self, ScheduledFault, SimulatedFault};

const SCOPE: &str = "qualification";

fn rehearse(
    directory: &tempfile::TempDir,
) -> Result<(
    std::path::PathBuf,
    QualificationProfile,
    String,
    Qualification,
)> {
    let (database, profile, token) = simulated_rehearsal(directory.path())?;
    let run = Qualification::simulated(profile.clone(), token.clone(), &database, SCOPE)?;
    Ok((database, profile, token, run))
}

fn probes<'a>(receipt: &'a Value, name: &str) -> Vec<&'a Value> {
    receipt["probes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|probe| probe["probe"] == name)
        .collect()
}

fn group_permissions(database: &std::path::Path) -> Result<Vec<simulated::GoogleDrivePermission>> {
    simulated::update_google_workspace(database, SCOPE, |state| {
        Ok(state
            .world
            .drive_files
            .values()
            .flat_map(|file| file.permissions.clone())
            .filter(|p| p.kind == "group")
            .collect())
    })
}

/// The whole battery through the adapter and the simulated port: every probe
/// answers as the organization says, the share writes once and is listed at
/// once, the metadata server is never asked, and the receipt holds no value
/// of the profile, the world or the token.
#[test]
fn a_rehearsal_runs_every_probe_through_the_adapter_and_writes_once() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (database, profile, token, mut run) = rehearse(&directory)?;
    run.read()?;
    assert_eq!(run.share()?, json!({"outcome":"Shared"}));
    let receipt = run.finish()?;
    for (probe, outcome) in [
        ("directory_group", "Found"),
        ("directory_group_alias", "Found"),
        ("directory_group_member", "Member"),
        ("calendar_in_play", "Found"),
        ("calendar_free_busy", "NotFound"),
        ("calendar_unshared", "NotFound"),
        ("events_page", "Found"),
        ("event_recorded", "Found"),
        ("event_imported", "Found"),
        ("conferences_recorded", "Found"),
        ("conferences_imported", "NoOwner"),
        ("share_alias", "GroupNotPrimary"),
        ("share", "Shared"),
        ("share_again", "AlreadyShared"),
    ] {
        assert_eq!(probes(&receipt, probe)[0]["outcome"], outcome, "{probe}");
    }
    let detail = |probe: &str, name: &str| probes(&receipt, probe)[0]["details"][name].clone();
    assert_eq!(detail("directory_group_alias", "primary_is_group"), true);
    assert_eq!(detail("directory_group_alias", "primary_is_alias"), false);
    assert_eq!(detail("event_recorded", "organizer"), "creator");
    assert_eq!(detail("event_imported", "organizer"), "person_in_domain");
    assert_eq!(detail("conferences_recorded", "artifact_listed"), true);
    assert_eq!(detail("share_again", "same_permission"), true);
    assert_eq!(
        (
            receipt["creates_sent"].clone(),
            receipt["creates_fenced"].clone()
        ),
        (json!(1), json!(0))
    );
    assert_eq!(receipt["visible_after_seconds"], 0);
    assert_eq!(receipt["provider_qualified"], false);
    let rendered = receipt.to_string();
    assert!(
        !rendered.contains("\"metadata\""),
        "the metadata server is never asked"
    );
    let created = group_permissions(&database)?;
    assert_eq!(created.len(), 1, "exactly one permission landed");
    let profile_values = serde_json::to_value(&profile)?;
    let mut private: Vec<String> = vec![token, created[0].id.clone(), "1recStandupFile01".into()];
    let mut pending = vec![&profile_values];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(text) => private.push(text.clone()),
            Value::Array(items) => pending.extend(items),
            Value::Object(map) => pending.extend(map.values()),
            _ => {}
        }
    }
    for value in private {
        assert!(
            !rendered.contains(&value),
            "{value} leaked into the receipt"
        );
    }
    // A hostile error body is reduced to reviewed reasons.
    let hostile = json!({"error":{"errors":[{"reason":"SENTINEL_REASON"},{"reason":"notFound"}],
        "status":"SENTINEL_STATUS","details":[{"reason":"SENTINEL_DETAIL"}]}});
    let shape = classify("calendar_events", 404, &hostile, None);
    assert_eq!(
        shape,
        BTreeMap::from([("notFound", 1), ("reason_other", 3)])
    );
    Ok(())
}

/// A create that fails before Drive acts leaves the outcome unknown; every
/// later check is refused at the fence unsent, so nothing is written twice
/// and nothing lands.
#[test]
fn an_unknown_share_is_checked_with_the_fence_closed_and_never_retried() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (database, _, _, mut run) = rehearse(&directory)?;
    run.delays = &[0, 0];
    run.read()?;
    simulated::schedule_faults(
        &database,
        SCOPE,
        simulated::GOOGLE_WORKSPACE_WORLD,
        vec![ScheduledFault {
            endpoint: simulated::GOOGLE_DRIVE_SHARE_ENDPOINT.into(),
            remaining: 1,
            fault: SimulatedFault::ServerError,
        }],
    )?;
    assert_eq!(
        run.share()?,
        json!({"outcome":"google_workspace_share_outcome_unknown"})
    );
    assert!(run.share().is_err(), "the write step runs once");
    let receipt = run.finish()?;
    assert_eq!(
        (
            receipt["creates_sent"].clone(),
            receipt["creates_fenced"].clone()
        ),
        (json!(1), json!(2))
    );
    assert_eq!(receipt["visible_after_seconds"], Value::Null);
    assert_eq!(probes(&receipt, "share_again").len(), 2);
    assert!(group_permissions(&database)?.is_empty());
    Ok(())
}

#[test]
fn only_a_bounded_consistent_profile_and_a_token_shaped_token_may_run() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (database, profile, token) = simulated_rehearsal(directory.path())?;
    let now = crate::oauth::effects::wall_time()?;
    type Edit = fn(&mut QualificationProfile);
    let edits: [(Edit, &str); 6] = [
        (
            |p| p.format = 2,
            "google_workspace_qualification_profile_format",
        ),
        (
            |p| p.expires_at = 0,
            "google_workspace_qualification_profile_expired",
        ),
        (
            |p| p.expires_at = i64::MAX,
            "google_workspace_qualification_profile_expired",
        ),
        (
            |p| p.calendars.unshared = p.calendars.in_play.clone(),
            "google_workspace_qualification_profile_invalid",
        ),
        (
            |p| p.group_alias = p.group.clone(),
            "google_workspace_qualification_profile_invalid",
        ),
        (
            |p| p.group = "team@outside.example".into(),
            "google_workspace_qualification_profile_invalid",
        ),
    ];
    for (edit, expected) in edits {
        let mut edited = profile.clone();
        edit(&mut edited);
        assert_eq!(admit(&edited, now).unwrap_err().to_string(), expected);
        let refused = Qualification::simulated(edited, token.clone(), &database, SCOPE);
        assert_eq!(
            refused.err().map(|error| error.to_string()).as_deref(),
            Some(expected)
        );
    }
    for bad in ["", "two words", &"t".repeat(8193)] {
        let refused = Qualification::simulated(profile.clone(), bad.into(), &database, SCOPE);
        assert_eq!(
            refused.err().map(|error| error.to_string()).as_deref(),
            Some("google_workspace_qualification_token_invalid")
        );
    }
    let mut run = Qualification::simulated(profile, token, &database, SCOPE)?;
    assert!(run.share().is_err(), "no write before the reads");
    Ok(())
}
