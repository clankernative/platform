use super::*;
use crate::integrations::simulated::{self, ScheduledFault, SimulatedFault};

const SCOPE: &str = "qualification";

fn rehearse(
    directory: &tempfile::TempDir,
) -> Result<(std::path::PathBuf, Vec<u8>, String, Qualification)> {
    let (database, profile, token) = simulated_rehearsal(directory.path())?;
    let now = crate::oauth::effects::wall_time()?;
    let run = Qualification::simulated(admit(&profile, now)?, token.clone(), &database, SCOPE)?;
    Ok((database, profile, token, run))
}

/// The recipe's order: every read step, then the share.
fn read_and_share(run: &mut Qualification) -> Result<Value> {
    for step in Step::READS {
        assert_eq!(run.step(step)?, json!({}));
    }
    run.step(Step::Share)
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
            .filter(|permission| permission.kind == "group")
            .collect())
    })
}

/// The whole battery through the adapter and the simulated port: every probe
/// answers as the organization says, the share writes once and is listed at
/// the first check, the metadata server is never asked, and the receipt holds
/// no value of the profile, the world or the token.
#[test]
fn a_rehearsal_runs_every_step_through_the_adapter_and_writes_once() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (database, profile, token, mut run) = rehearse(&directory)?;
    assert_eq!(read_and_share(&mut run)?, json!({"check":true}));
    assert_eq!(run.step(Step::Check)?, json!({"visible":true}));
    assert!(run.step(Step::Check).is_err(), "no check after it is seen");
    let receipt = run.finish()?;
    for (probe, outcome) in [
        ("directory_group", "Found"),
        ("directory_group_alias", "Found"),
        ("directory_group_member", "Member"),
        ("calendar_in_play", "Found"),
        ("calendar_free_busy", "NotFound"),
        ("calendar_unshared", "NotFound"),
        ("events_page", "Found"),
        ("events_token_other_query", "unsettled_single_page"),
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
    assert_eq!(detail("share_again", "delay_seconds"), 0);
    assert!(detail("share_again", "elapsed_ms").is_u64());
    assert_eq!(
        receipt["visible_after_ms"],
        detail("share_again", "elapsed_ms")
    );
    assert_eq!(
        (
            receipt["creates_sent"].clone(),
            receipt["requests_fenced"].clone()
        ),
        (json!(1), json!(0))
    );
    assert_eq!(receipt["checks"], 1);
    assert_eq!(receipt["check_delays_seconds"], json!(VISIBILITY_DELAYS));
    assert_eq!(receipt["profile_digest"], crate::digest(&profile));
    assert_eq!(receipt["provider_qualified"], false);
    let rendered = receipt.to_string();
    assert!(
        !rendered.contains("\"metadata\""),
        "the metadata server is never asked"
    );
    let created = group_permissions(&database)?;
    assert_eq!(created.len(), 1, "exactly one permission landed");
    let now = crate::oauth::effects::wall_time()?;
    let mut private = admit(&profile, now)?.values();
    private.extend([token, created[0].id.clone(), "1recStandupFile01".into()]);
    for value in private {
        assert!(
            !rendered.contains(&value),
            "{value} leaked into the receipt"
        );
    }
    // Hostile bodies are reduced to reviewed reasons and forms.
    let hostile = json!({"error":{"errors":[{"reason":"SENTINEL_REASON"},{"reason":"notFound"}],
        "status":"SENTINEL_STATUS","details":[{"reason":"SENTINEL_DETAIL"}]}});
    let shape = classify("calendar_events", 404, &hostile, None);
    assert_eq!(
        shape,
        BTreeMap::from([("notFound", 1), ("reason_other", 3)])
    );
    let unknown = json!({"permissions":[{"type":"SENTINEL","role":"SENTINEL","deleted":true}]});
    let shape = classify("drive_permissions", 200, &unknown, None);
    assert_eq!(
        shape,
        BTreeMap::from([
            ("items", 1),
            ("type_other", 1),
            ("role_other", 1),
            ("deleted", 1)
        ])
    );
    let unknown = json!({"recordings":[{"name":"conferenceRecords/r/recordings/SENTINEL VALUE",
        "state":"SENTINEL","driveDestination":{"file":"SENTINEL VALUE"}}]});
    let shape = classify("meet_recordings", 200, &unknown, None);
    assert_eq!(
        shape,
        BTreeMap::from([
            ("items", 1),
            ("state_other", 1),
            ("destination_other", 1),
            ("ids_outside_bound", 1)
        ])
    );
    Ok(())
}

/// A create that fails before Drive acts leaves the outcome unknown; every
/// later check is refused at the fence unsent, the checks stop at the budget,
/// and nothing is written twice or lands.
#[test]
fn an_unknown_share_is_checked_with_the_fence_closed_and_never_retried() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (database, _, _, mut run) = rehearse(&directory)?;
    run.delays = &[0, 0];
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
    assert_eq!(read_and_share(&mut run)?, json!({"check":true}));
    assert!(run.step(Step::Share).is_err(), "the write step runs once");
    for _ in 0..2 {
        assert_eq!(run.step(Step::Check)?, json!({"visible":false}));
    }
    assert!(
        run.step(Step::Check).is_err(),
        "at most one check per delay"
    );
    let receipt = run.finish()?;
    assert_eq!(
        probes(&receipt, "share")[0]["outcome"],
        "google_workspace_share_outcome_unknown"
    );
    assert_eq!(
        (
            receipt["creates_sent"].clone(),
            receipt["requests_fenced"].clone()
        ),
        (json!(1), json!(2))
    );
    assert_eq!(receipt["visible_after_ms"], Value::Null);
    assert!(group_permissions(&database)?.is_empty());
    Ok(())
}

#[test]
fn only_a_bounded_consistent_profile_and_a_token_shaped_token_may_run() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (database, bytes, token) = simulated_rehearsal(directory.path())?;
    let now = crate::oauth::effects::wall_time()?;
    let profile: Profile = crate::json::decode(&bytes)?;
    type Edit = fn(&mut Profile);
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
        let refused = admit(&serde_json::to_vec(&edited)?, now).err();
        assert_eq!(
            refused.map(|error| error.to_string()).as_deref(),
            Some(expected)
        );
    }
    for bad in [
        "",
        "two words",
        r#"{"type":"service_account"}"#,
        &"t".repeat(8193),
    ] {
        assert_eq!(
            token_shape(bad).unwrap_err().to_string(),
            "google_workspace_qualification_token_invalid"
        );
    }
    let mut run = Qualification::simulated(admit(&bytes, now)?, token.clone(), &database, SCOPE)?;
    for step in [Step::Share, Step::Check] {
        assert!(run.step(step).is_err(), "{step:?} before the reads");
    }
    run.step(Step::Directory)?;
    assert!(run.step(Step::Directory).is_err(), "a read step runs once");
    assert!(run.finish().is_err(), "no receipt before the share");
    // An "alias" that is really another group would reach Drive: the fence
    // refuses that create during the reads, unsent.
    let mut other = profile;
    other.group_alias = format!("platform@{}", other.email_domain);
    let mut run = Qualification::simulated(
        admit(&serde_json::to_vec(&other)?, now)?,
        token,
        &database,
        SCOPE,
    )?;
    run.step(Step::ShareAlias)?;
    assert_eq!(run.port.inner.creates_sent, 0);
    assert_eq!(run.port.inner.requests_fenced, 1);
    assert!(group_permissions(&database)?.is_empty());
    Ok(())
}
