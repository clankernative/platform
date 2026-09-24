use anyhow::{Result, bail};
use day2_control::gcp_secret_conformance::{
    AliasResolution, DisableOutcome, DisabledObservation, Fixture, ObservationReason,
    SecretMetadata, VersionMetadata, VersionState,
};
use day2_control::provider_conformance::{
    FileToken, Observation, Origin, Probe, Profile, Request, Session,
};
use day2_control::secrets::SecretVersion;
use day2_control::{Digest, Name};
use std::{
    collections::BTreeMap,
    fs,
    num::NonZeroU64,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};

const NOW: u64 = 1_800_000_000;
const ACTIONS: [&str; 10] = [
    "provider-open",
    "provider-aliases",
    "provider-lost-ack-dispatch",
    "provider-lost-ack-observe",
    "provider-late-hold",
    "provider-late-observe",
    "provider-late-deliver",
    "provider-late-reconcile",
    "provider-quiescence",
    "provider-receipt",
];

fn profile() -> Profile {
    Profile {
        format: 1,
        installation: Name::try_from("exampleco".to_owned()).unwrap(),
        environment: Name::try_from("sandbox".to_owned()).unwrap(),
        project_number: NonZeroU64::new(123).unwrap(),
        secret: "day2-conformance-fixture".into(),
        run_marker: "run-one".into(),
        aliases: ["reports".into(), "spend".into()],
        lost_ack_version: NonZeroU64::new(1).unwrap(),
        late_version: NonZeroU64::new(2).unwrap(),
        expires_at_unix: NOW + 600,
        gke: None,
    }
}

fn fixture() -> Fixture {
    let value = |version| VersionMetadata {
        version: SecretVersion {
            project_number: 123,
            secret: profile().secret,
            version,
        },
        create_time: "2026-09-09T00:00:00Z".into(),
        state: VersionState::Enabled,
        etag: format!("opaque-{version}").try_into().unwrap(),
    };
    Fixture {
        secret: SecretMetadata {
            project_number: 123,
            secret: profile().secret,
            create_time: "2026-09-09T00:00:00Z".into(),
            etag: "parent-token".to_owned().try_into().unwrap(),
            run_marker: "run-one".into(),
            version_aliases: BTreeMap::from([("reports".into(), 1), ("spend".into(), 1)]),
        },
        first: value(1),
        second: value(2),
    }
}

struct World {
    fixture: Fixture,
    calls: usize,
    writes: Vec<Digest>,
    crash: Option<bool>,
    wrong_alias: bool,
    reject_late: bool,
    contradictory: bool,
}

#[derive(Clone)]
struct Fake(Arc<Mutex<World>>);

impl Fake {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(World {
            fixture: fixture(),
            calls: 0,
            writes: vec![],
            crash: None,
            wrong_alias: false,
            reject_late: false,
            contradictory: false,
        })))
    }
}

impl Probe for Fake {
    fn origin(&self) -> Origin {
        Origin::TransportFixture
    }

    fn execute(&mut self, _: &Profile, request: &Request) -> Result<Observation> {
        let mut world = self.0.lock().unwrap();
        world.calls += 1;
        Ok(match request {
            Request::Open {} => Observation::Fixture {
                fixture: world.fixture.clone(),
            },
            Request::Aliases { .. } => {
                let alias = |name: &str| AliasResolution {
                    alias: name.into(),
                    parent: world.fixture.secret.clone(),
                    version: if world.wrong_alias {
                        world.fixture.second.clone()
                    } else {
                        world.fixture.first.clone()
                    },
                };
                Observation::Aliases {
                    aliases: [alias("reports"), alias("spend")],
                }
            }
            Request::Dispatch { attempt, lose_ack } => {
                let crash = world.crash.take();
                if crash == Some(false) {
                    bail!("injected before network dispatch");
                }
                assert!(
                    !world.writes.contains(&attempt.effect),
                    "blind repeat dispatch"
                );
                world.writes.push(attempt.effect.clone());
                let version = if attempt.version.version == 1 {
                    &mut world.fixture.first
                } else {
                    &mut world.fixture.second
                };
                assert_eq!(attempt.expected_etag, version.etag);
                version.state = VersionState::Disabled;
                version.etag = format!("after-{}", attempt.version.version)
                    .try_into()
                    .unwrap();
                let metadata = version.clone();
                if attempt.version.version == 2 && world.reject_late {
                    return Ok(Observation::Dispatch { outcome: DisableOutcome::Rejected {
                        reason: day2_control::gcp_secret_conformance::DisableRejection::PreconditionFailed,
                    }});
                }
                if crash == Some(true) {
                    bail!("injected after provider application");
                }
                Observation::Dispatch {
                    outcome: if *lose_ack {
                        DisableOutcome::Uncertain {}
                    } else {
                        DisableOutcome::Acknowledged { metadata }
                    },
                }
            }
            Request::Observe { attempt } => {
                let metadata = if attempt.version.version == 1 {
                    world.fixture.first.clone()
                } else {
                    world.fixture.second.clone()
                };
                if world.contradictory {
                    return Ok(Observation::State {
                        readback: DisabledObservation::Inconclusive {
                            reason: ObservationReason::NotFound,
                            metadata: Some(metadata),
                        },
                    });
                }
                Observation::State {
                    readback: if metadata.state == VersionState::Disabled {
                        DisabledObservation::DisabledObservation { metadata }
                    } else {
                        DisabledObservation::Inconclusive {
                            reason: ObservationReason::NotDisabled,
                            metadata: Some(metadata),
                        }
                    },
                }
            }
            Request::Hold { .. } => Observation::Held {},
            Request::Quiescence {} => Observation::Quiescence { observation: None },
        })
    }
}

fn call(session: &mut Session<Fake>, action: &str, now: u64) -> Result<serde_json::Value> {
    session.effect(
        &day2::automation::Request {
            protocol: 1,
            action: action.into(),
            input: "{}".into(),
        },
        now,
    )
}

fn complete(session: &mut Session<Fake>) -> Result<serde_json::Value> {
    let mut result = serde_json::Value::Null;
    for action in ACTIONS {
        result = call(session, action, NOW)?;
    }
    Ok(result)
}

#[test]
fn probes_preserve_uncertainty_and_late_delivery_without_claiming_qualification() -> Result<()> {
    let root = tempfile::tempdir()?;
    let fake = Fake::new();
    let mut session = Session::open(
        &root.path().join("run"),
        profile(),
        fake.clone(),
        NOW,
        false,
    )?;
    let report = complete(&mut session)?;
    assert_eq!(report["provider_qualified"], false);
    assert_eq!(report["origin"], "transport_fixture");
    assert_eq!(
        report["checks"]["lost_ack"],
        "disabled_state_observed_without_redispatch"
    );
    assert_eq!(
        report["checks"]["late_application"],
        "controlled_late_delivery_observed"
    );
    assert_eq!(report["checks"]["physical_quiescence"], "not_configured");
    assert_eq!(fake.0.lock().unwrap().writes.len(), 2);
    Ok(())
}

#[test]
fn crash_before_or_after_provider_application_never_redispatches_original_attempt() -> Result<()> {
    for (boundary, applied) in [(2, false), (2, true), (6, false), (6, true)] {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("run");
        let fake = Fake::new();
        let mut session = Session::open(&directory, profile(), fake.clone(), NOW, false)?;
        for action in &ACTIONS[..boundary] {
            call(&mut session, action, NOW)?;
        }
        fake.0.lock().unwrap().crash = Some(applied);
        assert!(call(&mut session, ACTIONS[boundary], NOW).is_err());
        drop(session);
        let mut reconstructed = Session::open(&directory, profile(), fake.clone(), NOW, true)?;
        let report = complete(&mut reconstructed)?;
        assert_eq!(
            fake.0.lock().unwrap().writes.len(),
            if applied { 2 } else { 1 }
        );
        assert_eq!(
            report["checks"]["lost_ack"],
            if applied || boundary == 6 {
                "disabled_state_observed_without_redispatch"
            } else {
                "inconclusive_no_redispatch"
            }
        );
    }
    Ok(())
}

#[test]
fn completed_session_reconstructs_from_evidence_without_any_provider_calls() -> Result<()> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("run");
    let fake = Fake::new();
    let mut session = Session::open(&directory, profile(), fake.clone(), NOW, false)?;
    let original = complete(&mut session)?;
    drop(session);
    let before = fake.0.lock().unwrap().calls;
    let mut reconstructed = Session::open(&directory, profile(), fake.clone(), NOW, true)?;
    assert_eq!(complete(&mut reconstructed)?, original);
    assert_eq!(fake.0.lock().unwrap().calls, before);
    Ok(())
}

#[test]
fn recipe_reordering_unknown_inputs_and_premature_receipts_make_no_calls() -> Result<()> {
    let root = tempfile::tempdir()?;
    let fake = Fake::new();
    let mut session = Session::open(
        &root.path().join("run"),
        profile(),
        fake.clone(),
        NOW,
        false,
    )?;
    assert!(call(&mut session, "provider-late-deliver", NOW).is_err());
    assert!(call(&mut session, "provider-receipt", NOW).is_err());
    assert!(session.report().is_err());
    assert!(
        session
            .effect(
                &day2::automation::Request {
                    protocol: 1,
                    action: ACTIONS[0].into(),
                    input: "{\"override\":true}".into()
                },
                NOW
            )
            .is_err()
    );
    assert_eq!(fake.0.lock().unwrap().calls, 0);
    Ok(())
}

#[test]
fn aliases_cannot_retarget_the_admitted_numeric_version() -> Result<()> {
    let root = tempfile::tempdir()?;
    let fake = Fake::new();
    fake.0.lock().unwrap().wrong_alias = true;
    let mut session = Session::open(
        &root.path().join("run"),
        profile(),
        fake.clone(),
        NOW,
        false,
    )?;
    call(&mut session, ACTIONS[0], NOW)?;
    assert!(call(&mut session, ACTIONS[1], NOW).is_err());
    assert!(fake.0.lock().unwrap().writes.is_empty());
    Ok(())
}

#[test]
fn expired_scope_cannot_dispatch_and_changed_scope_cannot_resume() -> Result<()> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("run");
    let fake = Fake::new();
    let mut session = Session::open(&directory, profile(), fake.clone(), NOW, false)?;
    call(&mut session, ACTIONS[0], NOW)?;
    call(&mut session, ACTIONS[1], NOW)?;
    assert!(call(&mut session, ACTIONS[2], NOW + 601).is_err());
    assert!(fake.0.lock().unwrap().writes.is_empty());
    drop(session);
    let mut different = profile();
    different.run_marker = "another-run".into();
    assert!(Session::open(&directory, different, fake, NOW, true).is_err());
    Ok(())
}

#[test]
fn journal_is_append_only_and_future_schemas_fail_closed() -> Result<()> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("run");
    let fake = Fake::new();
    let mut session = Session::open(&directory, profile(), fake.clone(), NOW, false)?;
    call(&mut session, ACTIONS[0], NOW)?;
    drop(session);
    let database = rusqlite::Connection::open(directory.join("observations.sqlite3"))?;
    assert!(
        database
            .execute("UPDATE observations SET body='{}'", [])
            .is_err()
    );
    assert!(database.execute("DELETE FROM observations", []).is_err());
    assert!(
        database
            .execute(
                "INSERT OR REPLACE INTO observations SELECT * FROM observations",
                []
            )
            .is_err()
    );
    database.execute_batch("PRAGMA user_version=2")?;
    assert!(Session::open(&directory, profile(), fake, NOW, true).is_err());
    Ok(())
}

#[test]
fn profile_rejects_production_ambient_aliases_and_unbounded_authorization() {
    let mut invalid = profile();
    invalid.environment = "production".to_owned().try_into().unwrap();
    assert!(invalid.validate(NOW).is_err());
    invalid = profile();
    invalid.secret = "real-payroll-token".into();
    assert!(invalid.validate(NOW).is_err());
    invalid = profile();
    invalid.aliases[1] = "latest".into();
    assert!(invalid.validate(NOW).is_err());
    invalid = profile();
    invalid.late_version = invalid.lost_ack_version;
    assert!(invalid.validate(NOW).is_err());
    invalid = profile();
    invalid.expires_at_unix = NOW + 3601;
    assert!(invalid.validate(NOW).is_err());
}

#[test]
fn tokens_require_private_regular_files_and_are_never_in_evidence() -> Result<()> {
    let root = tempfile::tempdir()?;
    let token = root.path().join("token");
    fs::write(&token, "test-token-that-must-not-be-recorded")?;
    fs::set_permissions(&token, fs::Permissions::from_mode(0o644))?;
    assert!(FileToken::load(&token).is_err());
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600))?;
    FileToken::load(&token)?;
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&token, &link)?;
    assert!(FileToken::load(&link).is_err());
    let mut session = Session::open(&root.path().join("run"), profile(), Fake::new(), NOW, false)?;
    let report = serde_json::to_string(&complete(&mut session)?)?;
    assert!(!report.contains("test-token-that-must-not-be-recorded"));
    Ok(())
}

#[test]
fn rejected_delivery_cannot_claim_the_external_disabled_state_as_its_own() -> Result<()> {
    let root = tempfile::tempdir()?;
    let fake = Fake::new();
    fake.0.lock().unwrap().reject_late = true;
    let mut session = Session::open(&root.path().join("run"), profile(), fake, NOW, false)?;
    assert_eq!(
        complete(&mut session)?["checks"]["late_application"],
        "inconclusive"
    );
    Ok(())
}

#[test]
fn contradictory_observation_and_extra_protocol_fields_are_rejected() -> Result<()> {
    for raw in [
        r#"{"kind":"open","extra":1}"#,
        r#"{"kind":"quiescence","extra":1}"#,
    ] {
        assert!(serde_json::from_str::<Request>(raw).is_err());
    }
    assert!(serde_json::from_str::<Observation>(r#"{"kind":"held","extra":1}"#).is_err());
    let root = tempfile::tempdir()?;
    let fake = Fake::new();
    fake.0.lock().unwrap().contradictory = true;
    let mut session = Session::open(&root.path().join("run"), profile(), fake, NOW, false)?;
    for action in &ACTIONS[..3] {
        call(&mut session, action, NOW)?;
    }
    assert!(call(&mut session, ACTIONS[3], NOW).is_err());
    assert!(session.report().is_err());
    Ok(())
}
