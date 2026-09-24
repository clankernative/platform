use day2_control::{
    BindingRef, Digest,
    journal::Journal,
    provider_evidence::{RevisionToken, StateEvidence},
    release::{ImmutableSecretRef, ReleaseNotReady},
};
use rusqlite::Connection;

#[path = "support/release.rs"]
mod support;
use support::*;

#[test]
fn weak_secret_evidence_cannot_grant_readiness_or_raise_qualified_revision() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
    configure(&mut journal, &target("alpha"), &plan("alpha", 1));
    let candidate = approval(&mut journal, "alpha", 1, 0);
    let approved = journal.approve_release(&candidate).unwrap();
    for revision in [
        RevisionToken::Opaque {
            token: "opaque-ready-etag".to_owned().try_into().unwrap(),
        },
        RevisionToken::Ordered {
            stream: Digest::of(&candidate.secret).unwrap(),
            sequence: 999_u64.try_into().unwrap(),
        },
    ] {
        let mut weak = observation(&candidate, 999);
        weak.provider_state = StateEvidence::Observed { revision };
        assert!(
            journal
                .observe_release_secret(&candidate.target, &name("weak"), 0, &weak)
                .is_err()
        );
        assert!(
            journal
                .release_secret_metadata(&candidate.target, &candidate.secret)
                .unwrap()
                .is_none()
        );
        assert!(journal.prepare_release(&approved).is_err());
    }
    journal
        .observe_release_secret(
            &candidate.target,
            &name("qualified"),
            0,
            &observation(&candidate, 1),
        )
        .unwrap();
    let ready = journal.prepare_release(&approved).unwrap();
    journal.activate_release(&ready).unwrap();
}

#[test]
fn qualified_incomparable_or_contradictory_secret_evidence_invalidates_cached_readiness() {
    for change in 0..3 {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
        configure(&mut journal, &target("alpha"), &plan("alpha", 1));
        let candidate = approval(&mut journal, "alpha", 1, 0);
        let approved = journal.approve_release(&candidate).unwrap();
        let original = observation(&candidate, 10);
        journal
            .observe_release_secret(&candidate.target, &name("original"), 0, &original)
            .unwrap();
        let ready = journal.prepare_release(&approved).unwrap();
        let mut conflicting = original.clone();
        conflicting.enabled = false;
        let StateEvidence::Qualified { revision, .. } = &mut conflicting.provider_state else {
            unreachable!()
        };
        match change {
            0 => {
                *revision = RevisionToken::Ordered {
                    stream: Digest::new(b"replacement-provider-epoch"),
                    sequence: 1000_u64.try_into().unwrap(),
                }
            }
            1 => {
                *revision = RevisionToken::Opaque {
                    token: "unknown-new-etag".to_owned().try_into().unwrap(),
                }
            }
            _ => {}
        }
        let events = journal.release_event_count(&candidate.target).unwrap();
        assert!(
            journal
                .observe_release_secret(&candidate.target, &name("conflicting"), 1, &conflicting)
                .is_err()
        );
        assert!(journal.release_event_count(&candidate.target).unwrap() > events);
        assert_eq!(
            journal
                .release_secret_metadata(&candidate.target, &candidate.secret)
                .unwrap(),
            Some((1, original))
        );
        assert!(journal.activate_release(&ready).is_err());
        assert!(journal.prepare_release(&approved).is_err());
        journal
            .observe_release_secret(
                &candidate.target,
                &name("newer-qualified"),
                1,
                &observation(&candidate, 11),
            )
            .unwrap();
        if change < 2 {
            assert!(journal.prepare_release(&approved).is_err());
            assert!(journal.activate_release(&ready).is_err());
            continue;
        }
        let restored = journal.prepare_release(&approved).unwrap();
        assert_ne!(restored.id(), ready.id());
        journal.activate_release(&restored).unwrap();
    }
}

#[test]
fn fresh_receipt_for_identical_qualified_revision_and_state_is_not_a_contradiction() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
    configure(&mut journal, &target("alpha"), &plan("alpha", 1));
    let candidate = approval(&mut journal, "alpha", 1, 0);
    let approved = journal.approve_release(&candidate).unwrap();
    let original = observation(&candidate, 1);
    journal
        .observe_release_secret(&candidate.target, &name("original"), 0, &original)
        .unwrap();
    let ready = journal.prepare_release(&approved).unwrap();
    let mut fresh = original;
    fresh.evidence = Digest::new(b"new-observation-envelope");
    let StateEvidence::Qualified { barrier, .. } = &mut fresh.provider_state else {
        unreachable!()
    };
    barrier.receipt = Digest::new(b"new-qualified-read-receipt");
    let _ = journal.observe_release_secret(&candidate.target, &name("fresh-receipt"), 1, &fresh);
    journal.activate_release(&ready).unwrap();
}

#[test]
fn exact_approved_build_and_secret_activate_atomically_with_idempotent_restart_receipts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    configure(&mut journal, &target("alpha"), &plan("alpha", 1));
    let first = approval(&mut journal, "alpha", 1, 0);
    let approved = journal.approve_release(&first).unwrap();
    assert_eq!(journal.release_state(&first.target).unwrap().active, None);
    let missing = journal.prepare_release(&approved).unwrap_err();
    assert_eq!(
        missing.downcast_ref::<ReleaseNotReady>(),
        Some(&ReleaseNotReady::AwaitingSecretMetadata)
    );
    metadata(&mut journal, &first);
    let ready = journal.prepare_release(&approved).unwrap();
    let receipt = journal.activate_release(&ready).unwrap();
    let events = journal.release_event_count(&first.target).unwrap();
    assert_eq!(journal.activate_release(&ready).unwrap(), receipt);
    assert_eq!(journal.approve_release(&first).unwrap().id(), approved.id());
    assert_eq!(journal.release_event_count(&first.target).unwrap(), events);
    drop(journal);

    let mut journal = Journal::open(&path).unwrap();
    assert_eq!(journal.activate_release(&ready).unwrap(), receipt);
    assert_eq!(
        journal.load_approved_release(approved.id()).unwrap().id(),
        approved.id()
    );
    assert_eq!(
        journal.release_state(&first.target).unwrap().active,
        Some(receipt.clone())
    );

    let second = approval(&mut journal, "alpha", 2, 1);
    let second_approved = journal.approve_release(&second).unwrap();
    journal.approve_release(&first).unwrap();
    let state = journal.release_state(&first.target).unwrap();
    assert_eq!(state.generation, 2);
    assert_eq!(state.desired.as_ref(), Some(second_approved.id()));
    assert_eq!(state.active, Some(receipt.clone()));
    assert!(journal.prepare_release(&approved).is_err());
    metadata(&mut journal, &second);
    let second_ready = journal.prepare_release(&second_approved).unwrap();
    let second_receipt = journal.activate_release(&second_ready).unwrap();
    let events = journal.release_event_count(&first.target).unwrap();
    assert_eq!(journal.activate_release(&ready).unwrap(), receipt);
    assert_eq!(
        journal.release_state(&first.target).unwrap().active,
        Some(second_receipt.clone())
    );
    assert_eq!(journal.release_event_count(&first.target).unwrap(), events);

    let mut disabled = observation(&first, 2);
    disabled.enabled = false;
    journal
        .observe_release_secret(&first.target, &name("old-secret-disabled"), 1, &disabled)
        .unwrap();
    let state = journal.release_state(&first.target).unwrap();
    let events = journal.release_event_count(&first.target).unwrap();
    assert_eq!(journal.activate_release(&ready).unwrap(), receipt);
    assert_eq!(journal.release_state(&first.target).unwrap(), state);
    assert_eq!(state.active, Some(second_receipt));
    assert_eq!(journal.release_event_count(&first.target).unwrap(), events);
}

#[test]
fn wrong_tenant_environment_candidate_evidence_or_policy_cannot_approve() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
    let valid = approval(&mut journal, "alpha", 1, 0);
    assert!(journal.approve_release(&valid).is_err());
    configure(&mut journal, &target("alpha"), &plan("alpha", 1));
    configure(&mut journal, &target("beta"), &plan("alpha", 1));
    for field in 0..7 {
        let mut invalid = valid.clone();
        match field {
            0 => invalid.target.company = name("beta"),
            1 => invalid.target.app = name("other-app"),
            2 => invalid.artifact = Digest::new(b"other-artifact"),
            3 => invalid.evidence = Digest::new(b"other-evidence"),
            4 => invalid.git.commit = plan("alpha", 2).commit,
            5 => invalid.git.source.revision = Digest::new(b"other-repository"),
            _ => invalid.git.policy = Digest::new(b"unapproved-policy"),
        }
        assert!(
            journal.approve_release(&invalid).is_err(),
            "accepted mutation {field}"
        );
    }
    let mut other_environment = valid.clone();
    other_environment.target.environment = name("staging");
    assert!(journal.approve_release(&other_environment).is_err());
    let queued = plan("alpha", 2);
    journal.accept(&queued).unwrap();
    let mut unverified = valid.clone();
    unverified.build_execution = queued.execution_id().unwrap();
    unverified.git.commit = queued.commit;
    assert!(journal.approve_release(&unverified).is_err());
    assert_eq!(journal.release_state(&valid.target).unwrap().generation, 0);
    let approved = journal.approve_release(&valid).unwrap();
    let mut stale_generation = valid.clone();
    stale_generation.request = name("competing-release");
    assert!(journal.approve_release(&stale_generation).is_err());
    let mut rebound = valid.clone();
    rebound.git.actor = actor("other-reviewer");
    assert!(journal.approve_release(&rebound).is_err());
    assert!(journal.prepare_release(&approved).is_err());
}

#[test]
fn secret_readiness_is_per_exact_version_and_old_handles_never_survive_loss_and_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
    configure(&mut journal, &target("alpha"), &plan("alpha", 1));
    let approval = approval(&mut journal, "alpha", 1, 0);
    let approved = journal.approve_release(&approval).unwrap();
    let mut other_approval = approval.clone();
    other_approval.secret.version = 2.try_into().unwrap();
    let other_version = observation(&other_approval, 1);
    journal
        .observe_release_secret(&approval.target, &name("v2"), 0, &other_version)
        .unwrap();
    assert_eq!(
        journal
            .prepare_release(&approved)
            .unwrap_err()
            .downcast_ref::<ReleaseNotReady>(),
        Some(&ReleaseNotReady::AwaitingSecretMetadata)
    );

    for (offset, expected) in [
        ReleaseNotReady::SecretDisabled,
        ReleaseNotReady::SecretAccessDenied,
        ReleaseNotReady::SecretProjectionUnavailable,
    ]
    .into_iter()
    .enumerate()
    {
        let mut missing = observation(&approval, offset as u64 + 1);
        match expected {
            ReleaseNotReady::SecretDisabled => missing.enabled = false,
            ReleaseNotReady::SecretAccessDenied => missing.access_granted = false,
            _ => missing.projection_ready = false,
        }
        journal
            .observe_release_secret(
                &approval.target,
                &name(&format!("missing-{offset}")),
                offset as u64,
                &missing,
            )
            .unwrap();
        assert_eq!(
            journal
                .prepare_release(&approved)
                .unwrap_err()
                .downcast_ref::<ReleaseNotReady>(),
            Some(&expected)
        );
    }
    journal
        .observe_release_secret(
            &approval.target,
            &name("v1-ready"),
            3,
            &observation(&approval, 4),
        )
        .unwrap();
    let old_ready = journal.prepare_release(&approved).unwrap();
    let mut disabled = observation(&approval, 5);
    disabled.enabled = false;
    journal
        .observe_release_secret(&approval.target, &name("disabled"), 4, &disabled)
        .unwrap();
    assert!(journal.activate_release(&old_ready).is_err());
    journal
        .observe_release_secret(
            &approval.target,
            &name("recovered"),
            5,
            &observation(&approval, 6),
        )
        .unwrap();
    assert!(journal.activate_release(&old_ready).is_err());
    assert_eq!(
        journal.release_state(&approval.target).unwrap().active,
        None
    );
    let ready = journal.prepare_release(&approved).unwrap();
    journal.activate_release(&ready).unwrap();
}

#[test]
fn stale_observation_cas_and_provider_order_are_rejected_without_cross_tenant_contamination() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
    let approval = approval(&mut journal, "alpha", 1, 0);
    let first = observation(&approval, 10);
    let receipt = journal
        .observe_release_secret(&approval.target, &name("first"), 0, &first)
        .unwrap();
    assert_eq!(
        journal
            .observe_release_secret(&approval.target, &name("first"), 0, &first)
            .unwrap(),
        receipt
    );
    assert!(
        journal
            .observe_release_secret(
                &approval.target,
                &name("stale-cas"),
                0,
                &observation(&approval, 11)
            )
            .is_err()
    );
    assert!(
        journal
            .observe_release_secret(
                &approval.target,
                &name("stale-provider"),
                1,
                &observation(&approval, 9)
            )
            .is_err()
    );
    assert!(
        journal
            .observe_release_secret(&approval.target, &name("same-provider"), 1, &first)
            .is_err()
    );
    let mut disabled = observation(&approval, 11);
    disabled.access_granted = false;
    journal
        .observe_release_secret(&approval.target, &name("second"), 1, &disabled)
        .unwrap();
    assert_eq!(
        journal
            .observe_release_secret(&approval.target, &name("first"), 0, &first)
            .unwrap(),
        receipt
    );
    configure(&mut journal, &approval.target, &plan("alpha", 1));
    let approved = journal.approve_release(&approval).unwrap();
    assert_eq!(
        journal
            .prepare_release(&approved)
            .unwrap_err()
            .downcast_ref::<ReleaseNotReady>(),
        Some(&ReleaseNotReady::SecretAccessDenied)
    );
    let beta = target("beta");
    journal
        .observe_release_secret(&beta, &name("first"), 0, &first)
        .unwrap();
    assert_eq!(
        journal
            .prepare_release(&approved)
            .unwrap_err()
            .downcast_ref::<ReleaseNotReady>(),
        Some(&ReleaseNotReady::SecretAccessDenied)
    );
}

#[test]
fn cancelled_revoked_superseded_and_changed_authority_never_replace_incumbent() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
    configure(&mut journal, &target("alpha"), &plan("alpha", 1));
    let first = approval(&mut journal, "alpha", 1, 0);
    let approved = journal.approve_release(&first).unwrap();
    metadata(&mut journal, &first);
    let ready = journal.prepare_release(&approved).unwrap();
    let incumbent = journal.activate_release(&ready).unwrap();
    let mut authority_revision = 1;
    for revision in 2..=5 {
        let candidate = approval(&mut journal, "alpha", revision, u64::from(revision - 1));
        let approved = journal.approve_release(&candidate).unwrap();
        metadata(&mut journal, &candidate);
        let ready = journal.prepare_release(&approved).unwrap();
        match revision {
            2 => {
                journal
                    .cancel_release(&approved, &actor("operator"))
                    .unwrap();
                let count = journal.release_event_count(&candidate.target).unwrap();
                journal
                    .cancel_release(&approved, &actor("operator"))
                    .unwrap();
                assert_eq!(
                    journal.release_event_count(&candidate.target).unwrap(),
                    count
                );
                assert!(
                    journal
                        .cancel_release(&approved, &actor("another-operator"))
                        .is_err()
                );
            }
            3 => journal
                .revoke_release(&approved, &actor("reviewer"))
                .unwrap(),
            4 => {
                let old_authority = authority(&plan("alpha", revision));
                let mut changed = old_authority.clone();
                changed.policy = Digest::new(b"new-policy");
                authority_revision = journal
                    .observe_release_authority(
                        &candidate.target,
                        &name("new-policy"),
                        authority_revision,
                        &changed,
                    )
                    .unwrap();
                authority_revision = journal
                    .observe_release_authority(
                        &candidate.target,
                        &name("restored-policy"),
                        authority_revision,
                        &old_authority,
                    )
                    .unwrap();
            }
            _ => {
                let mut successor = candidate.clone();
                successor.request = name("newer-desired");
                successor.expected_generation = 5;
                journal.approve_release(&successor).unwrap();
                journal.approve_release(&candidate).unwrap();
            }
        }
        assert!(journal.activate_release(&ready).is_err());
        assert!(journal.prepare_release(&approved).is_err());
        assert_eq!(
            journal.release_state(&candidate.target).unwrap().active,
            Some(incumbent.clone())
        );
    }
}

#[test]
fn activation_and_audit_are_one_transaction_and_release_history_is_append_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    configure(&mut journal, &target("alpha"), &plan("alpha", 1));
    let candidate = approval(&mut journal, "alpha", 1, 0);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER deny_release_audit BEFORE INSERT ON release_events
        WHEN NEW.kind='approved' BEGIN SELECT RAISE(ABORT,'test audit outage'); END;",
        )
        .unwrap();
    assert!(journal.approve_release(&candidate).is_err());
    assert_eq!(
        journal.release_state(&candidate.target).unwrap().generation,
        0
    );
    connection
        .execute_batch("DROP TRIGGER deny_release_audit;")
        .unwrap();
    let approved = journal.approve_release(&candidate).unwrap();
    metadata(&mut journal, &candidate);
    let ready = journal.prepare_release(&approved).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER deny_release_audit BEFORE INSERT ON release_events
        WHEN NEW.kind='activated' BEGIN SELECT RAISE(ABORT,'test audit outage'); END;",
        )
        .unwrap();
    assert!(journal.activate_release(&ready).is_err());
    assert_eq!(
        journal.release_state(&candidate.target).unwrap().active,
        None
    );
    connection
        .execute_batch("DROP TRIGGER deny_release_audit;")
        .unwrap();
    journal.activate_release(&ready).unwrap();
    for table in ["release_events", "release_approvals", "release_activations"] {
        assert!(
            connection
                .execute(&format!("UPDATE {table} SET body=body"), [])
                .is_err()
        );
        assert!(
            connection
                .execute(&format!("DELETE FROM {table}"), [])
                .is_err()
        );
    }
    connection
        .execute_batch("PRAGMA recursive_triggers=OFF;")
        .unwrap();
    assert!(
        connection
            .execute(
                "INSERT OR REPLACE INTO release_events(sequence,target,kind,body)
        SELECT sequence,target,'replacement','{}' FROM release_events LIMIT 1",
                []
            )
            .is_err()
    );
}

#[test]
fn future_release_schema_fails_before_schema_repair_or_migration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.sqlite");
    drop(Journal::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("UPDATE release_meta SET version=99; DROP TABLE release_readiness;")
        .unwrap();
    let before: String = connection
        .query_row(
            "SELECT group_concat(sql,';') FROM
        (SELECT sql FROM sqlite_schema ORDER BY name)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(Journal::open(&path).is_err());
    let after: String = connection
        .query_row(
            "SELECT group_concat(sql,';') FROM
        (SELECT sql FROM sqlite_schema ORDER BY name)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(before, after);
}

#[test]
fn secret_contract_rejects_zero_mutable_aliases_and_unrecognized_fields() {
    let reference = ImmutableSecretRef {
        binding: BindingRef::pin(name("secrets"), &"project-number").unwrap(),
        secret: name("credential"),
        version: 1.try_into().unwrap(),
    };
    for version in [
        serde_json::json!(0),
        serde_json::json!("latest"),
        serde_json::json!(null),
    ] {
        let mut value = serde_json::to_value(&reference).unwrap();
        value["version"] = version;
        assert!(serde_json::from_value::<ImmutableSecretRef>(value).is_err());
    }
    let mut value = serde_json::to_value(&reference).unwrap();
    value["secret_value"] = serde_json::json!("not-an-admitted-field");
    assert!(serde_json::from_value::<ImmutableSecretRef>(value).is_err());
}

#[test]
fn two_connection_races_serialize_readiness_revocation_and_desired_generation_with_their_audits() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("readiness-race.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    configure(&mut journal, &target("alpha"), &plan("alpha", 1));
    let candidate = approval(&mut journal, "alpha", 1, 0);
    let approved = journal.approve_release(&candidate).unwrap();
    metadata(&mut journal, &candidate);
    let ready = journal.prepare_release(&approved).unwrap();
    let before = journal.release_event_count(&candidate.target).unwrap();
    let mut disabled = observation(&candidate, 2);
    disabled.enabled = false;
    let mut activation_journal = Journal::open(&path).unwrap();
    let mut secret_journal = Journal::open(&path).unwrap();
    let barrier = std::sync::Barrier::new(2);

    // The OS chooses the winner. This qualifies SQLite serialization, not the
    // deterministic simulator's scheduling or coverage of both orderings.
    let (activation, secret) = std::thread::scope(|scope| {
        let activation = scope.spawn(|| {
            barrier.wait();
            activation_journal.activate_release(&ready)
        });
        let secret = scope.spawn(|| {
            barrier.wait();
            secret_journal.observe_release_secret(
                &candidate.target,
                &name("disable-race"),
                1,
                &disabled,
            )
        });
        (activation.join().unwrap(), secret.join().unwrap())
    });
    assert_eq!(secret.unwrap().revision, 2);
    let connection = Connection::open(&path).unwrap();
    let disable_sequence: i64 = connection
        .query_row(
            "SELECT max(sequence) FROM release_events WHERE kind='secret'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let activation_count: i64 = connection
        .query_row("SELECT count(*) FROM release_activations", [], |row| {
            row.get(0)
        })
        .unwrap();
    match activation {
        Ok(receipt) => {
            let activation_sequence: i64 = connection
                .query_row(
                    "SELECT sequence FROM release_events WHERE kind='activated'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(activation_sequence < disable_sequence);
            assert_eq!(activation_count, 1);
            assert_eq!(
                journal.release_state(&candidate.target).unwrap().active,
                Some(receipt)
            );
            assert_eq!(
                journal.release_event_count(&candidate.target).unwrap(),
                before + 2
            );
        }
        Err(error) => {
            assert_eq!(
                error.downcast_ref::<ReleaseNotReady>(),
                Some(&ReleaseNotReady::SecretDisabled)
            );
            assert_eq!(activation_count, 0);
            assert_eq!(
                journal.release_state(&candidate.target).unwrap().active,
                None
            );
            assert_eq!(
                journal.release_event_count(&candidate.target).unwrap(),
                before + 1
            );
        }
    }

    let path = directory.path().join("desired-race.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    configure(&mut journal, &target("alpha"), &plan("alpha", 1));
    let baseline = approval(&mut journal, "alpha", 1, 0);
    let approved = journal.approve_release(&baseline).unwrap();
    metadata(&mut journal, &baseline);
    let ready = journal.prepare_release(&approved).unwrap();
    let incumbent = journal.activate_release(&ready).unwrap();
    let first = approval(&mut journal, "alpha", 2, 1);
    let second = approval(&mut journal, "alpha", 3, 1);
    let before = journal.release_event_count(&baseline.target).unwrap();
    let mut first_journal = Journal::open(&path).unwrap();
    let mut second_journal = Journal::open(&path).unwrap();
    let barrier = std::sync::Barrier::new(2);
    let (first_result, second_result) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            first_journal.approve_release(&first)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            second_journal.approve_release(&second)
        });
        (first.join().unwrap(), second.join().unwrap())
    });
    let (winner, rejection) = match (first_result, second_result) {
        (Ok(winner), Err(rejection)) | (Err(rejection), Ok(winner)) => (winner, rejection),
        other => panic!("expected exactly one generation winner, got {other:?}"),
    };
    assert!(rejection.to_string().contains("stale desired generation"));
    let state = journal.release_state(&baseline.target).unwrap();
    assert_eq!(state.generation, 2);
    assert_eq!(state.desired.as_ref(), Some(winner.id()));
    assert_eq!(state.active, Some(incumbent));
    assert_eq!(
        journal.release_event_count(&baseline.target).unwrap(),
        before + 1
    );
    let connection = Connection::open(&path).unwrap();
    let (approvals, pending): (i64, i64) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM release_approvals),
                (SELECT count(*) FROM release_status WHERE status='approved')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((approvals, pending), (2, 1));
}
