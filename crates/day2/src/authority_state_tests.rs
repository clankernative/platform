use super::*;
use crate::authority::{Mode, OperationPolicy};
use crate::security_epoch::restore_authority::RestoreFenceSchema;
use day2_capabilities::{
    BindingRef, Name,
    credentials::{
        CredentialRoot, DeliveryProfile, FamilyDeclaration, GrantMode, ManagedProfile,
        ManagementPredicate, Namespace, RotationProfile, SourceLocation,
    },
    oauth::{
        AuthorityNode, OperationAuthorityContract, OperationKind, ResourceAudienceRef,
        SecurityOriginRef,
    },
};
use rusqlite::TransactionBehavior;
use std::{collections::BTreeMap, sync::mpsc, thread, time::Duration};

#[test]
fn activated_credential_selection_pins_policy_family_and_artifact() -> Result<()> {
    fn name(value: &str) -> Name {
        Name::try_from(value.to_owned()).unwrap()
    }

    fn pin(value: &str) -> BindingRef {
        BindingRef::pin(name(value), &value).unwrap()
    }

    let root = OperationAuthorityContract::derive(
        "submit".into(),
        1,
        Digest::of(&"submit-v1")?,
        OperationKind::Command,
        AuthorityNode {
            actions: BTreeSet::new(),
            children: BTreeMap::new(),
        },
    )?;
    let approved: BTreeMap<String, OperationAuthorityContract> =
        BTreeMap::from([("submit".into(), root.clone())]);
    let family = day2_capabilities::credentials::ManifestFamily::derive(
        FamilyDeclaration {
            registration: name("keys"),
            id: name("keys"),
            profile: ManagedProfile::Client,
            grant: GrantMode::Fixed,
            roots: vec!["submit".into()],
            lifetime_seconds: 3600,
            source: SourceLocation {
                file: "App.roc".into(),
                line: 1,
            },
        },
        &BTreeMap::from([(
            "submit".into(),
            CredentialRoot {
                authority: root,
                direct_ingress: true,
                interactive_security: false,
                single_resource_model: None,
            },
        )]),
    )?;
    let policy = ManagementPolicy {
        identity_authority: pin("people"),
        issue: ManagementPredicate::Creator,
        read_metadata: ManagementPredicate::Creator,
        rotate: ManagementPredicate::Creator,
        revoke: ManagementPredicate::Creator,
    };
    let binding = CredentialFamilyBinding {
        namespace: Namespace {
            installation: name("acme"),
            environment: name("dev"),
            app: name("reports"),
            binding_generation: 1,
        },
        family: name("keys"),
        approved_authority: BindingRef {
            id: name("approved"),
            revision: Digest::of(&("credential-approved-authority-v1", &approved))?,
        },
        management: BindingRef::pin(name("managers"), &policy)?,
        rotation: RotationProfile::AtomicReplace,
        delivery: DeliveryProfile::AuthenticatedCreatorReveal,
        verifier: pin("verifier"),
        custody: pin("custody"),
        security_shell: SecurityOriginRef(pin("security")),
        audience: ResourceAudienceRef(pin("audience")),
        epoch_store: pin("epoch"),
        max_lifetime_seconds: 3600,
        reveal_window_seconds: 300,
        quota: pin("quota"),
    };
    let instance = |selected: Option<&CredentialFamilyBinding>, policy: &ManagementPolicy| {
        let bindings = selected
            .map(|value| BTreeMap::from([("keys", value)]))
            .unwrap_or_default();
        let bytes = serde_json::to_vec(&serde_json::json!({
            "installation": "acme", "environment": "dev",
            "apps": {"reports": {"artifact": "unused", "readers": [], "writers": [],
                "credential_families": bindings}},
            "resources": {"version": 1, "connections": {}, "resources": {}, "policies": {},
                "credentials": {"management": {"managers": policy},
                    "approved_authority": {"approved": approved}}}
        }))?;
        if selected.is_some() {
            // Deliberately incomplete DATA for pure composition, not CURRENT.
            let error = Instance::from_bytes(&bytes).unwrap_err();
            assert!(error.to_string().contains("credential_runtime_missing"));
            crate::json::decode(&bytes)
        } else {
            Instance::from_bytes(&bytes)
        }
    };
    let selected = instance(Some(&binding), &policy)?;
    let active = resolve_credentials(
        &selected,
        "reports",
        "artifact-one",
        std::slice::from_ref(&family),
    )?;
    assert_eq!(
        active["keys"].qualification.family_contract,
        family.contract
    );
    assert_eq!(active["keys"].management, policy);
    assert_ne!(
        active["keys"].qualification.composition,
        resolve_credentials(
            &selected,
            "reports",
            "artifact-two",
            std::slice::from_ref(&family)
        )?["keys"]
            .qualification
            .composition
    );
    assert!(
        resolve_credentials(
            &instance(None, &policy)?,
            "reports",
            "artifact-one",
            std::slice::from_ref(&family)
        )
        .is_err()
    );
    let mut document = document();
    document.credentials = active;
    let authority = ActiveAuthority {
        stamp: AuthorityStamp {
            epoch: "test".into(),
            revision: 1,
        },
        document,
        artifact_id: "artifact-one".into(),
        artifact_path: String::new(),
    };
    let session = crate::web_security::Session {
        hash: "test".into(),
        actor: "alice".into(),
        expires: 100,
        origin: None,
    };
    let manifest = [family.clone()];
    let read = crate::managed_credentials::metadata_read(
        "reports",
        "acme/dev/reports",
        "artifact-one",
        &manifest,
        &authority,
        &session,
        "keys",
    )?;
    assert_eq!(read.policy, &policy);
    assert_eq!(read.requester, "alice");
    assert!(
        crate::managed_credentials::metadata_read(
            "reports",
            "acme/prod/reports",
            "artifact-one",
            &manifest,
            &authority,
            &session,
            "keys"
        )
        .is_err()
    );
    assert!(
        crate::managed_credentials::metadata_read(
            "reports",
            "acme/dev/reports",
            "artifact-two",
            &manifest,
            &authority,
            &session,
            "keys"
        )
        .is_err()
    );
    let changed = ManagementPolicy {
        read_metadata: ManagementPredicate::MemberOf {
            group: name("admins"),
        },
        ..policy
    };
    assert!(
        resolve_credentials(
            &instance(Some(&binding), &changed)?,
            "reports",
            "artifact-one",
            &[family]
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn desired_receipts_survive_expiry_and_artifact_changes_without_reactivating_grants() -> Result<()>
{
    let mut original_document = document();
    let operation = original_document
        .policy
        .as_mut()
        .unwrap()
        .operations
        .get_mut("items.write")
        .unwrap();
    operation
        .observations
        .insert("notifications.recipient.v1".into());
    let (mut catalog, mut attachments) = crate::development::local_resource_fixture(
        "app",
        original_document.policy.as_ref().unwrap(),
        Some(day2_capabilities::resources::TopicScope::Any),
        None,
    )?;
    for policy in catalog.policies.values_mut() {
        policy.max_duration_seconds = Some(1);
    }
    for attachment in &mut attachments {
        attachment.expires_at_ms = Some(1500);
    }
    let mut instance: Instance = serde_json::from_value(serde_json::json!({
        "installation":"test","environment":"test","resources":catalog,
        "apps":{"app":{"artifact":"/admitted/one","readers":["viewer"],"writers":["alice"],
            "authority":original_document.policy,"resource_policies":attachments}}
    }))?;
    original_document.resources = instance.resources.as_ref().unwrap().resolve(
        "app",
        &instance.apps["app"].resource_policies,
        1000,
    )?;
    let operator = LocalOperator::assert_local("operator")?;
    let mut db = Connection::open_in_memory()?;
    initialize(&mut db)?;
    let expected = Some(current(&db)?.stamp);
    let source = desired_fingerprint(&instance, "app", &operator, &expected, None)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let change = ApplyAuthority {
        request_id: "temporary-grant".into(),
        expected: expected.clone(),
        document: original_document,
    };
    let receipt = apply_transition_in(
        &tx,
        &operator,
        &change,
        ("artifact-one", Path::new("/admitted/one")),
        active(),
    )?;
    pin_desired_receipt_in(&tx, &change.request_id, &source, &receipt)?;
    tx.commit()?;
    assert!(
        instance
            .resources
            .as_ref()
            .unwrap()
            .resolve("app", &instance.apps["app"].resource_policies, 2000)
            .is_err()
    );
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut next = active();
    next.artifact_id = "artifact-two".into();
    next.artifact_path = "/admitted/two".into();
    let upgrade = ApplyAuthority {
        request_id: "next-artifact".into(),
        expected: Some(receipt.stamp.clone()),
        document: document(),
    };
    apply_transition_in(
        &tx,
        &operator,
        &upgrade,
        ("artifact-one", Path::new("/admitted/one")),
        next,
    )?;
    let latest = current(&tx)?;
    instance.apps.get_mut("app").unwrap().artifact = "/admitted/two".into();
    assert_eq!(
        desired_fingerprint(&instance, "app", &operator, &expected, None)?,
        source
    );
    assert_eq!(
        cached_desired_receipt_in(&tx, "temporary-grant", &source)?,
        Some(receipt.clone())
    );
    assert_eq!(current(&tx)?, latest);
    let changed_operator = desired_fingerprint(
        &instance,
        "app",
        &LocalOperator::assert_local("other")?,
        &expected,
        None,
    )?;
    assert!(cached_desired_receipt_in(&tx, "temporary-grant", &changed_operator).is_err());
    instance.apps.get_mut("app").unwrap().resource_policies[0].expires_at_ms = Some(2500);
    let changed_source = desired_fingerprint(&instance, "app", &operator, &expected, None)?;
    assert!(cached_desired_receipt_in(&tx, "temporary-grant", &changed_source).is_err());
    assert!(
        tx.execute(
            "UPDATE day2_authority_desired_requests SET fingerprint='forged'",
            []
        )
        .is_err()
    );
    assert!(
        tx.execute("DELETE FROM day2_authority_desired_requests", [])
            .is_err()
    );
    fence_restored_in(&tx, latest, Path::new("/restored/two"))?;
    assert!(cached_desired_receipt_in(&tx, "temporary-grant", &source)?.is_none());
    tx.commit()?;
    Ok(())
}

#[test]
fn resource_resolution_intersects_membership_and_operation_revocation_and_old_snapshots_deny()
-> Result<()> {
    use day2_capabilities::resources::Action;
    let operation: Operation = serde_json::from_value(serde_json::json!({
        "name":"items.write","kind":"command","input_type":"input","output_type":"output"
    }))?;
    let mut granted = document();
    let approved = granted
        .policy
        .as_mut()
        .unwrap()
        .operations
        .get_mut("items.write")
        .unwrap();
    approved
        .observations
        .insert("notifications.recipient.v1".into());
    approved.effects.insert("notifications.send.v1".into());
    granted.resources = serde_json::from_value(serde_json::json!({
        "operations":{"items.write":{"notifications":{
            "policy":{"id":"updates","revision":1},
            "resource":{"id":"mailbox","revision":1},
            "connection":{"id":"local","revision":1},
            "provider":"local_notifications","target":{"kind":"notification_mailbox","topics":{"kind":"any"}},
            "actions":["notifications_resolve","notifications_send"],"actors":["alice","viewer"],
            "limits":{"max_request_bytes":1024,"max_response_bytes":1024,"max_calls_per_invocation":5},
            "budgets":[],"expires_at_ms":null
        }}},"budgets":{}
    }))?;
    let mut effective = granted.clone();
    effective.attenuate_resources(std::slice::from_ref(&operation))?;
    assert_eq!(
        effective.resources.operations["items.write"]["notifications"].actors,
        BTreeSet::from(["alice".into()])
    );
    effective
        .policy
        .as_mut()
        .unwrap()
        .operations
        .get_mut("items.write")
        .unwrap()
        .effects
        .clear();
    effective.attenuate_resources(std::slice::from_ref(&operation))?;
    assert_eq!(
        effective.resources.operations["items.write"]["notifications"].actions,
        BTreeSet::from([Action::NotificationsResolve])
    );
    for remove in 0..3 {
        let mut revoked = granted.clone();
        match remove {
            0 => revoked.writers.clear(),
            1 => {
                revoked
                    .policy
                    .as_mut()
                    .unwrap()
                    .operations
                    .remove("items.write");
            }
            _ => revoked.policy = None,
        }
        revoked.attenuate_resources(std::slice::from_ref(&operation))?;
        assert!(revoked.resources.is_empty());
    }
    let mut legacy = serde_json::to_value(granted)?;
    legacy.as_object_mut().unwrap().remove("resources");
    assert!(
        serde_json::from_value::<AuthorityDocument>(legacy)?
            .resources
            .is_empty()
    );
    Ok(())
}

#[test]
fn policy_retry_after_artifact_upgrade_returns_original_receipt_and_rejects_activation_id_reuse()
-> Result<()> {
    for legacy in [false, true] {
        let mut connection = Connection::open_in_memory()?;
        if legacy {
            connection.execute_batch(
                "CREATE TABLE day2_invocations(id TEXT PRIMARY KEY,status TEXT NOT NULL)",
            )?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            upgrade(&tx)?;
            tx.commit()?;
        } else {
            initialize(&mut connection)?;
        }
        let operator = LocalOperator::assert_local("operator")?;
        let original_request = ApplyAuthority {
            request_id: "policy-before-upgrade".into(),
            expected: if legacy {
                None
            } else {
                Some(current(&connection)?.stamp)
            },
            document: document(),
        };
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let original_receipt = apply_transition_in(
            &tx,
            &operator,
            &original_request,
            ("artifact-one", Path::new("/admitted/one")),
            active(),
        )?;
        let mut upgraded = active();
        upgraded.artifact_id = "artifact-two".into();
        upgraded.artifact_path = "/admitted/two".into();
        let upgrade_request = ApplyAuthority {
            request_id: "explicit-artifact-upgrade".into(),
            expected: Some(original_receipt.stamp.clone()),
            document: document(),
        };
        let upgrade_receipt = apply_transition_in(
            &tx,
            &operator,
            &upgrade_request,
            ("artifact-one", Path::new("/admitted/one")),
            upgraded,
        )?;
        assert_eq!(
            cached_policy_receipt_in(&tx, &operator, &original_request)?,
            Some(original_receipt)
        );
        assert_eq!(current(&tx)?.stamp, upgrade_receipt.stamp);
        assert_eq!(current(&tx)?.artifact_id, "artifact-two");
        assert!(cached_policy_receipt_in(&tx, &operator, &upgrade_request).is_err());
        let mut different_document = original_request.clone();
        different_document.document.enabled = false;
        assert!(cached_policy_receipt_in(&tx, &operator, &different_document).is_err());
        let saved = current(&tx)?;
        fence_restored_in(&tx, saved, Path::new("/restored/two"))?;
        assert!(cached_policy_receipt_in(&tx, &operator, &original_request)?.is_none());
        tx.commit()?;
    }
    Ok(())
}

#[test]
fn blocked_work_releases_cursor_capacity_without_discarding_history() -> Result<()> {
    let mut connection = Connection::open_in_memory()?;
    initialize(&mut connection)?;
    connection.execute_batch("CREATE TABLE day2_selection_cursor_pins(token TEXT,invocation TEXT,PRIMARY KEY(token,invocation))")?;
    let original = current(&connection)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("INSERT INTO day2_invocations VALUES('old','pending')", [])?;
    pin_invocation(&tx, "old", &original.stamp)?;
    tx.execute(
        "INSERT INTO day2_selection_cursor_pins VALUES('old-cursor','old')",
        [],
    )?;
    let receipt = change(&tx, &original.stamp, document(), "revoke-old")?;
    assert_eq!(
        tx.query_row(
            "SELECT count(*) FROM day2_selection_cursor_pins",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(invocation_stamp(&tx, "old")?, original.stamp);
    assert_eq!(
        tx.query_row(
            "SELECT status FROM day2_invocations WHERE id='old'",
            [],
            |row| row.get::<_, String>(0)
        )?,
        "pending"
    );
    tx.execute(
        "INSERT INTO day2_invocations VALUES('direct','pending')",
        [],
    )?;
    pin_invocation(&tx, "direct", &receipt.stamp)?;
    tx.execute(
        "INSERT INTO day2_selection_cursor_pins VALUES('next-cursor','direct')",
        [],
    )?;
    block_invocation(&tx, "direct", "authority_policy_changed")?;
    assert_eq!(
        tx.query_row(
            "SELECT count(*) FROM day2_selection_cursor_pins",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(invocation_stamp(&tx, "direct")?, receipt.stamp);
    tx.commit()?;
    Ok(())
}

#[test]
fn restore_fences_old_work_and_requires_explicit_new_activation() -> Result<()> {
    let mut connection = Connection::open_in_memory()?;
    initialize(&mut connection)?;
    let original = current(&connection)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT INTO day2_invocations VALUES('copied','pending')",
        [],
    )?;
    pin_invocation(&tx, "copied", &original.stamp)?;
    fence_restored_in(&tx, original.clone(), Path::new("/restored/one"))?;
    let fenced = current(&tx)?;
    assert_ne!(fenced.stamp.epoch, original.stamp.epoch);
    assert_eq!(fenced.stamp.revision, original.stamp.revision + 1);
    assert_eq!(fenced.artifact_id, original.artifact_id);
    assert_eq!(fenced.artifact_path, "/restored/one");
    assert!(!fenced.document.enabled);
    assert!(is_blocked(&tx, "copied")?);
    assert!(pin_invocation(&tx, "copied", &fenced.stamp).is_err());
    let request = ApplyAuthority {
        request_id: "approve-restored-instance".into(),
        expected: Some(fenced.stamp.clone()),
        document: original.document.clone(),
    };
    let receipt = apply_transition_in(
        &tx,
        &LocalOperator::assert_local("operator")?,
        &request,
        ("artifact-one", Path::new("/restored/one")),
        fenced.clone(),
    )?;
    assert_eq!(receipt.stamp.epoch, fenced.stamp.epoch);
    assert_eq!(receipt.stamp.revision, fenced.stamp.revision + 1);
    assert!(current(&tx)?.document.enabled);
    assert!(is_blocked(&tx, "copied")?);
    assert_eq!(invocation_stamp(&tx, "copied")?, original.stamp);
    assert!(pin_invocation(&tx, "copied", &receipt.stamp).is_err());
    tx.commit()?;
    Ok(())
}

#[test]
fn prepared_restore_fence_keeps_real_usage_unknown_holds_and_old_work_across_reopen() -> Result<()>
{
    use crate::budget::{BudgetContext, Consumption, ReservationRequest, Settlement};
    use day2_capabilities::resources::{BudgetDefinition, BudgetLimits, BudgetScope};
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("app.sqlite");
    let mut db = Connection::open(&path)?;
    initialize_restore_fence(&mut db)?;
    let token = "a".repeat(43);
    db.execute(
        "INSERT INTO day2_web_sessions VALUES(?1,'alice',200)",
        [crate::digest(token.as_bytes())],
    )?;
    db.execute("INSERT INTO day2_web_secret VALUES(1,?1)", [&[7u8; 32][..]])?;
    assert_eq!(
        crate::web_security::session_for_token_in(&db, &token, 100)?.actor,
        "alice"
    );
    let previous = current(&db)?;
    let request = |id: &str| ReservationRequest {
        id: id.into(),
        binding: "authority+resource+input".into(),
        context: BudgetContext {
            app: "app".into(),
            actor: "alice".into(),
            connection: "mailbox".into(),
            invocation_root: "copied".into(),
            now: 100,
        },
        budgets: BTreeMap::from([(
            "app".into(),
            BudgetDefinition {
                revision: 1,
                scope: BudgetScope::App,
                period_seconds: 60,
                limits: BudgetLimits {
                    calls: Some(100),
                    ..Default::default()
                },
            },
        )]),
        quote: Consumption {
            calls: 3,
            bytes: 100,
            concurrency: 1,
            ..Default::default()
        },
    };
    let outgoing = serde_json::to_string(&crate::delegation_commands::Delivery {
        first_at: 90,
        incarnation: "original-source".into(),
    })?;
    {
        let tx = db.transaction()?;
        tx.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status) VALUES('copied','submit','alice','{}','artifact-one',100,'pending')",[])?;
        pin_invocation(&tx, "copied", &previous.stamp)?;
        crate::delegation_commands::upgrade(&tx)?;
        tx.execute(
            "INSERT INTO day2_app_outgoing VALUES('unknown-send','exact-fingerprint',?1,'copied')",
            [&outgoing],
        )?;
        crate::delegation_commands::restore_fence_in(&tx, 200)?;
        let known = crate::budget::reserve_in(&tx, &request("known"))?;
        crate::budget::settle_in(
            &tx,
            &known,
            &Settlement::Known {
                actual: Consumption {
                    calls: 2,
                    bytes: 80,
                    ..Default::default()
                },
            },
        )?;
        let unknown = crate::budget::reserve_in(&tx, &request("unknown"))?;
        crate::budget::settle_in(&tx, &unknown, &Settlement::Unknown)?;
        tx.commit()?;
    }
    let before = {
        let snapshot = db.transaction()?;
        let value = crate::budget::inspect_in(&snapshot)?;
        snapshot.commit()?;
        value
    };
    assert_eq!(before.known_usage.calls, 2);
    assert_eq!(before.unknown_usage.len(), 1);
    assert!(
        before
            .accounts
            .iter()
            .any(|account| account.used == 2 && account.reserved == 3)
    );
    // Preparation itself has no SQL effect and gives no restore permission.
    let schema = RestoreFenceSchema::prepare()?;
    let prepared = PreparedRestoreFence::new(
        previous.clone(),
        Path::new("/restored/one"),
        Digest::new(b"fresh-prepared-restore"),
        100,
    )?;
    assert!(db.is_autocommit());
    assert_eq!(current(&db)?, previous);
    {
        let tx = db.transaction()?;
        crate::oauth::schema::admit(&tx, |db| prepared.apply_in(db, &schema))?;
        assert!(is_blocked(&tx, "copied")?);
        assert!(pin_invocation(&tx, "copied", &current(&tx)?.stamp).is_err());
        tx.commit()?;
    }
    drop(db);
    for _ in 0..2 {
        let mut reopened = Connection::open(&path)?;
        let active = current(&reopened)?;
        assert!(!active.document.enabled);
        assert_ne!(active.stamp.epoch, previous.stamp.epoch);
        assert_eq!(active.stamp.revision, previous.stamp.revision + 1);
        assert_eq!(active.artifact_id, previous.artifact_id);
        assert_eq!(active.artifact_path, "/restored/one");
        assert!(crate::web_security::session_for_token_in(&reopened, &token, 100).is_err());
        assert_eq!(
            reopened.query_row("SELECT count(*) FROM day2_web_secret", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        assert_eq!(invocation_stamp(&reopened, "copied")?, previous.stamp);
        let after = {
            let snapshot = reopened.transaction()?;
            let value = crate::budget::inspect_in(&snapshot)?;
            snapshot.commit()?;
            value
        };
        assert!(after.frozen_after_restore);
        assert_eq!(after.ledger_id, before.ledger_id);
        assert_eq!(after.accounts, before.accounts);
        assert_eq!(after.known_usage, before.known_usage);
        assert_eq!(after.unknown_usage, before.unknown_usage);
        assert_eq!(after.outstanding_attempts, before.outstanding_attempts);
        assert_eq!(
            reopened.query_row(
                "SELECT delivery FROM day2_app_outgoing WHERE identity='unknown-send'",
                [],
                |r| r.get::<_, String>(0)
            )?,
            outgoing
        );
        assert_eq!(
            reopened.query_row(
                "SELECT not_before FROM day2_app_restore_fence WHERE singleton=1",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            200
        );
        let tx = reopened.transaction()?;
        assert!(crate::oauth::schema::admit(&tx, |db| prepared.apply_in(db, &schema)).is_err());
        assert!(crate::budget::reserve_in(&tx, &request("new-work")).is_err());
        assert_eq!(current(&tx)?, active);
        tx.rollback()?;
    }
    Ok(())
}

#[test]
fn prepared_restore_fence_refuses_changed_snapshot_reused_epoch_and_invalid_input_before_writes()
-> Result<()> {
    for cut in 0..5 {
        let mut db = Connection::open_in_memory()?;
        initialize_restore_fence(&mut db)?;
        let original = current(&db)?;
        let replacement = Digest::new(b"prepared-target-epoch");
        let schema = RestoreFenceSchema::prepare()?;
        let prepared = PreparedRestoreFence::new(
            original.clone(),
            Path::new("/restored/one"),
            replacement.clone(),
            100,
        )?;
        let tx = db.transaction()?;
        match cut {
            0 => {
                tx.execute(
                    "UPDATE day2_authority SET artifact_path='/different-current-path'",
                    [],
                )?;
            }
            1 => {
                let mut changed = original.clone();
                changed.document.readers.insert("new-reader".into());
                tx.execute(
                    "UPDATE day2_authority SET document=?1",
                    [serde_json::to_string(&changed.document)?],
                )?;
            }
            2 => {
                tx.execute("INSERT INTO day2_authority_history SELECT ?1,revision,document,artifact_id,artifact_path,operator,reason FROM day2_authority_history LIMIT 1",[replacement.as_str()])?;
            }
            3 => {
                tx.execute_batch(
                    "CREATE TEMP TABLE day2_authority AS SELECT * FROM main.day2_authority",
                )?;
            }
            _ => {
                tx.execute_batch("ATTACH ':memory:' AS unselected")?;
            }
        }
        let before = current(&tx)?;
        assert!(crate::oauth::schema::admit(&tx, |db| prepared.apply_in(db, &schema)).is_err());
        assert_eq!(current(&tx)?, before);
        assert_eq!(
            tx.query_row(
                "SELECT restored FROM day2_budget_meta WHERE singleton=1",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            0
        );
        tx.rollback()?;
        assert!(prepared.apply_in(&db, &schema).is_err());
        assert!(
            PreparedRestoreFence::new(
                original.clone(),
                Path::new("/restored/one"),
                Digest::try_from(original.stamp.epoch.clone())?,
                100
            )
            .is_err()
        );
        assert!(
            PreparedRestoreFence::new(original, Path::new("/restored/one"), replacement, -1)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn prepared_restore_fence_rejects_partial_unknown_or_corrupt_units_without_repair() -> Result<()> {
    for mutation in [
        "DROP TABLE day2_app_restore_fence",
        "DROP TRIGGER day2_budget_reservations_no_update",
        "DELETE FROM day2_budget_meta",
        "UPDATE day2_budget_meta SET pool_return_version=0",
        "CREATE TABLE day2_budget_unrecognized(value INTEGER)",
        "CREATE TRIGGER extra_restore_trigger AFTER UPDATE ON day2_authority BEGIN UPDATE day2_budget_meta SET restored=0; END",
        "DROP TABLE day2_web_secret",
        "ALTER TABLE day2_invocations ADD COLUMN unreviewed INTEGER",
    ] {
        let mut db = Connection::open_in_memory()?;
        initialize_restore_fence(&mut db)?;
        let original = current(&db)?;
        let schema = RestoreFenceSchema::prepare()?;
        let prepared = PreparedRestoreFence::new(
            original.clone(),
            Path::new("/restored/one"),
            Digest::new(b"unrepaired-fence"),
            100,
        )?;
        db.execute_batch(mutation)?;
        let before_schema: Vec<(String, String, Option<String>)> = db
            .prepare("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let before_meta: Vec<(String, i64, i64)> = db
            .prepare("SELECT ledger_id,restored,pool_return_version FROM day2_budget_meta")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        // Catching and committing the refusal cannot publish a replacement
        // table, guard, ledger or current marker from an initializer.
        let tx = db.transaction()?;
        assert!(
            crate::oauth::schema::admit(&tx, |db| prepared.apply_in(db, &schema)).is_err(),
            "{mutation}"
        );
        tx.commit()?;
        assert_eq!(current(&db)?, original);
        let after_schema: Vec<(String, String, Option<String>)> = db
            .prepare("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let after_meta: Vec<(String, i64, i64)> = db
            .prepare("SELECT ledger_id,restored,pool_return_version FROM day2_budget_meta")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        assert_eq!(after_schema, before_schema);
        assert_eq!(after_meta, before_meta);
    }
    Ok(())
}

#[test]
fn prepared_restore_fence_requires_same_active_scope_and_preserves_the_actual_hook() -> Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let mut db = Connection::open_in_memory()?;
    initialize_restore_fence(&mut db)?;
    let mut other = Connection::open_in_memory()?;
    initialize_restore_fence(&mut other)?;
    let schema = RestoreFenceSchema::prepare()?;
    let original = current(&db)?;
    let prepared = PreparedRestoreFence::new(
        original.clone(),
        Path::new("/restored/one"),
        Digest::new(b"hook-fence"),
        100,
    )?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    db.progress_handler(
        1,
        Some(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            crate::oauth::schema::admission_step(1)
        }),
    )?;
    let tx = db.transaction()?;
    assert!(prepared.apply_in(&tx, &schema).is_err());
    assert_eq!(current(&tx)?, original);
    let before = calls.load(Ordering::SeqCst);
    assert_eq!(tx.query_row("SELECT 17", [], |r| r.get::<_, i64>(0))?, 17);
    assert!(calls.load(Ordering::SeqCst) > before);
    let foreign = other.transaction()?;
    // The explicitly installed callback above really debits the current scope;
    // this is not an assertion that an arbitrary raw connection has such a hook.
    crate::oauth::schema::admit_with_runtime_hook(&tx, |db| {
        assert!(prepared.apply_in(&foreign, &schema).is_err());
        prepared.apply_in(db, &schema)
    })?;
    let before = calls.load(Ordering::SeqCst);
    assert_eq!(tx.query_row("SELECT 23", [], |r| r.get::<_, i64>(0))?, 23);
    assert!(calls.load(Ordering::SeqCst) > before);
    tx.rollback()?;
    foreign.rollback()?;
    assert_eq!(current(&db)?, original);
    Ok(())
}

#[test]
fn prepared_restore_fence_owned_scope_stops_at_actual_vm_budget_without_denial_writes() -> Result<()>
{
    let mut db = Connection::open_in_memory()?;
    initialize_restore_fence(&mut db)?;
    let original = current(&db)?;
    let schema = RestoreFenceSchema::prepare()?;
    let prepared = PreparedRestoreFence::new(
        original.clone(),
        Path::new("/restored/one"),
        Digest::new(b"step-bounded-fence"),
        100,
    )?;
    let tx = db.transaction()?;
    let mut entered = false;
    let result = crate::oauth::schema::admit_with_limits(&tx, 1024, 16384, 8 * 1048576, |db| {
        entered = true;
        prepared.apply_in(db, &schema)
    });
    assert!(entered);
    let error = result.unwrap_err();
    assert!(error.to_string().contains("budget"));
    assert_eq!(current(&tx)?, original);
    assert_eq!(
        tx.query_row("SELECT restored FROM day2_budget_meta", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    // The temporary callback has actually been removed; a later finite query
    // succeeds rather than inheriting the exhausted scope or a renewed budget.
    assert_eq!(tx.query_row("WITH RECURSIVE n(v) AS(VALUES(0) UNION ALL SELECT v+1 FROM n WHERE v<1000) SELECT sum(v) FROM n",[],|r|r.get::<_,i64>(0))?,500500);
    tx.commit()?;
    assert_eq!(current(&db)?, original);
    Ok(())
}

#[test]
fn prepared_restore_fence_late_failure_rolls_back_inside_the_actual_owned_scope() -> Result<()> {
    let mut db = Connection::open_in_memory()?;
    initialize_restore_fence(&mut db)?;
    let original = current(&db)?;
    let schema = RestoreFenceSchema::prepare()?;
    let prepared = PreparedRestoreFence::new(
        original.clone(),
        Path::new("/restored/one"),
        Digest::new(b"late-denial-fault"),
        100,
    )?;
    // A controlled callback failure after the real denial writes exercises the
    // same enclosing adapter savepoint, including callers that then commit.
    let tx = db.transaction()?;
    let outcome: Result<()> = crate::oauth::schema::admit(&tx, |db| {
        prepared.apply_in(db, &schema)?;
        assert!(!current(db)?.document.enabled);
        anyhow::bail!("controlled post-fence failure")
    });
    assert!(outcome.is_err());
    tx.commit()?;
    assert_eq!(current(&db)?, original);
    assert_eq!(
        db.query_row("SELECT restored FROM day2_budget_meta", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM day2_app_restore_fence", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn prepared_restore_fence_rollback_preserves_original_authority_and_budget_on_reopen() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("app.sqlite");
    let mut db = Connection::open(&path)?;
    initialize_restore_fence(&mut db)?;
    let original = current(&db)?;
    let schema = RestoreFenceSchema::prepare()?;
    let prepared = PreparedRestoreFence::new(
        original.clone(),
        Path::new("/restored/one"),
        Digest::new(b"uncommitted-fence"),
        100,
    )?;
    {
        let tx = db.transaction()?;
        crate::oauth::schema::admit(&tx, |db| prepared.apply_in(db, &schema))?;
        assert!(!current(&tx)?.document.enabled);
    }
    drop(db);
    for _ in 0..2 {
        let db = Connection::open(&path)?;
        assert_eq!(current(&db)?, original);
        assert_eq!(
            db.query_row(
                "SELECT restored FROM day2_budget_meta WHERE singleton=1",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            0
        );
    }
    Ok(())
}

#[test]
fn exhaustion_autocommit_and_tampered_history_guards_fail_closed() -> Result<()> {
    let mut connection = Connection::open_in_memory()?;
    initialize(&mut connection)?;
    assert!(change(&connection, &active().stamp, document(), "autocommit").is_err());
    connection.execute("UPDATE day2_authority SET revision=?1", [i64::MAX])?;
    let exhausted = current(&connection)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(change(&tx, &exhausted.stamp, document(), "overflow").is_err());
    assert_eq!(current(&tx)?, exhausted);
    assert_eq!(
        tx.query_row("SELECT count(*) FROM day2_authority_requests", [], |row| {
            row.get::<_, i64>(0)
        })?,
        0
    );
    assert!(
        tx.execute("DELETE FROM day2_authority_history", [])
            .is_err()
    );
    assert!(
        tx.execute("UPDATE day2_authority_history SET operator='forged'", [])
            .is_err()
    );
    assert!(
        tx.execute(
            "INSERT OR REPLACE INTO day2_authority_history SELECT * FROM day2_authority_history",
            []
        )
        .is_err()
    );
    tx.commit()?;
    connection.execute_batch("DROP TRIGGER day2_authority_history_no_update")?;
    assert!(upgrade(&connection).is_err());
    Ok(())
}

fn document() -> AuthorityDocument {
    AuthorityDocument {
        security: None,
        hosted_domain: None,
        resources: Default::default(),
        credentials: Default::default(),
        enabled: true,
        readers: BTreeSet::from(["viewer".into()]),
        writers: BTreeSet::from(["alice".into()]),
        policy: Some(Policy {
            version: 1,
            admins: BTreeSet::from(["auditor".into()]),
            delegations: Default::default(),
            operations: BTreeMap::from([
                (
                    "items.write".into(),
                    OperationPolicy {
                        actors: BTreeSet::from(["alice".into()]),
                        mode: Mode::CurrentState,
                        models: BTreeMap::new(),
                        commands: BTreeSet::new(),
                        observations: BTreeSet::new(),
                        effects: BTreeSet::new(),
                    },
                ),
                (
                    "items.read".into(),
                    OperationPolicy {
                        actors: BTreeSet::from(["alice".into(), "viewer".into()]),
                        mode: Mode::Read,
                        models: BTreeMap::new(),
                        commands: BTreeSet::new(),
                        observations: BTreeSet::new(),
                        effects: BTreeSet::new(),
                    },
                ),
            ]),
            constraints: BTreeMap::new(),
        }),
    }
}

fn active() -> ActiveAuthority {
    ActiveAuthority {
        stamp: AuthorityStamp {
            epoch: crate::digest(b"authority-test-epoch"),
            revision: 1,
        },
        document: document(),
        artifact_id: "artifact-one".into(),
        artifact_path: "/admitted/one".into(),
    }
}

fn initialize_restore_fence(db: &mut Connection) -> Result<()> {
    db.pragma_update(None, "foreign_keys", true)?;
    db.execute_batch(crate::store::PLATFORM_DDL)?;
    let tx = db.transaction()?;
    crate::audit::upgrade(&tx)?;
    upgrade(&tx)?;
    crate::delegation_commands::upgrade(&tx)?;
    store(&tx, &active(), "test", "initialize")?;
    tx.commit()?;
    Ok(())
}

fn initialize(connection: &mut Connection) -> Result<()> {
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.execute_batch(
        "CREATE TABLE day2_invocations(id TEXT PRIMARY KEY, status TEXT NOT NULL) STRICT;
         CREATE TABLE business(id TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT;",
    )?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    upgrade(&tx)?;
    store(&tx, &active(), "test", "initialize")?;
    tx.commit()?;
    Ok(())
}

fn change(
    connection: &Connection,
    expected: &AuthorityStamp,
    document: AuthorityDocument,
    request: &str,
) -> Result<AuthorityReceipt> {
    apply_transition_in(
        connection,
        &LocalOperator::assert_local("operator")?,
        &ApplyAuthority {
            request_id: request.into(),
            expected: Some(expected.clone()),
            document,
        },
        ("artifact-one", Path::new("/admitted/one")),
        active(),
    )
}

#[test]
fn memberships_disable_and_missing_policy_all_deny_independently() -> Result<()> {
    let read: Operation = serde_json::from_value(
        serde_json::json!({"name":"items.read","kind":"query","input_type":"input","output_type":"output"}),
    )?;
    let write: Operation = serde_json::from_value(
        serde_json::json!({"name":"items.write","kind":"command","input_type":"input","output_type":"output"}),
    )?;
    let mut doc = document();
    doc.authorize(&read, "viewer")?;
    doc.authorize(&write, "alice")?;
    doc.authorize_audit("auditor")?;
    assert!(doc.authorize(&write, "viewer").is_err());
    assert!(doc.authorize_audit("alice").is_err());
    doc.readers.clear();
    assert!(doc.authorize(&read, "viewer").is_err());
    doc.writers.clear();
    assert!(doc.authorize(&write, "alice").is_err());
    doc = document();
    doc.enabled = false;
    assert!(doc.authorize(&write, "alice").is_err());
    assert!(doc.authorize_audit("auditor").is_err());
    doc = document();
    doc.policy = None;
    assert!(doc.authorize(&write, "alice").is_err());
    assert!(doc.authorize_audit("auditor").is_err());
    Ok(())
}

#[test]
fn legacy_persisted_auditors_are_ignored_and_never_serialized() -> Result<()> {
    let mut connection = Connection::open_in_memory()?;
    initialize(&mut connection)?;
    let mut stored = serde_json::to_value(document())?;
    stored["auditors"] = serde_json::json!(["former-auditor", "alice"]);
    connection.execute(
        "UPDATE day2_authority SET document=?1",
        [serde_json::to_string(&stored)?],
    )?;
    let loaded = current(&connection)?;
    loaded.document.authorize_audit("auditor")?;
    assert!(loaded.document.authorize_audit("former-auditor").is_err());
    assert!(loaded.document.authorize_audit("alice").is_err());
    assert!(
        serde_json::to_value(&loaded.document)?
            .get("auditors")
            .is_none()
    );
    stored["unknown_grant"] = serde_json::json!(["alice"]);
    assert!(serde_json::from_value::<AuthorityDocument>(stored).is_err());
    Ok(())
}

#[test]
fn activation_is_cas_idempotent_and_aba_never_reauthorizes_old_work() -> Result<()> {
    let mut connection = Connection::open_in_memory()?;
    initialize(&mut connection)?;
    let original = current(&connection)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("INSERT INTO day2_invocations VALUES('old','pending')", [])?;
    pin_invocation(&tx, "old", &original.stamp)?;
    tx.commit()?;
    let mut revoked = original.document.clone();
    revoked.writers.clear();
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let receipt = change(&tx, &original.stamp, revoked.clone(), "revoke")?;
    assert_eq!(receipt.stamp.revision, 2);
    assert!(is_blocked(&tx, "old")?);
    assert_eq!(change(&tx, &original.stamp, revoked, "revoke")?, receipt);
    assert!(change(&tx, &original.stamp, document(), "revoke").is_err());
    assert!(change(&tx, &original.stamp, document(), "stale").is_err());
    tx.commit()?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let restored = change(
        &tx,
        &receipt.stamp,
        original.document.clone(),
        "restore-permission",
    )?;
    assert_eq!(restored.stamp.revision, 3);
    assert_eq!(current(&tx)?.document, original.document);
    assert_ne!(invocation_stamp(&tx, "old")?, restored.stamp);
    assert!(pin_invocation(&tx, "old", &restored.stamp).is_err());
    tx.execute("INSERT INTO day2_invocations VALUES('new','pending')", [])?;
    pin_invocation(&tx, "new", &restored.stamp)?;
    assert!(!is_blocked(&tx, "new")?);
    tx.commit()?;
    assert_eq!(
        connection.query_row("SELECT count(*) FROM day2_authority_history", [], |row| row
            .get::<_, i64>(0))?,
        3
    );
    Ok(())
}

#[test]
fn rollback_preserves_authority_business_rows_and_invocation_state() -> Result<()> {
    let mut connection = Connection::open_in_memory()?;
    initialize(&mut connection)?;
    let original = current(&connection)?;
    {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO day2_invocations VALUES('rollback','pending')",
            [],
        )?;
        pin_invocation(&tx, "rollback", &original.stamp)?;
        tx.execute("INSERT INTO business VALUES('row','committing')", [])?;
        let mut denied = document();
        denied.enabled = false;
        change(&tx, &original.stamp, denied, "rolled-back")?;
    }
    assert_eq!(current(&connection)?, original);
    for table in [
        "business",
        "day2_invocations",
        "day2_invocation_authority",
        "day2_authority_blocks",
        "day2_authority_requests",
    ] {
        assert_eq!(
            connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))?,
            0
        );
    }
    Ok(())
}

#[test]
fn binding_and_authority_publish_together_and_stale_runtime_cannot_change_them() -> Result<()> {
    let mut connection = Connection::open_in_memory()?;
    initialize(&mut connection)?;
    let original = current(&connection)?;
    let mut target = active();
    target.artifact_id = "artifact-two".into();
    target.artifact_path = "/admitted/two".into();
    let mut changed = document();
    changed.policy.as_mut().unwrap().admins.clear();
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let request = ApplyAuthority {
        request_id: "artifact-upgrade".into(),
        expected: Some(original.stamp.clone()),
        document: changed.clone(),
    };
    let receipt = apply_transition_in(
        &tx,
        &LocalOperator::assert_local("operator")?,
        &request,
        ("artifact-one", Path::new("/admitted/one")),
        target.clone(),
    )?;
    let published = current(&tx)?;
    assert_eq!(published.artifact_id, "artifact-two");
    assert_eq!(published.artifact_path, "/admitted/two");
    assert_eq!(published.document, changed);
    assert_eq!(published.stamp, receipt.stamp);
    assert_eq!(
        apply_transition_in(
            &tx,
            &LocalOperator::assert_local("operator")?,
            &request,
            ("artifact-one", Path::new("/admitted/one")),
            target
        )?,
        receipt
    );
    assert!(change(&tx, &receipt.stamp, document(), "stale-runtime").is_err());
    tx.commit()?;
    Ok(())
}

#[test]
fn legacy_activation_never_assigns_authority_to_unstamped_pending_work() -> Result<()> {
    let mut connection = Connection::open_in_memory()?;
    connection.execute_batch("CREATE TABLE day2_invocations(id TEXT PRIMARY KEY,status TEXT NOT NULL); INSERT INTO day2_invocations VALUES('legacy','pending')")?;
    assert!(!exists(&connection)?);
    assert!(current(&connection).is_err());
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    upgrade(&tx)?;
    assert!(current(&tx).is_err());
    let request = ApplyAuthority {
        request_id: "explicit-legacy-activation".into(),
        expected: None,
        document: document(),
    };
    let receipt = apply_transition_in(
        &tx,
        &LocalOperator::assert_local("operator")?,
        &request,
        ("artifact-one", Path::new("/admitted/one")),
        active(),
    )?;
    assert_eq!(receipt.stamp.revision, 1);
    assert!(is_blocked(&tx, "legacy")?);
    assert!(invocation_stamp(&tx, "legacy").is_err());
    // Reuse cannot add a current stamp to previously accepted work.
    assert!(pin_invocation(&tx, "legacy", &receipt.stamp).is_err());
    tx.commit()?;
    Ok(())
}

#[test]
fn sqlite_writer_lock_orders_business_commit_before_revocation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let db = directory.path().join("authority.sqlite");
    let mut business = Connection::open(&db)?;
    initialize(&mut business)?;
    business.pragma_update(None, "journal_mode", "WAL")?;
    let stamp = current(&business)?.stamp;
    let transaction = business.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute("INSERT INTO business VALUES('row','authorized')", [])?;
    let (started_send, started_receive) = mpsc::channel();
    let (done_send, done_receive) = mpsc::channel();
    let concurrent_stamp = stamp.clone();
    let updater = thread::spawn(move || -> Result<()> {
        let mut connection = Connection::open(db)?;
        connection.busy_timeout(Duration::from_secs(3))?;
        started_send.send(())?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut revoked = document();
        revoked.enabled = false;
        let receipt = change(&tx, &concurrent_stamp, revoked, "concurrent-revoke")?;
        tx.commit()?;
        done_send.send(receipt)?;
        Ok(())
    });
    started_receive.recv_timeout(Duration::from_secs(3))?;
    assert!(
        done_receive
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );
    assert_eq!(current(&transaction)?.stamp, stamp);
    transaction.commit()?;
    let receipt = done_receive.recv_timeout(Duration::from_secs(3))?;
    updater.join().expect("authority updater panicked")?;
    assert_eq!(current(&business)?.stamp, receipt.stamp);
    assert_eq!(
        business.query_row("SELECT value FROM business WHERE id='row'", [], |row| {
            row.get::<_, String>(0)
        })?,
        "authorized"
    );
    let tx = business.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert_ne!(current(&tx)?.stamp, stamp);
    assert!(!current(&tx)?.document.enabled);
    Ok(())
}

#[test]
fn domain_membership_admits_only_under_the_document_s_verified_domain() -> Result<()> {
    let artifact = LoadedArtifact::from_contract_for_tests(
        "domain-test".into(),
        "/admitted/domain".into(),
        serde_json::from_value(serde_json::json!({
            "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,"roc_version":"domain-test",
            "worker_digest":"domain-test","schema_digest":"domain-test",
            "schema":{"models":{},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":[
                {"name":"items.read","kind":"query","input_type":"input","output_type":""},
                {"name":"items.write","kind":"command","input_type":"input","output_type":""}],
            "sources":{},"admission":"local-spike-only"}))?,
    );
    let read = artifact.route("items.read")?.clone();
    let write = artifact.route("items.write")?.clone();
    let everyone = String::from("domain:wonderly.com");
    let mut doc = document();
    doc.hosted_domain = Some("wonderly.com".into());
    doc.readers.insert(everyone.clone());
    let policy = doc.policy.as_mut().unwrap();
    for operation in policy.operations.values_mut() {
        operation.actors.insert(everyone.clone());
    }
    doc.validate(&artifact)?;

    // A reader by domain may query and may not write; named members are unchanged.
    let hire = "newhire@wonderly.com";
    doc.authorize(&read, hire)?;
    assert!(doc.authorize(&write, hire).is_err());
    doc.authorize(&write, "alice")?;
    doc.authorize(&read, "viewer")?;
    for outsider in [
        "newhire@evil-wonderly.com",
        "newhire@wonderly.com.evil.com",
        "newhire@sub.wonderly.com",
        "NewHire@wonderly.com",
        "a@b@wonderly.com",
        "app:links@wonderly.com",
        "domain:wonderly.com",
    ] {
        assert!(doc.authorize(&read, outsider).is_err(), "{outsider}");
    }
    // Owners stay named: the audit is never opened by a domain.
    assert!(doc.authorize_audit(hire).is_err());
    let mut owners = doc.clone();
    owners
        .policy
        .as_mut()
        .unwrap()
        .admins
        .insert(everyone.clone());
    assert!(owners.validate(&artifact).is_err());

    // The same entries without the verified domain, or under another, are refused.
    let mut unverified = doc.clone();
    unverified.hosted_domain = None;
    let error = unverified.validate(&artifact).unwrap_err();
    assert!(format!("{error:#}").contains("google_iap"), "{error:#}");
    let mut elsewhere = doc.clone();
    elsewhere.hosted_domain = Some("example.com".into());
    assert!(elsewhere.validate(&artifact).is_err());
    let mut operation_only = document();
    operation_only
        .policy
        .as_mut()
        .unwrap()
        .operations
        .get_mut("items.read")
        .unwrap()
        .actors
        .insert(everyone);
    assert!(operation_only.validate(&artifact).is_err());

    // The document keeps its domain through storage, and omits it when absent.
    let stored: AuthorityDocument = serde_json::from_str(&serde_json::to_string(&doc)?)?;
    assert_eq!(stored, doc);
    assert!(
        serde_json::to_value(document())?
            .get("hosted_domain")
            .is_none()
    );
    Ok(())
}

#[test]
fn domain_resource_grants_stay_within_domain_membership_and_never_delegate() -> Result<()> {
    let artifact = LoadedArtifact::from_contract_for_tests(
        "domain-resource-test".into(),
        "/admitted/domain-resource".into(),
        serde_json::from_value(serde_json::json!({
            "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,"roc_version":"domain-resource-test",
            "worker_digest":"domain-resource-test","schema_digest":"domain-resource-test",
            "schema":{"models":{},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":[
                {"name":"items.read","kind":"query","input_type":"input","output_type":""},
                {"name":"items.write","kind":"command","input_type":"input","output_type":""}],
            "sources":{},"admission":"local-spike-only"}))?,
    );
    let read = artifact.route("items.read")?.clone();
    let everyone = String::from("domain:wonderly.com");
    let grant = |operation: &str, provider_target: serde_json::Value, actors: &[&str]| {
        let mut grant = serde_json::json!({
            "policy":{"id":"reading","revision":1},
            "resource":{"id":"directory","revision":1},
            "connection":{"id":"local","revision":1},
            "actors":actors,
            "limits":{"max_request_bytes":1024,"max_response_bytes":1024,"max_calls_per_invocation":5},
            "budgets":[],"expires_at_ms":null
        });
        grant
            .as_object_mut()
            .unwrap()
            .extend(provider_target.as_object().unwrap().clone());
        serde_json::json!({"operations":{operation:{"directory":grant}},"budgets":{}})
    };
    let notifications = serde_json::json!({
        "provider":"local_notifications",
        "target":{"kind":"notification_mailbox","topics":{"kind":"any"}},
        "actions":["notifications_resolve"]
    });
    let mut doc = document();
    doc.hosted_domain = Some("wonderly.com".into());
    doc.readers.insert(everyone.clone());
    let approved = doc
        .policy
        .as_mut()
        .unwrap()
        .operations
        .get_mut("items.read")
        .unwrap();
    approved.actors.insert(everyone.clone());
    approved
        .observations
        .insert("notifications.recipient.v1".into());
    doc.resources = serde_json::from_value(grant(
        "items.read",
        notifications.clone(),
        &[everyone.as_str(), "viewer"],
    ))?;
    doc.validate(&artifact)?;

    // Activation keeps the domain entry, and the bound grant then admits a
    // person of that domain while refusing lookalikes and the entry itself.
    let mut effective = doc.clone();
    effective.attenuate_resources(&artifact.contract().operations)?;
    let actors = &effective.resources.operations["items.read"]["directory"].actors;
    assert_eq!(actors, &BTreeSet::from([everyone.clone(), "viewer".into()]));
    assert!(crate::authority::admits(actors, "newhire@wonderly.com"));
    assert!(crate::authority::admits(actors, "viewer"));
    for outsider in [
        "newhire@sub.wonderly.com",
        "newhire@wonderly.com.evil.com",
        "NewHire@wonderly.com",
        "app:links@wonderly.com",
        "domain:wonderly.com",
    ] {
        assert!(!crate::authority::admits(actors, outsider), "{outsider}");
    }
    effective.authorize(&read, "newhire@wonderly.com")?;

    // A domain is covered only by the same domain: naming people in the
    // operation or membership does not stretch to everyone at the domain.
    type Narrow = fn(&mut AuthorityDocument, &str);
    let narrowings: [(&str, Narrow); 2] = [
        ("membership", |doc, entry| {
            doc.readers.remove(entry);
        }),
        ("operation", |doc, entry| {
            doc.policy
                .as_mut()
                .unwrap()
                .operations
                .get_mut("items.read")
                .unwrap()
                .actors
                .remove(entry);
        }),
    ];
    for (narrowing, narrow) in narrowings {
        let mut narrowed = doc.clone();
        narrow(&mut narrowed, &everyone);
        assert!(narrowed.validate(&artifact).is_err(), "{narrowing}");
        narrowed.attenuate_resources(&artifact.contract().operations)?;
        assert_eq!(
            narrowed.resources.operations["items.read"]["directory"].actors,
            BTreeSet::from(["viewer".into()]),
            "{narrowing}"
        );
    }

    // A command's grant is covered by writers only: a domain that may read
    // the app does not reach a resource bound to one of its commands.
    let mut command = doc.clone();
    let approved = command
        .policy
        .as_mut()
        .unwrap()
        .operations
        .get_mut("items.write")
        .unwrap();
    approved.actors.insert(everyone.clone());
    approved
        .observations
        .insert("notifications.recipient.v1".into());
    command.resources = serde_json::from_value(grant(
        "items.write",
        notifications.clone(),
        &[everyone.as_str(), "alice"],
    ))?;
    assert!(command.validate(&artifact).is_err());
    let mut attenuated = command.clone();
    attenuated.attenuate_resources(&artifact.contract().operations)?;
    assert_eq!(
        attenuated.resources.operations["items.write"]["directory"].actors,
        BTreeSet::from(["alice".into()])
    );
    command.writers.insert(everyone.clone());
    command.validate(&artifact)?;

    // The entry must name the verified hosted domain, which membership
    // already requires of the entry that covers it.
    let mut unverified = doc.clone();
    unverified.hosted_domain = None;
    assert!(unverified.validate(&artifact).is_err());
    let mut elsewhere = doc.clone();
    elsewhere.hosted_domain = Some("example.com".into());
    assert!(elsewhere.validate(&artifact).is_err());

    // App delegation never carries a domain across an application boundary.
    let mut delegated = doc.clone();
    delegated
        .policy
        .as_mut()
        .unwrap()
        .operations
        .get_mut("items.read")
        .unwrap()
        .observations
        .insert("app.query.v1".into());
    delegated.resources = serde_json::from_value(grant(
        "items.read",
        serde_json::json!({
            "provider":"local_delegation",
            "target":{"kind":"app_operation","app":"callee","operation":"callee.list",
                "schema_digest":format!("sha256:{}", "1".repeat(64))},
            "actions":["delegate_query"]
        }),
        &[everyone.as_str()],
    ))?;
    let error = delegated.validate(&artifact).unwrap_err();
    assert!(format!("{error:#}").contains("app delegation"), "{error:#}");
    Ok(())
}
