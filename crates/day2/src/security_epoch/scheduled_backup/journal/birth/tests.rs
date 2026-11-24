//! External immutable binding DATA only. No native creator/activation/supplier.
use super::*;
use day2_capabilities::security_epoch::{AuthorityScope, EpochIam};

fn digest(text: &str) -> Digest {
    Digest::new(text.as_bytes())
}

fn binding(scope: u8, cron: u8, revision: u8) -> RootBindingData {
    RootBindingData {
        scope: AuthorityScope {
            installation: "fixture".to_owned().try_into().unwrap(),
            environment: "test".to_owned().try_into().unwrap(),
            app: format!("app{scope}").try_into().unwrap(),
        },
        cron_job_uid: format!("00000000-0000-0000-0000-{cron:012}")
            .try_into()
            .unwrap(),
        physical_disk: digest(&format!("disk{revision}")),
        creator_nonce: digest(&format!("nonce{revision}")),
    }
}

fn selection(binding: &RootBindingData) -> EpochStore {
    EpochStore {
        scope: binding.scope.clone(),
        provider: EpochProvider::FirestoreNativeV1 {
            project: "fixture-project".to_owned().try_into().unwrap(),
            project_number: 7.try_into().unwrap(),
            database: "control".to_owned().try_into().unwrap(),
            database_uid: "00000000-0000-0000-0000-000000000099".into(),
            iam_source: EpochIam::GkeWorkloadIdentityV1 {
                service_account: "controller@fixture-project.iam.gserviceaccount.com".into(),
                service_account_uid: "100000000000000000001".to_owned().try_into().unwrap(),
            },
        },
        key_set: digest("keys"),
        max_lease_seconds: 5,
    }
}

fn ack() -> Vec<u8> {
    br#"{"writeResults":[{"updateTime":"2026-11-23T17:00:00.000001Z"}],"commitTime":"2026-11-23T17:00:00.000001Z"}"#.to_vec()
}

fn known_version() -> UpdateTime {
    "2026-11-23T17:00:00.000001Z".to_owned().try_into().unwrap()
}

fn stored(write: &Value) -> Value {
    let mut value = write["writes"][0]["update"].clone();
    value["createTime"] = json!("2026-11-23T17:00:00.000001Z");
    value["updateTime"] = value["createTime"].clone();
    value
}

#[test]
fn fixed_root_document_key_is_stable_but_exact_disk_header_and_database_uid_are_bound() -> Result<()>
{
    let root = binding(0, 1, 0);
    let selected = selection(&root);
    let mut first = BirthTurn::new_data(&selected, root.clone())?;
    let write = first.submit_data()?;
    assert_eq!(write.as_object().unwrap().len(), 1);
    assert_eq!(write["writes"].as_array().unwrap().len(), 1);
    assert_eq!(
        write["writes"][0]["currentDocument"],
        json!({"exists":false})
    );
    assert_eq!(write["writes"][0].as_object().unwrap().len(), 2);
    let row = stored(&write);
    compare_existing_data(&selected, &root, &known_version(), &serde_json::to_vec(&row)?)?;
    for revision in 1..12 {
        let replacement = binding(0, 1, revision);
        assert_eq!(
            document_data(&selected, &root)?,
            document_data(&selected, &replacement)?
        );
        assert_ne!(
            RootRecordData::new_data(&selected, root.clone())?,
            RootRecordData::new_data(&selected, replacement.clone())?
        );
        assert!(
            compare_existing_data(&selected, &replacement, &known_version(), &serde_json::to_vec(&row)?).is_err()
        );
    }
    let mut rotated = selected.clone();
    rotated.key_set = digest("rotated-key-set");
    assert_eq!(
        document_data(&selected, &root)?,
        document_data(&rotated, &root)?
    );
    compare_existing_data(&rotated, &root, &known_version(), &serde_json::to_vec(&row)?)?;
    let EpochProvider::FirestoreNativeV1 { database_uid, .. } = &mut rotated.provider;
    *database_uid = "00000000-0000-0000-0000-000000000098".into();
    assert_eq!(
        document_data(&selected, &root)?,
        document_data(&rotated, &root)?
    );
    assert!(compare_existing_data(&rotated, &root, &known_version(), &serde_json::to_vec(&row)?).is_err());
    for other in [binding(1, 1, 0), binding(0, 2, 0)] {
        assert!(
            document_data(&selected, &other).is_err()
                || document_data(&selected, &other)? != document_data(&selected, &root)?
        );
        let config = selection(&other);
        assert_ne!(
            document_data(&config, &other)?,
            document_data(&selected, &root)?
        );
    }
    Ok(())
}

#[test]
fn unknown_birth_never_resumes_from_existing_row_absence_or_late_valid_ack() -> Result<()> {
    for applied in [false, true] {
        let root = binding(0, 1, 0);
        let selected = selection(&root);
        let mut turn = BirthTurn::new_data(&selected, root.clone())?;
        let write = turn.submit_data()?;
        turn.lose_data();
        if applied {
            compare_existing_data(&selected, &root, &known_version(), &serde_json::to_vec(&stored(&write))?)?;
        } else {
            assert!(compare_existing_data(&selected, &root, &known_version(), b"{}").is_err());
        }
        assert_eq!(turn.disposition, DispositionData::Unknown);
        assert!(turn.observe_data(200, &ack()).is_err());
        assert!(turn.submit_data().is_err());
        assert_eq!(turn.disposition, DispositionData::Unknown);
    }
    Ok(())
}

#[test]
fn strict_ack_and_stored_root_fail_closed_without_provider_messages_or_mutable_rows() -> Result<()>
{
    let root = binding(0, 1, 0);
    let selected = selection(&root);
    for (status, body) in [
        (409, ack()),
        (500, b"private-provider-message".to_vec()),
        (200, b"{}".to_vec()),
        (
            200,
            br#"{"writeResults":[],"commitTime":"2026-11-23T17:00:00Z"}"#.to_vec(),
        ),
        (200, [ack(), vec![b' '; 4097]].concat()),
    ] {
        let mut turn = BirthTurn::new_data(&selected, root.clone())?;
        turn.submit_data()?;
        assert!(turn.observe_data(status, &body).is_err());
        assert_eq!(turn.disposition, DispositionData::Unknown);
        assert!(turn.observe_data(200, &ack()).is_err());
        assert!(turn.submit_data().is_err());
    }
    let mut turn = BirthTurn::new_data(&selected, root.clone())?;
    assert!(turn.observe_data(200, &ack()).is_err());
    let mut turn = BirthTurn::new_data(&selected, root.clone())?;
    let write = turn.submit_data()?;
    turn.observe_data(200, &ack())?;
    assert_eq!(turn.disposition, DispositionData::Known);
    assert!(turn.submit_data().is_err());
    assert_eq!(turn.disposition, DispositionData::Unknown);
    for path in [
        "/name",
        "/fields/root_json/stringValue",
        "/fields/root_digest/stringValue",
        "/updateTime",
    ] {
        let mut row = stored(&write);
        *row.pointer_mut(path).unwrap() = json!("changed");
        assert!(compare_existing_data(&selected, &root, &known_version(), &serde_json::to_vec(&row)?).is_err());
    }
    let mut row = stored(&write);
    row["updateTime"] = json!("2026-11-23T17:00:00.000002Z");
    assert_eq!(
        compare_existing_data(&selected, &root, &known_version(), &serde_json::to_vec(&row)?)
            .unwrap_err()
            .to_string(),
        "backup_root_record_mutated"
    );
    let mut row = stored(&write);
    row["fields"]["unexpected"] = json!({"stringValue":"private"});
    assert!(compare_existing_data(&selected, &root, &known_version(), &serde_json::to_vec(&row)?).is_err());
    let mut row = stored(&write);
    row["fields"]["root_json"]["bytesValue"] = json!("AA==");
    assert!(compare_existing_data(&selected, &root, &known_version(), &serde_json::to_vec(&row)?).is_err());
    Ok(())
}

#[test]
fn duplicate_unknown_noncanonical_root_payloads_cannot_pass_the_historical_comparison() -> Result<()>
{
    let root = binding(0, 1, 0);
    let selected = selection(&root);
    let mut turn = BirthTurn::new_data(&selected, root.clone())?;
    let row = stored(&turn.submit_data()?);
    let payload = row["fields"]["root_json"]["stringValue"].as_str().unwrap();
    let duplicate = payload.replacen("\"format\":1", "\"format\":1,\"format\":1", 1);
    for bad in [
        duplicate,
        format!(" {payload}"),
        format!("{payload} "),
        "[]".into(),
        payload.replacen("\"format\":1", "\"format\":2", 1),
        payload.replacen("\"format\":1", "\"format\":1,\"unexpected\":0", 1),
    ] {
        let mut changed = row.clone();
        changed["fields"]["root_json"]["stringValue"] = json!(bad);
        assert!(compare_existing_data(&selected, &root, &known_version(), &serde_json::to_vec(&changed)?).is_err());
    }
    let encoded = serde_json::to_string(&row)?;
    let duplicate = encoded.replacen(
        "\"createTime\":",
        "\"createTime\":\"2026-11-23T17:00:00.000001Z\",\"createTime\":",
        1,
    );
    assert!(compare_existing_data(&selected, &root, &known_version(), duplicate.as_bytes()).is_err());
    assert!(compare_existing_data(&selected, &root, &known_version(), &vec![b' '; MAX_PAYLOAD * 2 + 1]).is_err());
    Ok(())
}


fn confirmation_response(write: &Value) -> Value {
    json!([{"found": stored(write), "readTime":"2026-11-23T17:00:00.000002Z"}])
}

fn acknowledged_turn() -> Result<(EpochStore, BirthTurn, Value)> {
    // Only local codec DATA. This cannot construct a genuine native root.
    let root = binding(0, 1, 0);
    let selected = selection(&root);
    let mut turn = BirthTurn::new_data(&selected, root)?;
    let write = turn.submit_data()?;
    turn.observe_data(200, &ack())?;
    Ok((selected, turn, write))
}

#[test]
fn root_confirmation_binds_the_original_known_ack_and_never_adopts_a_recreated_row() -> Result<()> {
    let (selected, mut turn, write) = acknowledged_turn()?;
    assert!(turn.require_confirmed_data().is_err());
    let request = turn.begin_confirmation_data(&selected)?;
    assert_eq!(request, json!({"documents":[write["writes"][0]["update"]["name"]]}));
    assert_eq!(request.as_object().unwrap().len(), 1);
    let response = confirmation_response(&write);
    turn.observe_confirmation_data(&selected, 200, &serde_json::to_vec(&response)?)?;
    turn.require_confirmed_data()?;
    // The same response cannot renew an already consumed confirmation.
    assert!(turn.observe_confirmation_data(&selected, 200, &serde_json::to_vec(&response)?).is_err());
    assert!(turn.require_confirmed_data().is_err());
    assert!(turn.begin_confirmation_data(&selected).is_err());

    let (selected, mut turn, write) = acknowledged_turn()?;
    turn.begin_confirmation_data(&selected)?;
    let mut recreated = confirmation_response(&write);
    // Identical name and binding bytes, but delete/recreate has a new version.
    recreated[0]["found"]["createTime"] = json!("2026-11-23T17:00:00.000002Z");
    recreated[0]["found"]["updateTime"] = recreated[0]["found"]["createTime"].clone();
    assert!(turn.observe_confirmation_data(&selected, 200, &serde_json::to_vec(&recreated)?).is_err());
    assert!(turn.require_confirmed_data().is_err());
    assert!(turn.observe_confirmation_data(&selected, 200, &serde_json::to_vec(&confirmation_response(&write))?).is_err());
    assert!(turn.submit_data().is_err());

    for cut in 0..3 {
        let root = binding(0, 1, 0); let selected = selection(&root);
        let mut turn = BirthTurn::new_data(&selected, root)?;
        if cut != 0 { turn.submit_data()?; }
        if cut == 2 { turn.lose_data(); }
        assert!(turn.begin_confirmation_data(&selected).is_err());
        assert!(turn.require_confirmed_data().is_err());
        // A matching row cannot supply the absent ACK or resume lost state.
        assert!(turn.observe_confirmation_data(&selected, 200, b"[]").is_err());
        assert!(turn.observe_data(200, &ack()).is_err());
    }
    Ok(())
}

#[test]
fn confirmation_stream_is_exact_bounded_and_provider_time_does_not_renew_native_time() -> Result<()> {
    let (_, _, write) = acknowledged_turn()?;
    let good = confirmation_response(&write);
    let mut invalid = vec![Value::Null, json!({}), json!([]), json!([good[0],good[0]]),
        json!([{"transaction":"not-started"}]), json!([{"missing":good[0]["found"]["name"],"readTime":good[0]["readTime"]}])];
    for (path, replacement) in [
        (vec!["extra"],json!(true)), (vec!["readTime"],Value::Null),
        (vec!["readTime"],json!("2026-11-23T16:59:59.999999Z")),
        (vec!["found"],Value::Null),
        (vec!["found","name"],json!("projects/wrong/databases/control/documents/wrong/root")),
        (vec!["found","createTime"],json!("2026-11-23T17:00:00Z")),
        (vec!["found","updateTime"],json!("2026-11-23T17:00:00.000002Z")),
        (vec!["found","fields","extra"],json!({"stringValue":"unrecognized"})),
    ] {
        let mut changed = good.clone(); let mut at = &mut changed[0];
        for component in &path[..path.len()-1] { at = &mut at[*component]; }
        at[*path.last().unwrap()] = replacement; invalid.push(changed);
    }
    for value in invalid {
        let (selected, mut turn, _) = acknowledged_turn()?;
        turn.begin_confirmation_data(&selected)?;
        assert!(turn.observe_confirmation_data(&selected, 200, &serde_json::to_vec(&value)?).is_err());
        assert!(turn.require_confirmed_data().is_err());
        assert!(turn.observe_confirmation_data(&selected, 200, &serde_json::to_vec(&good)?).is_err());
    }
    for read in ["2026-11-23T17:00:00.000001Z", "2026-11-23T17:00:00.000002Z"] {
        let (selected, mut turn, _) = acknowledged_turn()?; turn.begin_confirmation_data(&selected)?;
        let mut value = good.clone(); value[0]["readTime"] = json!(read);
        turn.observe_confirmation_data(&selected, 200, &serde_json::to_vec(&value)?)?;
        turn.require_confirmed_data()?;
    }
    let encoded = serde_json::to_vec(&good)?;
    let text = String::from_utf8(encoded.clone())?;
    let duplicate = text.replacen("\"readTime\":", "\"readTime\":null,\"readTime\":", 1);
    assert_ne!(duplicate, text);
    let mut oversized = encoded.clone(); oversized.resize(MAX_PAYLOAD * 2 + 1, b' ');
    let _: Value = serde_json::from_slice(&oversized)?;
    for (status, body) in [(201,encoded.clone()),(500,encoded.clone()),(200,duplicate.into_bytes()),
        (200,encoded[..encoded.len()-1].to_vec()),(200,oversized)] {
        let (selected, mut turn, _) = acknowledged_turn()?; turn.begin_confirmation_data(&selected)?;
        assert!(turn.observe_confirmation_data(&selected, status, &body).is_err());
        assert!(turn.require_confirmed_data().is_err());
    }
    Ok(())
}
