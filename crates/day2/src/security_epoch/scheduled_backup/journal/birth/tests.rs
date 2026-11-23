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
    compare_existing_data(&selected, &root, &serde_json::to_vec(&row)?)?;
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
            compare_existing_data(&selected, &replacement, &serde_json::to_vec(&row)?).is_err()
        );
    }
    let mut rotated = selected.clone();
    rotated.key_set = digest("rotated-key-set");
    assert_eq!(
        document_data(&selected, &root)?,
        document_data(&rotated, &root)?
    );
    compare_existing_data(&rotated, &root, &serde_json::to_vec(&row)?)?;
    let EpochProvider::FirestoreNativeV1 { database_uid, .. } = &mut rotated.provider;
    *database_uid = "00000000-0000-0000-0000-000000000098".into();
    assert_eq!(
        document_data(&selected, &root)?,
        document_data(&rotated, &root)?
    );
    assert!(compare_existing_data(&rotated, &root, &serde_json::to_vec(&row)?).is_err());
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
            compare_existing_data(&selected, &root, &serde_json::to_vec(&stored(&write))?)?;
        } else {
            assert!(compare_existing_data(&selected, &root, b"{}").is_err());
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
        assert!(compare_existing_data(&selected, &root, &serde_json::to_vec(&row)?).is_err());
    }
    let mut row = stored(&write);
    row["updateTime"] = json!("2026-11-23T17:00:00.000002Z");
    assert_eq!(
        compare_existing_data(&selected, &root, &serde_json::to_vec(&row)?)
            .unwrap_err()
            .to_string(),
        "backup_root_record_mutated"
    );
    let mut row = stored(&write);
    row["fields"]["unexpected"] = json!({"stringValue":"private"});
    assert!(compare_existing_data(&selected, &root, &serde_json::to_vec(&row)?).is_err());
    let mut row = stored(&write);
    row["fields"]["root_json"]["bytesValue"] = json!("AA==");
    assert!(compare_existing_data(&selected, &root, &serde_json::to_vec(&row)?).is_err());
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
        assert!(compare_existing_data(&selected, &root, &serde_json::to_vec(&changed)?).is_err());
    }
    let encoded = serde_json::to_string(&row)?;
    let duplicate = encoded.replacen(
        "\"createTime\":",
        "\"createTime\":\"2026-11-23T17:00:00.000001Z\",\"createTime\":",
        1,
    );
    assert!(compare_existing_data(&selected, &root, duplicate.as_bytes()).is_err());
    assert!(compare_existing_data(&selected, &root, &vec![b' '; MAX_PAYLOAD * 2 + 1]).is_err());
    Ok(())
}
