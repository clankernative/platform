//! Actual bounded codec controls over synthetic protocol DATA. No HTTP request,
//! approval/current-role owner or native writer is constructed by these tests.
use super::*;
use crate::security_epoch::firestore::{Budget, EpochReply, Port, Sample};
use crate::security_epoch::kernel::restore::writer::tests::{Fixture, fixture};
use serde::Serialize;
use std::{collections::VecDeque, time::Duration};

const READ: &str = "2026-11-04T00:00:01Z";
const TX: &str = "d3JpdGVyLXRva2Vu";

fn version(n: u64) -> UpdateTime {
    format!("2026-11-04T00:00:00.{n:06}Z").try_into().unwrap()
}

// Separate simple encoder oracle: authority fields are string/map ONLY.
fn fields(value: Value) -> Result<Value> {
    let Value::Object(values) = value else {
        anyhow::bail!("writer_fixture_object");
    };
    let mut out = serde_json::Map::new();
    for (key, value) in values {
        out.insert(
            key,
            match value {
                Value::String(text) => json!({"stringValue":text}),
                Value::Object(_) => json!({"mapValue":{"fields":fields(value)?}}),
                _ => anyhow::bail!("writer_fixture_authority_field_type"),
            },
        );
    }
    Ok(Value::Object(out))
}

fn doc<T: Serialize>(name: &str, value: &T, token: u64, domain: Option<&str>) -> Result<Value> {
    let value = match domain {
        None => fields(serde_json::to_value(value)?)?,
        Some(domain) => json!({
            "restore_json":{"stringValue":serde_json::to_string(value)?},
            "restore_digest":{"stringValue":Digest::of(&(domain,value))?},
        }),
    };
    Ok(json!({"readTime":READ,"found":{"name":name,"fields":value,
        "createTime":version(1),"updateTime":version(token)}}))
}

fn publication(
    f: &Fixture,
) -> Result<Versioned<crate::security_epoch::restore_approval::publication::Publication>> {
    Ok(Versioned {
        value: crate::security_epoch::restore_approval::fixture_publication_for_request_data(
            &f.selected,
            &f.authority.grant.approval,
        )?,
        version: version(2),
    })
}

fn publication_entry(f: &Fixture, name: &str) -> Result<Value> {
    let value = publication(f)?;
    Ok(json!({"readTime":READ,"found":{"name":name,
    "createTime":version(1),"updateTime":value.version,
    "fields":{
        "payload":{"stringValue":String::from_utf8(value.value.encode(&f.selected)?)?},
        "commitment":{"stringValue":Digest::of(&("day2-restore-approval-publication-document-v1",&value.value))?}
    }}}))
}

fn reply(f: &Fixture, p: &kernel::Plan, after: bool, header: bool) -> Result<Vec<Value>> {
    let names = Names::new(&f.selected, &f.request, p, &publication(f)?)?;
    let n = names.documents();
    let s = &f.before.settled;
    let mut values = vec![
        doc(
            n[0],
            if after {
                &p.root
            } else {
                &s.snapshot.root.as_ref().unwrap().value
            },
            if after { 5 } else { 3 },
            None,
        )?,
        doc(
            n[1],
            if after {
                &p.sentinel
            } else {
                &s.snapshot.sentinel.as_ref().unwrap().value
            },
            if after { 5 } else { 3 },
            None,
        )?,
        doc(n[2], &s.snapshot.create.as_ref().unwrap().value, 1, None)?,
        doc(n[3], &s.snapshot.activate.as_ref().unwrap().value, 2, None)?,
        doc(
            n[4],
            &s.advance.value,
            3,
            Some("day2-restore-advance-document-v1"),
        )?,
        doc(
            n[5],
            &s.reservation.value,
            3,
            Some("day2-restore-reservation-document-v1"),
        )?,
        doc(
            n[6],
            &f.before.consumed.value,
            3,
            Some("day2-restore-grant-document-v1"),
        )?,
        publication_entry(f, n[7])?,
        doc(
            n[8],
            &f.before.terminal.value,
            4,
            Some("day2-restore-settlement-document-v1"),
        )?,
    ];
    values.push(if after {
        doc(n[9], &p.receipt, 5, Some("day2-restore-writer-document-v1"))?
    } else {
        json!({"readTime":READ,"missing":n[9]})
    });
    if header {
        values.insert(0, json!({"transaction":TX}));
    }
    Ok(values)
}

fn plan(f: &Fixture) -> Result<kernel::Plan> {
    f.request
        .prepare(&f.selected, &f.authority, 1002, &f.before, None)
}

#[test]
fn writer_transaction_reads_all_nine_and_cas_updates_two_creates_one() -> Result<()> {
    let f = fixture(80, true)?;
    let p = plan(&f)?;
    let names = Names::new(&f.selected, &f.request, &p, &publication(&f)?)?;
    let begin: Value = crate::json::decode(&names.begin_body()?)?;
    assert_eq!(
        begin,
        json!({"documents":names.documents(),"newTransaction":{"readWrite":{}}})
    );
    assert_eq!(names.documents().len(), 10);
    let strong: Value = crate::json::decode(&names.strong_body()?)?;
    assert_eq!(strong, json!({"documents":names.documents()}));
    assert!(names.endpoint("beginTransaction").is_err());
    let tx = names.transaction(&serde_json::to_vec(&reply(&f, &p, false, true)?)?)?;
    assert_eq!(tx.observed()?.state, f.before);
    let body: Value =
        crate::json::decode(&tx.commit_body(&f.selected, &f.request, &p, &f.authority, 1002)?)?;
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert_eq!(body["transaction"], TX);
    let writes = body["writes"].as_array().unwrap();
    assert_eq!(writes.len(), 3);
    assert_eq!(
        writes[0]["update"]["fields"],
        fields(serde_json::to_value(&p.root)?)?
    );
    assert_eq!(
        writes[1]["update"]["fields"],
        fields(serde_json::to_value(&p.sentinel)?)?
    );
    assert_eq!(
        writes[0]["currentDocument"],
        json!({"updateTime":version(3)})
    );
    assert_eq!(
        writes[1]["currentDocument"],
        json!({"updateTime":version(3)})
    );
    assert_eq!(writes[2]["currentDocument"], json!({"exists":false}));
    assert_eq!(
        writes[2]["update"]["fields"]["restore_json"]["stringValue"],
        serde_json::to_string(&p.receipt)?
    );
    assert_eq!(
        tx.rollback_body()?,
        serde_json::to_vec(&json!({"transaction":TX}))?
    );
    Ok(())
}

#[test]
fn every_observed_record_version_and_occupied_writer_refuses_before_commit_body() -> Result<()> {
    let f = fixture(81, true)?;
    let p = plan(&f)?;
    for index in 0..9 {
        let mut values = reply(&f, &p, false, true)?;
        values[index + 1]["found"]["updateTime"] = json!(version(90));
        let tx = Names::new(&f.selected, &f.request, &p, &publication(&f)?)?
            .transaction(&serde_json::to_vec(&values)?)?;
        assert!(
            tx.commit_body(&f.selected, &f.request, &p, &f.authority, 1002)
                .is_err()
        );
        assert!(!tx.rollback_body()?.is_empty());
    }
    let tx = Names::new(&f.selected, &f.request, &p, &publication(&f)?)?
        .transaction(&serde_json::to_vec(&reply(&f, &p, true, true)?)?)?;
    assert!(
        tx.commit_body(&f.selected, &f.request, &p, &f.authority, 1002)
            .is_err()
    );
    let mut current = f.authority.clone();
    current.enabled = false;
    let tx = Names::new(&f.selected, &f.request, &p, &publication(&f)?)?
        .transaction(&serde_json::to_vec(&reply(&f, &p, false, true)?)?)?;
    assert!(
        tx.commit_body(&f.selected, &f.request, &p, &current, 1002)
            .is_err()
    );
    assert!(
        tx.commit_body(
            &f.selected,
            &f.request,
            &p,
            &f.authority,
            f.authority.ready_until
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn malformed_streams_keep_known_header_but_never_become_valid_observations() -> Result<()> {
    let f = fixture(82, true)?;
    let p = plan(&f)?;
    for change in 0..7 {
        let mut values = reply(&f, &p, false, true)?;
        match change {
            0 => {
                values.pop();
            }
            1 => values[2] = values[1].clone(),
            2 => {
                values[1]["found"]["name"] =
                    json!("projects/foreign/databases/foreign/documents/foreign")
            }
            3 => values[7]["transaction"] = json!(TX),
            4 => {
                values[9]["found"]["fields"]["restore_digest"]["stringValue"] =
                    json!(Digest::new(b"wrong"))
            }
            5 => values[9]["readTime"] = json!("2026-11-03T00:00:00Z"),
            _ => values[9]["found"]["fields"]["unexpected"] = json!({"stringValue":"not-admitted"}),
        }
        let tx = Names::new(&f.selected, &f.request, &p, &publication(&f)?)?
            .transaction(&serde_json::to_vec(&values)?)?;
        assert!(tx.observed().is_err());
        assert!(!tx.rollback_body()?.is_empty());
    }
    let raw = serde_json::to_string(&reply(&f, &p, false, true)?)?;
    let duplicate = raw.replacen(
        "\"transaction\":",
        "\"transaction\":\"AQ==\",\"transaction\":",
        1,
    );
    assert_ne!(raw, duplicate);
    assert!(
        Names::new(&f.selected, &f.request, &p, &publication(&f)?)?
            .transaction(duplicate.as_bytes())
            .is_err()
    );
    assert!(
        Names::new(&f.selected, &f.request, &p, &publication(&f)?)?
            .transaction(&vec![b' '; 65_537])
            .is_err()
    );
    Ok(())
}

#[test]
fn exact_three_result_ack_and_strong_read_join_actual_versions() -> Result<()> {
    let f = fixture(83, true)?;
    let p = plan(&f)?;
    let ack = json!({"writeResults":[{"updateTime":version(5)},{"updateTime":version(5)},{"updateTime":version(5)}],"commitTime":version(5)});
    let commit = commit_reply(&serde_json::to_vec(&ack)?)?;
    let names = Names::new(&f.selected, &f.request, &p, &publication(&f)?)?;
    let observed = names.strong(&serde_json::to_vec(&reply(&f, &p, true, false)?)?)?;
    observed.after_commit(&commit)?;
    assert!(matches!(
        kernel::reconcile(
            &f.selected,
            &f.request,
            &p,
            &observed.state,
            observed.writer.as_ref()
        )?,
        kernel::Outcome::Applied(_)
    ));
    for index in [1, 2, 10] {
        let mut values = reply(&f, &p, true, true)?;
        values.remove(0);
        values[index - 1]["found"]["updateTime"] = json!(version(6));
        assert!(
            names
                .strong(&serde_json::to_vec(&values)?)?
                .after_commit(&commit)
                .is_err()
        );
    }
    for mutation in 0..4 {
        let mut wrong = ack.clone();
        match mutation {
            0 => {
                wrong["writeResults"].as_array_mut().unwrap().pop();
            }
            1 => wrong["writeResults"][0] = json!([]),
            2 => wrong["writeResults"][0]["updateTime"] = json!(version(8)),
            _ => wrong["unknown"] = json!("refused"),
        }
        assert!(commit_reply(&serde_json::to_vec(&wrong)?).is_err());
    }
    Ok(())
}

#[test]
fn writer_never_substitutes_or_refreshes_the_consumed_publication_version() -> Result<()> {
    let f = fixture(84, true)?;
    let p = plan(&f)?;
    let expected = publication(&f)?;
    for after in [false, true] {
        let mut values = reply(&f, &p, after, true)?;
        // Same canonical signed bytes at a new updateTime still lose the
        // exact version captured by the consuming transaction.
        values[8]["found"]["updateTime"] = json!(version(3));
        let tx = Names::new(&f.selected, &f.request, &p, &expected)?
            .transaction(&serde_json::to_vec(&values)?)?;
        assert!(tx.observed().is_err());
        assert!(!tx.rollback_body()?.is_empty());
        values.remove(0);
        assert!(
            Names::new(&f.selected, &f.request, &p, &expected)?
                .strong(&serde_json::to_vec(&values)?)
                .is_err()
        );
    }
    let other = fixture(85, true)?;
    assert!(Names::new(&f.selected, &f.request, &p, &publication(&other)?).is_err());
    Ok(())
}

// Controlled transport only; this cannot install a production provider port.
struct WriterPort {
    replies: VecDeque<Option<Vec<u8>>>,
    calls: Vec<&'static str>,
    refused: bool,
}

impl Port for WriterPort {
    fn sample(&mut self) -> Result<Sample> {
        ensure!(!self.refused, "writer_fixture_refused");
        Ok(Sample {
            domain: Digest::new(b"writer-fixture-clock"),
            elapsed: Duration::from_millis(1),
        })
    }
    fn post(
        &mut self,
        url: &str,
        _body: &[u8],
        _budget: &mut Budget,
        maximum: usize,
    ) -> Result<EpochReply> {
        assert_eq!(maximum, 65_536);
        self.calls.push(if url.ends_with(":commit") {
            "commit"
        } else if url.ends_with(":batchGet") {
            "read"
        } else {
            "rollback"
        });
        Ok(EpochReply {
            status: 200,
            body: self
                .replies
                .pop_front()
                .flatten()
                .context("writer_fixture_unknown")?,
        })
    }
    fn refuse(&mut self) {
        self.refused = true;
    }
}

#[test]
fn actual_consuming_writer_send_checks_three_ack_versions_and_all_ten_post_records() -> Result<()> {
    let f = fixture(607, true)?;
    let p = plan(&f)?;
    for cut in 0..12 {
        let mut rows = reply(&f, &p, true, false)?;
        let mut ack = json!({"writeResults":[{"updateTime":version(5)},{"updateTime":version(5)},{"updateTime":version(5)}],"commitTime":version(5)});
        if (1..=10).contains(&cut) {
            rows[cut - 1]["found"]["updateTime"] = json!(version(90));
        }
        if cut == 11 {
            ack["writeResults"] = json!([]);
        }
        let mut port = WriterPort {
            replies: VecDeque::from([
                Some(serde_json::to_vec(&ack)?),
                Some(serde_json::to_vec(&rows)?),
            ]),
            calls: Vec::new(),
            refused: false,
        };
        let budget = Budget::for_context(port.sample()?, Duration::from_secs(5))?;
        let tx = Names::new(&f.selected, &f.request, &p, &publication(&f)?)?
            .transaction(&serde_json::to_vec(&reply(&f, &p, false, true)?)?)?;
        let result = tx.commit_and_readback(
            &mut port,
            budget,
            &f.selected,
            &f.request,
            &p,
            (&f.authority, 1002),
        );
        if cut == 0 {
            assert_eq!(result?.receipt_data()?, p.receipt);
            assert!(!port.refused);
        } else {
            assert!(result.is_err());
            assert!(port.refused);
        }
        assert!(port.calls == ["commit"] || port.calls == ["commit", "read"]);
    }
    let mut port = WriterPort {
        replies: VecDeque::from([None]),
        calls: Vec::new(),
        refused: false,
    };
    let budget = Budget::for_context(port.sample()?, Duration::from_secs(5))?;
    let tx = Names::new(&f.selected, &f.request, &p, &publication(&f)?)?
        .transaction(&serde_json::to_vec(&reply(&f, &p, false, true)?)?)?;
    assert!(
        tx.commit_and_readback(
            &mut port,
            budget,
            &f.selected,
            &f.request,
            &p,
            (&f.authority, 1002)
        )
        .is_err()
    );
    assert_eq!(port.calls, ["commit"]);
    assert!(port.refused);
    Ok(())
}

#[test]
fn separate_post_cas_observation_retains_every_value_version_and_read_floor() -> Result<()> {
    let f = fixture(87, true)?;
    let plan = plan(&f)?;
    let names = Names::new(&f.selected, &f.request, &plan, &publication(&f)?)?;
    let rows = reply(&f, &plan, true, false)?;
    let known = KnownWriter {
        observed: names.strong(&serde_json::to_vec(&rows)?)?,
        acknowledged: commit_reply(&serde_json::to_vec(&json!({
            "writeResults":[{"updateTime":version(5)},{"updateTime":version(5)},{"updateTime":version(5)}],
            "commitTime":version(5)
        }))?)?,
    };
    let mut later = rows.clone();
    for entry in &mut later {
        entry["readTime"] = json!("2026-11-04T00:00:02Z");
    }
    assert_eq!(
        known.require_observed_data(&names.strong(&serde_json::to_vec(&later)?)?)?,
        plan.receipt
    );
    let mut compared = 0;
    for index in 0..10 {
        let mut rewritten = rows.clone();
        rewritten[index]["found"]["updateTime"] = json!(version(99));
        if let Ok(observed) = names.strong(&serde_json::to_vec(&rewritten)?) {
            compared += 1;
            assert!(
                known.require_observed_data(&observed).is_err(),
                "same-value version rewrite {index}"
            );
        }
    }
    assert!(
        compared >= 6,
        "unchanged history versions reach actual known-observation check"
    );
    // A separately decoded names object must not lose the captured publication
    // version merely because its signed payload bytes remain identical.
    let mut changed_publication = names.strong(&serde_json::to_vec(&rows)?)?;
    changed_publication.publication.version = version(7);
    assert!(known.require_observed_data(&changed_publication).is_err());
    let mut older = rows;
    for entry in &mut older {
        entry["readTime"] = json!(version(6));
    }
    let older = names.strong(&serde_json::to_vec(&older)?)?;
    older.after_commit(&known.acknowledged)?;
    assert!(known.require_observed_data(&older).is_err());
    Ok(())
}

#[test]
fn post_cas_registry_snapshot_refuses_fenced_or_rewritten_history() -> Result<()> {
    let f = fixture(88, true)?;
    let plan = plan(&f)?;
    let names = Names::new(&f.selected, &f.request, &plan, &publication(&f)?)?;
    let rows = reply(&f, &plan, true, false)?;
    let known = KnownWriter {
        observed: names.strong(&serde_json::to_vec(&rows)?)?,
        acknowledged: commit_reply(&serde_json::to_vec(&json!({
            "writeResults":[{"updateTime":version(5)},{"updateTime":version(5)},{"updateTime":version(5)}],
            "commitTime":version(5)
        }))?)?,
    };
    known.require_snapshot_data(&known.observed.state.settled.snapshot)?;
    assert!(
        known
            .require_snapshot_data(&f.before.settled.snapshot)
            .is_err()
    );
    for index in 0..4 {
        let mut rewritten = rows.clone();
        rewritten[index]["found"]["updateTime"] = json!(version(99));
        let changed = names.strong(&serde_json::to_vec(&rewritten)?)?;
        assert!(
            known
                .require_snapshot_data(&changed.state.settled.snapshot)
                .is_err(),
            "same-value registry row version {index}"
        );
    }
    let mut missing = known.observed.state.settled.snapshot.clone();
    missing.root = None;
    assert!(known.require_snapshot_data(&missing).is_err());
    // Even a synthetically fabricated self-consistent DATA record cannot
    // relabel a Fenced predecessor as this post-writer registry purpose.
    let mut fabricated = known;
    fabricated
        .observed
        .state
        .settled
        .snapshot
        .root
        .as_mut()
        .unwrap()
        .value
        .phase = f
        .before
        .settled
        .snapshot
        .root
        .as_ref()
        .unwrap()
        .value
        .phase
        .clone();
    let same_fenced = fabricated.observed.state.settled.snapshot.clone();
    assert!(fabricated.require_snapshot_data(&same_fenced).is_err());
    Ok(())
}

struct PeerFixture {
    fixture: Fixture,
    plan: kernel::Plan,
    known: KnownWriter,
    projection: crate::security_epoch::native_enrollment::RestoreFileProjectionData,
    holder: crate::security_epoch::kernel::Holder,
    activation: crate::security_epoch::native_enrollment::RestoreWriterActivationData,
    rows: Vec<Value>,
}

fn peer_fixture(seed: u64) -> Result<PeerFixture> {
    let fixture = fixture(seed, true)?;
    let plan = plan(&fixture)?;
    let selectors = fixture
        .request
        .reservation_data()
        .selectors(&fixture.selected)?;
    let terminal = serde_json::to_value(&fixture.before.terminal.value)?;
    let holder = serde_json::from_value(
        serde_json::to_value(&plan.receipt)?["restoration"]["holder"].clone(),
    )?;
    let projection = serde_json::from_value(json!({
        "selection":{
            "operation":fixture.request.operation(),"approval_request":fixture.authority.grant.approval.commitment()?,
            "intent":fixture.authority.grant.intent,"full_archive":fixture.authority.grant.approval.full_archive_digest,
            "target":fixture.authority.target,
        },
        "creator":{"device_major":8,"device_minor":1,"inode":73,"length":8192,"user":10001,"group":10001},
        "report":terminal["disposition"]["completed"]["report"],
        "consumed_use":Digest::of(&fixture.before.consumed.value)?,"captured_records":fixture.before.commitment_data()?,
        "ledger":{"initial_create":selectors.bootstrap.create_operation,"initial_activation":selectors.activation,"advance":selectors.advance,"grant":fixture.before.consumed.value.grant_id_data()}
    }))?;
    let names = Names::new(
        &fixture.selected,
        &fixture.request,
        &plan,
        &publication(&fixture)?,
    )?;
    let rows = reply(&fixture, &plan, true, false)?;
    let known = KnownWriter {
        observed: names.strong(&serde_json::to_vec(&rows)?)?,
        acknowledged: commit_reply(&serde_json::to_vec(&json!({
            "writeResults":[{"updateTime":version(5)},{"updateTime":version(5)},{"updateTime":version(5)}],"commitTime":version(5)
        }))?)?,
    };
    let activation = known.peer_activation_data(
        &fixture.selected,
        &fixture.request,
        &plan,
        &projection,
        &holder,
    )?;
    Ok(PeerFixture {
        fixture,
        plan,
        known,
        projection,
        holder,
        activation,
        rows,
    })
}

#[test]
fn receiving_app_uses_the_same_ten_selectors_and_canonical_strong_decoder() -> Result<()> {
    let f = peer_fixture(89)?;
    let peer = super::peer::ReaderNames::new(
        &f.fixture.selected,
        &f.projection,
        &f.activation,
        &f.holder,
    )?;
    let controller = Names::new(
        &f.fixture.selected,
        &f.fixture.request,
        &f.plan,
        &publication(&f.fixture)?,
    )?;
    assert_eq!(peer.endpoint_data(), controller.endpoint("batchGet")?);
    assert_eq!(peer.strong_body_data()?, controller.strong_body()?);
    let body: Value = crate::json::decode(&peer.strong_body_data()?)?;
    assert_eq!(body.as_object().unwrap().len(), 1);
    assert_eq!(body["documents"].as_array().unwrap().len(), 10);
    assert!(body.get("newTransaction").is_none() && body.get("readTime").is_none());
    peer.validate_response_data(&serde_json::to_vec(&f.rows)?)?;
    // These are historical comparisons: twice parsing DATA is not a native
    // read, a fresh original or permission to open a keeper.
    peer.validate_response_data(&serde_json::to_vec(&f.rows)?)?;
    let mut shuffled = f.rows.clone();
    shuffled.reverse();
    peer.validate_response_data(&serde_json::to_vec(&shuffled)?)?;
    assert_eq!(f.activation.expectation.committed_at_data(), &version(5));
    assert!(serde_json::to_vec(&f.activation)?.len() < 4096);
    Ok(())
}

// Independent expected history from the fixture's typed predecessor and plan,
// never the production decoder, record_data or activation expectation arrays.
fn peer_commitment_records(f: &PeerFixture) -> Result<([Digest; 10], [UpdateTime; 10])> {
    fn record<T: Serialize>(index: u8, value: &T) -> Result<Digest> {
        Digest::of(&("day2-restore-writer-peer-record-v1", index, value))
    }
    let before = &f.fixture.before;
    let initial = &before.settled.snapshot;
    Ok((
        [
            record(0, &f.plan.root)?,
            record(1, &f.plan.sentinel)?,
            record(2, &initial.create.as_ref().unwrap().value)?,
            record(3, &initial.activate.as_ref().unwrap().value)?,
            record(4, &before.settled.advance.value)?,
            record(5, &before.settled.reservation.value)?,
            record(6, &before.consumed.value)?,
            record(7, &publication(&f.fixture)?.value)?,
            record(8, &before.terminal.value)?,
            record(9, &f.plan.receipt)?,
        ],
        [
            version(5),
            version(5),
            version(1),
            version(2),
            version(3),
            version(3),
            version(3),
            version(2),
            version(4),
            version(5),
        ],
    ))
}

#[test]
fn receiving_reader_binding_includes_expected_lineage_and_exact_holder() -> Result<()> {
    let f = peer_fixture(97)?;
    let reader = super::peer::ReaderNames::new(
        &f.fixture.selected,
        &f.projection,
        &f.activation,
        &f.holder,
    )?;
    let actual = reader.binding_data()?;
    let expected =
        |selected: &EpochStore,
         projection: &crate::security_epoch::native_enrollment::RestoreFileProjectionData,
         activation: &crate::security_epoch::native_enrollment::RestoreWriterActivationData,
         holder: &crate::security_epoch::kernel::Holder| {
            Digest::of(&(
                "day2-restored-writer-reader-binding-v1",
                selected,
                projection,
                activation,
                holder,
            ))
        };
    assert_eq!(
        actual,
        expected(&f.fixture.selected, &f.projection, &f.activation, &f.holder)?
    );
    assert!(reader.matches_selection_data(&f.fixture.selected));
    let mut store = f.fixture.selected.clone();
    store.scope.app = serde_json::from_value(json!("another-app"))?;
    assert!(!reader.matches_selection_data(&store));
    assert_ne!(
        actual,
        expected(&store, &f.projection, &f.activation, &f.holder)?
    );
    let mut projection = f.projection.clone();
    projection.captured_records = Digest::new(b"different-history-with-identical-selectors");
    assert_ne!(
        actual,
        expected(&f.fixture.selected, &projection, &f.activation, &f.holder)?
    );
    let mut activation = f.activation.clone();
    activation.receipt = Digest::new(b"different-current-writer");
    assert_ne!(
        actual,
        expected(&f.fixture.selected, &f.projection, &activation, &f.holder)?
    );
    let mut holder = f.holder.clone();
    holder.ephemeral_key = Digest::new(b"different-actual-key");
    assert_ne!(
        actual,
        expected(&f.fixture.selected, &f.projection, &f.activation, &holder)?
    );
    Ok(())
}

#[test]
fn receiving_commitment_binds_all_ten_records_versions_and_selectors() -> Result<()> {
    let f = peer_fixture(95)?;
    let peer = super::peer::ReaderNames::new(
        &f.fixture.selected,
        &f.projection,
        &f.activation,
        &f.holder,
    )?;
    let controller = Names::new(
        &f.fixture.selected,
        &f.fixture.request,
        &f.plan,
        &publication(&f.fixture)?,
    )?;
    let selectors = controller.documents();
    assert_eq!(selectors.len(), 10);
    let (records, versions) = peer_commitment_records(&f)?;
    let expected = |selected: &EpochStore,
                    selectors: &[&str],
                    records: &[Digest; 10],
                    versions: &[UpdateTime; 10]| {
        Digest::of(&(
            "day2-restore-writer-peer-observation-v1",
            selected,
            selectors,
            records,
            versions,
        ))
    };
    let actual = peer.response_commitment_data(&serde_json::to_vec(&f.rows)?)?;
    assert_eq!(
        actual,
        expected(&f.fixture.selected, &selectors, &records, &versions)?
    );
    let mut foreign_store = f.fixture.selected.clone();
    foreign_store.scope.app = serde_json::from_value(json!("another-app"))?;
    assert_ne!(
        actual,
        expected(&foreign_store, &selectors, &records, &versions)?
    );
    peer.validate_response_data(&serde_json::to_vec(&f.rows)?)?;
    for index in 0..10 {
        let mut changed_records = records.clone();
        changed_records[index] = Digest::new(b"different independently expected value");
        assert_ne!(
            actual,
            expected(&f.fixture.selected, &selectors, &changed_records, &versions)?,
            "record {index}"
        );
        let mut changed_versions = versions.clone();
        changed_versions[index] = version(99);
        assert_ne!(
            actual,
            expected(&f.fixture.selected, &selectors, &records, &changed_versions)?,
            "version {index}"
        );
        let mut changed_selectors = selectors.clone();
        changed_selectors[index] = "projects/foreign/databases/foreign/documents/foreign";
        assert_ne!(
            actual,
            expected(&f.fixture.selected, &changed_selectors, &records, &versions)?,
            "selector {index}"
        );
    }
    let mut reordered = f.rows.clone();
    reordered.reverse();
    assert_eq!(
        actual,
        peer.response_commitment_data(&serde_json::to_vec(&reordered)?)?
    );
    let mut later = f.rows.clone();
    for row in &mut later {
        row["readTime"] = json!("2026-11-04T00:00:02Z");
    }
    assert_eq!(
        actual,
        peer.response_commitment_data(&serde_json::to_vec(&later)?)?
    );
    // This stable DATA digest does not carry either read's freshness/original.
    Ok(())
}

#[test]
fn receiving_commitment_refuses_missing_foreign_and_rewritten_history() -> Result<()> {
    let f = peer_fixture(96)?;
    let peer = super::peer::ReaderNames::new(
        &f.fixture.selected,
        &f.projection,
        &f.activation,
        &f.holder,
    )?;
    for index in 0..10 {
        let mut rewritten = f.rows.clone();
        rewritten[index]["found"]["updateTime"] = json!(version(99));
        assert!(
            peer.response_commitment_data(&serde_json::to_vec(&rewritten)?)
                .is_err(),
            "version {index}"
        );
        let mut missing = f.rows.clone();
        missing.remove(index);
        assert!(
            peer.response_commitment_data(&serde_json::to_vec(&missing)?)
                .is_err(),
            "missing {index}"
        );
        let mut foreign = f.rows.clone();
        foreign[index]["found"]["name"] =
            json!("projects/foreign/databases/foreign/documents/foreign");
        assert!(
            peer.response_commitment_data(&serde_json::to_vec(&foreign)?)
                .is_err(),
            "foreign {index}"
        );
        let mut changed = f.rows.clone();
        changed[index]["found"]["fields"]["unrecognized"] = json!({"stringValue":"must refuse"});
        assert!(
            peer.response_commitment_data(&serde_json::to_vec(&changed)?)
                .is_err(),
            "value {index}"
        );
    }
    // Valid canonical historical value with the original version: reach the
    // value comparison rather than relying on unknown-field/version refusal.
    let mut rewritten = f
        .fixture
        .before
        .settled
        .snapshot
        .create
        .as_ref()
        .unwrap()
        .value
        .clone();
    rewritten.after_root = Digest::new(b"different valid historical root");
    let mut changed = f.rows.clone();
    changed[2]["found"]["fields"] = fields(serde_json::to_value(rewritten)?)?;
    let controller = Names::new(
        &f.fixture.selected,
        &f.fixture.request,
        &f.plan,
        &publication(&f.fixture)?,
    )?;
    controller.strong(&serde_json::to_vec(&changed)?)?;
    assert!(
        peer.response_commitment_data(&serde_json::to_vec(&changed)?)
            .is_err()
    );
    let mut duplicated = f.rows.clone();
    duplicated[1] = duplicated[0].clone();
    assert!(
        peer.response_commitment_data(&serde_json::to_vec(&duplicated)?)
            .is_err()
    );
    let mut old = f.rows.clone();
    for row in &mut old {
        row["readTime"] = json!(version(6));
    }
    assert!(
        peer.response_commitment_data(&serde_json::to_vec(&old)?)
            .is_err()
    );
    assert!(peer.response_commitment_data(&vec![b' '; 65_537]).is_err());
    let bytes = serde_json::to_vec(&f.rows)?;
    assert!(
        peer.response_commitment_data(&bytes[..bytes.len() - 1])
            .is_err()
    );
    Ok(())
}

#[test]
fn receiving_app_refuses_every_changed_version_value_missing_or_foreign_record() -> Result<()> {
    let f = peer_fixture(90)?;
    let peer = super::peer::ReaderNames::new(
        &f.fixture.selected,
        &f.projection,
        &f.activation,
        &f.holder,
    )?;
    for index in 0..10 {
        let mut changed = f.rows.clone();
        changed[index]["found"]["updateTime"] = json!(version(99));
        assert!(
            peer.validate_response_data(&serde_json::to_vec(&changed)?)
                .is_err(),
            "version rewrite {index}"
        );
        let mut missing = f.rows.clone();
        missing.remove(index);
        assert!(
            peer.validate_response_data(&serde_json::to_vec(&missing)?)
                .is_err(),
            "missing {index}"
        );
        let mut foreign = f.rows.clone();
        foreign[index]["found"]["name"] =
            json!("projects/foreign/databases/foreign/documents/foreign");
        assert!(
            peer.validate_response_data(&serde_json::to_vec(&foreign)?)
                .is_err(),
            "foreign {index}"
        );
        let mut value = f.rows.clone();
        value[index]["found"]["fields"]["unrecognized"] = json!({"stringValue":"must refuse"});
        assert!(
            peer.validate_response_data(&serde_json::to_vec(&value)?)
                .is_err(),
            "value change {index}"
        );
    }
    let mut duplicated = f.rows.clone();
    duplicated[1] = duplicated[0].clone();
    assert!(
        peer.validate_response_data(&serde_json::to_vec(&duplicated)?)
            .is_err()
    );
    let mut before = f.rows.clone();
    for entry in &mut before {
        entry["readTime"] = json!(version(6));
    }
    assert!(
        peer.validate_response_data(&serde_json::to_vec(&before)?)
            .is_err(),
        "read before captured Known floor"
    );
    assert!(peer.validate_response_data(&vec![b' '; 65_537]).is_err());
    let bytes = serde_json::to_vec(&f.rows)?;
    assert!(
        peer.validate_response_data(&bytes[..bytes.len() - 1])
            .is_err()
    );
    // Still a valid canonical receipt with the captured version, but not
    // the actual immutable history. This must reach the value commitments,
    // rather than relying only on parser or update-token rejection.
    let mut rewritten = f
        .fixture
        .before
        .settled
        .snapshot
        .create
        .as_ref()
        .unwrap()
        .value
        .clone();
    rewritten.after_root = Digest::new(b"different valid historical root");
    let mut changed = f.rows.clone();
    changed[2]["found"]["fields"] = fields(serde_json::to_value(rewritten)?)?;
    let names = Names::new(
        &f.fixture.selected,
        &f.fixture.request,
        &f.plan,
        &publication(&f.fixture)?,
    )?;
    names.strong(&serde_json::to_vec(&changed)?)?;
    assert!(
        peer.validate_response_data(&serde_json::to_vec(&changed)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn receiving_app_refuses_nonatomic_acknowledged_write_versions() -> Result<()> {
    let mut f = peer_fixture(92)?;
    // The wire decoder permits distinct updateTime values. The existing
    // writer reconciliation additionally requires one common version for
    // the atomic three-write transition; the receiving boundary retains it.
    for (index, token) in [(0, 5), (1, 6), (9, 7)] {
        f.rows[index]["found"]["updateTime"] = json!(version(token));
    }
    let names = Names::new(
        &f.fixture.selected,
        &f.fixture.request,
        &f.plan,
        &publication(&f.fixture)?,
    )?;
    let known = KnownWriter {
        observed: names.strong(&serde_json::to_vec(&f.rows)?)?,
        acknowledged: commit_reply(&serde_json::to_vec(&json!({
            "writeResults":[{"updateTime":version(5)},{"updateTime":version(6)},{"updateTime":version(7)}],"commitTime":version(8)
        }))?)?,
    };
    assert!(
        known
            .peer_activation_data(
                &f.fixture.selected,
                &f.fixture.request,
                &f.plan,
                &f.projection,
                &f.holder
            )
            .is_err()
    );
    // A caller-created DATA expectation cannot bypass the same rule, even
    // when its visible fields match all three stored version slots.
    let mut activation = serde_json::to_value(&f.activation)?;
    activation["sentinel_version"] = json!(version(6));
    activation["receipt_version"] = json!(version(7));
    activation["expectation"]["versions"][1] = json!(version(6));
    activation["expectation"]["versions"][9] = json!(version(7));
    activation["expectation"]["committed_at"] = json!(version(8));
    let activation = serde_json::from_value(activation)?;
    assert!(
        super::peer::ReaderNames::new(&f.fixture.selected, &f.projection, &activation, &f.holder)
            .is_err()
    );
    Ok(())
}

#[test]
fn receiving_expectation_preserves_commit_floor_map_shape_and_exact_original_bindings() -> Result<()>
{
    let f = peer_fixture(91)?;
    let value = serde_json::to_value(&f.activation)?;
    for change in 0..8 {
        let mut changed = value.clone();
        match change {
            0 => changed["expectation"]["read_floor"] = json!("2026-11-03T00:00:00Z"),
            1 => changed["expectation"]["committed_at"] = json!("2026-11-05T00:00:00Z"),
            2 => changed["expectation"]["versions"][0] = json!(version(99)),
            3 => changed["root_version"] = json!(version(99)),
            4 => changed["expectation"]["records"] = json!([]),
            5 => changed["expectation"]["versions"] = json!([]),
            6 => changed["expectation"]["unknown"] = json!("not DATA"),
            _ => changed["expectation"] = json!([]),
        }
        if let Ok(activation) = serde_json::from_value(changed) {
            assert!(
                super::peer::ReaderNames::new(
                    &f.fixture.selected,
                    &f.projection,
                    &activation,
                    &f.holder
                )
                .is_err(),
                "cut {change}"
            );
        }
    }
    let raw = serde_json::to_string(&f.activation)?;
    let duplicated = raw.replacen(
        "\"read_floor\":",
        "\"read_floor\":\"2026-11-04T00:00:01Z\",\"read_floor\":",
        1,
    );
    assert_ne!(raw, duplicated);
    assert!(serde_json::from_str::<crate::security_epoch::native_enrollment::RestoreWriterActivationData>(&duplicated).is_err());
    for change in 0..12 {
        let mut projection = f.projection.clone();
        match change {
            0 => projection.selection.operation = Digest::new(b"another restore"),
            1 => projection.ledger.grant = Digest::new(b"another grant"),
            2 => projection.ledger.advance = Digest::new(b"another advance"),
            3 => projection.ledger.initial_create = projection.ledger.initial_activation.clone(),
            4 => projection.captured_records = Digest::new(b"another predecessor"),
            5 => projection.consumed_use = Digest::new(b"another use"),
            6 => projection.selection.full_archive = Digest::new(b"another archive"),
            7 => projection.selection.approval_request = Digest::new(b"another approval"),
            8 => projection.selection.intent = Digest::new(b"another intent"),
            9 => projection.selection.target.binding_generation += 1,
            10 => projection.ledger.initial_create = Digest::new(b"another initial create"),
            _ => projection.ledger.initial_activation = Digest::new(b"another initial activation"),
        }
        assert!(
            f.known
                .peer_activation_data(
                    &f.fixture.selected,
                    &f.fixture.request,
                    &f.plan,
                    &projection,
                    &f.holder
                )
                .is_err(),
            "producer binding {change}"
        );
        if let Ok(peer) = super::peer::ReaderNames::new(
            &f.fixture.selected,
            &projection,
            &f.activation,
            &f.holder,
        ) {
            assert!(
                peer.validate_response_data(&serde_json::to_vec(&f.rows)?)
                    .is_err(),
                "consumer binding {change}"
            );
        }
    }
    let mut foreign_holder = f.holder.clone();
    foreign_holder.ephemeral_key = Digest::new(b"another actual holder");
    assert!(
        f.known
            .peer_activation_data(
                &f.fixture.selected,
                &f.fixture.request,
                &f.plan,
                &f.projection,
                &foreign_holder
            )
            .is_err()
    );
    let peer = super::peer::ReaderNames::new(
        &f.fixture.selected,
        &f.projection,
        &f.activation,
        &foreign_holder,
    )?;
    assert!(
        peer.validate_response_data(&serde_json::to_vec(&f.rows)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn release_activation_comparison_retains_every_captured_record_version_and_plan() -> Result<()> {
    let f = peer_fixture(609)?;
    f.known.require_activation_data(&f.plan, &f.activation)?;
    let raw = serde_json::to_value(&f.activation)?;
    let foreign = Digest::of(&"restore-release-foreign")?;
    for field in [
        "receipt",
        "root",
        "sentinel",
        "root_version",
        "sentinel_version",
        "receipt_version",
    ] {
        let mut changed = raw.clone();
        changed[field] = if field.ends_with("version") {
            json!(version(99))
        } else {
            json!(&foreign)
        };
        let changed = serde_json::from_value(changed)?;
        assert!(
            f.known.require_activation_data(&f.plan, &changed).is_err(),
            "{field}"
        );
    }
    for index in 0..10 {
        for field in ["records", "versions"] {
            let mut changed = raw.clone();
            changed["expectation"][field][index] = if field == "records" {
                json!(&foreign)
            } else {
                json!(version(98))
            };
            let changed = serde_json::from_value(changed)?;
            assert!(
                f.known.require_activation_data(&f.plan, &changed).is_err(),
                "{field} {index}"
            );
        }
    }
    for field in ["committed_at", "read_floor"] {
        let mut changed = raw.clone();
        changed["expectation"][field] = json!(version(97));
        let changed = serde_json::from_value(changed)?;
        assert!(
            f.known.require_activation_data(&f.plan, &changed).is_err(),
            "{field}"
        );
    }
    let other = peer_fixture(610)?;
    assert!(
        f.known
            .require_activation_data(&other.plan, &f.activation)
            .is_err()
    );
    Ok(())
}
