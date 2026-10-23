//! DATA-only schedules over the existing independent SQLite provider oracles.
//! No native role, P3, file, readiness or current-write permission is constructed.
use super::*;
use crate::security_epoch::kernel::{self, Outcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    TokenWithDocument,
    ReverseDocuments,
    IncreasingInterleaved,
    DuplicateDocument,
    DuplicateSlot,
    MissingDocument,
    UnknownDocument,
    ExtraDocument,
    DuplicateToken,
    HeaderReadTime,
    MissingReadTime,
    CrossPartitionRewind,
    InvalidReadTime,
    FoundAndMissing,
    InvalidSlot,
    ExtraSlotField,
    InvalidToken,
    DuplicateJsonField,
    OversizedReply,
    RollbackFailure,
    MalformedRollback,
    ExpireBeforeRollback,
    ExpireAfterRollback,
    LostReadReply,
}

struct PairPort {
    inner: SharedPort,
    fault: Fault,
    cleanup_fault: Option<Fault>,
    requests: Vec<(String, Value)>,
    reads: usize,
    insert_on_second: Option<(EpochStore, LogicalCore)>,
}

impl PairPort {
    fn new(with_slot: bool) -> (EpochStore, LogicalCore, Self) {
        let (selection, core) = fixture();
        let mut inner = SharedPort::new();
        if with_slot {
            inner
                .slots
                .apply(
                    &codec::create_data(&selection, &Slot::prepared(core.clone())).unwrap(),
                    false,
                )
                .unwrap();
        }
        (
            selection,
            core,
            Self {
                inner,
                fault: Fault::None,
                cleanup_fault: None,
                requests: Vec::new(),
                reads: 0,
                insert_on_second: None,
            },
        )
    }

    fn budget(&mut self) -> Budget {
        Budget::for_context(self.sample().unwrap(), Duration::from_secs(105)).unwrap()
    }
}

impl Port for PairPort {
    fn sample(&mut self) -> Result<Sample> {
        self.inner.sample()
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        budget: &mut Budget,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        self.requests.push((url.into(), crate::json::decode(body)?));
        if url.ends_with(":batchGet") {
            self.reads += 1;
            if self.reads == 2
                && let Some((selection, core)) = self.insert_on_second.take()
            {
                self.inner.slots.apply(
                    &codec::create_data(&selection, &Slot::prepared(core))?,
                    false,
                )?;
            }
        }
        let cleanup_fault = self.cleanup_fault.unwrap_or(self.fault);
        if url.ends_with(":rollback") {
            if cleanup_fault == Fault::RollbackFailure {
                anyhow::bail!("scripted rollback lost");
            }
            if cleanup_fault == Fault::ExpireBeforeRollback {
                self.inner
                    .counter
                    .set_slot_fixture_time(Duration::from_secs(105));
            }
        }
        let mut reply = self.inner.post(url, body, budget, max_bytes)?;
        if url.ends_with(":rollback") {
            if cleanup_fault == Fault::MalformedRollback {
                reply.body = br#"{"extra":true}"#.to_vec();
            }
            if cleanup_fault == Fault::ExpireAfterRollback {
                self.inner
                    .counter
                    .set_slot_fixture_time(Duration::from_secs(105));
            }
            return Ok(reply);
        }
        if !url.ends_with(":batchGet") {
            return Ok(reply);
        }
        if self.fault == Fault::LostReadReply {
            anyhow::bail!("scripted read reply lost");
        }
        let mut entries: Vec<Value> = crate::json::decode(&reply.body)?;
        let slot = entries
            .iter()
            .position(|entry| {
                entry
                    .get("found")
                    .and_then(|doc| doc.get("name"))
                    .or_else(|| entry.get("missing"))
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.contains("/day2_credential_control_v1/"))
            })
            .context("test slot entry")?;
        match self.fault {
            Fault::TokenWithDocument => {
                let header = entries.remove(0);
                entries[0]["transaction"] = header["transaction"].clone();
            }
            Fault::ReverseDocuments => entries[1..].reverse(),
            Fault::IncreasingInterleaved => {
                let entry = entries.remove(slot);
                entries.insert(2, entry);
                for (index, entry) in entries.iter_mut().enumerate().skip(1) {
                    entry["readTime"] = json!(format!("2026-10-14T00:00:00.{:06}Z", 100 + index));
                }
            }
            Fault::DuplicateDocument => entries[2] = entries[1].clone(),
            Fault::DuplicateSlot => entries[1] = entries[slot].clone(),
            Fault::MissingDocument => { entries.remove(1); }
            Fault::UnknownDocument => entries[1] = json!({"missing":"projects/foreign/databases/other/documents/x/y","readTime":"2026-10-14T00:00:00.000100Z"}),
            Fault::ExtraDocument => entries.push(json!({"missing":"projects/foreign/databases/other/documents/x/y","readTime":"2026-10-14T00:00:00.000100Z"})),
            Fault::DuplicateToken => entries[slot]["transaction"] = json!("dHhuLTE="),
            Fault::HeaderReadTime => entries[0]["readTime"] = json!("2026-10-14T00:00:00.000100Z"),
            Fault::MissingReadTime => { entries[slot].as_object_mut().unwrap().remove("readTime"); }
            Fault::CrossPartitionRewind => entries[slot]["readTime"] = json!("2026-10-14T00:00:00.000099Z"),
            Fault::InvalidReadTime => entries[slot]["readTime"] = json!("bad-time"),
            Fault::FoundAndMissing => entries[slot]["missing"] = entries[slot]["found"]["name"].clone(),
            Fault::InvalidSlot => entries[slot]["found"]["fields"]["control_json"]["stringValue"] = json!("[]"),
            Fault::ExtraSlotField => entries[slot]["found"]["extra"] = json!(true),
            Fault::InvalidToken => entries[0]["transaction"] = json!("not-canonical"),
            _ => {}
        }
        reply.body = serde_json::to_vec(&entries)?;
        if self.fault == Fault::DuplicateJsonField {
            reply.body = String::from_utf8(reply.body)?
                .replacen(
                    "\"transaction\":",
                    "\"transaction\":\"dHhuLTE=\",\"transact\\u0069on\":",
                    1,
                )
                .into_bytes();
        }
        if self.fault == Fault::OversizedReply {
            reply.body = vec![b' '; 65_537];
        }
        Ok(reply)
    }

    fn refuse(&mut self) {
        self.inner.refuse();
    }
}

#[test]
fn pair_uses_one_exact_read_transaction_and_rollback_with_unordered_or_first_document_token() {
    for with_slot in [false, true] {
        for fault in [
            Fault::None,
            Fault::TokenWithDocument,
            Fault::ReverseDocuments,
            Fault::IncreasingInterleaved,
        ] {
            let (selection, core, mut port) = PairPort::new(with_slot);
            port.fault = fault;
            let budget = port.budget();
            let (counter, slot) =
                guarded::read_with_counter(&selection, &core, &mut port, budget).unwrap();
            assert_eq!(
                kernel::reconcile(&selection, &core.counter, counter.snapshot()).unwrap(),
                Outcome::NotApplied
            );
            assert_eq!(slot.data().is_some(), with_slot);
            if let Some(value) = slot.data() {
                assert_eq!(value.slot, Slot::prepared(core.clone()));
            }
            assert_eq!(port.requests.len(), 2);
            assert!(port.requests[0].0.ends_with(":batchGet"));
            assert!(port.requests[1].0.ends_with(":rollback"));
            let names = firestore::Names::new(&selection, core.counter.bootstrap(), None).unwrap();
            assert_eq!(
                port.requests[0].1,
                json!({"documents":[names.root,names.sentinel,names.create,codec::name(&selection,&core).unwrap()],"newTransaction":{"readOnly":{}}})
            );
            assert_eq!(port.requests[1].1, json!({"transaction":"dHhuLTE="}));
            assert_eq!((port.inner.slot_posts, port.inner.counter_posts), (0, 0));
        }
    }
}

#[test]
fn pair_rejects_whole_stream_and_slot_faults_then_closes_known_transaction() {
    for fault in [
        Fault::DuplicateDocument,
        Fault::DuplicateSlot,
        Fault::MissingDocument,
        Fault::UnknownDocument,
        Fault::ExtraDocument,
        Fault::DuplicateToken,
        Fault::HeaderReadTime,
        Fault::MissingReadTime,
        Fault::CrossPartitionRewind,
        Fault::InvalidReadTime,
        Fault::FoundAndMissing,
        Fault::InvalidSlot,
        Fault::ExtraSlotField,
    ] {
        let (selection, core, mut port) = PairPort::new(true);
        port.fault = fault;
        let budget = port.budget();
        assert!(
            guarded::read_with_counter(&selection, &core, &mut port, budget).is_err(),
            "{fault:?}"
        );
        assert_eq!(port.requests.len(), 2, "{fault:?}");
        assert_eq!(port.requests[1].1, json!({"transaction":"dHhuLTE="}));
        assert!(port.sample().is_err(), "{fault:?}");
        port.fault = Fault::None;
        assert!(
            port.sample().is_err(),
            "restoration must not revive {fault:?}"
        );
        assert_eq!((port.inner.slot_posts, port.inner.counter_posts), (0, 0));
    }
}

#[test]
fn pair_never_exports_observations_for_ambiguous_tokens_byte_overflow_or_failed_cleanup() {
    for fault in [
        Fault::InvalidToken,
        Fault::DuplicateJsonField,
        Fault::OversizedReply,
        Fault::RollbackFailure,
        Fault::MalformedRollback,
        Fault::ExpireBeforeRollback,
        Fault::ExpireAfterRollback,
        Fault::LostReadReply,
    ] {
        let (selection, core, mut port) = PairPort::new(true);
        port.fault = fault;
        let budget = port.budget();
        assert!(
            guarded::read_with_counter(&selection, &core, &mut port, budget).is_err(),
            "{fault:?}"
        );
        assert!(port.requests.len() <= 2, "no resend: {fault:?}");
        assert!(port.sample().is_err());
        port.fault = Fault::None;
        port.inner
            .counter
            .set_slot_fixture_time(Duration::from_secs(104));
        assert!(
            port.sample().is_err(),
            "healthy clock must not revive {fault:?}"
        );
        assert_eq!((port.inner.slot_posts, port.inner.counter_posts), (0, 0));
    }
}

#[test]
fn discovery_rereads_the_entire_counter_slot_pair_and_uses_the_second_slot() {
    let (selection, core, mut port) = PairPort::new(false);
    port.inner.pending(&selection, &core);
    let complete = completion(&core);
    port.inner.pending(&selection, &complete);
    let prior_writes = port.inner.counter_posts;
    port.insert_on_second = Some((selection.clone(), core.clone()));
    let budget = port.budget();
    let (counter, slot) = guarded::read_with_counter(&selection, &core, &mut port, budget).unwrap();
    assert_eq!(port.reads, 2);
    assert_eq!(port.requests.len(), 4);
    let first = port.requests[0].1["documents"].as_array().unwrap();
    let second = port.requests[2].1["documents"].as_array().unwrap();
    assert_eq!((first.len(), second.len()), (4, 5));
    assert!(first.iter().all(|name| second.contains(name)));
    assert_eq!(slot.data().unwrap().slot, Slot::prepared(core.clone()));
    assert!(matches!(
        counter.snapshot().root.as_ref().unwrap().value.phase,
        kernel::Phase::ActiveFirstHolder { .. }
    ));
    assert_eq!(port.inner.counter_posts, prior_writes);
    assert_eq!(port.inner.slot_posts, 0);
}

#[test]
fn paired_observations_retain_spent_budget_and_expire_before_a_new_claim() {
    let (selection, core, mut port) = PairPort::new(true);
    let budget = port.budget();
    port.inner
        .counter
        .set_slot_fixture_time(Duration::from_secs(104));
    let (counter, slot) = guarded::read_with_counter(&selection, &core, &mut port, budget).unwrap();
    assert!(
        port.inner
            .selected_timeouts
            .iter()
            .all(|timeout| *timeout == Duration::from_secs(1))
    );
    let context = CurrentBootstrapExecution::fixture(
        &selection,
        &core.counter,
        counter.snapshot(),
        Purpose::Dispatch,
        port.sample().unwrap(),
    )
    .unwrap();
    let proposed = attempt(&core, version(1), AttemptOrdinal::first(), b"paired-expiry");
    port.inner
        .counter
        .set_slot_fixture_time(Duration::from_secs(105));
    assert!(
        guarded::claim(
            &selection, core, counter, slot, context, proposed, &mut port
        )
        .is_err()
    );
    assert_eq!((port.inner.slot_posts, port.inner.counter_posts), (0, 0));
    assert!(port.sample().is_err());
}

#[test]
fn primary_semantic_failure_survives_failed_or_expired_cleanup_without_exporting_a_pair() {
    for primary in [
        Fault::DuplicateDocument,
        Fault::CrossPartitionRewind,
        Fault::InvalidSlot,
    ] {
        let (selection, core, mut baseline) = PairPort::new(true);
        baseline.fault = primary;
        let budget = baseline.budget();
        let expected = guarded::read_with_counter(&selection, &core, &mut baseline, budget)
            .err()
            .unwrap()
            .root_cause()
            .to_string();
        for cleanup in [
            Fault::RollbackFailure,
            Fault::MalformedRollback,
            Fault::ExpireBeforeRollback,
            Fault::ExpireAfterRollback,
        ] {
            let (_, _, mut port) = PairPort::new(true);
            port.fault = primary;
            port.cleanup_fault = Some(cleanup);
            let budget = port.budget();
            let error = guarded::read_with_counter(&selection, &core, &mut port, budget)
                .err()
                .unwrap();
            assert_eq!(
                error.root_cause().to_string(),
                expected,
                "{primary:?}/{cleanup:?}"
            );
            assert_eq!(port.requests.len(), 2, "exact token cleanup attempted once");
            assert!(port.sample().is_err());
            assert_eq!((port.inner.slot_posts, port.inner.counter_posts), (0, 0));
        }
    }
}
