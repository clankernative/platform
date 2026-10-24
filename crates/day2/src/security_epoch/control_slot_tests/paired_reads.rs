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
    ExpireAfterRead,
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
        if self.fault == Fault::ExpireAfterRead {
            self.inner
                .counter
                .set_slot_fixture_time(Duration::from_secs(105));
        }
        let mut entries: Vec<Value> = crate::json::decode(&reply.body)?;
        let start = usize::from(entries[0].get("transaction").is_some());
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
            Fault::ReverseDocuments => entries[start..].reverse(),
            Fault::IncreasingInterleaved => {
                let entry = entries.remove(slot);
                entries.insert(start + 1, entry);
                for (index, entry) in entries.iter_mut().enumerate().skip(start) {
                    entry["readTime"] = json!(format!("2026-10-14T00:00:00.{:06}Z", 100 + index));
                }
            }
            Fault::DuplicateDocument => entries[start + 1] = entries[start].clone(),
            Fault::DuplicateSlot => entries[start] = entries[slot].clone(),
            Fault::MissingDocument => { entries.remove(start); }
            Fault::UnknownDocument => entries[start] = json!({"missing":"projects/foreign/databases/other/documents/x/y","readTime":"2026-10-14T00:00:00.000100Z"}),
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
                    "\"readTime\":",
                    "\"readTime\":\"2026-10-14T00:00:00.000100Z\",\"read\\u0054ime\":",
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
fn action_keeps_one_exact_read_write_transaction_until_commit_or_abort() {
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
            let (counter, mut slot) =
                guarded::read_for_action(&selection, &core, &mut port, budget).unwrap();
            assert_eq!(
                kernel::reconcile(&selection, &core.counter, counter.snapshot()).unwrap(),
                Outcome::NotApplied
            );
            assert_eq!(slot.data().is_some(), with_slot);
            if let Some(value) = slot.data() {
                assert_eq!(value.slot, Slot::prepared(core.clone()));
            }
            assert_eq!(port.requests.len(), 1);
            assert!(port.requests[0].0.ends_with(":batchGet"));
            let names = firestore::Names::new(&selection, core.counter.bootstrap(), None).unwrap();
            assert_eq!(
                port.requests[0].1,
                json!({"documents":[names.root,names.sentinel,names.create,codec::name(&selection,&core).unwrap()],"newTransaction":{"readWrite":{}}})
            );
            slot.abort(&mut port).unwrap();
            assert_eq!(port.requests.len(), 2);
            assert!(port.requests[1].0.ends_with(":rollback"));
            assert_eq!(port.requests[1].1, json!({"transaction":"YWN0aW9uLTE="}));
            slot.abort(&mut port).unwrap();
            assert_eq!(port.requests.len(), 2, "one consuming cleanup");
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
            guarded::read_for_action(&selection, &core, &mut port, budget).is_err(),
            "{fault:?}"
        );
        assert_eq!(port.requests.len(), 2, "{fault:?}");
        assert_eq!(port.requests[1].1, json!({"transaction":"YWN0aW9uLTE="}));
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
        if matches!(
            fault,
            Fault::RollbackFailure
                | Fault::MalformedRollback
                | Fault::ExpireBeforeRollback
                | Fault::ExpireAfterRollback
        ) {
            port.fault = Fault::InvalidSlot;
            port.cleanup_fault = Some(fault);
        } else {
            port.fault = fault;
        }
        let budget = port.budget();
        assert!(
            guarded::read_for_action(&selection, &core, &mut port, budget).is_err(),
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
    let (counter, mut slot) =
        guarded::read_for_action(&selection, &core, &mut port, budget).unwrap();
    assert_eq!(port.reads, 2);
    assert_eq!(port.requests.len(), 3);
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
    slot.abort(&mut port).unwrap();
    assert_eq!(port.requests.len(), 4);
}

#[test]
fn paired_observations_retain_spent_budget_and_expire_before_a_new_claim() {
    let (selection, core, mut port) = PairPort::new(true);
    let budget = port.budget();
    port.inner
        .counter
        .set_slot_fixture_time(Duration::from_secs(104));
    let (counter, slot) = guarded::read_for_action(&selection, &core, &mut port, budget).unwrap();
    assert_eq!(port.inner.selected_timeouts, [Duration::from_secs(1)]);
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
        let expected = guarded::read_for_action(&selection, &core, &mut baseline, budget)
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
            let error = guarded::read_for_action(&selection, &core, &mut port, budget)
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

#[test]
fn strong_pair_is_one_token_free_request_with_global_stream_validation() {
    for with_slot in [false, true] {
        for fault in [
            Fault::None,
            Fault::ReverseDocuments,
            Fault::IncreasingInterleaved,
        ] {
            let (selection, core, mut port) = PairPort::new(with_slot);
            port.fault = fault;
            let budget = port.budget();
            let (counter, mut slot) =
                guarded::read_with_counter(&selection, &core, &mut port, budget).unwrap();
            assert_eq!(
                kernel::reconcile(&selection, &core.counter, counter.snapshot()).unwrap(),
                Outcome::NotApplied
            );
            assert_eq!(slot.data().is_some(), with_slot);
            assert_eq!(port.requests.len(), 1);
            assert_eq!(
                port.requests[0]
                    .1
                    .as_object()
                    .unwrap()
                    .keys()
                    .collect::<Vec<_>>(),
                ["documents"]
            );
            slot.abort(&mut port).unwrap();
            assert_eq!(port.requests.len(), 1, "strong reads own no transaction");
            assert!(port.inner.transactions.is_empty());
        }
    }
    for fault in [
        Fault::DuplicateDocument,
        Fault::DuplicateSlot,
        Fault::MissingDocument,
        Fault::UnknownDocument,
        Fault::ExtraDocument,
        Fault::DuplicateToken,
        Fault::MissingReadTime,
        Fault::CrossPartitionRewind,
        Fault::InvalidReadTime,
        Fault::FoundAndMissing,
        Fault::InvalidSlot,
        Fault::ExtraSlotField,
        Fault::InvalidToken,
        Fault::DuplicateJsonField,
        Fault::OversizedReply,
        Fault::LostReadReply,
        Fault::ExpireAfterRead,
    ] {
        let (selection, core, mut port) = PairPort::new(true);
        port.fault = fault;
        let budget = port.budget();
        assert!(
            guarded::read_with_counter(&selection, &core, &mut port, budget).is_err(),
            "{fault:?}"
        );
        assert_eq!(
            port.requests.len(),
            1,
            "no token requested or cleanup/resend: {fault:?}"
        );
        assert!(port.sample().is_err());
        assert_eq!((port.inner.slot_posts, port.inner.counter_posts), (0, 0));
    }
}

#[test]
fn strong_discovery_discards_both_first_values_without_starting_a_transaction() {
    let (selection, core, mut port) = PairPort::new(false);
    port.inner.pending(&selection, &core);
    port.inner.pending(&selection, &completion(&core));
    port.insert_on_second = Some((selection.clone(), core.clone()));
    let budget = port.budget();
    let (counter, slot) = guarded::read_with_counter(&selection, &core, &mut port, budget).unwrap();
    assert_eq!(slot.data().unwrap().slot, Slot::prepared(core));
    assert!(matches!(
        counter.snapshot().root.as_ref().unwrap().value.phase,
        kernel::Phase::ActiveFirstHolder { .. }
    ));
    assert_eq!(port.requests.len(), 2);
    for (_, body) in &port.requests {
        assert_eq!(body.as_object().unwrap().len(), 1);
    }
    assert_eq!(port.requests[0].1["documents"].as_array().unwrap().len(), 4);
    assert_eq!(port.requests[1].1["documents"].as_array().unwrap().len(), 5);
    assert!(port.inner.transactions.is_empty());
}

fn action_evidence(
    port: &mut SharedPort,
    selection: &EpochStore,
    core: &LogicalCore,
    purpose: Purpose,
) -> (
    firestore::EpochObservation,
    guarded::SlotObservation,
    CurrentBootstrapExecution<'static, 'static>,
) {
    let budget = Budget::for_context(port.sample().unwrap(), Duration::from_secs(105)).unwrap();
    let (counter, slot) = guarded::read_for_action(selection, core, port, budget).unwrap();
    let context = CurrentBootstrapExecution::fixture(
        selection,
        &core.counter,
        counter.snapshot(),
        purpose,
        port.sample().unwrap(),
    )
    .unwrap();
    (counter, slot, context)
}

fn strong_after(
    port: &mut SharedPort,
    selection: &EpochStore,
    core: &LogicalCore,
) -> (firestore::EpochObservation, guarded::SlotObservation) {
    let budget = Budget::for_context(port.sample().unwrap(), Duration::from_secs(105)).unwrap();
    guarded::read_with_counter(selection, core, port, budget).unwrap()
}

#[test]
fn normal_actions_use_three_or_four_rpcs_with_known_may_before_counter_send() {
    let (selection, create) = fixture();
    for core in [&create, &completion(&create)] {
        let mut port = SharedPort::new();
        if core.stage == Stage::Complete {
            port.pending(&selection, &create);
        }
        port.requests.clear();
        let (counter, slot, context) =
            action_evidence(&mut port, &selection, core, Purpose::Dispatch);
        guarded::accept(&selection, core.clone(), counter, slot, context, &mut port)
            .unwrap()
            .send(&selection, &mut port)
            .unwrap();
        let (counter, prepared) = strong_after(&mut port, &selection, core);
        assert_eq!(port.requests.len(), 3);
        assert_eq!(
            kernel::reconcile(&selection, &core.counter, counter.snapshot()).unwrap(),
            Outcome::NotApplied
        );
        assert_eq!(prepared.data().unwrap().slot, Slot::prepared(core.clone()));
        assert_eq!(
            port.requests[0].1["newTransaction"],
            json!({"readWrite":{}})
        );
        assert!(port.requests[1].1["transaction"].is_string());
        assert_eq!(port.requests[2].1.as_object().unwrap().len(), 1);
        assert!(port.transactions.is_empty());

        port.requests.clear();
        let (counter, slot, context) =
            action_evidence(&mut port, &selection, core, Purpose::Dispatch);
        let before = slot.data().unwrap().version.clone();
        let claim = guarded::claim(
            &selection,
            core.clone(),
            counter,
            slot,
            context,
            attempt(core, before, AttemptOrdinal::first(), b"transaction"),
            &mut port,
        )
        .unwrap()
        .send(&selection, &mut port)
        .unwrap();
        assert_eq!(port.requests.len(), 2);
        let durable = codec::decode(
            &selection,
            core,
            &port.slots.read(&codec::name(&selection, core).unwrap()),
        )
        .unwrap();
        assert!(matches!(
            durable.slot.state,
            SlotState::MayHaveBeenSent { .. }
        ));
        assert!(port.transactions.is_empty());
        claim.send(&selection, &mut port).unwrap();
        let (counter, may) = strong_after(&mut port, &selection, core);
        assert_eq!(port.requests.len(), 4);
        assert_eq!(port.requests[1].1["writes"].as_array().unwrap().len(), 1);
        assert!(port.requests[1].1["transaction"].is_string());
        assert_eq!(port.requests[2].1["writes"].as_array().unwrap().len(), 3);
        assert!(port.requests[2].1.get("transaction").is_none());
        assert_eq!(port.requests[3].1.as_object().unwrap().len(), 1);
        assert_eq!(
            kernel::reconcile(&selection, &core.counter, counter.snapshot()).unwrap(),
            Outcome::Applied(Box::new(core.counter.receipt().unwrap()))
        );

        port.requests.clear();
        let (counter, slot, context) =
            action_evidence(&mut port, &selection, core, Purpose::Reconcile);
        let SlotState::MayHaveBeenSent { attempt: lineage } = &may.data().unwrap().slot.state
        else {
            unreachable!()
        };
        let settlement = SettlementCore {
            logical: core.digest().unwrap(),
            expected: slot.data().unwrap().version.clone(),
            control_attempt: lineage.id.clone(),
            receipt: core.counter.receipt().unwrap().digest().unwrap(),
        };
        guarded::settle(
            &selection,
            core.clone(),
            counter,
            slot,
            context,
            settlement,
            &mut port,
        )
        .unwrap()
        .send(&selection, &mut port)
        .unwrap();
        let (_, settled) = strong_after(&mut port, &selection, core);
        assert_eq!(port.requests.len(), 3);
        assert!(matches!(
            settled.data().unwrap().slot.state,
            SlotState::Observed { .. }
        ));
        assert!(port.transactions.is_empty());
    }
}

#[test]
fn action_transaction_conflict_never_retries_or_overwrites_the_winner() {
    for conflict in ["slot", "counter"] {
        let (selection, core) = fixture();
        let mut port = SharedPort::new();
        let (counter, slot, context) =
            action_evidence(&mut port, &selection, &core, Purpose::Dispatch);
        let first =
            guarded::accept(&selection, core.clone(), counter, slot, context, &mut port).unwrap();
        if conflict == "slot" {
            let (counter, slot, context) =
                action_evidence(&mut port, &selection, &core, Purpose::Dispatch);
            guarded::accept(&selection, core.clone(), counter, slot, context, &mut port)
                .unwrap()
                .send(&selection, &mut port)
                .unwrap();
        } else {
            port.pending(&selection, &core);
        }
        let sends = port.slot_posts;
        let counter_sends = port.counter_posts;
        assert!(first.send(&selection, &mut port).is_err(), "{conflict}");
        assert_eq!(port.slot_posts, sends + 1, "one attempted commit, no retry");
        assert_eq!(port.counter_posts, counter_sends);
        assert_eq!(port.slots.rows(), i64::from(conflict == "slot"));
        assert!(port.transactions.is_empty());
        assert!(port.sample().is_err());
    }
}

#[test]
fn strong_observation_cannot_mutate_and_cleanup_never_bypasses_refused_owner() {
    for source in ["strong", "foreign", "lost-owner"] {
        let (selection, core) = fixture();
        let mut port = SharedPort::new();
        let budget = Budget::for_context(port.sample().unwrap(), Duration::from_secs(105)).unwrap();
        let (counter, slot) = if source == "strong" {
            guarded::read_with_counter(&selection, &core, &mut port, budget).unwrap()
        } else {
            guarded::read_for_action(&selection, &core, &mut port, budget).unwrap()
        };
        let mut context = CurrentBootstrapExecution::fixture(
            &selection,
            &core.counter,
            counter.snapshot(),
            Purpose::Dispatch,
            port.sample().unwrap(),
        )
        .unwrap();
        let mut selected = selection.clone();
        if source == "foreign" {
            selected.key_set = Digest::new(b"different-selected-key-set");
        }
        if source == "lost-owner" {
            context.lose_original_creator_fixture();
        }
        assert!(
            guarded::accept(&selected, core.clone(), counter, slot, context, &mut port).is_err()
        );
        assert_eq!((port.slot_posts, port.counter_posts), (0, 0));
        assert_eq!(port.transactions.len(), usize::from(source == "lost-owner"));
        // A pure proposal error can close its token before refusal. A lost
        // actual owner cannot send rollback; its resource expires at provider.
        assert_eq!(port.requests.len(), if source == "foreign" { 2 } else { 1 });
        if source == "foreign" {
            assert_eq!(port.requests[1].1, json!({"transaction":"YWN0aW9uLTE="}));
        }
        assert!(port.sample().is_err());
    }
}

#[test]
fn provider_transaction_deadline_refuses_before_slot_commit_without_native_budget_renewal() {
    let (selection, core) = fixture();
    let mut port = SharedPort::new();
    let (counter, slot, context) = action_evidence(&mut port, &selection, &core, Purpose::Dispatch);
    let mutation =
        guarded::accept(&selection, core.clone(), counter, slot, context, &mut port).unwrap();
    // The provider may abort under its independent lock deadline even while
    // the original native clock is still valid. Model that response directly;
    // no native bound, token or body is renewed and no callback is retried.
    port.claim_reply = ClaimReply::ProviderDeadline;
    assert!(mutation.send(&selection, &mut port).is_err());
    assert_eq!(port.requests.len(), 2);
    assert_eq!(
        (port.slots.rows(), port.slot_posts, port.counter_posts),
        (0, 1, 0)
    );
    assert!(port.transactions.is_empty());
    assert!(port.sample().is_err());
}

#[test]
fn invalid_or_expired_strong_post_read_keeps_durable_may_without_completion_or_resend() {
    for fault in [
        Fault::InvalidSlot,
        Fault::ExpireAfterRead,
        Fault::LostReadReply,
    ] {
        let (selection, core, mut port) = PairPort::new(false);
        let (counter, slot, context) =
            action_evidence(&mut port.inner, &selection, &core, Purpose::Dispatch);
        guarded::accept(
            &selection,
            core.clone(),
            counter,
            slot,
            context,
            &mut port.inner,
        )
        .unwrap()
        .send(&selection, &mut port.inner)
        .unwrap();
        let (counter, slot, context) =
            action_evidence(&mut port.inner, &selection, &core, Purpose::Dispatch);
        let expected = slot.data().unwrap().version.clone();
        guarded::claim(
            &selection,
            core.clone(),
            counter,
            slot,
            context,
            attempt(&core, expected, AttemptOrdinal::first(), b"post-read"),
            &mut port.inner,
        )
        .unwrap()
        .send(&selection, &mut port.inner)
        .unwrap()
        .send(&selection, &mut port.inner)
        .unwrap();
        let name = codec::name(&selection, &core).unwrap();
        let original = port.inner.slots.read(&name);
        assert!(matches!(
            codec::decode(&selection, &core, &original)
                .unwrap()
                .slot
                .state,
            SlotState::MayHaveBeenSent { .. }
        ));
        port.fault = fault;
        let budget = port.budget();
        assert!(
            guarded::read_with_counter(&selection, &core, &mut port, budget).is_err(),
            "{fault:?}"
        );
        assert_eq!(port.inner.slots.read(&name), original);
        assert_eq!((port.inner.slot_posts, port.inner.counter_posts), (2, 1));
        assert_eq!(port.requests.len(), 1, "no cleanup transaction or resend");
        port.fault = Fault::None;
        port.inner
            .counter
            .set_slot_fixture_time(Duration::from_secs(100));
        assert!(
            port.sample().is_err(),
            "restoration never revives {fault:?}"
        );
    }
}
