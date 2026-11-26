//! Synthetic signed DATA only. No native owner, process, page, source, clock,
//! protected Job, receiving context or positive upload factory is constructed.
use super::*;
use crate::security_epoch::native_enrollment::protocol::{IssuerData, KeyOwner, ProcessData};
use serde_json::{Value, json};

struct Fixture {
    root: KeyOwner,
    issuer: KeyOwner,
    controller: KeyOwner,
    policy: EnrollmentPolicy,
    certificate: IssuerCertificate,
    pending: SignedPendingData,
    comparison: SignedRecipientData,
}

fn certificate(root: &KeyOwner, issuer: &KeyOwner, policy: &EnrollmentPolicy, salt: u8) -> Result<IssuerCertificate> {
    let process = |code| ProcessData {
        process: 71 + u32::from(salt),
        start_ticks: 123 + u64::from(salt),
        code,
        boot: "synthetic-boot".into(),
        namespaces: ["time", "time_for_children", "pid", "mnt", "user", "cgroup"]
            .into_iter().map(|name| (name.to_owned(), (7, 9))).collect(),
    };
    let data = IssuerData {
        policy: policy.digest()?,
        root_version: policy.root.version.clone(),
        nonce: Digest::new(&[salt]),
        public_key: issuer.public(),
        process: process(policy.issuer_code.clone()),
        provisioner: process(policy.provisioner_code.clone()),
    };
    Ok(IssuerCertificate { signature: root.sign("issuer-birth", &data)?, data })
}

fn fixture() -> Result<Fixture> {
    let root = KeyOwner::generate()?;
    let issuer = KeyOwner::generate()?;
    let controller = KeyOwner::generate()?;
    let mut policy = crate::security_epoch::native_enrollment::tests::policy(&root);
    for role in [&mut policy.bootstrap.app, &mut policy.bootstrap.controller, &mut policy.bootstrap.shell] {
        role.namespace.uid = "00000000-0000-0000-0000-000000000002".into();
    }
    let (mut selected, _, _) = crate::security_epoch::scheduled_backup::requester::comparison_fixture_data()?;
    selected.scope = policy.bootstrap.scope.clone();
    selected.cluster = Digest::of(&policy.bootstrap.cluster)?;
    selected.node_name = policy.runtime.node_name.clone();
    selected.node = Digest::of(&("day2-scheduled-backup-node-v1", &policy.runtime.node_name, &policy.runtime.node_uid))?;
    selected.namespace = policy.bootstrap.app.namespace.clone();
    selected.image = policy.bootstrap.app.container.image.clone();
    policy.scheduled_backup = Some(selected);
    policy.validate()?;
    let certificate = certificate(&root, &issuer, &policy, 1)?;
    let data = PendingData {
        issuer: certificate.digest()?,
        policy: policy.digest()?,
        controller_key: controller.public(),
        // Opaque comparison bytes only; no real ABI page is fabricated.
        envelope: EnvelopeData::from_bytes_data([17; day2_completion_page::FRAME_BYTES]),
    };
    let pending = SignedPendingData { signature: controller.sign(PENDING_PURPOSE, &data)?, data };
    let data = RecipientData {
        issuer: certificate.digest()?,
        policy: policy.digest()?,
        pending: pending.digest_data()?,
        courier_request: Digest::new(b"synthetic actual request bytes"),
        receiver_challenge: Digest::new(b"synthetic receiver challenge"),
    };
    let comparison = SignedRecipientData { signature: issuer.sign(COMPARISON_PURPOSE, &data)?, data };
    Ok(Fixture {root, issuer, controller, policy, certificate, pending, comparison})
}

impl Fixture {
    fn check(&self, comparison: &SignedRecipientData, pending: &SignedPendingData) -> Result<()> {
        comparison.verify_data(&self.policy, &self.certificate, pending, (
            &self.pending.data,
            &self.comparison.data.courier_request,
            &self.comparison.data.receiver_challenge,
        ))
    }

    fn ack(&self) -> Result<ReceiverAckData> {
        Ok(ReceiverAckData {
            pending: self.pending.digest_data()?,
            comparison: self.comparison.digest_data()?,
            courier_request: self.comparison.data.courier_request.clone(),
            receiver_challenge: self.comparison.data.receiver_challenge.clone(),
        })
    }
}

#[test]
fn pending_comparison_binds_every_envelope_byte_and_exact_creator_key_without_native_authority() -> Result<()> {
    let f = fixture()?;
    f.check(&f.comparison, &f.pending)?;
    for index in 0..day2_completion_page::FRAME_BYTES {
        let mut bytes = [17; day2_completion_page::FRAME_BYTES];
        bytes[index] ^= 1;
        let mut changed = f.pending.clone();
        changed.data.envelope = EnvelopeData::from_bytes_data(bytes);
        changed.signature = f.controller.sign(PENDING_PURPOSE, &changed.data)?;
        assert!(changed.verify_data(&f.policy, &f.certificate, &f.pending.data.controller_key, &f.pending.data.envelope).is_err());
        // Even a freshly signed comparison of the wrong pending statement may
        // not replace the actual context's expected pending object.
        let mut comparison = f.comparison.clone();
        comparison.data.pending = changed.digest_data()?;
        comparison.signature = f.issuer.sign(COMPARISON_PURPOSE, &comparison.data)?;
        assert!(f.check(&comparison, &changed).is_err());
    }
    let foreign = KeyOwner::generate()?;
    let mut changed = f.pending.clone();
    changed.data.controller_key = foreign.public();
    changed.signature = foreign.sign(PENDING_PURPOSE, &changed.data)?;
    assert!(f.check(&f.comparison, &changed).is_err());
    let mut changed = f.pending.clone();
    changed.signature = foreign.sign(PENDING_PURPOSE, &changed.data)?;
    assert!(f.check(&f.comparison, &changed).is_err());
    for field in ["issuer", "policy"] {
        let mut value = serde_json::to_value(&f.pending.data)?;
        value[field] = serde_json::to_value(Digest::new(b"different pending field"))?;
        let data: PendingData = serde_json::from_value(value)?;
        let changed = SignedPendingData { signature: f.controller.sign(PENDING_PURPOSE, &data)?, data };
        assert!(changed.verify_data(&f.policy, &f.certificate, &f.pending.data.controller_key, &f.pending.data.envelope).is_err());
    }
    Ok(())
}

#[test]
fn actual_signed_data_refuses_same_root_generation_mixing_and_every_recipient_join() -> Result<()> {
    let f = fixture()?;
    for field in ["issuer", "policy", "pending", "courier_request", "receiver_challenge"] {
        let mut value = serde_json::to_value(&f.comparison.data)?;
        value[field] = serde_json::to_value(Digest::new(b"different comparison field"))?;
        let data: RecipientData = serde_json::from_value(value)?;
        let changed = SignedRecipientData { signature: f.issuer.sign(COMPARISON_PURPOSE, &data)?, data };
        assert!(f.check(&changed, &f.pending).is_err(), "{field}");
    }
    let other = KeyOwner::generate()?;
    let next = certificate(&f.root, &other, &f.policy, 2)?;
    next.verify(&f.policy)?;
    let mut pending = f.pending.clone();
    pending.data.issuer = next.digest()?;
    pending.signature = f.controller.sign(PENDING_PURPOSE, &pending.data)?;
    let mut comparison = f.comparison.clone();
    comparison.data.issuer = next.digest()?;
    comparison.data.pending = pending.digest_data()?;
    comparison.signature = other.sign(COMPARISON_PURPOSE, &comparison.data)?;
    assert!(f.check(&comparison, &pending).is_err());
    // Replacing the held certificate argument still cannot silently replace
    // this same actual context's earlier pending cohort or bytes.
    assert!(comparison.verify_data(&f.policy, &next, &pending, (
        &f.pending.data, &f.comparison.data.courier_request, &f.comparison.data.receiver_challenge,
    )).is_err());
    let mut wrong_signature = f.comparison.clone();
    wrong_signature.signature = f.controller.sign(COMPARISON_PURPOSE, &wrong_signature.data)?;
    assert!(f.check(&wrong_signature, &f.pending).is_err());
    let mut disabled = f.policy.clone();
    disabled.scheduled_backup = None;
    // Re-sign the ENTIRE otherwise valid chain for the disabled policy. The
    // test must fail on the actual disabled-selection gate, not accidentally
    // on an earlier stale certificate/policy digest comparison.
    let disabled_certificate = certificate(&f.root, &f.issuer, &disabled, 3)?;
    disabled_certificate.verify(&disabled)?;
    let mut pending = f.pending.clone();
    pending.data.policy = disabled.digest()?;
    pending.data.issuer = disabled_certificate.digest()?;
    pending.signature = f.controller.sign(PENDING_PURPOSE, &pending.data)?;
    assert!(pending.verify_data(&disabled, &disabled_certificate, &f.pending.data.controller_key, &f.pending.data.envelope).is_err());
    Ok(())
}

#[test]
fn receiver_ack_joins_the_exact_prior_comparison_and_replay_never_selects_a_fresh_context() -> Result<()> {
    let f = fixture()?;
    let ack = f.ack()?;
    for _ in 0..2 {
        let bytes = PacketData::Ack {ack: ack.clone()}.encode_data()?;
        let PacketData::Ack { ack: decoded } = decode_data(&bytes)? else {panic!("wrong fixed kind")};
        assert!(decoded == ack);
        decoded.require_exact_data(&f.pending, &f.comparison)?;
        // DATA is replayable. A fresh context still has a different challenge
        // or request and may not adopt that earlier comparison.
        for replacement in [true, false] {
            let changed = Digest::new(b"another receiver context");
            let (request, challenge) = if replacement {(&changed, &f.comparison.data.receiver_challenge)}
                else {(&f.comparison.data.courier_request, &changed)};
            assert!(f.comparison.verify_data(&f.policy, &f.certificate, &f.pending, (&f.pending.data, request, challenge)).is_err());
        }
    }
    for field in ["pending", "comparison", "courier_request", "receiver_challenge"] {
        let mut value = serde_json::to_value(&ack)?;
        value[field] = serde_json::to_value(Digest::new(b"another ack field"))?;
        let changed: ReceiverAckData = serde_json::from_value(value)?;
        assert!(changed.require_exact_data(&f.pending, &f.comparison).is_err());
    }
    let mut changed = f.comparison.clone();
    changed.signature = "A".repeat(86);
    assert!(ack.require_exact_data(&f.pending, &changed).is_err());
    Ok(())
}

#[test]
fn bounded_fixed_codec_rejects_duplicate_unknown_sequence_and_noncanonical_envelope_data() -> Result<()> {
    let f = fixture()?;
    let records = [PacketData::Pending {pending:f.pending.clone()}, PacketData::Comparison {comparison:f.comparison.clone()}, PacketData::Ack {ack:f.ack()?}];
    for (packet, exact_bytes) in records.into_iter().zip([874, 583, 380]) {
        let bytes = packet.encode_data()?;
        assert!(decode_data(&bytes)? == packet);
        assert_eq!(bytes.len(), exact_bytes);
        assert!(bytes.len() <= MAX_DATA_BYTES);
        let original: Value = serde_json::from_slice(&bytes)?;
        for extra in ["private_unrecognized_field", "another_field"] {
            let mut changed = original.clone();
            changed[extra] = json!("SYNTHETIC_FOREIGN_VALUE_NEVER_FORMAT");
            let error = decode_data(&serde_json::to_vec(&changed)?).err().unwrap();
            assert!(!error.to_string().contains("SYNTHETIC_FOREIGN_VALUE"));
        }
        let text = String::from_utf8(bytes.clone())?;
        let duplicate = text.replacen("{", "{\"kind\":\"ack\",", 1);
        assert!(decode_data(duplicate.as_bytes()).is_err());
        let mut changed = original.clone();
        changed["kind"] = json!("unsupported");
        assert!(decode_data(&serde_json::to_vec(&changed)?).is_err());
        for pointer in match packet {
            PacketData::Pending {..} => &["/pending", "/pending/data"][..],
            PacketData::Comparison {..} => &["/comparison", "/comparison/data"][..],
            PacketData::Ack {..} => &["/ack"][..],
        } {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = json!([]);
            assert!(decode_data(&serde_json::to_vec(&changed)?).is_err());
            let mut changed = original.clone();
            changed.pointer_mut(pointer).unwrap()["extra"] = json!(0);
            assert!(decode_data(&serde_json::to_vec(&changed)?).is_err());
        }
    }
    let packet = PacketData::Pending { pending:f.pending.clone() }.encode_data()?;
    let text = String::from_utf8(packet)?;
    assert_eq!(text.matches("\"policy\":").count(), 1);
    let duplicate = text.replacen("\"policy\":", "\"policy\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\",\"policy\":", 1);
    assert!(decode_data(duplicate.as_bytes()).is_err());
    let mut changed: Value = serde_json::from_str(&text)?;
    let mut trailing_bits = f.pending.data.envelope.0.clone();
    trailing_bits.pop();
    trailing_bits.push('B');
    for invalid in ["".to_owned(), "A".repeat(490), "A".repeat(492), format!("{}=",f.pending.data.envelope.0), trailing_bits, "+".repeat(491)] {
        changed["pending"]["data"]["envelope"] = json!(invalid);
        assert!(decode_data(&serde_json::to_vec(&changed)?).is_err());
    }
    assert!(decode_data(&[]).is_err());
    assert!(decode_data(&vec![b' '; MAX_DATA_BYTES+1]).is_err());
    assert!(decode_data(b"[]").is_err());
    assert!(decode_data(b"{\"kind\":\"ack\"}").is_err());
    Ok(())
}
