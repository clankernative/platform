//! Cryptographic and parser DATA controls only. No native peer, stage,
//! original, credential, passkey or accepted restore owner is constructed.
use super::*;
use crate::security_epoch::native_enrollment::protocol::KeyOwner;

fn request(request: ProtectedRestoreRequest) -> Data {
    Data::request(
        Digest::new(b"connection"),
        Digest::new(b"sender"),
        u64::MAX,
        request,
    )
    .unwrap()
}

fn reply(reply: ProtectedRestoreReply) -> Data {
    Data::reply(
        Digest::new(b"connection"),
        Digest::new(b"sender"),
        u64::MAX,
        reply,
    )
    .unwrap()
}

fn signed(data: Data, key: &KeyOwner) -> Vec<u8> {
    let signature = key
        .sign(SIGNING_DOMAIN, &data.commitment().unwrap())
        .unwrap();
    UnverifiedPacket::encode(data, signature).unwrap()
}

fn fixture() -> Data {
    request(ProtectedRestoreRequest::Abandon {
        id: Digest::new(b"command"),
    })
}

#[test]
fn every_closed_turn_roundtrips_with_maximal_payload_and_normal_json_budget() {
    let key = KeyOwner::generate().unwrap();
    let mut maximum = 0;
    for data in [
        request(ProtectedRestoreRequest::BeginApproval {
            input: vec![255; MAX_INPUT_BYTES],
        }),
        request(ProtectedRestoreRequest::Approve {
            id: Digest::new(b"command"),
            assertion: vec![255; MAX_ASSERTION_BYTES],
        }),
        request(ProtectedRestoreRequest::BeginExecution {
            id: Digest::new(b"command"),
        }),
        request(ProtectedRestoreRequest::Authenticate {
            id: Digest::new(b"command"),
            assertion: vec![255; MAX_ASSERTION_BYTES],
        }),
        fixture(),
        reply(ProtectedRestoreReply::ApprovalPrompt {
            id: Digest::new(b"command"),
            prompt: vec![255; MAX_INPUT_BYTES],
        }),
        reply(ProtectedRestoreReply::ApprovalRecorded {
            commitment: Digest::new(b"record"),
        }),
        reply(ProtectedRestoreReply::ExecutionPrompt {
            id: Digest::new(b"command"),
            prompt: vec![255; MAX_INPUT_BYTES],
        }),
        reply(ProtectedRestoreReply::Abandoned),
        reply(ProtectedRestoreReply::Refused),
    ] {
        let original = serde_json::to_value(&data).unwrap();
        let direction = data.body.direction();
        let bytes = signed(data, &key);
        maximum = maximum.max(bytes.len());
        let decoded = UnverifiedPacket::decode(&bytes)
            .unwrap()
            .verify_data(&key.public())
            .unwrap();
        decoded
            .require_binding(
                &Digest::new(b"connection"),
                &Digest::new(b"sender"),
                u64::MAX,
                direction,
            )
            .unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), original);
        match direction {
            Direction::Request => {
                decoded.into_request().unwrap().validate_data().unwrap();
            }
            Direction::Reply => {
                decoded.into_reply().unwrap().validate_data().unwrap();
            }
        }
    }
    // This is the encoded DATA frame including format, all digests, the
    // maximal sequence and the complete real signature. No extra native
    // admission object may be appended without revisiting this fixed profile.
    assert!(maximum > 43_690 && maximum <= MAX_PACKET_BYTES);
    assert_eq!(super::super::super::protocol::MAX_PACKET, 8192);
}

#[test]
fn packet_signature_binds_every_field_and_cannot_cross_the_serving_domain() {
    let key = KeyOwner::generate().unwrap();
    let bytes = signed(fixture(), &key);
    assert!(
        UnverifiedPacket::decode(&bytes)
            .unwrap()
            .verify_data(&KeyOwner::generate().unwrap().public())
            .is_err()
    );
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for (field, value) in [
        (
            "connection",
            serde_json::json!(Digest::new(b"foreign connection")),
        ),
        (
            "sender",
            serde_json::json!(Digest::new(b"foreign enrollment")),
        ),
        ("sequence", serde_json::json!(0)),
        (
            "body",
            serde_json::json!({"kind":"abandon", "id":Digest::new(b"foreign command")}),
        ),
    ] {
        let mut changed = original.clone();
        changed["data"][field] = value;
        let encoded = serde_json::to_vec(&changed).unwrap();
        assert!(
            UnverifiedPacket::decode(&encoded)
                .unwrap()
                .verify_data(&key.public())
                .is_err()
        );
    }
    let data = fixture();
    let wrong_domain = key
        .sign(
            "shell-controller-serving-message",
            &data.commitment().unwrap(),
        )
        .unwrap();
    let bytes = UnverifiedPacket::encode(data, wrong_domain).unwrap();
    assert!(
        UnverifiedPacket::decode(&bytes)
            .unwrap()
            .verify_data(&key.public())
            .is_err()
    );
}

#[test]
fn binding_rejects_wrong_connection_enrollment_sequence_and_direction_after_valid_signature() {
    let key = KeyOwner::generate().unwrap();
    let bytes = signed(fixture(), &key);
    for cut in 0..4 {
        let decoded = UnverifiedPacket::decode(&bytes)
            .unwrap()
            .verify_data(&key.public())
            .unwrap();
        assert!(
            decoded
                .require_binding(
                    &Digest::new(if cut == 0 { b"foreign" } else { b"connection" }),
                    &Digest::new(if cut == 1 { b"foreign" } else { b"sender" }),
                    if cut == 2 { 0 } else { u64::MAX },
                    if cut == 3 {
                        Direction::Reply
                    } else {
                        Direction::Request
                    },
                )
                .is_err()
        );
    }
    assert!(fixture().into_reply().is_err());
    assert!(
        reply(ProtectedRestoreReply::Refused)
            .into_request()
            .is_err()
    );
}

#[test]
fn strict_decoder_rejects_duplicate_unknown_truncated_oversize_and_wrong_domain_packets() {
    let key = KeyOwner::generate().unwrap();
    let bytes = signed(fixture(), &key);
    for length in 0..bytes.len() {
        assert!(UnverifiedPacket::decode(&bytes[..length]).is_err());
    }
    assert!(UnverifiedPacket::decode(&vec![b' '; MAX_PACKET_BYTES + 1]).is_err());
    let text = String::from_utf8(bytes.clone()).unwrap();
    let duplicate = text.replace("\"sequence\":", "\"sequence\":0,\"sequence\":");
    assert!(UnverifiedPacket::decode(duplicate.as_bytes()).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["data"]["privilege"] = serde_json::json!(true);
    assert!(UnverifiedPacket::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["data"]["body"]["permission"] = serde_json::json!(true);
    assert!(UnverifiedPacket::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let mut domain: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    domain["data"]["format"] = serde_json::json!("shell-controller-serving-message");
    assert!(UnverifiedPacket::decode(&serde_json::to_vec(&domain).unwrap()).is_err());
    let mut positive: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    positive["data"]["body"] = serde_json::json!({"kind":"restore_completed"});
    assert!(UnverifiedPacket::decode(&serde_json::to_vec(&positive).unwrap()).is_err());
}

#[test]
fn payload_and_signature_encodings_are_canonical_and_bounded_before_native_admission() {
    for size in [0, MAX_INPUT_BYTES + 1] {
        assert!(
            Data::request(
                Digest::new(b"c"),
                Digest::new(b"s"),
                0,
                ProtectedRestoreRequest::BeginApproval {
                    input: vec![0; size]
                }
            )
            .is_err()
        );
    }
    for size in [0, MAX_ASSERTION_BYTES + 1] {
        assert!(
            Data::request(
                Digest::new(b"c"),
                Digest::new(b"s"),
                0,
                ProtectedRestoreRequest::Authenticate {
                    id: Digest::new(b"i"),
                    assertion: vec![0; size]
                }
            )
            .is_err()
        );
    }
    for encoded in ["", "AA==", "A+", "A/", "a", "AB"] {
        assert!(decode_bytes(encoded, MAX_INPUT_BYTES).is_err());
    }
    for signature in [
        "".to_owned(),
        "A".repeat(85),
        "A".repeat(87),
        "!".repeat(86),
    ] {
        assert!(UnverifiedPacket::encode(fixture(), signature).is_err());
    }
}

#[test]
fn both_fieldless_replies_reject_extra_signed_fields_and_all_envelope_array_shapes() {
    let key = KeyOwner::generate().unwrap();
    for response in [
        ProtectedRestoreReply::Abandoned,
        ProtectedRestoreReply::Refused,
    ] {
        let bytes = signed(reply(response), &key);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let body = value["data"]["body"].clone();
        assert_eq!(body.as_object().unwrap().len(), 1);
        UnverifiedPacket::decode(&bytes)
            .unwrap()
            .verify_data(&key.public())
            .unwrap();
        let mut extra = value.clone();
        extra["data"]["body"]["permission"] = serde_json::json!(true);
        assert!(UnverifiedPacket::from_value(extra.clone()).is_err());
        assert!(UnverifiedPacket::decode(&serde_json::to_vec(&extra).unwrap()).is_err());

        let outer_array = serde_json::json!([value["data"], value["signature"]]);
        let mut data_array = value.clone();
        data_array["data"] = serde_json::json!([
            value["data"]["format"],
            value["data"]["connection"],
            value["data"]["sender"],
            value["data"]["sequence"],
            value["data"]["body"],
        ]);
        let mut body_array = value.clone();
        body_array["data"]["body"] = serde_json::json!([body["kind"]]);
        // A derived unit enum may otherwise admit the externally tagged map
        // form of the same version before normalizing it back to a string.
        let mut format_map = value.clone();
        format_map["data"]["format"] =
            serde_json::json!({"day2_protected_restore_packet_v1": null});
        for malformed in [outer_array, data_array, body_array, format_map] {
            assert!(UnverifiedPacket::from_value(malformed.clone()).is_err());
            assert!(UnverifiedPacket::decode(&serde_json::to_vec(&malformed).unwrap()).is_err());
        }
    }
}
