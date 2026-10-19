//! A loopback KMS peer exercises the real bounded HTTP client. Test keys and
//! fixture acquisitions supply no production enrollment or kernel authority.
use super::*;
use day2_capabilities::Digest;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

fn acquisition(limit: Duration) -> NativeAcquisition {
    NativeAcquisition::fixture(
        Digest::new(b"kms-test-clock"),
        std::process::id(),
        Duration::from_secs(10),
        limit,
    )
}

fn fixture() -> (KmsRootSelection, Vec<u8>, Vec<Value>) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let selection = KmsRootSelection {
        version: "projects/test-project/locations/us-central1/keyRings/enrollment/cryptoKeys/root/cryptoKeyVersions/1".into(),
        public_key: URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
    };
    let process = protocol::ProcessData {
        process: 71,
        start_ticks: 123,
        code: Digest::new(b"fixture-native-code"),
        boot: "fixture-boot".into(),
        namespaces: ["time", "time_for_children", "pid", "mnt", "user", "cgroup"]
            .into_iter()
            .map(|name| (name.to_owned(), (7, 9)))
            .collect(),
    };
    let frame = protocol::issuer_birth_frame(&IssuerData {
        policy: Digest::new(b"fixture-policy"),
        root_version: selection.version.clone(),
        nonce: Digest::new(b"original-birth"),
        public_key: URL_SAFE_NO_PAD.encode([9; 32]),
        process: process.clone(),
        provisioner: process,
    })
    .unwrap();
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(key.public_key().as_ref());
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        STANDARD.encode(der)
    );
    let sig = key.sign(&frame);
    let responses = vec![
        json!({"name":selection.version,"algorithm":ALGORITHM,"protectionLevel":PROTECTION,"state":"ENABLED"}),
        json!({"name":selection.version,"algorithm":ALGORITHM,"protectionLevel":PROTECTION,"pem":pem,"pemCrc32c":crc32c::crc32c(pem.as_bytes()).to_string()}),
        json!({"name":selection.version,"protectionLevel":PROTECTION,"signature":STANDARD.encode(sig.as_ref()),
            "signatureCrc32c":crc32c::crc32c(sig.as_ref()).to_string(),"verifiedDataCrc32c":true}),
    ];
    (selection, frame, responses)
}

fn peer(
    replies: Vec<(u16, Vec<u8>)>,
    delay: Duration,
) -> (RootKms, thread::JoinHandle<Vec<(String, Value)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut calls = Vec::new();
        for (status, body) in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
                assert!(head.len() <= 8192);
            }
            let head = String::from_utf8(head).unwrap();
            assert!(
                head.to_ascii_lowercase()
                    .contains("authorization: bearer test-token\r\n")
            );
            let length: usize = head
                .lines()
                .find_map(|s| {
                    s.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .map_or(0, |s| s.trim().parse().unwrap());
            assert!(length <= LIMIT);
            let mut request = vec![0; length];
            stream.read_exact(&mut request).unwrap();
            calls.push((
                head.lines().next().unwrap().to_owned(),
                if request.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&request).unwrap()
                },
            ));
            thread::sleep(delay);
            let _ = write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(&body);
        }
        calls
    });
    (
        RootKms {
            client: client(false).unwrap(),
            origin,
        },
        handle,
    )
}

fn responses(values: Vec<Value>) -> Vec<(u16, Vec<u8>)> {
    values
        .into_iter()
        .map(|v| (200, serde_json::to_vec(&v).unwrap()))
        .collect()
}

fn authorization() -> HeaderValue {
    let mut value = HeaderValue::from_static("Bearer test-token");
    value.set_sensitive(true);
    value
}

#[test]
fn real_http_signs_only_raw_birth_frame_and_verifies_selected_key_and_checksums() {
    let (selected, frame, replies) = fixture();
    let (kms, server) = peer(responses(replies), Duration::ZERO);
    let mut acquisition = acquisition(Duration::from_secs(1));
    let signature = kms
        .sign_frame(&selected, &frame, authorization(), &mut acquisition)
        .unwrap();
    let calls = server.join().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].0, format!("GET /v1/{} HTTP/1.1", selected.version));
    assert_eq!(
        calls[1].0,
        format!("GET /v1/{}/publicKey HTTP/1.1", selected.version)
    );
    assert_eq!(
        calls[2].0,
        format!("POST /v1/{}:asymmetricSign HTTP/1.1", selected.version)
    );
    assert_eq!(
        calls[2].1,
        json!({"data":STANDARD.encode(&frame),"dataCrc32c":crc32c::crc32c(&frame).to_string()})
    );
    let sig = URL_SAFE_NO_PAD.decode(signature).unwrap();
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        decode_key(&selected.public_key).unwrap(),
    )
    .verify(&frame, &sig)
    .unwrap();
    assert!(acquisition.remaining().is_ok());
}

#[test]
fn wrong_resource_algorithm_protection_state_public_key_and_signature_permanently_refuse() {
    let (selected, frame, good) = fixture();
    for (stage, field, replacement) in [
        (0, "name", json!(selected.version.replace("/1", "/2"))),
        (0, "algorithm", json!("EC_SIGN_P256_SHA256")),
        (0, "protectionLevel", json!("HSM")),
        (0, "state", json!("DISABLED")),
        (1, "name", json!("other-key")),
        (1, "algorithm", json!("EC_SIGN_P256_SHA256")),
        (1, "protectionLevel", json!("HSM")),
        (1, "pemCrc32c", json!("0")),
        (2, "name", json!("other-key")),
        (2, "protectionLevel", json!("HSM")),
        (2, "verifiedDataCrc32c", json!(false)),
        (2, "verifiedDigestCrc32c", json!(true)),
        (2, "signatureCrc32c", json!("0")),
        (2, "signature", json!(STANDARD.encode([0u8; 64]))),
    ] {
        let mut replies = good[..=stage].to_vec();
        replies[stage][field] = replacement;
        let (kms, server) = peer(responses(replies), Duration::ZERO);
        let mut acquisition = acquisition(Duration::from_secs(1));
        assert!(
            kms.sign_frame(&selected, &frame, authorization(), &mut acquisition)
                .is_err(),
            "{stage}/{field}"
        );
        assert!(acquisition.remaining().is_err());
        assert_eq!(server.join().unwrap().len(), stage + 1);
    }
    // A different authentic public key and a matching CRC cannot replace the
    // pinned key even if the provider names/algorithm/protection all match.
    let other = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    let mut changed = selected.clone();
    changed.public_key = URL_SAFE_NO_PAD.encode(other.public_key().as_ref());
    let (kms, server) = peer(responses(good[..2].to_vec()), Duration::ZERO);
    let mut acquisition = acquisition(Duration::from_secs(1));
    assert!(
        kms.sign_frame(&changed, &frame, authorization(), &mut acquisition)
            .is_err()
    );
    assert!(acquisition.remaining().is_err());
    assert_eq!(server.join().unwrap().len(), 2);
}

#[test]
fn network_failures_redirects_oversize_and_duplicate_json_never_retry_or_fall_back() {
    let (selected, frame, _) = fixture();
    for (status, body) in [
        (302, b"redirect".to_vec()),
        (429, b"busy".to_vec()),
        (500, b"server".to_vec()),
        (200, vec![b' '; LIMIT + 1]),
        (200, br#"{"state":"ENABLED","state":"DISABLED"}"#.to_vec()),
    ] {
        let (kms, server) = peer(vec![(status, body)], Duration::ZERO);
        let mut acquisition = acquisition(Duration::from_secs(1));
        assert!(
            kms.sign_frame(&selected, &frame, authorization(), &mut acquisition)
                .is_err()
        );
        assert!(acquisition.remaining().is_err());
        assert_eq!(server.join().unwrap().len(), 1);
    }
}

#[test]
fn timeout_and_expired_original_do_not_receive_a_fresh_budget() {
    let (selected, frame, replies) = fixture();
    let (kms, server) = peer(responses(replies[..1].to_vec()), Duration::from_millis(150));
    let mut acquisition = acquisition(Duration::from_millis(20));
    let started = Instant::now();
    assert!(
        kms.sign_frame(&selected, &frame, authorization(), &mut acquisition)
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(acquisition.remaining().is_err());
    assert_eq!(server.join().unwrap().len(), 1);
    let mut expired = super::tests::acquisition(Duration::ZERO);
    assert!(
        kms.sign_frame(&selected, &frame, authorization(), &mut expired)
            .is_err()
    );
    assert!(expired.remaining().is_err());
}

#[test]
fn selection_has_no_endpoint_override_latest_alias_or_private_key_path() {
    let (good, _, _) = fixture();
    good.validate().unwrap();
    for version in [
        "latest",
        "file:///key.pk8",
        "../root",
        "https://other/key",
        &good.version.replace("/1", "/0"),
        &good.version.replace("/1", "/01"),
        &good.version.replace("/1", "/latest"),
    ] {
        let mut bad = good.clone();
        bad.version = version.into();
        assert!(bad.validate().is_err(), "{version}");
    }
    let mut bad = serde_json::to_value(good).unwrap();
    bad["endpoint"] = json!("http://127.0.0.1");
    assert!(serde_json::from_value::<KmsRootSelection>(bad).is_err());
}
