//! Actual loopback HTTP and fixture clocks only. Neither provides a native
//! registry, signing owner, qualified time, cloud key or accepting approval.
use super::*;
use crate::security_epoch::restore_approval::AdminIdentity;
use day2_capabilities::Digest;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

fn fixture() -> Result<(KeySelection, ApprovalStatement, Vec<Value>)> {
    let key = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).expect("fixture key");
    let selected = KeySelection {
        version: "projects/approval-project/locations/global/keyRings/restore/cryptoKeys/approval/cryptoKeyVersions/7".to_owned().try_into()?,
        public_key: key.public_key().as_ref().try_into()?,
    };
    let statement = ApprovalStatement {
        request: crate::security_epoch::restore_approval::fixture_request_data()?,
        approver: AdminIdentity {
            email: "approver@example.org".into(),
            subject: "approver-subject".into(),
        },
        registry: Digest::new(b"current reviewed registry"),
        credential: Digest::new(b"actual selected credential"),
        assertion: Digest::new(b"verified assertion and exact request challenge"),
        signing_key: selected.commitment()?,
    };
    // Independent purpose literal/frame and SPKI encoder. Do not sign the
    // implementation's output to create the oracle's expected signature.
    let frame = serde_json::to_vec(&("day2-restore-approval-grant-ed25519-v1", &statement))?;
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(key.public_key().as_ref());
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        STANDARD.encode(der)
    );
    let signature = key.sign(&frame);
    let metadata = json!({"name":selected.version.as_str(),"algorithm":"EC_SIGN_ED25519","protectionLevel":"SOFTWARE","state":"ENABLED"});
    let replies = vec![
        metadata.clone(),
        json!({"name":selected.version.as_str(),"algorithm":"EC_SIGN_ED25519","protectionLevel":"SOFTWARE","pem":pem,"pemCrc32c":crc32c::crc32c(pem.as_bytes()).to_string()}),
        json!({"name":selected.version.as_str(),"protectionLevel":"SOFTWARE","signature":STANDARD.encode(signature.as_ref()),"signatureCrc32c":crc32c::crc32c(signature.as_ref()).to_string(),"verifiedDataCrc32c":true}),
        metadata,
    ];
    Ok((selected, statement, replies))
}

fn acquisition(limit: Duration) -> NativeAcquisition {
    NativeAcquisition::fixture(
        Digest::new(b"fixture-only kms original"),
        std::process::id(),
        Duration::from_secs(10),
        limit,
    )
}

fn authorization() -> HeaderValue {
    let mut value = HeaderValue::from_static("Bearer fixture-token");
    value.set_sensitive(true);
    value
}

impl Kms {
    fn sign_fixture(
        &mut self,
        selected: &KeySelection,
        statement: &ApprovalStatement,
        authorization: HeaderValue,
        acquisition: &mut NativeAcquisition,
    ) -> Result<SignedApprovalRecord> {
        let mut context = RequestContext::Fixture {
            authorization,
            acquisition,
        };
        self.sign(selected, statement, &mut context)
    }
}

type Calls = Vec<(String, Value)>;

struct Reply {
    status: u16,
    body: Vec<u8>,
    delay: Duration,
    length: Option<usize>,
}

fn reply(status: u16, body: Vec<u8>, delay: Duration) -> Reply {
    let length = Some(body.len());
    Reply {
        status,
        body,
        delay,
        length,
    }
}

fn encoded(values: Vec<Value>) -> Vec<Reply> {
    values
        .into_iter()
        .map(|v| reply(200, serde_json::to_vec(&v).unwrap(), Duration::ZERO))
        .collect()
}

fn peer(replies: Vec<Reply>) -> (Kms, thread::JoinHandle<Calls>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut calls = Vec::new();
        for Reply {
            status,
            body,
            delay,
            length,
        } in replies
        {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::park_timeout(Duration::from_millis(1))
                    }
                    Err(_) => panic!("expected bounded fixture HTTP request missing"),
                }
            };
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
                    .contains("authorization: bearer fixture-token\r\n")
            );
            let request_length: usize = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .map_or(0, |n| n.parse().unwrap());
            assert!(request_length <= REQUEST_LIMIT);
            let mut request = vec![0; request_length];
            stream.read_exact(&mut request).unwrap();
            calls.push((
                head.lines().next().unwrap().to_owned(),
                if request.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&request).unwrap()
                },
            ));
            thread::park_timeout(delay);
            let length = length.map_or_else(String::new, |n| format!("Content-Length: {n}\r\n"));
            let _ = write!(
                stream,
                "HTTP/1.1 {status} Fixture\r\n{length}Connection: close\r\n\r\n"
            );
            let _ = stream.write_all(&body);
        }
        calls
    });
    (
        Kms {
            client: client(false).unwrap(),
            attempted: false,
            local: PhantomData,
            fixture_origin: Some(origin),
        },
        handle,
    )
}

#[test]
fn actual_http_signs_only_complete_restore_frame_on_the_exact_version_once() -> Result<()> {
    let (selected, statement, replies) = fixture()?;
    let (mut kms, server) = peer(encoded(replies));
    let mut original = acquisition(Duration::from_secs(2));
    let signed = kms.sign_fixture(&selected, &statement, authorization(), &mut original)?;
    let calls = server.join().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls.iter().map(|c| c.0.clone()).collect::<Vec<_>>(),
        vec![
            format!("GET /v1/{} HTTP/1.1", selected.version.as_str()),
            format!("GET /v1/{}/publicKey HTTP/1.1", selected.version.as_str()),
            format!(
                "POST /v1/{}:asymmetricSign HTTP/1.1",
                selected.version.as_str()
            ),
            format!("GET /v1/{} HTTP/1.1", selected.version.as_str()),
        ]
    );
    let independent = serde_json::to_vec(&("day2-restore-approval-grant-ed25519-v1", &statement))?;
    assert_eq!(
        calls[2].1,
        json!({"data":STANDARD.encode(&independent),"dataCrc32c":crc32c::crc32c(&independent).to_string()})
    );
    assert!(
        calls
            .iter()
            .enumerate()
            .all(|(i, c)| i == 2 || c.1.is_null())
    );
    signed.verify_signature_data(&statement, &selected)?;
    assert_eq!(
        signed.statement.request.expires_at - signed.statement.request.approved_at,
        3600
    );
    assert!(original.remaining().is_ok());
    assert!(
        kms.sign_fixture(&selected, &statement, authorization(), &mut original)
            .is_err()
    );
    assert!(original.remaining().is_err());
    Ok(())
}

#[test]
fn each_actual_resource_integrity_or_crypto_failure_is_terminal_and_never_retried() -> Result<()> {
    let (selected, statement, good) = fixture()?;
    let cases = [
        (
            0,
            "name",
            json!(
                selected
                    .version
                    .as_str()
                    .replace("Versions/7", "Versions/8")
            ),
        ),
        (0, "algorithm", json!("EC_SIGN_P256_SHA256")),
        (0, "protectionLevel", json!("HSM")),
        (0, "state", json!("DISABLED")),
        (1, "name", json!("another-key")),
        (1, "algorithm", json!("RSA_SIGN_PSS_2048_SHA256")),
        (1, "protectionLevel", json!("HSM")),
        (1, "pemCrc32c", json!("0")),
        (
            2,
            "name",
            json!(
                selected
                    .version
                    .as_str()
                    .replace("Versions/7", "Versions/8")
            ),
        ),
        (2, "protectionLevel", json!("HSM")),
        (2, "verifiedDataCrc32c", json!(false)),
        (2, "verifiedDigestCrc32c", json!(true)),
        (2, "signatureCrc32c", json!("0")),
        (2, "signature", json!(STANDARD.encode([0; 63]))),
        (3, "state", json!("DISABLED")),
        (
            3,
            "name",
            json!(
                selected
                    .version
                    .as_str()
                    .replace("Versions/7", "Versions/8")
            ),
        ),
    ];
    for (index, field, value) in cases {
        let mut replies = good[..=index].to_vec();
        replies[index][field] = value;
        let (mut kms, server) = peer(encoded(replies));
        let mut original = acquisition(Duration::from_secs(2));
        assert!(
            kms.sign_fixture(&selected, &statement, authorization(), &mut original)
                .is_err(),
            "{index}/{field}"
        );
        assert_eq!(server.join().unwrap().len(), index + 1);
        assert!(original.remaining().is_err());
        assert!(
            kms.sign_fixture(
                &selected,
                &statement,
                authorization(),
                &mut acquisition(Duration::from_secs(2))
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn well_checksummed_foreign_key_or_wrong_purpose_signature_still_refuses() -> Result<()> {
    let (selected, statement, good) = fixture()?;
    let key = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
    for frame in [
        serde_json::to_vec(&statement)?,
        serde_json::to_vec(&("day2-native-enrollment-v1", "issuer-birth", &statement))?,
    ] {
        let mut replies = good[..=2].to_vec();
        let signature = key.sign(&frame);
        replies[2]["signature"] = json!(STANDARD.encode(signature.as_ref()));
        replies[2]["signatureCrc32c"] = json!(crc32c::crc32c(signature.as_ref()).to_string());
        let (mut kms, server) = peer(encoded(replies));
        let mut original = acquisition(Duration::from_secs(2));
        assert!(
            kms.sign_fixture(&selected, &statement, authorization(), &mut original)
                .is_err()
        );
        assert_eq!(server.join().unwrap().len(), 3);
        assert!(original.remaining().is_err());
    }
    let foreign = Ed25519KeyPair::from_seed_unchecked(&[38; 32]).unwrap();
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(foreign.public_key().as_ref());
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        STANDARD.encode(der)
    );
    let mut replies = good[..=1].to_vec();
    replies[1]["pem"] = json!(pem);
    replies[1]["pemCrc32c"] = json!(crc32c::crc32c(pem.as_bytes()).to_string());
    let (mut kms, server) = peer(encoded(replies));
    let mut original = acquisition(Duration::from_secs(2));
    assert!(
        kms.sign_fixture(&selected, &statement, authorization(), &mut original)
            .is_err()
    );
    assert_eq!(server.join().unwrap().len(), 2);
    assert!(original.remaining().is_err());
    Ok(())
}

#[test]
fn changed_selection_and_spent_original_refuse_before_any_network_attempt() -> Result<()> {
    let (selected, statement, _) = fixture()?;
    let mut different = selected.clone();
    different.version = selected
        .version
        .as_str()
        .replace("Versions/7", "Versions/8")
        .try_into()?;
    for (selection, limit) in [
        (&different, Duration::from_secs(1)),
        (&selected, Duration::ZERO),
    ] {
        // Port zero cannot receive a successful request. The exact local
        // reason distinguishes refusal before HTTP from a transport failure.
        let mut kms = Kms {
            client: client(false)?,
            attempted: false,
            local: PhantomData,
            fixture_origin: Some("http://127.0.0.1:0".into()),
        };
        let mut original = acquisition(limit);
        let error = kms
            .sign_fixture(selection, &statement, authorization(), &mut original)
            .expect_err("must refuse");
        if limit.is_zero() {
            assert!(original.remaining().is_err());
        } else {
            assert_eq!(error.to_string(), "restore_kms_selection_changed");
        }
        assert!(kms.attempted);
        assert!(original.remaining().is_err());
    }
    Ok(())
}

#[test]
fn rejected_status_oversize_duplicate_json_and_timeout_do_not_retry() -> Result<()> {
    let (selected, statement, good) = fixture()?;
    for (status, body, delay, limit) in [
        (
            302,
            serde_json::to_vec(&good[0])?,
            Duration::ZERO,
            Duration::from_secs(1),
        ),
        (
            503,
            b"provider-private-content-must-not-escape".to_vec(),
            Duration::ZERO,
            Duration::from_secs(1),
        ),
        (
            200,
            vec![b' '; REPLY_LIMIT + 1],
            Duration::ZERO,
            Duration::from_secs(1),
        ),
        (
            200,
            b"{\"name\":\"first\",\"name\":\"second\"}".to_vec(),
            Duration::ZERO,
            Duration::from_secs(1),
        ),
        (
            200,
            serde_json::to_vec(&good[0])?,
            Duration::from_millis(100),
            Duration::from_millis(10),
        ),
    ] {
        let (mut kms, server) = peer(vec![reply(status, body, delay)]);
        let mut original = acquisition(limit);
        let error = kms
            .sign_fixture(&selected, &statement, authorization(), &mut original)
            .expect_err("must refuse");
        assert!(!error.to_string().contains("provider-private"));
        assert_eq!(server.join().unwrap().len(), 1);
        assert!(original.remaining().is_err());
        assert!(
            kms.sign_fixture(
                &selected,
                &statement,
                authorization(),
                &mut acquisition(Duration::from_secs(1))
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn unknown_length_oversize_and_truncated_actual_bodies_refuse_without_retry() -> Result<()> {
    let (selected, statement, good) = fixture()?;
    let body = serde_json::to_vec(&good[0])?;
    for received in [
        Reply {
            status: 200,
            body: vec![b' '; REPLY_LIMIT + 1],
            delay: Duration::ZERO,
            length: None,
        },
        Reply {
            status: 200,
            length: Some(body.len() + 10),
            body,
            delay: Duration::ZERO,
        },
    ] {
        let (mut kms, server) = peer(vec![received]);
        let mut original = acquisition(Duration::from_secs(2));
        assert!(
            kms.sign_fixture(&selected, &statement, authorization(), &mut original)
                .is_err()
        );
        assert_eq!(server.join().unwrap().len(), 1);
        assert!(original.remaining().is_err());
        assert!(
            kms.sign_fixture(
                &selected,
                &statement,
                authorization(),
                &mut acquisition(Duration::from_secs(2))
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn actual_default_client_requires_https_and_refusal_reaches_the_parent_original() -> Result<()> {
    let (selected, statement, _) = fixture()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let mut kms = Kms::new()?;
    kms.fixture_origin = Some(format!("http://{}", listener.local_addr()?));
    let mut parent = acquisition(Duration::from_secs(2));
    let mut child = parent.narrow(1, Duration::from_secs(12))?;
    let error = kms
        .sign_fixture(&selected, &statement, authorization(), &mut child)
        .expect_err("HTTP origin refused by actual production client");
    assert_eq!(error.to_string(), "restore_kms_transport");
    assert!(
        listener
            .accept()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert!(child.remaining().is_err());
    assert!(parent.remaining().is_err());
    Ok(())
}

fn is_closed(source: &str) -> Result<bool> {
    let file = syn::parse_file(source)?;
    let mut saw_kms = false;
    let mut methods = Vec::new();
    for item in file.items {
        match item {
            syn::Item::Struct(item) if item.ident == "Kms" => {
                saw_kms = true;
                if !matches!(item.vis, syn::Visibility::Inherited)
                    || item
                        .fields
                        .iter()
                        .any(|f| !matches!(f.vis, syn::Visibility::Inherited))
                {
                    return Ok(false);
                }
            }
            syn::Item::Impl(item) => {
                for entry in item.items {
                    if let syn::ImplItem::Fn(method) = entry {
                        if !matches!(method.vis, syn::Visibility::Inherited) {
                            return Ok(false);
                        }
                        methods.push(method.sig.ident.to_string());
                    }
                }
            }
            syn::Item::Fn(item) if !matches!(item.vis, syn::Visibility::Inherited) => {
                return Ok(false);
            }
            _ => (),
        }
    }
    methods.sort();
    Ok(saw_kms && methods == ["new", "request", "sign"])
}

#[test]
fn production_data_transport_has_no_reachable_signer_factory_or_general_frame_api() -> Result<()> {
    let source = include_str!("../kms.rs");
    assert!(is_closed(source)?);
    for (from, to) in [
        ("struct Kms {", "pub(super) struct Kms {"),
        ("fn new()", "pub(super) fn new()"),
        ("fn sign(", "pub(super) fn sign("),
        ("fn client(", "pub(super) fn client("),
    ] {
        assert_eq!(source.matches(from).count(), 1);
        assert!(!is_closed(&source.replacen(from, to, 1))?);
    }
    Ok(())
}
