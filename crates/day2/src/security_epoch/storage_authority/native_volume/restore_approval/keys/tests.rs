//! Local resolver/HTTP controls, not a native availability or cloud receipt.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{io::Write, net::TcpListener, thread};

fn admitted() -> Result<Vec<SecurityKeySelection>> {
    crate::oauth::admission::live::tests::selected()?
        .instance()
        .security_key_selections("workspace")
}

fn requirement(selected: &SecurityKeySelection, purpose: KeyPurpose) -> ExactKey {
    let SecretProvider::GcpVersion { version, .. } = &selected.provider;
    ExactKey {
        binding: selected.binding.clone(),
        version: version.to_string(),
        purpose,
    }
}

#[test]
fn archive_resolution_uses_exact_admitted_versions_and_never_aliases() -> Result<()> {
    let admitted = admitted()?;
    let selected = admitted
        .iter()
        .find(|key| key.purpose == SecurityKeyPurpose::OauthCustodyEncryption)
        .unwrap();
    let exact = requirement(selected, KeyPurpose::CustodyEncryption);
    let complete = complete_requirements(&admitted)?;
    let resolved = resolve(&complete, &admitted)?;
    let SecretProvider::GcpVersion {
        project_number,
        secret,
        version,
    } = &selected.provider;
    assert_eq!(resolved.len(), complete.len());
    let selected_resource = resolved.iter().find(|key| key.archive == exact).unwrap();
    assert_eq!(
        selected_resource.provider.project_number,
        project_number.get()
    );
    assert_eq!(selected_resource.provider.secret, secret.as_str());
    assert_eq!(selected_resource.provider.version, version.get());
    for index in 0..complete.len() {
        let mut missing = complete.clone();
        missing.remove(index);
        assert!(
            resolve(&missing, &admitted).is_err(),
            "every admitted archive key is required"
        );
    }
    for value in [
        "latest".into(),
        "current".into(),
        format!("0{}", exact.version),
        format!("version-{}", exact.version),
        (version.get() + 1).to_string(),
    ] {
        let mut wrong = complete.clone();
        wrong.iter_mut().find(|key| **key == exact).unwrap().version = value;
        assert!(resolve(&wrong, &admitted).is_err());
    }
    let mut wrong = exact.clone();
    wrong.binding.revision = Digest::new(b"changed binding revision");
    assert!(resolve(&[wrong], &admitted).is_err());
    let mut wrong = exact.clone();
    wrong.purpose = KeyPurpose::ShellAttestation;
    assert!(resolve(&[wrong], std::slice::from_ref(selected)).is_err());
    assert!(resolve(&[], &admitted).is_err());
    assert!(resolve(&[exact.clone(), exact.clone()], &admitted).is_err());
    assert!(resolve(std::slice::from_ref(&exact), &[]).is_err());
    let mut competing = selected.clone();
    let SecretProvider::GcpVersion { secret, .. } = &mut competing.provider;
    *secret = "another-secret".to_owned().try_into()?;
    assert!(resolve(&[exact], &[selected.clone(), competing]).is_err());
    Ok(())
}

fn selected() -> Result<Vec<SelectedKey>> {
    let admitted = admitted()?;
    let selected = admitted
        .iter()
        .find(|key| key.purpose == SecurityKeyPurpose::OauthCustodyEncryption)
        .unwrap();
    let mut all = resolve(&complete_requirements(&admitted)?, &admitted)?;
    let exact = requirement(selected, KeyPurpose::CustodyEncryption);
    all.retain(|key| key.archive == exact);
    Ok(all)
}

fn body(version: &GcpSecretVersion, material: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "name":format!("projects/{}/secrets/{}/versions/{}",version.project_number,version.secret,version.version),
        "payload":{"data":STANDARD.encode(material),"dataCrc32c":crc32c::crc32c(material).to_string()}
    })).unwrap()
}

// Each expected request is an actual loopback TCP exchange. The independent
// model chooses statuses/payload mutations; it does not call the decoder.
fn peer_many(replies: Vec<(u16, Vec<u8>)>) -> (KeyHttp, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, body) in replies {
            let end = std::time::Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < end,
                            "bounded key fixture request"
                        );
                        thread::yield_now();
                    }
                    Err(error) => panic!("key fixture accept: {:?}", error.kind()),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).unwrap(), 1);
                request.push(byte[0]);
                assert!(request.len() <= 16384);
            }
            write!(
                stream,
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            let _ = stream.write_all(&body);
            let request = String::from_utf8(request).unwrap();
            requests.push(request.lines().next().unwrap().to_owned());
        }
        requests
    });
    let mut http = KeyHttp::new().unwrap();
    http.fixture_origin = Some(origin);
    (http, task)
}

fn peer(status: u16, body: Vec<u8>) -> (KeyHttp, thread::JoinHandle<Vec<String>>) {
    peer_many(vec![(status, body)])
}

fn original(limit: Duration) -> NativeAcquisition {
    NativeAcquisition::fixture(
        Digest::new(b"key transport fixture only"),
        std::process::id(),
        Duration::from_secs(10),
        limit,
    )
}

fn context(original: &mut NativeAcquisition) -> KeyContext<'_, '_, '_, '_, '_> {
    KeyContext::Fixture {
        authorization: HeaderValue::from_static("Bearer fixture"),
        fail_at: None,
        checks: 0,
        original,
    }
}

#[test]
fn exact_key_http_refuses_status_resource_checksum_size_and_material_failures() -> Result<()> {
    let selection = selected()?;
    for case in 0..7 {
        let mut bytes = body(&selection[0].provider, &[31; 32]);
        let status = if case == 1 { 403 } else { 200 };
        if case == 2 {
            bytes = body(
                &GcpSecretVersion {
                    version: selection[0].provider.version + 1,
                    ..selection[0].provider.clone()
                },
                &[31; 32],
            );
        }
        if case == 3 {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
            value["payload"]["dataCrc32c"] = "0".into();
            bytes = serde_json::to_vec(&value)?;
        }
        if case == 4 {
            bytes = vec![b' '; MAX_REPLY + 1];
        }
        if case == 5 {
            bytes = body(&selection[0].provider, &[31; 31]);
        }
        if case == 6 {
            bytes = b"malformed".to_vec();
        }
        let (http, task) = peer(status, bytes);
        let mut clock = original(Duration::from_secs(5));
        let result = http.read_all(&selection, &mut context(&mut clock));
        assert_eq!(result.is_ok(), case == 0, "independent case {case}");
        let request = task.join().unwrap();
        assert_eq!(
            request,
            vec![format!(
                "GET /v1/{}:access HTTP/1.1",
                selection[0].provider.resource_name()
            )]
        );
        if case == 0 {
            assert_eq!(&*result.unwrap()[0].material, &[31; 32]);
        } else {
            // A repaired reply cannot reopen this SAME fixture original.
            assert!(clock.remaining().is_err());
            assert!(http.read_all(&selection, &mut context(&mut clock)).is_err());
        }
    }
    Ok(())
}

#[test]
fn deadline_equality_and_abandoned_key_attempt_remain_refused() -> Result<()> {
    let mut expired = original(Duration::ZERO);
    let selection = selected()?;
    assert!(
        KeyHttp::new()?
            .read_all(&selection, &mut context(&mut expired))
            .is_err()
    );
    assert!(expired.remaining().is_err());
    for unwind in [false, true] {
        let mut clock = original(Duration::from_secs(5));
        let attempt = KeyBirth {
            original: Some(clock.narrow(5, Duration::MAX)?),
        };
        if unwind {
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = attempt;
                panic!("lost key acquisition fixture");
            }));
            assert!(caught.is_err());
        } else {
            drop(attempt);
        }
        assert!(clock.remaining().is_err());
    }
    Ok(())
}

#[test]
fn actual_retained_owner_has_no_manifest_or_fixture_constructor() {
    let source = include_str!("../../restore_approval.rs");
    let production: String = source.split_whitespace().collect();
    assert_eq!(
        production
            .matches("letmutkeys=HistoricalKeyAvailability{")
            .count(),
        1
    );
    assert!(production.contains("letmaterial=http.read_all(&selection,&mutcontext)?;"));
    assert!(production.contains("context.check()?;keys.original.remaining()?;"));
    assert!(production.contains("ifletSome(original)=&mutself.original{original.refuse();}"));
}

#[test]
fn each_actual_key_io_postcheck_refuses_and_cannot_be_repaired() -> Result<()> {
    let selection = selected()?;
    // A real reply has already arrived for send/body/final-check cuts. The
    // independent oracle requires refusal, no returned partial material and
    // permanent denial even when the simulated authority is repaired.
    for cut in 2..=4 {
        let (http, task) = peer(200, body(&selection[0].provider, &[41; 32]));
        let mut clock = original(Duration::from_secs(5));
        let mut context = context(&mut clock);
        let KeyContext::Fixture { fail_at, .. } = &mut context else {
            unreachable!()
        };
        *fail_at = Some(cut);
        assert!(http.read_all(&selection, &mut context).is_err());
        let KeyContext::Fixture { fail_at, .. } = &mut context else {
            unreachable!()
        };
        *fail_at = None;
        assert!(http.read_all(&selection, &mut context).is_err());
        assert!(task.join().is_ok());
    }
    Ok(())
}

#[test]
fn complete_set_matches_independent_seeded_partial_failure_expectations() -> Result<()> {
    let admitted = admitted()?;
    let mut required = Vec::new();
    for (purpose, selected_purpose) in [
        (
            KeyPurpose::CustodyEncryption,
            SecurityKeyPurpose::OauthCustodyEncryption,
        ),
        (
            KeyPurpose::CustodyVerifier,
            SecurityKeyPurpose::OauthCustodyVerifier,
        ),
    ] {
        required.push(requirement(
            admitted
                .iter()
                .find(|key| key.purpose == selected_purpose)
                .unwrap(),
            purpose,
        ));
    }
    let mut selected = resolve(&complete_requirements(&admitted)?, &admitted)?;
    selected.retain(|key| required.contains(&key.archive));
    assert_eq!(selected.len(), 2);
    for seed in 0..12u64 {
        let case = seed.wrapping_mul(6364136223846793005).wrapping_add(1) % 4;
        // Independent expectation: only two exact 32-byte successful replies
        // produce the whole set; one successful prefix is never availability.
        let expected = case == 0;
        let mut second = body(&selected[1].provider, &[59; 32]);
        let status = if case == 1 { 404 } else { 200 };
        if case == 2 {
            second = body(&selected[1].provider, &[59; 31]);
        }
        if case == 3 {
            second = body(
                &GcpSecretVersion {
                    version: selected[1].provider.version + 1,
                    ..selected[1].provider.clone()
                },
                &[59; 32],
            );
        }
        let (http, task) = peer_many(vec![
            (200, body(&selected[0].provider, &[53; 32])),
            (status, second),
        ]);
        let mut clock = original(Duration::from_secs(5));
        let result = http.read_all(&selected, &mut context(&mut clock));
        assert_eq!(result.is_ok(), expected, "replay seed {seed}, fault {case}");
        assert_eq!(task.join().unwrap().len(), 2, "replay seed {seed}");
        if expected {
            let result = result?;
            assert_eq!(result.len(), 2);
            assert_eq!(&*result[0].material, &[53; 32]);
            assert_eq!(&*result[1].material, &[59; 32]);
        } else {
            assert!(
                clock.remaining().is_err(),
                "partial material must not survive seed {seed}"
            );
        }
    }
    Ok(())
}
