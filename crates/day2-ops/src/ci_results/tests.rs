use super::*;
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
};

const TOKEN: &str = "synthetic-apply-token";
const BUCKET: &str = "exampleco-tools-links-ci";
const NAME: &str = "aa/bb-4/41/2/receipt.json";

/// Each request's target and authorization.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

/// A local JSON API: each request's target and authorization, answered with
/// the scripted status and body (and connection close) for its path.
fn serve(answer: fn(&str) -> (u16, Vec<u8>)) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let target = line
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let mut authorization = String::new();
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                let header = header.trim_end();
                if header.is_empty() {
                    break;
                }
                if let Some(value) = header.strip_prefix("authorization: ") {
                    authorization = value.to_owned();
                }
            }
            let (status, body) = answer(&target);
            log.lock().unwrap().push((target, authorization));
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(&body);
        }
    });
    (base, seen)
}

fn gcs(base: &str) -> Gcs {
    Gcs::build(base, false, Some(TOKEN.to_owned())).unwrap()
}

fn projected(name: &str) -> Vec<u8> {
    serde_json::json!({"name": name, "bucket": BUCKET, "generation": "1700000000000001",
        "size": "7", "timeCreated": "2026-11-25T18:05:00.123Z",
        "metadata": {"run": "41", "attempt": "2"}})
    .to_string()
    .into_bytes()
}

#[test]
fn an_object_is_its_exact_projection_read_with_the_apply_identitys_token() {
    let (base, seen) = serve(|target| {
        if target.contains("alt=media") {
            (200, b"receipt".to_vec())
        } else {
            (200, projected(NAME))
        }
    });
    let mut storage = gcs(&base);
    let stored = storage.object(BUCKET, NAME).unwrap().unwrap();
    assert_eq!(
        stored,
        Stored {
            generation: "1700000000000001".into(),
            size: 7,
            time_created: "2026-11-25T18:05:00.123Z".into(),
            metadata: BTreeMap::from([
                ("attempt".to_owned(), "2".to_owned()),
                ("run".to_owned(), "41".to_owned()),
            ]),
        }
    );
    assert_eq!(
        storage.media(BUCKET, NAME, "1700000000000001", 7).unwrap(),
        b"receipt"
    );
    let seen = seen.lock().unwrap();
    // The name is one path segment; the projection and generation are exact.
    assert_eq!(
        seen[0].0,
        "/b/exampleco-tools-links-ci/o/aa%2Fbb-4%2F41%2F2%2Freceipt.json\
         ?fields=name%2Cbucket%2Cgeneration%2Csize%2CtimeCreated%2Cmetadata"
    );
    assert_eq!(
        seen[1].0,
        "/b/exampleco-tools-links-ci/o/aa%2Fbb-4%2F41%2F2%2Freceipt.json?alt=media&generation=1700000000000001"
    );
    assert!(
        seen.iter()
            .all(|(_, authorization)| authorization == &format!("Bearer {TOKEN}"))
    );
}

#[test]
fn absence_is_absence_and_every_other_answer_is_closed() {
    let (base, _) = serve(|_| (404, b"{\"error\":\"not-a-secret\"}".to_vec()));
    assert_eq!(gcs(&base).object(BUCKET, NAME).unwrap(), None);
    for (status, body, retryable) in [
        (503_u16, b"not-a-secret".to_vec(), true),
        (429, Vec::new(), true),
        (403, b"not-a-secret".to_vec(), false),
        // Another object, an unselected field, a malformed number or time, or too much.
        (200, projected("other/receipt.json"), false),
        (
            200,
            br#"{"name":"aa/bb-4/41/2/receipt.json","bucket":"exampleco-tools-links-ci","generation":"1","size":"7","timeCreated":"2026-11-25T18:05:00Z","selfLink":"not-a-secret"}"#.to_vec(),
            false,
        ),
        (
            200,
            br#"{"name":"aa/bb-4/41/2/receipt.json","bucket":"exampleco-tools-links-ci","generation":"01","size":"7","timeCreated":"2026-11-25T18:05:00Z"}"#.to_vec(),
            false,
        ),
        (
            200,
            br#"{"name":"aa/bb-4/41/2/receipt.json","bucket":"exampleco-tools-links-ci","generation":"1","size":"7","timeCreated":"2026-11-25 18:05:00Z"}"#.to_vec(),
            false,
        ),
        (200, vec![b' '; 16_385], false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let reply = body.clone();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                let _ = stream.write_all(&reply);
            }
        });
        let error = gcs(&base).object(BUCKET, NAME).unwrap_err();
        let shown = format!("{error:#} {error:?}");
        assert!(!shown.contains("not-a-secret"), "{shown}");
        assert!(!shown.contains(TOKEN), "{shown}");
        assert_eq!(
            error.downcast_ref::<Retryable>().is_some(),
            retryable,
            "{status}: {shown}"
        );
    }
}

#[test]
fn a_download_is_exactly_the_size_asked_for() {
    let (base, _) = serve(|_| (200, b"receipt".to_vec()));
    let error = gcs(&base).media(BUCKET, NAME, "1", 6).unwrap_err();
    assert_eq!(format!("{error:#}"), "app_ci_results_reply_too_large");
    let error = gcs(&base).media(BUCKET, NAME, "1", 8).unwrap_err();
    assert!(error.downcast_ref::<Retryable>().is_some());
    let (base, _) = serve(|_| (404, Vec::new()));
    assert_eq!(
        format!("{:#}", gcs(&base).media(BUCKET, NAME, "1", 7).unwrap_err()),
        "app_ci_results_http_404"
    );
}

#[test]
fn a_refused_connection_is_retryable_and_names_nothing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let error = gcs(&base).object(BUCKET, NAME).unwrap_err();
    assert!(error.downcast_ref::<Retryable>().is_some());
    assert!(!format!("{error:#}").contains("127.0.0.1"));
}

/// A reply that dribbles a valid body in 16-byte chunks every 100 ms, for
/// about two seconds; whether the client hung up before the end.
fn dribble(body: Vec<u8>) -> (String, std::thread::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
        }
        let mut padded = body;
        padded.resize(320, b' ');
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            padded.len()
        );
        for chunk in padded.chunks(16) {
            if stream
                .write_all(chunk)
                .and_then(|()| stream.flush())
                .is_err()
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    });
    (base, handle)
}

#[test]
fn each_read_has_one_total_deadline_that_body_reads_cannot_renew() {
    // Every chunk arrives well within the client's per-read bound; the request's total bound still expires.
    let (base, server) = dribble(projected(NAME));
    let mut storage = gcs(&base);
    storage.describe = Duration::from_millis(500);
    let error = storage.object(BUCKET, NAME).unwrap_err();
    assert!(error.downcast_ref::<Retryable>().is_some(), "{error:#}");
    assert!(
        server.join().unwrap(),
        "the client read the whole dribbled reply"
    );
    let (base, server) = dribble(b"receipt".to_vec());
    let mut storage = gcs(&base);
    storage.download = Duration::from_millis(500);
    assert!(
        storage
            .media(BUCKET, NAME, "1", 320)
            .unwrap_err()
            .downcast_ref::<Retryable>()
            .is_some()
    );
    assert!(server.join().unwrap());
    // The production bounds are the documented ones.
    let native = Gcs::native().unwrap();
    assert_eq!(
        (native.describe, native.download),
        (Duration::from_secs(60), Duration::from_secs(900))
    );
    assert!(native.client.is_none() && native.token.is_none());
}

#[test]
fn decimals_are_gcs_integers() {
    assert_eq!(decimal("0"), Some(0));
    assert_eq!(decimal("1700000000000001"), Some(1_700_000_000_000_001));
    for value in ["", "01", "-1", "+1", "1.0", " 1", "18446744073709551616"] {
        assert_eq!(decimal(value), None, "{value}");
    }
}
