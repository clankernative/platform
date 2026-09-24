use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_control::{GitOid, secrets::*, source::*};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const TOKEN: &str = "gcp-fixture-access-token";
const SECRET: &str = "github-fixture-installation-token";
const RESOURCE: &str = "projects/12345/secrets/github-read/versions/7";

struct Tokens;
impl AccessTokenProvider for Tokens {
    fn access_token(&self) -> Result<AccessToken, SourceError> {
        AccessToken::new(TOKEN.into())
    }
}
fn reference() -> SecretRef {
    "source-read".to_owned().try_into().unwrap()
}
fn bindings() -> BTreeMap<SecretRef, SecretVersion> {
    BTreeMap::from([(
        reference(),
        SecretVersion {
            project_number: 12345,
            secret: "github-read".into(),
            version: 7,
        },
    )])
}
fn payload() -> Value {
    json!({"name":RESOURCE,"payload":{"data":STANDARD.encode(SECRET),"dataCrc32c":crc32c::crc32c(SECRET.as_bytes()).to_string()}})
}

struct Fixture {
    endpoint: String,
    request: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Fixture {
    fn new(status: u16, body: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let request = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, shutdown) = (request.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !shutdown.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut header = vec![];
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                    assert!(header.len() < 16_384);
                }
                *seen.lock().unwrap() = Some(String::from_utf8(header).unwrap());
                let bytes = serde_json::to_vec(&body).unwrap();
                let head = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nLocation: http://127.0.0.1:1/forbidden\r\n\r\n",
                    bytes.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&bytes);
                break;
            }
        });
        Self {
            endpoint,
            request,
            stop,
            worker: Some(worker),
        }
    }
    fn request(&self) -> String {
        self.request
            .lock()
            .unwrap()
            .clone()
            .expect("expected HTTP request")
    }
    fn resolver(&self) -> GcpSecretManager<'_> {
        GcpSecretManager::with_endpoint(&self.endpoint, bindings(), &Tokens).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let joined = worker.join();
            if !thread::panicking() {
                joined.unwrap();
            }
        }
    }
}

#[test]
fn installation_grants_only_app_scoped_provider_secret_references() {
    use day2_capabilities::{ControlScope, InstallationControl, Name};
    use day2_control::service::Service;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let config: InstallationControl = serde_json::from_value(json!({
        "version":1,
        "state_directory":root.join("state"),
        "operators":["operator@example.com"],
        "sources":{
            "links-source":{"kind":"local_git","repository":root.join("repositories/links.git")},
            "other-source":{"kind":"local_git","repository":root.join("repositories/other.git")}
        },
        "apps":{
            "links":{"source":"links-source","provider_secrets":{"source-read":"github-read"}},
            "other":{"source":"other-source","provider_secrets":{"other-read":"other-credential"}}
        },
        "secrets":{
            "github-read":{"kind":"gcp_version","project_number":12345,"secret":"github-read","version":7},
            "other-credential":{"kind":"gcp_version","project_number":54321,"secret":"other-secret","version":2}
        }
    })).unwrap();
    let name = |value: &str| Name::try_from(value.to_owned()).unwrap();
    let service = Service::open(
        ControlScope {
            installation: name("example"),
            environment: name("development"),
        },
        config.clone(),
        ["links", "other"],
    )
    .unwrap();
    let handle = service
        .authorize("operator@example.com", &name("links"))
        .unwrap();
    let fixture = Fixture::new(200, payload());
    let resolver = service
        .secret_resolver_with_endpoint(&handle, Arc::new(Tokens), &fixture.endpoint)
        .unwrap();
    for denied in ["other-read", "other-credential", "github-read", "unknown"] {
        assert_eq!(
            resolver
                .resolve(&SecretRef::try_from(denied.to_owned()).unwrap())
                .unwrap_err()
                .class,
            FailureClass::Unauthorized
        );
    }
    assert_eq!(
        format!("{:?}", resolver.resolve(&reference()).unwrap()),
        "SecretValue([REDACTED])"
    );
    let request = fixture.request();
    assert!(request.starts_with(&format!("GET /v1/{RESOURCE}:access ")));
    assert!(request.contains(&format!("Bearer {TOKEN}")));
    assert!(!request.contains("other-secret"));
    let mut invalid = serde_json::to_value(config).unwrap();
    invalid["secrets"]["github-read"]["version"] = json!(0);
    assert!(serde_json::from_value::<InstallationControl>(invalid.clone()).is_err());
    invalid["secrets"]["github-read"]["version"] = json!("latest");
    assert!(serde_json::from_value::<InstallationControl>(invalid).is_err());
}

#[test]
fn pinned_secret_with_verified_checksum_is_only_delivered_to_bound_provider() {
    let secrets = Fixture::new(200, payload());
    let github = Fixture::new(401, json!({"error":"fixture-stop"}));
    let resolver = secrets.resolver();
    let binding = GithubBinding {
        owner: "company".into(),
        repository: "app".into(),
        repository_id: 42,
        subdirectory: None,
        credential: Some(reference()),
        checks: None,
    };
    let commit: GitOid = "1111111111111111111111111111111111111111"
        .to_owned()
        .try_into()
        .unwrap();
    let result = GithubSource::new(&github.endpoint)
        .unwrap()
        .fetch(&binding, &commit, &resolver);
    assert_eq!(result.unwrap_err().class, FailureClass::Unauthorized);
    assert!(
        secrets
            .request()
            .starts_with(&format!("GET /v1/{RESOURCE}:access HTTP/1.1\r\n"))
    );
    assert!(
        secrets
            .request()
            .contains(&format!("authorization: Bearer {TOKEN}"))
    );
    assert!(
        github
            .request()
            .contains(&format!("authorization: Bearer {SECRET}"))
    );
    assert!(!github.request().contains(TOKEN));
    assert!(!format!("{:?}", AccessToken::new(TOKEN.into()).unwrap()).contains(TOKEN));
    assert_eq!(resolver.bindings()[&reference()].version, 7);
}

#[test]
fn version_name_checksum_encoding_and_missing_checksum_fail_closed() {
    let mut wrong_version = payload();
    wrong_version["name"] = "projects/12345/secrets/github-read/versions/8".into();
    let mut wrong_checksum = payload();
    wrong_checksum["payload"]["dataCrc32c"] = "0".into();
    let mut wrong_encoding = payload();
    wrong_encoding["payload"]["data"] = "!not-base64!".into();
    let mut missing_checksum = payload();
    missing_checksum["payload"]
        .as_object_mut()
        .unwrap()
        .remove("dataCrc32c");
    let mut overflow_checksum = payload();
    overflow_checksum["payload"]["dataCrc32c"] = "4294967296".into();
    for value in [
        wrong_version,
        wrong_checksum,
        wrong_encoding,
        missing_checksum,
        overflow_checksum,
    ] {
        let fixture = Fixture::new(200, value);
        let error = fixture.resolver().resolve(&reference()).unwrap_err();
        assert_eq!(error.class, FailureClass::Integrity);
        assert!(!format!("{error:?}").contains(SECRET));
    }
}

#[test]
fn unbound_references_and_unpinned_versions_never_request_credentials() {
    let fixture = Fixture::new(200, payload());
    let error = fixture
        .resolver()
        .resolve(&"unbound".to_owned().try_into().unwrap())
        .unwrap_err();
    assert_eq!(error.code, "gcp_secret_not_bound");
    assert!(fixture.request.lock().unwrap().is_none());
    for value in [
        json!({"project_number":12345,"secret":"github","version":"latest"}),
        json!({"project_number":12345,"secret":"github","version":7,"fallback":"latest"}),
    ] {
        assert!(serde_json::from_value::<SecretVersion>(value).is_err());
    }
    for version in [
        SecretVersion {
            project_number: 0,
            secret: "github".into(),
            version: 7,
        },
        SecretVersion {
            project_number: 12345,
            secret: "github".into(),
            version: 0,
        },
        SecretVersion {
            project_number: 12345,
            secret: "../github".into(),
            version: 7,
        },
    ] {
        assert!(GcpSecretManager::new(BTreeMap::from([(reference(), version)]), &Tokens).is_err());
    }
}

#[test]
fn endpoints_are_fixed_and_remote_failures_are_redacted() {
    for endpoint in [
        "https://attacker.example/",
        "http://secretmanager.googleapis.com/",
        "https://secretmanager.googleapis.com/path/",
        "https://token@secretmanager.googleapis.com/",
        "https://secretmanager.googleapis.com/?token=secret",
    ] {
        assert!(GcpSecretManager::with_endpoint(endpoint, bindings(), &Tokens).is_err());
    }
    for (status, class) in [
        (401, FailureClass::Unauthorized),
        (403, FailureClass::Unauthorized),
        (404, FailureClass::NotFound),
        (429, FailureClass::RateLimited),
        (503, FailureClass::Transient),
        (302, FailureClass::Unsupported),
    ] {
        let fixture = Fixture::new(status, json!({"message":format!("{TOKEN}:{SECRET}")}));
        let error = fixture.resolver().resolve(&reference()).unwrap_err();
        assert_eq!(error.class, class);
        assert!(!error.to_string().contains(TOKEN));
        assert!(!error.to_string().contains(SECRET));
    }
}

#[test]
fn oversized_or_non_token_secret_material_is_rejected() {
    let fixture = Fixture::new(200, json!({"excess": "x".repeat(33*1024)}));
    assert_eq!(
        fixture.resolver().resolve(&reference()).unwrap_err().class,
        FailureClass::Limit
    );
    for bytes in [b"secret\n".to_vec(), vec![255], vec![b'x'; 8193]] {
        let fixture = Fixture::new(
            200,
            json!({"name":RESOURCE,"payload":{"data":STANDARD.encode(&bytes),"dataCrc32c":crc32c::crc32c(&bytes).to_string()}}),
        );
        assert!(fixture.resolver().resolve(&reference()).is_err());
    }
}

#[test]
fn binding_revision_pins_endpoint_and_numeric_version_not_access_token_bytes() {
    struct RefreshedToken;
    impl AccessTokenProvider for RefreshedToken {
        fn access_token(&self) -> Result<AccessToken, SourceError> {
            AccessToken::new("different-short-lived-token".into())
        }
    }
    let original = GcpSecretManager::new(bindings(), &Tokens).unwrap();
    let refreshed = GcpSecretManager::new(bindings(), &RefreshedToken).unwrap();
    assert_eq!(original.binding_revision(), refreshed.binding_revision());
    let mut changed = bindings();
    changed.get_mut(&reference()).unwrap().version = 8;
    assert_ne!(
        original.binding_revision(),
        GcpSecretManager::new(changed, &Tokens)
            .unwrap()
            .binding_revision()
    );
    assert_ne!(
        original.binding_revision(),
        GcpSecretManager::with_endpoint("http://127.0.0.1:1001/", bindings(), &Tokens)
            .unwrap()
            .binding_revision()
    );
}
