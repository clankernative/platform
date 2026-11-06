//! Bounded, explicitly credentialled Secret Manager writes. No ADC or retries.
use super::{Provider, ProviderFailure, Target};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{blocking::Client, header, redirect::Policy};
use serde_json::{Value, json};
use std::{fs, io::Read as _, time::Duration};
use zeroize::Zeroizing;

pub struct Gcp {
    origin: String,
}

impl Default for Gcp {
    fn default() -> Self {
        Self {
            origin: "https://secretmanager.googleapis.com".into(),
        }
    }
}

impl Gcp {
    fn request(
        &self,
        target: &Target,
        path: &str,
        body: Option<Zeroizing<String>>,
    ) -> Result<Value, ProviderFailure> {
        let token_path = std::path::Path::new(&target.namespace.access_token_file);
        let metadata = fs::symlink_metadata(token_path).map_err(|_| ProviderFailure::Refused)?;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
        if !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > 8192
        {
            return Err(ProviderFailure::Refused);
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(token_path)
            .map_err(|_| ProviderFailure::Refused)?;
        let opened = file.metadata().map_err(|_| ProviderFailure::Refused)?;
        if !opened.is_file()
            || opened.permissions().mode() & 0o077 != 0
            || opened.ino() != metadata.ino()
            || opened.dev() != metadata.dev()
            || opened.nlink() != 1
        {
            return Err(ProviderFailure::Refused);
        }
        let mut token = Zeroizing::new(String::new());
        file.take(8193)
            .read_to_string(&mut token)
            .map_err(|_| ProviderFailure::Refused)?;
        if token.len() > 8192 {
            return Err(ProviderFailure::Refused);
        }
        let token = token.trim_end_matches(['\r', '\n']);
        if token.is_empty() || token.len() > 8192 || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ProviderFailure::Refused);
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| ProviderFailure::Refused)?;
        let mut authorization = header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| ProviderFailure::Refused)?;
        authorization.set_sensitive(true);
        let endpoint = format!("{}{path}", self.origin);
        let request = match &body {
            Some(body) => client
                .post(endpoint)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.as_bytes().to_vec()),
            None => client.get(endpoint),
        };
        let response = request
            .header(header::AUTHORIZATION, authorization)
            .header(header::ACCEPT, "application/json")
            .send()
            .map_err(|_| ProviderFailure::Unknown)?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                400 | 401 | 403 | 404 | 409 | 412 => ProviderFailure::Refused,
                _ => ProviderFailure::Unknown,
            });
        }
        if !response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(';').next() == Some("application/json"))
        {
            return Err(ProviderFailure::Unknown);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take(16_385)
            .read_to_end(&mut bytes)
            .map_err(|_| ProviderFailure::Unknown)?;
        if bytes.len() > 16_384 {
            return Err(ProviderFailure::Unknown);
        }
        crate::json::decode(&bytes).map_err(|_| ProviderFailure::Unknown)
    }

    fn scope_label(target: &Target) -> String {
        day2_capabilities::Digest::new(target.scope().as_bytes()).as_str()[7..63].into()
    }

    fn selected(&self, target: &Target, value: &Value) -> bool {
        value["name"].as_str() == Some(&target.resource())
            && value["labels"]["day2_scope"].as_str() == Some(Self::scope_label(target).as_str())
    }
}

impl Provider for Gcp {
    fn create(&self, target: &Target, request_id: &str) -> Result<(), ProviderFailure> {
        let resource = target.resource();
        let (_, secret_id) = resource.rsplit_once('/').ok_or(ProviderFailure::Refused)?;
        let path = format!(
            "/v1/projects/{}/secrets?secretId={secret_id}",
            target.namespace.project_number
        );
        let request_digest = day2_capabilities::Digest::new(request_id.as_bytes());
        let request_label = &request_digest.as_str()[7..47];
        let body = Zeroizing::new(json!({"replication":{"automatic":{}},"labels":{"day2_scope":Self::scope_label(target),"day2_request":request_label}}).to_string());
        let result = self.request(target, &path, Some(body))?;
        if !self.selected(target, &result)
            || result["labels"]["day2_request"].as_str() != Some(request_label)
        {
            return Err(ProviderFailure::Unknown);
        }
        Ok(())
    }

    fn add_version(&self, target: &Target, value: &[u8]) -> Result<u64, ProviderFailure> {
        let resource = target.resource();
        let current = self
            .request(target, &format!("/v1/{resource}"), None)
            .map_err(|_| ProviderFailure::Refused)?;
        if !self.selected(target, &current) {
            return Err(ProviderFailure::Refused);
        }
        let encoded = Zeroizing::new(STANDARD.encode(value));
        // Do not build a serde Value containing the payload: its allocations
        // cannot be zeroized. Base64 has no JSON-escaping characters.
        let body = Zeroizing::new(format!(
            "{{\"payload\":{{\"data\":\"{}\",\"dataCrc32c\":\"{}\"}}}}",
            encoded.as_str(),
            crc32c::crc32c(value)
        ));
        let result = self.request(target, &format!("/v1/{resource}:addVersion"), Some(body))?;
        let prefix = format!("{resource}/versions/");
        let number = result["name"]
            .as_str()
            .and_then(|name| name.strip_prefix(&prefix))
            .ok_or(ProviderFailure::Unknown)?;
        let version = number
            .parse::<u64>()
            .map_err(|_| ProviderFailure::Unknown)?;
        if version == 0 || version.to_string() != number || result["state"] != "ENABLED" {
            return Err(ProviderFailure::Unknown);
        }
        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write as _,
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
    };

    struct Server {
        origin: String,
        requests: Arc<Mutex<Vec<String>>>,
        join: Option<thread::JoinHandle<()>>,
    }
    impl Server {
        fn start(replies: Vec<(u16, String)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let captured = requests.clone();
            let join = thread::spawn(move || {
                for (status, body) in replies {
                    let (mut socket, _) = listener.accept().unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let mut end = None;
                    loop {
                        let mut chunk = [0; 4096];
                        let count = socket.read(&mut chunk).unwrap();
                        assert!(count > 0);
                        bytes.extend_from_slice(&chunk[..count]);
                        if end.is_none()
                            && let Some(index) =
                                bytes.windows(4).position(|part| part == b"\r\n\r\n")
                        {
                            let headers = String::from_utf8_lossy(&bytes[..index]);
                            let length = headers
                                .lines()
                                .find_map(|line| {
                                    line.split_once(':')
                                        .filter(|(key, _)| {
                                            key.eq_ignore_ascii_case("content-length")
                                        })
                                        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            end = Some(index + 4 + length);
                        }
                        if end.is_some_and(|end| bytes.len() >= end) {
                            break;
                        }
                        assert!(bytes.len() <= 131_072);
                    }
                    captured
                        .lock()
                        .unwrap()
                        .push(String::from_utf8(bytes).unwrap());
                    write!(socket, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                }
            });
            Self {
                origin,
                requests,
                join: Some(join),
            }
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            if let Some(join) = self.join.take() {
                join.join().unwrap();
            }
        }
    }

    fn target(directory: &std::path::Path) -> Target {
        let file = directory.join("token");
        use std::os::unix::fs::PermissionsExt as _;
        fs::write(&file, "synthetic-private-bearer").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        Target {
            namespace: super::super::Namespace {
                project_number: 123_456.try_into().unwrap(),
                access_token_file: file.to_string_lossy().into(),
            },
            scope: "company/test/reports".into(),
            name: "API_KEY".into(),
        }
    }
    fn metadata(target: &Target, id: &str) -> Value {
        json!({"name":target.resource(),"labels":{"day2_scope":Gcp::scope_label(target),"day2_request":&day2_capabilities::Digest::new(id.as_bytes()).as_str()[7..47]}})
    }

    #[test]
    fn actual_http_create_and_version_add_bind_scope_resource_and_checksum() {
        let directory = tempfile::tempdir().unwrap();
        let target = target(directory.path());
        let metadata = metadata(&target, "create-1");
        let server = Server::start(vec![
            (200, metadata.to_string()),
            (200, metadata.to_string()),
            (
                200,
                json!({"name":format!("{}/versions/1", target.resource()),"state":"ENABLED"})
                    .to_string(),
            ),
        ]);
        let provider = Gcp {
            origin: server.origin.clone(),
        };
        assert!(provider.create(&target, "create-1").is_ok());
        assert_eq!(provider.add_version(&target, b"123456789").unwrap(), 1);
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with("POST /v1/projects/123456/secrets?secretId=day2-"));
        assert!(requests[1].starts_with(&format!("GET /v1/{} ", target.resource())));
        assert!(requests[2].starts_with(&format!("POST /v1/{}:addVersion ", target.resource())));
        let payload: Value =
            serde_json::from_str(requests[2].split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(payload["payload"]["data"], "MTIzNDU2Nzg5");
        assert_eq!(payload["payload"]["dataCrc32c"], "3808858755");
    }

    #[test]
    fn malformed_wrong_resource_and_uncertain_write_responses_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let target = target(directory.path());
        for response in [
            json!({"name":"projects/other/secrets/foreign"}).to_string(),
            "{\"name\":\"first\",\"name\":\"second\"}".into(),
            "not-json".into(),
        ] {
            let server = Server::start(vec![(200, response)]);
            let provider = Gcp {
                origin: server.origin.clone(),
            };
            assert!(matches!(
                provider.create(&target, "create-1"),
                Err(ProviderFailure::Unknown)
            ));
        }
        let server = Server::start(vec![(
            200,
            json!({"name":"projects/other/secrets/foreign"}).to_string(),
        )]);
        let provider = Gcp {
            origin: server.origin.clone(),
        };
        assert!(matches!(
            provider.add_version(&target, b"never-dispatch-this"),
            Err(ProviderFailure::Refused)
        ));
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        for (status, expected_unknown) in [(403, false), (409, false), (500, true), (429, true)] {
            let server = Server::start(vec![(status, "{}".into())]);
            let provider = Gcp {
                origin: server.origin.clone(),
            };
            let result = provider.create(&target, "create-1");
            assert!(if expected_unknown {
                matches!(result, Err(ProviderFailure::Unknown))
            } else {
                matches!(result, Err(ProviderFailure::Refused))
            });
        }
    }

    #[test]
    fn token_files_are_private_regular_bounded_and_never_discovered() {
        let directory = tempfile::tempdir().unwrap();
        let mut target = target(directory.path());
        let provider = Gcp::default();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(
            &target.namespace.access_token_file,
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            provider.create(&target, "x"),
            Err(ProviderFailure::Refused)
        ));
        fs::set_permissions(
            &target.namespace.access_token_file,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(&target.namespace.access_token_file, vec![b'x'; 8193]).unwrap();
        assert!(matches!(
            provider.create(&target, "x"),
            Err(ProviderFailure::Refused)
        ));
        let symlink = directory.path().join("symlink");
        std::os::unix::fs::symlink(&target.namespace.access_token_file, &symlink).unwrap();
        target.namespace.access_token_file = symlink.to_string_lossy().into();
        assert!(matches!(
            provider.create(&target, "x"),
            Err(ProviderFailure::Refused)
        ));
    }
}
