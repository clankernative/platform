//! Copy a verified backup bundle to Google Cloud Storage, one object per file.
//!
//! Used by `day2-backup --upload-gcs` in the runtime image (scheduled GKE
//! backups). The credential is the pod's Workload Identity access token from
//! the GKE metadata server; there is no key. Every object is a JSON API media
//! upload with `ifGenerationMatch=0`, so an existing object is never replaced
//! (the uploader identity may only create objects anyway). Files are streamed,
//! and each response must be a success naming the object with the file's exact
//! size. The `COMPLETE` marker is written last and lists every object: a prefix
//! without it is a partial upload, never a backup. Nothing is retried; a
//! failed run leaves an incomplete prefix and the next run uses a new one.
use anyhow::{Context, Result, bail, ensure};
use reqwest::{
    Url,
    blocking::{Body, Client},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
pub const GCS_UPLOAD_URL: &str = "https://storage.googleapis.com/upload/storage/v1";
pub const COMPLETE: &str = "COMPLETE";

const MAX_FILES: usize = 4096;
const MAX_DEPTH: usize = 10;

/// Where the token and the uploads go. `day2-backup` always uses
/// [`Endpoints::google`]; tests pass a local mock.
pub struct Endpoints {
    pub metadata_token: String,
    pub upload: String,
}

impl Endpoints {
    pub fn google() -> Self {
        Self {
            metadata_token: METADATA_TOKEN_URL.into(),
            upload: GCS_UPLOAD_URL.into(),
        }
    }
}

/// A GCS bucket name without dots (3-63 lowercase letters, digits, `-`, `_`).
pub fn validate_bucket(bucket: &str) -> Result<()> {
    let bytes = bucket.as_bytes();
    ensure!(
        (3..=63).contains(&bytes.len())
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && !bucket.starts_with("goog"),
        "invalid GCS bucket name"
    );
    Ok(())
}

/// `/`-separated segments of ASCII letters, digits, `-` and `_`.
pub fn validate_prefix(prefix: &str) -> Result<()> {
    ensure!(
        !prefix.is_empty()
            && prefix.len() <= 256
            && prefix.split('/').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            }),
        "object prefix must be /-separated segments of [A-Za-z0-9_-]"
    );
    Ok(())
}

/// `yyyymmddThhmmssZ` in UTC, e.g. `20260925T051700Z`.
pub fn utc_stamp(at: SystemTime) -> Result<String> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Howard Hinnant's civil_from_days, for days since 1970-01-01.
    let z = i64::try_from(days)? + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Ok(format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    ))
}

fn files(root: &Path, directory: &Path, depth: usize, found: &mut Vec<PathBuf>) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "backup directory depth");
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let kind = entry.file_type()?;
        if kind.is_dir() {
            files(root, &entry.path(), depth + 1, found)?;
        } else {
            ensure!(
                kind.is_file(),
                "backup symlinks and special files forbidden"
            );
            found.push(entry.path().strip_prefix(root)?.to_owned());
            ensure!(found.len() <= MAX_FILES, "backup file count");
        }
    }
    Ok(())
}

fn object_name(prefix: &str, relative: &Path) -> Result<String> {
    let mut name = prefix.to_owned();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            bail!("backup path component");
        };
        let part = part.to_str().context("backup file names must be UTF-8")?;
        ensure!(
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "unexpected backup file name {part}"
        );
        name.push('/');
        name.push_str(part);
    }
    Ok(name)
}

#[derive(Deserialize)]
struct Token {
    access_token: String,
    token_type: String,
}

fn access_token(client: &Client, url: &str) -> Result<String> {
    let response = client
        .get(url)
        .header("Metadata-Flavor", "Google")
        .timeout(Duration::from_secs(30))
        .send()
        .context("GKE metadata server unreachable")?;
    let status = response.status();
    ensure!(status.is_success(), "GKE metadata server returned {status}");
    let token: Token =
        serde_json::from_slice(&response.bytes()?).context("GKE metadata server token response")?;
    ensure!(
        token.token_type.eq_ignore_ascii_case("bearer")
            && !token.access_token.is_empty()
            && token.access_token.bytes().all(|b| b.is_ascii_graphic()),
        "GKE metadata server returned no usable access token"
    );
    Ok(token.access_token)
}

struct Uploader<'a> {
    client: Client,
    endpoint: Url,
    bucket: &'a str,
    token: String,
}

impl Uploader<'_> {
    fn put(&self, name: &str, body: Body, bytes: u64, content_type: &str) -> Result<Value> {
        let mut url = self.endpoint.clone();
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("GCS upload URL"))?
            .extend(["b", self.bucket, "o"]);
        url.query_pairs_mut()
            .append_pair("uploadType", "media")
            .append_pair("ifGenerationMatch", "0")
            .append_pair("name", name);
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .header("Content-Type", content_type)
            .body(body)
            .send()
            .with_context(|| format!("upload gs://{}/{name}", self.bucket))?;
        let status = response.status();
        ensure!(
            status.is_success(),
            "upload gs://{}/{name} returned {status}{}",
            self.bucket,
            if status.as_u16() == 412 {
                " (object already exists)"
            } else {
                ""
            }
        );
        let object: Value = serde_json::from_slice(&response.bytes()?)
            .with_context(|| format!("upload gs://{}/{name} response", self.bucket))?;
        ensure!(
            object["name"] == name
                && object["bucket"] == self.bucket
                && object["size"].as_str() == Some(bytes.to_string().as_str()),
            "gs://{}/{name} stored {} bytes as {}, expected {bytes}",
            self.bucket,
            object["size"],
            object["name"]
        );
        Ok(json!({"name":name,"bytes":bytes,"generation":object["generation"]}))
    }
}

/// Upload every file of `bundle` (a verified backup directory) as
/// `<prefix>/<relative path>`, then `<prefix>/COMPLETE` listing them.
pub fn upload_gcs(
    bundle: &Path,
    bucket: &str,
    prefix: &str,
    endpoints: &Endpoints,
) -> Result<Value> {
    validate_bucket(bucket)?;
    validate_prefix(prefix)?;
    ensure!(
        fs::symlink_metadata(bundle.join("backup.json"))?.is_file(),
        "upload requires a completed backup bundle"
    );
    let mut relative = Vec::new();
    files(bundle, bundle, 0, &mut relative)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(900))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let token = access_token(&client, &endpoints.metadata_token)?;
    let uploader = Uploader {
        client,
        endpoint: Url::parse(&endpoints.upload)?,
        bucket,
        token,
    };
    let mut objects = Vec::new();
    let mut total = 0_u64;
    for path in &relative {
        let name = object_name(prefix, path)?;
        let file = fs::File::open(bundle.join(path))?;
        let bytes = file.metadata()?.len();
        objects.push(uploader.put(
            &name,
            Body::sized(file, bytes),
            bytes,
            "application/octet-stream",
        )?);
        total += bytes;
    }
    let manifest = fs::read(bundle.join("backup.json"))?;
    let marker = serde_json::to_vec_pretty(&json!({
        "format": 1,
        "backup_json_sha256": day2::digest(&manifest),
        "objects": objects.iter().map(|object| json!({"name":object["name"],"bytes":object["bytes"]})).collect::<Vec<_>>(),
        "bytes": total,
    }))?;
    let marker_name = format!("{prefix}/{COMPLETE}");
    let marker_bytes = u64::try_from(marker.len())?;
    uploader.put(
        &marker_name,
        Body::from(marker),
        marker_bytes,
        "application/json",
    )?;
    Ok(json!({
        "bucket": bucket,
        "prefix": prefix,
        "objects": objects.len() + 1,
        "bytes": total + marker_bytes,
        "complete": format!("gs://{bucket}/{marker_name}"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Debug)]
    struct Seen {
        method: String,
        target: String,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    }

    enum Fault {
        None,
        Status(u16, String),
        WrongSize(String),
        TokenStatus(u16),
    }

    /// A minimal in-process HTTP/1.1 server standing in for both the GKE
    /// metadata server and the GCS JSON API.
    fn mock(fault: Fault) -> Result<(Endpoints, Arc<Mutex<Vec<Seen>>>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let base = format!("http://{}", listener.local_addr()?);
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
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_owned();
                let target = parts.next().unwrap_or_default().to_owned();
                let mut headers = BTreeMap::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap();
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                }
                let length: usize = headers
                    .get("content-length")
                    .map_or(0, |value| value.parse().unwrap());
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let request = Seen {
                    method,
                    target,
                    headers,
                    body,
                };
                let (status, response) = if request.target == "/token" {
                    match fault {
                        Fault::TokenStatus(status) => (status, String::new()),
                        _ => (
                            200,
                            r#"{"access_token":"test-token","expires_in":3599,"token_type":"Bearer"}"#
                                .into(),
                        ),
                    }
                } else {
                    let url = Url::parse(&format!("http://mock{}", request.target)).unwrap();
                    let name = url
                        .query_pairs()
                        .find(|(key, _)| key == "name")
                        .map(|(_, value)| value.into_owned())
                        .unwrap_or_default();
                    match &fault {
                        Fault::Status(status, failing) if name.ends_with(failing.as_str()) => {
                            (*status, "{}".into())
                        }
                        Fault::WrongSize(failing) if name.ends_with(failing.as_str()) => (
                            200,
                            json!({"name":name,"bucket":"example-backups","size":"1","generation":"7"})
                                .to_string(),
                        ),
                        _ => (
                            200,
                            json!({"name":name,"bucket":"example-backups",
                                "size":request.body.len().to_string(),"generation":"7"})
                            .to_string(),
                        ),
                    }
                };
                log.lock().unwrap().push(request);
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                );
            }
        });
        Ok((
            Endpoints {
                metadata_token: format!("{base}/token"),
                upload: format!("{base}/upload/storage/v1"),
            },
            seen,
        ))
    }

    fn bundle() -> Result<tempfile::TempDir> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        fs::write(root.join("backup.json"), br#"{"format":2}"#)?;
        fs::write(root.join("app.sqlite"), vec![7_u8; 300_000])?;
        fs::create_dir_all(root.join("providers"))?;
        fs::write(root.join("providers/notifications.sqlite"), b"provider")?;
        fs::create_dir_all(root.join("artifacts/abc/web"))?;
        fs::write(root.join("artifacts/abc/artifact.json"), b"{}")?;
        fs::write(root.join("artifacts/abc/web/app.css"), b"")?;
        Ok(directory)
    }

    fn query(seen: &Seen, key: &str) -> Option<String> {
        Url::parse(&format!("http://mock{}", seen.target))
            .unwrap()
            .query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
    }

    #[test]
    fn uploads_each_file_once_without_overwrite_and_marks_completion_last() -> Result<()> {
        let bundle = bundle()?;
        let (endpoints, seen) = mock(Fault::None)?;
        let summary = upload_gcs(
            bundle.path(),
            "example-backups",
            "app/20260925T051700Z",
            &endpoints,
        )?;
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[0].method, "GET");
        assert_eq!(seen[0].target, "/token");
        assert_eq!(seen[0].headers["metadata-flavor"], "Google");
        let uploads = &seen[1..];
        let names: Vec<_> = uploads.iter().map(|s| query(s, "name").unwrap()).collect();
        assert_eq!(
            names,
            [
                "app/20260925T051700Z/app.sqlite",
                "app/20260925T051700Z/artifacts/abc/artifact.json",
                "app/20260925T051700Z/artifacts/abc/web/app.css",
                "app/20260925T051700Z/backup.json",
                "app/20260925T051700Z/providers/notifications.sqlite",
                "app/20260925T051700Z/COMPLETE",
            ]
        );
        for upload in uploads {
            assert_eq!(upload.method, "POST");
            assert!(
                upload
                    .target
                    .starts_with("/upload/storage/v1/b/example-backups/o?")
            );
            assert_eq!(query(upload, "uploadType").as_deref(), Some("media"));
            assert_eq!(query(upload, "ifGenerationMatch").as_deref(), Some("0"));
            assert_eq!(upload.headers["authorization"], "Bearer test-token");
        }
        assert_eq!(uploads[0].body, vec![7_u8; 300_000]);
        assert_eq!(uploads[0].headers["content-length"], "300000");
        let marker: Value = serde_json::from_slice(&uploads[5].body)?;
        assert_eq!(marker["objects"].as_array().unwrap().len(), 5);
        assert_eq!(
            marker["backup_json_sha256"],
            day2::digest(br#"{"format":2}"#)
        );
        assert_eq!(summary["objects"], 6);
        assert_eq!(summary["bucket"], "example-backups");
        assert_eq!(summary["prefix"], "app/20260925T051700Z");
        assert_eq!(
            summary["bytes"],
            300_000 + 12 + 8 + 2 + uploads[5].body.len() as u64
        );
        Ok(())
    }

    #[test]
    fn a_refused_or_short_upload_fails_before_the_completion_marker() -> Result<()> {
        for (fault, expected) in [
            (
                Fault::Status(412, "backup.json".into()),
                "412 Precondition Failed (object already exists)",
            ),
            (Fault::Status(503, "app.sqlite".into()), "503"),
            (
                Fault::WrongSize("notifications.sqlite".into()),
                "stored \"1\" bytes",
            ),
        ] {
            let bundle = bundle()?;
            let (endpoints, seen) = mock(fault)?;
            let error = upload_gcs(bundle.path(), "example-backups", "app/x", &endpoints)
                .expect_err("a failed object upload must fail the backup");
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            let seen = seen.lock().unwrap();
            // Uploads stop at the failed object; the marker is never written.
            assert!(
                seen.iter()
                    .all(|s| query(s, "name").is_none_or(|name| !name.ends_with(COMPLETE)))
            );
        }
        let bundle = bundle()?;
        let (endpoints, seen) = mock(Fault::TokenStatus(404))?;
        let error = upload_gcs(bundle.path(), "example-backups", "app/x", &endpoints)
            .expect_err("no token, no upload");
        assert!(format!("{error:#}").contains("metadata server returned 404"));
        assert_eq!(seen.lock().unwrap().len(), 1);
        Ok(())
    }

    #[test]
    fn refuses_incomplete_bundles_bad_names_and_symlinks() -> Result<()> {
        let (endpoints, seen) = mock(Fault::None)?;
        let empty = tempfile::tempdir()?;
        assert!(upload_gcs(empty.path(), "example-backups", "app/x", &endpoints).is_err());
        let bundle = bundle()?;
        for prefix in ["", "/app", "app/", "app//x", "app x", "app/../x"] {
            assert!(upload_gcs(bundle.path(), "example-backups", prefix, &endpoints).is_err());
        }
        for bucket in ["gs://example", "a.b.c", "Example", "googbucket", "x"] {
            assert!(upload_gcs(bundle.path(), bucket, "app/x", &endpoints).is_err());
        }
        std::os::unix::fs::symlink("/etc/hostname", bundle.path().join("link"))?;
        assert!(upload_gcs(bundle.path(), "example-backups", "app/x", &endpoints).is_err());
        assert!(seen.lock().unwrap().is_empty());
        Ok(())
    }

    #[test]
    fn utc_stamps_are_calendar_correct() -> Result<()> {
        let at = |seconds| UNIX_EPOCH + Duration::from_secs(seconds);
        assert_eq!(utc_stamp(at(0))?, "19700101T000000Z");
        assert_eq!(utc_stamp(at(951_782_400))?, "20000229T000000Z");
        assert_eq!(utc_stamp(at(1_790_313_420))?, "20260925T051700Z");
        assert_eq!(utc_stamp(at(4_102_444_799))?, "20991231T235959Z");
        Ok(())
    }
}
