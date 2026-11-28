//! App CI's results bucket, read side (docs/INSTANCE.md, "App CI"): what a
//! candidate build reads of `gs://<project>-<id>-ci` with the apply identity,
//! which holds only object read access there, and what `ci reuse` reads with
//! the push run's federated read-only token.
//!
//! Each read is one JSON API request under one explicit total deadline, so
//! repeated blocking reads cannot renew it, and each reply is closed data: an
//! object's projected fields or one page of names, bounded and decoded
//! exactly, or exactly the bytes asked for. No reply or transport text enters
//! an error, and the token is held in memory only. A failed connection, a
//! timeout, a short or unreadable body, 408, 429 and 5xx are retryable;
//! absence is reported as absence; any other answer is a refusal.
use crate::instance_source::{Retryable, TEMPORARY};
use anyhow::{Context, Result, anyhow, bail, ensure};
use reqwest::Url;
use serde::Deserialize;
use std::{collections::BTreeMap, io::Read, path::PathBuf, process::Command, time::Duration};
use zeroize::Zeroizing;

/// The JSON API every read goes to.
pub const API: &str = "https://storage.googleapis.com/storage/v1";

/// The total deadline of one metadata read and of one object download.
const DESCRIBE: Duration = Duration::from_secs(60);
const DOWNLOAD: Duration = Duration::from_secs(900);

/// The most a metadata reply may hold.
const REPLY_LIMIT: u64 = 16_384;

/// The fields a metadata read selects, and nothing else.
const FIELDS: &str = "name,bucket,generation,size,timeCreated,metadata";

/// The fields a list read selects: each name and the next page's token.
const LIST_FIELDS: &str = "items(name),nextPageToken";

/// The most names one list page asks for, and the most its reply may hold.
pub const PAGE: u64 = 1000;
const LIST_LIMIT: u64 = 524_288;

/// The longest page token a list reply may hand back.
const TOKEN_LIMIT: usize = 1024;

/// One page of object names under a prefix, in the bucket's name order, and
/// the token of the next page when there is one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    pub names: Vec<String>,
    pub next: Option<String>,
}

/// One stored object, as its projected metadata describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    pub generation: String,
    pub size: u64,
    /// The server-set creation time: RFC 3339, UTC.
    pub time_created: String,
    /// The object's custom metadata; empty when it has none.
    pub metadata: BTreeMap<String, String>,
}

/// The results bucket. Tests substitute a fake. Given `within`, a read must
/// finish within the lesser of it and its own deadline.
pub trait Storage {
    /// The object's projected metadata, or nothing when it does not exist.
    fn object(
        &mut self,
        bucket: &str,
        name: &str,
        within: Option<Duration>,
    ) -> Result<Option<Stored>>;
    /// The object's bytes at exactly `generation`, which must be exactly
    /// `size` bytes.
    fn media(
        &mut self,
        bucket: &str,
        name: &str,
        generation: &str,
        size: u64,
        within: Option<Duration>,
    ) -> Result<Vec<u8>>;
    /// One page of at most [`PAGE`] names below `prefix`, after the page
    /// `page` names. Every name starts with `prefix`; the caller bounds the
    /// pages it reads.
    fn list(
        &mut self,
        bucket: &str,
        prefix: &str,
        page: Option<&str>,
        within: Option<Duration>,
    ) -> Result<Listing>;
}

/// A read's deadline: its own, or the caller's bound when that is sooner.
fn bounded(own: Duration, within: Option<Duration>) -> Duration {
    within.map_or(own, |within| within.min(own))
}

/// The JSON API over rustls, HTTPS only, no redirects, no proxy, with the
/// apply identity's access token from `gcloud auth print-access-token`, or a
/// token the caller already holds. The client and the token are made once,
/// when the first object is read, so a session that reads none (any without
/// forge.oidc) makes neither.
pub struct Gcs {
    https_only: bool,
    client: Option<reqwest::blocking::Client>,
    endpoint: Url,
    token: Option<Zeroizing<String>>,
    /// The total deadline of one metadata read and of one download.
    describe: Duration,
    download: Duration,
}

impl Gcs {
    pub fn native() -> Result<Self> {
        Self::build(API, true, None)
    }

    /// The JSON API with an access token the caller holds, such as `ci
    /// reuse`'s federated read-only token; gcloud is never run.
    pub fn with_token(token: String) -> Result<Self> {
        Self::build(API, true, Some(token))
    }

    fn build(endpoint: &str, https_only: bool, token: Option<String>) -> Result<Self> {
        Ok(Self {
            https_only,
            client: None,
            endpoint: Url::parse(endpoint)?,
            token: token.map(Zeroizing::new),
            describe: DESCRIBE,
            download: DOWNLOAD,
        })
    }

    fn client(&mut self) -> Result<reqwest::blocking::Client> {
        if self.client.is_none() {
            self.client = Some(
                reqwest::blocking::Client::builder()
                    .no_proxy()
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(DOWNLOAD)
                    .redirect(reqwest::redirect::Policy::none())
                    .https_only(self.https_only)
                    .build()
                    .context("app CI results HTTP client")?,
            );
        }
        self.client.clone().context("app CI results HTTP client")
    }

    fn token(&mut self) -> Result<String> {
        if self.token.is_none() {
            let gcloud: PathBuf = crate::maintenance::on_path("gcloud")?;
            let printed = crate::maintenance::bounded(
                Command::new(gcloud).args(["auth", "print-access-token"]),
                None,
                Duration::from_secs(60),
                None,
            )
            .map_err(|_| anyhow!("the apply identity's access token could not be read"))?;
            let token = printed.trim().to_owned();
            ensure!(
                !token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic()),
                "the apply identity's access token is malformed"
            );
            self.token = Some(Zeroizing::new(token));
        }
        Ok(self.token.as_deref().cloned().unwrap_or_default())
    }

    /// `<endpoint>/b/<bucket>/o/<name>`, the name one encoded path segment.
    fn url(&self, bucket: &str, name: &str) -> Result<Url> {
        let mut url = self.endpoint.clone();
        url.path_segments_mut()
            .map_err(|()| anyhow!("app CI results URL"))?
            .extend(["b", bucket, "o", name]);
        Ok(url)
    }

    fn get(&mut self, url: Url, timeout: Duration) -> Result<reqwest::blocking::Response> {
        let token = Zeroizing::new(self.token()?);
        let header = Zeroizing::new(format!("Bearer {}", token.as_str()));
        let mut value = reqwest::header::HeaderValue::from_str(&header)
            .map_err(|_| anyhow!("the apply identity's access token is malformed"))?;
        value.set_sensitive(true);
        // The deadline is the request's own total, which blocking body reads cannot renew. No transport error is
        // formatted: it names the URL.
        let client: reqwest::blocking::Client = self.client()?;
        let sent = client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, value)
            .timeout(timeout)
            .send();
        match sent {
            Ok(response) => Ok(response),
            Err(error) if error.is_builder() => bail!("invalid app CI results request"),
            Err(_) => Err(Retryable(TEMPORARY).into()),
        }
    }
}

/// The projection `LIST_FIELDS` selects; either key is absent when empty.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Page {
    #[serde(default)]
    items: Vec<Named>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Named {
    name: String,
}

/// A page token as GCS hands it back: bounded, printable, never blank.
fn page_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= TOKEN_LIMIT && token.bytes().all(|b| b.is_ascii_graphic())
}

/// The projection `FIELDS` selects; `metadata` is absent when an object has none.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Projected {
    name: String,
    bucket: String,
    generation: String,
    size: String,
    time_created: String,
    #[serde(default)]
    metadata: Option<BTreeMap<String, String>>,
}

/// A decimal string without a sign or leading zero, as GCS writes its integers.
pub fn decimal(value: &str) -> Option<u64> {
    let parsed: u64 = value
        .bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| value.parse().ok())
        .flatten()?;
    (parsed.to_string() == value).then_some(parsed)
}

/// A refusal for any status but success: retryable for 408, 429 and 5xx.
fn refused(status: u16) -> anyhow::Error {
    match status {
        408 | 429 | 500.. => Retryable(TEMPORARY).into(),
        _ => anyhow!("app_ci_results_http_{status}"),
    }
}

/// At most `limit` bytes of a body; a longer one is a refusal, an unreadable
/// or short one retryable.
fn body(response: reqwest::blocking::Response, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    response
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::Error::from(Retryable(TEMPORARY)))?;
    ensure!(
        bytes.len() as u64 <= limit,
        "app_ci_results_reply_too_large"
    );
    Ok(bytes)
}

impl Storage for Gcs {
    fn object(
        &mut self,
        bucket: &str,
        name: &str,
        within: Option<Duration>,
    ) -> Result<Option<Stored>> {
        let mut url = self.url(bucket, name)?;
        url.query_pairs_mut().append_pair("fields", FIELDS);
        let response = self.get(url, bounded(self.describe, within))?;
        match response.status().as_u16() {
            200 => {}
            404 => return Ok(None),
            status => return Err(refused(status)),
        }
        let raw = body(response, REPLY_LIMIT)?;
        let projected: Projected = day2::json::decode(&raw)
            .ok()
            .and_then(|value: serde_json::Value| serde_json::from_value(value).ok())
            .context("app_ci_results_reply_invalid")?;
        let generation = decimal(&projected.generation).filter(|generation| *generation > 0);
        let size = decimal(&projected.size);
        ensure!(
            projected.name == name
                && projected.bucket == bucket
                && generation.is_some()
                && size.is_some()
                && crate::instance_source::app_ci::gcs_seconds(&projected.time_created).is_some(),
            "app_ci_results_reply_invalid"
        );
        Ok(Some(Stored {
            generation: projected.generation,
            size: size.unwrap_or_default(),
            time_created: projected.time_created,
            metadata: projected.metadata.unwrap_or_default(),
        }))
    }

    fn media(
        &mut self,
        bucket: &str,
        name: &str,
        generation: &str,
        size: u64,
        within: Option<Duration>,
    ) -> Result<Vec<u8>> {
        let mut url = self.url(bucket, name)?;
        url.query_pairs_mut()
            .append_pair("alt", "media")
            .append_pair("generation", generation);
        let response = self.get(url, bounded(self.download, within))?;
        match response.status().as_u16() {
            200 => {}
            status => return Err(refused(status)),
        }
        let bytes = body(response, size)?;
        if bytes.len() as u64 != size {
            bail!(Retryable(TEMPORARY));
        }
        Ok(bytes)
    }

    fn list(
        &mut self,
        bucket: &str,
        prefix: &str,
        page: Option<&str>,
        within: Option<Duration>,
    ) -> Result<Listing> {
        ensure!(
            !prefix.is_empty() && page.is_none_or(page_token),
            "invalid app CI results listing"
        );
        let mut url = self.endpoint.clone();
        url.path_segments_mut()
            .map_err(|()| anyhow!("app CI results URL"))?
            .extend(["b", bucket, "o"]);
        url.query_pairs_mut()
            .append_pair("prefix", prefix)
            .append_pair("fields", LIST_FIELDS)
            .append_pair("maxResults", &PAGE.to_string());
        if let Some(page) = page {
            url.query_pairs_mut().append_pair("pageToken", page);
        }
        let response = self.get(url, bounded(self.describe, within))?;
        match response.status().as_u16() {
            200 => {}
            status => return Err(refused(status)),
        }
        let raw = body(response, LIST_LIMIT)?;
        let page: Page = day2::json::decode(&raw)
            .ok()
            .and_then(|value: serde_json::Value| serde_json::from_value(value).ok())
            .context("app_ci_results_reply_invalid")?;
        let names: Vec<String> = page.items.into_iter().map(|item| item.name).collect();
        ensure!(
            names.len() as u64 <= PAGE
                && names.iter().all(|name| name.starts_with(prefix))
                && page.next_page_token.as_deref().is_none_or(page_token),
            "app_ci_results_reply_invalid"
        );
        Ok(Listing {
            names,
            next: page.next_page_token,
        })
    }
}

#[cfg(test)]
mod tests;
