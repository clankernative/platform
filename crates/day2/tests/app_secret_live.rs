//! Explicitly opted-in provider canaries. Only run-created synthetic secrets are read or deleted.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2::{
    app_secrets::{self, Gcp, Operation, State, Write},
    store::Runtime,
};
use reqwest::{blocking::Client, redirect::Policy};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fs, path::PathBuf, time::Duration};
use zeroize::Zeroizing;

const FIRST: &[u8] = b"day2 synthetic canary first value\n";
const SECOND: &[u8] = b"day2 synthetic canary replacement value\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    project_number: std::num::NonZeroU64,
    access_token_file: String,
    apps: Vec<String>,
    allow_create_rotate_read_and_delete_test_secrets: bool,
}

struct Canary {
    _directory: tempfile::TempDir,
    runtime: Runtime,
    client: Client,
    resource: String,
    scope_label: String,
    request_label: String,
    cleanup_required: bool,
    native_delete_attempted: bool,
}

impl Canary {
    fn open(profile: &Profile, app: &str) -> Result<Self> {
        ensure!(
            profile.apps.iter().any(|approved| approved == app),
            "unapproved canary app"
        );
        let artifact = PathBuf::from(
            std::env::var_os("DAY2_TEST_OWNED_PROBE_ARTIFACT")
                .context("owned probe artifact required")?,
        );
        let directory = tempfile::tempdir()?;
        let mut nonce = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
            .map_err(|_| anyhow::anyhow!("canary entropy unavailable"))?;
        let nonce = &day2::digest(&nonce)[7..31];
        let installation = format!("secret_canary_{nonce}");
        let policy: Value = serde_json::from_str(include_str!(
            "../../../fixtures/authority-policies/owned-links.json"
        ))?;
        let instance = directory.path().join("instance.json");
        fs::write(
            &instance,
            serde_json::to_vec(&json!({
                "installation":installation,"environment":"qualification","apps":{app:{
                    "artifact":artifact,"readers":[],"writers":["admin"],"authority":policy,
                    "managed_secrets":{"project_number":profile.project_number,"access_token_file":profile.access_token_file}
                }}
            }))?,
        )?;
        let runtime = Runtime::load(&instance, app)?;
        runtime.initialize()?;
        let resource = format!(
            "projects/{}/secrets/{}{}",
            profile.project_number,
            day2_capabilities::app_secrets::prefix(runtime.scope()),
            &day2_capabilities::Digest::of(&(
                "app-secret-container-v2",
                runtime.scope(),
                "canary",
                "canary-create"
            ))?
            .as_str()[7..39]
        );
        let token = Zeroizing::new(fs::read_to_string(&profile.access_token_file)?);
        let mut bearer =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.trim_end()))?;
        bearer.set_sensitive(true);
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(15))
            .default_headers(reqwest::header::HeaderMap::from_iter([(
                reqwest::header::AUTHORIZATION,
                bearer,
            )]))
            .build()?;
        let absent = client
            .get(format!(
                "https://secretmanager.googleapis.com/v1/{resource}"
            ))
            .send()?;
        ensure!(
            absent.status().as_u16() == 404,
            "canary resource must be absent before creation"
        );
        let scope_label = day2::digest(runtime.scope().as_bytes())[7..63].into();
        let request_label = day2::digest(b"canary-create")[7..47].into();
        Ok(Self {
            _directory: directory,
            runtime,
            client,
            resource,
            scope_label,
            request_label,
            cleanup_required: false,
            native_delete_attempted: false,
        })
    }

    fn write(&mut self, operation: Operation) -> Result<()> {
        // Arm cleanup before any dispatch, including a lost create acknowledgement.
        self.cleanup_required = true;
        let rotate = operation == Operation::Rotate;
        let receipt = app_secrets::write(
            &self.runtime,
            "admin",
            &Write {
                operation,
                name: "canary".into(),
                request_id: if rotate {
                    "canary-rotate"
                } else {
                    "canary-create"
                }
                .into(),
                expected_authority: app_secrets::list(&self.runtime, "admin")?.authority,
                expected_version: rotate.then_some(1),
                expected_incarnation: if rotate {
                    app_secrets::list(&self.runtime, "admin")?
                        .secrets
                        .first()
                        .map(|e| e.incarnation.clone())
                } else {
                    None
                },
                value: Zeroizing::new(if rotate { SECOND } else { FIRST }.to_vec()),
            },
            &Gcp::default(),
        )?;
        ensure!(
            receipt.state == State::Stored
                && receipt.version == Some(if rotate { 2 } else { 1 })
                && !receipt.activation_performed,
            "canary storage not confirmed"
        );
        Ok(())
    }

    fn read(&self, version: u64, expected: &[u8]) -> Result<()> {
        let listed = app_secrets::list(&self.runtime, "admin")?;
        if let Some(entry) = listed
            .secrets
            .first()
            .filter(|entry| entry.version == Some(version))
        {
            let actual = app_secrets::reveal(
                &self.runtime,
                "admin",
                &app_secrets::Selection {
                    name: "canary".into(),
                    incarnation: entry.incarnation.clone(),
                    version,
                    expected_authority: listed.authority,
                    request_id: format!("canary-reveal-current-{version}"),
                },
                &Gcp::default(),
            )?;
            ensure!(
                actual.as_slice() == expected,
                "native owner disclosure differs"
            );
        }
        // Independently inspect both immutable provider versions after rotation.

        let name = format!("{}/versions/{version}", self.resource);
        let response = self
            .client
            .get(format!(
                "https://secretmanager.googleapis.com/v1/{name}:access"
            ))
            .send()?;
        ensure!(
            response.status().is_success(),
            "synthetic canary readback refused"
        );
        let body: Value = response.json()?;
        ensure!(body["name"] == name, "canary readback resource mismatch");
        let actual = Zeroizing::new(
            STANDARD.decode(
                body["payload"]["data"]
                    .as_str()
                    .context("canary payload missing")?,
            )?,
        );
        ensure!(&actual[..] == expected, "synthetic canary readback differs");
        ensure!(
            body["payload"]["dataCrc32c"].as_str()
                == Some(crc32c::crc32c(expected).to_string().as_str()),
            "canary CRC mismatch"
        );
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.cleanup_required {
            return Ok(());
        }
        if !self.native_delete_attempted {
            let listed = app_secrets::list(&self.runtime, "admin")?;
            if let Some(entry) = listed
                .secrets
                .first()
                .filter(|entry| entry.container_created && !entry.blocked)
            {
                self.native_delete_attempted = true;
                let receipt = app_secrets::write(
                    &self.runtime,
                    "admin",
                    &Write {
                        operation: Operation::Delete,
                        name: "canary".into(),
                        request_id: "canary-delete".into(),
                        expected_authority: listed.authority,
                        expected_version: entry.version,
                        expected_incarnation: Some(entry.incarnation.clone()),
                        value: Zeroizing::new(Vec::new()),
                    },
                    &Gcp::default(),
                )?;
                ensure!(
                    receipt.state == State::Deleted && !receipt.activation_performed,
                    "native deletion not confirmed"
                );
            }
        }
        // Failure cleanup retains its independent exact scope/create-label/ETag
        // guard; it never retries a provider version write or the native request.
        let url = format!("https://secretmanager.googleapis.com/v1/{}", self.resource);
        let response = self.client.get(&url).send()?;
        if response.status().as_u16() == 404 {
            self.cleanup_required = false;
            eprintln!("synthetic canary cleanup=404 app={}", self.runtime.app());
            return Ok(());
        }
        ensure!(
            response.status().is_success(),
            "canary cleanup metadata unavailable"
        );
        let body: Value = response.json()?;
        ensure!(
            body["name"] == self.resource
                && body["labels"]["day2_scope"] == self.scope_label
                && body["labels"]["day2_request"] == self.request_label,
            "refuse cleanup of a resource without this run's exact labels"
        );
        let etag = body["etag"]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("canary cleanup requires etag")?;
        let removed = self.client.delete(&url).query(&[("etag", etag)]).send()?;
        ensure!(
            removed.status().is_success(),
            "canary deletion not confirmed"
        );
        ensure!(
            self.client.get(&url).send()?.status().as_u16() == 404,
            "canary still exists after deletion"
        );
        self.cleanup_required = false;
        eprintln!(
            "synthetic secret canary: create=1 rotate=2 readback=verified cleanup=404 app={}",
            self.runtime.app()
        );
        Ok(())
    }
}

impl Drop for Canary {
    fn drop(&mut self) {
        if self.cleanup_required && self.cleanup().is_err() {
            eprintln!("CANARY CLEANUP REQUIRED: {}", self.resource);
        }
    }
}

#[test]
#[ignore = "live writes: requires an explicit private profile and cleanup permission"]
fn create_rotate_readback_and_delete_synthetic_secrets() -> Result<()> {
    let path = PathBuf::from(
        std::env::var_os("DAY2_APP_SECRET_LIVE_PROFILE")
            .context("private live profile required")?,
    );
    let profile: Profile = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        profile.allow_create_rotate_read_and_delete_test_secrets
            && !profile.apps.is_empty()
            && profile.apps.len() <= 8,
        "explicit bounded canary authorization required"
    );
    let mut canary: Option<Canary> = None;
    day2::automation::run(
        &day2::automation::runner()?,
        &["app-secret-canary"],
        |call| {
            let result = match call.action.as_str() {
                "secret-canary-settings" => json!({"apps":profile.apps}),
                "secret-canary-open" => {
                    ensure!(canary.is_none(), "prior canary has not been cleaned up");
                    let app: Value = serde_json::from_str(&call.input)?;
                    canary = Some(Canary::open(
                        &profile,
                        app["app_name"].as_str().context("canary app missing")?,
                    )?);
                    json!({})
                }
                action => {
                    let current = canary.as_mut().context("canary not open")?;
                    match action {
                        "secret-canary-create" => current.write(Operation::Create)?,
                        "secret-canary-read-first" => current.read(1, FIRST)?,
                        "secret-canary-rotate" => current.write(Operation::Rotate)?,
                        "secret-canary-read-both" => {
                            current.read(1, FIRST)?;
                            current.read(2, SECOND)?;
                        }
                        "secret-canary-cleanup" => {
                            current.cleanup()?;
                            canary = None;
                        }
                        _ => anyhow::bail!("unknown canary action"),
                    }
                    json!({})
                }
            };
            Ok(result)
        },
    )?;
    ensure!(canary.is_none(), "canary recipe did not finish cleanup");
    // Do not treat this as qualification of hosted IAP, OS stores or app activation.
    Ok(())
}
