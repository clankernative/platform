//! Generated Roc metadata reads through ordinary admission, SQLite and HTTP.
use anyhow::{Context, Result, ensure};
use day2::{
    artifact::{Instance, LoadedArtifact},
    authority_state::{self, LocalOperator},
    protocol::Outcome,
    simulation::Simulation,
    store::{Fault, Runtime, replay},
    web::LocalServer,
};
use day2_capabilities::{BindingRef, Digest, Name, oauth::GrantCeiling};
use reqwest::{
    StatusCode,
    blocking::Client,
    header::{COOKIE, HOST, SET_COOKIE},
    redirect::Policy,
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use rusqlite::params;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::mpsc, thread, time::Duration};

use crate::support::compiler;

struct World {
    _directory: tempfile::TempDir,
    runtime: Runtime,
}

struct MetadataIapKeys(String);

impl day2::iap::KeySource for MetadataIapKeys {
    fn fetch(&self) -> Result<String> {
        Ok(self.0.clone())
    }
}

/// Real test-held signature, checked by the existing IAP verifier and session
/// path. These keys are not Google keys or a live browser/provider receipt.
fn metadata_iap(edge: &day2::artifact::Edge, domain: &str) -> Result<(String, String)> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let random = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
        .map_err(|_| anyhow::anyhow!("metadata IAP signing key"))?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &random)
        .map_err(|_| anyhow::anyhow!("metadata IAP key"))?;
    let point = pair.public_key().as_ref();
    let keys = json!({"keys":[{"kid":"metadata","kty":"EC","crv":"P-256","alg":"ES256",
        "x":URL_SAFE_NO_PAD.encode(&point[1..33]),"y":URL_SAFE_NO_PAD.encode(&point[33..65])}]})
    .to_string();
    let now: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .try_into()?;
    let claims = json!({"iss":day2::iap::ISSUER,"aud":edge.iap_audience,"iat":now,"exp":now+600,
        "sub":"accounts.google.com:google-bob","email":"bob@example.com","hd":domain});
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"metadata","typ":"JWT"}).to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = pair
        .sign(&random, signed.as_bytes())
        .map_err(|_| anyhow::anyhow!("metadata IAP signature"))?;
    Ok((
        keys,
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref())),
    ))
}

/// Canonical public fixture data, never a generated credential or entropy port.
fn metadata_selector(id: &str) -> String {
    let bytes = Sha256::digest(format!("credential-metadata-selector-v1:{id}"));
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &bytes[..16],
    )
}

#[test]
fn lifecycle_admission_rejects_unbound_or_ambiguous_management_intent() -> Result<()> {
    let path = PathBuf::from(
        std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
            .context("credential fixture required")?,
    );
    let artifact = LoadedArtifact::load(&path)?;
    for mutation in [
        "missing_lineage",
        "missing_head",
        "wrong_revision_type",
        "mixed_action",
        "ordinary_context",
        "unknown_family",
    ] {
        let mut contract = artifact.contract().clone();
        let access = &mut contract
            .app_contract
            .as_mut()
            .unwrap()
            .operations
            .get_mut("credential_metadata.rotate_client")
            .unwrap()
            .credential_access;
        match mutation {
            "missing_lineage" => access.management_lineage.clear(),
            "missing_head" => access.rotation_head.clear(),
            "wrong_revision_type" => access.rotation_revision = access.rotation_head.clone(),
            "mixed_action" => access.revocations = access.rotations.clone(),
            "ordinary_context" => access.interactive = false,
            "unknown_family" => access.rotations = vec!["unknown".into()],
            _ => unreachable!(),
        }
        assert!(
            contract
                .app_contract
                .as_ref()
                .unwrap()
                .validate(&contract)
                .is_err(),
            "accepted {mutation}"
        );
    }
    Ok(())
}

#[test]
fn ordinary_creation_refuses_credentials_before_output_and_verification_preserves_complete_selection()
-> Result<()> {
    use day2_capabilities::credentials::ManagementPredicate;
    let artifact_path = PathBuf::from(
        std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
            .context("credential fixture required")?,
    );
    let artifact = LoadedArtifact::load(&artifact_path)?;
    let directory = tempfile::tempdir()?;
    for explicit_actor in [false, true] {
        let output = directory.path().join(if explicit_actor {
            "ordinary-for"
        } else {
            "ordinary"
        });
        let result = if explicit_actor {
            day2::development::create_for(&artifact_path, &output, None, "alice@example.com")
        } else {
            day2::development::create(&artifact_path, &output, None)
        };
        let error = result
            .err()
            .context("ordinary credential creation was admitted")?;
        assert!(
            error
                .to_string()
                .contains("credential artifacts require explicit verification selection")
        );
        assert!(!output.exists());
    }
    let runtime = day2::development::create_verification_for(
        &artifact_path,
        &directory.path().join("verification"),
        None,
        "alice@example.com",
    )?;
    let original = Instance::load(runtime.instance_path())?;
    for mutation in ["runtime", "missing_epoch", "foreign_epoch", "wrong_alias"] {
        let mut invalid = original.clone();
        match mutation {
            "runtime" => invalid.credential_runtime = None,
            "missing_epoch" => invalid.control.as_mut().unwrap().security_epochs.clear(),
            "foreign_epoch" => {
                invalid
                    .control
                    .as_mut()
                    .unwrap()
                    .security_epochs
                    .values_mut()
                    .next()
                    .unwrap()
                    .scope
                    .environment = Name::try_from("foreign".to_owned())?
            }
            "wrong_alias" => {
                invalid
                    .apps
                    .get_mut("app")
                    .unwrap()
                    .credential_families
                    .values_mut()
                    .next()
                    .unwrap()
                    .epoch_store
                    .id = Name::try_from("foreign-epoch".to_owned())?
            }
            _ => unreachable!(),
        }
        assert!(
            day2::development::repin_credential_verification_data(&mut invalid, &artifact).is_err(),
            "{mutation}"
        );
    }
    let mut current = original.clone();
    current.identity.as_mut().unwrap().hosted_domain = "other.example.com".into();
    current.security_shell.as_mut().unwrap().origin = "https://security.other.example.com".into();
    current
        .apps
        .get_mut("app")
        .unwrap()
        .edge
        .as_mut()
        .unwrap()
        .origin = "https://app.other.example.com".into();
    current
        .resources
        .as_mut()
        .unwrap()
        .credentials
        .management
        .get_mut("client_keys")
        .unwrap()
        .read_metadata = ManagementPredicate::MemberOf {
        group: Name::try_from("managers".to_owned())?,
    };
    let expected = current.clone();
    day2::development::repin_credential_verification_data(&mut current, &artifact)?;
    let admitted = Instance::from_bytes(&serde_json::to_vec(&current)?)?;
    let old_epoch = original
        .control
        .as_ref()
        .unwrap()
        .security_epochs
        .values()
        .next()
        .unwrap();
    let epoch = admitted
        .control
        .as_ref()
        .unwrap()
        .security_epochs
        .values()
        .next()
        .unwrap();
    assert_eq!(epoch.scope, old_epoch.scope);
    assert_eq!(epoch.provider, old_epoch.provider);
    assert_eq!(epoch.max_lease_seconds, old_epoch.max_lease_seconds);
    assert_eq!(epoch.key_set, admitted.security_key_set("app")?);
    assert_eq!(
        admitted
            .resources
            .as_ref()
            .unwrap()
            .credentials
            .approved_authority,
        expected
            .resources
            .as_ref()
            .unwrap()
            .credentials
            .approved_authority
    );
    assert_eq!(
        admitted.resources.as_ref().unwrap().credentials.management["client_keys"].read_metadata,
        expected.resources.as_ref().unwrap().credentials.management["client_keys"].read_metadata
    );
    assert_eq!(
        admitted
            .credential_runtime
            .as_ref()
            .unwrap()
            .apps
            .values()
            .next()
            .unwrap()
            .families,
        original
            .credential_runtime
            .as_ref()
            .unwrap()
            .apps
            .values()
            .next()
            .unwrap()
            .families
    );
    assert_eq!(
        admitted.control.as_ref().unwrap().secrets,
        original.control.as_ref().unwrap().secrets
    );
    Ok(())
}

impl World {
    fn new() -> Result<Self> {
        let artifact_path = PathBuf::from(std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
            .context("run xtask verify or build credential-metadata-conformance and set DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")?);
        let artifact = LoadedArtifact::load(&artifact_path)?;
        let mut policy = day2::development::local_policy_for(&artifact, "alice@example.com")?;
        for operation in policy.operations.values_mut() {
            operation.actors.insert("bob@example.com".into());
        }
        let directory = tempfile::tempdir()?;
        let runtime = day2::development::create_verification_for(
            &artifact_path,
            &directory.path().join("instance"),
            Some(policy),
            "alice@example.com",
        )?;
        let mut instance = Instance::load(runtime.instance_path())?;
        instance
            .apps
            .get_mut("app")
            .unwrap()
            .readers
            .insert("bob@example.com".into());
        fs::write(
            runtime.instance_path(),
            serde_json::to_vec_pretty(&instance)?,
        )?;
        let current = authority_state::current(&rusqlite::Connection::open(runtime.db())?)?;
        authority_state::apply_desired(
            &runtime,
            &LocalOperator::assert_local("alice@example.com")?,
            "fixture-read-access",
            Some(current.stamp),
        )?;
        let world = Self {
            _directory: directory,
            runtime,
        };
        world.seed("client_keys", "a", "alice@example.com")?;
        world.seed("client_keys", "b", "alice@example.com")?;
        world.seed("client_keys", "c", "bob@example.com")?;
        world.seed("personal_keys", "d", "alice@example.com")?;
        world
            .runtime
            .initialize()
            .context("validate complete credential metadata fixture")?;
        Ok(world)
    }

    /// Seed metadata rows, never an issuing route or qualified key provider.
    fn seed(&self, family: &str, id: &str, creator: &str) -> Result<()> {
        let instance = Instance::load(self.runtime.instance_path())?;
        let binding = &instance.apps["app"].credential_families[family];
        let manifest = self
            .runtime
            .artifact()
            .contract()
            .credential_manifest
            .iter()
            .find(|entry| entry.id.as_str() == family)
            .context("manifest family")?;
        let ceiling = GrantCeiling::derive(
            BindingRef::pin(Name::try_from("test-client".to_owned())?, &"test")?,
            creator
                .split_once('@')
                .context("fixture creator email")?
                .0
                .into(),
            binding.audience.clone(),
            manifest.roots.clone(),
        )?;
        let namespace = Digest::of(&("credential-namespace-v1", &binding.namespace))?;
        let version = format!("version-{id}");
        let identity = json!({
            "namespace": binding.namespace,
            "family": family,
            "lineage": id,
            "version": version,
            "recipient": "PRIVATE_RECIPIENT",
            "security_epoch": 1,
            "material_revision": 1,
        });
        let request_digest = Digest::of(&(
            "credential-metadata-fixture-issue-v1",
            &namespace,
            family,
            id,
            creator,
        ))?;
        let mut db = rusqlite::Connection::open(self.runtime.db())?;
        let tx = db.transaction()?;
        tx.execute("INSERT INTO day2_credential_lineages VALUES(?1,?2,?3,?4,?5,?10,?6,'Test key','PRIVATE_RECIPIENT','PRIVATE_SESSION',?7,?8,4000,1,'active',?9,1)",
            params![id, namespace.as_str(), serde_json::to_string(&binding.namespace)?, family, manifest.contract.as_str(), creator, serde_json::to_string(&ceiling)?, ceiling.digest.as_str(), version, ceiling.subject])
            .context("seed credential metadata lineage")?;
        tx.execute("INSERT INTO day2_credential_versions VALUES(?1,?2,NULL,?3,?4,'PRIVATE_VERIFIER_KEY',100,3700,1,?5,'active')",
            params![version, id, metadata_selector(id), [8u8;32].as_slice(), ceiling.digest.as_str()])
            .context("seed credential metadata version")?;
        tx.execute(
            "INSERT INTO day2_credential_material VALUES(?1,?2,1,1,'PRIVATE_ENCRYPTION_KEY',?3,?4)",
            params![
                version,
                serde_json::to_string(&identity)?,
                [0u8; 12].as_slice(),
                [9u8; 32].as_slice()
            ],
        )
        .context("seed credential metadata material identity")?;
        tx.execute("INSERT INTO day2_credential_deliveries VALUES(?1,'PRIVATE_RECIPIENT','PRIVATE_SESSION',3700,'available','')",
            params![version])
            .context("seed credential metadata delivery")?;
        tx.execute(
            "INSERT INTO day2_credential_receipts VALUES(?1,?2,0,?3,?4,'issue',?5,?6)",
            params![
                namespace.as_str(),
                format!("metadata-seed-{id}"),
                manifest.contract.as_str(),
                request_digest.as_str(),
                id,
                version
            ],
        )
        .context("seed credential metadata issue receipt")?;
        tx.commit().context("commit credential metadata fixture")?;
        Ok(())
    }

    fn assert_private_trace(&self, invocation: &str) -> Result<()> {
        let trace = serde_json::to_string(&self.runtime.trace(invocation)?)?;
        self.assert_private_metadata(&trace)
    }

    fn assert_private_metadata(&self, encoded: &str) -> Result<()> {
        assert!(!encoded.contains("PRIVATE_"));
        assert!(!encoded.contains("d2c1."));
        let db = rusqlite::Connection::open(self.runtime.db())?;
        let mut statement = db.prepare("SELECT selector FROM day2_credential_versions")?;
        for selector in statement.query_map([], |row| row.get::<_, String>(0))? {
            let selector = selector?;
            assert!(!encoded.contains(selector.as_str()));
        }
        Ok(())
    }

    fn invoke(&self, operation: &str, actor: &str, id: &str, input: Value) -> Result<Outcome> {
        let outcome = self
            .runtime
            .invoke(operation, actor, id, &input, 200, Fault::None)?;
        ensure!(outcome.status == "success", "{outcome:?}");
        replay(self.runtime.artifact(), &self.runtime.trace(id)?)?;
        Ok(outcome)
    }

    fn change_policy(&self) -> Result<()> {
        use day2_capabilities::credentials::ManagementPredicate;
        let mut instance = Instance::load(self.runtime.instance_path())?;
        let catalog = &mut instance
            .resources
            .as_mut()
            .context("resource catalog")?
            .credentials;
        let policy = catalog
            .management
            .get_mut("client_keys")
            .context("management policy")?;
        policy.read_metadata = ManagementPredicate::MemberOf {
            group: Name::try_from("managers".to_owned())?,
        };
        instance
            .apps
            .get_mut("app")
            .unwrap()
            .credential_families
            .get_mut("client_keys")
            .unwrap()
            .management
            .revision = Digest::of(policy)?;
        fs::write(
            self.runtime.instance_path(),
            serde_json::to_vec_pretty(&instance)?,
        )?;
        let current = authority_state::current(&rusqlite::Connection::open(self.runtime.db())?)?;
        authority_state::apply_desired(
            &self.runtime,
            &LocalOperator::assert_local("alice@example.com")?,
            "metadata-policy-change",
            Some(current.stamp),
        )?;
        Ok(())
    }
}

#[test]
fn native_family_reads_page_inspect_hide_foreign_lineages_and_replay_safe_metadata() -> Result<()> {
    let world = World::new()?;
    let first = world
        .invoke(
            "credential_metadata.list",
            "alice@example.com",
            "first",
            json!({"after":"","limit":1}),
        )?
        .result;
    assert_eq!(first["status"], "ok");
    assert_eq!(first["page"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["page"]["items"][0]["principal"], "alice");
    assert_eq!(first["page"]["items"][0]["version"], "version-a");
    assert_eq!(first["page"]["has_more"], true);
    let cursor = first["page"]["next_after"].as_str().unwrap();
    assert!(cursor.starts_with("cm1_clients_"));
    let second = world
        .invoke(
            "credential_metadata.list",
            "alice@example.com",
            "second",
            json!({"after":cursor,"limit":1}),
        )?
        .result;
    assert_eq!(second["page"]["items"][0]["version"], "version-b");
    assert_eq!(second["page"]["has_more"], false);
    assert_eq!(second["page"]["next_after"], "");
    let foreign = world
        .invoke(
            "credential_metadata.list",
            "bob@example.com",
            "foreign-cursor",
            json!({"after":cursor,"limit":1}),
        )?
        .result;
    assert_eq!(foreign["status"], "invalid_cursor");
    let lineage = first["page"]["items"][0]["lineage"].as_str().unwrap();
    let inspect = world
        .invoke(
            "credential_metadata.inspect",
            "alice@example.com",
            "inspect",
            json!({"lineage":lineage}),
        )?
        .result;
    assert_eq!(inspect["status"], "ok");
    assert_eq!(inspect["revision"], 1);
    assert_eq!(inspect["version"], "version-a");
    let foreign = world
        .invoke(
            "credential_metadata.inspect",
            "bob@example.com",
            "invisible",
            json!({"lineage":lineage}),
        )?
        .result;
    assert_eq!(foreign["status"], "not_visible");
    world.assert_private_trace("first")?;
    for after in [
        "cm1_personal_bad",
        "cm1_clients_",
        "cm1_clients_not-valid-json",
    ] {
        assert_eq!(
            world
                .invoke(
                    "credential_metadata.list",
                    "alice@example.com",
                    after,
                    json!({"after":after,"limit":1})
                )?
                .result["status"],
            "invalid_cursor"
        );
    }
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let original: String = db.query_row(
        "SELECT grant_digest FROM day2_credential_lineages WHERE id='a'",
        [],
        |row| row.get(0),
    )?;
    // Malformed data is rejected by the row guard before serving can read it.
    let error = db
        .execute(
            "UPDATE day2_credential_lineages SET grant_digest='sha256:broken' WHERE id='a'",
            [],
        )
        .unwrap_err();
    assert!(matches!(error, rusqlite::Error::SqliteFailure(code, _)
        if code.code == rusqlite::ErrorCode::ConstraintViolation
            && code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER));
    let unchanged: String = db.query_row(
        "SELECT grant_digest FROM day2_credential_lineages WHERE id='a'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(unchanged, original);
    // A well-formed but different grant reaches the original semantic refusal.
    let foreign = Digest::of(&"foreign-metadata-grant")?;
    assert_ne!(foreign.as_str(), original);
    assert_eq!(
        db.execute(
            "UPDATE day2_credential_lineages SET grant_digest=?1 WHERE id='a'",
            [foreign.as_str()],
        )?,
        1
    );
    let stored: String = db.query_row(
        "SELECT grant_digest FROM day2_credential_lineages WHERE id='a'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(stored, foreign.as_str());
    assert_eq!(
        world
            .invoke(
                "credential_metadata.inspect",
                "alice@example.com",
                "damaged",
                json!({"lineage":lineage})
            )?
            .result["status"],
        "unavailable"
    );
    Ok(())
}

#[test]
fn oversized_metadata_page_returns_a_closed_failure_without_truncation() -> Result<()> {
    let world = World::new()?;
    for index in 0..100 {
        world.seed(
            "client_keys",
            &format!("{index:03}{}", "x".repeat(116)),
            "alice@example.com",
        )?;
    }
    rusqlite::Connection::open(world.runtime.db())?.execute(
        "UPDATE day2_credential_lineages SET label=?1 WHERE creator='alice@example.com'",
        ["\"".repeat(128)],
    )?;
    let output = world
        .invoke(
            "credential_metadata.list",
            "alice@example.com",
            "bounded-page",
            json!({"after":"","limit":100}),
        )?
        .result;
    assert_eq!(output["status"], "throttled");
    assert_eq!(output["page"]["items"], json!([]));
    assert_eq!(output["page"]["has_more"], false);
    assert_eq!(output["page"]["next_after"], "");
    world.assert_private_trace("bounded-page")?;
    Ok(())
}

#[test]
fn hostile_instructions_require_exact_declared_family_and_current_invocation_authority()
-> Result<()> {
    let world = World::new()?;
    let runtime = &world.runtime;
    runtime.accept(
        "credential_metadata.list",
        "alice@example.com",
        "probe",
        &json!({"after":"","limit":1}),
        200,
    )?;
    runtime.accept(
        "credential_metadata.ping",
        "alice@example.com",
        "undeclared",
        &json!({}),
        200,
    )?;
    let simulation = Simulation::new(runtime.clone(), [7u8; 32], 200_000)?;
    let list = day2::credential_codegen::LIST;
    assert_eq!(
        simulation.resource_probe(
            "probe",
            list,
            json!({"registration":"clients","after":"","limit":1})
        )?["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    for (invocation, data) in [
        (
            "undeclared",
            json!({"registration":"clients","after":"","limit":1}),
        ),
        (
            "probe",
            json!({"registration":"personal","after":"","limit":1}),
        ),
        (
            "probe",
            json!({"registration":"clients","after":"","limit":1,"actor":"bob@example.com"}),
        ),
        (
            "probe",
            json!({"registration":"clients","after":"","limit":1,"session":"forged"}),
        ),
    ] {
        assert!(simulation.resource_probe(invocation, list, data).is_err());
    }
    world.change_policy()?;
    assert!(
        simulation
            .resource_probe(
                "probe",
                list,
                json!({"registration":"clients","after":"","limit":1})
            )
            .is_err()
    );
    assert_eq!(
        world
            .invoke(
                "credential_metadata.list",
                "alice@example.com",
                "denied",
                json!({"after":"","limit":1})
            )?
            .result["status"],
        "denied"
    );
    Ok(())
}

#[test]
fn http_session_principal_controls_the_generated_metadata_query() -> Result<()> {
    let world = World::new()?;
    let runtime = world.runtime.clone();
    let instance = Instance::load(runtime.instance_path())?;
    let edge = instance.apps[runtime.app()]
        .edge
        .as_ref()
        .context("metadata fixture edge")?
        .clone();
    let domain = instance
        .identity
        .as_ref()
        .context("metadata fixture identity")?
        .hosted_domain
        .clone();
    let (keys, assertion) = metadata_iap(&edge, &domain)?;
    let authority = edge.authority().to_owned();
    let (sender, receiver) = mpsc::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = thread::spawn(move || -> Result<()> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(async {
                let listener =
                    tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
                let address = format!("http://{}", listener.local_addr()?);
                let verifier = day2::iap::Verifier::new(
                    &edge.iap_audience,
                    &domain,
                    Box::new(MetadataIapKeys(keys)),
                )?;
                let server =
                    LocalServer::bind_edge_listener(runtime, listener, &edge, verifier, 4)?;
                sender.send(address)?;
                server
                    .serve(async {
                        let _ = stopped.await;
                    })
                    .await
            })
    });
    let origin = match receiver.recv_timeout(Duration::from_secs(10)) {
        Ok(addresses) => addresses,
        Err(error) => {
            thread.join().expect("HTTP server startup")?;
            return Err(error.into());
        }
    };
    let client = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let result = (|| -> Result<()> {
        assert_eq!(
            Client::new()
                .get(format!(
                    "{origin}/api/credential_metadata.list?after=&limit=1"
                ))
                .header(HOST, &authority)
                .send()?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let session = client
            .get(format!("{origin}/api/session"))
            .header(HOST, &authority)
            .header("x-goog-iap-jwt-assertion", &assertion)
            .send()?;
        assert_eq!(session.status(), StatusCode::OK);
        let set_cookie = session
            .headers()
            .get(SET_COOKIE)
            .context("metadata IAP session cookie")?
            .to_str()?;
        assert!(set_cookie.contains("Secure") && set_cookie.contains("HttpOnly"));
        let cookie = set_cookie
            .split(';')
            .next()
            .context("metadata IAP cookie")?
            .to_owned();
        let session_body: Value = serde_json::from_slice(&session.bytes()?)?;
        assert_eq!(session_body["actor"], "bob@example.com");
        let response = client
            .get(format!(
                "{origin}/api/credential_metadata.list?after=&limit=1"
            ))
            .header(HOST, &authority)
            .header("x-goog-iap-jwt-assertion", &assertion)
            .header(COOKIE, &cookie)
            .header("X-Authenticated-User", "alice@example.com")
            .send()?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text()?;
        let page: Value = serde_json::from_str(&body)?;
        assert_eq!(page["page"]["items"].as_array().unwrap().len(), 1);
        assert_eq!(page["page"]["items"][0]["principal"], "bob");
        assert_eq!(page["page"]["items"][0]["version"], "version-c");
        world.assert_private_metadata(&body)?;
        assert_eq!(
            client
                .get(format!(
                    "{origin}/api/credential_metadata.list?after=&limit=1&actor=alice@example.com"
                ))
                .header(HOST, &authority)
                .header("x-goog-iap-jwt-assertion", &assertion)
                .header(COOKIE, &cookie)
                .send()?
                .status(),
            StatusCode::BAD_REQUEST
        );
        Ok(())
    })();
    let _ = stop.send(());
    thread.join().expect("HTTP server thread")?;
    result
}

#[test]
fn native_compiler_preserves_family_types_and_seals_host_read_constructors() -> Result<()> {
    use day2::{
        output_schema,
        schema::{Kind, Record, Schema},
    };
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path().join("stage");
    fs::create_dir_all(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    fs::write(
        stage.join("app/Credentials.roc"),
        day2::credential_codegen::module(["clients", "personal"], false)?,
    )?;
    let base = r#"app [step] { pf: platform "../sdk/main.roc" }
import pf.Observe
import pf.PageSize
import pf.Credential
import Credentials
step : Str -> Str
step = |raw| raw
"#;
    let compiler = root.join("../.toolchains/roc").canonicalize()?;
    let run = |directory: &std::path::Path, operation: &str| -> Result<(bool, String)> {
        let output = compiler::output(
            day2::sandbox::compiler(&root, directory, &compiler)?
                .arg(operation)
                .arg(directory.join("app/main.roc")),
            Duration::from_secs(60),
        )?;
        Ok((
            output.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        ))
    };
    eprintln!("Checking metadata witness constructors");
    fs::write(
        stage.join("app/main.roc"),
        r#"app [step] { pf: platform "../sdk/main.roc" }
import pf.Credential
step : Str -> Str
step = |raw| raw
expect Credential.metadata_access(Credential.client_family({id: "client", grant: Credential.fixed([]), lifetime_seconds: 10})).family() == "client"
expect Credential.metadata_access(Credential.personal_family({id: "personal", grant: Credential.fixed([]), lifetime_seconds: 10})).family() == "personal"
"#,
    )?;
    let (success, diagnostics) = run(&stage, "test")?;
    ensure!(
        success && diagnostics.contains("All (2) tests passed"),
        "{diagnostics}"
    );
    eprintln!("Checking generated family metadata helpers");
    fs::write(
        stage.join("app/main.roc"),
        format!(
            r#"{base}
expect Credentials.clients.start.to_str() == ""
expect (Credentials.clients.cursor_from_str)("cm1_personal_abc") == Err(InvalidCursor)
expect (Credentials.clients.ref_from_str)("cr1_personal_abc") == Err(InvalidRef)
"#
        ),
    )?;
    let (success, diagnostics) = run(&stage, "test")?;
    ensure!(
        success && diagnostics.contains("All (3) tests passed"),
        "{diagnostics}"
    );
    for (probe, expected) in [
        (
            "(Credentials.clients.list)({ after: Credentials.personal.start, limit: PageSize.one })",
            "Cursor_personal",
        ),
        (
            "(Credentials.clients.list)({ after: Credentials.clients.start, limit: PageSize.one, actor: \"alice\" })",
            "actor",
        ),
    ] {
        fs::write(
            stage.join("app/main.roc"),
            format!(
                "{base}\nprobe = |flag| if flag {{ {probe} }} else {{ (Credentials.clients.list)({{ after: Credentials.clients.start, limit: PageSize.one }}) }}\n"
            ),
        )?;
        let (success, diagnostics) = run(&stage, "check")?;
        ensure!(!success && diagnostics.contains(expected), "{diagnostics}");
    }
    fs::write(
        stage.join("app/main.roc"),
        format!(
            "{base}\nprobe : Credentials.Ref_personal -> Observe(Try(Credentials.Inspection_clients, Credentials.InspectionFailure_clients))\nprobe = |lineage| (Credentials.clients.inspect)({{ lineage: lineage }})\n"
        ),
    )?;
    let (success, diagnostics) = run(&stage, "check")?;
    ensure!(
        !success && diagnostics.contains("Ref_personal"),
        "cross-family reference probe: {diagnostics}"
    );
    fs::write(
        stage.join("app/main.roc"),
        format!(
            "{base}\nprobe = |flag| if flag {{ Credentials.day2_read_list_clients(\"clients\", {{ after: Credentials.clients.start, limit: PageSize.one }}) }} else {{ (Credentials.clients.list)({{ after: Credentials.clients.start, limit: PageSize.one }}) }}\n"
        ),
    )?;
    let (success, diagnostics) = run(&stage, "check")?;
    ensure!(success, "normal host factory probe: {diagnostics}");
    let schema = Schema {
        models: BTreeMap::from([(
            "entries".into(),
            Record {
                fields: BTreeMap::from([("note".into(), Kind::Text)]),
                roc_type: Some("Models.Entry".into()),
                identity: None,
            },
        )]),
        inputs: BTreeMap::new(),
        domains: BTreeMap::new(),
        foreign_keys: vec![],
        rollups: vec![],
        indexes: vec![],
    };
    let restricted = temporary.path().join("restricted");
    day2::admission::prepare(
        &stage,
        &restricted,
        &schema,
        &output_schema::Catalog::new(),
        &BTreeMap::new(),
        None,
    )?;
    fs::write(
        restricted.join("app/Credentials.roc"),
        day2::credential_codegen::module(["clients", "personal"], true)?,
    )?;
    let (success, diagnostics) = run(&restricted, "check")?;
    ensure!(
        !success && diagnostics.contains("read_list"),
        "restricted host factory probe: {diagnostics}"
    );
    let descriptor_probe = "app [step] { pf: platform \"../sdk/main.roc\" }\nimport pf.CredentialMetadataAccess as Access\nstep : Str -> Str\nstep = |raw| Access.define(raw).family()\n";
    fs::write(stage.join("app/main.roc"), descriptor_probe)?;
    fs::write(restricted.join("app/main.roc"), descriptor_probe)?;
    let (success, diagnostics) = run(&stage, "check")?;
    ensure!(success, "normal access factory probe: {diagnostics}");
    let (success, diagnostics) = run(&restricted, "check")?;
    ensure!(
        !success && diagnostics.contains("define"),
        "restricted access factory probe: {diagnostics}"
    );
    let issuance_base = r#"app [step] { pf: platform "../sdk/main.roc" }
import pf.InteractiveContext
import pf.Context
import pf.Credential
import pf.Tx
import pf.Handler
import Credentials
step : Str -> Str
step = |raw| raw
"#;
    let positive = format!(
        "{issuance_base}\nprobe : InteractiveContext, Credential.Label -> Tx(Credentials.Issued_clients)\nprobe = |context, label| (Credentials.clients.issue)(context, {{ label: label }})\nhandler = Handler.interactive(|context, label| probe(context, label))\n"
    );
    for directory in [&stage, &restricted] {
        fs::write(directory.join("app/main.roc"), &positive)?;
        let (success, diagnostics) = run(directory, "check")?;
        ensure!(success, "native interactive issuance: {diagnostics}");
    }
    let lifecycle_positive = format!(
        "{issuance_base}\nrotate : InteractiveContext, Credentials.ManagementSnapshot_clients -> Tx(Credentials.RotationOutcome_clients)\nrotate = |context, expected| (Credentials.clients.rotate)(context, {{ expected: expected }})\nrevoke : InteractiveContext, Credentials.Ref_personal -> Tx(Credentials.RevocationOutcome_personal)\nrevoke = |context, lineage| (Credentials.personal.revoke)(context, {{ lineage: lineage }})\n"
    );
    for directory in [&stage, &restricted] {
        fs::write(directory.join("app/main.roc"), &lifecycle_positive)?;
        let (success, diagnostics) = run(directory, "check")?;
        ensure!(success, "native interactive lifecycle: {diagnostics}");
        for (probe, expected) in [
            (
                "probe : Context, Credentials.ManagementSnapshot_clients -> Tx(Credentials.RotationOutcome_clients)\nprobe = |context, expected| (Credentials.clients.rotate)(context, { expected: expected })",
                "Context",
            ),
            (
                "probe : Context, Credentials.Ref_clients -> Tx(Credentials.RevocationOutcome_clients)\nprobe = |context, lineage| (Credentials.clients.revoke)(context, { lineage: lineage })",
                "Context",
            ),
            (
                "probe : InteractiveContext, Credentials.ManagementSnapshot_personal -> Tx(Credentials.RotationOutcome_clients)\nprobe = |context, expected| (Credentials.clients.rotate)(context, { expected: expected })",
                "ManagementSnapshot_personal",
            ),
            (
                "probe : InteractiveContext, Credentials.Ref_personal -> Tx(Credentials.RevocationOutcome_clients)\nprobe = |context, lineage| (Credentials.clients.revoke)(context, { lineage: lineage })",
                "Ref_personal",
            ),
            (
                "probe = |context, expected| (Credentials.clients.rotate)(context, { expected, actor: \"alice\" })",
                "actor",
            ),
            (
                "probe = |context, lineage| (Credentials.personal.revoke)(context, { lineage, version: \"other\" })",
                "version",
            ),
            (
                "probe : Credentials.Issued_clients -> Str\nprobe = |issued| issued.token",
                "token",
            ),
        ] {
            fs::write(
                directory.join("app/main.roc"),
                format!("{issuance_base}\n{probe}\n"),
            )?;
            let (success, diagnostics) = run(directory, "check")?;
            ensure!(
                !success && diagnostics.contains(expected),
                "negative lifecycle fixture: {diagnostics}"
            );
        }
    }
    for (probe, expected) in [
        (
            "probe : Context, Credential.Label -> Tx(Credentials.Issued_clients)\nprobe = |context, label| (Credentials.clients.issue)(context, { label: label })",
            "Context",
        ),
        (
            "probe = |context, label| (Credentials.personal.issue)(context, { label, subject: \"someone-else\" })",
            "subject",
        ),
        (
            "probe : Credentials.Issued_clients -> Str\nprobe = |issued| issued.token",
            "token",
        ),
        (
            "probe : Credentials.Issued_clients -> Credentials.Ref_personal\nprobe = |issued| issued.lineage()",
            "Ref_personal",
        ),
    ] {
        fs::write(
            stage.join("app/main.roc"),
            format!("{issuance_base}\n{probe}\n"),
        )?;
        let (success, diagnostics) = run(&stage, "check")?;
        ensure!(
            !success && diagnostics.contains(expected),
            "negative issuance fixture: {diagnostics}"
        );
    }
    let constructor =
        format!("{issuance_base}\nprobe = |context| InteractiveContext.from_context(context)\n");
    fs::write(stage.join("app/main.roc"), &constructor)?;
    fs::write(restricted.join("app/main.roc"), &constructor)?;
    let (success, diagnostics) = run(&stage, "check")?;
    ensure!(success, "normal interactive constructor: {diagnostics}");
    let (success, diagnostics) = run(&restricted, "check")?;
    ensure!(
        !success && diagnostics.contains("from_context"),
        "sealed interactive constructor: {diagnostics}"
    );
    // The navigation descriptor retains each command's nominal input type and
    // its generated codec. Neither descriptor nor return reference is authored.
    let mut navigation_schema = schema.clone();
    for (key, ty) in [
        ("client_input", "CreateClientTypes.Input"),
        ("personal_input", "CreatePersonalTypes.Input"),
    ] {
        navigation_schema.inputs.insert(
            key.into(),
            Record {
                fields: BTreeMap::from([("label".into(), Kind::Text)]),
                roc_type: Some(ty.into()),
                identity: None,
            },
        );
    }
    let navigation_outputs = BTreeMap::from([(
        "unit".into(),
        output_schema::Contract {
            roc_type: "{ ready : Bool }".into(),
            shape: output_schema::Type::Record(BTreeMap::from([(
                "ready".into(),
                output_schema::Type::Boolean,
            )])),
        },
    )]);
    let navigation_catalog = day2::registry::Catalog {
        unified: true,
        commands: BTreeMap::from([
            (
                "create_client".into(),
                day2::registry::Operation {
                    input: "client_input".into(),
                    output: "unit".into(),
                },
            ),
            (
                "create_personal".into(),
                day2::registry::Operation {
                    input: "personal_input".into(),
                    output: "unit".into(),
                },
            ),
        ]),
        pages: vec!["keys".into()],
        ..Default::default()
    };
    {
        let directory = &stage;
        for (name, source) in [
            ("Models.roc", "Models :: [].{ Entry := { note : Str } }"),
            (
                "CreateClientTypes.roc",
                "CreateClientTypes :: [].{ Input := { label : Str } }",
            ),
            (
                "CreatePersonalTypes.roc",
                "CreatePersonalTypes :: [].{ Input := { label : Str } }",
            ),
            (
                "AppIdentity.roc",
                "AppIdentity :: [].{ namespace = \"credential_metadata\" }",
            ),
        ] {
            fs::write(directory.join("app").join(name), source)?;
        }
        fs::write(
            directory.join("app/Data.roc"),
            navigation_schema.data_module()?,
        )?;
        fs::write(
            directory.join("app/Inputs.roc"),
            navigation_schema.inputs_module()?,
        )?;
        fs::write(
            directory.join("app/Outputs.roc"),
            output_schema::roc_module(&navigation_outputs)?,
        )?;
        let modules = navigation_catalog.modules(&navigation_schema, &navigation_outputs, false)?;
        for module in ["SecurityActions.roc", "ProductReturns.roc"] {
            fs::write(directory.join("app").join(module), &modules[module])?;
        }
    }
    fs::write(
        stage.join("registry.json"),
        serde_json::to_vec(&navigation_catalog)?,
    )?;
    let restricted = temporary.path().join("navigation-restricted");
    day2::admission::prepare(
        &stage,
        &restricted,
        &navigation_schema,
        &navigation_outputs,
        &BTreeMap::new(),
        None,
    )?;
    let navigation_base = "app [step] { pf: platform \"../sdk/main.roc\" }\nimport pf.SecurityAction\nimport pf.ProductReturnRef\nimport pf.Input\nimport CreateClientTypes\nimport CreatePersonalTypes\nimport SecurityActions\nimport ProductReturns\nstep : Str -> Str\nstep = |raw| raw\n";
    let positive = format!(
        "{navigation_base}\nprobe : CreateClientTypes.Input -> {{operation : Str, payload : Str, product_return : Str}}\nprobe = |input| SecurityAction.bind(SecurityActions.create_client, input, ProductReturns.keys)\n"
    );
    for directory in [&stage, &restricted] {
        fs::write(directory.join("app/main.roc"), &positive)?;
        let (success, diagnostics) = run(directory, "check")?;
        ensure!(success, "typed security navigation: {diagnostics}");
        fs::write(
            directory.join("app/main.roc"),
            format!(
                "{navigation_base}\nprobe : CreatePersonalTypes.Input -> {{operation : Str, payload : Str, product_return : Str}}\nprobe = |input| SecurityAction.bind(SecurityActions.create_client, input, ProductReturns.keys)\n"
            ),
        )?;
        let (success, diagnostics) = run(directory, "check")?;
        ensure!(
            !success && diagnostics.contains("Input"),
            "wrong command navigation input: {diagnostics}"
        );
    }
    for probe in [
        "probe = ProductReturnRef.define(\"keys\")",
        "probe : SecurityAction(CreateClientTypes.Input)\nprobe = SecurityAction.define(\"credential_metadata.create_client\", Input.define(\"client\", |_raw| Err(\"no\"), |_input| \"{}\"))",
    ] {
        fs::write(
            stage.join("app/main.roc"),
            format!("{navigation_base}\n{probe}\n"),
        )?;
        fs::write(
            restricted.join("app/main.roc"),
            format!("{navigation_base}\n{probe}\n"),
        )?;
        let (success, diagnostics) = run(&stage, "check")?;
        ensure!(success, "normal navigation factory: {diagnostics}");
        let (success, diagnostics) = run(&restricted, "check")?;
        ensure!(
            !success && diagnostics.contains("define"),
            "sealed navigation factory: {diagnostics}"
        );
    }
    for directory in [&stage, &restricted] {
        fs::write(
            directory.join("app/main.roc"),
            format!("{navigation_base}\nprobe : ProductReturnRef\nprobe = {{ page: \"keys\" }}\n"),
        )?;
        let (success, diagnostics) = run(directory, "check")?;
        ensure!(
            !success && diagnostics.contains("ProductReturnRef"),
            "forged return reference: {diagnostics}"
        );
    }
    Ok(())
}
