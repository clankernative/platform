use super::*;

type Fixture = (
    Instance,
    Instance,
    Value,
    Provisioning,
    BTreeMap<String, Required>,
);

fn fixture(path: &Path) -> Result<Fixture> {
    let original: Instance = serde_json::from_value(json!({
        "installation":"company","environment":"development",
        "control":{"version":1,"state_directory":"/private/source-control",
            "operators":["admin${LOCAL}"],"sources":{"source":{"kind":"local_git","repository":"/private/DO_NOT_EXPORT_SOURCE"}},
            "apps":{"reports":{"source":"source"}}},
        "apps":{"reports":{"artifact":"artifacts/pinned","readers":["alice"],"writers":["alice"],
            "runtime":{"kind":"linux_sqlite_single_v1","resources":{"memory_mib":512,"cpu_millis":1000,"process_limit":64,"http_concurrency":4,"shutdown_seconds":30}}}}
    }))?;
    let mut exported = original.clone();
    exported.control = None;
    let image = format!("sha256:{}", "a".repeat(64));
    let compose = super::super::compose(
        &exported,
        "reports",
        "alice",
        &image,
        NonZeroU16::new(18080).unwrap(),
    )?;
    let reference = VersionRef {
        id: "slack-bot".into(),
        revision: 1,
    };
    let live = LiveConnection::Slack {
        credential_ref: reference.clone(),
        signing_secret_ref: None,
        workspace_id: "T123".into(),
    };
    let request = Provisioning {
        tooling_image: image,
        operator: "admin${LOCAL}".into(),
        credentials: vec![CredentialSource {
            credential_ref: reference.clone(),
            source_file: path.into(),
        }],
    };
    Ok((
        original,
        exported,
        compose,
        request,
        BTreeMap::from([(
            reference_key(&reference)?,
            Required {
                connection: live,
                reference: None,
            },
        )]),
    ))
}

fn secret(path: &Path) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(b"SYNTHETIC_NEVER_EXPORT_TOKEN")?;
    Ok(())
}

#[test]
fn provisioning_projects_only_operator_authority_and_literal_readonly_mounts() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("${PRIVATE_TOKEN_FILE}");
    secret(&path)?;
    let (original, exported, compose, request, required) = fixture(&path)?;
    let prepared = prepare_connections(
        &original, &exported, "reports", &compose, &request, required,
    )?;
    assert!(exported.control.is_none());
    let operator = Instance::from_bytes(&prepared.operator)?;
    let control = operator.control.as_ref().unwrap();
    assert_eq!(
        control.operators,
        BTreeSet::from([request.operator.clone()])
    );
    assert!(
        control.apps.is_empty()
            && control.sources.is_empty()
            && control.builders.is_empty()
            && control.runtimes.is_empty()
            && control.secrets.is_empty()
    );
    let mount: crate::integration_host::Mount = crate::json::decode(&prepared.inputs[0].1)?;
    assert_eq!(mount.expected_fingerprint, Some(secret_digest(&path)?));
    assert_eq!(
        prepared.mounts[0]["target"],
        mount.credential_file.to_str().unwrap()
    );
    assert!(
        prepared.mounts[0]["source"]
            .as_str()
            .unwrap()
            .ends_with("$${PRIVATE_TOKEN_FILE}")
    );
    assert_eq!(prepared.mounts[0]["read_only"], true);
    assert_eq!(prepared.mounts[0]["bind"]["create_host_path"], false);
    let service = &prepared.service;
    assert_eq!(service["profiles"], json!(["operator"]));
    assert_eq!(service["network_mode"], "none");
    assert_eq!(service["user"], compose["services"]["app"]["user"]);
    assert_eq!(service["command"][4], "admin$${LOCAL}");
    assert_eq!(service["read_only"], true);
    assert_eq!(service["cap_drop"], json!(["ALL"]));
    assert_eq!(
        service["tmpfs"],
        json!(["/tmp:rw,exec,nosuid,nodev,mode=1777,size=64m"])
    );
    assert!(service.get("ports").is_none() && service.get("depends_on").is_none());
    assert!(
        service["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|mount| mount["source"] == "state" && mount["target"] == "/srv/day2/.state")
    );
    assert_eq!(service["volumes"][0], prepared.mounts[0]);
    let service_bytes = serde_json::to_vec(&prepared.service)?;
    for bytes in [
        &prepared.operator,
        &prepared.plan,
        &prepared.inputs[0].1,
        &service_bytes,
    ] {
        let text = std::str::from_utf8(bytes)?;
        assert!(!text.contains("SYNTHETIC_NEVER_EXPORT_TOKEN"));
        assert!(!text.contains("DO_NOT_EXPORT_SOURCE"));
    }
    assert_eq!(fs::read(&path)?, b"SYNTHETIC_NEVER_EXPORT_TOKEN");
    Ok(())
}

#[test]
fn provisioning_denies_unapproved_refs_operators_and_unsafe_source_files() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("token");
    secret(&path)?;
    let (original, exported, compose, request, required) = fixture(&path)?;
    let reject = |changed: &Provisioning| -> bool {
        prepare_connections(
            &original,
            &exported,
            "reports",
            &compose,
            changed,
            required.clone(),
        )
        .is_err()
    };
    let mut changed = request.clone();
    changed.operator = "policy-delegate".into();
    assert!(reject(&changed));
    changed = request.clone();
    changed.credentials[0].credential_ref.revision = 2;
    assert!(reject(&changed));
    changed = request.clone();
    changed.credentials.push(changed.credentials[0].clone());
    assert!(reject(&changed));
    changed.credentials.clear();
    assert!(reject(&changed));
    changed = request.clone();
    changed.tooling_image = "tooling:latest".into();
    assert!(reject(&changed));
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&path, &link)?;
    changed = request.clone();
    changed.credentials[0].source_file = link;
    assert!(reject(&changed));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(reject(&request));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert!(
        prepare_connections(
            &original, &exported, "reports", &compose, &request, required
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn operator_only_control_rejects_each_dormant_provider_map() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("token");
    secret(&path)?;
    let (original, exported, compose, request, required) = fixture(&path)?;
    let prepared = prepare_connections(
        &original, &exported, "reports", &compose, &request, required,
    )?;
    let value: Value = crate::json::decode(&prepared.operator)?;
    for (field, provider) in [
        (
            "sources",
            json!({"kind":"local_git","repository":"/private/repository"}),
        ),
        (
            "builders",
            json!({"kind":"local_macos","platform_root":"/private/platform","toolchains":"/private/toolchains","xtask":"/private/xtask","rust":"/private/rust","registry":"/private/registry"}),
        ),
        (
            "runtimes",
            json!({"kind":"temporal_local","endpoint":"127.0.0.1:7233","namespace":"day2","task_queue":"queue"}),
        ),
        (
            "secrets",
            json!({"kind":"gcp_version","project_number":1,"secret":"secret","version":1}),
        ),
    ] {
        let mut changed = value.clone();
        changed["control"][field] = json!({"unreviewed":provider});
        assert!(
            Instance::from_bytes(&serde_json::to_vec(&changed)?)
                .unwrap_err()
                .to_string()
                .contains("operator_only_control_cannot_have_provider_bindings")
        );
    }
    let mut changed = value;
    changed["control"]["operators"] = json!([]);
    assert!(Instance::from_bytes(&serde_json::to_vec(&changed)?).is_err());
    Ok(())
}

#[test]
fn registration_rechecks_reviewed_fingerprint_before_creating_registry() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("token");
    secret(&path)?;
    let (original, exported, compose, request, required) = fixture(&path)?;
    let prepared = prepare_connections(
        &original, &exported, "reports", &compose, &request, required,
    )?;
    let instance = temp.path().join("operator-instance.json");
    fs::write(&instance, &prepared.operator)?;
    let mut mount: crate::integration_host::Mount = crate::json::decode(&prepared.inputs[0].1)?;
    // The host test uses its private source path in place of the container bind.
    // The profile and reviewed fingerprint are the actual packaged input.
    mount.credential_file = path.clone();
    fs::write(&path, b"ROTATED_AFTER_PACKAGE_REVIEW")?;
    let error = crate::integration_host::mount(&instance, &request.operator, &mount).unwrap_err();
    assert_eq!(error.to_string(), "reviewed_credential_changed");
    assert!(!temp.path().join(".state").exists());
    fs::write(&path, b"SYNTHETIC_NEVER_EXPORT_TOKEN")?;
    crate::integration_host::mount(&instance, &request.operator, &mount)?;
    crate::integration_host::mount(&instance, &request.operator, &mount)?;
    let connection =
        rusqlite::Connection::open(temp.path().join(".state/provider-credentials.sqlite"))?;
    let (count, profile, fingerprint): (i64, String, String) = connection.query_row(
        "SELECT count(*),profile,fingerprint FROM mounts",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(count, 1);
    assert_eq!(
        crate::json::decode::<LiveConnection>(profile.as_bytes())?,
        mount.connection
    );
    assert_eq!(Some(fingerprint), mount.expected_fingerprint);
    // Subsequent secret rotation remains blocked without changing this version.
    fs::write(&path, b"ROTATED_AFTER_FIRST_REGISTRATION")?;
    assert!(crate::integration_host::mount(&instance, &request.operator, &mount).is_err());
    assert_eq!(
        connection.query_row("SELECT count(*) FROM mounts", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn verification_secrets_are_provisioned_by_their_own_reference() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (token_path, signer_path) = (temp.path().join("token"), temp.path().join("signer"));
    secret(&token_path)?;
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&signer_path)?
        .write_all(b"SYNTHETIC_NEVER_EXPORT_SIGNER")?;
    let (original, exported, compose, mut request, _) = fixture(&token_path)?;
    let (token, signer) = (
        VersionRef {
            id: "forge-token".into(),
            revision: 1,
        },
        VersionRef {
            id: "forge-signer".into(),
            revision: 1,
        },
    );
    let live = LiveConnection::GiteaActions {
        credential_ref: token.clone(),
        endpoint: "https://git.example.com".into(),
        signing_secret_ref: Some(signer.clone()),
    };
    let mut required = BTreeMap::new();
    require(
        &mut required,
        Required {
            connection: live.clone(),
            reference: None,
        },
    )?;
    require(
        &mut required,
        Required {
            connection: live.clone(),
            reference: Some(signer.clone()),
        },
    )?;
    // The same secret required twice with a different profile is refused.
    let mut retargeted = live.clone();
    if let LiveConnection::GiteaActions { endpoint, .. } = &mut retargeted {
        *endpoint = "https://other.example.com".into();
    }
    assert!(
        require(
            &mut required.clone(),
            Required {
                connection: retargeted,
                reference: Some(signer.clone()),
            },
        )
        .is_err()
    );
    request.credentials = vec![
        CredentialSource {
            credential_ref: token.clone(),
            source_file: token_path.clone(),
        },
        CredentialSource {
            credential_ref: signer.clone(),
            source_file: signer_path.clone(),
        },
    ];
    let prepared = prepare_connections(
        &original, &exported, "reports", &compose, &request, required,
    )?;
    let mounts: Vec<crate::integration_host::Mount> = prepared
        .inputs
        .iter()
        .map(|(_, bytes)| crate::json::decode(bytes))
        .collect::<Result<_>>()?;
    assert_eq!(mounts[0].reference, None);
    assert_eq!(mounts[1].reference, Some(signer.clone()));
    assert_eq!(mounts[1].credential_file, Path::new(&target(&signer)?));
    assert_ne!(mounts[0].credential_file, mounts[1].credential_file);
    for (_, bytes) in &prepared.inputs {
        assert!(!std::str::from_utf8(bytes)?.contains("SYNTHETIC_NEVER_EXPORT"));
    }
    // Registration records the signer under its own reference, not the token's.
    let instance = temp.path().join("operator-instance.json");
    fs::write(&instance, &prepared.operator)?;
    for (mut mount, path) in mounts.into_iter().zip([&token_path, &signer_path]) {
        mount.credential_file = path.clone();
        crate::integration_host::mount(&instance, &request.operator, &mount)?;
    }
    let connection =
        rusqlite::Connection::open(temp.path().join(".state/provider-credentials.sqlite"))?;
    let ids: Vec<String> = connection
        .prepare("SELECT id FROM mounts ORDER BY id")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    assert_eq!(ids, ["forge-signer", "forge-token"]);
    Ok(())
}
