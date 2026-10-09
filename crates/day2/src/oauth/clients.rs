//! Installation-owned provider client selection. This is desired configuration,
//! never registration readiness. Credentials are resolved only by native code.

use super::approval_keys::{AccessTokenSource, GcpSecretReader, GcpSecretVersion};
use crate::artifact::Instance;
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    BindingRef, Name, SecretProvider,
    oauth::{GoogleWebClient, ProviderClient},
};
use std::{collections::BTreeSet, sync::Arc};

/// The reviewed edge grants unconditional container access, across versions. Shell
/// client and attestation selections must not expose an app custody container.
pub(crate) fn shell_secret_containers(instance: &Instance) -> Result<BTreeSet<(u64, String)>> {
    validate(instance)?;
    let catalog = instance
        .oauth_clients
        .as_ref()
        .context("OAuth clients missing")?;
    let control = instance
        .control
        .as_ref()
        .context("OAuth client secret catalog missing")?;
    let registrations: BTreeSet<_> = instance
        .apps
        .values()
        .flat_map(|app| app.oauth_connections.values())
        .map(|binding| binding.registration.id.clone())
        .collect();
    ensure!(
        registrations == catalog.registrations.keys().cloned().collect(),
        "security shell client catalog must exactly cover selected registrations"
    );
    let container = |name: &Name| -> Result<(u64, String)> {
        let SecretProvider::GcpVersion {
            project_number,
            secret,
            ..
        } = control
            .secrets
            .get(name)
            .context("OAuth secret provider missing")?;
        Ok((project_number.get(), secret.as_str().into()))
    };
    let reauthentication = container(&catalog.reauthentication.credential)?;
    let mut clients = BTreeSet::from([reauthentication.clone()]);
    for registration in catalog.registrations.values() {
        let client = container(registration.client().credential())?;
        ensure!(
            client != reauthentication,
            "security shell provider client and reauthentication containers overlap"
        );
        clients.insert(client);
    }
    let mut attestation = BTreeSet::new();
    let mut custody = BTreeSet::new();
    for binding in instance
        .apps
        .values()
        .flat_map(|app| app.oauth_connections.values())
    {
        attestation.insert(container(&binding.shell_attestation_secret)?);
        custody.insert(container(&binding.custody_verifier_secret)?);
        custody.insert(container(&binding.custody_encryption_secret)?);
    }
    let credential_apps: BTreeSet<_> = instance
        .apps
        .iter()
        .filter(|(_, app)| !app.credential_families.is_empty())
        .map(|(name, _)| Name::try_from(name.clone()))
        .collect::<Result<_>>()?;
    if let Some(runtime) = &instance.credential_runtime {
        runtime.validate()?;
        ensure!(
            credential_apps == runtime.apps.keys().cloned().collect(),
            "security shell credential runtime must exactly cover selected apps"
        );
        let (_, edge) = instance.security_edge()?;
        for (name, app) in &runtime.apps {
            let binding = instance
                .apps
                .get(name.as_str())
                .context("security shell credential app missing")?;
            let scope = day2_capabilities::security_epoch::AuthorityScope {
                installation: instance.installation.clone().try_into()?,
                environment: instance.environment.clone().try_into()?,
                app: name.clone(),
            };
            app.attestation_key(
                &scope,
                &binding.credential_families,
                &control.secrets,
                &edge.origin,
                &edge.iap_audience,
            )?;
            attestation.insert(container(&app.attestation_secret)?);
            for key in app.selected_keys(&binding.credential_families, &control.secrets)? {
                let SecretProvider::GcpVersion {
                    project_number,
                    secret,
                    ..
                } = key.provider;
                custody.insert((project_number.get(), secret.as_str().into()));
            }
        }
    } else {
        ensure!(
            credential_apps.is_empty(),
            "security shell credential runtime missing"
        );
    }
    ensure!(
        clients.is_disjoint(&attestation),
        "security shell client and attestation containers overlap"
    );
    let selected: BTreeSet<_> = clients.union(&attestation).cloned().collect();
    ensure!(
        selected.is_disjoint(&custody),
        "security shell cannot access app custody secret containers"
    );
    Ok(selected)
}

pub(crate) fn validate(instance: &Instance) -> Result<()> {
    let Some(catalog) = &instance.oauth_clients else {
        return Ok(());
    };
    catalog.validate()?;
    instance.security_edge()?;
    let control = instance
        .control
        .as_ref()
        .context("OAuth client secret catalog missing")?;
    let reauthentication = control
        .secrets
        .get(&catalog.reauthentication.credential)
        .context("OAuth reauthentication credential missing")?;
    for selected in catalog.registrations.values() {
        let secret = control
            .secrets
            .get(selected.client().credential())
            .context("OAuth provider client credential missing")?;
        ensure!(
            secret != reauthentication,
            "OAuth client roles must use distinct secret versions"
        );
    }
    for binding in instance
        .apps
        .values()
        .flat_map(|app| app.oauth_connections.values())
    {
        ensure!(
            catalog.registrations.contains_key(&binding.registration.id),
            "OAuth registration client missing"
        );
        for role in [
            &binding.custody_verifier_secret,
            &binding.custody_encryption_secret,
            &binding.shell_attestation_secret,
        ] {
            let key = control
                .secrets
                .get(role)
                .context("OAuth key provider missing")?;
            ensure!(
                key != reauthentication
                    && catalog
                        .registrations
                        .values()
                        .all(
                            |client| control.secrets.get(client.client().credential()) != Some(key)
                        ),
                "OAuth client credentials cannot be custody or attestation keys"
            );
        }
    }
    Ok(())
}

pub(super) fn version(instance: &Instance, client: &GoogleWebClient) -> Result<GcpSecretVersion> {
    client.validate()?;
    version_for(instance, &client.credential)
}

fn version_for(instance: &Instance, credential: &Name) -> Result<GcpSecretVersion> {
    let provider = instance
        .control
        .as_ref()
        .context("OAuth client secret catalog missing")?
        .secrets
        .get(credential)
        .context("OAuth client credential missing")?;
    let SecretProvider::GcpVersion {
        project_number,
        secret,
        version,
    } = provider;
    let version = GcpSecretVersion {
        project_number: project_number.get(),
        secret: secret.as_str().into(),
        version: version.get(),
    };
    version.validate()?;
    Ok(version)
}

pub(super) fn reauthentication(
    instance: &Instance,
    tokens: Arc<dyn AccessTokenSource>,
) -> Result<(String, Box<dyn super::shell_oidc::CodeExchange>)> {
    validate(instance)?;
    let client = &instance
        .oauth_clients
        .as_ref()
        .context("OAuth clients not selected")?
        .reauthentication;
    Ok((
        client.client_id.clone(),
        Box::new(super::shell_oidc::GoogleCodeExchange::new(
            GcpSecretReader::new(tokens)?,
            version(instance, client)?,
        )?),
    ))
}

pub(super) fn credential(raw: Vec<u8>) -> Result<String> {
    let value =
        String::from_utf8(raw).map_err(|_| anyhow::anyhow!("invalid OAuth client credential"))?;
    ensure!(
        !value.is_empty()
            && value.len() <= 2048
            && value.bytes().all(|byte| byte.is_ascii_graphic()),
        "invalid OAuth client credential"
    );
    Ok(value)
}

pub(super) fn credential_reference(
    instance: &BindingRef,
    client_id: &str,
    secret: &GcpSecretVersion,
) -> Result<BindingRef> {
    BindingRef::pin(
        Name::try_from("google_client_credential".to_owned())?,
        &(
            "oauth-google-client-credential-v1",
            instance,
            client_id,
            secret,
        ),
    )
}

pub(crate) fn selected_credential(
    instance: &Instance,
    client: &GoogleWebClient,
) -> Result<BindingRef> {
    credential_reference(
        &super::admission::instance_identity(instance)?,
        &client.client_id,
        &version(instance, client)?,
    )
}

pub(super) fn provider_credential_reference(
    instance: &BindingRef,
    client: &ProviderClient,
    secret: &GcpSecretVersion,
) -> Result<BindingRef> {
    client.validate()?;
    match client {
        ProviderClient::Google { client_id, .. } => {
            credential_reference(instance, client_id, secret)
        }
        ProviderClient::Gitlab { client_id, .. } => BindingRef::pin(
            Name::try_from("gitlab_client_credential".to_owned())?,
            &(
                "oauth-gitlab-client-credential-v1",
                instance,
                client_id,
                secret,
            ),
        ),
    }
}

pub(crate) fn selected_provider_credential(
    instance: &Instance,
    client: &ProviderClient,
) -> Result<BindingRef> {
    provider_credential_reference(
        &super::admission::instance_identity(instance)?,
        client,
        &version_for(instance, client.credential())?,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    /// Synthetic CURRENT selectors only; no native database identity, epoch,
    /// metadata token, enrollment or readiness is manufactured by this helper.
    pub(crate) fn select_desired_epoch(
        instance: &mut Instance,
        app: &str,
        account: &str,
    ) -> Result<()> {
        use day2_capabilities::security_epoch::{
            AuthorityScope, EpochIam, EpochProvider, EpochStore,
        };
        let project = account
            .split_once('@')
            .context("fixture GSA")?
            .1
            .strip_suffix(".iam.gserviceaccount.com")
            .context("fixture GSA project")?;
        let control = instance.control.as_ref().context("fixture control")?;
        let day2_capabilities::SecretProvider::GcpVersion { project_number, .. } = control
            .secrets
            .values()
            .next()
            .context("fixture project number")?;
        let store = EpochStore {
            scope: AuthorityScope {
                installation: instance.installation.clone().try_into()?,
                environment: instance.environment.clone().try_into()?,
                app: app.to_owned().try_into()?,
            },
            provider: EpochProvider::FirestoreNativeV1 {
                project: project.to_owned().try_into()?,
                project_number: *project_number,
                database: "security".to_owned().try_into()?,
                database_uid: "01234567-89ab-4cde-8fab-0123456789ab".into(),
                iam_source: EpochIam::GkeWorkloadIdentityV1 {
                    service_account: account.into(),
                },
            },
            key_set: instance.security_key_set(app)?,
            max_lease_seconds: 30,
        };
        store.validate()?;
        let control = instance.control.as_mut().unwrap();
        control
            .security_epochs
            .retain(|_, selected| selected.scope.app.as_str() != app);
        control
            .security_epochs
            .insert(format!("selected-epoch-{app}").try_into()?, store);
        Ok(())
    }

    /// Desired selectors only. Real native admission/readiness is not supplied
    /// by this fixture; exact key and epoch pins are derived from its selections.
    pub(crate) fn security_instance(app: &str, keep_oauth: bool) -> Result<Instance> {
        use day2_capabilities::{
            Digest,
            credential_runtime::{
                CustodyRole, FamilyRuntime, RuntimeApp, RuntimeCatalog, attestation_revision,
                quota_revision,
            },
            credentials::{
                CredentialCatalog, CredentialFamilyBinding, DeliveryProfile, ManagementPolicy,
                ManagementPredicate, Namespace, RotationProfile,
            },
            oauth::{ResourceAudienceRef, SecurityOriginRef},
            security_epoch::{AuthorityScope, EpochIam, EpochProvider, EpochStore},
        };
        use std::{collections::BTreeMap, num::NonZeroU64};

        let name = |value: &str| Name::try_from(value.to_owned()).unwrap();
        let pin = |value: &str| BindingRef::pin(name(value), &value).unwrap();
        let mut instance = crate::oauth::admission::live::tests::selected()?
            .instance()
            .clone();
        let account = instance.oauth_runtime.as_ref().unwrap().apps[&name("workspace")]
            .service_account
            .clone();
        if app != "workspace" {
            let mut binding = instance.apps["workspace"].clone();
            binding.oauth_connections.clear();
            if let Some(edge) = &mut binding.edge {
                edge.origin = format!("https://{app}.example.com");
                edge.iap_audience = format!("{}/3", edge.iap_audience.rsplit_once('/').unwrap().0);
            }
            instance.apps.insert(app.into(), binding);
            let control = instance.control.as_mut().unwrap();
            let selected = control.apps[&name("workspace")].clone();
            control.apps.insert(name(app), selected);
        }
        if !keep_oauth {
            for binding in instance.apps.values_mut() {
                binding.oauth_connections.clear();
            }
            instance.oauth_runtime.as_mut().unwrap().apps.clear();
            instance
                .oauth_clients
                .as_mut()
                .unwrap()
                .registrations
                .clear();
            instance.control.as_mut().unwrap().security_epochs.clear();
        }
        let scope = AuthorityScope {
            installation: name(&instance.installation),
            environment: name(&instance.environment),
            app: name(app),
        };
        let namespace = Namespace {
            installation: scope.installation.clone(),
            environment: scope.environment.clone(),
            app: scope.app.clone(),
            binding_generation: 7,
        };
        let management = ManagementPolicy {
            identity_authority: BindingRef {
                id: name("credential-identity"),
                revision: instance.credential_identity_revision(app)?,
            },
            issue: ManagementPredicate::Creator,
            read_metadata: ManagementPredicate::Creator,
            rotate: ManagementPredicate::Creator,
            revoke: ManagementPredicate::Creator,
        };
        let family = CredentialFamilyBinding {
            namespace: namespace.clone(),
            family: name("agents"),
            approved_authority: pin("approved"),
            management: BindingRef {
                id: name("credential-management"),
                revision: Digest::of(&management)?,
            },
            rotation: RotationProfile::AtomicReplace,
            delivery: DeliveryProfile::AuthenticatedCreatorReveal,
            verifier: pin("credential-verifier"),
            custody: pin("credential-custody"),
            security_shell: SecurityOriginRef(BindingRef {
                id: name("credential-shell"),
                revision: instance.credential_shell_revision(app)?,
            }),
            audience: ResourceAudienceRef(pin("credential-audience")),
            epoch_store: pin("pending-epoch"),
            max_lifetime_seconds: 3600,
            reveal_window_seconds: 60,
            quota: BindingRef {
                id: name("credential-quota"),
                revision: quota_revision(12)?,
            },
        };
        instance
            .apps
            .get_mut(app)
            .unwrap()
            .credential_families
            .insert("agents".into(), family);
        instance.resources = Some(day2_capabilities::resources::Catalog {
            version: 1,
            connections: BTreeMap::new(),
            resources: BTreeMap::new(),
            policies: BTreeMap::new(),
            budgets: BTreeMap::new(),
            credentials: CredentialCatalog {
                management: BTreeMap::from([("credential-management".into(), management)]),
                approved_authority: BTreeMap::new(),
            },
        });
        let project_number = match instance
            .control
            .as_ref()
            .unwrap()
            .secrets
            .values()
            .next()
            .unwrap()
        {
            SecretProvider::GcpVersion { project_number, .. } => *project_number,
        };
        let control = instance.control.as_mut().unwrap();
        for (alias, secret, version) in [
            ("credential-verify", "credential-verifier", 2),
            ("credential-encrypt", "credential-encryption", 3),
            ("credential-attest", "credential-attestation", 4),
        ] {
            control.secrets.insert(
                name(alias),
                SecretProvider::GcpVersion {
                    project_number,
                    secret: name(secret),
                    version: NonZeroU64::new(version).unwrap(),
                },
            );
        }
        let (_, edge) = instance.security_edge()?;
        let attestation = BindingRef {
            id: name("credential-attestation"),
            revision: attestation_revision(
                &scope,
                &[namespace],
                &instance.control.as_ref().unwrap().secrets[&name("credential-attest")],
                &edge.origin,
                &edge.iap_audience,
            )?,
        };
        instance.credential_runtime = Some(RuntimeCatalog {
            version: 1,
            apps: BTreeMap::from([(
                name(app),
                RuntimeApp {
                    service_account: account.clone(),
                    attestation,
                    attestation_secret: name("credential-attest"),
                    families: BTreeMap::from([(
                        name("agents"),
                        FamilyRuntime {
                            verifier_secret: name("credential-verify"),
                            custody: CustodyRole::IssuerReveal {
                                encryption_secret: name("credential-encrypt"),
                            },
                            max_active_lineages: 12,
                        },
                    )]),
                },
            )]),
        });
        let store = EpochStore {
            scope,
            provider: EpochProvider::FirestoreNativeV1 {
                project: name(&instance.oauth_runtime.as_ref().unwrap().shell.project),
                project_number,
                database: name("tools"),
                database_uid: "00000000-0000-4000-8000-000000000007".into(),
                iam_source: EpochIam::GkeWorkloadIdentityV1 {
                    service_account: account,
                },
            },
            key_set: instance.security_key_set(app)?,
            max_lease_seconds: 30,
        };
        instance
            .apps
            .get_mut(app)
            .unwrap()
            .credential_families
            .get_mut("agents")
            .unwrap()
            .epoch_store = BindingRef {
            id: name("credential-epoch"),
            revision: Digest::of(&store)?,
        };
        let control = instance.control.as_mut().unwrap();
        control
            .security_epochs
            .retain(|_, selected| selected.scope.app.as_str() != app);
        control
            .security_epochs
            .insert(name("credential-epoch"), store);
        Ok(instance)
    }

    #[test]
    fn shell_deployment_plan_oracle_uses_the_native_closed_instance_contract() -> Result<()> {
        // The shell plan mounts this exact desired DATA. Synthetic bindings/UID
        // exercise composition, without admitting an artifact or live provider.
        let instance = Instance::from_bytes(include_bytes!(
            "../../../../deploy/gke/stacks/security-shell/tests/oauth-instance.json"
        ))?;
        let name = |value: &str| Name::try_from(value.to_owned()).unwrap();
        let epoch = &instance.control.as_ref().unwrap().security_epochs[&name("app_epoch")];
        assert_eq!(epoch.key_set, instance.security_key_set("workspace")?);
        assert_eq!(epoch.scope.app, name("workspace"));
        assert_eq!(
            instance.security_edge()?.1.iap_audience,
            "/projects/123456789012/global/backendServices/987654321"
        );
        assert_eq!(
            instance
                .oauth_shell_transport
                .as_ref()
                .unwrap()
                .service_account,
            "shell@example-tools.iam.gserviceaccount.com"
        );
        let resources = instance
            .oauth_runtime
            .as_ref()
            .unwrap()
            .shell_resources
            .as_ref()
            .unwrap();
        assert_eq!(resources.http_concurrency(), 4);
        assert_eq!(
            shell_secret_containers(&instance)?,
            BTreeSet::from([
                (123456789012, "shell_attestation".into()),
                (123456789012, "google_reauth".into()),
                (123456789012, "google_calendar".into()),
            ])
        );
        Ok(())
    }

    #[test]
    fn shared_shell_secret_projection_is_complete_for_credentials_only_and_combined() -> Result<()>
    {
        for keep_oauth in [false, true] {
            let instance = security_instance("workspace", keep_oauth)?;
            let admitted = Instance::from_bytes(&serde_json::to_vec(&instance)?)?;
            admitted.validate_credential_runtime_metadata()?;
            let selected = shell_secret_containers(&admitted)?;
            assert_eq!(selected.len(), if keep_oauth { 4 } else { 2 });
            let project = selected.iter().next().unwrap().0;
            assert!(selected.contains(&(project, "credential-attestation".into())));
            assert!(!selected.contains(&(project, "credential-verifier".into())));
            assert!(!selected.contains(&(project, "credential-encryption".into())));
            if !keep_oauth {
                assert!(admitted.oauth_runtime.as_ref().unwrap().apps.is_empty());
                assert!(
                    admitted
                        .oauth_clients
                        .as_ref()
                        .unwrap()
                        .registrations
                        .is_empty()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn complete_current_metadata_preserves_member_of_reads_and_refuses_group_lifecycle()
    -> Result<()> {
        use day2_capabilities::{Digest, credentials::ManagementPredicate};
        let mut instance = security_instance("workspace", true)?;
        let name = |value: &str| Name::try_from(value.to_owned()).unwrap();
        let policy = instance
            .resources
            .as_mut()
            .unwrap()
            .credentials
            .management
            .get_mut("credential-management")
            .unwrap();
        policy.read_metadata = ManagementPredicate::MemberOf {
            group: name("managers"),
        };
        instance
            .apps
            .get_mut("workspace")
            .unwrap()
            .credential_families
            .get_mut("agents")
            .unwrap()
            .management
            .revision = Digest::of(policy)?;
        let admitted = Instance::from_bytes(&serde_json::to_vec(&instance)?)?;
        assert_eq!(
            admitted.resources.as_ref().unwrap().credentials.management["credential-management"]
                .read_metadata,
            ManagementPredicate::MemberOf {
                group: name("managers")
            }
        );
        for action in ["issue", "rotate", "revoke"] {
            let mut changed = instance.clone();
            let policy = changed
                .resources
                .as_mut()
                .unwrap()
                .credentials
                .management
                .get_mut("credential-management")
                .unwrap();
            let predicate = match action {
                "issue" => &mut policy.issue,
                "rotate" => &mut policy.rotate,
                _ => &mut policy.revoke,
            };
            *predicate = ManagementPredicate::MemberOf {
                group: name("managers"),
            };
            changed
                .apps
                .get_mut("workspace")
                .unwrap()
                .credential_families
                .get_mut("agents")
                .unwrap()
                .management
                .revision = Digest::of(policy)?;
            let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("unsupported_credential_management_or_delivery"),
                "{action}"
            );
        }
        Ok(())
    }

    #[test]
    fn canonical_metadata_admission_rejects_self_consistent_identity_and_shell_substitution()
    -> Result<()> {
        let instance = security_instance("workspace", true)?;
        instance.validate_credential_runtime_metadata()?;
        let mut changed = instance.clone();
        changed.credential_runtime = None;
        let error = changed.validate_credential_runtime_metadata().unwrap_err();
        assert!(format!("{error:#}").contains("credential_runtime_missing"));
        let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
        assert!(format!("{error:#}").contains("credential_runtime_missing"));
        let mut changed = instance.clone();
        let policy = changed
            .resources
            .as_mut()
            .unwrap()
            .credentials
            .management
            .get_mut("credential-management")
            .unwrap();
        policy.identity_authority.revision =
            day2_capabilities::Digest::new(b"different identity authority");
        let revision = day2_capabilities::Digest::of(policy)?;
        changed
            .apps
            .get_mut("workspace")
            .unwrap()
            .credential_families
            .get_mut("agents")
            .unwrap()
            .management
            .revision = revision;
        assert!(changed.validate_credential_runtime_metadata().is_err());
        let mut changed = instance.clone();
        changed
            .apps
            .get_mut("workspace")
            .unwrap()
            .credential_families
            .get_mut("agents")
            .unwrap()
            .security_shell
            .0
            .revision = day2_capabilities::Digest::new(b"different dedicated shell");
        assert!(changed.validate_credential_runtime_metadata().is_err());
        let mut changed = instance.clone();
        changed
            .credential_runtime
            .as_mut()
            .unwrap()
            .apps
            .values_mut()
            .next()
            .unwrap()
            .families
            .values_mut()
            .next()
            .unwrap()
            .max_active_lineages += 1;
        assert!(changed.validate_credential_runtime_metadata().is_err());
        let mut changed = instance.clone();
        changed
            .apps
            .get_mut("workspace")
            .unwrap()
            .credential_families
            .get_mut("agents")
            .unwrap()
            .namespace
            .binding_generation += 1;
        assert!(changed.validate_credential_runtime_metadata().is_err());
        let mut changed = instance;
        changed.credential_runtime.as_mut().unwrap().apps.clear();
        assert!(changed.validate_credential_runtime_metadata().is_err());
        Ok(())
    }

    #[test]
    fn shared_shell_refuses_credential_custody_and_client_role_container_aliases() -> Result<()> {
        let instance = security_instance("workspace", true)?;
        let reauthentication = instance
            .oauth_clients
            .as_ref()
            .unwrap()
            .reauthentication
            .credential
            .clone();
        let provider_client = instance
            .oauth_clients
            .as_ref()
            .unwrap()
            .registrations
            .values()
            .next()
            .unwrap()
            .client()
            .credential()
            .clone();
        for (shell, target) in [
            (reauthentication.clone(), "credential-verify"),
            (provider_client.clone(), "credential-encrypt"),
            (provider_client.clone(), "credential-attest"),
            (provider_client, reauthentication.as_str()),
        ] {
            let mut wrong = instance.clone();
            let mut provider = wrong.control.as_ref().unwrap().secrets
                [&Name::try_from(target.to_owned())?]
                .clone();
            let SecretProvider::GcpVersion { version, .. } = &mut provider;
            *version = std::num::NonZeroU64::new(version.get() + 1).unwrap();
            wrong
                .control
                .as_mut()
                .unwrap()
                .secrets
                .insert(shell, provider);
            assert!(
                shell_secret_containers(&wrong).is_err(),
                "accepted {target} container at a different version"
            );
        }
        let mut missing = instance.clone();
        missing.credential_runtime = None;
        assert!(shell_secret_containers(&missing).is_err());
        let mut missing = instance.clone();
        missing
            .control
            .as_mut()
            .unwrap()
            .secrets
            .remove(&Name::try_from("credential-encrypt".to_owned())?);
        assert!(shell_secret_containers(&missing).is_err());
        let mut incomplete = instance.clone();
        incomplete
            .credential_runtime
            .as_mut()
            .unwrap()
            .apps
            .values_mut()
            .next()
            .unwrap()
            .families
            .clear();
        assert!(shell_secret_containers(&incomplete).is_err());
        let mut excess = instance;
        let selected = excess
            .credential_runtime
            .as_ref()
            .unwrap()
            .apps
            .values()
            .next()
            .unwrap()
            .clone();
        excess
            .credential_runtime
            .as_mut()
            .unwrap()
            .apps
            .insert(Name::try_from("unbound".to_owned())?, selected);
        assert!(shell_secret_containers(&excess).is_err());
        Ok(())
    }

    #[test]
    fn credential_attestation_cannot_grant_shell_access_to_oauth_custody_container() -> Result<()> {
        use day2_capabilities::{
            credential_runtime::attestation_revision, security_epoch::AuthorityScope,
        };
        let mut instance = security_instance("workspace", true)?;
        let app = Name::try_from("workspace".to_owned())?;
        let scope = AuthorityScope {
            installation: instance.installation.clone().try_into()?,
            environment: instance.environment.clone().try_into()?,
            app: app.clone(),
        };
        let namespace = instance.apps["workspace"].credential_families["agents"]
            .namespace
            .clone();
        let verifier =
            &instance.apps["workspace"].oauth_connections["calendar"].custody_verifier_secret;
        let mut provider = instance.control.as_ref().unwrap().secrets[verifier].clone();
        let SecretProvider::GcpVersion { version, .. } = &mut provider;
        *version = std::num::NonZeroU64::new(version.get() + 1).unwrap();
        let (_, edge) = instance.security_edge()?;
        let revision = attestation_revision(
            &scope,
            &[namespace],
            &provider,
            &edge.origin,
            &edge.iap_audience,
        )?;
        instance
            .control
            .as_mut()
            .unwrap()
            .secrets
            .insert(Name::try_from("credential-attest".to_owned())?, provider);
        instance
            .credential_runtime
            .as_mut()
            .unwrap()
            .apps
            .get_mut(&app)
            .unwrap()
            .attestation
            .revision = revision;
        // The changed signer selector is internally consistent and its exact
        // version differs. Its container-wide IAM grant still exposes custody.
        assert!(shell_secret_containers(&instance).is_err());
        Ok(())
    }

    #[test]
    fn verifier_only_credential_family_does_not_project_unused_encryption_container() -> Result<()>
    {
        let mut instance = security_instance("workspace", false)?;
        instance
            .credential_runtime
            .as_mut()
            .unwrap()
            .apps
            .values_mut()
            .next()
            .unwrap()
            .families
            .values_mut()
            .next()
            .unwrap()
            .custody = day2_capabilities::credential_runtime::CustodyRole::VerifierOnly {};
        // This catalog alias is unused by verifier-only custody; sharing it with
        // reauthentication cannot manufacture an issuer/reveal shell grant.
        let reauthentication = &instance
            .oauth_clients
            .as_ref()
            .unwrap()
            .reauthentication
            .credential;
        let provider = instance.control.as_ref().unwrap().secrets[reauthentication].clone();
        instance
            .control
            .as_mut()
            .unwrap()
            .secrets
            .insert(Name::try_from("credential-encrypt".to_owned())?, provider);
        assert_eq!(shell_secret_containers(&instance)?.len(), 2);
        Ok(())
    }

    #[test]
    fn shell_cannot_read_custody_containers_even_at_distinct_versions() -> anyhow::Result<()> {
        let selected = crate::oauth::admission::live::tests::selected()?;
        let mut instance = selected.instance().clone();
        let containers = super::shell_secret_containers(&instance)?;
        assert_eq!(containers.len(), 3);
        let mut excess = instance.clone();
        let client = excess
            .oauth_clients
            .as_ref()
            .unwrap()
            .registrations
            .values()
            .next()
            .unwrap()
            .clone();
        excess
            .oauth_clients
            .as_mut()
            .unwrap()
            .registrations
            .insert(Name::try_from("unused_client".to_owned())?, client);
        assert!(super::shell_secret_containers(&excess).is_err());
        let connection = instance.apps["workspace"].oauth_connections["calendar"].clone();
        let credential = instance
            .oauth_clients
            .as_ref()
            .unwrap()
            .reauthentication
            .credential
            .clone();
        let mut shared =
            instance.control.as_ref().unwrap().secrets[&connection.custody_verifier_secret].clone();
        let day2_capabilities::SecretProvider::GcpVersion { version, .. } = &mut shared;
        *version = std::num::NonZeroU64::new(version.get() + 1).unwrap();
        instance
            .control
            .as_mut()
            .unwrap()
            .secrets
            .insert(credential, shared);
        super::validate(&instance)?; // Exact versions differ, but IAM is container-wide.
        assert!(super::shell_secret_containers(&instance).is_err());
        Ok(())
    }
    use super::*;
    use serde_json::{Value, json};

    fn document() -> Value {
        json!({
            "installation":"company","environment":"production",
            "identity":{"scheme":"google_iap","hosted_domain":"example.com"},
            "security_shell":{"origin":"https://security.example.com","iap_audience":"/projects/12345/global/backendServices/2"},
            "apps":{"workspace":{"artifact":"artifacts/selected","readers":[],"writers":[]}},
            "control":{"version":1,"state_directory":"/srv/control","operators":["operator@example.com"],
                "sources":{"workspace_source":{"kind":"local_git","repository":"/srv/workspace"}},
                "apps":{"workspace":{"source":"workspace_source"}},
                "secrets":{
                    "reauth":{"kind":"gcp_version","project_number":12345,"secret":"reauth_client","version":3},
                    "calendar":{"kind":"gcp_version","project_number":12345,"secret":"calendar_client","version":7}
                }},
            "oauth_clients":{"version":1,
                "reauthentication":{"client_id":"123-reauth.apps.googleusercontent.com","credential":"reauth"},
                "registrations":{"calendar_registration":{"client":{"client_id":"123-calendar.apps.googleusercontent.com","credential":"calendar"},
                    "canary_subject":"112233","canary_tenant":"example.com"}}}
        })
    }

    #[test]
    fn instance_selects_public_clients_and_existing_exact_secret_versions() -> Result<()> {
        let document = document();
        let instance = Instance::from_bytes(&serde_json::to_vec(&document)?)?;
        assert_eq!(
            serde_json::to_value(&instance)?["oauth_clients"],
            document["oauth_clients"]
        );
        let selected = &instance.oauth_clients.as_ref().unwrap().reauthentication;
        assert_eq!(
            version(&instance, selected)?.resource_name(),
            "projects/12345/secrets/reauth_client/versions/3"
        );
        // Different installations own their addresses without changing a client
        // contract or introducing an authored redirect in desired metadata.
        let mut other = document;
        other["security_shell"]["origin"] = json!("https://security.other-company.example");
        assert!(Instance::from_bytes(&serde_json::to_vec(&other)?).is_ok());
        Ok(())
    }

    #[test]
    fn tagged_clients_are_closed_and_do_not_confuse_shell_and_provider_identities() -> Result<()> {
        let mut document = document();
        document["oauth_clients"]["version"] = json!(2);
        document["oauth_clients"]["registrations"]["calendar_registration"] = json!({
            "client":{"kind":"gitlab","client_id":"a".repeat(64),"credential":"calendar"},
            "canary":{"qualification_subject":"accounts.google.com:shell-human","provider_subject":"42","provider_tenant":"gitlab.com"}
        });
        let instance = Instance::from_bytes(&serde_json::to_vec(&document)?)?;
        assert_eq!(
            serde_json::to_value(&instance)?["oauth_clients"],
            document["oauth_clients"]
        );
        let client = instance
            .oauth_clients
            .as_ref()
            .unwrap()
            .registrations
            .values()
            .next()
            .unwrap()
            .client();
        assert_eq!(
            selected_provider_credential(&instance, &client)?
                .id
                .as_str(),
            "gitlab_client_credential"
        );
        for (path, value) in [
            ("/oauth_clients/version", json!(1)),
            ("/oauth_clients/version", json!(3)),
            (
                "/oauth_clients/registrations/calendar_registration/client/kind",
                json!("unreviewed"),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/client/client_id",
                json!("123-google.apps.googleusercontent.com"),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/client/credential",
                json!("reauth"),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/canary/qualification_subject",
                json!("42"),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/canary/provider_tenant",
                json!("GITLAB.COM"),
            ),
        ] {
            let mut invalid = document.clone();
            *invalid.pointer_mut(path).unwrap() = value;
            assert!(
                Instance::from_bytes(&serde_json::to_vec(&invalid)?).is_err(),
                "{path}"
            );
        }
        for field in ["secret", "ready", "origin", "token_endpoint", "scopes"] {
            let mut invalid = document.clone();
            invalid["oauth_clients"]["registrations"]["calendar_registration"]["client"][field] =
                json!(true);
            assert!(Instance::from_bytes(&serde_json::to_vec(&invalid)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn malformed_unknown_aliased_missing_or_shared_client_selections_are_refused() -> Result<()> {
        for (path, value) in [
            ("/oauth_clients/version", json!(2)),
            (
                "/oauth_clients/reauthentication/client_id",
                json!("client.apps.googleusercontent.com/attack"),
            ),
            (
                "/oauth_clients/reauthentication/credential",
                json!("missing"),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/canary_subject",
                json!(""),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/canary_tenant",
                json!("EXAMPLE.com"),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/client/client_id",
                json!("123-reauth.apps.googleusercontent.com"),
            ),
            (
                "/oauth_clients/registrations/calendar_registration/client/credential",
                json!("reauth"),
            ),
            ("/control/secrets/calendar/version", json!("latest")),
            ("/control/secrets/calendar/version", json!(0)),
            (
                "/control/secrets/calendar",
                json!({"kind":"gcp_version","project_number":12345,"secret":"reauth_client","version":3}),
            ),
            ("/security_shell", Value::Null),
        ] {
            let mut document = document();
            *document.pointer_mut(path).unwrap() = value;
            assert!(
                Instance::from_bytes(&serde_json::to_vec(&document)?).is_err(),
                "{path}"
            );
        }
        for field in ["client_secret", "callback_url", "ready"] {
            let mut document = document();
            document["oauth_clients"]["reauthentication"][field] = json!("untrusted");
            assert!(Instance::from_bytes(&serde_json::to_vec(&document)?).is_err());
        }
        for raw in [
            vec![],
            b"secret\n".to_vec(),
            b"secret value".to_vec(),
            vec![0xff],
            vec![b'x'; 2049],
        ] {
            assert!(credential(raw).is_err());
        }
        assert_eq!(credential(b"fixture-secret".to_vec())?, "fixture-secret");
        Ok(())
    }
}
