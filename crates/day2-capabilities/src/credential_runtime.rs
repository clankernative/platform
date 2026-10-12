//! Installation selectors for managed credential custody. No readiness, epoch,
//! subject mapping or secret material can be supplied by this wire contract.
use crate::{BindingRef, Digest, Name, SecretProvider};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCatalog {
    pub version: u32,
    pub apps: BTreeMap<Name, RuntimeApp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeApp {
    pub service_account: String,
    pub attestation: BindingRef,
    pub attestation_secret: Name,
    pub families: BTreeMap<Name, FamilyRuntime>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyRuntime {
    /// Alias in the existing InstallationControl.secrets catalog.
    pub verifier_secret: Name,
    pub custody: CustodyRole,
    pub max_active_lineages: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CustodyRole {
    IssuerReveal { encryption_secret: Name },
    VerifierOnly {},
}

impl<'de> Deserialize<'de> for CustodyRole {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            IssuerReveal { encryption_secret: Name },
            VerifierOnly {},
        }

        struct RoleVisitor;
        impl<'de> serde::de::Visitor<'de> for RoleVisitor {
            type Value = CustodyRole;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a custody role object")
            }

            fn visit_map<M>(self, map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let wire = Wire::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(match wire {
                    Wire::IssuerReveal { encryption_secret } => {
                        CustodyRole::IssuerReveal { encryption_secret }
                    }
                    Wire::VerifierOnly {} => CustodyRole::VerifierOnly {},
                })
            }
        }

        deserializer.deserialize_map(RoleVisitor)
    }
}

impl RuntimeCatalog {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported credential runtime version");
        ensure!(
            !self.apps.is_empty() && self.apps.len() <= 128,
            "credential runtime app budget"
        );
        for app in self.apps.values() {
            crate::oauth::ShellTransport {
                service_account: app.service_account.clone(),
            }
            .validate()?;
            ensure!(
                !app.families.is_empty() && app.families.len() <= 64,
                "credential runtime family budget"
            );
            for family in app.families.values() {
                ensure!(
                    (1..=10_000).contains(&family.max_active_lineages),
                    "credential runtime quota budget"
                );
                if let CustodyRole::IssuerReveal { encryption_secret } = &family.custody {
                    ensure!(
                        encryption_secret != &family.verifier_secret,
                        "credential key role aliases overlap"
                    );
                }
            }
        }
        Ok(())
    }
}

/// One exact key selection, suitable for the app's complete external epoch
/// key-set digest. Physical versions are reused from the operator catalog.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeySelection {
    pub namespace: crate::credentials::Namespace,
    pub family: Name,
    pub purpose: KeyPurpose,
    pub binding: BindingRef,
    pub provider: SecretProvider,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    Verifier,
    Encryption,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AttestationSelection {
    pub namespaces: Vec<crate::credentials::Namespace>,
    pub binding: BindingRef,
    pub provider: SecretProvider,
}

impl RuntimeApp {
    pub fn attestation_key(
        &self,
        scope: &crate::security_epoch::AuthorityScope,
        bindings: &BTreeMap<String, crate::credentials::CredentialFamilyBinding>,
        secrets: &BTreeMap<Name, SecretProvider>,
        shell_origin: &str,
        shell_audience: &str,
    ) -> Result<AttestationSelection> {
        let provider = secrets
            .get(&self.attestation_secret)
            .context("credential attestation alias missing")?;
        let mut namespaces = BTreeSet::new();
        for binding in bindings.values() {
            binding.namespace.validate()?;
            ensure!(
                binding.namespace.installation == scope.installation
                    && binding.namespace.environment == scope.environment
                    && binding.namespace.app == scope.app,
                "credential attestation namespace mismatch"
            );
            namespaces.insert(binding.namespace.clone());
        }
        let namespaces: Vec<_> = namespaces.into_iter().collect();
        ensure!(
            !namespaces.is_empty(),
            "credential attestation has no families"
        );
        let revision =
            attestation_revision(scope, &namespaces, provider, shell_origin, shell_audience)?;
        ensure!(
            self.attestation.revision == revision,
            "credential attestation revision mismatch"
        );
        let SecretProvider::GcpVersion {
            project_number,
            secret,
            ..
        } = provider;
        for key in self.selected_keys(bindings, secrets)? {
            let SecretProvider::GcpVersion {
                project_number: key_project,
                secret: key_secret,
                ..
            } = key.provider;
            ensure!(
                (project_number, secret) != (&key_project, &key_secret)
                    && key.binding != self.attestation,
                "credential attestation container overlaps custody role"
            );
        }
        Ok(AttestationSelection {
            namespaces,
            binding: self.attestation.clone(),
            provider: provider.clone(),
        })
    }

    pub fn selected_keys(
        &self,
        bindings: &BTreeMap<String, crate::credentials::CredentialFamilyBinding>,
        secrets: &BTreeMap<Name, SecretProvider>,
    ) -> Result<Vec<KeySelection>> {
        ensure!(
            self.families.len() == bindings.len() && !bindings.is_empty(),
            "credential runtime family selection incomplete"
        );
        let mut physical = BTreeSet::new();
        let mut logical = BTreeSet::new();
        let mut keys = Vec::new();
        for (family, runtime) in &self.families {
            let binding = bindings
                .get(family.as_str())
                .context("credential runtime family unbound")?;
            ensure!(
                &binding.family == family,
                "credential runtime family mismatch"
            );
            ensure!(
                (1..=10_000).contains(&runtime.max_active_lineages)
                    && binding.quota.revision == quota_revision(runtime.max_active_lineages)?,
                "credential selected quota revision mismatch"
            );
            let mut selections = vec![(
                KeyPurpose::Verifier,
                &binding.verifier,
                &runtime.verifier_secret,
            )];
            if let CustodyRole::IssuerReveal { encryption_secret } = &runtime.custody {
                selections.push((KeyPurpose::Encryption, &binding.custody, encryption_secret));
            }
            for (purpose, key_binding, alias) in selections {
                let provider = secrets
                    .get(alias)
                    .context("credential secret alias missing")?;
                let SecretProvider::GcpVersion {
                    project_number,
                    secret,
                    version,
                } = provider;
                ensure!(
                    physical.insert((*project_number, secret.clone(), *version))
                        && logical.insert((key_binding.id.clone(), key_binding.revision.clone())),
                    "credential exact key version or binding reused"
                );
                keys.push(KeySelection {
                    namespace: binding.namespace.clone(),
                    family: family.clone(),
                    purpose,
                    binding: key_binding.clone(),
                    provider: provider.clone(),
                });
            }
        }
        Ok(keys)
    }

    pub fn key_set(
        &self,
        scope: &crate::security_epoch::AuthorityScope,
        bindings: &BTreeMap<String, crate::credentials::CredentialFamilyBinding>,
        secrets: &BTreeMap<Name, SecretProvider>,
    ) -> Result<Digest> {
        for binding in bindings.values() {
            binding.namespace.validate()?;
            ensure!(
                binding.namespace.installation == scope.installation
                    && binding.namespace.environment == scope.environment
                    && binding.namespace.app == scope.app,
                "credential key-set namespace mismatch"
            );
        }
        Digest::of(&(
            "credential-installation-key-set-v1",
            scope,
            self.selected_keys(bindings, secrets)?,
        ))
    }
}

pub fn attestation_revision(
    scope: &crate::security_epoch::AuthorityScope,
    namespaces: &[crate::credentials::Namespace],
    provider: &SecretProvider,
    shell_origin: &str,
    shell_audience: &str,
) -> Result<Digest> {
    Digest::of(&(
        "credential-shell-attestation-key-v1",
        scope,
        namespaces,
        provider,
        shell_origin,
        shell_audience,
    ))
}

pub fn quota_revision(max_active_lineages: u32) -> Result<Digest> {
    ensure!(
        (1..=10_000).contains(&max_active_lineages),
        "credential quota budget"
    );
    Digest::of(&("credential-active-lineages-quota-v1", max_active_lineages))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credentials::{CredentialFamilyBinding, DeliveryProfile, Namespace, RotationProfile},
        oauth::{ResourceAudienceRef, SecurityOriginRef},
        security_epoch::AuthorityScope,
    };
    use std::num::NonZeroU64;

    fn name(value: &str) -> Name {
        value.to_owned().try_into().unwrap()
    }

    fn pin(value: &str) -> BindingRef {
        BindingRef::pin(name(value), &value).unwrap()
    }

    fn fixture() -> (
        RuntimeApp,
        BTreeMap<String, CredentialFamilyBinding>,
        BTreeMap<Name, SecretProvider>,
    ) {
        let app = RuntimeApp {
            service_account: "credentials@company.iam.gserviceaccount.com".into(),
            attestation: pin("attestation"),
            attestation_secret: name("attestation"),
            families: BTreeMap::from([(
                name("clients"),
                FamilyRuntime {
                    verifier_secret: name("verify"),
                    custody: CustodyRole::IssuerReveal {
                        encryption_secret: name("encrypt"),
                    },
                    max_active_lineages: 12,
                },
            )]),
        };
        let binding = CredentialFamilyBinding {
            namespace: Namespace {
                installation: name("company"),
                environment: name("staging"),
                app: name("reports"),
                binding_generation: 1,
            },
            family: name("clients"),
            approved_authority: pin("approved"),
            management: pin("management"),
            rotation: RotationProfile::AtomicReplace,
            delivery: DeliveryProfile::AuthenticatedCreatorReveal,
            verifier: pin("verifier"),
            custody: pin("custody"),
            security_shell: SecurityOriginRef(pin("shell")),
            audience: ResourceAudienceRef(pin("audience")),
            epoch_store: pin("epoch"),
            max_lifetime_seconds: 3600,
            reveal_window_seconds: 60,
            quota: BindingRef {
                id: name("quota"),
                revision: quota_revision(12).unwrap(),
            },
        };
        let secret = |id, version| SecretProvider::GcpVersion {
            project_number: NonZeroU64::new(7).unwrap(),
            secret: name(id),
            version: NonZeroU64::new(version).unwrap(),
        };
        (
            app,
            BTreeMap::from([("clients".into(), binding)]),
            BTreeMap::from([
                (name("verify"), secret("verifier", 2)),
                (name("encrypt"), secret("encryption", 3)),
            ]),
        )
    }

    #[test]
    fn exact_versions_roles_namespace_and_binding_change_key_set() {
        let (app, bindings, mut secrets) = fixture();
        let scope = AuthorityScope {
            installation: name("company"),
            environment: name("staging"),
            app: name("reports"),
        };
        let original = app.key_set(&scope, &bindings, &secrets).unwrap();
        let SecretProvider::GcpVersion { version, .. } = secrets.get_mut(&name("verify")).unwrap();
        *version = NonZeroU64::new(4).unwrap();
        assert_ne!(original, app.key_set(&scope, &bindings, &secrets).unwrap());
        let (_, _, secrets) = fixture();
        let mut rebound = bindings.clone();
        rebound.get_mut("clients").unwrap().verifier = pin("other_verifier");
        assert_ne!(original, app.key_set(&scope, &rebound, &secrets).unwrap());
        let mut other_scope = scope.clone();
        other_scope.environment = name("production");
        assert!(app.key_set(&other_scope, &bindings, &secrets).is_err());
        let mut other_bindings = bindings.clone();
        other_bindings
            .get_mut("clients")
            .unwrap()
            .namespace
            .environment = name("production");
        assert_ne!(
            original,
            app.key_set(&other_scope, &other_bindings, &secrets)
                .unwrap()
        );
        let mut regenerated = bindings.clone();
        regenerated
            .get_mut("clients")
            .unwrap()
            .namespace
            .binding_generation = 2;
        assert_ne!(
            original,
            app.key_set(&scope, &regenerated, &secrets).unwrap()
        );
        let mut verifier = app.clone();
        verifier.families.get_mut(&name("clients")).unwrap().custody = CustodyRole::VerifierOnly {};
        let keys = verifier.selected_keys(&bindings, &secrets).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].purpose, KeyPurpose::Verifier);
        assert_ne!(
            original,
            verifier.key_set(&scope, &bindings, &secrets).unwrap()
        );
    }

    #[test]
    fn physical_alias_reuse_missing_family_and_quota_change_are_denied() {
        let (mut app, bindings, mut secrets) = fixture();
        secrets.insert(name("encrypt"), secrets[&name("verify")].clone());
        assert!(app.selected_keys(&bindings, &secrets).is_err());
        let (_, _, secrets) = fixture();
        let mut invalid = bindings.clone();
        invalid.get_mut("clients").unwrap().custody = invalid["clients"].verifier.clone();
        assert!(app.selected_keys(&invalid, &secrets).is_err());
        invalid.clear();
        assert!(app.selected_keys(&invalid, &secrets).is_err());
        app.families
            .get_mut(&name("clients"))
            .unwrap()
            .max_active_lineages = 13;
        assert!(app.selected_keys(&bindings, &secrets).is_err());
        assert!(quota_revision(0).is_err());
        assert!(quota_revision(10_001).is_err());
    }

    #[test]
    fn attestation_pins_exact_namespace_edge_version_and_distinct_container() {
        let (mut app, bindings, mut secrets) = fixture();
        let scope = crate::security_epoch::AuthorityScope {
            installation: name("company"),
            environment: name("staging"),
            app: name("reports"),
        };
        let provider = SecretProvider::GcpVersion {
            project_number: NonZeroU64::new(7).unwrap(),
            secret: name("shell_attestation"),
            version: NonZeroU64::new(9).unwrap(),
        };
        secrets.insert(name("attestation"), provider.clone());
        let namespaces = vec![bindings["clients"].namespace.clone()];
        app.attestation.revision = attestation_revision(
            &scope,
            &namespaces,
            &provider,
            "https://security.company.example",
            "/projects/7/global/backendServices/9",
        )
        .unwrap();
        app.attestation_key(
            &scope,
            &bindings,
            &secrets,
            "https://security.company.example",
            "/projects/7/global/backendServices/9",
        )
        .unwrap();
        assert!(
            app.attestation_key(
                &scope,
                &bindings,
                &secrets,
                "https://reports.company.example",
                "/projects/7/global/backendServices/9"
            )
            .is_err()
        );
        let mut newer = secrets.clone();
        let SecretProvider::GcpVersion { version, .. } =
            newer.get_mut(&name("attestation")).unwrap();
        *version = NonZeroU64::new(10).unwrap();
        assert!(
            app.attestation_key(
                &scope,
                &bindings,
                &newer,
                "https://security.company.example",
                "/projects/7/global/backendServices/9"
            )
            .is_err()
        );
        let mut regenerated = bindings.clone();
        regenerated
            .get_mut("clients")
            .unwrap()
            .namespace
            .binding_generation += 1;
        assert!(
            app.attestation_key(
                &scope,
                &regenerated,
                &secrets,
                "https://security.company.example",
                "/projects/7/global/backendServices/9"
            )
            .is_err()
        );
        let reused = secrets[&name("verify")].clone();
        secrets.insert(name("attestation"), reused.clone());
        app.attestation.revision = attestation_revision(
            &scope,
            &namespaces,
            &reused,
            "https://security.company.example",
            "/projects/7/global/backendServices/9",
        )
        .unwrap();
        assert!(
            app.attestation_key(
                &scope,
                &bindings,
                &secrets,
                "https://security.company.example",
                "/projects/7/global/backendServices/9"
            )
            .is_err()
        );
    }

    #[test]
    fn custody_roles_roundtrip_exactly_and_refuse_unknown_missing_or_duplicate_fields() {
        assert_eq!(
            serde_json::to_string(&CustodyRole::VerifierOnly {}).unwrap(),
            r#"{"kind":"verifier_only"}"#
        );
        assert_eq!(
            serde_json::to_string(&CustodyRole::IssuerReveal {
                encryption_secret: name("encrypt"),
            })
            .unwrap(),
            r#"{"kind":"issuer_reveal","encryption_secret":"encrypt"}"#
        );
        for (role, wire) in [
            (
                CustodyRole::IssuerReveal {
                    encryption_secret: name("encrypt"),
                },
                serde_json::json!({"kind": "issuer_reveal", "encryption_secret": "encrypt"}),
            ),
            (
                CustodyRole::VerifierOnly {},
                serde_json::json!({"kind": "verifier_only"}),
            ),
        ] {
            assert_eq!(serde_json::to_value(&role).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CustodyRole>(wire.clone()).unwrap(),
                role
            );
            for field in ["ready", "security_epoch", "subject", "key_bytes"] {
                let mut invalid = wire.clone();
                invalid[field] = serde_json::json!(true);
                assert!(serde_json::from_value::<CustodyRole>(invalid).is_err());
            }
        }
        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"kind": null}),
            serde_json::json!("verifier_only"),
            serde_json::json!(["verifier_only"]),
            serde_json::json!(["issuer_reveal", "encrypt"]),
            serde_json::json!({"kind": "unknown"}),
            serde_json::json!({"kind": "issuer_reveal"}),
            serde_json::json!({"kind": "verifier_only", "encryption_secret": "encrypt"}),
        ] {
            assert!(serde_json::from_value::<CustodyRole>(invalid).is_err());
        }
        let (app, _, _) = fixture();
        let catalog = RuntimeCatalog {
            version: 1,
            apps: BTreeMap::from([(name("reports"), app)]),
        };
        catalog.validate().unwrap();
        for invalid_role in [
            serde_json::json!(["verifier_only"]),
            serde_json::json!(["issuer_reveal", "encrypt"]),
        ] {
            let mut invalid = serde_json::to_value(&catalog).unwrap();
            invalid["apps"]["reports"]["families"]["clients"]["custody"] = invalid_role;
            assert!(serde_json::from_value::<RuntimeCatalog>(invalid).is_err());
        }
        for duplicate in [
            r#"{"kind":"verifier_only","kind":"verifier_only"}"#,
            r#"{"kind":"issuer_reveal","encryption_secret":"encrypt","encryption_secret":"encrypt"}"#,
        ] {
            assert!(serde_json::from_str::<CustodyRole>(duplicate).is_err());
        }
    }

    #[test]
    fn wire_selectors_cannot_supply_readiness_subject_epoch_or_verifier_decryption() {
        let (app, _, _) = fixture();
        let catalog = RuntimeCatalog {
            version: 1,
            apps: BTreeMap::from([(name("reports"), app)]),
        };
        catalog.validate().unwrap();
        let value = serde_json::to_value(&catalog).unwrap();
        for field in [
            "ready",
            "security_epoch",
            "issuers",
            "observed_at",
            "key_bytes",
        ] {
            let mut invalid = value.clone();
            invalid["apps"]["reports"][field] = serde_json::json!(true);
            assert!(serde_json::from_value::<RuntimeCatalog>(invalid).is_err());
        }
        let mut invalid = value.clone();
        invalid["apps"]["reports"]["families"]["clients"]["custody"] = serde_json::json!({
            "kind": "verifier_only", "encryption_secret": "encrypt"
        });
        assert!(serde_json::from_value::<RuntimeCatalog>(invalid).is_err());
        let mut invalid = value;
        invalid["apps"]["reports"]["families"]["clients"]["max_active_lineages"] =
            serde_json::json!(0);
        assert!(
            serde_json::from_value::<RuntimeCatalog>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
