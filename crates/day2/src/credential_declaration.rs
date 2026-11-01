//! Checked app credential intent. This does not qualify authority or enable issuance.

use crate::artifact::Artifact;
use anyhow::{Context, Result, ensure};
pub use day2_capabilities::credentials::FamilyDeclaration;
use day2_capabilities::{
    Name,
    credentials::{GrantMode, ManagedProfile, SourceLocation},
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    registration: String,
    profile: String,
    id: String,
    grant_mode: String,
    roots: Vec<String>,
    lifetime_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryWire {
    families: String,
    operations: Vec<OperationWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationWire {
    operation: String,
    definition: crate::credential_authority::Definition,
}

pub struct Discovery {
    pub families: Vec<FamilyDeclaration>,
    pub operations: BTreeMap<String, crate::credential_authority::Definition>,
}

pub fn decode_discovery(
    raw: &[u8],
    catalog: &crate::registry::Catalog,
    namespace: &str,
) -> Result<Discovery> {
    ensure!(
        raw.len() <= 2 * 1024 * 1024,
        "credential authority projection byte budget"
    );
    let wire: DiscoveryWire = crate::json::decode(raw)?;
    let families = decode_catalog(wire.families.as_bytes(), catalog, namespace)?;
    let mut operations = BTreeMap::new();
    for entry in wire.operations {
        ensure!(
            operations
                .insert(entry.operation, entry.definition)
                .is_none(),
            "duplicate credential operation projection"
        );
    }
    let expected = catalog.operation_inventory(namespace)?;
    ensure!(
        operations.len() == expected.len()
            && operations
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == expected
                    .iter()
                    .map(|operation| operation.name.as_str())
                    .collect(),
        "credential operation projection inventory differs"
    );
    Ok(Discovery {
        families,
        operations,
    })
}

pub fn decode(raw: &[u8], artifact: &Artifact) -> Result<Vec<FamilyDeclaration>> {
    let operations = artifact
        .operations
        .iter()
        .map(|operation| (operation.name.as_str(), operation))
        .collect::<BTreeMap<_, _>>();
    let families = decode_targets(raw, |name, input, output| {
        let operation = operations
            .get(name)
            .with_context(|| format!("unregistered credential root {name}"))?;
        ensure!(
            operation.input_type == input && operation.output_type == output,
            "credential root {name} differs from its checked operation type"
        );
        Ok(())
    })?;
    validate(&families, artifact)?;
    Ok(families)
}

/// Pure compiled declaration discovery before the executable SDK is bound.
/// This checks target codecs against compiler reflection; final artifact
/// validation still rejects internal roots and derives complete authority.
pub fn decode_catalog(
    raw: &[u8],
    catalog: &crate::registry::Catalog,
    namespace: &str,
) -> Result<Vec<FamilyDeclaration>> {
    day2_contracts::names::identifier(namespace)?;
    let prefix = format!("{namespace}.");
    let families = decode_targets(raw, |name, input, output| {
        let local = name
            .strip_prefix(&prefix)
            .context("credential root belongs to another app")?;
        let operation = match (catalog.commands.get(local), catalog.queries.get(local)) {
            (Some(operation), None) | (None, Some(operation)) => operation,
            _ => anyhow::bail!("unregistered or ambiguous credential root {name}"),
        };
        ensure!(
            operation.input == input && operation.output == output,
            "credential root {name} differs from its checked operation type"
        );
        Ok(())
    })?;
    validate_catalog(&families, catalog)?;
    Ok(families)
}

fn decode_targets(
    raw: &[u8],
    mut validate_target: impl FnMut(&str, &str, &str) -> Result<()>,
) -> Result<Vec<FamilyDeclaration>> {
    ensure!(
        raw.len() <= 128 * 1024,
        "credential declaration byte budget"
    );
    let registered: Vec<Registration> = crate::json::decode(raw)?;
    ensure!(
        registered.len() <= 64,
        "credential family registration budget"
    );
    let mut families = Vec::new();
    for entry in registered {
        let profile = match entry.profile.as_str() {
            "client" => ManagedProfile::Client,
            "personal" => ManagedProfile::Personal,
            _ => anyhow::bail!("unsupported credential family profile"),
        };
        let grant = match entry.grant_mode.as_str() {
            "fixed" => GrantMode::Fixed,
            "selectable" => GrantMode::Selectable,
            _ => anyhow::bail!("unsupported credential grant mode"),
        };
        let mut roots = Vec::new();
        for target in entry.roots {
            let mut parts = target.split('|');
            let name = parts.next().context("credential root name missing")?;
            let input = parts.next().context("credential root input type missing")?;
            let output = parts
                .next()
                .context("credential root output type missing")?;
            ensure!(
                parts.next().is_none(),
                "invalid credential root target encoding"
            );
            validate_target(name, input, output)?;
            roots.push(name.to_owned());
        }
        families.push(FamilyDeclaration {
            registration: Name::try_from(entry.registration)?,
            id: Name::try_from(entry.id)?,
            profile,
            grant,
            roots,
            lifetime_seconds: entry.lifetime_seconds,
            // The registration is the reliable source witness at this stage.
            source: SourceLocation {
                file: "App.roc".into(),
                line: 1,
            },
        });
    }
    Ok(families)
}

pub fn validate(families: &[FamilyDeclaration], artifact: &Artifact) -> Result<()> {
    validate_catalog(families, &artifact.declarations)?;
    for family in families {
        for root in &family.roots {
            ensure!(
                artifact
                    .operations
                    .iter()
                    .any(|operation| operation.name == *root)
                    && !artifact.internal_command(root),
                "credential root {root} is not eligible for direct ingress"
            );
        }
    }
    Ok(())
}

pub fn validate_catalog(
    families: &[FamilyDeclaration],
    catalog: &crate::registry::Catalog,
) -> Result<()> {
    ensure!(
        families.len() <= 64,
        "credential family registration budget"
    );
    let mut registrations = BTreeSet::new();
    let mut ids = BTreeMap::new();
    for family in families {
        let name = family.registration.as_str();
        ensure!(
            registrations.insert(name),
            "duplicate credential registration {name}"
        );
        let previous = ids.insert(family.id.as_str(), name);
        ensure!(
            previous.is_none(),
            "credential family ID {} is registered as both {} and {name}",
            family.id.as_str(),
            previous.unwrap_or("")
        );
        let expected = catalog
            .credentials
            .get(name)
            .with_context(|| format!("unregistered credential family {name}"))?;
        ensure!(
            matches!(
                (&family.profile, expected.profile.as_str()),
                (ManagedProfile::Client, "client") | (ManagedProfile::Personal, "personal")
            ),
            "credential family {name} profile differs from checked type"
        );
        ensure!(
            family.grant == expected.grant,
            "credential family {name} grant mode differs from checked type"
        );
        ensure!(
            (1..=31_536_000).contains(&family.lifetime_seconds),
            "credential family {name} requires a bounded lifetime"
        );
        ensure!(
            !family.roots.is_empty() && family.roots.len() <= 64,
            "credential family {name} requires 1 to 64 roots"
        );
        let mut roots = BTreeSet::new();
        for root in &family.roots {
            ensure!(roots.insert(root), "duplicate credential root {root}");
        }
    }
    ensure!(
        registrations == catalog.credentials.keys().map(String::as_str).collect(),
        "credential declarations differ from checked App.definition registrations"
    );
    Ok(())
}

/// One projection is shared by the discovery probe and the final worker.
pub(crate) fn projection(catalog: &crate::registry::Catalog, product: &str) -> String {
    let families = catalog.credentials.iter().map(|(name, registration)| {
        let profile = &registration.profile;
        format!(
        "{{ registration: \"{name}\", profile: \"{profile}\", id: {product}.credentials.{name}.metadata().id, grant_mode: {product}.credentials.{name}.metadata().grant.mode, roots: {product}.credentials.{name}.metadata().grant.roots.map(|root| \"${{root.operation}}|${{root.input_type}}|${{root.output_type}}\"), lifetime_seconds: {product}.credentials.{name}.metadata().lifetime_seconds }}"
    )}).collect::<Vec<_>>().join(", ");
    format!("Json.to_str([{families}])")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn catalog() -> crate::registry::Catalog {
        catalog_for(GrantMode::Fixed)
    }

    fn catalog_for(grant: GrantMode) -> crate::registry::Catalog {
        let operation = day2_contracts::registry::Operation {
            input: "Request".into(),
            output: "Reply".into(),
        };
        crate::registry::Catalog {
            commands: BTreeMap::from([("save".into(), operation.clone())]),
            queries: BTreeMap::from([("read".into(), operation)]),
            credentials: BTreeMap::from([
                (
                    "clients".into(),
                    crate::registry::CredentialRegistration {
                        profile: "client".into(),
                        grant: grant.clone(),
                    },
                ),
                (
                    "personal".into(),
                    crate::registry::CredentialRegistration {
                        profile: "personal".into(),
                        grant,
                    },
                ),
            ]),
            ..Default::default()
        }
    }

    fn declarations(mode: &str) -> Value {
        json!([
            {"registration":"clients","profile":"client","id":"client_keys",
             "grant_mode":mode,"roots":["fixture.save|Request|Reply","fixture.read|Request|Reply"],"lifetime_seconds":3600},
            {"registration":"personal","profile":"personal","id":"personal_keys",
             "grant_mode":mode,"roots":["fixture.read|Request|Reply"],"lifetime_seconds":900}
        ])
    }

    fn decode_value(
        value: &Value,
        catalog: &crate::registry::Catalog,
    ) -> Result<Vec<FamilyDeclaration>> {
        decode_catalog(&serde_json::to_vec(value)?, catalog, "fixture")
    }

    #[test]
    fn compiled_discovery_preserves_both_local_profiles_and_exact_declared_mode() -> Result<()> {
        for (mode, expected) in [
            ("fixed", GrantMode::Fixed),
            ("selectable", GrantMode::Selectable),
        ] {
            let families = decode_value(&declarations(mode), &catalog_for(expected.clone()))?;
            assert_eq!(families.len(), 2);
            assert_eq!(families[0].grant, expected);
            assert_eq!(families[1].grant, expected);
            assert_eq!(families[0].profile, ManagedProfile::Client);
            assert_eq!(families[1].profile, ManagedProfile::Personal);
            assert_eq!(families[0].roots, ["fixture.save", "fixture.read"]);
            assert_eq!(families[1].roots, ["fixture.read"]);
            assert_eq!(families[0].lifetime_seconds, 3600);
            assert_eq!(families[1].lifetime_seconds, 900);
        }
        Ok(())
    }

    #[test]
    fn discovery_refuses_foreign_unregistered_ambiguous_and_mismatched_root_types() -> Result<()> {
        let original = declarations("selectable");
        let checked = catalog_for(GrantMode::Selectable);
        decode_value(&original, &checked)?;
        for root in [
            "another.save|Request|Reply",
            "fixture.missing|Request|Reply",
            "fixture.save|Foreign|Reply",
            "fixture.save|Request|Foreign",
            "fixture.save|Request|Reply|Extra",
            "fixture.save",
            "*|Request|Reply",
        ] {
            let mut altered = original.clone();
            altered[0]["roots"][0] = json!(root);
            assert!(decode_value(&altered, &checked).is_err(), "{root}");
        }
        let mut ambiguous = checked;
        ambiguous
            .queries
            .insert("save".into(), ambiguous.commands["save"].clone());
        assert!(decode_value(&original, &ambiguous).is_err());
        Ok(())
    }

    #[test]
    fn discovery_refuses_family_inventory_profile_and_bounded_shape_drift() -> Result<()> {
        let original = declarations("fixed");
        for (field, value) in [
            ("registration", json!("foreign")),
            ("profile", json!("personal")),
            ("id", json!("personal_keys")),
            ("grant_mode", json!("default_all")),
            ("grant_mode", json!("selectable")),
            ("roots", json!([])),
            ("roots", json!(vec!["fixture.save|Request|Reply"; 65])),
            (
                "roots",
                json!(["fixture.save|Request|Reply", "fixture.save|Request|Reply"]),
            ),
            ("lifetime_seconds", json!(0)),
            ("lifetime_seconds", json!(31_536_001)),
            ("supplied_authority", json!({})),
        ] {
            let mut altered = original.clone();
            altered[0][field] = value;
            assert!(decode_value(&altered, &catalog()).is_err(), "{field}");
        }
        assert!(decode_value(&json!([]), &catalog()).is_err());
        assert!(decode_value(&json!([original[0], original[0]]), &catalog()).is_err());
        assert!(decode_catalog(&[b' '; 131_073], &catalog(), "fixture").is_err());
        Ok(())
    }

    #[test]
    fn early_catalog_and_final_artifact_use_the_same_typed_declaration_decoder() -> Result<()> {
        let catalog = catalog();
        let artifact: Artifact = serde_json::from_value(json!({
            "format":crate::artifact::CURRENT_FORMAT,
            "verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
            "roc_version":"test","worker_digest":"test","schema_digest":"test",
            "sources":{},"admission":"local-spike-only",
            "schema":{"models":{},"inputs":{},"foreign_keys":[]},
            "declarations":catalog,
            "operations":[
                {"name":"fixture.save","kind":"command","input_type":"Request","output_type":"Reply"},
                {"name":"fixture.read","kind":"query","input_type":"Request","output_type":"Reply"}
            ]
        }))?;
        for mode in ["fixed", "selectable"] {
            let checked = catalog_for(if mode == "fixed" {
                GrantMode::Fixed
            } else {
                GrantMode::Selectable
            });
            let mut artifact = artifact.clone();
            artifact.declarations = checked.clone();
            let raw = serde_json::to_vec(&declarations(mode))?;
            assert_eq!(
                decode_catalog(&raw, &checked, "fixture")?,
                decode(&raw, &artifact)?
            );
            let mut changed = artifact.clone();
            changed.operations[0].output_type = "ChangedReply".into();
            assert!(decode(&raw, &changed).is_err());
        }
        Ok(())
    }

    #[test]
    fn worker_metadata_must_preserve_checked_profile_and_grant_mode() -> Result<()> {
        for profile in ["client", "personal"] {
            for mode in ["fixed", "selectable"] {
                let mut artifact: Artifact = serde_json::from_value(json!({
                    "format":crate::artifact::CURRENT_FORMAT,
                    "verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
                    "roc_version":"test", "worker_digest":"test", "schema_digest":"test",
                    "schema":{"models":{},"inputs":{"Request":{"fields":{}}},"foreign_keys":[]},
                    "operations":[{"name":"fixture.save","kind":"command","input_type":"Request","output_type":"Reply"}],
                    "declarations":{"commands":{"save":{"input":"Request","output":"Reply"}},"queries":{},
                        "credentials":{"keys":{"profile":profile,"grant":mode}}},
                    "sources":{},"admission":"local-spike-only"
                }))?;
                let wire = json!([{"registration":"keys","profile":profile,"id":"keys",
                    "grant_mode":mode,"roots":["fixture.save|Request|Reply"],"lifetime_seconds":3600}]);
                let raw = serde_json::to_vec(&wire)?;
                assert_eq!(decode(&raw, &artifact)?.len(), 1);
                let checked = artifact.declarations.credentials["keys"].clone();
                artifact
                    .declarations
                    .credentials
                    .get_mut("keys")
                    .unwrap()
                    .grant = if mode == "fixed" {
                    GrantMode::Selectable
                } else {
                    GrantMode::Fixed
                };
                assert!(decode(&raw, &artifact).is_err(), "mode {profile} {mode}");
                artifact
                    .declarations
                    .credentials
                    .insert("keys".into(), checked);
                artifact
                    .declarations
                    .credentials
                    .get_mut("keys")
                    .unwrap()
                    .profile = if profile == "client" {
                    "personal"
                } else {
                    "client"
                }
                .into();
                assert!(decode(&raw, &artifact).is_err(), "profile {profile} {mode}");
            }
        }
        Ok(())
    }

    #[test]
    fn authority_probe_requires_complete_typed_operation_metadata_without_unknown_or_duplicate_rows()
    -> Result<()> {
        let definition = json!({
            "execution":{"internal":false,"model":"","id_field":"","version_field":"","effects":[]},
            "credential_access":{"enabled":true,"local_reads":[]},"required_all_rows":[],"export_version":1
        });
        let original = json!({"families":declarations("selectable").to_string(),"operations":[
            {"operation":"fixture.save","definition":definition}, {"operation":"fixture.read","definition":definition}
        ]});
        let read = |value: &Value| {
            decode_discovery(
                &serde_json::to_vec(value)?,
                &catalog_for(GrantMode::Selectable),
                "fixture",
            )
        };
        let decoded = read(&original)?;
        assert_eq!(decoded.families.len(), 2);
        assert_eq!(decoded.operations.len(), 2);
        for case in 0..7 {
            let mut altered = original.clone();
            match case {
                0 => {
                    altered["operations"].as_array_mut().unwrap().pop();
                }
                1 => altered["operations"][1] = altered["operations"][0].clone(),
                2 => altered["operations"][0]["operation"] = json!("foreign.save"),
                3 => {
                    altered["operations"][0]["definition"]
                        .as_object_mut()
                        .unwrap()
                        .remove("execution");
                }
                4 => altered["operations"][0]["definition"]["supplied_authority"] = json!(true),
                5 => altered["operations"][0]["definition"]["execution"]["unknown"] = json!(true),
                _ => altered["unknown"] = json!(true),
            }
            assert!(read(&altered).is_err(), "projection mutation {case}");
        }
        assert!(decode_discovery(&vec![b' '; 2 * 1024 * 1024 + 1], &catalog(), "fixture").is_err());
        Ok(())
    }
}
