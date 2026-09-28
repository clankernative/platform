//! Checked app credential intent. This does not qualify authority or enable issuance.

use crate::artifact::Artifact;
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Name,
    credentials::{FamilyDeclaration, GrantMode, ManagedProfile, SourceLocation},
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

pub fn decode(raw: &[u8], artifact: &Artifact) -> Result<Vec<FamilyDeclaration>> {
    ensure!(
        raw.len() <= 128 * 1024,
        "credential declaration byte budget"
    );
    let registered: Vec<Registration> = serde_json::from_slice(raw)?;
    ensure!(
        registered.len() <= 64,
        "credential family registration budget"
    );
    let operations = artifact
        .operations
        .iter()
        .map(|operation| (operation.name.as_str(), operation))
        .collect::<BTreeMap<_, _>>();
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
            let operation = operations
                .get(name)
                .with_context(|| format!("unregistered credential root {name}"))?;
            ensure!(
                operation.input_type == input && operation.output_type == output,
                "credential root {name} differs from its checked operation type"
            );
            ensure!(
                !artifact.internal_command(name),
                "internal command cannot be a direct credential root"
            );
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
    validate(&families, artifact)?;
    Ok(families)
}

pub fn validate(families: &[FamilyDeclaration], artifact: &Artifact) -> Result<()> {
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
        let expected = artifact
            .declarations
            .credentials
            .get(name)
            .with_context(|| format!("unregistered credential family {name}"))?;
        ensure!(
            matches!(
                (&family.profile, expected.as_str()),
                (ManagedProfile::Client, "client") | (ManagedProfile::Personal, "personal")
            ),
            "credential family {name} profile differs from checked type"
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
    ensure!(
        registrations
            == artifact
                .declarations
                .credentials
                .keys()
                .map(String::as_str)
                .collect(),
        "credential declarations differ from checked App.definition registrations"
    );
    Ok(())
}
