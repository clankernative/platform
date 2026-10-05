//! App-owned connection intent, derived from the checked native registration.
//! Declaring a requirement does not grant provider access or qualify an instance.

use crate::artifact::Artifact;
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Name,
    oauth::{AccountBindingPolicy, ConnectionDeclaration, ConnectionOwner, ConnectionRequirement},
};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    registration: Name,
    requirement: Requirement,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Requirement {
    logical_id: String,
    revision: u32,
    capability: String,
    actions: Vec<String>,
    owner: ConnectionOwner,
    account_policy: AccountBindingPolicy,
    usage: String,
}

pub fn decode(raw: &[u8], artifact: &Artifact) -> Result<Vec<ConnectionDeclaration>> {
    ensure!(
        raw.len() <= 128 * 1024,
        "connection declaration byte budget"
    );
    let entries: Vec<Registration> = serde_json::from_slice(raw)?;
    ensure!(
        entries.len() <= 64,
        "connection requirement registration budget"
    );
    let mut declarations = Vec::new();
    for entry in entries {
        let actions = entry.requirement.actions;
        let unique = actions.iter().cloned().collect::<BTreeSet<_>>();
        ensure!(actions.len() == unique.len(), "duplicate connection action");
        declarations.push(ConnectionDeclaration {
            registration: entry.registration,
            requirement: ConnectionRequirement {
                logical_id: entry.requirement.logical_id,
                revision: entry.requirement.revision,
                capability: entry.requirement.capability,
                actions: unique,
                owner: entry.requirement.owner,
                account_policy: entry.requirement.account_policy,
                usage: entry.requirement.usage,
            },
        });
    }
    declarations.sort_by(|a, b| a.registration.cmp(&b.registration));
    validate(&declarations, artifact)?;
    Ok(declarations)
}

pub fn validate(declarations: &[ConnectionDeclaration], artifact: &Artifact) -> Result<()> {
    ensure!(
        declarations.len() <= 64,
        "connection requirement registration budget"
    );
    let mut registrations = BTreeSet::new();
    let mut logical_ids = BTreeSet::new();
    for declaration in declarations {
        let name = declaration.registration.as_str();
        ensure!(
            registrations.insert(name),
            "duplicate connection registration {name}"
        );
        let requirement = &declaration.requirement;
        requirement.validate()?;
        ensure!(
            logical_ids.insert(&requirement.logical_id),
            "duplicate logical connection requirement"
        );
        let owner = artifact
            .declarations
            .connections
            .get(name)
            .with_context(|| format!("unregistered connection requirement {name}"))?;
        ensure!(
            matches!(
                (owner.as_str(), &requirement.owner),
                ("current_human", ConnectionOwner::CurrentHuman)
                    | ("installation", ConnectionOwner::Installation)
            ),
            "connection owner differs from checked nominal declaration: {name}"
        );
        validate_access(requirement)?;
    }
    ensure!(
        registrations
            == artifact
                .declarations
                .connections
                .keys()
                .map(String::as_str)
                .collect(),
        "connection declarations differ from checked App.definition registrations"
    );
    ensure!(
        declarations
            .windows(2)
            .all(|pair| pair[0].registration < pair[1].registration),
        "connection declarations must be in canonical registration order"
    );
    Ok(())
}

/// Closed semantic contracts shared by declaration admission and reviewed
/// provider selection. Adding a capability requires a corresponding SDK contract.
pub(crate) fn validate_access(requirement: &ConnectionRequirement) -> Result<()> {
    super::catalog::validate_access(requirement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn artifact() -> Artifact {
        serde_json::from_value(json!({
            "format":14,"roc_version":"test","worker_digest":"test","schema_digest":"test",
            "sources":{},"admission":"local-spike-only",
            "schema":{"models":{},"inputs":{},"foreign_keys":[]},"operations":[],
            "declarations":{"commands":{},"queries":{},"connections":{"calendar":"current_human"}}
        }))
        .unwrap()
    }

    fn registration() -> Value {
        json!([{"registration":"calendar","requirement":{
            "logical_id":"work_calendar","revision":1,"capability":"google_calendar_events",
            "actions":["list_events","create_event"],"owner":"current_human",
            "account_policy":"mapped_human","usage":"Read and create work events."
        }}])
    }

    #[test]
    fn declarations_reject_forged_owner_actions_fields_and_inventory() -> Result<()> {
        let contract = artifact();
        let original = registration();
        let decoded = decode(&serde_json::to_vec(&original)?, &contract)?;
        assert_eq!(decoded[0].requirement.logical_id, "work_calendar");
        for (field, value) in [
            ("owner", json!("installation")),
            ("account_policy", json!("installation_account")),
            ("capability", json!("unknown_provider")),
            ("actions", json!(["delete_event"])),
            ("actions", json!(["list_events", "list_events"])),
            ("revision", json!(0)),
            ("provider_scope", json!("arbitrary")),
        ] {
            let mut forged = original.clone();
            forged[0]["requirement"][field] = value;
            assert!(
                decode(&serde_json::to_vec(&forged)?, &contract).is_err(),
                "{field}"
            );
        }
        assert!(decode(b"[]", &contract).is_err());
        let mut forged = original.clone();
        forged[0]["registration"] = json!("another");
        assert!(decode(&serde_json::to_vec(&forged)?, &contract).is_err());
        let mut duplicate = original.clone();
        duplicate.as_array_mut().unwrap().push(original[0].clone());
        assert!(decode(&serde_json::to_vec(&duplicate)?, &contract).is_err());
        let mut another = contract.clone();
        another
            .declarations
            .connections
            .insert("second".into(), "current_human".into());
        duplicate[1]["registration"] = json!("second");
        assert!(decode(&serde_json::to_vec(&duplicate)?, &another).is_err());
        Ok(())
    }

    #[test]
    fn nominal_identity_is_stable_across_usage_and_registration_but_tracks_semantic_change()
    -> Result<()> {
        let original = decode(&serde_json::to_vec(&registration())?, &artifact())?[0].clone();
        let nominal = original.requirement.nominal_identity()?;
        let mut renamed = original.clone();
        renamed.registration = Name::try_from("renamed".to_owned())?;
        renamed.requirement.usage = "Updated help text.".into();
        assert_eq!(renamed.requirement.nominal_identity()?, nominal);
        let mut changed = original.requirement;
        changed.actions.remove("create_event");
        assert_ne!(changed.nominal_identity()?, nominal);
        changed.revision += 1;
        assert_ne!(changed.nominal_identity()?, nominal);
        Ok(())
    }
}
