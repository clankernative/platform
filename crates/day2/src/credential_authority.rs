//! Canonical, bounded authority for credential roots in a checked app artifact.
//! Local reads are explicitly declared and enforced by the runtime. Provider,
//! resource and imported-operation paths require later selected-instance pins.

use crate::protocol::{Database, Step};
use crate::{app_contract::CredentialAccess, artifact::Artifact};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{self, CredentialRoot, ManifestFamily},
    oauth::{AuthorityAction, AuthorityNode, OperationAuthorityContract, OperationKind},
};
use std::collections::{BTreeMap, BTreeSet};

pub fn manifest(artifact: &Artifact) -> Result<Vec<ManifestFamily>> {
    let mut catalog = BTreeMap::new();
    for family in &artifact.credential_declarations {
        for root in &family.roots {
            if !catalog.contains_key(root) {
                let authority = derive(artifact, root, &mut BTreeSet::new())
                    .with_context(|| format!("unsupported credential authority closure: {root}"))?;
                catalog.insert(
                    root.clone(),
                    CredentialRoot {
                        authority,
                        direct_ingress: !artifact.internal_command(root),
                        interactive_security: false,
                        single_resource_model: None,
                    },
                );
            }
        }
    }
    credentials::build_manifest(artifact.credential_declarations.clone(), &catalog)
}

/// The same declared bound used to build a manifest is enforced for every
/// invocation of an opted-in operation, regardless of ingress channel.
pub(crate) fn check_step(artifact: &Artifact, operation: &str, step: Step<'_>) -> Result<()> {
    let Some(access) = artifact
        .app_contract
        .as_ref()
        .and_then(|contract| contract.operations.get(operation))
        .map(|definition| &definition.credential_access)
    else {
        return Ok(());
    };
    if !access.enabled {
        return Ok(());
    }
    check_access(access, operation, step)
}

fn check_access(access: &CredentialAccess, operation: &str, step: Step<'_>) -> Result<()> {
    match step {
        Step::Database(
            Database::Get { model, .. }
            | Database::Page { model, .. }
            | Database::Select { model, .. },
        ) => ensure!(
            access.local_reads.iter().any(|declared| declared == model),
            "undeclared credential local read: {operation}/{model}"
        ),
        Step::Observe { capability, .. } if crate::credential_codegen::observation(capability) => {}
        Step::Observe { .. } | Step::External { .. } => {
            anyhow::bail!("unsupported credential provider or resource path: {operation}")
        }
        _ => {}
    }
    Ok(())
}

fn derive(
    artifact: &Artifact,
    name: &str,
    active: &mut BTreeSet<String>,
) -> Result<OperationAuthorityContract> {
    ensure!(active.len() < 16, "credential dependency depth budget");
    ensure!(
        active.insert(name.to_owned()),
        "cyclic credential command dependency: {name}"
    );
    let result = derive_inner(artifact, name, active);
    active.remove(name);
    result
}

fn derive_inner(
    artifact: &Artifact,
    name: &str,
    active: &mut BTreeSet<String>,
) -> Result<OperationAuthorityContract> {
    let registered = artifact
        .operations
        .iter()
        .find(|operation| operation.name == name)
        .with_context(|| format!("unregistered credential operation: {name}"))?;
    let definition = artifact
        .app_contract
        .as_ref()
        .and_then(|contract| contract.operations.get(name))
        .with_context(|| format!("missing checked credential operation: {name}"))?;
    ensure!(
        definition.credential_access.enabled,
        "credential operation requires explicit bounded authority: {name}"
    );
    ensure!(
        definition.credential_access.metadata_reads.is_empty(),
        "credential metadata cannot be a credential ingress root: {name}"
    );
    ensure!(
        definition
            .required_all_rows
            .iter()
            .all(|model| definition.credential_access.local_reads.contains(model)),
        "credential operation has undeclared all-rows read: {name}"
    );

    let mut actions = BTreeSet::new();
    for model in &definition.credential_access.local_reads {
        let schema = artifact
            .schema
            .models
            .get(model)
            .with_context(|| format!("unknown credential read model: {name}/{model}"))?;
        actions.insert(AuthorityAction::LocalData {
            category: model.clone(),
            policy: Digest::of(&("credential-local-read-v1", model, schema))?,
            write: false,
        });
    }
    let mut children = BTreeMap::new();
    for effect in &definition.execution.effects {
        match effect.kind.as_str() {
            "request" => {
                let child = derive(artifact, &effect.command, active)?;
                children.insert(effect.command.clone(), child.closure);
            }
            "external" => anyhow::bail!(
                "credential provider write requires a selected permission contract: {name}/{}",
                effect.command
            ),
            "create" | "soft_delete" | "update" | "update_created" => {
                let schema = artifact.schema.models.get(&effect.model).with_context(|| {
                    format!("unknown credential write model: {name}/{}", effect.model)
                })?;
                // A local mutation returns its full row under the model's read
                // grant, so that read is reachable even without an explicit
                // Query step in the handler.
                actions.insert(AuthorityAction::LocalData {
                    category: effect.model.clone(),
                    policy: Digest::of(&("credential-local-write-result-read-v1", effect, schema))?,
                    write: false,
                });
                actions.insert(AuthorityAction::LocalData {
                    category: effect.model.clone(),
                    policy: Digest::of(&("credential-local-write-v1", effect, schema))?,
                    write: true,
                });
            }
            _ => anyhow::bail!("unsupported credential effect: {name}/{}", effect.kind),
        }
    }
    let kind = match registered.kind.as_str() {
        "query" => OperationKind::Query,
        "command" => OperationKind::Command,
        _ => anyhow::bail!("unsupported credential operation kind: {name}"),
    };
    let operation_contract = Digest::of(&(
        "credential-operation-contract-v1",
        &registered.name,
        &registered.kind,
        &registered.input_type,
        &registered.output_type,
        artifact
            .schema
            .inputs
            .get(&registered.input_type)
            .context("credential input schema missing")?,
        artifact
            .outputs
            .get(&registered.output_type)
            .context("credential output schema missing")?,
        &definition.execution,
        &definition.credential_access,
        &definition.required_all_rows,
    ))?;
    OperationAuthorityContract::derive(
        name.to_owned(),
        definition.export_version.max(1),
        operation_contract,
        kind,
        AuthorityNode { actions, children },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marked_operations_enforce_the_declared_read_envelope() {
        let access = CredentialAccess {
            enabled: true,
            local_reads: vec!["reports".into()],
            metadata_reads: Vec::new(),
        };
        fn read(model: &str) -> Step<'_> {
            Step::Database(Database::Select {
                model,
                data: "{}",
                find: true,
            })
        }
        assert!(check_access(&access, "reports.list", read("reports")).is_ok());
        assert!(check_access(&access, "reports.list", read("secrets")).is_err());
        assert!(
            check_access(
                &access,
                "reports.list",
                Step::Observe {
                    capability: "notifications.latest.v1",
                    input: "{}",
                },
            )
            .is_err()
        );
    }
}
