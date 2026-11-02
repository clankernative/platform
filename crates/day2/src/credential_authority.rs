//! Canonical, bounded authority for credential roots in a checked app artifact.
//! Local reads are explicitly declared and enforced by the runtime. Provider,
//! resource and imported-operation paths require later selected-instance pins.

use crate::protocol::{Database, Step};
use crate::{app_contract::CredentialAccess, artifact::Artifact};
use anyhow::{Context, Result, ensure};
pub use day2_capabilities::credentials::ManifestFamily;
use day2_capabilities::{
    Digest,
    credentials::{self, CredentialRoot},
    oauth::{AuthorityAction, AuthorityNode, OperationAuthorityContract, OperationKind},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Complete DATA read by the canonical credential authority interpreter. The
/// pure compiler probe can supply it without invoking examples or handlers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub execution: crate::app_contract::Execution,
    pub credential_access: CredentialAccess,
    pub required_all_rows: Vec<String>,
    pub export_version: u32,
}

struct DefinitionView<'a> {
    execution: &'a crate::app_contract::Execution,
    credential_access: &'a CredentialAccess,
    required_all_rows: &'a [String],
    export_version: u32,
}

struct Inputs<'a> {
    operations: &'a [crate::artifact::Operation],
    schema: &'a crate::schema::Schema,
    outputs: &'a crate::output_schema::Catalog,
}

impl<'a> From<&'a Artifact> for Inputs<'a> {
    fn from(artifact: &'a Artifact) -> Self {
        Self {
            operations: &artifact.operations,
            schema: &artifact.schema,
            outputs: &artifact.outputs,
        }
    }
}

fn checked_definition<'a>(artifact: &'a Artifact, name: &str) -> Result<DefinitionView<'a>> {
    let definition = artifact
        .app_contract
        .as_ref()
        .and_then(|contract| contract.operations.get(name))
        .with_context(|| format!("missing checked credential operation: {name}"))?;
    Ok(DefinitionView {
        execution: &definition.execution,
        credential_access: &definition.credential_access,
        required_all_rows: &definition.required_all_rows,
        export_version: definition.export_version,
    })
}

pub fn manifest(artifact: &Artifact) -> Result<Vec<ManifestFamily>> {
    manifest_with(
        &artifact.credential_declarations,
        &Inputs::from(artifact),
        &|name| checked_definition(artifact, name),
    )
}

/// Static contract derivation, never runtime permission. Final publication
/// must compare the entire result with manifest() of the admitted worker.
pub fn manifest_from_projection(
    declarations: &[credentials::FamilyDeclaration],
    operations: &[crate::artifact::Operation],
    schema: &crate::schema::Schema,
    outputs: &crate::output_schema::Catalog,
    definitions: &BTreeMap<String, Definition>,
) -> Result<Vec<ManifestFamily>> {
    ensure!(
        definitions.len() == operations.len()
            && definitions
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == operations
                    .iter()
                    .map(|operation| operation.name.as_str())
                    .collect(),
        "credential authority projection differs from checked operation inventory"
    );
    manifest_with(
        declarations,
        &Inputs {
            operations,
            schema,
            outputs,
        },
        &|name| {
            let definition = definitions
                .get(name)
                .context("credential authority projection missing")?;
            Ok(DefinitionView {
                execution: &definition.execution,
                credential_access: &definition.credential_access,
                required_all_rows: &definition.required_all_rows,
                export_version: definition.export_version,
            })
        },
    )
}

fn manifest_with<'a>(
    declarations: &[credentials::FamilyDeclaration],
    inputs: &Inputs<'_>,
    definition: &impl Fn(&str) -> Result<DefinitionView<'a>>,
) -> Result<Vec<ManifestFamily>> {
    let mut catalog = BTreeMap::new();
    for family in declarations {
        for root in &family.roots {
            if !catalog.contains_key(root) {
                let authority = derive(inputs, definition, root, &mut BTreeSet::new())
                    .with_context(|| format!("unsupported credential authority closure: {root}"))?;
                catalog.insert(
                    root.clone(),
                    CredentialRoot {
                        authority,
                        direct_ingress: !definition(root)?.execution.internal,
                        interactive_security: false,
                        single_resource_model: None,
                    },
                );
            }
        }
    }
    credentials::build_manifest(declarations.to_vec(), &catalog)
}

pub(crate) fn operation(artifact: &Artifact, name: &str) -> Result<OperationAuthorityContract> {
    derive(
        &Inputs::from(artifact),
        &|name| checked_definition(artifact, name),
        name,
        &mut BTreeSet::new(),
    )
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
    if access.interactive {
        ensure!(
            matches!(
                step,
                Step::Database(_)
                    | Step::CredentialMutation
                    | Step::Boundary(
                        crate::protocol::Boundary::Decide | crate::protocol::Boundary::Commit
                    )
            ),
            "interactive credential commands permit only local transactions"
        );
    }
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
            | Database::Select { model, .. }
            | Database::Count { model, .. },
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

fn derive<'a>(
    inputs: &Inputs<'_>,
    definition: &impl Fn(&str) -> Result<DefinitionView<'a>>,
    name: &str,
    active: &mut BTreeSet<String>,
) -> Result<OperationAuthorityContract> {
    ensure!(active.len() < 16, "credential dependency depth budget");
    ensure!(
        active.insert(name.to_owned()),
        "cyclic credential command dependency: {name}"
    );
    let result = derive_inner(inputs, definition, name, active);
    active.remove(name);
    result
}

fn derive_inner<'a>(
    inputs: &Inputs<'_>,
    definitions: &impl Fn(&str) -> Result<DefinitionView<'a>>,
    name: &str,
    active: &mut BTreeSet<String>,
) -> Result<OperationAuthorityContract> {
    let registered = inputs
        .operations
        .iter()
        .find(|operation| operation.name == name)
        .with_context(|| format!("unregistered credential operation: {name}"))?;
    let definition = definitions(name)?;
    ensure!(
        definition.credential_access.enabled,
        "credential operation requires explicit bounded authority: {name}"
    );
    ensure!(
        definition.credential_access.metadata_reads.is_empty()
            && definition.credential_access.issues.is_empty()
            && definition.credential_access.rotations.is_empty()
            && definition.credential_access.revocations.is_empty()
            && !definition.credential_access.interactive,
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
        let schema = inputs
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
                let child = derive(inputs, definitions, &effect.command, active)?;
                children.insert(effect.command.clone(), child.closure);
            }
            "external" => anyhow::bail!(
                "credential provider write requires a selected permission contract: {name}/{}",
                effect.command
            ),
            "create" | "soft_delete" | "update" | "update_created" => {
                let schema = inputs.schema.models.get(&effect.model).with_context(|| {
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
        inputs
            .schema
            .inputs
            .get(&registered.input_type)
            .context("credential input schema missing")?,
        inputs
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
            ..Default::default()
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
