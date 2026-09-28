//! Roc query clients generated from a caller's exact imported closure.
//!
//! Commands retain their checked types; query functions construct observations
//! whose contract and resource authority are verified by the host.

use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;

use crate::instance_catalog::ImportedContracts;

pub const MODULE: &str = "ImportedContracts.roc";

fn type_name(operation: &str) -> Result<String> {
    ensure!(operation.len() <= 80, "imported operation name budget");
    let mut name = String::new();
    for segment in operation.split(['.', '_', '-']) {
        ensure!(
            !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "unsupported imported operation name"
        );
        let mut chars = segment.chars();
        name.extend(chars.next().unwrap().to_uppercase());
        name.extend(chars);
    }
    ensure!(
        name.as_bytes()[0].is_ascii_uppercase(),
        "invalid generated import type name"
    );
    Ok(name)
}

pub fn module(imports: &ImportedContracts) -> Result<String> {
    render(imports, false)
}

pub fn admission_module(imports: &ImportedContracts) -> Result<String> {
    render(imports, true)
}

fn render(imports: &ImportedContracts, admission: bool) -> Result<String> {
    imports.verify()?;
    let mut names = BTreeSet::new();
    let mut functions = BTreeSet::new();
    let mut source = if imports
        .operations
        .values()
        .any(|package| package.operation.kind == crate::operation_contract::Kind::Query)
    {
        String::from("import pf.Observe\n\n")
    } else {
        String::new()
    };
    source
        .push_str("# Generated from exact checked import contracts.\nImportedContracts :: [].{\n");
    for package in imports.operations.values() {
        let prefix = type_name(&package.operation.id)?;
        ensure!(names.insert(prefix.clone()), "imported type name collision");
        let input = &package
            .types
            .get(&package.operation.input)
            .context("imported input type missing")?
            .object;
        let output = &package
            .types
            .get(&package.operation.output)
            .context("imported output type missing")?
            .object;
        ensure!(
            input.dependencies.is_empty() && output.dependencies.is_empty(),
            "generated import needs self-contained structural types"
        );
        let input: crate::schema::Record = serde_json::from_value(input.schema.clone())?;
        ensure!(
            input.identity.is_none() && input.roc_type.is_none(),
            "generated import does not yet support nominal input types"
        );
        let output: crate::output_schema::Contract = serde_json::from_value(output.schema.clone())?;
        ensure!(
            package.operation.output.contains(".operation."),
            "generated import does not yet support nominal output types"
        );
        let input_fields = input
            .fields
            .iter()
            .map(|(field, kind)| {
                ensure!(
                    crate::schema::identifier(field).is_ok(),
                    "unsupported imported input field"
                );
                let shape = match kind {
                    crate::schema::Kind::Integer
                    | crate::schema::Kind::Unsigned(_)
                    | crate::schema::Kind::Text
                    | crate::schema::Kind::Boolean
                    | crate::schema::Kind::OptionalText => kind.wire_type(true).to_owned(),
                    crate::schema::Kind::InputShape { shape, .. } => shape.wire_annotation(),
                    _ => anyhow::bail!("unsupported generated import input shape"),
                };
                Ok(format!("{field} : {shape}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let input_type = if input_fields.is_empty() {
            "{}".to_owned()
        } else {
            format!("{{ {} }}", input_fields.join(", "))
        };
        source.push_str(&format!(
            "\t{prefix}Input : {input_type}\n\n\t{prefix}Output : {}\n\n",
            output.shape.wire_annotation()
        ));
        if package.operation.kind == crate::operation_contract::Kind::Query {
            let function = package.operation.id.replace(['.', '-'], "_");
            crate::schema::identifier(&function)?;
            ensure!(
                functions.insert(function.clone()),
                "imported function name collision"
            );
            let capability = if admission {
                "admission_capability"
            } else {
                "capability"
            };
            let from_host = if admission {
                "admission_from_host"
            } else {
                "from_host"
            };
            let operation = serde_json::to_string(&package.operation.id)?;
            let digest = serde_json::to_string(&package.digest)?;
            source.push_str(&format!(
                "\t{function} : {prefix}Input -> Observe({prefix}Output)\n\t{function} = |input|\n\t\tObserve.{capability}(\n\t\t\t\"app.query.v1\",\n\t\t\tJson.to_str({{ contract: {{ operation: {operation}, digest: {digest} }}, input: Json.to_str(input) }}),\n\t\t).and_then(|raw| {{\n\t\t\tparsed : Try({prefix}Output, _)\n\t\t\tparsed = Json.parse(raw)\n\t\t\tObserve.{from_host}(parsed.map_err(|_| \"invalid_imported_response\"))\n\t\t}})\n\n"
            ));
        }
    }
    source.push_str("}\n");
    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation_contract::{Codec, Kind, OperationSpec, Package, TypeObject};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};

    fn imported() -> ImportedContracts {
        let objects = BTreeMap::from([
            (
                "directory.operation.lookup.input.v1".into(),
                TypeObject {
                    id: "directory.operation.lookup.input.v1".into(),
                    codec: Codec::RocJsonV1,
                    schema: json!({"fields": {}}),
                    dependencies: BTreeSet::new(),
                },
            ),
            (
                "directory.operation.lookup.output.v1".into(),
                TypeObject {
                    id: "directory.operation.lookup.output.v1".into(),
                    codec: Codec::RocJsonV1,
                    schema: json!({
                        "shape": {"record": {"name": "string"}},
                        "roc_type": "{ name : Str }"
                    }),
                    dependencies: BTreeSet::new(),
                },
            ),
            (
                "directory.operation.lookup.error.v1".into(),
                TypeObject {
                    id: "directory.operation.lookup.error.v1".into(),
                    codec: Codec::RocJsonV1,
                    schema: json!([]),
                    dependencies: BTreeSet::new(),
                },
            ),
        ]);
        let package = Package::derive(
            OperationSpec {
                id: "directory.lookup".into(),
                version: 1,
                kind: Kind::Query,
                input: "directory.operation.lookup.input.v1".into(),
                output: "directory.operation.lookup.output.v1".into(),
                error: "directory.operation.lookup.error.v1".into(),
                semantics: json!({}),
            },
            &objects,
        )
        .unwrap();
        ImportedContracts::from_resolved(crate::instance_catalog::ResolvedImports {
            operations: BTreeMap::from([("directory.lookup".into(), package.clone())]),
            types: package.types,
        })
        .unwrap()
    }

    #[test]
    fn emits_only_pinned_structural_contracts() {
        let imports = imported();
        let source = module(&imports).unwrap();
        assert!(source.contains("DirectoryLookupInput : {}"));
        assert!(source.contains("DirectoryLookupOutput : { name : Str }"));
        assert!(
            source.contains(
                "directory_lookup : DirectoryLookupInput -> Observe(DirectoryLookupOutput)"
            )
        );
        assert!(source.contains("Observe.capability("));
        assert!(source.contains(&imports.operations["directory.lookup"].digest));
        let admission = admission_module(&imports).unwrap();
        assert!(admission.contains("Observe.admission_capability("));
        assert!(admission.contains("Observe.admission_from_host("));
        assert!(!source.contains("directory.manager"));
    }

    #[test]
    fn rejects_tampered_closure() {
        let mut imports = imported();
        imports.types.remove("directory.operation.lookup.output.v1");
        assert!(module(&imports).is_err());
    }

    #[test]
    fn commands_have_contract_types_without_a_read_function() {
        let mut imports = imported();
        let package = imports.operations.get_mut("directory.lookup").unwrap();
        let objects = package
            .types
            .values()
            .map(|pin| (pin.object.id.clone(), pin.object.clone()))
            .collect();
        let mut operation = package.operation.clone();
        operation.kind = Kind::Command;
        *package = Package::derive(operation, &objects).unwrap();
        let source = module(&imports).unwrap();
        assert!(!source.contains("import pf.Observe"));
        assert!(!source.contains("directory_lookup ="));
    }

    #[test]
    fn rejects_nominal_input_until_identity_preserving_codegen_exists() {
        let mut imports = imported();
        let package = imports.operations.get_mut("directory.lookup").unwrap();
        let input = package
            .types
            .get_mut("directory.operation.lookup.input.v1")
            .unwrap();
        input.object.schema = json!({"fields": {}, "roc_type": "Inputs.Lookup"});
        let objects = package
            .types
            .values()
            .map(|pin| (pin.object.id.clone(), pin.object.clone()))
            .collect();
        *package = Package::derive(package.operation.clone(), &objects).unwrap();
        imports.types = package.types.clone();
        assert!(module(&imports).is_err());
    }
}
