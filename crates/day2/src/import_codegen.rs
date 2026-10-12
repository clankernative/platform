//! Roc query clients generated from a caller's exact imported closure.
//!
//! Commands retain their checked types; query functions construct observations
//! whose contract and resource authority are verified by the host.

use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

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
    let mut source = if !imports.operations.is_empty() {
        String::from("import pf.Observe\n\n")
    } else {
        String::new()
    };
    if imports
        .operations
        .values()
        .any(|package| package.operation.kind == crate::operation_contract::Kind::Command)
    {
        source.push_str("import pf.Effects\n\n");
    }
    source
        .push_str("# Generated from exact checked import contracts.\nImportedContracts :: [].{\n");
    let mut types = BTreeMap::new();
    let mut shapes = BTreeMap::new();
    for package in imports.operations.values() {
        for id in [&package.operation.input, &package.operation.output] {
            if types.contains_key(id) {
                continue;
            }
            let object = &package
                .types
                .get(id)
                .context("imported type missing")?
                .object;
            let contract: crate::output_schema::Contract = if object.schema.get("fields").is_some()
            {
                crate::operation_contract::input_contract(&serde_json::from_value(
                    object.schema.clone(),
                )?)?
            } else {
                serde_json::from_value(object.schema.clone())?
            };
            ensure!(
                object.dependencies.is_empty(),
                "unsupported imported codec dependencies"
            );
            let nominal = crate::schema::roc_type_name(&contract.roc_type).is_ok()
                && matches!(contract.shape, crate::output_schema::Type::Record(_));
            let wire = if matches!(&contract.shape, crate::output_schema::Type::Record(fields) if fields.is_empty())
            {
                "{}".into()
            } else {
                contract.shape.wire_annotation()
            };
            let annotation = if nominal {
                let name = format!("Contract{}", &crate::digest(id.as_bytes())[7..23]);
                source.push_str(&format!("\t{name} := {}\n\n", wire));
                name
            } else {
                wire
            };
            types.insert(id.clone(), annotation);
            shapes.insert(id.clone(), contract.shape);
        }
    }
    for package in imports.operations.values() {
        let prefix = type_name(&package.operation.id)?;
        ensure!(names.insert(prefix.clone()), "imported type name collision");
        let input_type = &types[&package.operation.input];
        let output_type = &types[&package.operation.output];
        source.push_str(&format!(
            "\t{prefix}Input : {input_type}\n\n\t{prefix}Output : {}\n\n",
            output_type
        ));
        let function = package.operation.id.replace(['.', '-'], "_");
        if package.operation.kind == crate::operation_contract::Kind::Query {
            day2_contracts::names::identifier(&function)?;
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
            let input = match &shapes[&package.operation.input] {
                crate::output_schema::Type::Record(fields) => format!(
                    "{{ {} }}",
                    fields
                        .keys()
                        .map(|field| format!("{field}: input.{field}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                _ => "input".into(),
            };
            let output = match &shapes[&package.operation.output] {
                crate::output_schema::Type::Record(fields) => format!(
                    "{{ {} }}",
                    fields
                        .keys()
                        .map(|field| format!("{field}: dto.{field}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                _ => "dto".into(),
            };
            let wire_output = shapes[&package.operation.output].wire_annotation();
            let argument = if input == "{  }" { "_input" } else { "input" };
            source.push_str(&format!(
                "\t{function} : {prefix}Input -> Observe({prefix}Output)\n\t{function} = |{argument}|\n\t\tObserve.{capability}(\n\t\t\t\"app.query.v1\",\n\t\t\tJson.to_str({{ contract: {{ operation: {operation}, digest: {digest} }}, input: Json.to_str({input}) }}),\n\t\t).and_then(|raw| {{\n\t\t\tparsed : Try({wire_output}, _)\n\t\t\tparsed = Json.parse(raw)\n\t\t\tresult : Try({prefix}Output, Str)\n\t\t\tresult = match parsed {{\n\t\t\t\tOk(dto) => Ok({output})\n\t\t\t\tErr(_) => Err(\"invalid_imported_response\")\n\t\t\t}}\n\t\t\tObserve.{from_host}(result)\n\t\t}})\n\n"
            ));
        } else {
            let send = format!("{function}_send");
            let status = format!("{function}_status");
            day2_contracts::names::identifier(&send)?;
            day2_contracts::names::identifier(&status)?;
            ensure!(
                functions.insert(send.clone()) && functions.insert(status.clone()),
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
            let input = match &shapes[&package.operation.input] {
                crate::output_schema::Type::Record(fields) => format!(
                    "{{ {} }}",
                    fields
                        .keys()
                        .map(|field| format!("{field}: input.{field}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                _ => "input".into(),
            };
            let argument = if input == "{  }" { "_input" } else { "input" };
            source.push_str(&format!(
                "\t{prefix}Receipt := {{ id : Str }}\n\n\t{prefix}Status : [Pending, Success, Refused, Blocked, Unknown]\n\n\t{send} : {prefix}Input -> Effects({prefix}Receipt)\n\t{send} = |{argument}|\n\t\tEffects.{capability}(\n\t\t\t\"app.send.v1\",\n\t\t\tJson.to_str({{ contract: {{ operation: {operation}, digest: {digest} }}, input: Json.to_str({input}) }}),\n\t\t).and_then(|raw| {{\n\t\t\tparsed : Try({{ id : Str, status : Str }}, _)\n\t\t\tparsed = Json.parse(raw)\n\t\t\tresult : Try({prefix}Receipt, Str)\n\t\t\tresult = match parsed {{\n\t\t\t\tOk(dto) if dto.status == \"accepted\" => Ok({{ id: dto.id }})\n\t\t\t\t_ => Err(\"invalid_imported_receipt\")\n\t\t\t}}\n\t\t\tEffects.{from_host}(result)\n\t\t}})\n\n\t{status} : {prefix}Receipt -> Observe({prefix}Status)\n\t{status} = |receipt|\n\t\tObserve.{capability}(\n\t\t\t\"app.status.v1\",\n\t\t\tJson.to_str({{ contract: {{ operation: {operation}, digest: {digest} }}, input: Json.to_str({{ id: receipt.id }}) }}),\n\t\t).and_then(|raw| {{\n\t\t\tparsed : Try({{ id : Str, status : Str }}, _)\n\t\t\tparsed = Json.parse(raw)\n\t\t\tresult : Try({prefix}Status, Str)\n\t\t\tresult = match parsed {{\n\t\t\t\tOk(dto) if dto.id == receipt.id => match dto.status {{\n\t\t\t\t\t\"pending\" => Ok(Pending)\n\t\t\t\t\t\"success\" => Ok(Success)\n\t\t\t\t\t\"refused\" => Ok(Refused)\n\t\t\t\t\t\"blocked\" => Ok(Blocked)\n\t\t\t\t\t\"unknown\" => Ok(Unknown)\n\t\t\t\t\t_ => Err(\"invalid_imported_status\")\n\t\t\t\t}}\n\t\t\t\t_ => Err(\"invalid_imported_status\")\n\t\t\t}}\n\t\t\tObserve.{from_host}(result)\n\t\t}})\n\n"
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
    fn commands_generate_effects_and_scoped_status_reads() {
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
        assert!(source.contains("import pf.Observe"));
        assert!(source.contains(
            "directory_lookup_send : DirectoryLookupInput -> Effects(DirectoryLookupReceipt)"
        ));
        assert!(source.contains(
            "directory_lookup_status : DirectoryLookupReceipt -> Observe(DirectoryLookupStatus)"
        ));
        assert!(
            admission_module(&imports)
                .unwrap()
                .contains("Effects.admission_capability(")
        );
        assert!(!source.contains("directory_lookup ="));
    }

    #[test]
    fn emits_a_stable_nominal_input_type() {
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
        let source = module(&imports).unwrap();
        assert!(source.contains(" := {}"));
        assert!(source.contains("DirectoryLookupInput : Contract"));
    }
}
