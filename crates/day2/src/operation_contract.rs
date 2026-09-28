//! Immutable per-operation contract objects and their exact type closure.
//!
//! This model deliberately has no app artifact or catalog digest in a package:
//! adding an unrelated export cannot change an existing caller's pinned input.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeObject {
    /// Stable nominal identity, independent of artifact and catalog revisions.
    pub id: String,
    pub codec: Codec,
    pub schema: Value,
    pub dependencies: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Codec {
    RocJsonV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Query,
    Command,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSpec {
    pub id: String,
    pub version: u32,
    pub kind: Kind,
    pub input: String,
    pub output: String,
    pub error: String,
    /// Caller-relevant prerequisites and execution meaning, in canonical form.
    pub semantics: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypePin {
    pub digest: String,
    pub object: TypeObject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub operation: OperationSpec,
    pub digest: String,
    pub types: BTreeMap<String, TypePin>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub app: String,
    pub digest: String,
    pub exports: BTreeMap<String, Package>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportPin {
    pub operation: String,
    pub version: u32,
    pub digest: String,
}

fn type_pin(id: &str, catalog: &BTreeMap<String, TypeObject>) -> Result<TypePin> {
    let object = catalog
        .get(id)
        .with_context(|| format!("missing contract type {id}"))?;
    ensure!(object.id == id, "contract type key mismatch");
    ensure!(
        !id.is_empty() && !object.schema.is_null(),
        "invalid contract type"
    );
    let digest = crate::digest(&serde_json::to_vec(object)?);
    Ok(TypePin {
        digest,
        object: object.clone(),
    })
}

fn visit(
    id: &str,
    catalog: &BTreeMap<String, TypeObject>,
    active: &mut BTreeSet<String>,
    pins: &mut BTreeMap<String, TypePin>,
) -> Result<()> {
    if pins.contains_key(id) {
        return Ok(());
    }
    ensure!(
        pins.len() + active.len() < 1024,
        "contract type closure budget"
    );
    ensure!(
        active.insert(id.to_owned()),
        "cyclic contract type dependency"
    );
    let pin = type_pin(id, catalog)?;
    for dependency in &pin.object.dependencies {
        visit(dependency, catalog, active, pins)?;
    }
    active.remove(id);
    pins.insert(id.to_owned(), pin);
    Ok(())
}

impl Package {
    pub fn derive(
        operation: OperationSpec,
        catalog: &BTreeMap<String, TypeObject>,
    ) -> Result<Self> {
        ensure!(
            !operation.id.is_empty() && operation.version > 0,
            "invalid operation identity"
        );
        ensure!(
            !operation.input.is_empty()
                && !operation.output.is_empty()
                && !operation.error.is_empty(),
            "incomplete operation contract"
        );
        ensure!(
            !operation.semantics.is_null(),
            "missing operation semantics"
        );
        let mut types = BTreeMap::new();
        let mut active = BTreeSet::new();
        for id in [&operation.input, &operation.output, &operation.error] {
            visit(id, catalog, &mut active, &mut types)?;
        }
        let digests = types
            .iter()
            .map(|(id, pin)| (id, &pin.digest))
            .collect::<BTreeMap<_, _>>();
        let digest = crate::digest(&serde_json::to_vec(&(&operation, digests))?);
        Ok(Self {
            operation,
            digest,
            types,
        })
    }

    pub fn verify(&self) -> Result<()> {
        let catalog = self
            .types
            .iter()
            .map(|(id, pin)| (id.clone(), pin.object.clone()))
            .collect();
        let expected = Self::derive(self.operation.clone(), &catalog)?;
        ensure!(
            self == &expected,
            "operation contract digest or closure mismatch"
        );
        Ok(())
    }
}

impl Manifest {
    /// Derive the export inventory from the app's checked, registered operation
    /// definitions. The first codec admits only self-contained structural types.
    pub fn from_checked_artifact(artifact: &crate::artifact::Artifact) -> Result<Self> {
        let definitions = artifact
            .app_contract
            .as_ref()
            .context("checked application contract required for exports")?;
        let mut types = BTreeMap::new();
        let mut exports = Vec::new();
        for (name, definition) in &definitions.operations {
            let version = definition.export_version;
            if version == 0 {
                continue;
            }
            ensure!(version == 1, "unsupported cross-app export version");
            ensure!(
                !definition.execution.internal,
                "internal command cannot be exported"
            );
            let operation = artifact
                .operations
                .iter()
                .find(|operation| &operation.name == name)
                .context("export missing registered operation")?;
            let local_name = name
                .strip_prefix(&format!("{}.", artifact.namespace))
                .context("export operation namespace mismatch")?;
            let input = artifact
                .schema
                .inputs
                .get(&operation.input_type)
                .context("export missing checked input")?;
            let output = artifact
                .outputs
                .get(&operation.output_type)
                .context("export missing checked output")?;
            ensure!(
                input.fields.values().all(supported_input),
                "cross-app input requires a self-contained structural codec"
            );
            ensure!(
                supported_output(&output.shape),
                "cross-app output requires a self-contained structural codec"
            );
            let input_id = type_id(
                &artifact.namespace,
                local_name,
                "input",
                version,
                input.roc_type.as_deref(),
            );
            let output_id = type_id(
                &artifact.namespace,
                local_name,
                "output",
                version,
                Some(&output.roc_type),
            );
            let error_id = format!(
                "{}.operation.{local_name}.error.v{version}",
                artifact.namespace
            );
            insert_type(
                &mut types,
                TypeObject {
                    id: input_id.clone(),
                    codec: Codec::RocJsonV1,
                    schema: serde_json::to_value(input)?,
                    dependencies: BTreeSet::new(),
                },
            )?;
            insert_type(
                &mut types,
                TypeObject {
                    id: output_id.clone(),
                    codec: Codec::RocJsonV1,
                    schema: serde_json::to_value(output)?,
                    dependencies: BTreeSet::new(),
                },
            )?;
            insert_type(
                &mut types,
                TypeObject {
                    id: error_id.clone(),
                    codec: Codec::RocJsonV1,
                    schema: serde_json::to_value(&definition.errors)?,
                    dependencies: BTreeSet::new(),
                },
            )?;
            let kind = match operation.kind.as_str() {
                "query" => Kind::Query,
                "command" => Kind::Command,
                _ => anyhow::bail!("invalid exported operation kind"),
            };
            exports.push(OperationSpec {
                id: name.clone(),
                version,
                kind,
                input: input_id,
                output: output_id,
                error: error_id,
                semantics: serde_json::json!({
                    "required_all_rows": definition.required_all_rows,
                    "preconditions": definition.intent.usage.preconditions,
                }),
            });
        }
        Self::derive(artifact.namespace.clone(), exports, &types)
    }

    /// `exports` is the set explicitly selected by the checked app definition.
    /// An internal operation must never be passed as an export by the builder.
    pub fn derive(
        app: String,
        exports: impl IntoIterator<Item = OperationSpec>,
        catalog: &BTreeMap<String, TypeObject>,
    ) -> Result<Self> {
        ensure!(!app.is_empty(), "missing export app identity");
        let mut packages = BTreeMap::new();
        for operation in exports {
            ensure!(
                operation.id.starts_with(&format!("{app}.")),
                "export operation belongs to a different app"
            );
            let id = operation.id.clone();
            ensure!(
                packages
                    .insert(id, Package::derive(operation, catalog)?)
                    .is_none(),
                "duplicate exported operation"
            );
        }
        let digests = packages
            .iter()
            .map(|(id, package)| (id, &package.digest))
            .collect::<BTreeMap<_, _>>();
        let digest = crate::digest(&serde_json::to_vec(&(&app, digests))?);
        Ok(Self {
            app,
            digest,
            exports: packages,
        })
    }

    pub fn verify(&self) -> Result<()> {
        let mut catalog = BTreeMap::new();
        for package in self.exports.values() {
            package.verify()?;
            for (id, pin) in &package.types {
                if let Some(previous) = catalog.insert(id.clone(), pin.object.clone()) {
                    ensure!(
                        previous == pin.object,
                        "conflicting exported nominal type {id}"
                    );
                }
            }
        }
        let expected = Self::derive(
            self.app.clone(),
            self.exports
                .values()
                .map(|package| package.operation.clone()),
            &catalog,
        )?;
        ensure!(self == &expected, "export manifest digest mismatch");
        Ok(())
    }

    pub fn resolve<'a>(&'a self, pins: &[ImportPin]) -> Result<Vec<&'a Package>> {
        self.verify()?;
        let mut seen = BTreeSet::new();
        let mut packages = Vec::new();
        for pin in pins {
            ensure!(seen.insert(&pin.operation), "duplicate imported operation");
            let package = self
                .exports
                .get(&pin.operation)
                .with_context(|| format!("operation not exported: {}", pin.operation))?;
            ensure!(
                package.operation.version == pin.version && package.digest == pin.digest,
                "imported operation contract mismatch: {}",
                pin.operation
            );
            packages.push(package);
        }
        resolve_type_closure(packages.iter().copied())?;
        Ok(packages)
    }
}

fn type_id(app: &str, operation: &str, side: &str, version: u32, roc_type: Option<&str>) -> String {
    if let Some(name) = roc_type.filter(|name| crate::schema::roc_type_name(name).is_ok()) {
        format!("{app}.type.{name}")
    } else {
        format!("{app}.operation.{operation}.{side}.v{version}")
    }
}

fn insert_type(catalog: &mut BTreeMap<String, TypeObject>, object: TypeObject) -> Result<()> {
    if let Some(previous) = catalog.insert(object.id.clone(), object.clone()) {
        ensure!(
            previous == object,
            "conflicting exported nominal type {}",
            object.id
        );
    }
    Ok(())
}

fn supported_input(kind: &crate::schema::Kind) -> bool {
    use crate::schema::Kind as K;
    match kind {
        K::Integer | K::Unsigned(_) | K::Text | K::Boolean | K::OptionalText => true,
        K::InputShape { shape, .. } => supported_output(shape),
        _ => false,
    }
}

fn supported_output(shape: &crate::output_schema::Type) -> bool {
    use crate::output_schema::Type as T;
    match shape {
        T::String | T::OptionalText | T::Integer | T::Unsigned(_) | T::Boolean => true,
        T::Record(fields) => fields.values().all(supported_output),
        T::List(item) => supported_output(item),
        _ => false,
    }
}

/// Merge only the types actually used by a caller's imported operations.
pub fn resolve_type_closure<'a>(
    packages: impl IntoIterator<Item = &'a Package>,
) -> Result<BTreeMap<String, TypePin>> {
    let mut closure: BTreeMap<String, TypePin> = BTreeMap::new();
    for package in packages {
        package.verify()?;
        for (id, pin) in &package.types {
            if let Some(existing) = closure.get(id) {
                ensure!(
                    existing.digest == pin.digest,
                    "conflicting schema for nominal contract type {id}"
                );
            } else {
                closure.insert(id.clone(), pin.clone());
            }
        }
    }
    Ok(closure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn checked_operation(name: &str, input_type: &str, export_version: u32) -> Value {
        json!({
            "intent": {
                "target": {"operation":name,"input_type":input_type,"output_type":"person"},
                "title":"t",
                "usage":{"purpose":"p","use_when":[],"avoid_when":[],"preconditions":[],"effects":[],"result":"r"},
                "inputs":[],"outputs":[],"input_sources":[],"follow_ups":[]
            },
            "request_example":"{}","response_example":"{}","deprecated":false,
            "export_version":export_version,
            "execution":{"internal":false,"model":"","id_field":"","version_field":"","effects":[]},
            "errors":[],"required_all_rows":[]
        })
    }

    fn checked_artifact() -> crate::artifact::Artifact {
        serde_json::from_value(json!({
            "format":14,"namespace":"directory","roc_version":"test","worker_digest":"test",
            "schema_digest":"test","sources":{},"admission":"local-spike-only",
            "schema":{"models":{},"inputs":{"person":{"fields":{"name":"text"},"roc_type":"DirectoryTypes.Person"}},"foreign_keys":[]},
            "outputs":{"person":{"shape":{"record":{"name":"string"}},"roc_type":"{ name : Str }"}},
            "operations":[{"name":"directory.lookup","kind":"query","input_type":"person","output_type":"person"}],
            "app_contract":{
                "operations":{"directory.lookup":checked_operation("directory.lookup","person",1)},
                "presentation":{"stylesheet":"","script":""},"identities":"model-identities.json",
                "invariants":{},"domains":{},"errors":{}
            }
        })).unwrap()
    }

    fn ty(id: &str, schema: Value, dependencies: &[&str]) -> TypeObject {
        TypeObject {
            id: id.into(),
            codec: Codec::RocJsonV1,
            schema,
            dependencies: dependencies.iter().map(|id| (*id).into()).collect(),
        }
    }

    fn catalog() -> BTreeMap<String, TypeObject> {
        [
            ty(
                "directory.PersonId.v1",
                json!({"nominal":"PersonId","wire":"string"}),
                &[],
            ),
            ty(
                "directory.LookupInput.v1",
                json!({"person":"directory.PersonId.v1"}),
                &["directory.PersonId.v1"],
            ),
            ty("directory.PersonSummary.v1", json!({"name":"string"}), &[]),
            ty("directory.LookupFailure.v1", json!({"missing":"unit"}), &[]),
            ty(
                "directory.ManagerInput.v1",
                json!({"person":"directory.PersonId.v1"}),
                &["directory.PersonId.v1"],
            ),
            ty(
                "directory.ManagerOutput.v1",
                json!({"manager":"directory.PersonId.v1"}),
                &["directory.PersonId.v1"],
            ),
        ]
        .into_iter()
        .map(|object| (object.id.clone(), object))
        .collect()
    }

    fn lookup() -> OperationSpec {
        OperationSpec {
            id: "directory.lookup".into(),
            version: 1,
            kind: Kind::Query,
            input: "directory.LookupInput.v1".into(),
            output: "directory.PersonSummary.v1".into(),
            error: "directory.LookupFailure.v1".into(),
            semantics: json!({"phase":"observe"}),
        }
    }

    #[test]
    fn unrelated_export_does_not_change_existing_package() {
        let before = Package::derive(lookup(), &catalog()).unwrap();
        let mut expanded = catalog();
        expanded.insert(
            "directory.NewType.v1".into(),
            ty("directory.NewType.v1", json!({"value":"integer"}), &[]),
        );
        let after = Package::derive(lookup(), &expanded).unwrap();
        assert_eq!(before, after);
        assert!(!after.types.contains_key("directory.NewType.v1"));
        after.verify().unwrap();
    }

    #[test]
    fn manifest_inventory_changes_without_repinning_an_unrelated_import() {
        let before = Manifest::derive("directory".into(), [lookup()], &catalog()).unwrap();
        let lock = ImportPin {
            operation: "directory.lookup".into(),
            version: 1,
            digest: before.exports["directory.lookup"].digest.clone(),
        };
        let manager = OperationSpec {
            id: "directory.manager".into(),
            version: 1,
            kind: Kind::Query,
            input: "directory.ManagerInput.v1".into(),
            output: "directory.ManagerOutput.v1".into(),
            error: "directory.LookupFailure.v1".into(),
            semantics: json!({"phase":"observe"}),
        };
        let after = Manifest::derive("directory".into(), [lookup(), manager], &catalog()).unwrap();
        assert_ne!(before.digest, after.digest);
        assert_eq!(
            before.exports["directory.lookup"],
            after.exports["directory.lookup"]
        );
        assert_eq!(after.resolve(&[lock]).unwrap().len(), 1);
        assert!(
            after
                .resolve(&[ImportPin {
                    operation: "directory.lookup".into(),
                    version: 2,
                    digest: before.exports["directory.lookup"].digest.clone(),
                }])
                .is_err()
        );
    }

    #[test]
    fn checked_export_locality_tracks_only_its_reachable_types() {
        let mut artifact = checked_artifact();
        let before = Manifest::from_checked_artifact(&artifact).unwrap();
        assert!(before.exports.contains_key("directory.lookup"));
        artifact.schema.inputs.insert(
            "extra".into(),
            crate::schema::Record {
                fields: BTreeMap::from([("unused".into(), crate::schema::Kind::Boolean)]),
                roc_type: Some("DirectoryTypes.Extra".into()),
                identity: None,
            },
        );
        artifact.operations.push(crate::artifact::Operation {
            name: "directory.manager".into(),
            kind: "query".into(),
            input_type: "extra".into(),
            output_type: "person".into(),
        });
        artifact.operations.push(crate::artifact::Operation {
            name: "directory.find".into(),
            kind: "query".into(),
            input_type: "person".into(),
            output_type: "person".into(),
        });
        artifact.app_contract.as_mut().unwrap().operations.insert(
            "directory.manager".into(),
            serde_json::from_value(checked_operation("directory.manager", "extra", 1)).unwrap(),
        );
        artifact.app_contract.as_mut().unwrap().operations.insert(
            "directory.find".into(),
            serde_json::from_value(checked_operation("directory.find", "person", 1)).unwrap(),
        );
        let expanded = Manifest::from_checked_artifact(&artifact).unwrap();
        assert_ne!(before.digest, expanded.digest);
        assert_eq!(
            before.exports["directory.lookup"],
            expanded.exports["directory.lookup"]
        );
        artifact
            .schema
            .inputs
            .get_mut("person")
            .unwrap()
            .fields
            .insert("name".into(), crate::schema::Kind::Integer);
        let changed = Manifest::from_checked_artifact(&artifact).unwrap();
        assert_ne!(
            before.exports["directory.lookup"].digest,
            changed.exports["directory.lookup"].digest
        );
        assert_ne!(
            expanded.exports["directory.find"].digest,
            changed.exports["directory.find"].digest
        );
        assert_eq!(
            expanded.exports["directory.manager"],
            changed.exports["directory.manager"]
        );
    }

    #[test]
    fn changed_shared_type_invalidates_actual_consumers() {
        let before = Package::derive(lookup(), &catalog()).unwrap();
        let mut changed = catalog();
        changed.get_mut("directory.PersonId.v1").unwrap().schema =
            json!({"nominal":"PersonId","wire":"integer"});
        let after = Package::derive(lookup(), &changed).unwrap();
        assert_ne!(before.digest, after.digest);
        let unrelated = OperationSpec {
            id: "directory.count".into(),
            version: 1,
            kind: Kind::Query,
            input: "directory.PersonSummary.v1".into(),
            output: "directory.PersonSummary.v1".into(),
            error: "directory.LookupFailure.v1".into(),
            semantics: json!({"phase":"observe"}),
        };
        assert_eq!(
            Package::derive(unrelated.clone(), &catalog()).unwrap(),
            Package::derive(unrelated, &changed).unwrap()
        );
    }

    #[test]
    fn a_caller_rejects_conflicting_nominal_shapes() {
        let first = Package::derive(lookup(), &catalog()).unwrap();
        let mut changed = catalog();
        changed.get_mut("directory.PersonId.v1").unwrap().schema = json!({"wire":"integer"});
        let second = Package::derive(
            OperationSpec {
                id: "directory.manager".into(),
                version: 1,
                kind: Kind::Query,
                input: "directory.ManagerInput.v1".into(),
                output: "directory.ManagerOutput.v1".into(),
                error: "directory.LookupFailure.v1".into(),
                semantics: json!({"phase":"observe"}),
            },
            &changed,
        )
        .unwrap();
        assert!(resolve_type_closure([&first, &second]).is_err());
    }

    #[test]
    fn tampering_and_missing_dependencies_fail_closed() {
        let mut package = Package::derive(lookup(), &catalog()).unwrap();
        package
            .types
            .get_mut("directory.PersonId.v1")
            .unwrap()
            .object
            .schema = json!({"wire":"integer"});
        assert!(package.verify().is_err());
        let mut missing = catalog();
        missing.remove("directory.PersonId.v1");
        assert!(Package::derive(lookup(), &missing).is_err());
    }
}
