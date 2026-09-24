use anyhow::{Context, Result, ensure};
use day2::{artifact::LoadedArtifact, digest};
use serde_json::Value;
use std::{fs, path::Path};

fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        ensure!(!entry.file_type()?.is_symlink(), "artifact fixture symlink");
        let output = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &output)?;
        } else {
            fs::copy(entry.path(), output)?;
        }
    }
    Ok(())
}

#[test]
fn loader_rederives_complete_catalogs_from_hash_bound_compiler_evidence() -> Result<()> {
    let source = std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
        .context("run xtask verify or set DAY2_TEST_REPORTS_ARTIFACT")?;
    let source = Path::new(&source);
    let original = LoadedArtifact::load(source)?;
    ensure!(
        original.contract().format >= 10,
        "format 10 fixture required"
    );
    for case in [
        "missing",
        "corrupt",
        "declaration",
        "schema",
        "output",
        "contract",
        "prose",
        "empty",
        "resource",
        "coverage",
    ] {
        let temporary = tempfile::tempdir()?;
        let mut value: Value = serde_json::from_slice(&fs::read(source.join("artifact.json"))?)?;
        match case {
            "declaration" => {
                let codec = original.contract().declarations.queries["list"]
                    .input
                    .as_str();
                value["declarations"]["queries"]["detail"]["input"] = codec.into();
                let operations = value["operations"].as_array_mut().context("operations")?;
                let operation = operations
                    .iter_mut()
                    .find(|op| op["name"] == "reports.detail")
                    .context("detail operation")?;
                operation["input_type"] = codec.into();
            }
            "schema" => {
                let codec = original.contract().declarations.queries["list"]
                    .input
                    .as_str();
                value["schema"]["inputs"][codec]["fields"]["limit"] = "integer".into();
                let schema: day2::schema::Schema = serde_json::from_value(value["schema"].clone())?;
                value["schema_digest"] = schema.hash()?.into();
            }
            "output" => {
                let codec = original.contract().declarations.queries["detail"]
                    .output
                    .as_str();
                value["outputs"][codec]["shape"] = "string".into();
            }
            "contract" => {
                value.as_object_mut().unwrap().remove("app_contract");
            }
            "prose" => {
                value["app_contract"]["operations"]["reports.submit"]["intent"]["title"] =
                    "Tampered but nonempty title".into()
            }
            "empty" => {
                value["app_contract"]["operations"]["reports.submit"]["intent"]["title"] = "".into()
            }
            "resource" => {
                value["app_contract"]["presentation"]["stylesheet"] = "removed.css".into()
            }
            "coverage" => {
                value["app_contract"]["operations"]
                    .as_object_mut()
                    .unwrap()
                    .remove("reports.detail");
            }
            _ => (),
        }
        let id = digest(&serde_json::to_vec(&value)?);
        let target = temporary
            .path()
            .join(id.strip_prefix("sha256:").context("digest")?);
        copy_tree(source, &target)?;
        fs::write(target.join("artifact.json"), serde_json::to_vec(&value)?)?;
        match case {
            "missing" => fs::remove_file(target.join("checked-types.json"))?,
            "corrupt" => fs::write(target.join("checked-types.json"), b"[]")?,
            _ => (),
        }
        let error = LoadedArtifact::load(&target)
            .err()
            .context("tampered artifact admitted")?;
        let expected = match case {
            "missing" => "No such file",
            "corrupt" => "checked compiler metadata digest mismatch",
            "declaration" => "declaration catalog differs from checked compiler metadata",
            "schema" => "schema differs from checked compiler metadata",
            "output" => "output catalog differs from checked compiler metadata",
            "contract" => "current artifact requires app_contract",
            "prose" => "application contract differs from compiled App.definition",
            "empty" => "",
            "resource" => "declared presentation resource is missing",
            "coverage" => "every operation requires a complete contract",
            _ => unreachable!(),
        };
        assert!(error.to_string().contains(expected), "{case}: {error:#}");
    }
    Ok(())
}
