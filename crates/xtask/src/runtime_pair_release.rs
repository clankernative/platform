//! Join two published SDK closures and one independently reviewed runtime pair.
//! Uses the instance publisher's digest-addressed blobs. The index is a
//! publication input, never a native test runner or a deployment approval.
use anyhow::{Context, Result, ensure};
use day2::{
    automation,
    runtime_pair::{Admission, Manifest, Profile, Receipt, RuntimeIdentity},
    sdk_release::{
        self, BlobIdentity, DISTRIBUTION_LIMIT, Distribution, EVIDENCE_LIMIT, FILE_LIMIT,
        MANIFEST_LIMIT, Release, verify,
    },
    security_admission::{Containment, LinuxEvidence},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Write, path::Path};

const INDEX_LIMIT: u64 = 65_536;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    profile: Profile,
    source_sdk: BlobIdentity,
    target_sdk: BlobIdentity,
    pair: BlobIdentity,
    verifier: String,
    recipe: String,
}

struct Sdk {
    release: Release,
    runtime: RuntimeIdentity,
}

fn blob(root: &Path, file: &BlobIdentity, limit: u64) -> Result<Vec<u8>> {
    let name = day2_assets::hash_part(&file.digest)?;
    verify(&root.join(name), file, limit)
}

impl Sdk {
    fn load(root: &Path, manifest: &BlobIdentity) -> Result<Self> {
        let release = Release::decode(&blob(root, manifest, MANIFEST_LIMIT)?)
            .context("unsupported pair SDK release")?;
        let distribution: Distribution =
            day2::json::decode(&blob(root, &release.distribution, DISTRIBUTION_LIMIT)?)?;
        distribution
            .bind(&release)
            .context("pair SDK distribution changed")?;
        blob(root, &release.operator, FILE_LIMIT)?;

        let native_bytes = blob(root, &release.evidence.native, EVIDENCE_LIMIT)?;
        let native: Value = day2::json::decode(&native_bytes)?;
        let evidence = LinuxEvidence::from_receipt(&native_bytes)?;
        let strict: Value =
            day2::json::decode(&blob(root, &release.evidence.strict, EVIDENCE_LIMIT)?)?;
        sdk_release::bind_evidence(&release, &distribution, &native, &strict)
            .context("native receipt does not bind the selected SDK")?;
        validate_strict(&native, &strict)?;
        Ok(Self {
            runtime: RuntimeIdentity {
                platform_inventory: evidence.platform_inventory.clone(),
                containment: Some(Containment::LinuxQualifiedV1 { evidence }),
            },
            release,
        })
    }
}

/// The complete strict campaign, beyond the binding sdk_release checks.
fn validate_strict(native: &Value, strict: &Value) -> Result<()> {
    let results = strict["results"]
        .as_object()
        .context("strict campaign results required")?;
    let actions = super::linux_runtime_qualification::STRICT_ACTIONS;
    for key in ["platform", "artifact"] {
        day2_assets::hash_part(
            native[key]
                .as_str()
                .context("native qualification identity")?,
        )?;
    }
    ensure!(
        strict["format"] == 1
            && strict["error"].is_null()
            && results.len() == actions.len()
            && actions
                .iter()
                .all(|action| results.get(*action).is_some_and(Value::is_object))
            && results["linux-strict-denial"]["code"] == "security_runtime_mismatch"
            && results["linux-strict-start"]["health"] == json!({"live":200,"ready":200})
            && ["runtime_supervisor", "runtime_sandbox"]
                .iter()
                .all(|key| { results["linux-strict-start"][*key] == native[*key] })
            && results["linux-strict-receipt"]["status"] == "strict-admission-passed"
            && results["linux-strict-receipt"]["qualification"] == false,
        "strict supplement does not bind the complete native SDK campaign"
    );
    Ok(())
}

fn validate_pair(index: &Index, pair_bytes: &[u8], source: &Sdk, target: &Sdk) -> Result<()> {
    let receipt: Receipt = day2::json::decode(pair_bytes)?;
    let source_manifest = Manifest {
        runtime: source.runtime.clone(),
        protocols: receipt.source.protocols.clone(),
    };
    let pair = Admission::review(pair_bytes, &index.pair.digest, &source_manifest)?.receipt;
    ensure!(
        source.release.runtime.image != target.release.runtime.image
            && source.release.runtime.config != target.release.runtime.config
            && pair.target.runtime == target.runtime
            && pair.profile == index.profile
            && pair.verifier == index.verifier
            && pair.recipe == index.recipe,
        "pair evidence does not bind the selected direction, SDKs and verifier"
    );
    Ok(())
}

pub(super) fn execute(root: &Path, request: &Path, blobs: &Path, output: &Path) -> Result<()> {
    let index: Index = day2::json::decode(&day2_assets::read_regular(request, INDEX_LIMIT)?)?;
    ensure!(
        index.version == 1 && index.source_sdk.digest != index.target_sdk.digest,
        "distinct source and target SDK selections required"
    );
    day2_assets::hash_part(&index.recipe)?;
    day2_assets::hash_part(&index.verifier)?;
    let runner = automation::checked_runner(&root.join("build-out/bin/day2-workflows"))?;
    let mut source = None;
    let mut target = None;
    let mut passed = false;
    let mut sealed = false;
    automation::run(&runner, &["assemble-runtime-pair-release"], |request| {
        ensure!(
            request.decode::<Value>()? == json!({}) && !sealed,
            "closed pair index recipe required"
        );
        match request.action.as_str() {
            "runtime-pair-release-source" if source.is_none() => {
                source = Some(Sdk::load(blobs, &index.source_sdk).context("source SDK evidence")?);
            }
            "runtime-pair-release-target" if source.is_some() && target.is_none() => {
                target = Some(Sdk::load(blobs, &index.target_sdk).context("target SDK evidence")?);
            }
            "runtime-pair-release-receipt" if !passed => {
                let bytes = blob(blobs, &index.pair, EVIDENCE_LIMIT)
                    .context("read the pinned runtime pair receipt")?;
                validate_pair(
                    &index,
                    &bytes,
                    source.as_ref().context("source SDK required")?,
                    target.as_ref().context("target SDK required")?,
                )?;
                passed = true;
            }
            "runtime-pair-release-index" if passed => sealed = true,
            _ => anyhow::bail!("unexpected pair index step"),
        }
        Ok(json!({}))
    })?;
    ensure!(sealed, "runtime pair release incomplete");
    let bytes = serde_json::to_vec(&index)?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(output)?;
    println!(
        "{}",
        json!({"digest":day2::digest(&bytes), "bytes":bytes.len()})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2::digest;
    use day2::sdk_release::OPERATOR_FILES;
    use std::fs;

    fn store(root: &Path, bytes: &[u8]) -> Result<BlobIdentity> {
        let digest = digest(bytes);
        fs::write(root.join(day2_assets::hash_part(&digest)?), bytes)?;
        Ok(BlobIdentity {
            digest,
            bytes: bytes.len() as u64,
        })
    }

    fn store_json(root: &Path, value: &Value) -> Result<BlobIdentity> {
        store(root, &serde_json::to_vec(value)?)
    }

    // Synthetic evidence exercises the publication boundary only. It can't
    // qualify a runtime or replace the native pair campaign.
    fn sdk_fixture(root: &Path, revision: char) -> Result<(BlobIdentity, Sdk)> {
        let label = revision.to_string();
        let platform_commit = label.repeat(40);
        let runtime = digest(format!("{label}:runtime").as_bytes());
        let tooling = digest(format!("{label}:tooling").as_bytes());
        let inventory = digest(format!("{label}:inventory").as_bytes());
        let workflow = digest(b"workflow");
        let toolchain = digest(b"toolchain");
        let operator = store(root, label.as_bytes())?;
        let worker = json!({"digest": digest(b"archive"), "bytes": 7});
        let files: serde_json::Map<_, _> = OPERATOR_FILES
            .iter()
            .map(|name| (name.to_string(), json!(operator)))
            .collect();
        let distribution = store_json(
            root,
            &json!({
                "format":1, "target":"linux-x86_64", "inputs":inventory,
                "workflow_sources":workflow, "toolchain":toolchain,
                "worker":worker, "operator":operator, "operator_files":files,
            }),
        )?;
        let native = json!({
            "format":1, "status":"passed", "scope":"linux_sqlite_single_v1",
            "source_revision":platform_commit, "platform":inventory, "platform_inventory":inventory,
            "workflow":workflow, "toolchain":toolchain, "runtime_image":runtime, "tooling_image":tooling,
            "artifact":digest(b"fixture"), "runtime_supervisor":runtime, "runtime_sandbox":runtime,
            "checks":super::super::linux_qualification::required_steps(), "exclusions":[],
            "environment":{"architecture":"x86_64"},
            "tooling_distribution":{"distribution":distribution.digest,"worker":worker,"operator":operator},
        });
        let native_file = store_json(root, &native)?;
        let results: serde_json::Map<_, _> =
            super::super::linux_runtime_qualification::STRICT_ACTIONS
                .iter()
                .map(|action| (action.to_string(), json!({})))
                .collect();
        let mut strict = json!({
            "format":1, "status":"strict-admission-passed", "qualification":false,
            "qualification_digest":native_file.digest,
            "runtime_image":runtime, "tooling_image":tooling, "platform":inventory, "platform_inventory":inventory,
            "artifact":native["artifact"], "results":results, "error":null,
        });
        strict["results"]["linux-strict-denial"] = json!({"code":"security_runtime_mismatch"});
        strict["results"]["linux-strict-receipt"] =
            json!({"status":"strict-admission-passed","qualification":false});
        strict["results"]["linux-strict-start"] = json!({
            "health":{"live":200,"ready":200}, "runtime_supervisor":runtime, "runtime_sandbox":runtime
        });
        let strict_file = store_json(root, &strict)?;
        let manifest = store_json(
            root,
            &json!({
                "version":1, "profile":"linux_sqlite_single_v1", "target":"linux-x86_64", "platform_commit":platform_commit,
                "runtime":{"image":format!("registry/runtime@{runtime}"),"config":runtime},
                "tooling":{"image":format!("registry/tooling@{tooling}"),"config":tooling},
                "distribution":distribution, "operator":operator, "evidence":{"native":native_file,"strict":strict_file},
            }),
        )?;
        let sdk = Sdk::load(root, &manifest)?;
        Ok((manifest, sdk))
    }

    #[test]
    fn recipe_seals_only_two_complete_sdk_closures_and_an_exact_directed_pair() -> Result<()> {
        let root = automation::source_root()?;
        super::super::workflows::build(&root)?;
        let temp = tempfile::tempdir()?;
        let blobs = temp.path();
        let (source_sdk, source) = sdk_fixture(blobs, 'a')?;
        let (target_sdk, target) = sdk_fixture(blobs, 'b')?;
        let protocols = json!({
            "private_schema":digest(b"private"), "artifact_catalog_schema":digest(b"catalog"),
            "serving_lease":2,"operation_lease":2,"execution_lease":2,"release_journal":5,
            "authority":1,"invocation_effect":2,"web_ticket":1,"worker":1,"artifact_catalog":1,
        });
        let recipe = digest(b"reviewed recipe");
        let verifier = digest(b"reviewed verifier");
        let mut receipt = json!({
            "version":1,"outcome":"passed","profile":"sqlite_local_v1",
            "source":{"runtime":source.runtime,"protocols":protocols},
            "target":{"runtime":target.runtime,"protocols":protocols},
            "recipe":recipe,"verifier":verifier,
            "checks":["sqlite_read_write_both_directions","current_authority","source_executor_ownership",
                "lease_exclusion","unknown_pair_refusal","schema_protocol_refusal","source_death","candidate_death",
                "operator_recovery","no_duplicate_effects"],
        });
        let mut index = Index {
            version: 1,
            profile: Profile::SqliteLocalV1,
            source_sdk,
            target_sdk,
            pair: store_json(blobs, &receipt)?,
            verifier,
            recipe,
        };
        let request = temp.path().join("request.json");
        let output = temp.path().join("release.json");
        let assemble = |index: &Index, output: &Path| {
            fs::write(&request, serde_json::to_vec(index)?)?;
            execute(&root, &request, blobs, output)
        };
        assemble(&index, &output)?;
        let selected = fs::read(&output)?;
        assert_eq!(selected, serde_json::to_vec(&index)?);
        assert!(assemble(&index, &output).is_err());
        assert_eq!(selected, fs::read(output)?);

        let rejected = temp.path().join("rejected.json");
        std::mem::swap(&mut index.source_sdk, &mut index.target_sdk);
        assert!(assemble(&index, &rejected).is_err());
        std::mem::swap(&mut index.source_sdk, &mut index.target_sdk);
        let correct_recipe = std::mem::replace(&mut index.recipe, digest(b"another recipe"));
        assert!(assemble(&index, &rejected).is_err());
        index.recipe = correct_recipe;
        receipt["checks"].as_array_mut().unwrap().pop();
        let complete_pair = std::mem::replace(&mut index.pair, store_json(blobs, &receipt)?);
        assert!(assemble(&index, &rejected).is_err());
        index.pair = complete_pair;
        let strict = blobs.join(day2_assets::hash_part(
            &target.release.evidence.strict.digest,
        )?);
        let mut evidence: Value = day2::json::decode(&fs::read(&strict)?)?;
        evidence["results"]["linux-strict-denial"]["code"] = json!("wrong_denial");
        let invalid_strict = store_json(blobs, &evidence)?;
        let mut target_manifest: Value =
            day2::json::decode(&blob(blobs, &index.target_sdk, INDEX_LIMIT)?)?;
        target_manifest["evidence"]["strict"] = json!(invalid_strict);
        let correct_target =
            std::mem::replace(&mut index.target_sdk, store_json(blobs, &target_manifest)?);
        assert!(assemble(&index, &rejected).is_err());
        index.target_sdk = correct_target;
        let operator = blobs.join(day2_assets::hash_part(&target.release.operator.digest)?);
        fs::write(operator, b"x")?;
        assert!(assemble(&index, &rejected).is_err());
        assert!(!rejected.exists());
        Ok(())
    }
}
