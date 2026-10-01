//! Operator-reviewed security prerequisites bound to activated app authority.
//! These pin trusted build/runtime evidence; they are not signed provenance or
//! proof against a malicious native host, compiler or kernel.
use crate::{artifact::LoadedArtifact, digest};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    sync::OnceLock,
};

const LINUX_CHECKS: &[&str] = &[
    "linux-capture",
    "linux-build-tooling",
    "linux-build-runtime",
    "linux-start-tooling",
    "linux-build-check",
    "linux-build-probe",
    "linux-build-owned",
    "linux-build-delegation",
    "linux-build-delegation-business",
    "linux-test-delegation",
    "test-sandbox",
    "test-worker",
    "test-http",
    "test-backup",
    "linux-runtime-package",
    "linux-runtime-start",
    "linux-runtime-read-write",
    "linux-runtime-revoke",
    "linux-runtime-graceful-restart",
    "linux-runtime-forced-restart",
    "linux-runtime-isolation",
    "linux-runtime-restore",
    "linux-runtime-stop",
    "linux-stop-tooling",
];

/// Require the complete reviewed Linux campaign before issuing or consuming
/// evidence. Recipe preflight uses the same guard before native effects begin.
pub fn require_linux_checks(checks: &BTreeSet<String>) -> Result<()> {
    ensure!(
        *checks
            == LINUX_CHECKS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        "security_qualification_incomplete"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxEvidence {
    pub receipt_digest: String,
    pub platform_inventory: String,
    pub toolchain: String,
    pub runtime_image: String,
    pub runtime_supervisor: String,
    pub runtime_sandbox: String,
    pub checks: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Containment {
    /// Explicit development approval, tied to the exact trusted host binary.
    MacosSandboxV1 {
        supervisor: String,
    },
    LinuxQualifiedV1 {
        evidence: LinuxEvidence,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Requirements {
    pub version: u32,
    pub artifact: String,
    pub platform_inventory: String,
    pub roc_version: String,
    pub containment: Containment,
}

/// SDK/compiler/platform inputs, excluding application source. This permits a
/// qualified platform profile to admit another independently checked app while
/// each Requirements document also pins that app's exact artifact identity.
pub fn platform_inventory_digest(artifact: &LoadedArtifact) -> Result<String> {
    let sources: BTreeMap<_, _> = artifact
        .contract()
        .sources
        .iter()
        .filter(|(path, _)| {
            [
                "Cargo.toml",
                "Cargo.lock",
                "rust-toolchain.toml",
                "toolchain.json",
                ".dockerignore",
            ]
            .contains(&path.as_str())
                || [
                    "sdk/",
                    "compiler/",
                    "crates/",
                    "tools/",
                    "vendor/",
                    "assets/",
                    "ops/",
                    "infra/",
                    "deploy/",
                    "toolchains/",
                ]
                .iter()
                .any(|prefix| path.starts_with(prefix))
        })
        .collect();
    ensure!(!sources.is_empty(), "security_platform_inventory_missing");
    Ok(digest(&serde_json::to_vec(&sources)?))
}

impl Requirements {
    pub fn validate(&self, artifact: &LoadedArtifact) -> Result<()> {
        ensure!(self.version == 1, "unsupported_security_requirements");
        artifact.require_current_api()?;
        ensure!(
            self.artifact == artifact.id()
                && self.roc_version == artifact.contract().roc_version
                && self.platform_inventory == platform_inventory_digest(artifact)?,
            "security_artifact_mismatch"
        );
        for key in [
            "compiler/roc",
            "crates/day2/src/admission.rs",
            "sdk/main.roc",
            "sdk/contracts/Resource.roc",
        ] {
            crate::assets::hash_part(
                artifact
                    .contract()
                    .sources
                    .get(key)
                    .context("security_build_evidence_missing")?,
            )?;
        }
        match &self.containment {
            Containment::MacosSandboxV1 { supervisor } => {
                crate::assets::hash_part(supervisor)?;
            }
            Containment::LinuxQualifiedV1 { evidence } => {
                for value in [
                    &evidence.receipt_digest,
                    &evidence.toolchain,
                    &evidence.runtime_image,
                    &evidence.runtime_supervisor,
                    &evidence.runtime_sandbox,
                ] {
                    crate::assets::hash_part(value)?;
                }
                ensure!(
                    evidence.platform_inventory == self.platform_inventory,
                    "security_qualification_platform_mismatch"
                );
                require_linux_checks(&evidence.checks)?;
                // Each pin names its own host target, so the digest the
                // qualification recorded identifies the architecture it ran on.
                ensure!(
                    [
                        "toolchains/linux-aarch64.json",
                        "toolchains/linux-x86_64.json"
                    ]
                    .iter()
                    .any(|pin| artifact.contract().sources.get(*pin) == Some(&evidence.toolchain)),
                    "security_linux_toolchain_mismatch"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn require_runtime(&self) -> Result<()> {
        let evidence = HOST.get_or_init(measure_host);
        let (os, supervisor, sandbox) = evidence
            .as_ref()
            .map_err(|_| anyhow::anyhow!("security_host_evidence_unavailable"))?;
        match &self.containment {
            Containment::MacosSandboxV1 {
                supervisor: expected,
            } => ensure!(
                os == "macos" && supervisor == expected,
                "security_runtime_mismatch"
            ),
            Containment::LinuxQualifiedV1 { evidence } => ensure!(
                os == "linux"
                    && supervisor == &evidence.runtime_supervisor
                    && sandbox.as_ref() == Some(&evidence.runtime_sandbox),
                "security_runtime_mismatch"
            ),
        }
        Ok(())
    }

    pub(crate) fn require_image(&self, image: &str) -> Result<()> {
        let Containment::LinuxQualifiedV1 { evidence } = &self.containment else {
            anyhow::bail!("security_deployment_requires_linux_profile")
        };
        ensure!(
            evidence.runtime_image == image,
            "security_runtime_image_mismatch"
        );
        Ok(())
    }
}

type HostEvidence = Result<(String, String, Option<String>), String>;
static HOST: OnceLock<HostEvidence> = OnceLock::new();

fn measure_host() -> HostEvidence {
    (|| -> Result<_> {
        let executable = std::env::current_exe()?.canonicalize()?;
        let supervisor = digest(&fs::read(&executable)?);
        let sandbox = if cfg!(target_os = "linux") {
            Some(digest(&fs::read(
                executable
                    .parent()
                    .context("supervisor_directory")?
                    .join("day2-sandbox"),
            )?))
        } else {
            None
        };
        Ok((std::env::consts::OS.into(), supervisor, sandbox))
    })()
    .map_err(|_| "security_host_evidence_unavailable".into())
}

/// Produce a concrete review document from an actual completed Linux receipt.
/// A trusted operator must still activate it; reading a receipt grants nothing.
pub fn review_linux(artifact: &LoadedArtifact, receipt_path: &Path) -> Result<Requirements> {
    let metadata = fs::symlink_metadata(receipt_path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 1_048_576,
        "security_receipt_budget"
    );
    let bytes = fs::read(receipt_path)?;
    let receipt: serde_json::Value = crate::json::decode(&bytes)?;
    ensure!(
        receipt["format"] == 1
            && receipt["status"] == "passed"
            && receipt["scope"] == "linux_sqlite_single_v1",
        "security_qualification_not_passed"
    );
    let field = |name: &str| {
        receipt[name]
            .as_str()
            .map(str::to_owned)
            .context("security_receipt_field_missing")
    };
    let exclusions = receipt["exclusions"]
        .as_array()
        .context("security_receipt_exclusions_missing")?;
    ensure!(
        exclusions.iter().all(|value| matches!(
            value.as_str(),
            Some(
                "complete-platform-verification"
                    | "formatter-qualification"
                    | "production-identity"
                    | "hostile-native-code-certification"
            )
        )),
        "security_qualification_has_runtime_exclusions"
    );
    let requirements = Requirements {
        version: 1,
        artifact: artifact.id().into(),
        platform_inventory: platform_inventory_digest(artifact)?,
        roc_version: artifact.contract().roc_version.clone(),
        containment: Containment::LinuxQualifiedV1 {
            evidence: LinuxEvidence {
                receipt_digest: digest(&bytes),
                platform_inventory: field("platform_inventory")?,
                toolchain: field("toolchain")?,
                runtime_image: field("runtime_image")?,
                runtime_supervisor: field("runtime_supervisor")?,
                runtime_sandbox: field("runtime_sandbox")?,
                checks: serde_json::from_value(receipt["checks"].clone())?,
            },
        },
    };
    requirements.validate(artifact)?;
    Ok(requirements)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub receipt_file: std::path::PathBuf,
}

pub fn review_instance(
    instance_path: &Path,
    app: &str,
    operator: &str,
    review: &Review,
) -> Result<serde_json::Value> {
    ensure!(
        crate::resource_admin::is_administrator(instance_path, operator)?,
        "installation_admin_required"
    );
    let instance = crate::artifact::Instance::load(instance_path)?;
    let binding = instance.apps.get(app).context("app_not_installed")?;
    let artifact = LoadedArtifact::load(
        &instance_path
            .parent()
            .context("instance_directory")?
            .join(&binding.artifact),
    )?;
    Ok(serde_json::to_value(review_linux(
        &artifact,
        &review.receipt_file,
    )?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn artifact(app: &str, compiler: &str) -> LoadedArtifact {
        let sources = BTreeMap::from([
            ("compiler/roc", digest(compiler.as_bytes())),
            ("toolchains/linux-aarch64.json", digest(b"linux-pin")),
            (
                "crates/day2/src/admission.rs",
                digest(b"two-profile-admission"),
            ),
            ("sdk/main.roc", digest(b"pure-worker")),
            ("sdk/contracts/Resource.roc", digest(b"sealed-resource")),
            ("app/App.roc", digest(app.as_bytes())),
        ]);
        let contract = serde_json::from_value(json!({"format":crate::artifact::CURRENT_FORMAT,
            "roc_version":"reviewed-compiler","worker_digest":digest(app.as_bytes()),"schema_digest":digest(b"schema"),
            "schema":{"models":{},"inputs":{},"foreign_keys":[]},"operations":[],"sources":sources,"admission":"local-spike-only"})).unwrap();
        LoadedArtifact::from_contract_for_tests(
            digest(app.as_bytes()),
            Path::new("/test/admitted").into(),
            contract,
        )
    }

    fn receipt(artifact: &LoadedArtifact) -> serde_json::Value {
        json!({"format":1,"status":"passed","scope":"linux_sqlite_single_v1",
            "platform_inventory":platform_inventory_digest(artifact).unwrap(),"toolchain":digest(b"linux-pin"),
            "runtime_image":digest(b"qualified-image"),"runtime_supervisor":digest(b"qualified-server"),
            "runtime_sandbox":digest(b"qualified-launcher"),"checks":LINUX_CHECKS,"exclusions":["production-identity"]})
    }

    #[test]
    fn qualification_is_scoped_to_platform_and_each_app_pins_its_own_artifact() -> Result<()> {
        let first = artifact("first", "compiler-one");
        let second = artifact("second", "compiler-one");
        let changed = artifact("second", "compiler-two");
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("receipt.json");
        fs::write(&path, serde_json::to_vec(&receipt(&first))?)?;
        let requirements = review_linux(&first, &path)?;
        assert!(
            requirements.validate(&second).is_err(),
            "approval must not follow another artifact"
        );
        let second_requirements = review_linux(&second, &path)?;
        assert_eq!(
            requirements.platform_inventory,
            second_requirements.platform_inventory
        );
        assert!(
            review_linux(&changed, &path).is_err(),
            "different actual compiler needs qualification"
        );
        assert!(requirements.require_image(&digest(b"other-image")).is_err());
        assert!(
            requirements.require_runtime().is_err(),
            "this test runner is not the approved runtime"
        );
        Ok(())
    }

    #[test]
    fn missing_failed_or_runtime_excluded_qualification_never_becomes_approval() -> Result<()> {
        let artifact = artifact("app", "compiler");
        let original = receipt(&artifact);
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("receipt.json");
        let mut cases = Vec::new();
        let mut failed = original.clone();
        failed["status"] = json!("failed");
        cases.push(failed);
        let mut incomplete = original.clone();
        incomplete["checks"].as_array_mut().unwrap().pop();
        cases.push(incomplete);
        let mut excluded = original.clone();
        excluded["exclusions"] = json!(["restored-server-startup"]);
        cases.push(excluded);
        let mut toolchain = original.clone();
        toolchain["toolchain"] = json!(digest(b"other-pin"));
        cases.push(toolchain);
        let mut unknown = original;
        unknown["runtime_sandbox"] = json!("unknown");
        cases.push(unknown);
        for receipt in cases {
            fs::write(&path, serde_json::to_vec(&receipt)?)?;
            assert!(review_linux(&artifact, &path).is_err());
        }
        Ok(())
    }
}
