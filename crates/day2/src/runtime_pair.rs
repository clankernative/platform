//! Directed, operator-reviewed runtime compatibility DATA. R1 can prepare a
//! release, never start or promote its candidate. This is neither signed build
//! provenance nor permission to execute business work. R2 owns serving/drain;
//! R3 owns production of the native pair campaign and published compiled outputs.
use crate::{
    artifact::{Instance, LoadedArtifact},
    authority_state::{self, LocalOperator},
    rollout::{self, Generation, Phase, Release, ReleaseKind},
    security_admission::{Containment, Requirements},
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentity {
    pub platform_inventory: String,
    pub containment: Option<Containment>,
}

impl RuntimeIdentity {
    pub(crate) fn from_artifact(
        artifact: &LoadedArtifact,
        requirements: Option<&Requirements>,
    ) -> Result<Self> {
        if let Some(requirements) = requirements {
            requirements.validate(artifact)?;
        }
        Ok(Self {
            platform_inventory: crate::security_admission::platform_inventory_digest(artifact)?,
            containment: requirements.map(|value| value.containment.clone()),
        })
    }

    fn require_qualified(&self) -> Result<()> {
        day2_assets::hash_part(&self.platform_inventory)?;
        let Some(Containment::LinuxQualifiedV1 { evidence }) = &self.containment else {
            anyhow::bail!("runtime_pair_requires_linux_qualification");
        };
        ensure!(
            evidence.platform_inventory == self.platform_inventory,
            "runtime_pair_inventory_changed"
        );
        for digest in [
            &evidence.receipt_digest,
            &evidence.toolchain,
            &evidence.runtime_image,
            &evidence.runtime_supervisor,
            &evidence.runtime_sandbox,
        ] {
            day2_assets::hash_part(digest)?;
        }
        crate::security_admission::require_linux_checks(&evidence.checks)
    }
}

/// These versions describe semantics in addition to SQLite shape. Changing a
/// worker wire/receipt/lease contract requires a new version and qualification;
/// an equal SQLite schema alone never admits a pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocols {
    pub private_schema: String,
    pub artifact_catalog_schema: String,
    pub serving_lease: u32,
    pub operation_lease: u32,
    pub execution_lease: u32,
    pub release_journal: u32,
    pub authority: u32,
    pub invocation_effect: u32,
    pub web_ticket: u32,
    pub worker: u32,
    pub artifact_catalog: u32,
}

impl Protocols {
    fn current(private_schema: String, artifact_catalog_schema: String) -> Self {
        Self {
            private_schema,
            artifact_catalog_schema,
            serving_lease: 1,
            operation_lease: 1,
            execution_lease: 1,
            release_journal: 2,
            authority: 1,
            invocation_effect: 1,
            web_ticket: 1,
            worker: 1,
            artifact_catalog: 1,
        }
    }

    fn require_current(&self) -> Result<()> {
        day2_assets::hash_part(&self.private_schema)?;
        day2_assets::hash_part(&self.artifact_catalog_schema)?;
        ensure!(
            *self
                == Self::current(
                    self.private_schema.clone(),
                    self.artifact_catalog_schema.clone()
                ),
            "runtime_pair_protocol_unsupported"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub runtime: RuntimeIdentity,
    pub protocols: Protocols,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    SqliteReadWriteBothDirections,
    CurrentAuthority,
    SourceExecutorOwnership,
    LeaseExclusion,
    UnknownPairRefusal,
    SchemaProtocolRefusal,
    SourceDeath,
    CandidateDeath,
    OperatorRecovery,
    NoDuplicateEffects,
}

impl Check {
    fn required() -> BTreeSet<Self> {
        use Check::*;
        [
            SqliteReadWriteBothDirections,
            CurrentAuthority,
            SourceExecutorOwnership,
            LeaseExclusion,
            UnknownPairRefusal,
            SchemaProtocolRefusal,
            SourceDeath,
            CandidateDeath,
            OperatorRecovery,
            NoDuplicateEffects,
        ]
        .into_iter()
        .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    SqliteLocalV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Passed,
}

/// Shared evidence contains no app/artifact/controller identities: the campaign
/// is reusable for the exact directed runtime pair and feature profile. Actual
/// installed shape, scope, instance and authority are checked separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: u32,
    pub source: Manifest,
    pub target: Manifest,
    pub profile: Profile,
    pub verifier: String,
    pub recipe: String,
    pub outcome: Outcome,
    pub checks: BTreeSet<Check>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub receipt_digest: String,
    pub receipt: Receipt,
}

impl Admission {
    // Native caller pins the exact operator-reviewed bytes, not a boolean in
    // application metadata. Construct only inside the authorized operation.
    fn review(bytes: &[u8], expected: &str, source: &Manifest) -> Result<Self> {
        ensure!(bytes.len() <= 1_048_576, "runtime_pair_receipt_budget");
        day2_assets::hash_part(expected)?;
        ensure!(
            crate::digest(bytes) == expected,
            "runtime_pair_receipt_changed"
        );
        let receipt: Receipt = crate::json::decode(bytes)?;
        ensure!(
            receipt.version == 1 && receipt.checks == Check::required(),
            "runtime_pair_qualification_incomplete"
        );
        day2_assets::hash_part(&receipt.verifier)?;
        day2_assets::hash_part(&receipt.recipe)?;
        receipt.source.runtime.require_qualified()?;
        receipt.target.runtime.require_qualified()?;
        receipt.source.protocols.require_current()?;
        receipt.target.protocols.require_current()?;
        ensure!(receipt.source == *source, "runtime_pair_source_changed");
        ensure!(
            receipt.source.runtime != receipt.target.runtime,
            "runtime_pair_requires_new_runtime"
        );
        ensure!(
            receipt.source.protocols == receipt.target.protocols,
            "runtime_pair_protocol_changed"
        );
        Ok(Self {
            receipt_digest: expected.into(),
            receipt,
        })
    }

    /// No target host may pick up source work merely because its app artifact
    /// matches. All accepted work remains source-owned until R2 can capture and
    /// drain both generations. This comparison is DATA, not measured execution.
    pub(crate) fn require_source(&self, runtime: &RuntimeIdentity) -> Result<()> {
        ensure!(
            *runtime == self.receipt.source.runtime,
            "runtime_pair_executor_changed"
        );
        Ok(())
    }
}

/// Compile the current private shape in memory. Model tables are checked on
/// each installed app, but excluded from the reusable runtime protocol digest.
pub fn protocols(runtime: &Runtime) -> Result<Protocols> {
    Ok(expected_storage(runtime)?.protocols)
}

struct ExpectedStorage {
    shape: Vec<(String, String, String)>,
    protocols: Protocols,
}

fn expected_storage(runtime: &Runtime) -> Result<ExpectedStorage> {
    let metadata =
        crate::store::InitialStoreMetadata::load(runtime.instance_path(), runtime.app())?;
    let mut db = rusqlite::Connection::open_in_memory()?;
    let tx = db.transaction()?;
    metadata.initialize_in_transaction(&tx)?;
    rollout::install(&tx)?;
    let mut business_objects = BTreeSet::new();
    for table in runtime.artifact().contract().schema.models.keys() {
        let mut statement = tx.prepare("SELECT name FROM sqlite_master WHERE tbl_name=?1")?;
        business_objects.extend(
            statement
                .query_map([table], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
    }
    let shape = rollout::storage_shape(runtime, &tx)?;
    let private = shape
        .iter()
        .filter(|(_, name, _)| !business_objects.contains(name))
        .collect::<Vec<_>>();
    let protocols = Protocols::current(
        crate::digest(&serde_json::to_vec(&private)?),
        crate::digest(&serde_json::to_vec(&rollout::catalog_shape()?)?),
    );
    Ok(ExpectedStorage { shape, protocols })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub source_image: String,
    pub target_image: String,
    pub receipt_digest: String,
}

fn local_stores(runtime: &Runtime) -> Result<()> {
    let allowed = [
        format!("{}.sqlite", runtime.app()),
        format!("{}.artifacts.sqlite", runtime.app()),
    ];
    let mut entries = 0;
    for entry in std::fs::read_dir(runtime.db().parent().context("state root")?)? {
        entries += 1;
        ensure!(entries <= 4096, "runtime_pair_state_entry_budget");
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().context("runtime_pair_state_name")?;
        let store = name
            .strip_suffix("-wal")
            .or_else(|| name.strip_suffix("-shm"))
            .unwrap_or(name);
        if store.ends_with(".sqlite") {
            ensure!(
                allowed.iter().any(|allowed| allowed == store) && entry.file_type()?.is_file(),
                "runtime_pair_auxiliary_store_unsupported"
            );
            if name == allowed[1] {
                let db = rusqlite::Connection::open_with_flags(
                    entry.path(),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )?;
                ensure!(
                    rollout::catalog_storage_shape(&db)? == rollout::catalog_shape()?,
                    "runtime_pair_artifact_catalog_changed"
                );
            }
        }
    }
    Ok(())
}

/// Prepare only the same-artifact, unchanged-instance, local-SQLite class.
/// External providers/auxiliary stores require a separately qualified profile.
/// This never changes the active security requirements, artifact, or readiness.
pub fn prepare(
    runtime: &Runtime,
    candidate_bytes: &[u8],
    request: &Request,
    receipt_bytes: &[u8],
    operator: &LocalOperator,
) -> Result<Release> {
    rollout::operator(runtime, operator)?;
    let _lease = rollout::release_lock(runtime)?;
    ensure!(
        !request.id.is_empty()
            && request.id.len() <= 96
            && request
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "rollout_release_id_invalid"
    );
    rollout::image(&request.source_image)?;
    rollout::image(&request.target_image)?;
    ensure!(candidate_bytes.len() <= 1_048_576, "instance byte budget");
    let candidate = Instance::from_bytes(candidate_bytes)?;
    let candidate_bytes_digest = crate::digest(candidate_bytes);
    ensure!(
        request.source_image != request.target_image,
        "runtime_pair_requires_new_image"
    );
    let original = Instance::load(runtime.instance_path())?;
    let instance_digest = crate::digest(&serde_json::to_vec(&original)?);
    ensure!(
        instance_digest == runtime.instance_digest(),
        "runtime_pair_source_instance_changed"
    );
    ensure!(
        serde_json::to_value(&original)? == serde_json::to_value(&candidate)?,
        "runtime_pair_instance_changed"
    );
    let binding = &original.apps[runtime.app()];
    ensure!(
        binding.managed_secrets.is_none()
            && binding.resource_policies.is_empty()
            && binding.credential_families.is_empty()
            && binding.oauth_connections.is_empty()
            && binding.ingress.is_empty()
            && binding.schedules.is_empty()
            && runtime
                .artifact()
                .contract()
                .connection_declarations
                .is_empty()
            && runtime
                .artifact()
                .contract()
                .credential_declarations
                .is_empty()
            && runtime
                .artifact()
                .contract()
                .app_contract
                .as_ref()
                .is_some_and(
                    |contract| contract.operations.values().all(|operation| operation
                        .observations
                        .is_empty()
                        && !operation.credential_access.enabled
                        && operation.execution.effects.iter().all(|effect| matches!(
                            effect.kind.as_str(),
                            "create" | "update" | "update_created" | "soft_delete"
                        )))
                ),
        "runtime_pair_profile_unsupported"
    );
    local_stores(runtime)?;
    let expected = expected_storage(runtime)?;
    runtime.sql_write(|tx| {
        runtime.check_binding(tx)?;
        let active = authority_state::current(tx)?;
        ensure!(
            active.artifact_id == runtime.artifact().id()
                && active.document
                    == authority_state::AuthorityDocument::resolve(
                        &original,
                        runtime.app(),
                        runtime.artifact()
                    )?,
            "runtime_pair_authority_changed"
        );
        ensure!(
            rollout::storage_shape(runtime, tx)? == expected.shape,
            "runtime_pair_store_shape_changed"
        );
        let source = Manifest {
            runtime: RuntimeIdentity::from_artifact(
                runtime.artifact(),
                active.document.security.as_ref(),
            )?,
            protocols: expected.protocols,
        };
        let admission = Admission::review(receipt_bytes, &request.receipt_digest, &source)?;
        let generation = |identity: RuntimeIdentity, image: &str| Generation {
            artifact: active.artifact_id.clone(),
            runtime: identity,
            instance_digest: instance_digest.clone(),
            image: image.into(),
        };
        let release = Release {
            id: request.id.clone(),
            scope: runtime.scope().into(),
            source: generation(
                admission.receipt.source.runtime.clone(),
                &request.source_image,
            ),
            target: generation(
                admission.receipt.target.runtime.clone(),
                &request.target_image,
            ),
            kind: ReleaseKind::RuntimePair {
                admission: Box::new(admission),
            },
            target_instance_digest: candidate_bytes_digest.clone(),
            probe: None,
            placement: None,
            authority: active.stamp,
            target_security: active.document.security,
            phase: Phase::Prepared,
        };
        persist(tx, release)
    })
}

fn persist(db: &rusqlite::Connection, release: Release) -> Result<Release> {
    let active = authority_state::current(db)?;
    ensure!(
        active.stamp == release.authority && active.artifact_id == release.source.artifact,
        "runtime_pair_authority_changed"
    );
    if let Some(previous) = rollout::state(db)? {
        if previous.id == release.id {
            ensure!(previous == release, "rollout_id_conflict");
            return Ok(previous);
        }
        ensure!(
            matches!(previous.phase, Phase::Complete | Phase::Aborted),
            "rollout_already_running"
        );
    }
    rollout::write(db, &release)?;
    Ok(release)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{authority_state::AuthorityStamp, security_admission::LinuxEvidence};
    use rusqlite::{Connection, params};

    // Synthetic metadata exercises admission, never native qualification.
    fn manifest(label: &[u8]) -> Manifest {
        let digest = crate::digest(label);
        Manifest {
            runtime: RuntimeIdentity {
                platform_inventory: digest.clone(),
                containment: Some(Containment::LinuxQualifiedV1 {
                    evidence: LinuxEvidence {
                        receipt_digest: digest.clone(),
                        platform_inventory: digest.clone(),
                        toolchain: digest.clone(),
                        runtime_image: digest.clone(),
                        runtime_supervisor: digest.clone(),
                        runtime_sandbox: digest,
                        checks: crate::security_admission::LINUX_CHECKS
                            .iter()
                            .map(|value| (*value).into())
                            .collect(),
                    },
                }),
            },
            protocols: Protocols::current(
                crate::digest(b"private schema"),
                crate::digest(b"catalog schema"),
            ),
        }
    }

    fn receipt() -> Receipt {
        Receipt {
            version: 1,
            source: manifest(b"source"),
            target: manifest(b"target"),
            profile: Profile::SqliteLocalV1,
            verifier: crate::digest(b"verifier"),
            recipe: crate::digest(b"recipe"),
            outcome: Outcome::Passed,
            checks: Check::required(),
        }
    }

    fn review(receipt: &Receipt, source: &Manifest) -> Result<Admission> {
        let bytes = serde_json::to_vec(receipt)?;
        Admission::review(&bytes, &crate::digest(&bytes), source)
    }

    #[test]
    fn pair_is_exact_directed_and_never_executor_authority() -> Result<()> {
        let receipt = receipt();
        let admitted = review(&receipt, &receipt.source)?;
        admitted.require_source(&receipt.source.runtime)?;
        assert!(admitted.require_source(&receipt.target.runtime).is_err());
        assert!(review(&receipt, &receipt.target).is_err());
        let bytes = serde_json::to_vec(&receipt)?;
        assert!(
            Admission::review(&bytes, &crate::digest(b"other approval"), &receipt.source).is_err()
        );
        let mut unknown = receipt.source.clone();
        unknown.runtime.platform_inventory = crate::digest(b"unknown runtime");
        assert!(review(&receipt, &unknown).is_err());
        for check in Check::required() {
            let mut incomplete = receipt.clone();
            incomplete.checks.remove(&check);
            assert!(review(&incomplete, &receipt.source).is_err());
        }
        Ok(())
    }

    #[test]
    fn closed_protocols_refuse_schema_abi_leases_and_missing_native_evidence() -> Result<()> {
        let receipt = receipt();
        for key in [
            "private_schema",
            "artifact_catalog_schema",
            "worker",
            "web_ticket",
            "serving_lease",
            "operation_lease",
            "execution_lease",
            "release_journal",
            "authority",
            "invocation_effect",
            "artifact_catalog",
        ] {
            let mut value = serde_json::to_value(&receipt)?;
            value["target"]["protocols"][key] = if key.ends_with("schema") {
                serde_json::json!(crate::digest(b"changed schema"))
            } else {
                serde_json::json!(999)
            };
            let changed: Receipt = crate::json::decode(&serde_json::to_vec(&value)?)?;
            assert!(review(&changed, &receipt.source).is_err(), "{key}");
        }
        let mut value = serde_json::to_value(&receipt)?;
        value["target"]["protocols"]["future_format"] = serde_json::json!(1);
        assert!(crate::json::decode::<Receipt>(&serde_json::to_vec(&value)?).is_err());
        let mut incomplete = receipt.clone();
        incomplete.target.runtime.containment = None;
        assert!(review(&incomplete, &receipt.source).is_err());
        incomplete.target = incomplete.source.clone();
        assert!(review(&incomplete, &receipt.source).is_err());
        Ok(())
    }

    #[test]
    fn same_artifact_generations_round_trip_on_two_sqlite_connections_and_authority_fences_pair()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("app.sqlite");
        let mut source = Connection::open(&path)?;
        source.execute_batch("PRAGMA journal_mode=WAL")?;
        {
            let tx = source.transaction()?;
            tx.execute_batch(crate::store::PLATFORM_DDL)?;
            tx.execute(
                "INSERT INTO day2_meta VALUES('scope','installation/test/app')",
                [],
            )?;
            crate::audit::upgrade(&tx)?;
            authority_state::upgrade(&tx)?;
            rollout::install(&tx)?;
            tx.commit()?;
        }
        let document: authority_state::AuthorityDocument =
            crate::json::decode(br#"{"enabled":true,"readers":[],"writers":[]}"#)?;
        let artifact = crate::digest(b"same artifact");
        source.execute(
            "INSERT INTO day2_authority VALUES(1,?1,1,?2,?3,'artifact')",
            params![
                crate::digest(b"epoch"),
                serde_json::to_string(&document)?,
                artifact
            ],
        )?;
        let receipt = receipt();
        let generation = |runtime: RuntimeIdentity, image: &str| Generation {
            artifact: artifact.clone(),
            runtime,
            instance_digest: crate::digest(b"instance"),
            image: format!("registry/app@{}", crate::digest(image.as_bytes())),
        };
        let release = Release {
            id: "pair".into(),
            scope: "installation/test/app".into(),
            source: generation(receipt.source.runtime.clone(), "source"),
            target: generation(receipt.target.runtime.clone(), "target"),
            kind: ReleaseKind::RuntimePair {
                admission: Box::new(review(&receipt, &receipt.source)?),
            },
            authority: AuthorityStamp {
                epoch: crate::digest(b"epoch"),
                revision: 1,
            },
            target_instance_digest: crate::digest(b"instance bytes"),
            target_security: None,
            probe: None,
            placement: None,
            phase: Phase::Prepared,
        };
        assert_ne!(release.source, release.target);
        let target = Connection::open(&path)?;
        let mut old_record = serde_json::to_value(&release)?;
        old_record["source"] = serde_json::json!(artifact);
        assert!(crate::json::decode::<Release>(&serde_json::to_vec(&old_record)?).is_err());
        // Source writes are readable by the target journal reader, and vice
        // versa. This tests real SQLite/serde conformance, not two runtimes.
        let tx = source.transaction()?;
        persist(&tx, release.clone())?;
        tx.commit()?;
        assert_eq!(rollout::state(&target)?, Some(release.clone()));
        let tx = source.transaction()?;
        assert_eq!(persist(&tx, release.clone())?, release);
        let mut conflict = release.clone();
        conflict.target.image = format!("registry/app@{}", crate::digest(b"another image"));
        assert!(persist(&tx, conflict).is_err());
        let mut second = release.clone();
        second.id = "another-pair".into();
        assert!(persist(&tx, second).is_err());
        tx.commit()?;
        let mut invalid = release.clone();
        invalid.phase = Phase::Serving;
        rollout::write(&source, &invalid)?;
        assert!(rollout::state(&target).is_err());
        rollout::write(&source, &release)?;
        source.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status) VALUES('accepted','command','actor','{}',?1,1,'pending')", [&artifact])?;
        // Metadata-only Runtime fixture exercises the real operator transition;
        // it is not an admitted serving process or native qualification.
        let instance_path = directory.path().join("instance.json");
        std::fs::write(
            &instance_path,
            serde_json::to_vec(&serde_json::json!({
                "installation":"installation", "environment":"test",
                "control":{"version":1,"state_directory":directory.path().join("control"),
                    "operators":["operator"],"sources":{},"apps":{}},
                "apps":{"app":{"artifact":"artifact","readers":[],"writers":[],
                    "runtime":{"kind":"linux_sqlite_rwo_v1","resources":{
                        "memory_mib":512,"cpu_millis":1000,"process_limit":128,
                        "http_concurrency":16,"shutdown_seconds":30}}}}
            }))?,
        )?;
        let contract = serde_json::from_value(serde_json::json!({
            "format":crate::artifact::CURRENT_FORMAT,
            "verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
            "roc_version":"metadata-test", "worker_digest":"metadata-test", "schema_digest":"metadata-test",
            "schema":{"models":{},"inputs":{},"foreign_keys":[]},"operations":[],
            "sources":{},"admission":"local-spike-only"
        }))?;
        let runtime = Runtime::from_artifact_for_tests(
            instance_path,
            "app".into(),
            path,
            LoadedArtifact::from_contract_for_tests(
                artifact.clone(),
                directory.path().join("artifact"),
                contract,
            ),
        )?;
        let operator = LocalOperator::assert_local("operator")?;
        assert!(
            rollout::require_expected_release(&runtime, "pair")
                .unwrap_err()
                .to_string()
                .contains("runtime_pair_activation_not_implemented")
        );
        assert!(
            rollout::transition(&runtime, "pair", Phase::Prepared, Phase::Serving, &operator)
                .unwrap_err()
                .to_string()
                .contains("runtime_pair_activation_not_implemented")
        );
        let aborted =
            rollout::transition(&runtime, "pair", Phase::Prepared, Phase::Aborted, &operator)?;
        assert_eq!(rollout::state(&source)?, Some(aborted));
        let pending: i64 = source.query_row(
            "SELECT count(*) FROM day2_invocations WHERE status='pending'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(pending, 1);
        rollout::write(&source, &release)?;
        let previous = authority_state::current(&source)?;
        let tx = source.transaction()?;
        tx.execute("UPDATE day2_authority SET revision=2", [])?;
        assert!(persist(&tx, release.clone()).is_err());
        assert_eq!(rollout::state(&tx)?, Some(release));
        let next = authority_state::current(&tx)?;
        rollout::authority_changed(&tx, Some(&previous), &next)?;
        tx.commit()?;
        assert!(rollout::state(&target)?.is_none());
        assert_eq!(authority_state::current(&target)?.stamp.revision, 2);
        assert_eq!(authority_state::current(&target)?.artifact_id, artifact);
        Ok(())
    }
}
