//! Runtime-secret metadata and protected deployment consumers. This is a private
//! control-plane boundary; registration and observations come from trusted host
//! adapters, never app code. Availability permits admission, not cloud readiness.
use crate::{
    BindingRef, Digest, Name,
    journal::{Journal, OperatorActor},
    provider_evidence::{DeploymentIncarnation, OpaqueToken},
    release::{self, ActivationReceipt, ImmutableSecretRef, ReleaseApproval, ReleaseTarget},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderResource {
    pub provider: Name,
    pub account: Name,
    pub secret: Name,
}

impl ProviderResource {
    pub fn id(&self) -> Result<Digest> {
        Digest::of(&("day2-runtime-secret-resource-v1", self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceScope {
    pub company: Name,
    pub environment: Name,
}

impl From<&ReleaseTarget> for ResourceScope {
    fn from(target: &ReleaseTarget) -> Self {
        Self {
            company: target.company.clone(),
            environment: target.environment.clone(),
        }
    }
}

/// Physical identity, not authority. Logical app aliases do not participate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretVersionKey {
    pub resource: ProviderResource,
    pub version: NonZeroU64,
}

impl SecretVersionKey {
    pub fn id(&self) -> Result<Digest> {
        Digest::of(&("day2-runtime-secret-version-v1", self))
    }
}

#[derive(Clone, Debug)]
pub struct RegisteredRuntimeSecret {
    key: SecretVersionKey,
}

impl RegisteredRuntimeSecret {
    pub fn key(&self) -> &SecretVersionKey {
        &self.key
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAuthority {
    pub scope: ResourceScope,
    pub revision: u64,
    pub policy: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionState {
    Available,
    Retiring,
    Disabled,
}

impl VersionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Retiring => "retiring",
            Self::Disabled => "disabled",
        }
    }
}

/// Persisted barrier metadata. Every mutation rechecks this against the journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementGuard {
    pub id: Digest,
    pub key: SecretVersionKey,
    pub scope: ResourceScope,
    pub authority_revision: u64,
    pub policy: Digest,
    pub revision: u64,
    pub state: VersionState,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerCounts {
    pub pending: u64,
    pub active: u64,
    pub draining: u64,
    pub rollback: u64,
    pub unproven: u64,
    pub total: u64,
}

impl ConsumerCounts {
    pub fn protected(&self) -> bool {
        self.total != 0
    }
    pub fn total(&self) -> u64 {
        self.total
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerStage {
    Pending,
    Active,
    Draining,
    Drained,
    Abandoned,
}

impl ConsumerStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Drained => "drained",
            Self::Abandoned => "abandoned",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerDrainObservation {
    pub release: Digest,
    pub key: SecretVersionKey,
    pub successor: Digest,
    pub deployment: crate::release_execution::ReleaseProviderFact,
    pub proof: ConsumerQuiescenceProof,
}

/// An adapter qualification is an explicit trusted-host decision, not a digest
/// proving provider semantics. No live provider is granted this capability here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuiescenceAuthorityDecision {
    QualifiedTerminatedAndFenced { review: Digest },
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuiescenceAuthorityRef {
    id: Digest,
    revision: NonZeroU64,
}

impl QuiescenceAuthorityRef {
    pub fn revision(&self) -> NonZeroU64 {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuiescenceCoverage {
    CompleteDescendantsAndDelegatedWork,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerQuiescenceSubject {
    pub release: Digest,
    pub key: SecretVersionKey,
    pub successor: Digest,
    pub deployment: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsumerQuiescenceProof {
    ObservationOnly {
        incarnation: DeploymentIncarnation,
        evidence: Digest,
    },
    TerminatedAndFenced {
        subject: Box<ConsumerQuiescenceSubject>,
        incarnation: DeploymentIncarnation,
        authority: QuiescenceAuthorityRef,
        fence: OpaqueToken,
        coverage: QuiescenceCoverage,
        receipt: Digest,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerView {
    pub release: Digest,
    pub target: ReleaseTarget,
    pub key: SecretVersionKey,
    pub stage: ConsumerStage,
    pub successor: Option<Digest>,
    pub rollback_protected: bool,
    pub drain: Option<ConsumerDrainObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerPage {
    pub items: Vec<ConsumerView>,
    pub next: Option<Digest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeSecretRejection {
    Unregistered,
    WrongOwner,
    BindingConflict,
    VersionUnavailable,
    AuthorityChanged,
    RetirementConflict,
    ProtectedConsumers,
    ConsumerConflict,
    ActiveConsumer,
    UnsettledEffects,
    StaleDrain,
    QuiescenceUnproven,
}

impl std::fmt::Display for RuntimeSecretRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unregistered => "runtime secret is not registered",
            Self::WrongOwner => "runtime secret belongs to another scope",
            Self::BindingConflict => "runtime secret binding is immutable",
            Self::VersionUnavailable => "runtime secret version is not available",
            Self::AuthorityChanged => "runtime secret retirement authority changed",
            Self::RetirementConflict => "runtime secret retirement identity conflict",
            Self::ProtectedConsumers => "runtime secret has protected consumers",
            Self::ConsumerConflict => "runtime secret consumer identity conflict",
            Self::ActiveConsumer => "runtime secret consumer is still active",
            Self::UnsettledEffects => "runtime secret consumer has unsettled effects",
            Self::StaleDrain => "runtime secret drain proof is stale",
            Self::QuiescenceUnproven => "runtime secret physical quiescence is unproven",
        })
    }
}

impl std::error::Error for RuntimeSecretRejection {}

fn require(condition: bool, rejection: RuntimeSecretRejection) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(rejection.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredResource {
    resource: ProviderResource,
    scope: ResourceScope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredVersion {
    key: SecretVersionKey,
    state: VersionState,
    retirement: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBinding {
    target: ReleaseTarget,
    reference: ImmutableSecretRef,
    key: SecretVersionKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DisabledReceipt {
    effect: Digest,
    readback: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRetirement {
    guard: RetirementGuard,
    request: Name,
    actor: OperatorActor,
    disabled: Option<DisabledReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerReceipt {
    consumer: ConsumerView,
    actor: OperatorActor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDeployment {
    deployment: crate::release_execution::ReleaseProviderFact,
    incarnation: DeploymentIncarnation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredQuiescenceAuthority {
    reference: QuiescenceAuthorityRef,
    deployment: Digest,
    scope: ResourceScope,
    binding: BindingRef,
    incarnation: DeploymentIncarnation,
    decision: QuiescenceAuthorityDecision,
}

impl Journal {
    pub(crate) fn initialize_runtime_secret_schema(&mut self) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS runtime_secret_meta(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);
            INSERT OR IGNORE INTO runtime_secret_meta VALUES(1,2);",
        )?;
        let version: i64 = tx.query_row(
            "SELECT version FROM runtime_secret_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            version == 2,
            "unsupported runtime secret schema; explicit evidence migration required"
        );
        tx.execute_batch("CREATE TABLE IF NOT EXISTS runtime_secret_resources(
            id TEXT PRIMARY KEY,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runtime_secret_authority(
            resource TEXT PRIMARY KEY REFERENCES runtime_secret_resources(id),body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runtime_secret_authority_requests(
            id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runtime_secret_versions(
            id TEXT PRIMARY KEY,resource TEXT NOT NULL REFERENCES runtime_secret_resources(id),
            version TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('available','retiring','disabled')),
            body TEXT NOT NULL,UNIQUE(resource,version));
            CREATE TABLE IF NOT EXISTS runtime_secret_bindings(
            id TEXT PRIMARY KEY,version TEXT NOT NULL REFERENCES runtime_secret_versions(id),body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runtime_secret_consumers(
            release TEXT PRIMARY KEY REFERENCES release_approvals(id) DEFERRABLE INITIALLY DEFERRED,
            version TEXT NOT NULL REFERENCES runtime_secret_versions(id),
            stage TEXT NOT NULL CHECK(stage IN ('pending','active','draining','drained','abandoned')),
            rollback INTEGER NOT NULL CHECK(rollback IN (0,1)),body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS runtime_secret_consumers_version ON runtime_secret_consumers(version,release);
            CREATE TRIGGER IF NOT EXISTS runtime_secret_consumer_identity_no_update BEFORE UPDATE OF release,version ON runtime_secret_consumers
                WHEN NEW.release!=OLD.release OR NEW.version!=OLD.version
                BEGIN SELECT RAISE(ABORT,'runtime secret consumer identity is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_consumers_no_delete BEFORE DELETE ON runtime_secret_consumers
                BEGIN SELECT RAISE(ABORT,'runtime secret consumer history is retained'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_consumers_no_replace BEFORE INSERT ON runtime_secret_consumers
                WHEN EXISTS(SELECT 1 FROM runtime_secret_consumers WHERE release=NEW.release)
                BEGIN SELECT RAISE(ABORT,'runtime secret consumer identity is immutable'); END;
            CREATE TABLE IF NOT EXISTS runtime_secret_consumer_receipts(
            release TEXT NOT NULL REFERENCES release_approvals(id),kind TEXT NOT NULL,
            body TEXT NOT NULL,PRIMARY KEY(release,kind));
            CREATE TABLE IF NOT EXISTS runtime_secret_deployments(
            release TEXT PRIMARY KEY REFERENCES release_approvals(id),body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runtime_secret_deployment_history(
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,release TEXT NOT NULL REFERENCES release_approvals(id),
            incarnation TEXT NOT NULL,body TEXT NOT NULL,UNIQUE(release,incarnation));
            CREATE INDEX IF NOT EXISTS runtime_secret_deployment_history_release ON runtime_secret_deployment_history(release,sequence);
            CREATE TRIGGER IF NOT EXISTS runtime_secret_deployment_history_no_update BEFORE UPDATE ON runtime_secret_deployment_history
                BEGIN SELECT RAISE(ABORT,'runtime secret incarnation history is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_deployment_history_no_delete BEFORE DELETE ON runtime_secret_deployment_history
                BEGIN SELECT RAISE(ABORT,'runtime secret incarnation history is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_deployment_history_no_replace BEFORE INSERT ON runtime_secret_deployment_history
                WHEN EXISTS(SELECT 1 FROM runtime_secret_deployment_history WHERE sequence=NEW.sequence OR (release=NEW.release AND incarnation=NEW.incarnation))
                BEGIN SELECT RAISE(ABORT,'runtime secret incarnation history is immutable'); END;
            CREATE TABLE IF NOT EXISTS runtime_secret_quiescence_authorities(
            id TEXT PRIMARY KEY,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runtime_secret_quiescence_requests(
            id TEXT PRIMARY KEY,authority TEXT NOT NULL,revision INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,body TEXT NOT NULL,UNIQUE(authority,revision));
            CREATE TRIGGER IF NOT EXISTS runtime_secret_deployments_no_delete BEFORE DELETE ON runtime_secret_deployments
                BEGIN SELECT RAISE(ABORT,'runtime secret deployment history is retained'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_deployments_no_replace BEFORE INSERT ON runtime_secret_deployments
                WHEN EXISTS(SELECT 1 FROM runtime_secret_deployments WHERE release=NEW.release)
                BEGIN SELECT RAISE(ABORT,'runtime secret deployment identity is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_deployments_identity_no_update BEFORE UPDATE OF release ON runtime_secret_deployments
                WHEN NEW.release!=OLD.release
                BEGIN SELECT RAISE(ABORT,'runtime secret deployment identity is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_quiescence_requests_no_update BEFORE UPDATE ON runtime_secret_quiescence_requests
                BEGIN SELECT RAISE(ABORT,'runtime secret qualification receipts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_quiescence_requests_no_delete BEFORE DELETE ON runtime_secret_quiescence_requests
                BEGIN SELECT RAISE(ABORT,'runtime secret qualification receipts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_quiescence_requests_no_replace BEFORE INSERT ON runtime_secret_quiescence_requests
                WHEN EXISTS(SELECT 1 FROM runtime_secret_quiescence_requests WHERE id=NEW.id)
                BEGIN SELECT RAISE(ABORT,'runtime secret qualification receipts are immutable'); END;
            CREATE TABLE IF NOT EXISTS runtime_secret_retirements(
            id TEXT PRIMARY KEY,version TEXT NOT NULL UNIQUE REFERENCES runtime_secret_versions(id),
            fingerprint TEXT NOT NULL,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runtime_secret_events(
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,resource TEXT NOT NULL,kind TEXT NOT NULL,body TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS runtime_secret_events_no_update BEFORE UPDATE ON runtime_secret_events
                BEGIN SELECT RAISE(ABORT,'runtime secret audit is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_events_no_delete BEFORE DELETE ON runtime_secret_events
                BEGIN SELECT RAISE(ABORT,'runtime secret audit is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_events_no_replace BEFORE INSERT ON runtime_secret_events
                WHEN EXISTS(SELECT 1 FROM runtime_secret_events WHERE sequence=NEW.sequence)
                BEGIN SELECT RAISE(ABORT,'runtime secret audit is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_resources_no_update BEFORE UPDATE ON runtime_secret_resources
                BEGIN SELECT RAISE(ABORT,'runtime secret ownership is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_resources_no_delete BEFORE DELETE ON runtime_secret_resources
                BEGIN SELECT RAISE(ABORT,'runtime secret ownership is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_resources_no_replace BEFORE INSERT ON runtime_secret_resources
                WHEN EXISTS(SELECT 1 FROM runtime_secret_resources WHERE id=NEW.id)
                BEGIN SELECT RAISE(ABORT,'runtime secret ownership is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_bindings_no_update BEFORE UPDATE ON runtime_secret_bindings
                BEGIN SELECT RAISE(ABORT,'runtime secret aliases are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_bindings_no_delete BEFORE DELETE ON runtime_secret_bindings
                BEGIN SELECT RAISE(ABORT,'runtime secret aliases are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_bindings_no_replace BEFORE INSERT ON runtime_secret_bindings
                WHEN EXISTS(SELECT 1 FROM runtime_secret_bindings WHERE id=NEW.id)
                BEGIN SELECT RAISE(ABORT,'runtime secret aliases are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_receipts_no_update BEFORE UPDATE ON runtime_secret_consumer_receipts
                BEGIN SELECT RAISE(ABORT,'runtime secret consumer receipts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_receipts_no_delete BEFORE DELETE ON runtime_secret_consumer_receipts
                BEGIN SELECT RAISE(ABORT,'runtime secret consumer receipts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS runtime_secret_receipts_no_replace BEFORE INSERT ON runtime_secret_consumer_receipts
                WHEN EXISTS(SELECT 1 FROM runtime_secret_consumer_receipts WHERE release=NEW.release AND kind=NEW.kind)
                BEGIN SELECT RAISE(ABORT,'runtime secret consumer receipts are immutable'); END;")?;
        let untracked: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM release_approvals AS approval LEFT JOIN runtime_secret_consumers AS consumer ON consumer.release=approval.id WHERE consumer.release IS NULL)", [], |row| row.get(0))?;
        ensure!(
            !untracked,
            "legacy release approvals require explicit runtime secret consumer migration"
        );
        tx.commit()?;
        Ok(())
    }

    pub fn register_runtime_secret(
        &mut self,
        target: &ReleaseTarget,
        reference: &ImmutableSecretRef,
        resource: &ProviderResource,
        actor: &OperatorActor,
    ) -> Result<RegisteredRuntimeSecret> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let scope = ResourceScope::from(target);
        let resource_id = resource.id()?;
        if let Some(registered) = read_resource_optional(&tx, resource)? {
            require(
                registered.scope == scope,
                RuntimeSecretRejection::WrongOwner,
            )?;
        } else {
            let stored = StoredResource {
                resource: resource.clone(),
                scope,
            };
            tx.execute(
                "INSERT INTO runtime_secret_resources VALUES(?1,?2)",
                params![resource_id.as_str(), serde_json::to_string(&stored)?],
            )?;
            audit(&tx, resource, "registered_resource", &(stored, actor))?;
        }
        let key = SecretVersionKey {
            resource: resource.clone(),
            version: reference.version,
        };
        let version_id = key.id()?;
        let binding = StoredBinding {
            target: target.clone(),
            reference: reference.clone(),
            key: key.clone(),
        };
        let binding_id = binding_id(target, reference)?;
        if let Some(body) = tx
            .query_row(
                "SELECT body FROM runtime_secret_bindings WHERE id=?1",
                [binding_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let old: StoredBinding = serde_json::from_str(&body)?;
            require(old == binding, RuntimeSecretRejection::BindingConflict)?;
            read_binding(&tx, target, reference)?;
            tx.commit()?;
            return Ok(RegisteredRuntimeSecret { key });
        }
        if let Some(version) = read_version_optional(&tx, &key)? {
            require(
                version.state == VersionState::Available,
                RuntimeSecretRejection::VersionUnavailable,
            )?;
        } else {
            let stored = StoredVersion {
                key: key.clone(),
                state: VersionState::Available,
                retirement: None,
            };
            tx.execute(
                "INSERT INTO runtime_secret_versions VALUES(?1,?2,?3,'available',?4)",
                params![
                    version_id.as_str(),
                    resource_id.as_str(),
                    key.version.to_string(),
                    serde_json::to_string(&stored)?
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO runtime_secret_bindings VALUES(?1,?2,?3)",
            params![
                binding_id.as_str(),
                version_id.as_str(),
                serde_json::to_string(&binding)?
            ],
        )?;
        audit(&tx, resource, "registered_alias", &(&binding, actor))?;
        tx.commit()?;
        Ok(RegisteredRuntimeSecret { key })
    }

    pub fn runtime_secret_binding(
        &self,
        target: &ReleaseTarget,
        reference: &ImmutableSecretRef,
    ) -> Result<RegisteredRuntimeSecret> {
        Ok(RegisteredRuntimeSecret {
            key: read_binding(&self.connection, target, reference)?.key,
        })
    }

    pub fn observe_runtime_secret_authority(
        &mut self,
        resource: &ProviderResource,
        scope: &ResourceScope,
        request: &Name,
        expected_revision: u64,
        policy: &Digest,
        actor: &OperatorActor,
    ) -> Result<ResourceAuthority> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require(
            read_resource(&tx, resource)?.scope == *scope,
            RuntimeSecretRejection::WrongOwner,
        )?;
        let id = Digest::of(&("runtime-secret-authority-request-v1", resource, request))?;
        let fingerprint = Digest::of(&(scope, expected_revision, policy, actor))?;
        if let Some((prior, body)) = tx
            .query_row(
                "SELECT fingerprint,body FROM runtime_secret_authority_requests WHERE id=?1",
                [id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            require(
                prior == fingerprint.as_str(),
                RuntimeSecretRejection::AuthorityChanged,
            )?;
            return Ok(serde_json::from_str(&body)?);
        }
        let previous = read_authority_optional(&tx, resource)?;
        require(
            previous.map(|authority| authority.revision).unwrap_or(0) == expected_revision,
            RuntimeSecretRejection::AuthorityChanged,
        )?;
        let authority = ResourceAuthority {
            scope: scope.clone(),
            revision: expected_revision
                .checked_add(1)
                .context("runtime secret authority revision overflow")?,
            policy: policy.clone(),
        };
        let body = serde_json::to_string(&authority)?;
        tx.execute("INSERT INTO runtime_secret_authority VALUES(?1,?2) ON CONFLICT(resource) DO UPDATE SET body=excluded.body", params![resource.id()?.as_str(), &body])?;
        tx.execute(
            "INSERT INTO runtime_secret_authority_requests VALUES(?1,?2,?3)",
            params![id.as_str(), fingerprint.as_str(), body],
        )?;
        audit(
            &tx,
            resource,
            "authority_observed",
            &(&authority, request, actor),
        )?;
        tx.commit()?;
        Ok(authority)
    }

    pub fn runtime_secret_authority(
        &self,
        resource: &ProviderResource,
    ) -> Result<ResourceAuthority> {
        read_authority_optional(&self.connection, resource)?
            .ok_or_else(|| RuntimeSecretRejection::AuthorityChanged.into())
    }

    pub fn runtime_secret_retirement(&self, id: &Digest) -> Result<RetirementGuard> {
        retirement_in(&self.connection, id)
    }

    pub fn runtime_secret_retirement_for(
        &self,
        key: &SecretVersionKey,
    ) -> Result<Option<RetirementGuard>> {
        read_version(&self.connection, key)?
            .retirement
            .as_ref()
            .map(|id| retirement_in(&self.connection, id))
            .transpose()
    }

    pub fn runtime_secret_consumer_counts(&self, key: &SecretVersionKey) -> Result<ConsumerCounts> {
        counts_in(&self.connection, key)
    }

    pub fn runtime_secret_version(&self, key: &SecretVersionKey) -> Result<VersionState> {
        Ok(read_version(&self.connection, key)?.state)
    }

    pub fn runtime_secret_consumer(&self, release: &Digest) -> Result<ConsumerView> {
        read_consumer(&self.connection, release)
    }

    pub fn runtime_secret_consumers(
        &self,
        key: &SecretVersionKey,
        after: Option<&Digest>,
    ) -> Result<ConsumerPage> {
        read_version(&self.connection, key)?;
        let id = key.id()?;
        let after = after.map(Digest::as_str).unwrap_or("");
        let mut query = self.connection.prepare("SELECT release FROM runtime_secret_consumers WHERE version=?1 AND release>?2 ORDER BY release LIMIT 100")?;
        let ids = query
            .query_map(params![id.as_str(), after], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let items = ids
            .iter()
            .map(|id| read_consumer(&self.connection, &Digest::try_from(id.clone())?))
            .collect::<Result<Vec<_>>>()?;
        let next = if let Some(last) = items.last() {
            let exists: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM runtime_secret_consumers WHERE version=?1 AND release>?2)", params![id.as_str(), last.release.as_str()], |row| row.get(0))?;
            exists.then(|| last.release.clone())
        } else {
            None
        };
        Ok(ConsumerPage { items, next })
    }
}

/// Native release settlement calls this after validating its exact prepare ack,
/// in the caller's transaction. It is not a public app registration factory.
pub(crate) fn record_deployment_incarnation_in(
    connection: &Connection,
    deployment: &crate::release_execution::ReleaseProviderFact,
    incarnation: &DeploymentIncarnation,
) -> Result<()> {
    incarnation.validate()?;
    let approval = release::read_approval(connection, &deployment.release)?.approval;
    ensure!(
        deployment.target == approval.target
            && deployment.artifact == approval.artifact
            && deployment.secret == approval.secret
            && deployment.readiness.is_some()
            && deployment.execution
                == Digest::of(&("day2-release-workflow-v1", &deployment.release))?
            && deployment.resource
                == Digest::of(&(
                    "day2-release-resource-v1",
                    &deployment.execution,
                    "deployment"
                ))?,
        "runtime secret deployment incarnation scope mismatch"
    );
    let stored = StoredDeployment {
        deployment: deployment.clone(),
        incarnation: incarnation.clone(),
    };
    let prior: Option<String> = connection
        .query_row(
            "SELECT body FROM runtime_secret_deployments WHERE release=?1",
            [deployment.release.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(prior) = &prior {
        let previous: StoredDeployment = serde_json::from_str(prior)?;
        ensure!(
            previous.deployment.release == deployment.release,
            "runtime secret deployment identity corruption"
        );
        validate_deployment_history(connection, &previous)?;
        if previous == stored {
            return Ok(());
        }
    }
    let body = serde_json::to_string(&stored)?;
    let incarnation_id = Digest::of(incarnation)?;
    let seen: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM runtime_secret_deployment_history WHERE release=?1 AND incarnation=?2)",params![deployment.release.as_str(),incarnation_id.as_str()],|row|row.get(0))?;
    require(!seen, RuntimeSecretRejection::StaleDrain)?;
    connection.execute(
        "INSERT INTO runtime_secret_deployment_history(release,incarnation,body) VALUES(?1,?2,?3)",
        params![deployment.release.as_str(), incarnation_id.as_str(), &body],
    )?;
    if prior.is_some() {
        connection.execute(
            "UPDATE runtime_secret_deployments SET body=?2 WHERE release=?1",
            params![deployment.release.as_str(), body],
        )?;
    } else {
        connection.execute(
            "INSERT INTO runtime_secret_deployments VALUES(?1,?2)",
            params![deployment.release.as_str(), body],
        )?;
    }
    let binding = read_binding(connection, &approval.target, &approval.secret)?;
    connection.execute("INSERT INTO runtime_secret_events(resource,kind,body) VALUES(?1,'deployment_incarnation_observed',?2)",params![binding.key.resource.id()?.as_str(),serde_json::to_string(&stored)?])?;
    Ok(())
}

pub(crate) fn deployment_incarnation_in(
    connection: &Connection,
    deployment: &crate::release_execution::ReleaseProviderFact,
) -> Result<DeploymentIncarnation> {
    let body: String = connection.query_row(
        "SELECT body FROM runtime_secret_deployments WHERE release=?1",
        [deployment.release.as_str()],
        |row| row.get(0),
    )?;
    let stored: StoredDeployment = serde_json::from_str(&body)?;
    require(
        stored.deployment == *deployment,
        RuntimeSecretRejection::StaleDrain,
    )?;
    validate_deployment_history(connection, &stored)?;
    stored.incarnation.validate()?;
    Ok(stored.incarnation)
}

fn validate_deployment_history(connection: &Connection, stored: &StoredDeployment) -> Result<()> {
    let latest: String = connection.query_row("SELECT body FROM runtime_secret_deployment_history WHERE release=?1 ORDER BY sequence DESC LIMIT 1",[stored.deployment.release.as_str()],|row|row.get(0))?;
    ensure!(
        serde_json::from_str::<StoredDeployment>(&latest)? == *stored,
        "runtime secret incarnation history corruption"
    );
    Ok(())
}

fn quiescence_authority_id(
    deployment: &Digest,
    scope: &ResourceScope,
    binding: &BindingRef,
    incarnation: &DeploymentIncarnation,
) -> Result<Digest> {
    Digest::of(&(
        "runtime-secret-quiescence-authority-v1",
        deployment,
        scope,
        binding,
        incarnation,
    ))
}

fn read_quiescence_authority(
    connection: &Connection,
    id: &Digest,
) -> Result<Option<StoredQuiescenceAuthority>> {
    let body: Option<String> = connection
        .query_row(
            "SELECT body FROM runtime_secret_quiescence_authorities WHERE id=?1",
            [id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    body.map(|body| {
        let stored: StoredQuiescenceAuthority = serde_json::from_str(&body)?;
        ensure!(stored.reference.id == *id && quiescence_authority_id(&stored.deployment,&stored.scope,&stored.binding,&stored.incarnation)? == *id,
            "runtime secret quiescence authority identity corruption");
        let latest: i64 = connection.query_row("SELECT MAX(revision) FROM runtime_secret_quiescence_requests WHERE authority=?1", [id.as_str()], |row| row.get(0))?;
        ensure!(u64::try_from(latest)? == stored.reference.revision.get(), "runtime secret quiescence authority revision corruption");
        let receipt: String = connection.query_row("SELECT body FROM runtime_secret_quiescence_requests WHERE authority=?1 AND revision=?2",params![id.as_str(),latest],|row|row.get(0))?;
        ensure!(serde_json::from_str::<StoredQuiescenceAuthority>(&receipt)? == stored,
            "runtime secret quiescence authority receipt corruption");
        Ok(stored)
    }).transpose()
}

impl Journal {
    /// Trusted adapter observation of an existing deployment's physical identity.
    /// A changed controller/generation invalidates earlier accepted free proofs.
    pub fn observe_deployment_incarnation(
        &mut self,
        deployment: &crate::release_execution::ReleaseProviderFact,
        incarnation: &DeploymentIncarnation,
        actor: &OperatorActor,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require(
            crate::release_execution::runtime_deployment_fact(&tx, &deployment.release)?.as_ref()
                == Some(deployment),
            RuntimeSecretRejection::StaleDrain,
        )?;
        record_deployment_incarnation_in(&tx, deployment, incarnation)?;
        let binding = read_binding(&tx, &deployment.target, &deployment.secret)?;
        audit(
            &tx,
            &binding.key.resource,
            "deployment_incarnation_attested",
            &(deployment, incarnation, actor),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn deployment_incarnation(
        &self,
        deployment: &crate::release_execution::ReleaseProviderFact,
    ) -> Result<DeploymentIncarnation> {
        deployment_incarnation_in(&self.connection, deployment)
    }

    /// The reviewer grants only the capability to attest full physical
    /// termination plus prevention of recreation, including delegated work.
    /// Provider API emptiness, polling and token revocation do not qualify.
    pub fn observe_quiescence_authority(
        &mut self,
        deployment: &crate::release_execution::ReleaseProviderFact,
        request: &Name,
        expected_revision: u64,
        decision: &QuiescenceAuthorityDecision,
        actor: &OperatorActor,
    ) -> Result<QuiescenceAuthorityRef> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require(
            crate::release_execution::runtime_deployment_fact(&tx, &deployment.release)?.as_ref()
                == Some(deployment),
            RuntimeSecretRejection::StaleDrain,
        )?;
        let incarnation = deployment_incarnation_in(&tx, deployment)?;
        let scope = ResourceScope::from(&deployment.target);
        let deployment_id = Digest::of(deployment)?;
        let id =
            quiescence_authority_id(&deployment_id, &scope, &deployment.binding, &incarnation)?;
        let request_id = Digest::of(&("runtime-secret-quiescence-request-v1", &id, request))?;
        let fingerprint = Digest::of(&(deployment, expected_revision, decision, actor))?;
        if let Some((prior, body)) = tx
            .query_row(
                "SELECT fingerprint,body FROM runtime_secret_quiescence_requests WHERE id=?1",
                [request_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            require(
                prior == fingerprint.as_str(),
                RuntimeSecretRejection::AuthorityChanged,
            )?;
            let stored: StoredQuiescenceAuthority = serde_json::from_str(&body)?;
            ensure!(
                stored.reference.id == id,
                "runtime secret qualification request corruption"
            );
            return Ok(stored.reference);
        }
        let prior = read_quiescence_authority(&tx, &id)?;
        require(
            prior
                .as_ref()
                .map(|value| value.reference.revision.get())
                .unwrap_or(0)
                == expected_revision,
            RuntimeSecretRejection::AuthorityChanged,
        )?;
        let revision = expected_revision
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .context("runtime secret qualification revision exhausted")?;
        let stored = StoredQuiescenceAuthority {
            reference: QuiescenceAuthorityRef {
                id: id.clone(),
                revision,
            },
            deployment: deployment_id,
            scope,
            binding: deployment.binding.clone(),
            incarnation,
            decision: decision.clone(),
        };
        let body = serde_json::to_string(&stored)?;
        tx.execute(
            "INSERT INTO runtime_secret_quiescence_requests VALUES(?1,?2,?3,?4,?5)",
            params![
                request_id.as_str(),
                id.as_str(),
                i64::try_from(revision.get())?,
                fingerprint.as_str(),
                body
            ],
        )?;
        tx.execute("INSERT INTO runtime_secret_quiescence_authorities VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET body=excluded.body",params![id.as_str(),serde_json::to_string(&stored)?])?;
        let binding = read_binding(&tx, &deployment.target, &deployment.secret)?;
        audit(
            &tx,
            &binding.key.resource,
            "quiescence_authority_observed",
            &(&stored, request, actor),
        )?;
        tx.commit()?;
        Ok(stored.reference)
    }

    pub fn quiescence_authority(
        &self,
        deployment: &crate::release_execution::ReleaseProviderFact,
    ) -> Result<Option<QuiescenceAuthorityRef>> {
        let incarnation = deployment_incarnation_in(&self.connection, deployment)?;
        let id = quiescence_authority_id(
            &Digest::of(deployment)?,
            &ResourceScope::from(&deployment.target),
            &deployment.binding,
            &incarnation,
        )?;
        Ok(read_quiescence_authority(&self.connection, &id)?.map(|value| value.reference))
    }
}

fn quiescence_proof_current(
    connection: &Connection,
    observation: &ConsumerDrainObservation,
) -> Result<bool> {
    let ConsumerQuiescenceProof::TerminatedAndFenced {
        incarnation,
        authority,
        ..
    } = &observation.proof
    else {
        return Ok(false);
    };
    if !quiescence_proof_admitted(connection, observation)? {
        return Ok(false);
    }
    incarnation.validate()?;
    match deployment_incarnation_in(connection, &observation.deployment) {
        Ok(current) if current == *incarnation => {}
        Ok(_) => return Ok(false),
        Err(error)
            if error.downcast_ref::<RuntimeSecretRejection>()
                == Some(&RuntimeSecretRejection::StaleDrain) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    }
    let scope = ResourceScope::from(&observation.deployment.target);
    let id = quiescence_authority_id(
        &Digest::of(&observation.deployment)?,
        &scope,
        &observation.deployment.binding,
        incarnation,
    )?;
    if authority.id != id {
        return Ok(false);
    }
    let Some(current) = read_quiescence_authority(connection, &id)? else {
        return Ok(false);
    };
    Ok(current.reference == *authority
        && matches!(
            current.decision,
            QuiescenceAuthorityDecision::QualifiedTerminatedAndFenced { .. }
        ))
}

fn quiescence_proof_admitted(
    connection: &Connection,
    observation: &ConsumerDrainObservation,
) -> Result<bool> {
    let ConsumerQuiescenceProof::TerminatedAndFenced {
        subject,
        incarnation,
        authority,
        ..
    } = &observation.proof
    else {
        return Ok(false);
    };
    if subject.release != observation.release
        || subject.key != observation.key
        || subject.successor != observation.successor
        || subject.deployment != Digest::of(&observation.deployment)?
    {
        return Ok(false);
    }
    let scope = ResourceScope::from(&observation.deployment.target);
    let id = quiescence_authority_id(
        &subject.deployment,
        &scope,
        &observation.deployment.binding,
        incarnation,
    )?;
    if authority.id != id {
        return Ok(false);
    }
    let body: Option<String> = connection.query_row("SELECT body FROM runtime_secret_quiescence_requests WHERE authority=?1 AND revision=?2",params![id.as_str(),i64::try_from(authority.revision.get())?],|row|row.get(0)).optional()?;
    let Some(body) = body else { return Ok(false) };
    let qualified: StoredQuiescenceAuthority = serde_json::from_str(&body)?;
    ensure!(
        qualified.reference == *authority
            && qualified.deployment == subject.deployment
            && qualified.scope == scope
            && qualified.binding == observation.deployment.binding
            && qualified.incarnation == *incarnation,
        "runtime secret historical quiescence authority corruption"
    );
    Ok(matches!(
        qualified.decision,
        QuiescenceAuthorityDecision::QualifiedTerminatedAndFenced { .. }
    ))
}

pub(crate) fn reserve_release_in(
    tx: &Transaction<'_>,
    id: &Digest,
    approval: &ReleaseApproval,
) -> Result<()> {
    ensure!(
        *id == Digest::of(&("day2-release-v1", &approval.target, &approval.request))?,
        "runtime secret release identity mismatch"
    );
    let binding = read_binding(tx, &approval.target, &approval.secret)?;
    require(
        read_version(tx, &binding.key)?.state == VersionState::Available,
        RuntimeSecretRejection::VersionUnavailable,
    )?;
    if tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_secret_consumers WHERE release=?1)",
        [id.as_str()],
        |row| row.get::<_, bool>(0),
    )? {
        let existing = read_consumer(tx, id)?;
        require(
            existing.target == approval.target && existing.key == binding.key,
            RuntimeSecretRejection::ConsumerConflict,
        )?;
        return Ok(());
    }
    let consumer = ConsumerView {
        release: id.clone(),
        target: approval.target.clone(),
        key: binding.key,
        stage: ConsumerStage::Pending,
        successor: None,
        rollback_protected: false,
        drain: None,
    };
    write_consumer(tx, &consumer, true)?;
    audit(tx, &consumer.key.resource, "consumer_reserved", &consumer)
}

pub(crate) fn require_release_in(
    connection: &Connection,
    id: &Digest,
    approval: &ReleaseApproval,
) -> Result<()> {
    let binding = read_binding(connection, &approval.target, &approval.secret)?;
    require(
        read_version(connection, &binding.key)?.state == VersionState::Available,
        RuntimeSecretRejection::VersionUnavailable,
    )?;
    let consumer = read_consumer(connection, id)?;
    require(
        consumer.target == approval.target && consumer.key == binding.key,
        RuntimeSecretRejection::ConsumerConflict,
    )?;
    require(
        matches!(
            consumer.stage,
            ConsumerStage::Pending | ConsumerStage::Active
        ),
        RuntimeSecretRejection::VersionUnavailable,
    )
}

/// Called before changing the active release slot, in the same transaction.
pub(crate) fn activate_release_in(tx: &Transaction<'_>, receipt: &ActivationReceipt) -> Result<()> {
    let mut consumer = read_consumer(tx, &receipt.release)?;
    require(
        consumer.target == receipt.target,
        RuntimeSecretRejection::ConsumerConflict,
    )?;
    require(
        read_version(tx, &consumer.key)?.state == VersionState::Available,
        RuntimeSecretRejection::VersionUnavailable,
    )?;
    let current = release::read_state(tx, &receipt.target)?;
    if current
        .active
        .as_ref()
        .is_some_and(|active| active.release == receipt.release)
    {
        require(
            consumer.stage == ConsumerStage::Active,
            RuntimeSecretRejection::ConsumerConflict,
        )?;
        return Ok(());
    }
    require(
        consumer.stage == ConsumerStage::Pending,
        RuntimeSecretRejection::ConsumerConflict,
    )?;
    if let Some(incumbent) = current.active {
        let mut old = read_consumer(tx, &incumbent.release)?;
        require(
            old.stage == ConsumerStage::Active && old.target == receipt.target,
            RuntimeSecretRejection::ConsumerConflict,
        )?;
        old.stage = ConsumerStage::Draining;
        old.successor = Some(receipt.release.clone());
        old.rollback_protected = true;
        write_consumer(tx, &old, false)?;
        audit(tx, &old.key.resource, "consumer_superseded", &old)?;
    }
    consumer.stage = ConsumerStage::Active;
    write_consumer(tx, &consumer, false)?;
    audit(tx, &consumer.key.resource, "consumer_activated", &consumer)
}

impl Journal {
    /// The adapter must actually observe the old deployment drained. An active
    /// pointer change alone never constructs this evidence.
    pub fn observe_runtime_secret_drain(
        &mut self,
        observation: &ConsumerDrainObservation,
        actor: &OperatorActor,
    ) -> Result<ConsumerView> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut consumer = read_consumer(&tx, &observation.release)?;
        require(
            consumer.key == observation.key
                && consumer.successor.as_ref() == Some(&observation.successor),
            RuntimeSecretRejection::StaleDrain,
        )?;
        require_superseded(&tx, &consumer, &observation.successor)?;
        require_no_unsettled_effects(&tx, &consumer.release)?;
        let deployment = crate::release_execution::runtime_deployment_fact(&tx, &consumer.release)?
            .ok_or(RuntimeSecretRejection::StaleDrain)?;
        require(
            deployment == observation.deployment
                && deployment.release == consumer.release
                && deployment.target == consumer.target,
            RuntimeSecretRejection::StaleDrain,
        )?;
        require(
            quiescence_proof_current(&tx, observation)?,
            RuntimeSecretRejection::QuiescenceUnproven,
        )?;
        if let Some(prior) = &consumer.drain {
            if prior == observation {
                return Ok(consumer);
            }
            return Err(RuntimeSecretRejection::StaleDrain.into());
        }
        require(
            matches!(
                consumer.stage,
                ConsumerStage::Draining | ConsumerStage::Drained
            ),
            RuntimeSecretRejection::StaleDrain,
        )?;
        consumer.stage = ConsumerStage::Drained;
        consumer.drain = Some(observation.clone());
        write_consumer_receipt(&tx, &consumer, "drain", actor)?;
        write_consumer(&tx, &consumer, false)?;
        audit(
            &tx,
            &consumer.key.resource,
            "consumer_drained",
            &(&consumer, actor),
        )?;
        tx.commit()?;
        Ok(consumer)
    }

    /// Explicit operator policy decision after a verified drain; there is no
    /// implicit timeout that silently removes rollback protection.
    pub fn release_runtime_secret_rollback(
        &mut self,
        release: &Digest,
        successor: &Digest,
        actor: &OperatorActor,
    ) -> Result<ConsumerView> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut consumer = read_consumer(&tx, release)?;
        require_superseded(&tx, &consumer, successor)?;
        require_no_unsettled_effects(&tx, release)?;
        require(
            consumer.stage == ConsumerStage::Drained
                && consumer
                    .drain
                    .as_ref()
                    .is_some_and(|proof| proof.successor == *successor),
            RuntimeSecretRejection::StaleDrain,
        )?;
        require(
            quiescence_proof_current(
                &tx,
                consumer
                    .drain
                    .as_ref()
                    .context("runtime secret drain required")?,
            )?,
            RuntimeSecretRejection::QuiescenceUnproven,
        )?;
        if consumer.rollback_protected {
            consumer.rollback_protected = false;
            write_consumer_receipt(&tx, &consumer, "rollback", actor)?;
            write_consumer(&tx, &consumer, false)?;
            audit(
                &tx,
                &consumer.key.resource,
                "rollback_released",
                &(&consumer, actor),
            )?;
        }
        tx.commit()?;
        Ok(consumer)
    }

    /// An unstarted, superseded/cancelled candidate may release its reservation.
    /// Any prepared deployment or unresolved dispatch requires explicit recovery.
    pub fn abandon_runtime_secret_consumer(
        &mut self,
        release: &Digest,
        actor: &OperatorActor,
    ) -> Result<ConsumerView> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut consumer = read_consumer(&tx, release)?;
        let current = release::read_state(&tx, &consumer.target)?;
        require(
            current
                .active
                .as_ref()
                .is_none_or(|active| active.release != *release),
            RuntimeSecretRejection::ActiveConsumer,
        )?;
        let status: String = tx.query_row(
            "SELECT status FROM release_status WHERE id=?1",
            [release.as_str()],
            |row| row.get(0),
        )?;
        require(
            current.desired.as_ref() != Some(release)
                || matches!(status.as_str(), "cancelled" | "revoked"),
            RuntimeSecretRejection::ConsumerConflict,
        )?;
        require_no_unsettled_effects(&tx, release)?;
        require_no_deployment_history(&tx, release)?;
        require(
            crate::release_execution::runtime_deployment_fact(&tx, release)?.is_none(),
            RuntimeSecretRejection::UnsettledEffects,
        )?;
        if consumer.stage == ConsumerStage::Abandoned {
            return Ok(consumer);
        }
        require(
            consumer.stage == ConsumerStage::Pending,
            RuntimeSecretRejection::ConsumerConflict,
        )?;
        consumer.stage = ConsumerStage::Abandoned;
        write_consumer_receipt(&tx, &consumer, "abandon", actor)?;
        write_consumer(&tx, &consumer, false)?;
        audit(
            &tx,
            &consumer.key.resource,
            "consumer_abandoned",
            &(&consumer, actor),
        )?;
        tx.commit()?;
        Ok(consumer)
    }
}

pub(crate) fn begin_retirement_in(
    tx: &Transaction<'_>,
    key: &SecretVersionKey,
    scope: &ResourceScope,
    request: &Name,
    expected_authority_revision: u64,
    policy: &Digest,
    actor: &OperatorActor,
) -> Result<RetirementGuard> {
    require(
        read_resource(tx, &key.resource)?.scope == *scope,
        RuntimeSecretRejection::WrongOwner,
    )?;
    let id = Digest::of(&("runtime-secret-retirement-v1", key))?;
    let fingerprint = Digest::of(&(
        key,
        scope,
        request,
        expected_authority_revision,
        policy,
        actor,
    ))?;
    if let Some(prior) = tx
        .query_row(
            "SELECT fingerprint FROM runtime_secret_retirements WHERE id=?1",
            [id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        require(
            prior == fingerprint.as_str(),
            RuntimeSecretRejection::RetirementConflict,
        )?;
        return retirement_in(tx, &id);
    }
    let version = read_version(tx, key)?;
    require(
        version.state == VersionState::Available,
        RuntimeSecretRejection::VersionUnavailable,
    )?;
    let guard = RetirementGuard {
        id: id.clone(),
        key: key.clone(),
        scope: scope.clone(),
        authority_revision: expected_authority_revision,
        policy: policy.clone(),
        revision: 1,
        state: VersionState::Retiring,
    };
    require_retirement_authority_in(tx, &guard)?;
    let stored = StoredRetirement {
        guard: guard.clone(),
        request: request.clone(),
        actor: actor.clone(),
        disabled: None,
    };
    tx.execute(
        "INSERT INTO runtime_secret_retirements VALUES(?1,?2,?3,?4)",
        params![
            id.as_str(),
            key.id()?.as_str(),
            fingerprint.as_str(),
            serde_json::to_string(&stored)?
        ],
    )?;
    write_version(
        tx,
        &StoredVersion {
            key: key.clone(),
            state: VersionState::Retiring,
            retirement: Some(id),
        },
    )?;
    audit(tx, &key.resource, "retirement_barrier", &stored)?;
    Ok(guard)
}

pub(crate) fn retirement_in(connection: &Connection, id: &Digest) -> Result<RetirementGuard> {
    Ok(read_retirement(connection, id)?.guard)
}

pub(crate) fn require_retirement_authority_in(
    connection: &Connection,
    guard: &RetirementGuard,
) -> Result<()> {
    require(
        read_resource(connection, &guard.key.resource)?.scope == guard.scope,
        RuntimeSecretRejection::WrongOwner,
    )?;
    let authority = read_authority_optional(connection, &guard.key.resource)?
        .ok_or(RuntimeSecretRejection::AuthorityChanged)?;
    require(
        authority.scope == guard.scope
            && authority.revision == guard.authority_revision
            && authority.policy == guard.policy,
        RuntimeSecretRejection::AuthorityChanged,
    )
}

pub(crate) fn retirement_consumers_in(
    connection: &Connection,
    id: &Digest,
) -> Result<ConsumerCounts> {
    let guard = retirement_in(connection, id)?;
    counts_in(connection, &guard.key)
}

pub(crate) fn require_disable_in(tx: &Transaction<'_>, guard: &RetirementGuard) -> Result<()> {
    let current = retirement_in(tx, &guard.id)?;
    require(
        current == *guard && current.state == VersionState::Retiring,
        RuntimeSecretRejection::RetirementConflict,
    )?;
    require_retirement_authority_in(tx, guard)?;
    require(
        !counts_in(tx, &guard.key)?.protected(),
        RuntimeSecretRejection::ProtectedConsumers,
    )
}

/// Only the native retirement host calls this after validating a persisted exact
/// provider readback and effect lease in this same transaction. Revocation cannot
/// erase a physical outcome; this does not authorize another provider mutation.
pub(crate) fn complete_disabled_in(
    tx: &Transaction<'_>,
    guard: &RetirementGuard,
    effect: &Digest,
    readback: &Digest,
) -> Result<RetirementGuard> {
    let mut stored = read_retirement(tx, &guard.id)?;
    require(
        stored.guard.key == guard.key
            && stored.guard.scope == guard.scope
            && stored.guard.authority_revision == guard.authority_revision
            && stored.guard.policy == guard.policy,
        RuntimeSecretRejection::RetirementConflict,
    )?;
    let observed = DisabledReceipt {
        effect: effect.clone(),
        readback: readback.clone(),
    };
    if let Some(previous) = &stored.disabled {
        require(
            previous == &observed,
            RuntimeSecretRejection::RetirementConflict,
        )?;
        return Ok(stored.guard);
    }
    require(
        stored.guard == *guard && guard.state == VersionState::Retiring,
        RuntimeSecretRejection::RetirementConflict,
    )?;
    // Dispatch already checked consumer protections. A later loss of quiescence
    // evidence cannot erase a qualified physical outcome of that authorized call.
    stored.guard.revision = stored
        .guard
        .revision
        .checked_add(1)
        .context("runtime secret retirement revision overflow")?;
    stored.guard.state = VersionState::Disabled;
    stored.disabled = Some(observed);
    tx.execute(
        "UPDATE runtime_secret_retirements SET body=?2 WHERE id=?1",
        params![guard.id.as_str(), serde_json::to_string(&stored)?],
    )?;
    write_version(
        tx,
        &StoredVersion {
            key: guard.key.clone(),
            state: VersionState::Disabled,
            retirement: Some(guard.id.clone()),
        },
    )?;
    audit(tx, &guard.key.resource, "version_disabled", &stored)?;
    Ok(stored.guard)
}

fn read_retirement(connection: &Connection, id: &Digest) -> Result<StoredRetirement> {
    let (version, fingerprint, body): (String, String, String) = connection.query_row(
        "SELECT version,fingerprint,body FROM runtime_secret_retirements WHERE id=?1",
        [id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let stored: StoredRetirement = serde_json::from_str(&body)?;
    let guard = &stored.guard;
    ensure!(
        guard.id == *id
            && *id == Digest::of(&("runtime-secret-retirement-v1", &guard.key))?
            && version == guard.key.id()?.as_str()
            && fingerprint
                == Digest::of(&(
                    &guard.key,
                    &guard.scope,
                    &stored.request,
                    guard.authority_revision,
                    &guard.policy,
                    &stored.actor
                ))?
                .as_str(),
        "runtime secret retirement identity corruption"
    );
    ensure!(
        (guard.state == VersionState::Retiring && guard.revision == 1 && stored.disabled.is_none())
            || (guard.state == VersionState::Disabled
                && guard.revision == 2
                && stored.disabled.is_some()),
        "runtime secret retirement state corruption"
    );
    let version = read_version(connection, &guard.key)?;
    ensure!(
        version.state == guard.state
            && version.retirement.as_ref() == Some(id)
            && read_resource(connection, &guard.key.resource)?.scope == guard.scope,
        "runtime secret retirement barrier corruption"
    );
    Ok(stored)
}

fn counts_in(connection: &Connection, key: &SecretVersionKey) -> Result<ConsumerCounts> {
    read_version(connection, key)?;
    let raw: (i64, i64, i64, i64, i64) = connection.query_row("SELECT
        COALESCE(SUM(stage='pending'),0),COALESCE(SUM(stage='active'),0),COALESCE(SUM(stage='draining'),0),
        COALESCE(SUM(rollback=1),0),COALESCE(SUM(stage IN ('pending','active','draining') OR rollback=1),0)
        FROM runtime_secret_consumers WHERE version=?1", [key.id()?.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?;
    let mut counts = ConsumerCounts {
        pending: raw.0.try_into()?,
        active: raw.1.try_into()?,
        draining: raw.2.try_into()?,
        rollback: raw.3.try_into()?,
        unproven: 0,
        total: raw.4.try_into()?,
    };
    // Freed consumers remain dependent on their exact qualified physical fence.
    // Revocation or incarnation drift restores protection without rewriting history.
    {
        let version = key.id()?;
        let mut after = String::new();
        loop {
            let mut query = connection.prepare("SELECT release FROM runtime_secret_consumers WHERE version=?1 AND release>?2 ORDER BY release LIMIT 100")?;
            let rows = query
                .query_map(params![version.as_str(), &after], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for id in &rows {
                let consumer = read_consumer(connection, &Digest::try_from(id.clone())?)?;
                ensure!(
                    consumer.key == *key,
                    "runtime secret consumer version corruption"
                );
                if consumer.stage == ConsumerStage::Drained
                    && !consumer.rollback_protected
                    && !quiescence_proof_current(
                        connection,
                        consumer
                            .drain
                            .as_ref()
                            .context("runtime secret drain required")?,
                    )?
                {
                    counts.unproven = counts
                        .unproven
                        .checked_add(1)
                        .context("runtime secret unproven count overflow")?;
                    counts.total = counts
                        .total
                        .checked_add(1)
                        .context("runtime secret consumer count overflow")?;
                }
            }
            if rows.len() < 100 {
                break;
            }
            after = rows.last().context("runtime secret consumer page")?.clone();
        }
    }
    Ok(counts)
}

fn write_consumer_receipt(
    tx: &Transaction<'_>,
    consumer: &ConsumerView,
    kind: &str,
    actor: &OperatorActor,
) -> Result<()> {
    let receipt = ConsumerReceipt {
        consumer: consumer.clone(),
        actor: actor.clone(),
    };
    tx.execute(
        "INSERT INTO runtime_secret_consumer_receipts VALUES(?1,?2,?3)",
        params![
            consumer.release.as_str(),
            kind,
            serde_json::to_string(&receipt)?
        ],
    )?;
    Ok(())
}

fn consumer_receipt(
    connection: &Connection,
    release: &Digest,
    kind: &str,
) -> Result<ConsumerReceipt> {
    let body: String = connection.query_row(
        "SELECT body FROM runtime_secret_consumer_receipts WHERE release=?1 AND kind=?2",
        params![release.as_str(), kind],
        |row| row.get(0),
    )?;
    let receipt: ConsumerReceipt = serde_json::from_str(&body)?;
    ensure!(
        receipt.consumer.release == *release,
        "runtime secret consumer receipt corruption"
    );
    Ok(receipt)
}

fn write_version(tx: &Transaction<'_>, version: &StoredVersion) -> Result<()> {
    let changed = tx.execute(
        "UPDATE runtime_secret_versions SET state=?2,body=?3 WHERE id=?1",
        params![
            version.key.id()?.as_str(),
            version.state.as_str(),
            serde_json::to_string(version)?
        ],
    )?;
    ensure!(changed == 1, "runtime secret version disappeared");
    Ok(())
}

fn write_consumer(tx: &Transaction<'_>, consumer: &ConsumerView, insert: bool) -> Result<()> {
    let sql = if insert {
        "INSERT INTO runtime_secret_consumers(release,version,stage,rollback,body) VALUES(?1,?2,?3,?4,?5)"
    } else {
        "UPDATE runtime_secret_consumers SET version=?2,stage=?3,rollback=?4,body=?5 WHERE release=?1"
    };
    let changed = tx.execute(
        sql,
        params![
            consumer.release.as_str(),
            consumer.key.id()?.as_str(),
            consumer.stage.as_str(),
            consumer.rollback_protected,
            serde_json::to_string(consumer)?
        ],
    )?;
    ensure!(changed == 1, "runtime secret consumer disappeared");
    Ok(())
}

fn read_consumer(connection: &Connection, id: &Digest) -> Result<ConsumerView> {
    let (version, stage, rollback, body): (String, String, bool, String) = connection.query_row(
        "SELECT version,stage,rollback,body FROM runtime_secret_consumers WHERE release=?1",
        [id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let consumer: ConsumerView = serde_json::from_str(&body)?;
    ensure!(
        consumer.release == *id
            && version == consumer.key.id()?.as_str()
            && stage == consumer.stage.as_str()
            && rollback == consumer.rollback_protected,
        "runtime secret consumer identity corruption"
    );
    let valid = match consumer.stage {
        ConsumerStage::Pending | ConsumerStage::Active | ConsumerStage::Abandoned => {
            consumer.successor.is_none() && !consumer.rollback_protected && consumer.drain.is_none()
        }
        ConsumerStage::Draining => {
            consumer.successor.is_some() && consumer.rollback_protected && consumer.drain.is_none()
        }
        ConsumerStage::Drained => consumer.drain.as_ref().is_some_and(|proof| {
            proof.release == consumer.release
                && proof.key == consumer.key
                && Some(&proof.successor) == consumer.successor.as_ref()
                && proof.deployment.release == consumer.release
                && proof.deployment.target == consumer.target
        }),
    };
    ensure!(valid, "runtime secret consumer state corruption");
    let approval = release::read_approval(connection, id)?.approval;
    let binding = read_binding(connection, &approval.target, &approval.secret)?;
    ensure!(
        consumer.target == approval.target && consumer.key == binding.key,
        "runtime secret consumer approval corruption"
    );
    let current = release::read_state(connection, &consumer.target)?;
    let activated: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM release_activations WHERE release=?1)",
        [id.as_str()],
        |row| row.get(0),
    )?;
    match consumer.stage {
        ConsumerStage::Pending => {
            ensure!(!activated, "activated runtime consumer cannot be pending")
        }
        ConsumerStage::Active => ensure!(
            activated
                && current
                    .active
                    .as_ref()
                    .is_some_and(|active| active.release == *id),
            "runtime secret active consumer corruption"
        ),
        ConsumerStage::Draining | ConsumerStage::Drained => {
            ensure!(
                activated,
                "runtime secret draining consumer lacks activation"
            );
            require_superseded(
                connection,
                &consumer,
                consumer
                    .successor
                    .as_ref()
                    .context("runtime secret consumer successor")?,
            )?;
            if consumer.stage == ConsumerStage::Drained {
                let recorded = consumer_receipt(connection, id, "drain")?;
                ensure!(
                    recorded.consumer.target == consumer.target
                        && recorded.consumer.key == consumer.key
                        && recorded.consumer.successor == consumer.successor
                        && recorded.consumer.drain == consumer.drain
                        && recorded.consumer.stage == ConsumerStage::Drained,
                    "runtime secret drain receipt corruption"
                );
                ensure!(
                    quiescence_proof_admitted(
                        connection,
                        consumer
                            .drain
                            .as_ref()
                            .context("runtime secret drain required")?
                    )?,
                    "runtime secret accepted drain lacks qualified physical evidence"
                );
                if !consumer.rollback_protected {
                    ensure!(
                        consumer_receipt(connection, id, "rollback")?.consumer == consumer,
                        "runtime secret rollback receipt corruption"
                    );
                }
            }
        }
        ConsumerStage::Abandoned => {
            ensure!(
                !activated && consumer_receipt(connection, id, "abandon")?.consumer == consumer,
                "runtime secret abandoned consumer corruption"
            );
        }
    }
    Ok(consumer)
}

fn require_superseded(
    connection: &Connection,
    consumer: &ConsumerView,
    successor: &Digest,
) -> Result<()> {
    require(
        consumer.successor.as_ref() == Some(successor),
        RuntimeSecretRejection::StaleDrain,
    )?;
    let current = release::read_state(connection, &consumer.target)?;
    let active = current.active.ok_or(RuntimeSecretRejection::StaleDrain)?;
    require(
        active.release != consumer.release,
        RuntimeSecretRejection::ActiveConsumer,
    )?;
    let body: String = connection.query_row(
        "SELECT body FROM release_activations WHERE release=?1",
        [successor.as_str()],
        |row| row.get(0),
    )?;
    let receipt: ActivationReceipt = serde_json::from_str(&body)?;
    require(
        receipt.release == *successor
            && receipt.target == consumer.target
            && active.generation >= receipt.generation,
        RuntimeSecretRejection::StaleDrain,
    )
}

fn require_no_unsettled_effects(connection: &Connection, release: &Digest) -> Result<()> {
    let execution = Digest::of(&("day2-release-workflow-v1", release))?;
    let outstanding: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM release_steps WHERE execution=?1 AND status!='complete' AND (started=1 OR recovery=1 OR status='ambiguous'))", [execution.as_str()], |row| row.get(0))?;
    require(!outstanding, RuntimeSecretRejection::UnsettledEffects)
}

fn require_no_deployment_history(connection: &Connection, release: &Digest) -> Result<()> {
    let execution = Digest::of(&("day2-release-workflow-v1", release))?;
    let mut after = -1_i64;
    loop {
        let mut query = connection.prepare("SELECT ordinal,request,status,started,recovery,result FROM release_steps WHERE execution=?1 AND ordinal>?2 ORDER BY ordinal LIMIT 100")?;
        let rows = query
            .query_map(params![execution.as_str(), after], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, bool>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (_, request, status, started, recovery, result) in &rows {
            let step: crate::release_execution::StepRequest = serde_json::from_str(request)?;
            if step.operation != crate::release_execution::ReleaseOperation::PrepareDeployment {
                continue;
            }
            require(
                !started && !recovery && status != "ambiguous",
                RuntimeSecretRejection::UnsettledEffects,
            )?;
            if let Some(result) = result {
                let result: crate::release_execution::ReleaseEffectResult =
                    serde_json::from_str(result)?;
                require(
                    !matches!(
                        result,
                        crate::release_execution::ReleaseEffectResult::Observed(observation)
                            if matches!(observation.outcome, crate::release_execution::ReleaseObserved::DeploymentPrepared { .. })
                    ),
                    RuntimeSecretRejection::UnsettledEffects,
                )?;
            }
        }
        if rows.len() < 100 {
            break;
        }
        after = rows
            .last()
            .context("runtime secret deployment history page")?
            .0;
    }
    Ok(())
}

fn binding_id(target: &ReleaseTarget, reference: &ImmutableSecretRef) -> Result<Digest> {
    Digest::of(&("runtime-secret-binding-v1", target, reference))
}

fn read_resource_optional(
    connection: &Connection,
    resource: &ProviderResource,
) -> Result<Option<StoredResource>> {
    let body = connection
        .query_row(
            "SELECT body FROM runtime_secret_resources WHERE id=?1",
            [resource.id()?.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    body.map(|body| {
        let stored: StoredResource = serde_json::from_str(&body)?;
        ensure!(
            stored.resource == *resource,
            "runtime secret resource identity corruption"
        );
        Ok(stored)
    })
    .transpose()
}

fn read_resource(connection: &Connection, resource: &ProviderResource) -> Result<StoredResource> {
    read_resource_optional(connection, resource)?
        .ok_or_else(|| RuntimeSecretRejection::Unregistered.into())
}

fn read_version_optional(
    connection: &Connection,
    key: &SecretVersionKey,
) -> Result<Option<StoredVersion>> {
    let row = connection
        .query_row(
            "SELECT resource,version,state,body FROM runtime_secret_versions WHERE id=?1",
            [key.id()?.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    row.map(|(resource, version, state, body)| {
        let stored: StoredVersion = serde_json::from_str(&body)?;
        ensure!(
            stored.key == *key
                && resource == key.resource.id()?.as_str()
                && version == key.version.to_string()
                && state == stored.state.as_str()
                && ((stored.state == VersionState::Available) == stored.retirement.is_none()),
            "runtime secret version identity corruption"
        );
        let retirement = connection
            .query_row(
                "SELECT id,body FROM runtime_secret_retirements WHERE version=?1",
                [key.id()?.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        match retirement {
            Some((id, body)) => {
                let retirement: StoredRetirement = serde_json::from_str(&body)?;
                ensure!(
                    stored
                        .retirement
                        .as_ref()
                        .is_some_and(|expected| expected.as_str() == id)
                        && retirement.guard.id.as_str() == id
                        && retirement.guard.key == *key
                        && retirement.guard.state == stored.state
                        && stored.state != VersionState::Available,
                    "runtime secret version barrier corruption"
                );
            }
            None => ensure!(
                stored.state == VersionState::Available && stored.retirement.is_none(),
                "runtime secret version barrier missing"
            ),
        }
        read_resource(connection, &key.resource)?;
        Ok(stored)
    })
    .transpose()
}

fn read_version(connection: &Connection, key: &SecretVersionKey) -> Result<StoredVersion> {
    read_version_optional(connection, key)?
        .ok_or_else(|| RuntimeSecretRejection::Unregistered.into())
}

fn read_binding(
    connection: &Connection,
    target: &ReleaseTarget,
    reference: &ImmutableSecretRef,
) -> Result<StoredBinding> {
    let row = connection
        .query_row(
            "SELECT version,body FROM runtime_secret_bindings WHERE id=?1",
            [binding_id(target, reference)?.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or(RuntimeSecretRejection::Unregistered)?;
    let binding: StoredBinding = serde_json::from_str(&row.1)?;
    ensure!(
        binding.target == *target
            && binding.reference == *reference
            && row.0 == binding.key.id()?.as_str()
            && binding.key.version == reference.version,
        "runtime secret alias identity corruption"
    );
    require(
        read_resource(connection, &binding.key.resource)?.scope == ResourceScope::from(target),
        RuntimeSecretRejection::WrongOwner,
    )?;
    read_version(connection, &binding.key)?;
    Ok(binding)
}

fn read_authority_optional(
    connection: &Connection,
    resource: &ProviderResource,
) -> Result<Option<ResourceAuthority>> {
    let body = connection
        .query_row(
            "SELECT body FROM runtime_secret_authority WHERE resource=?1",
            [resource.id()?.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    body.map(|body| {
        let authority: ResourceAuthority = serde_json::from_str(&body)?;
        ensure!(
            authority.revision != 0
                && authority.scope == read_resource(connection, resource)?.scope,
            "runtime secret authority corruption"
        );
        Ok(authority)
    })
    .transpose()
}

fn audit<T: Serialize>(
    tx: &Transaction<'_>,
    resource: &ProviderResource,
    kind: &str,
    body: &T,
) -> Result<()> {
    tx.execute(
        "INSERT INTO runtime_secret_events(resource,kind,body) VALUES(?1,?2,?3)",
        params![resource.id()?.as_str(), kind, serde_json::to_string(body)?],
    )?;
    Ok(())
}
