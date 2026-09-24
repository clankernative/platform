//! Activated company authority. Desired files never authorize running work.
//!
//! Authority updates and business transactions serialize on the same SQLite
//! writer lock. An epoch additionally fences work copied from a restored backup.

use crate::{
    artifact::{AppBinding, Instance, LoadedArtifact, Operation},
    authority::Policy,
    error::Failure,
    store::{Runtime, open},
};
use anyhow::{Context, Result, ensure};
pub use day2_capabilities::resources::ResolvedResources;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityStamp {
    pub epoch: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<crate::security_admission::Requirements>,
    pub enabled: bool,
    pub readers: BTreeSet<String>,
    pub writers: BTreeSet<String>,
    pub auditors: BTreeSet<String>,
    /// Absence is an explicit denial, never an implicit unrestricted policy.
    pub policy: Option<Policy>,
    /// Fully resolved immutable resource authority. Empty means deny all
    /// integration resource use, including on pre-resource authority snapshots.
    #[serde(
        default,
        skip_serializing_if = "day2_capabilities::resources::ResolvedResources::is_empty"
    )]
    pub resources: day2_capabilities::resources::ResolvedResources,
}

impl AuthorityDocument {
    pub fn from_binding(binding: &AppBinding) -> Self {
        Self {
            security: binding.security.clone(),
            enabled: true,
            readers: binding.readers.clone(),
            writers: binding.writers.clone(),
            auditors: binding.auditors.clone(),
            policy: binding.authority.clone(),
            resources: Default::default(),
        }
    }

    pub fn resolve(instance: &Instance, app: &str, artifact: &LoadedArtifact) -> Result<Self> {
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis(),
        )?;
        Self::resolve_at(instance, app, artifact, now_ms)
    }

    pub fn resolve_at(
        instance: &Instance,
        app: &str,
        artifact: &LoadedArtifact,
        now_ms: i64,
    ) -> Result<Self> {
        let binding = instance.apps.get(app).context("app_not_installed")?;
        let mut document = Self::from_binding(binding);
        document.resources = match &instance.resources {
            Some(catalog) => catalog.resolve(app, &binding.resource_policies, now_ms)?,
            None => {
                ensure!(
                    binding.resource_policies.is_empty(),
                    "resource_catalog_missing"
                );
                Default::default()
            }
        };
        document.attenuate_resources(&artifact.contract().operations)?;
        document.validate(artifact)?;
        Ok(document)
    }

    // Existing operation and membership policy remains an independent
    // ceiling. Revoking it must not require rewriting a reusable template.
    fn attenuate_resources(&mut self, operations: &[Operation]) -> Result<()> {
        for (name, bindings) in &mut self.resources.operations {
            let operation = operations
                .iter()
                .find(|operation| operation.name == *name)
                .context("resource_operation_missing")?;
            let Some(approved) = self
                .policy
                .as_ref()
                .and_then(|policy| policy.operations.get(name))
            else {
                bindings.clear();
                continue;
            };
            bindings.retain(|_, grant| {
                grant.actors.retain(|actor| {
                    approved.actors.contains(actor)
                        && (self.writers.contains(actor)
                            || (operation.kind == "query" && self.readers.contains(actor)))
                });
                grant.actions.retain(|action| {
                    if action.is_write() {
                        operation.kind == "command"
                            && approved.effects.contains(action.capability())
                    } else {
                        approved.observations.contains(action.capability())
                    }
                });
                !grant.actors.is_empty() && !grant.actions.is_empty()
            });
        }
        self.resources
            .operations
            .retain(|_, bindings| !bindings.is_empty());
        let used: BTreeSet<_> = self
            .resources
            .operations
            .values()
            .flat_map(|bindings| bindings.values())
            .flat_map(|grant| grant.budgets.iter().map(|budget| budget.id.clone()))
            .collect();
        self.resources.budgets.retain(|id, _| used.contains(id));
        Ok(())
    }

    pub fn validate(&self, artifact: &LoadedArtifact) -> Result<()> {
        if let Some(requirements) = &self.security {
            requirements.validate(artifact)?;
        }
        for actor in self
            .readers
            .iter()
            .chain(&self.writers)
            .chain(&self.auditors)
        {
            crate::authority::valid_actor(actor)?;
        }
        if let Some(policy) = &self.policy {
            policy.validate(&artifact.contract().operations, &artifact.contract().schema)?;
        }
        self.resources.validate()?;
        for (name, bindings) in &self.resources.operations {
            let operation = artifact.route(name)?;
            let policy = self
                .policy
                .as_ref()
                .context("resource_grants_require_operation_policy")?;
            let approved = policy
                .operations
                .get(name)
                .context("resource_operation_not_approved")?;
            for grant in bindings.values() {
                ensure!(
                    grant.actors.is_subset(&approved.actors),
                    "resource_actors_exceed_operation_authority"
                );
                ensure!(
                    grant.actors.iter().all(|actor| self.writers.contains(actor)
                        || (operation.kind == "query" && self.readers.contains(actor))),
                    "resource_actors_exceed_membership"
                );
                for action in &grant.actions {
                    ensure!(
                        if action.is_write() {
                            operation.kind == "command"
                                && approved.effects.contains(action.capability())
                        } else {
                            approved.observations.contains(action.capability())
                        },
                        "resource_action_exceeds_operation_authority"
                    );
                }
            }
        }
        Ok(())
    }

    pub fn authorize(&self, operation: &Operation, actor: &str) -> Result<()> {
        ensure!(self.enabled, Failure::Forbidden);
        ensure!(
            self.writers.contains(actor)
                || (operation.kind == "query" && self.readers.contains(actor)),
            Failure::Forbidden
        );
        self.policy
            .as_ref()
            .context("missing_authority_policy")?
            .authorize(&operation.name, actor)
    }

    pub fn authorize_audit(&self, actor: &str) -> Result<()> {
        ensure!(
            self.enabled && self.auditors.contains(actor),
            Failure::Forbidden
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActiveAuthority {
    pub stamp: AuthorityStamp,
    pub document: AuthorityDocument,
    pub artifact_id: String,
    pub artifact_path: String,
}

impl ActiveAuthority {
    pub fn policy(&self) -> Result<&Policy> {
        self.document
            .policy
            .as_ref()
            .context("missing_authority_policy")
    }
}

/// A deliberate assertion made by a trusted local platform operator. This is
/// not production authentication and cannot be constructed by a Roc app.
#[derive(Clone, Debug)]
pub struct LocalOperator {
    name: String,
}

impl LocalOperator {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub fn assert_local(name: &str) -> Result<Self> {
        crate::authority::valid_actor(name)?;
        Ok(Self { name: name.into() })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyAuthority {
    pub request_id: String,
    /// None is permitted only for explicit activation of a legacy database.
    pub expected: Option<AuthorityStamp>,
    pub document: AuthorityDocument,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityReceipt {
    pub stamp: AuthorityStamp,
}

pub(crate) fn upgrade(connection: &Connection) -> Result<()> {
    let existing: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='day2_authority_history')",
        [],
        |row| row.get(0),
    )?;
    let desired_existing: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='day2_authority_desired_requests')",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_authority(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            epoch TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
            document TEXT NOT NULL, artifact_id TEXT NOT NULL, artifact_path TEXT NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_authority_history(
            epoch TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
            document TEXT NOT NULL, artifact_id TEXT NOT NULL, artifact_path TEXT NOT NULL,
            operator TEXT NOT NULL, reason TEXT NOT NULL,
            PRIMARY KEY(epoch,revision)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_authority_requests(
            epoch TEXT NOT NULL, request_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
            receipt TEXT NOT NULL, PRIMARY KEY(epoch,request_id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_authority_desired_requests(
            epoch TEXT NOT NULL, request_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
            receipt TEXT NOT NULL, PRIMARY KEY(epoch,request_id),
            FOREIGN KEY(epoch,request_id) REFERENCES day2_authority_requests(epoch,request_id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_invocation_authority(
            invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id),
            epoch TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_authority_blocks(
            invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id), reason TEXT NOT NULL
        ) STRICT;",
    )?;
    for (table, key, previously_created) in [
        (
            "day2_authority_history",
            "epoch=NEW.epoch AND revision=NEW.revision",
            existing,
        ),
        (
            "day2_authority_requests",
            "epoch=NEW.epoch AND request_id=NEW.request_id",
            existing,
        ),
        (
            "day2_authority_desired_requests",
            "epoch=NEW.epoch AND request_id=NEW.request_id",
            desired_existing,
        ),
    ] {
        for (suffix, action) in [
            ("no_update", format!("BEFORE UPDATE ON {table}")),
            ("no_delete", format!("BEFORE DELETE ON {table}")),
            (
                "no_replace",
                format!("BEFORE INSERT ON {table} WHEN EXISTS(SELECT 1 FROM {table} WHERE {key})"),
            ),
        ] {
            let name = format!("{table}_{suffix}");
            let sql = format!(
                "CREATE TRIGGER {name} {action} BEGIN SELECT RAISE(ABORT,'append_only_authority'); END"
            );
            if !previously_created {
                connection.execute_batch(&sql)?;
            }
            crate::audit::validate_trigger(connection, &name, &sql)?;
        }
    }
    Ok(())
}

pub fn exists(connection: &Connection) -> Result<bool> {
    let table: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='day2_authority')",
        [],
        |row| row.get(0),
    )?;
    if !table {
        return Ok(false);
    }
    Ok(
        connection.query_row("SELECT EXISTS(SELECT 1 FROM day2_authority)", [], |row| {
            row.get(0)
        })?,
    )
}

pub fn current(connection: &Connection) -> Result<ActiveAuthority> {
    ensure!(exists(connection)?, "authority_activation_required");
    let (epoch, revision, document, artifact_id, artifact_path) = connection.query_row(
        "SELECT epoch,revision,document,artifact_id,artifact_path FROM day2_authority WHERE singleton=1",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?)),
    )?;
    ensure!(
        revision > 0
            && epoch
                .strip_prefix("sha256:")
                .is_some_and(|hash| hash.len() == 64
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
        "invalid_authority_stamp"
    );
    Ok(ActiveAuthority {
        stamp: AuthorityStamp {
            epoch,
            revision: u64::try_from(revision)?,
        },
        document: crate::json::decode(document.as_bytes())?,
        artifact_id,
        artifact_path,
    })
}

fn require_transaction(connection: &Connection) -> Result<()> {
    ensure!(
        !connection.is_autocommit(),
        "authority_requires_transaction"
    );
    Ok(())
}

fn scope_matches(connection: &Connection, runtime: &Runtime) -> Result<()> {
    let scope: String =
        connection.query_row("SELECT value FROM day2_meta WHERE key='scope'", [], |row| {
            row.get(0)
        })?;
    ensure!(scope == runtime.scope(), Failure::InstallationChanged);
    Ok(())
}

fn initial(
    runtime: &Runtime,
    document: AuthorityDocument,
    artifact: &LoadedArtifact,
) -> Result<ActiveAuthority> {
    document.validate(artifact)?;
    Ok(ActiveAuthority {
        stamp: AuthorityStamp {
            // Every fresh installation has its own lineage. Simulation supplies
            // a deterministic host before initialization instead of weakening it.
            epoch: crate::digest(
                &runtime
                    .host()
                    .entropy(runtime.scope(), "$authority-bootstrap")?,
            ),
            revision: 1,
        },
        document,
        artifact_id: artifact.id().into(),
        artifact_path: artifact.directory().to_string_lossy().into_owned(),
    })
}

pub(crate) fn initialize_new(
    tx: &Transaction<'_>,
    runtime: &Runtime,
    instance: &Instance,
) -> Result<()> {
    upgrade(tx)?;
    ensure!(!exists(tx)?, "authority_already_initialized");
    let invocations: i64 = tx.query_row("SELECT count(*) FROM day2_invocations", [], |row| {
        row.get(0)
    })?;
    ensure!(invocations == 0, "legacy_authority_requires_activation");
    scope_matches(tx, runtime)?;
    ensure!(
        instance.scope(runtime.app())? == runtime.scope(),
        Failure::InstallationChanged
    );
    store(
        tx,
        &initial(
            runtime,
            AuthorityDocument::resolve_at(
                instance,
                runtime.app(),
                runtime.artifact(),
                runtime.host().now_ms()?,
            )?,
            runtime.artifact(),
        )?,
        "platform-initialize",
        "initialize",
    )
}

fn store(
    connection: &Connection,
    active: &ActiveAuthority,
    operator: &str,
    reason: &str,
) -> Result<()> {
    require_transaction(connection)?;
    crate::budget::initialize_in(connection, &active.stamp.epoch)?;
    crate::budget::sync_definitions_in(connection, &active.document.resources.budgets)?;
    let document = serde_json::to_string(&active.document)?;
    let revision = i64::try_from(active.stamp.revision)?;
    connection.execute(
        "INSERT INTO day2_authority(singleton,epoch,revision,document,artifact_id,artifact_path) VALUES(1,?1,?2,?3,?4,?5)
         ON CONFLICT(singleton) DO UPDATE SET epoch=excluded.epoch,revision=excluded.revision,document=excluded.document,artifact_id=excluded.artifact_id,artifact_path=excluded.artifact_path",
        params![active.stamp.epoch,revision,document,active.artifact_id,active.artifact_path],
    )?;
    connection.execute(
        "INSERT INTO day2_authority_history VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            active.stamp.epoch,
            revision,
            document,
            active.artifact_id,
            active.artifact_path,
            operator,
            reason
        ],
    )?;
    // Blocks persist even when a later document grants the same authority again.
    connection.execute(
        "INSERT OR IGNORE INTO day2_authority_blocks(invocation,reason)
         SELECT i.id,'authority_policy_changed' FROM day2_invocations i
         LEFT JOIN day2_invocation_authority a ON a.invocation=i.id
         WHERE i.status='pending' AND (a.invocation IS NULL OR a.epoch!=?1 OR a.revision!=?2)",
        params![active.stamp.epoch, revision],
    )?;
    release_blocked_cursor_pins(connection)?;
    Ok(())
}

fn release_blocked_cursor_pins(connection: &Connection) -> Result<()> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='day2_selection_cursor_pins')",
        [],
        |row| row.get(0),
    )?;
    if exists {
        connection.execute("DELETE FROM day2_selection_cursor_pins WHERE invocation IN (SELECT invocation FROM day2_authority_blocks)", [])?;
    }
    Ok(())
}

pub(crate) fn authorize_in(
    connection: &Connection,
    runtime: &Runtime,
    operation: &str,
    actor: &str,
) -> Result<ActiveAuthority> {
    require_transaction(connection)?;
    scope_matches(connection, runtime)?;
    runtime.check_binding(connection)?;
    let active = current(connection)?;
    ensure!(
        active.artifact_id == runtime.artifact().id()
            && Path::new(&active.artifact_path) == runtime.artifact().directory(),
        Failure::ArtifactBindingChanged
    );
    active.document.validate(runtime.artifact())?;
    if let Some(requirements) = &active.document.security {
        requirements.require_runtime()?;
    }
    active
        .document
        .authorize(runtime.artifact().route(operation)?, actor)?;
    require_all_rows(active.policy()?, runtime.artifact(), operation, actor)?;
    Ok(active)
}

/// An app may rely on the absence of a row to authorize a decision. Owner-filtered
/// selections cannot establish that absence. Check the declared prerequisite
/// before any app branch executes, using this actor's effective native scope.
/// Authority activation deliberately permits narrowing or removing the grant:
/// revocation still commits, and affected operations are denied here instead.
pub(crate) fn require_all_rows(
    policy: &Policy,
    artifact: &LoadedArtifact,
    operation: &str,
    actor: &str,
) -> Result<()> {
    let operation = artifact.route(operation)?.name.as_str();
    for model in required_all_rows(artifact, operation)? {
        ensure!(
            matches!(
                policy.read_scope(operation, model, actor),
                Ok(crate::authority::RowFilter::All)
            ),
            Failure::RequiredAllRowsUnavailable
        );
    }
    Ok(())
}

pub(crate) fn required_all_rows<'a>(
    artifact: &'a LoadedArtifact,
    operation: &str,
) -> Result<&'a [String]> {
    let operation = artifact.route(operation)?.name.as_str();
    match &artifact.contract().app_contract {
        Some(definition) => Ok(&definition
            .operations
            .get(operation)
            .context("operation_contract_missing")?
            .required_all_rows),
        None => Ok(&[]),
    }
}

pub(crate) fn invocation_stamp(connection: &Connection, id: &str) -> Result<AuthorityStamp> {
    let (epoch, revision) = connection
        .query_row(
            "SELECT epoch,revision FROM day2_invocation_authority WHERE invocation=?1",
            [id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .context(Failure::AuthorityPolicyChanged)?;
    ensure!(revision > 0, "invalid_authority_stamp");
    Ok(AuthorityStamp {
        epoch,
        revision: u64::try_from(revision)?,
    })
}

pub(crate) fn pin_invocation(
    connection: &Connection,
    id: &str,
    stamp: &AuthorityStamp,
) -> Result<()> {
    require_transaction(connection)?;
    ensure!(
        current(connection)?.stamp == *stamp,
        Failure::AuthorityPolicyChanged
    );
    ensure!(
        !is_blocked(connection, id)?,
        Failure::AuthorityPolicyChanged
    );
    connection.execute(
        "INSERT OR IGNORE INTO day2_invocation_authority VALUES(?1,?2,?3)",
        params![id, stamp.epoch, i64::try_from(stamp.revision)?],
    )?;
    ensure!(
        invocation_stamp(connection, id)? == *stamp,
        Failure::AuthorityPolicyChanged
    );
    Ok(())
}

pub(crate) fn is_blocked(connection: &Connection, id: &str) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_authority_blocks WHERE invocation=?1)",
        [id],
        |row| row.get(0),
    )?)
}

pub(crate) fn block_invocation(connection: &Connection, id: &str, reason: &str) -> Result<()> {
    require_transaction(connection)?;
    connection.execute(
        "INSERT OR IGNORE INTO day2_authority_blocks VALUES(?1,?2)",
        params![id, reason],
    )?;
    release_blocked_cursor_pins(connection)?;
    Ok(())
}

pub(crate) fn require_invocation_in(
    connection: &Connection,
    runtime: &Runtime,
    id: &str,
    operation: &str,
    actor: &str,
) -> Result<ActiveAuthority> {
    require_transaction(connection)?;
    let active = current(connection)?;
    ensure!(
        invocation_stamp(connection, id)? == active.stamp && !is_blocked(connection, id)?,
        Failure::AuthorityPolicyChanged
    );
    authorize_in(connection, runtime, operation, actor)
}

pub fn apply(
    runtime: &Runtime,
    operator: &LocalOperator,
    change: &ApplyAuthority,
) -> Result<AuthorityReceipt> {
    let mut connection = open(runtime.db())?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    upgrade(&tx)?;
    scope_matches(&tx, runtime)?;
    if let Some(receipt) = cached_policy_receipt_in(&tx, operator, change)? {
        return Ok(receipt);
    }
    let receipt = apply_binding_in(&tx, runtime, runtime.artifact(), operator, change)?;
    tx.commit()?;
    Ok(receipt)
}

/// Policy-only retries retain the artifact that was active at the supplied
/// revision, even if an artifact upgrade committed before the caller retried.
/// Deriving it from the expected revision also rejects reuse of an artifact
/// activation request that explicitly selected a different target.
fn cached_policy_receipt_in(
    connection: &Connection,
    operator: &LocalOperator,
    change: &ApplyAuthority,
) -> Result<Option<AuthorityReceipt>> {
    require_transaction(connection)?;
    if !exists(connection)? {
        return Ok(None);
    }
    let epoch = current(connection)?.stamp.epoch;
    let cached: Option<(String, String)> = connection.query_row(
        "SELECT fingerprint,receipt FROM day2_authority_requests WHERE epoch=?1 AND request_id=?2",
        params![epoch,change.request_id], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional()?;
    let Some((fingerprint, receipt)) = cached else {
        return Ok(None);
    };
    let receipt: AuthorityReceipt = crate::json::decode(receipt.as_bytes())?;
    ensure!(
        receipt.stamp.epoch == epoch,
        "authority_receipt_epoch_mismatch"
    );
    // The initial legacy activation has no predecessor; its own history row
    // records the one binding that request originally approved.
    let binding_stamp = change.expected.as_ref().unwrap_or(&receipt.stamp);
    let (artifact_id, artifact_path): (String, String) = connection.query_row(
        "SELECT artifact_id,artifact_path FROM day2_authority_history WHERE epoch=?1 AND revision=?2",
        params![binding_stamp.epoch,i64::try_from(binding_stamp.revision)?],
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional()?.context(Failure::IdempotencyKeyConflict)?;
    ensure!(
        fingerprint == activation_fingerprint(operator, change, &artifact_id, &artifact_path)?,
        Failure::IdempotencyKeyConflict
    );
    Ok(Some(receipt))
}

pub fn apply_desired(
    runtime: &Runtime,
    operator: &LocalOperator,
    request_id: &str,
    expected: Option<AuthorityStamp>,
) -> Result<AuthorityReceipt> {
    let instance = Instance::load(runtime.instance_path())?;
    ensure!(
        instance.scope(runtime.app())? == runtime.scope(),
        Failure::InstallationChanged
    );
    let source = desired_fingerprint(&instance, runtime.app(), operator, &expected, None)?;
    let mut connection = open(runtime.db())?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    upgrade(&tx)?;
    scope_matches(&tx, runtime)?;
    if let Some(receipt) = cached_desired_receipt_in(&tx, request_id, &source)? {
        return Ok(receipt);
    }
    let change = ApplyAuthority {
        request_id: request_id.into(),
        expected,
        document: AuthorityDocument::resolve_at(
            &instance,
            runtime.app(),
            runtime.artifact(),
            runtime.host().now_ms()?,
        )?,
    };
    let receipt = match cached_policy_receipt_in(&tx, operator, &change)? {
        Some(receipt) => receipt,
        None => apply_binding_in(&tx, runtime, runtime.artifact(), operator, &change)?,
    };
    pin_desired_receipt_in(&tx, request_id, &source, &receipt)?;
    tx.commit()?;
    Ok(receipt)
}

/// Pins the exact authoring inputs independently from time-sensitive resolution.
/// A completed request can therefore return its original receipt after expiry
/// or a later artifact upgrade without activating or resolving anything again.
pub(crate) fn desired_fingerprint(
    instance: &Instance,
    app: &str,
    operator: &LocalOperator,
    expected: &Option<AuthorityStamp>,
    target: Option<&LoadedArtifact>,
) -> Result<String> {
    let binding = instance.apps.get(app).context("app_not_installed")?;
    let selected = instance
        .resources
        .as_ref()
        .filter(|_| !binding.resource_policies.is_empty())
        .map(|catalog| {
            let mut catalog = catalog.clone();
            let policies: BTreeSet<_> = binding
                .resource_policies
                .iter()
                .map(|attachment| attachment.policy.id.clone())
                .collect();
            catalog.policies.retain(|id, _| policies.contains(id));
            let resources: BTreeSet<_> = catalog
                .policies
                .values()
                .flat_map(|policy| policy.slots.values())
                .flat_map(|slot| {
                    slot.allowed_resources
                        .iter()
                        .map(|reference| reference.id.clone())
                })
                .chain(binding.resource_policies.iter().flat_map(|attachment| {
                    attachment
                        .bindings
                        .values()
                        .map(|reference| reference.id.clone())
                }))
                .collect();
            catalog.resources.retain(|id, _| resources.contains(id));
            let connections: BTreeSet<_> = catalog
                .resources
                .values()
                .map(|resource| resource.connection.id.clone())
                .collect();
            catalog.connections.retain(|id, _| connections.contains(id));
            let budgets: BTreeSet<_> = catalog
                .policies
                .values()
                .flat_map(|policy| policy.slots.values())
                .flat_map(|slot| slot.budgets.iter().map(|reference| reference.id.clone()))
                .collect();
            catalog.budgets.retain(|id, _| budgets.contains(id));
            catalog
        });
    Ok(crate::digest(&serde_json::to_vec(&(
        "day2-desired-authority-request-v1",
        instance.scope(app)?,
        &operator.name,
        expected,
        AuthorityDocument::from_binding(binding),
        &binding.resource_policies,
        selected,
        target.map(|target| (target.id(), target.directory())),
    ))?))
}

pub(crate) fn cached_desired_receipt_in(
    connection: &Connection,
    request_id: &str,
    fingerprint: &str,
) -> Result<Option<AuthorityReceipt>> {
    require_transaction(connection)?;
    if !exists(connection)? {
        return Ok(None);
    }
    let epoch = current(connection)?.stamp.epoch;
    let cached: Option<(String, String, String)> = connection
        .query_row(
            "SELECT d.fingerprint,d.receipt,r.receipt FROM day2_authority_desired_requests d
         JOIN day2_authority_requests r ON r.epoch=d.epoch AND r.request_id=d.request_id
         WHERE d.epoch=?1 AND d.request_id=?2",
            params![epoch, request_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((saved, receipt, activated)) = cached else {
        return Ok(None);
    };
    ensure!(saved == fingerprint, Failure::IdempotencyKeyConflict);
    ensure!(receipt == activated, "authority_desired_receipt_mismatch");
    let receipt: AuthorityReceipt = crate::json::decode(receipt.as_bytes())?;
    ensure!(
        receipt.stamp.epoch == epoch,
        "authority_receipt_epoch_mismatch"
    );
    Ok(Some(receipt))
}

pub(crate) fn pin_desired_receipt_in(
    connection: &Connection,
    request_id: &str,
    fingerprint: &str,
    receipt: &AuthorityReceipt,
) -> Result<()> {
    require_transaction(connection)?;
    if let Some(previous) = cached_desired_receipt_in(connection, request_id, fingerprint)? {
        ensure!(previous == *receipt, "authority_desired_receipt_mismatch");
        return Ok(());
    }
    let encoded = serde_json::to_string(receipt)?;
    let activated: String = connection.query_row(
        "SELECT receipt FROM day2_authority_requests WHERE epoch=?1 AND request_id=?2",
        params![receipt.stamp.epoch, request_id],
        |row| row.get(0),
    )?;
    ensure!(
        encoded == activated && receipt.stamp.epoch == current(connection)?.stamp.epoch,
        "authority_desired_receipt_mismatch"
    );
    connection.execute(
        "INSERT INTO day2_authority_desired_requests VALUES(?1,?2,?3,?4)",
        params![receipt.stamp.epoch, request_id, fingerprint, encoded],
    )?;
    Ok(())
}

pub(crate) fn apply_binding_in(
    connection: &Connection,
    runtime: &Runtime,
    target: &LoadedArtifact,
    operator: &LocalOperator,
    change: &ApplyAuthority,
) -> Result<AuthorityReceipt> {
    require_transaction(connection)?;
    upgrade(connection)?;
    scope_matches(connection, runtime)?;
    ensure!(
        !change.request_id.is_empty()
            && change.request_id.len() <= 128
            && change
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
        "invalid_authority_request_id"
    );
    target.require_current_api()?;
    change.document.validate(target)?;
    if let Some(receipt) = activation_receipt_in(connection, target, operator, change)? {
        return Ok(receipt);
    }
    let schema: String = connection.query_row(
        "SELECT value FROM day2_meta WHERE key='schema'",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        schema == target.contract().schema_digest,
        "schema_migration_required"
    );
    let next = if exists(connection)? {
        ActiveAuthority {
            stamp: current(connection)?.stamp,
            document: change.document.clone(),
            artifact_id: target.id().into(),
            artifact_path: target.directory().to_string_lossy().into_owned(),
        }
    } else {
        initial(runtime, change.document.clone(), target)?
    };
    apply_transition_in(
        connection,
        operator,
        change,
        (runtime.artifact().id(), runtime.artifact().directory()),
        next,
    )
}

pub(crate) fn activation_receipt_in(
    connection: &Connection,
    target: &LoadedArtifact,
    operator: &LocalOperator,
    change: &ApplyAuthority,
) -> Result<Option<AuthorityReceipt>> {
    require_transaction(connection)?;
    if !exists(connection)? {
        return Ok(None);
    }
    let epoch = current(connection)?.stamp.epoch;
    let fingerprint = activation_fingerprint(
        operator,
        change,
        target.id(),
        &target.directory().to_string_lossy(),
    )?;
    cached_receipt(connection, &epoch, &change.request_id, &fingerprint)
}

fn activation_fingerprint(
    operator: &LocalOperator,
    change: &ApplyAuthority,
    artifact_id: &str,
    artifact_path: &str,
) -> Result<String> {
    Ok(crate::digest(&serde_json::to_vec(&(
        &operator.name,
        &change.expected,
        &change.document,
        artifact_id,
        artifact_path,
    ))?))
}

fn cached_receipt(
    connection: &Connection,
    epoch: &str,
    request_id: &str,
    fingerprint: &str,
) -> Result<Option<AuthorityReceipt>> {
    let cached: Option<(String, String)> = connection.query_row(
        "SELECT fingerprint,receipt FROM day2_authority_requests WHERE epoch=?1 AND request_id=?2",
        params![epoch,request_id], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional()?;
    if let Some((prior_fingerprint, receipt)) = cached {
        ensure!(
            prior_fingerprint == fingerprint,
            Failure::IdempotencyKeyConflict
        );
        return Ok(Some(crate::json::decode(receipt.as_bytes())?));
    }
    Ok(None)
}

/// The caller has validated the target contract and schema under its writer
/// transaction. Keep compare-and-swap, receipts and publication indivisible.
fn apply_transition_in(
    connection: &Connection,
    operator: &LocalOperator,
    change: &ApplyAuthority,
    source: (&str, &Path),
    mut next: ActiveAuthority,
) -> Result<AuthorityReceipt> {
    require_transaction(connection)?;
    let previous = if exists(connection)? {
        Some(current(connection)?)
    } else {
        None
    };
    if let Some(previous) = &previous {
        next.stamp = previous.stamp.clone();
    }
    let fingerprint =
        activation_fingerprint(operator, change, &next.artifact_id, &next.artifact_path)?;
    if let Some(receipt) = cached_receipt(
        connection,
        &next.stamp.epoch,
        &change.request_id,
        &fingerprint,
    )? {
        return Ok(receipt);
    }
    ensure!(
        previous.as_ref().map(|active| &active.stamp) == change.expected.as_ref(),
        Failure::AuthorityPolicyChanged
    );
    if let Some(previous) = previous {
        ensure!(
            previous.artifact_id == source.0 && Path::new(&previous.artifact_path) == source.1,
            Failure::ArtifactBindingChanged
        );
        next.stamp.revision = previous
            .stamp
            .revision
            .checked_add(1)
            .context("authority_revision_exhausted")?;
        i64::try_from(next.stamp.revision).context("authority_revision_exhausted")?;
    }
    next.document = change.document.clone();
    store(connection, &next, &operator.name, "activate")?;
    let receipt = AuthorityReceipt {
        stamp: next.stamp.clone(),
    };
    connection.execute(
        "INSERT INTO day2_authority_requests VALUES(?1,?2,?3,?4)",
        params![
            next.stamp.epoch,
            change.request_id,
            fingerprint,
            serde_json::to_string(&receipt)?
        ],
    )?;
    Ok(receipt)
}

/// Restores never resurrect the authority or pending work held by a backup.
/// The caller relocates the verified artifact and commits this fence atomically.
pub fn invalidate_restored(connection: &Connection, artifact_path: &Path) -> Result<()> {
    require_transaction(connection)?;
    upgrade(connection)?;
    if !exists(connection)? {
        return Ok(());
    }
    let active = current(connection)?;
    let relocated = LoadedArtifact::load(artifact_path)?;
    ensure!(
        relocated.id() == active.artifact_id,
        "restore_artifact_mismatch"
    );
    fence_restored_in(connection, active, relocated.directory())
}

fn fence_restored_in(
    connection: &Connection,
    mut active: ActiveAuthority,
    relocated: &Path,
) -> Result<()> {
    require_transaction(connection)?;
    crate::budget::invalidate_restored(connection)?;
    let mut entropy = [0_u8; 32];
    getrandom::fill(&mut entropy)
        .map_err(|error| anyhow::anyhow!("authority restore entropy: {error}"))?;
    active.stamp.epoch = crate::digest(&entropy);
    active.stamp.revision = active
        .stamp
        .revision
        .checked_add(1)
        .context("authority_revision_exhausted")?;
    active.document.enabled = false;
    active.artifact_path = relocated.to_string_lossy().into_owned();
    store(connection, &active, "platform-restore", "restore-fence")
}

#[cfg(test)]
#[path = "authority_state_tests.rs"]
mod tests;
