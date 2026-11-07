//! App owners are the admins of active authority, not a second owner registry.
//! Mutations are trusted local operator operations; owner checks confer no
//! installation/provider authority and must share the protected read transaction.
use crate::{
    artifact::Instance,
    authority_state::{self, ApplyAuthority, AuthorityReceipt, AuthorityStamp, LocalOperator},
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Permission {
    #[serde(rename = "audit.read")]
    AuditRead,
    #[serde(rename = "secrets.list")]
    SecretsList,
    #[serde(rename = "secrets.read")]
    SecretsRead,
    #[serde(rename = "secrets.create")]
    SecretsCreate,
    #[serde(rename = "secrets.rotate")]
    SecretsRotate,
    #[serde(rename = "sqlite.download")]
    SqliteDownload,
}

pub const PERMISSIONS: [Permission; 6] = [
    Permission::AuditRead,
    Permission::SecretsList,
    Permission::SecretsRead,
    Permission::SecretsCreate,
    Permission::SecretsRotate,
    Permission::SqliteDownload,
];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Add,
    Remove,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub owner: String,
    pub expected: AuthorityStamp,
    pub request_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub stamp: AuthorityStamp,
    pub enabled: bool,
    pub owners: BTreeSet<String>,
    pub desired_owners: BTreeSet<String>,
    pub desired_matches_active: bool,
    pub permissions: [Permission; 6],
}

fn operator_instance(runtime: &Runtime, operator: &LocalOperator) -> Result<Instance> {
    let instance = Instance::load(runtime.instance_path())?;
    ensure!(
        instance.scope(runtime.app())? == runtime.scope(),
        "installation_changed"
    );
    ensure!(
        instance
            .control
            .as_ref()
            .is_some_and(|control| control.operators.contains(operator.name())),
        "owner_management_operator_required"
    );
    Ok(instance)
}

fn active_in(
    connection: &Connection,
    runtime: &Runtime,
) -> Result<authority_state::ActiveAuthority> {
    ensure!(
        !connection.is_autocommit(),
        "owner_check_requires_transaction"
    );
    authority_state::scope_matches(connection, runtime)?;
    runtime.check_binding(connection)?;
    let active = authority_state::current(connection)?;
    ensure!(
        active.artifact_id == runtime.artifact().id()
            && Path::new(&active.artifact_path) == runtime.artifact().directory(),
        "artifact_binding_changed"
    );
    ensure!(
        active.document.hosted_domain.is_none()
            || active.document.hosted_domain.as_deref() == runtime.hosted_domain(),
        "installation_changed"
    );
    active.document.validate(runtime.artifact())?;
    Ok(active)
}

/// Check the current owner in the same transaction that will read protected
/// values. A returned stamp is descriptive, never a reusable authorization token.
/// No secret-read or snapshot-export implementation is installed by this guard.
pub fn authorize_in(
    connection: &Connection,
    runtime: &Runtime,
    actor: &str,
    _permission: Permission,
) -> Result<AuthorityStamp> {
    let active = active_in(connection, runtime)?;
    if let Some(requirements) = &active.document.security {
        requirements.require_runtime()?;
    }
    active.document.authorize_audit(actor)?;
    Ok(active.stamp)
}

pub fn inspect(runtime: &Runtime, operator: &LocalOperator) -> Result<Inspection> {
    let instance = operator_instance(runtime, operator)?;
    runtime.sql_read(|tx| {
        let active = active_in(tx, runtime)?;
        let owners = active.policy()?.admins.clone();
        ensure!(owners.len() <= 512, "owner_count_budget");
        let desired_owners = instance
            .apps
            .get(runtime.app())
            .and_then(|app| app.authority.as_ref())
            .map(|policy| policy.admins.clone())
            .unwrap_or_default();
        ensure!(desired_owners.len() <= 512, "owner_count_budget");
        Ok(Inspection {
            stamp: active.stamp,
            enabled: active.document.enabled,
            desired_matches_active: owners == desired_owners,
            owners,
            desired_owners,
            permissions: PERMISSIONS,
        })
    })
}

/// Local operator diagnostic only. The actor string is not remote authentication.
pub fn check(
    runtime: &Runtime,
    operator: &LocalOperator,
    actor: &str,
    permission: Permission,
) -> Result<bool> {
    operator_instance(runtime, operator)?;
    crate::authority::valid_actor(actor)?;
    runtime.sql_read(|tx| {
        let active = active_in(tx, runtime)?;
        if !active.document.enabled || !active.policy()?.admins.contains(actor) {
            return Ok(false);
        }
        authorize_in(tx, runtime, actor, permission)?;
        Ok(true)
    })
}

fn changed_document(
    original: &authority_state::AuthorityDocument,
    operation: Operation,
    owner: &str,
) -> Result<authority_state::AuthorityDocument> {
    crate::authority::valid_actor(owner)?;
    ensure!(
        !owner.contains(':')
            && !owner.starts_with("client/")
            && !owner.ends_with(".gserviceaccount.com"),
        "owner_must_be_an_individual"
    );
    ensure!(original.enabled, "owner_management_app_disabled");
    let mut document = original.clone();
    let policy = document
        .policy
        .as_mut()
        .context("missing_authority_policy")?;
    ensure!(policy.admins.len() <= 512, "owner_count_budget");
    match operation {
        Operation::Add => {
            if let Some(domain) = &document.hosted_domain {
                ensure!(
                    crate::authority::in_domain(owner, domain),
                    "owner_must_belong_to_verified_domain"
                );
            }
            ensure!(policy.admins.len() < 512, "owner_count_budget");
            ensure!(policy.admins.insert(owner.into()), "already_an_owner");
        }
        Operation::Remove => {
            ensure!(policy.admins.remove(owner), "not_an_owner");
            ensure!(!policy.admins.is_empty(), "cannot_remove_last_owner");
        }
    }
    Ok(document)
}

/// Change only active policy admins. Desired files, memberships, resource grants,
/// app operations, enabled state and artifact identity are never activated here.
pub fn change(
    runtime: &Runtime,
    operator: &LocalOperator,
    operation: Operation,
    change: &Change,
) -> Result<AuthorityReceipt> {
    operator_instance(runtime, operator)?;
    let revision = i64::try_from(change.expected.revision)?;
    // Reconstruct the exact change from immutable history, including on a retry
    // after later revocation. The operator activation below owns the writer
    // transaction and compares the expected stamp before any new commit. Never
    // run its schema/authority maintenance inside ordinary runtime SQL guards.
    let document = runtime.sql_read(|tx| {
        active_in(tx, runtime)?;
        let raw: String = tx
            .query_row(
                "SELECT document FROM day2_authority_history WHERE epoch=?1 AND revision=?2",
                rusqlite::params![change.expected.epoch, revision],
                |row| row.get(0),
            )
            .context("expected_owner_authority_not_found")?;
        let original = crate::json::decode(raw.as_bytes())?;
        changed_document(&original, operation, &change.owner)
    })?;
    authority_state::apply(
        runtime,
        operator,
        &ApplyAuthority {
            request_id: change.request_id.clone(),
            expected: Some(change.expected.clone()),
            document,
        },
    )
}
