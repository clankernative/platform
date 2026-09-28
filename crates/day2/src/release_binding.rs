//! Read-only serving fence for release-managed imported queries.
//!
//! The release journal remains the only selector. An imported query must reach
//! the activated app artifact selected there, under the authority revision
//! observed at dispatch. Neither the instance's desired artifact nor a matching
//! exported contract is evidence that this process serves the selected release.

use crate::{artifact::Instance, authority_state, store::Runtime};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
struct Target {
    company: String,
    environment: String,
    app: String,
}

#[derive(Deserialize)]
struct Receipt {
    id: Digest,
    target: Target,
    release: Digest,
    generation: u64,
    artifact: Digest,
    readiness: Digest,
}

#[derive(Deserialize)]
struct StoredApproval {
    approval: Approval,
    generation: u64,
}

#[derive(Deserialize)]
struct Approval {
    target: Target,
    artifact: Digest,
}

pub(crate) struct Fence {
    journal: PathBuf,
    caller: Target,
    callee: Target,
    caller_release: Digest,
    callee_release: Digest,
    callee_stamp: authority_state::AuthorityStamp,
    callee_document: Digest,
}

impl Fence {
    pub(crate) fn begin(caller: &Runtime, callee: &Runtime) -> Result<Self> {
        let instance = Instance::load(caller.instance_path())?;
        let control = instance
            .control
            .context("delegated_release_binding_unavailable")?;
        let journal = PathBuf::from(control.state_directory).join("build-journal.sqlite");
        let caller_target = Target {
            company: instance.installation.clone(),
            environment: instance.environment.clone(),
            app: caller.app().to_owned(),
        };
        let callee_target = Target {
            app: callee.app().to_owned(),
            ..caller_target.clone()
        };
        let mut connection = open_journal(&journal)?;
        let tx = connection.transaction()?;
        let caller_receipt = selected(&tx, &caller_target)?;
        let callee_receipt = selected(&tx, &callee_target)?;
        tx.commit()?;
        ensure!(
            caller_receipt.artifact.as_str() == caller.artifact().id()
                && callee_receipt.artifact.as_str() == callee.artifact().id(),
            "delegated_serving_artifact_changed"
        );
        let active = active_callee(callee)?;
        let fence = Self {
            journal,
            caller: caller_target,
            callee: callee_target,
            caller_release: caller_receipt.id,
            callee_release: callee_receipt.id,
            callee_stamp: active.stamp,
            callee_document: Digest::of(&active.document)?,
        };
        fence.check(caller, callee)?;
        Ok(fence)
    }

    pub(crate) fn check(&self, caller: &Runtime, callee: &Runtime) -> Result<()> {
        let mut connection = open_journal(&self.journal)?;
        let tx = connection.transaction()?;
        let caller_receipt = selected(&tx, &self.caller)?;
        let callee_receipt = selected(&tx, &self.callee)?;
        tx.commit()?;
        ensure!(
            caller_receipt.id == self.caller_release
                && callee_receipt.id == self.callee_release
                && caller_receipt.artifact.as_str() == caller.artifact().id()
                && callee_receipt.artifact.as_str() == callee.artifact().id(),
            "delegated_serving_binding_changed"
        );
        let active = active_callee(callee)?;
        ensure!(
            active.stamp == self.callee_stamp
                && Digest::of(&active.document)? == self.callee_document,
            "delegated_authority_revision_changed"
        );
        Ok(())
    }
}

fn open_journal(path: &PathBuf) -> Result<Connection> {
    ensure!(path.is_file(), "delegated_release_binding_unavailable");
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.busy_timeout(std::time::Duration::from_secs(2))?;
    Ok(connection)
}

fn selected(connection: &Connection, target: &Target) -> Result<Receipt> {
    let key = serde_json::to_string(target)?;
    let (generation, body): (i64, String) = connection
        .query_row(
            "SELECT generation,active FROM release_slots WHERE target=?1 AND active IS NOT NULL",
            [key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .context("delegated_release_not_selected")?;
    let receipt: Receipt = serde_json::from_str(&body)?;
    ensure!(
        receipt.target == *target && receipt.generation <= u64::try_from(generation)?,
        "delegated_release_selection_changed"
    );
    ensure!(
        receipt.id
            == Digest::of(&(
                "day2-release-activation-v1",
                &receipt.release,
                &receipt.readiness
            ))?,
        "delegated_release_receipt_changed"
    );
    let immutable: Option<String> = connection
        .query_row(
            "SELECT body FROM release_activations WHERE release=?1",
            [receipt.release.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    ensure!(
        immutable.as_deref() == Some(body.as_str()),
        "delegated_release_activation_changed"
    );
    let approval: String = connection.query_row(
        "SELECT body FROM release_approvals WHERE id=?1",
        [receipt.release.as_str()],
        |row| row.get(0),
    )?;
    let approval: StoredApproval = serde_json::from_str(&approval)?;
    ensure!(
        approval.approval.target == *target
            && approval.approval.artifact == receipt.artifact
            && approval.generation == receipt.generation,
        "delegated_release_approval_changed"
    );
    Ok(receipt)
}

fn active_callee(runtime: &Runtime) -> Result<authority_state::ActiveAuthority> {
    let connection = Connection::open_with_flags(runtime.db(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let active = authority_state::current(&connection)?;
    ensure!(
        active.artifact_id == runtime.artifact().id()
            && std::path::Path::new(&active.artifact_path) == runtime.artifact().directory(),
        "delegated_activated_artifact_changed"
    );
    Ok(active)
}
