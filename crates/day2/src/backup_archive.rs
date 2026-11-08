//! Canonical historical backup graph metadata and SQLite/artifact consistency.
//! These checks return historical DATA only. They never supply native restore
//! authentication, a current epoch, exclusion, key custody or a writer.
use crate::{
    artifact::{Instance, LoadedArtifact},
    authority_state,
};
use anyhow::{Result, ensure};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub scope: String,
    pub artifact: String,
    pub database: String,
    /// Reviewed local provider stores, omitted when the snapshot has none.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_databases: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollout_artifacts: Option<String>,
    /// Additional durable companion state, keyed by its path beneath `.state`.
    pub companion_state: BTreeMap<String, String>,
    pub app: String,
    pub authority: authority_state::AuthorityStamp,
    #[serde(default)]
    pub resources: authority_state::ResolvedResources,
    pub instance: Instance,
}

impl Manifest {
    /// Semantic metadata commitment, distinct from full captured archive bytes
    /// and inventory. This is historical identity, never execution authority.
    pub fn security_restore_digest(&self) -> Result<day2_capabilities::Digest> {
        day2_capabilities::Digest::of(&("day2-security-backup-v1", self))
    }
}

impl Manifest {
    /// Canonical bundled-artifact selection, shared by ordinary verification
    /// and the native receiver's separately owned bounded capture.
    pub fn artifact_relative(&self) -> Result<String> {
        ensure!(
            self.format == 3
                && self.instance.apps.len() == 1
                && self.instance.scope(&self.app)? == self.scope,
            "invalid backup scope"
        );
        let relative = format!("artifacts/{}", day2_assets::hash_part(&self.artifact)?);
        ensure!(
            self.instance.branding.is_none() && self.instance.apps[&self.app].artifact == relative,
            "backup instance must refer to its bundled artifact"
        );
        Ok(relative)
    }
}

/// Validate the same actual SQLite snapshot and admitted artifact against its
/// manifest. Callers remain responsible for the complete graph and exact file
/// bytes. Success is historical consistency, never native execution authority.
/// This installs no progress hook and never replaces its caller's SQL limits.
pub fn verify_snapshot(
    manifest: &Manifest,
    artifact: &LoadedArtifact,
    db: &mut Connection,
) -> Result<authority_state::ActiveAuthority> {
    manifest.artifact_relative()?;
    ensure!(
        artifact.id() == manifest.artifact,
        "backup artifact mismatch"
    );
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    ensure!(
        integrity == "ok",
        "backup database failed SQLite integrity check"
    );
    crate::store::validate_storage_snapshot(db, artifact, &manifest.scope)?;
    let active = authority_state::current(db)?;
    let binding = &manifest.instance.apps[&manifest.app];
    ensure!(
        active.stamp == manifest.authority
            && active.artifact_id == manifest.artifact
            && active.document.readers == binding.readers
            && active.document.writers == binding.writers
            && active.document.policy == binding.authority
            && active.document.resources == manifest.resources,
        "backup authority snapshot mismatch"
    );
    Ok(active)
}

/// Exact handled artifact members. Blob names come from the same catalog
/// helpers used by artifact admission, so capture cannot silently keep an
/// uncommitted extra executable or skip a declared resource.
pub(crate) fn artifact_files(artifact: &LoadedArtifact) -> Result<BTreeSet<PathBuf>> {
    artifact.require_current_api()?;
    let contract = artifact.contract();
    let mut files = BTreeSet::from([
        PathBuf::from("artifact.json"),
        PathBuf::from("worker"),
        PathBuf::from("checked-types.json"),
        PathBuf::from(crate::identity::REGISTRY_FILE),
    ]);
    for asset in contract.assets.values() {
        files.insert(
            PathBuf::from("assets").join(format!("{}.png", day2_assets::hash_part(&asset.digest)?)),
        );
    }
    for resource in contract.web_resources.values() {
        files.insert(
            PathBuf::from("web_resources").join(crate::web_resources::blob_name(resource)?),
        );
    }
    for template in contract.templates.values() {
        files.insert(
            PathBuf::from("web_templates").join(crate::web_templates::blob_name(template)?),
        );
    }
    for download in contract.public_downloads.values() {
        files.insert(
            PathBuf::from(crate::public_downloads::SOURCE_DIRECTORY)
                .join(crate::public_downloads::blob_name(download)?),
        );
    }
    Ok(files)
}
