//! Host-only managed credential primitives. App code cannot import this module.
pub(crate) mod crypto;
pub(crate) mod store;

use crate::{
    authority_state::{self, ActiveAuthority},
    store::{Runtime, open},
    web_security::{self, Session},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::credentials::{
    CollectionPage, Inspection, LineageRef, ListFailure, ListRequest, ManifestFamily, Summary,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn session_time() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

/// Use only the current activated selection and authenticated session. The
/// private reader applies creator visibility in SQL before its page bound.
pub(crate) fn metadata_read<'a>(
    app: &str,
    scope: &str,
    artifact_id: &str,
    manifest: &'a [ManifestFamily],
    active: &'a ActiveAuthority,
    session: &'a Session,
    family: &str,
) -> Result<store::MetadataRead<'a>> {
    ensure!(active.document.enabled, "credential authority disabled");
    ensure!(
        active.artifact_id == artifact_id,
        "credential artifact is not active"
    );
    let declared: &ManifestFamily = manifest
        .iter()
        .find(|candidate| candidate.id.as_str() == family)
        .context("credential family not declared")?;
    let selected = active
        .document
        .credentials
        .get(family)
        .context("credential family not active")?;
    let namespace = &selected.binding.namespace;
    ensure!(
        namespace.app.as_str() == app
            && format!(
                "{}/{}/{}",
                namespace.installation.as_str(),
                namespace.environment.as_str(),
                namespace.app.as_str()
            ) == scope,
        "credential family is outside app scope"
    );
    Ok(store::MetadataRead {
        namespace,
        family: declared,
        policy: &selected.management,
        requester: &session.actor,
    })
}

impl Runtime {
    /// Host-only metadata read for a direct, still-live browser session. This
    /// does not create a public route or a credential lifecycle instruction.
    pub fn credential_metadata_page(
        &self,
        family: &str,
        session_token: &str,
        request: &ListRequest,
    ) -> Result<std::result::Result<CollectionPage<Summary>, ListFailure>> {
        let mut db = open(self.db())?;
        let tx = db.transaction()?;
        self.check_binding(&tx)?;
        let session = web_security::session_for_token_in(&tx, session_token, session_time()?)?;
        let active = authority_state::current(&tx)?;
        active.document.validate(self.artifact())?;
        let read = metadata_read(
            self.app(),
            self.scope(),
            self.artifact().id(),
            &self.artifact().contract().credential_manifest,
            &active,
            &session,
            family,
        )?;
        let result = store::list_metadata(&tx, &read, request)?;
        tx.commit()?;
        Ok(result)
    }

    /// An unknown lineage and one outside the session's visibility are both
    /// absent. The activated family and live session share one database read.
    pub fn credential_metadata_inspection(
        &self,
        family: &str,
        session_token: &str,
        lineage: &LineageRef,
    ) -> Result<Option<Inspection>> {
        let mut db = open(self.db())?;
        let tx = db.transaction()?;
        self.check_binding(&tx)?;
        let session = web_security::session_for_token_in(&tx, session_token, session_time()?)?;
        let active = authority_state::current(&tx)?;
        active.document.validate(self.artifact())?;
        let read = metadata_read(
            self.app(),
            self.scope(),
            self.artifact().id(),
            &self.artifact().contract().credential_manifest,
            &active,
            &session,
            family,
        )?;
        let result = store::inspect_metadata(&tx, &read, lineage)?;
        tx.commit()?;
        Ok(result)
    }
}
