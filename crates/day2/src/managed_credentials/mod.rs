//! Host-only managed credential primitives. App code cannot import this module.
pub(crate) mod authority;
pub(crate) mod browser;
pub(crate) mod crypto;
pub(crate) mod issuance;
pub(crate) mod store;
pub(crate) mod verification;

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
    principal_metadata_read(
        app,
        scope,
        artifact_id,
        manifest,
        active,
        &session.actor,
        family,
    )
}

fn principal_metadata_read<'a>(
    app: &str,
    scope: &str,
    artifact_id: &str,
    manifest: &'a [ManifestFamily],
    active: &'a ActiveAuthority,
    requester: &'a str,
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
        requester,
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PageInput {
    registration: String,
    after: String,
    limit: u16,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectInput {
    registration: String,
    lineage: String,
}

fn registration(instruction: &crate::protocol::Instruction) -> Result<String> {
    Ok(match instruction.model.as_str() {
        crate::credential_codegen::LIST => {
            crate::json::decode::<PageInput>(instruction.data.as_bytes())?.registration
        }
        crate::credential_codegen::INSPECT => {
            crate::json::decode::<InspectInput>(instruction.data.as_bytes())?.registration
        }
        _ => anyhow::bail!("invalid credential metadata instruction"),
    })
}

/// Rechecked before every use of a recorded observation, including replay in
/// the decision phase. The invocation's current authority stamp fences policy
/// revisions; neither app input nor an observation can substitute its actor.
pub(crate) fn require_metadata(
    db: &rusqlite::Connection,
    runtime: &Runtime,
    request: &crate::protocol::Request,
    instruction: &crate::protocol::Instruction,
) -> Result<()> {
    ensure!(
        instruction.kind == "observe",
        "credential metadata requires preparation"
    );
    instruction.decode()?;
    let name = registration(instruction)?;
    let family = runtime
        .artifact()
        .contract()
        .credential_declarations
        .iter()
        .find(|family| family.registration.as_str() == name)
        .context("undeclared credential metadata family")?;
    let operation = runtime
        .artifact()
        .contract()
        .app_contract
        .as_ref()
        .and_then(|app| app.operations.get(&request.operation))
        .context("credential metadata operation missing")?;
    ensure!(
        operation
            .credential_access
            .metadata_reads
            .iter()
            .any(|id| id == family.id.as_str()),
        "undeclared credential metadata access"
    );
    let origin = crate::store::invocation_context(db, &request.context.invocation_id)?;
    ensure!(
        origin == request.context,
        "credential metadata principal mismatch"
    );
    let active = authority_state::require_invocation_in(
        db,
        runtime,
        &origin.invocation_id,
        &request.operation,
        &origin.actor,
    )?;
    active.document.validate(runtime.artifact())?;
    principal_metadata_read(
        runtime.app(),
        runtime.scope(),
        runtime.artifact().id(),
        &runtime.artifact().contract().credential_manifest,
        &active,
        &origin.actor,
        family.id.as_str(),
    )?;
    Ok(())
}

fn encode_ref(registration: &str, lineage: &LineageRef) -> Result<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    Ok(format!(
        "cr1_{registration}_{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(lineage)?)
    ))
}

fn summary(registration: &str, value: &Summary) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "lineage": encode_ref(registration, &value.lineage)?,
        "version": value.current_version.id,
        "label": value.label.iter().collect::<Vec<_>>(),
        "principal": value.principal, "state": value.state,
        "grant": value.grant, "expires_at": value.expires_at,
    }))
}

/// Local bounded read under the normal invocation lock, with the host-created
/// principal and exact activated family. No resource, secret or private claim
/// is placed in the public wire response or the observation journal.
pub(crate) fn observe(
    db: &rusqlite::Connection,
    runtime: &Runtime,
    request: &crate::protocol::Request,
    instruction: &crate::protocol::Instruction,
) -> Result<String> {
    require_metadata(db, runtime, request, instruction)?;
    let registration = registration(instruction)?;
    let declared = runtime
        .artifact()
        .contract()
        .credential_declarations
        .iter()
        .find(|family| family.registration.as_str() == registration)
        .context("credential registration missing")?;
    let active = authority_state::current(db)?;
    let read = principal_metadata_read(
        runtime.app(),
        runtime.scope(),
        runtime.artifact().id(),
        &runtime.artifact().contract().credential_manifest,
        &active,
        &request.context.actor,
        declared.id.as_str(),
    )?;
    let result = if instruction.model == crate::credential_codegen::LIST {
        let input: PageInput = crate::json::decode(instruction.data.as_bytes())?;
        let prefix = format!("cm1_{registration}_");
        let after = if input.after.is_empty() {
            Some("")
        } else {
            input.after.strip_prefix(&prefix).filter(|opaque| {
                !opaque.is_empty() && crate::credential_codegen::cursor_shape(&input.after)
            })
        };
        let page = after
            .map(|opaque| {
                store::list_metadata(
                    db,
                    &read,
                    &ListRequest {
                        after: day2_capabilities::credentials::FamilyCursor {
                            family: declared.id.clone(),
                            opaque: opaque.into(),
                        },
                        limit: input.limit,
                    },
                )
            })
            .transpose();
        match page {
            Ok(Some(Ok(page))) => serde_json::json!({
                "error":"", "items":page.items.iter().map(|item| summary(&registration, item)).collect::<Result<Vec<_>>>()?,
                "has_more":page.next.is_some(), "next_after":page.next.map(|next| format!("{prefix}{}", next.opaque)).unwrap_or_default(),
            }),
            refused => {
                let error = match refused {
                    Ok(Some(Err(ListFailure::Denied))) => "denied",
                    Ok(None) | Ok(Some(Err(ListFailure::InvalidCursor))) => "invalid_cursor",
                    Ok(Some(Err(ListFailure::Throttled))) => "throttled",
                    _ => "unavailable",
                };
                serde_json::json!({"error":error, "items":[], "has_more":false, "next_after":""})
            }
        }
    } else {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let input: InspectInput = crate::json::decode(instruction.data.as_bytes())?;
        let lineage = input
            .lineage
            .strip_prefix(&format!("cr1_{registration}_"))
            .filter(|_| input.lineage.len() <= 2048)
            .and_then(|raw| URL_SAFE_NO_PAD.decode(raw).ok())
            .and_then(|bytes| crate::json::decode::<LineageRef>(&bytes).ok());
        let inspected = lineage
            .map(|lineage| store::inspect_metadata(db, &read, &lineage))
            .transpose();
        match inspected {
            Ok(Some(Some(value))) => serde_json::json!({
                "error":"", "items":[summary(&registration, &value.summary)?],
                "revisions":value.rotation.iter().map(|snapshot| snapshot.revision).collect::<Vec<_>>(),
            }),
            Ok(_) => serde_json::json!({"error":"not_visible", "items":[], "revisions":[]}),
            Err(_) => serde_json::json!({"error":"unavailable", "items":[], "revisions":[]}),
        }
    };
    let observation = crate::resources::bounded_observation(crate::protocol::Observation {
        instruction: instruction.clone(),
        result: serde_json::to_string(&result)?,
        error: String::new(),
    })?;
    if observation.error.is_empty() {
        return Ok(observation.result);
    }
    // Refuse the entire page within the closed read contract; never truncate it
    // or put an oversized result in the ordinary observation journal.
    Ok(serde_json::to_string(
        &if instruction.model == crate::credential_codegen::LIST {
            serde_json::json!({"error":"throttled", "items":[], "has_more":false, "next_after":""})
        } else {
            serde_json::json!({"error":"throttled", "items":[], "revisions":[]})
        },
    )?)
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
