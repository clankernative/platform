//! Managed bearer admission and durable, path-preserving invocation ceilings.
//! Tokens never enter journals, app inputs, receipts or browser sessions.
use super::{
    crypto::{VerifierLease, token_selector},
    store,
};
use crate::{
    authority_state::{self, ActiveAuthority, AuthorityStamp},
    error::Failure,
    store::{Runtime, open},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{GrantMode, ManagedProfile, Namespace},
    oauth::GrantCeiling,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

pub(crate) const PREFIX: &str = "/_day2/credentials/api/";

pub(crate) fn dispatch(
    runtime: &Runtime,
    catalog: &crate::openapi::Catalog,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    headers: &axum::http::HeaderMap,
    body: &[u8],
    at: i64,
) -> Result<axum::response::Response> {
    use crate::web_api::{self, single_header};
    use axum::http::{Method, StatusCode, header};
    ensure!(
        !headers.contains_key(header::COOKIE)
            && !headers.contains_key(header::ORIGIN)
            && !headers.contains_key("x-csrf-token")
            && !headers.contains_key(web_api::ACT_AS_HEADER)
            && !headers.contains_key("sec-fetch-site")
            && !headers.contains_key("x-goog-iap-jwt-assertion")
            && !headers.contains_key("x-goog-authenticated-user-email")
            && !headers.contains_key("x-goog-authenticated-user-id"),
        Failure::CredentialRejected
    );
    let token = single_header(headers, "authorization")
        .and_then(|raw| raw.strip_prefix("Bearer "))
        .context(Failure::CredentialRejected)?;
    let name = uri
        .path()
        .strip_prefix(PREFIX)
        .context(Failure::CredentialRejected)?;
    if let Some(id) = name.strip_prefix("invocations/") {
        ensure!(*method == Method::GET, Failure::UnsupportedMethod);
        ensure!(
            uri.query().is_none() && body.is_empty(),
            Failure::InvalidInput
        );
        let db = open(runtime.db())?;
        let origin = load(&db, id)?.context(Failure::CredentialRejected)?;
        ensure!(origin.path.is_empty(), Failure::CredentialRejected);
        let admission = prepare(runtime, &origin.root, token, at)?;
        ensure!(admission.origin == origin, Failure::CredentialRejected);
        let receipt = crate::invocations::status(runtime, id, &admission.actor)?;
        return Ok(web_api::json_response(
            StatusCode::OK,
            serde_json::to_value(receipt)?,
        ));
    }
    let Some(endpoint) = catalog
        .endpoints
        .values()
        .find(|endpoint| endpoint.path().strip_prefix("/api/") == Some(name))
    else {
        return Ok(web_api::error(
            StatusCode::NOT_FOUND,
            "unknown_operation",
            "Operation not found.",
        ));
    };
    ensure!(
        method.as_str() == endpoint.method(),
        Failure::UnsupportedMethod
    );
    let operation = &endpoint.operation;
    let admission = prepare(runtime, &operation.name, token, at)?;
    let record = &runtime.artifact().contract().schema.inputs[&operation.input_type];
    let (input, invocation) = if method == Method::GET {
        ensure!(body.is_empty(), Failure::InvalidInput);
        (
            crate::openapi::query_input(record, uri.query().unwrap_or(""))
                .context(Failure::InvalidInput)?,
            format!("credential-query-{}", super::effects::navigation_id()?),
        )
    } else {
        ensure!(uri.query().is_none(), Failure::InvalidInput);
        ensure!(
            single_header(headers, "content-type").is_some_and(|raw| raw
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))),
            Failure::UnsupportedContentType
        );
        let input: serde_json::Value = crate::json::decode(body).context(Failure::InvalidInput)?;
        record
            .validate_input(&input)
            .context(Failure::InvalidInput)?;
        let id = web_api::command_invocation(
            runtime,
            &admission.actor,
            single_header(headers, "idempotency-key").context(Failure::InvalidIdempotencyKey)?,
        )?;
        (input, id)
    };
    runtime.accept_credential(&operation.name, &admission, &invocation, &input, at)?;
    let outcome = runtime.execute(&invocation, crate::store::Fault::None)?;
    let mut response = if outcome.status == "success" {
        web_api::json_response(StatusCode::OK, outcome.result)
    } else if outcome.status == "pending" {
        web_api::json_response(
            StatusCode::ACCEPTED,
            serde_json::json!({"invocation_id":invocation,"status":"pending", "status_url":format!("{PREFIX}invocations/{invocation}")}),
        )
    } else {
        let (status, code, message) = web_api::outcome_failure(runtime, &outcome.error);
        web_api::error(status, &code, &message)
    };
    response
        .headers_mut()
        .insert("x-day2-invocation", invocation.parse()?);
    Ok(response)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Origin {
    namespace: Namespace,
    family: String,
    family_contract: Digest,
    lineage: String,
    version: String,
    principal: String,
    actor: String,
    binding: Digest,
    security_epoch: u64,
    verifier_version: String,
    ceiling: GrantCeiling,
    root: String,
    path: Vec<String>,
}

pub(crate) struct Admission {
    pub actor: String,
    origin: Origin,
    authority: AuthorityStamp,
    operation: String,
    keys: VerifierLease,
    token: Vec<u8>,
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.token.fill(0);
    }
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_credential_origins (
        invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id), evidence TEXT NOT NULL
    ) STRICT;",
    )?;
    Ok(())
}

/// Admit historical rows, including revoked versions, without granting current
/// permission. The owning store checks exact peer DDL and supplies the same
/// cumulative SQL/materialization budget as the core credential tables.
pub(super) fn validate_restored(db: &Connection) -> Result<()> {
    let present: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_credential_origins)",
        [],
        |row| row.get(0),
    )?;
    if !present {
        return Ok(());
    }
    let mut statement = db.prepare(
        "SELECT o.invocation,o.evidence,l.namespace,l.namespace_json,l.family,
                l.family_contract,l.principal,l.security_epoch,l.grant_json,
                v.id,v.lineage,v.verifier_key_version,v.security_epoch,i.operation,i.actor
         FROM day2_credential_origins o
         LEFT JOIN day2_invocations i ON i.id=o.invocation
         LEFT JOIN day2_credential_versions v ON v.id=json_extract(o.evidence,'$.version')
         LEFT JOIN day2_credential_lineages l ON l.id=v.lineage",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        crate::oauth::schema::materialize(row)?;
        let origin: Origin = crate::json::decode(row.get_ref(1)?.as_str()?.as_bytes())?;
        origin.namespace.validate()?;
        day2_capabilities::Name::try_from(origin.family.clone())?;
        for id in [
            row.get_ref(0)?.as_str()?,
            &origin.lineage,
            &origin.version,
            &origin.verifier_version,
            &origin.root,
        ] {
            stored_identifier(id)?;
        }
        crate::authority::valid_actor(&origin.principal)?;
        crate::authority::valid_actor(&origin.actor)?;
        ensure!(
            origin.security_epoch > 0 && origin.path.len() <= 16,
            "invalid restored credential origin epoch/path"
        );
        origin.ceiling.verify()?;
        let namespace: Namespace = crate::json::decode(row.get_ref(3)?.as_str()?.as_bytes())?;
        let ceiling: GrantCeiling = crate::json::decode(row.get_ref(8)?.as_str()?.as_bytes())?;
        ensure!(
            origin.namespace == namespace
                && Digest::of(&("credential-namespace-v1", &namespace))?.as_str()
                    == row.get_ref(2)?.as_str()?
                && origin.family == row.get_ref(4)?.as_str()?
                && origin.family_contract.as_str() == row.get_ref(5)?.as_str()?
                && origin.principal == row.get_ref(6)?.as_str()?
                && origin.security_epoch == u64::try_from(row.get::<_, i64>(7)?)?
                && origin.ceiling == ceiling
                && origin.ceiling.subject == origin.principal
                && origin.version == row.get_ref(9)?.as_str()?
                && origin.lineage == row.get_ref(10)?.as_str()?
                && origin.verifier_version == row.get_ref(11)?.as_str()?
                && origin.security_epoch == u64::try_from(row.get::<_, i64>(12)?)?
                && origin.actor == row.get_ref(14)?.as_str()?,
            "restored credential origin identity mismatch"
        );
        if let Some(family) = crate::authority::client_family(&origin.principal) {
            ensure!(
                family == origin.family && origin.actor == origin.principal,
                "restored client credential actor mismatch"
            );
        } else {
            let mut statement = db.prepare("SELECT subject FROM day2_principals WHERE email=?1")?;
            let mut subjects = statement.query([&origin.actor])?;
            let subject = subjects
                .next()?
                .context("restored credential subject mapping missing")?;
            crate::oauth::schema::materialize(subject)?;
            ensure!(
                subject.get_ref(0)?.as_str()? == origin.principal,
                "restored personal credential actor mismatch"
            );
        }
        let root = origin
            .ceiling
            .roots
            .get(&origin.root)
            .context("restored credential origin root missing")?;
        let mut closure = &root.closure;
        let mut expected = origin.root.as_str();
        for hop in &origin.path {
            stored_identifier(hop)?;
            closure = closure
                .children
                .get(hop)
                .context("restored credential origin path outside ceiling")?;
            expected = hop;
        }
        ensure!(
            expected == row.get_ref(13)?.as_str()?,
            "restored credential origin operation mismatch"
        );
    }
    Ok(())
}

fn stored_identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte)),
        "invalid restored credential origin identifier"
    );
    Ok(())
}

pub(crate) fn prepare(
    runtime: &Runtime,
    operation: &str,
    token: &str,
    now: i64,
) -> Result<Admission> {
    let selector = token_selector(token).map_err(|_| Failure::CredentialRejected)?;
    let mut db = open(runtime.db())?;
    let tx = db.transaction()?;
    runtime.check_binding(&tx)?;
    let active = authority_state::current(&tx)?;
    ensure!(
        active.document.enabled && active.artifact_id == runtime.artifact().id(),
        Failure::CredentialRejected
    );
    let family: Option<(String, String)> = tx.query_row(
        "SELECT l.family, v.verifier_key_version FROM day2_credential_versions v JOIN day2_credential_lineages l ON l.id=v.lineage
         WHERE v.selector=?1 AND l.head=v.id AND l.state='active' AND v.state='active'", [&selector], |row| Ok((row.get(0)?, row.get(1)?))
    ).optional()?;
    let (family, verifier_version) = family.context(Failure::CredentialRejected)?;
    let selected = active
        .document
        .credentials
        .get(&family)
        .context(Failure::CredentialRejected)?
        .clone();
    let manifest = runtime
        .artifact()
        .contract()
        .credential_manifest
        .iter()
        .find(|entry| entry.id.as_str() == family)
        .context(Failure::CredentialRejected)?;
    ensure!(
        matches!(
            manifest.profile,
            ManagedProfile::Client | ManagedProfile::Personal
        ) && matches!(manifest.grant, GrantMode::Fixed),
        Failure::CredentialRejected
    );
    let contract = crate::credential_authority::operation(runtime.artifact().contract(), operation)
        .map_err(|_| Failure::CredentialRejected)?;
    let stamp = active.stamp;
    tx.commit()?;
    // Provider reads happen before the admission writer; all facts are rechecked.
    let provider = runtime
        .credential_authority()
        .map_err(|_| Failure::CredentialUnavailable)?;
    let keys = provider
        .verification_keys(&selected.binding, &selected.management, now)
        .map_err(|_| Failure::CredentialUnavailable)?;
    ensure!(
        keys.verifier_version == verifier_version,
        Failure::CredentialRejected
    );
    let epoch = provider
        .verification_epoch(
            &selected.binding,
            &selected.management,
            &keys.verifier_version,
            now,
        )
        .map_err(|_| Failure::CredentialUnavailable)?
        .context(Failure::CredentialRejected)?;
    let mut db = open(runtime.db())?;
    let tx = db.transaction()?;
    ensure!(
        authority_state::current(&tx)?.stamp == stamp,
        Failure::CredentialRejected
    );
    let verified = store::verify_ingress(
        &tx,
        &keys,
        store::IngressVerification {
            namespace: &selected.binding.namespace,
            family: &family,
            family_contract: &manifest.contract,
            security_epoch: epoch,
            now,
            operation: &contract,
        },
        token,
    )?
    .context(Failure::CredentialRejected)?;
    ensure!(
        verified.ceiling.client == selected.binding.approved_authority
            && verified.ceiling.audience == selected.binding.audience,
        Failure::CredentialRejected
    );
    let actor = match manifest.profile {
        ManagedProfile::Client => {
            ensure!(
                crate::authority::client_family(&verified.principal) == Some(family.as_str()),
                Failure::CredentialRejected
            );
            verified.principal.clone()
        }
        _ => {
            let actor = provider
                .personal_actor(
                    &selected.binding,
                    &selected.management,
                    &verified.principal,
                    now,
                )
                .map_err(|_| Failure::CredentialRejected)?;
            let subject: Option<String> = tx
                .query_row(
                    "SELECT subject FROM day2_principals WHERE email=?1",
                    [&actor],
                    |row| row.get(0),
                )
                .optional()?;
            ensure!(
                subject.as_deref() == Some(verified.principal.as_str()),
                Failure::CredentialRejected
            );
            actor
        }
    };
    authority_state::authorize_in(&tx, runtime, operation, &actor)?;
    tx.commit()?;
    Ok(Admission {
        origin: Origin {
            namespace: selected.binding.namespace.clone(),
            family,
            family_contract: manifest.contract.clone(),
            lineage: verified.lineage,
            version: verified.version,
            principal: verified.principal,
            actor: actor.clone(),
            binding: Digest::of(&selected.binding)?,
            security_epoch: epoch,
            verifier_version: keys.verifier_version.clone(),
            ceiling: verified.ceiling,
            root: operation.into(),
            path: Vec::new(),
        },
        actor,
        authority: stamp,
        operation: operation.into(),
        keys,
        token: token.as_bytes().to_vec(),
    })
}

pub(crate) fn record(
    db: &Connection,
    runtime: &Runtime,
    id: &str,
    operation: &str,
    active: &ActiveAuthority,
    admission: &Admission,
) -> Result<()> {
    ensure!(
        active.stamp == admission.authority && operation == admission.operation,
        Failure::CredentialRejected
    );
    let selected = active
        .document
        .credentials
        .get(&admission.origin.family)
        .context(Failure::CredentialRejected)?;
    let now = runtime.host().now_ms()? / 1000;
    let epoch = runtime
        .credential_authority()
        .map_err(|_| Failure::CredentialUnavailable)?
        .verification_epoch(
            &selected.binding,
            &selected.management,
            &admission.keys.verifier_version,
            now,
        )
        .map_err(|_| Failure::CredentialUnavailable)?
        .context(Failure::CredentialRejected)?;
    let contract =
        crate::credential_authority::operation(runtime.artifact().contract(), operation)?;
    let verified = store::verify_ingress(
        db,
        &admission.keys,
        store::IngressVerification {
            namespace: &selected.binding.namespace,
            family: &admission.origin.family,
            family_contract: &admission.origin.family_contract,
            security_epoch: epoch,
            now,
            operation: &contract,
        },
        std::str::from_utf8(&admission.token)?,
    )?
    .context(Failure::CredentialRejected)?;
    ensure!(
        verified.lineage == admission.origin.lineage
            && verified.version == admission.origin.version
            && verified.ceiling == admission.origin.ceiling,
        Failure::CredentialRejected
    );
    if let Some(previous) = load(db, id)? {
        ensure!(
            previous == admission.origin,
            Failure::IdempotencyKeyConflict
        );
    } else {
        db.execute(
            "INSERT INTO day2_credential_origins VALUES(?1,?2)",
            params![id, serde_json::to_string(&admission.origin)?],
        )?;
    }
    require(db, runtime, id, operation, &admission.actor, active)
}

fn load(db: &Connection, id: &str) -> Result<Option<Origin>> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='day2_credential_origins')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let raw: Option<String> = db
        .query_row(
            "SELECT evidence FROM day2_credential_origins WHERE invocation=?1",
            [id],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(|raw| crate::json::decode(raw.as_bytes()))
        .transpose()
}

pub(crate) fn inherit(
    db: &Connection,
    runtime: &Runtime,
    parent: &str,
    child: &str,
    operation: &str,
    active: &ActiveAuthority,
) -> Result<()> {
    if let Some(mut origin) = load(db, parent)? {
        ensure!(origin.path.len() < 16, Failure::CredentialAuthorityChanged);
        origin.path.push(operation.into());
        db.execute(
            "INSERT INTO day2_credential_origins VALUES(?1,?2)",
            params![child, serde_json::to_string(&origin)?],
        )?;
        require(db, runtime, child, operation, &origin.actor, active)?;
    }
    Ok(())
}

pub(crate) fn require(
    db: &Connection,
    runtime: &Runtime,
    id: &str,
    operation: &str,
    actor: &str,
    active: &ActiveAuthority,
) -> Result<()> {
    let Some(origin) = load(db, id)? else {
        // Missing evidence must never turn a credential invocation or any of
        // its local descendants into an unrestricted ordinary invocation.
        let required: bool = db.query_row(
            "WITH RECURSIVE ancestry(id, depth) AS (
            SELECT ?1, 0 UNION ALL SELECT r.parent, a.depth+1
            FROM day2_command_requests r JOIN ancestry a ON r.id=a.id WHERE a.depth<16
        ) SELECT EXISTS(SELECT 1 FROM ancestry a JOIN day2_invocations i ON i.id=a.id
            WHERE i.trigger='credential')",
            [id],
            |row| row.get(0),
        )?;
        ensure!(!required, Failure::CredentialAuthorityChanged);
        return Ok(());
    };
    let selected = active
        .document
        .credentials
        .get(&origin.family)
        .context(Failure::CredentialAuthorityChanged)?;
    ensure!(
        origin.actor == actor
            && origin.namespace == selected.binding.namespace
            && origin.binding == Digest::of(&selected.binding)?
            && origin.family_contract == selected.qualification.family_contract,
        Failure::CredentialAuthorityChanged
    );
    let now = runtime.host().now_ms()? / 1000;
    let provider = runtime
        .credential_authority()
        .map_err(|_| Failure::CredentialUnavailable)?;
    let epoch = provider
        .verification_epoch(
            &selected.binding,
            &selected.management,
            &origin.verifier_version,
            now,
        )
        .map_err(|_| Failure::CredentialUnavailable)?
        .context(Failure::CredentialAuthorityChanged)?;
    ensure!(
        epoch == origin.security_epoch,
        Failure::CredentialAuthorityChanged
    );
    let family = runtime
        .artifact()
        .contract()
        .credential_manifest
        .iter()
        .find(|family| family.id.as_str() == origin.family)
        .context(Failure::CredentialAuthorityChanged)?;
    if matches!(family.profile, ManagedProfile::Personal) {
        ensure!(
            provider
                .personal_actor(
                    &selected.binding,
                    &selected.management,
                    &origin.principal,
                    now
                )
                .map_err(|_| Failure::CredentialAuthorityChanged)?
                == actor,
            Failure::CredentialAuthorityChanged
        );
    } else {
        ensure!(
            matches!(family.profile, ManagedProfile::Client)
                && crate::authority::client_family(&origin.principal)
                    == Some(origin.family.as_str()),
            Failure::CredentialAuthorityChanged
        );
    }
    let live: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_credential_lineages l
        JOIN day2_credential_versions v ON v.id=l.head AND v.lineage=l.id
        WHERE l.id=?1 AND v.id=?2 AND l.state='active' AND v.state='active'
        AND l.security_epoch=?3 AND v.security_epoch=l.security_epoch
        AND l.principal=?4 AND l.grant_digest=?5 AND v.grant_digest=l.grant_digest
        AND v.issued_at<=?6 AND ?6<v.expires_at AND ?6<l.grant_valid_until)",
        params![
            origin.lineage,
            origin.version,
            i64::try_from(epoch)?,
            origin.principal,
            origin.ceiling.digest.as_str(),
            now
        ],
        |row| row.get(0),
    )?;
    ensure!(live, Failure::CredentialAuthorityChanged);
    origin.ceiling.verify()?;
    let root = origin
        .ceiling
        .roots
        .get(&origin.root)
        .context(Failure::CredentialAuthorityChanged)?;
    let mut ceiling = &root.closure;
    let mut expected = origin.root.as_str();
    for hop in &origin.path {
        ceiling = ceiling
            .children
            .get(hop)
            .context(Failure::CredentialAuthorityChanged)?;
        expected = hop;
    }
    ensure!(expected == operation, Failure::CredentialAuthorityChanged);
    let current = crate::credential_authority::operation(runtime.artifact().contract(), operation)
        .map_err(|_| Failure::CredentialAuthorityChanged)?;
    ensure!(
        current.closure.is_within(ceiling),
        Failure::CredentialAuthorityChanged
    );
    if origin.path.is_empty() {
        ensure!(
            origin.ceiling.allows(&current)?,
            Failure::CredentialAuthorityChanged
        );
    }
    Ok(())
}
