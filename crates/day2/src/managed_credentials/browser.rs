//! Private host navigation, confirmation and delivery for ordinary commands.
use super::{
    issuance::{self, Confirmation},
    lifecycle::{self, Intent},
    store,
};
use crate::{
    artifact::Instance,
    authority_state, iap,
    store::{Fault, RequestIdentity, Runtime, open},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

pub(crate) const PREFIX: &str = "/credentials/actions/";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    pub attempt: String,
    pub invocation: String,
    pub operation: String,
    pub actor: String,
    pub input: Value,
    pub family: String,
    pub intent: Intent,
    pub artifact: String,
    pub authority: authority_state::AuthorityStamp,
    pub binding: Digest,
    pub created_at: i64,
    pub expires_at: i64,
    pub product_return: Option<String>,
}

impl Pending {
    pub(crate) fn challenge(&self) -> Result<Digest> {
        Digest::of(&("credential-confirmation-v1", self))
    }
    pub(crate) fn path(&self) -> String {
        format!("{PREFIX}{}", self.attempt)
    }
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_credential_browser (
        invocation TEXT PRIMARY KEY, attempt TEXT NOT NULL UNIQUE, intent TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS day2_credential_browser_expiry ON day2_credential_browser(expires_at);",
    )?;
    Ok(())
}

fn load(db: &Connection, attempt: &str) -> Result<Option<Pending>> {
    db.query_row(
        "SELECT intent FROM day2_credential_browser WHERE attempt=?1",
        [attempt],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|raw| crate::json::decode(raw.as_bytes()))
    .transpose()
}

/// Called only after ordinary app authentication, CSRF, input and idempotency
/// validation. This creates navigation, never acceptance or issuance authority.
pub(crate) fn start(
    runtime: &Runtime,
    operation: &str,
    actor: &str,
    invocation: &str,
    input: &Value,
    product_return: Option<&str>,
    now: i64,
) -> Result<String> {
    let access = issuance::access(runtime, operation)?;
    ensure!(
        access.interactive && access.mutation().is_some(),
        "interactive credential command required"
    );
    let op = runtime.artifact().operation(operation)?;
    runtime.artifact().contract().schema.inputs[&op.input_type].validate_input(input)?;
    let intent = lifecycle::intent(access, input)?;
    let (_, family) = access.mutation().context("credential action missing")?;
    let instance = Instance::load(runtime.instance_path())?;
    let (_, edge) = instance.security_edge()?;
    if let Some(page) = product_return {
        let page = runtime.artifact().page(page)?;
        ensure!(
            page.path.starts_with('/')
                && !page.path.starts_with("//")
                && !page.path.contains([':', '{', '}']),
            "credential return requires an admitted static page"
        );
    }
    let mut db = open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut db)?;
    tx.execute(
        "DELETE FROM day2_credential_browser WHERE expires_at<=?1",
        [now],
    )?;
    let active = authority_state::authorize_in(&tx, runtime, operation, actor)?;
    let selected = active
        .document
        .credentials
        .get(family)
        .context("credential family inactive")?;
    let binding = Digest::of(&selected.binding)?;
    let previous: Option<String> = tx
        .query_row(
            "SELECT intent FROM day2_credential_browser WHERE invocation=?1",
            [invocation],
            |row| row.get(0),
        )
        .optional()?;
    let pending = if let Some(raw) = previous {
        let previous: Pending = crate::json::decode(raw.as_bytes())?;
        ensure!(
            previous.actor == actor
                && previous.operation == operation
                && previous.input == *input
                && previous.product_return.as_deref() == product_return
                && previous.artifact == runtime.artifact().id()
                && previous.authority == active.stamp
                && previous.binding == binding
                && now < previous.expires_at,
            "credential intent changed or expired; use a new invocation"
        );
        previous
    } else {
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM (SELECT invocation FROM day2_credential_browser LIMIT 10001)",
            [],
            |row| row.get(0),
        )?;
        ensure!(count < 10_000, "credential navigation capacity reached");
        let pending = Pending {
            attempt: format!("credential-{}", super::effects::navigation_id()?),
            invocation: invocation.into(),
            operation: operation.into(),
            actor: actor.into(),
            input: input.clone(),
            family: family.into(),
            intent,
            artifact: runtime.artifact().id().into(),
            authority: active.stamp,
            binding,
            created_at: now,
            expires_at: now.checked_add(300).context("credential time overflow")?,
            product_return: product_return.map(str::to_owned),
        };
        tx.execute(
            "INSERT INTO day2_credential_browser VALUES (?1,?2,?3,?4)",
            params![
                invocation,
                pending.attempt,
                serde_json::to_string(&pending)?,
                pending.expires_at
            ],
        )?;
        pending
    };
    tx.commit()?;
    Ok(format!("{}{}", edge.origin, pending.path()))
}

/// A bounded installation-selected registry. No request chooses an app, DB,
/// key provider, origin, principal, grant or credential version.
pub(crate) struct Registry {
    runtimes: BTreeMap<String, Runtime>,
    origin: String,
    effects: super::effects::Captured,
}

impl Registry {
    pub(crate) fn new(
        instance: &Instance,
        runtimes: Vec<Runtime>,
        authority: Arc<dyn issuance::Authority>,
    ) -> Result<Self> {
        let (_, edge) = instance.security_edge()?;
        ensure!(runtimes.len() <= 128, "credential shell application budget");
        let mut selected = BTreeMap::new();
        for runtime in runtimes {
            ensure!(
                instance.scope(runtime.app())? == runtime.scope(),
                "credential shell installation mismatch"
            );
            let stored = Instance::load(runtime.instance_path())?;
            let stored_edge = stored.security_edge()?.1;
            ensure!(
                stored_edge.origin == edge.origin && stored_edge.iap_audience == edge.iap_audience,
                "credential shell edge mismatch"
            );
            ensure!(
                selected
                    .insert(
                        runtime.app().to_owned(),
                        runtime.with_credential_authority(authority.clone())
                    )
                    .is_none(),
                "duplicate shell application"
            );
        }
        Ok(Self {
            runtimes: selected,
            origin: edge.origin.clone(),
            effects: super::effects::capture(),
        })
    }

    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }

    pub(crate) fn effects(&self) -> super::effects::Captured {
        self.effects.clone()
    }

    pub(crate) fn resolve(
        &self,
        attempt: &str,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Option<(Runtime, Pending)>> {
        let mut found = None;
        for runtime in self.runtimes.values() {
            let mut db = open(runtime.db())?;
            let tx = crate::write_queue::immediate(&mut db)?;
            if let Some(pending) = load(&tx, attempt)? {
                ensure!(found.is_none(), "ambiguous credential attempt");
                let active = authority_state::authorize_in(
                    &tx,
                    runtime,
                    &pending.operation,
                    &identity.email,
                )?;
                let selected = active
                    .document
                    .credentials
                    .get(&pending.family)
                    .context("credential family inactive")?;
                runtime
                    .credential_authority()?
                    .check_shell(&selected.binding, &self.origin)?;
                ensure!(
                    pending.actor == identity.email
                        && pending.artifact == runtime.artifact().id()
                        && pending.authority == active.stamp
                        && pending.binding == Digest::of(&selected.binding)?
                        && pending.created_at <= now
                        && now < pending.expires_at,
                    "credential pending authority changed or expired"
                );
                iap::bind_subject(&tx, identity, now)?;
                found = Some((runtime.clone(), pending));
            }
            tx.commit()?;
        }
        Ok(found)
    }
}

/// Context data from the actual runtime/pending and current strict instance.
/// Existing Registry::resolve and native final writers separately check active
/// authority. This never loads provider keys or turns desired pins into proof.
pub(crate) fn fresh_intent(
    runtime: &Runtime,
    pending: &Pending,
    identity: &iap::Verified,
) -> Result<crate::oauth::fresh_auth::FreshIntent> {
    let instance = Instance::load(runtime.instance_path())?;
    ensure!(
        instance.scope(runtime.app())? == runtime.scope(),
        "credential fresh scope changed"
    );
    let (_, app) = instance.edge(runtime.app())?;
    let (_, shell) = instance.security_edge()?;
    crate::oauth::fresh_auth::FreshIntent::credential(
        runtime,
        pending,
        identity,
        &app.origin,
        &shell.origin,
    )
}

pub(crate) fn confirm(
    runtime: &Runtime,
    pending: &Pending,
    identity: &iap::Verified,
    session: &str,
    human_proof: &crate::oauth::fresh_auth::VerifiedAuthTime,
    now: i64,
) -> Result<crate::protocol::Outcome> {
    human_proof.require_intent(&fresh_intent(runtime, pending, identity)?, identity)?;
    human_proof.require_current(now)?;
    let authenticated_at = human_proof.authenticated_at();
    ensure!(
        identity.email == pending.actor
            && authenticated_at > pending.created_at
            && authenticated_at <= now
            && now - authenticated_at <= 300
            && now < pending.expires_at,
        "fresh credential authentication required"
    );
    // Key-provider I/O completes before acquiring the business writer lock.
    let mut db = open(runtime.db())?;
    let read = db.transaction()?;
    let active =
        authority_state::authorize_in(&read, runtime, &pending.operation, &identity.email)?;
    let selected = active
        .document
        .credentials
        .get(&pending.family)
        .context("credential family inactive")?;
    read.commit()?;
    let ready = runtime.credential_authority()?.prepare(
        &selected.binding,
        &selected.management,
        &identity.email,
        &identity.subject,
        now,
    )?;
    let now = human_proof.observe_current(now)?;
    human_proof.require_intent(&fresh_intent(runtime, pending, identity)?, identity)?;
    drop(db);
    let mut db = open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut db)?;
    let current = load(&tx, &pending.attempt)?.context("credential intent missing")?;
    ensure!(
        current.challenge()? == pending.challenge()?,
        "credential intent changed"
    );
    let active = authority_state::authorize_in(&tx, runtime, &pending.operation, &identity.email)?;
    let selected = active
        .document
        .credentials
        .get(&pending.family)
        .context("credential family inactive")?;
    ensure!(
        active.stamp == pending.authority
            && runtime.artifact().id() == pending.artifact
            && Digest::of(&selected.binding)? == pending.binding,
        "credential authority changed"
    );
    iap::bind_subject(&tx, identity, now)?;
    runtime.credential_authority()?.validate(
        &selected.binding,
        &selected.management,
        &identity.email,
        &identity.subject,
        &ready,
        now,
    )?;
    human_proof.require_current(now)?;
    if let Some(proof) = issuance::load(&tx, &pending.invocation)? {
        ensure!(
            proof.session == session
                && proof.subject == identity.subject
                && proof.binding == ready.binding
                && proof.security_epoch == ready.security_epoch,
            "credential approval cannot be retargeted"
        );
    } else {
        let confirmation = Confirmation {
            invocation: pending.invocation.clone(),
            operation: pending.operation.clone(),
            actor: pending.actor.clone(),
            subject: identity.subject.clone(),
            session: session.into(),
            input: pending.input.clone(),
            family: pending.family.clone(),
            intent: pending.intent.clone(),
            artifact: pending.artifact.clone(),
            authority: active.stamp,
            binding: ready.binding,
            security_epoch: ready.security_epoch,
            authenticated_at,
            approved_at: now,
            expires_at: pending.expires_at.min(human_proof.deadline()?),
        };
        tx.execute(
            "INSERT INTO day2_credential_confirmations VALUES (?1,?2)",
            params![pending.invocation, serde_json::to_string(&confirmation)?],
        )?;
    }
    tx.commit()?;
    let now = human_proof.observe_current(now)?;
    human_proof.require_intent(&fresh_intent(runtime, pending, identity)?, identity)?;
    runtime.invoke_verified(
        &pending.operation,
        RequestIdentity {
            actor: &identity.email,
            origin: Some(identity),
        },
        &pending.invocation,
        &pending.input,
        now,
        Fault::None,
    )
}

pub(crate) fn deliver(
    runtime: &Runtime,
    pending: &Pending,
    identity: &iap::Verified,
    session: &str,
    human_proof: &crate::oauth::fresh_auth::VerifiedAuthTime,
    now: i64,
    acknowledge: bool,
) -> Result<Option<String>> {
    human_proof.require_intent(&fresh_intent(runtime, pending, identity)?, identity)?;
    human_proof.require_current(now)?;
    let mut db = open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut db)?;
    let active = authority_state::authorize_in(&tx, runtime, &pending.operation, &identity.email)?;
    let selected = active
        .document
        .credentials
        .get(&pending.family)
        .context("credential family inactive")?;
    let proof = issuance::load(&tx, &pending.invocation)?.context("credential approval missing")?;
    ensure!(
        active.stamp == proof.authority
            && proof.artifact == runtime.artifact().id()
            && proof.binding == Digest::of(&selected.binding)?
            && proof.actor == identity.email
            && proof.subject == identity.subject
            && proof.session == session
            && proof.approved_at <= now
            && now < proof.expires_at,
        "credential delivery approval changed or expired"
    );
    iap::bind_subject(&tx, identity, now)?;
    let has_delivery: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_credential_receipts r JOIN day2_invocations i ON i.id=r.invocation
         WHERE r.invocation=?1 AND r.action IN ('issue','rotate') AND i.status='success')",
        [&pending.invocation], |row| row.get(0))?;
    if !has_delivery {
        let succeeded: bool = tx.query_row(
            "SELECT status='success' FROM day2_invocations WHERE id=?1",
            [&pending.invocation],
            |row| row.get(0),
        )?;
        ensure!(
            acknowledge && succeeded && !matches!(proof.intent, Intent::Issue { .. }),
            "credential delivery unavailable"
        );
        human_proof.require_current(now)?;
        tx.commit()?;
        return Ok(None);
    }
    let epoch = runtime.credential_authority()?.reveal_epoch(
        &selected.binding,
        &selected.management,
        &identity.email,
        &identity.subject,
        now,
    )?;
    let now = human_proof.observe_current(now)?;
    human_proof.require_intent(&fresh_intent(runtime, pending, identity)?, identity)?;
    ensure!(
        now < proof.expires_at,
        "credential delivery approval expired during preparation"
    );
    ensure!(
        epoch == proof.security_epoch,
        "credential security epoch changed"
    );
    let version = store::issued_version(
        &tx,
        &selected.binding.namespace,
        &pending.invocation,
        selected.binding.family.as_str(),
        &selected.qualification.family_contract,
    )?;
    if acknowledge {
        // Recipient/session checks above bind closure to the original approval.
        store::close_delivery(&tx, &version, "acknowledged")?;
        human_proof.require_current(now)?;
        tx.commit()?;
        return Ok(None);
    }
    let permit = store::authorize_reveal_in(
        &tx,
        store::VerifiedHumanPost {
            namespace: selected.binding.namespace.clone(),
            version,
            recipient: identity.email.clone(),
            session: session.into(),
            attempt: super::effects::navigation_id()?,
            now,
            security_epoch: epoch,
        },
    )?
    .context("credential delivery unavailable")?;
    let binding = selected.binding.clone();
    let management = selected.management.clone();
    let permit = permit.commit(tx)?;
    // No secret provider load or decryption is reachable before known commit.
    let keys = runtime.credential_authority()?.human_keys(
        &binding,
        &management,
        &identity.email,
        &identity.subject,
        &permit,
        now,
    )?;
    human_proof.require_current(now)?;
    human_proof.require_intent(&fresh_intent(runtime, pending, identity)?, identity)?;
    Ok(Some(permit.into_response_body(&keys)?))
}
