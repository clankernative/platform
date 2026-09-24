//! Local operator resource authoring and durable, transactionally approved reviews.
//! The authoring file is desired configuration. Only an approved app snapshot
//! authorizes execution; editing a reusable policy never remaps a live handle.
use crate::{
    artifact::Instance,
    authority_state::{self, ApplyAuthority, AuthorityDocument, AuthorityStamp, LocalOperator},
    store::{Runtime, open},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, io::Write, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authoring {
    pub revision: String,
    pub catalog: Value,
    pub bindings: BTreeMap<String, Value>,
}

fn administrator(instance: &Instance, operator: &str) -> Result<()> {
    crate::authority::valid_actor(operator)?;
    ensure!(
        instance
            .control
            .as_ref()
            .is_some_and(|control| control.operators.contains(operator)),
        "resource_admin_operator_required"
    );
    Ok(())
}

fn owns(policy: &day2_capabilities::resources::ReusablePolicy, operator: &str) -> bool {
    policy.owner == operator || policy.delegates.contains(operator)
}

fn admitted_operator(instance: &Instance, operator: &str) -> Result<()> {
    crate::authority::valid_actor(operator)?;
    ensure!(
        administrator(instance, operator).is_ok()
            || instance.resources.as_ref().is_some_and(|catalog| catalog
                .policies
                .values()
                .any(|policy| owns(policy, operator))),
        "resource_admin_operator_required"
    );
    Ok(())
}

fn app_operator(instance: &Instance, app: &str, operator: &str) -> Result<()> {
    if administrator(instance, operator).is_ok() {
        return Ok(());
    }
    ensure!(
        instance.resources.as_ref().is_some_and(|catalog| catalog
            .policies
            .values()
            .any(|policy| owns(policy, operator) && policy.allowed_apps.contains(app))),
        "resource_policy_owner_required"
    );
    Ok(())
}

fn may_review(
    instance: &Instance,
    app: &str,
    operator: &str,
    documents: &[&AuthorityDocument],
) -> Result<()> {
    if administrator(instance, operator).is_ok() {
        return Ok(());
    }
    app_operator(instance, app, operator)?;
    let catalog = instance
        .resources
        .as_ref()
        .context("resource_catalog_required")?;
    // Mixed-owner source/destination combinations escalate to IT. Ownership of
    // one destination never authorizes movement from somebody else's dataset.
    for document in documents {
        for grant in document
            .resources
            .operations
            .values()
            .flat_map(|slots| slots.values())
        {
            let policy = catalog
                .policies
                .get(&grant.policy.id)
                .context("resource_policy_missing")?;
            ensure!(
                policy.revision == grant.policy.revision
                    && owns(policy, operator)
                    && policy.allowed_apps.contains(app),
                "resource_review_requires_administrator"
            );
        }
    }
    Ok(())
}

fn may_propose(
    instance: &Instance,
    app: &str,
    operator: &str,
    active: &AuthorityDocument,
    proposed: &AuthorityDocument,
) -> Result<()> {
    if administrator(instance, operator).is_ok() {
        return Ok(());
    }
    app_operator(instance, app, operator)?;
    let catalog = instance
        .resources
        .as_ref()
        .context("resource_catalog_required")?;
    for (old, new) in [
        (&active.resources, &proposed.resources),
        (&proposed.resources, &active.resources),
    ] {
        for (operation, slots) in &old.operations {
            for (slot, grant) in slots {
                if new
                    .operations
                    .get(operation)
                    .and_then(|slots| slots.get(slot))
                    == Some(grant)
                {
                    continue;
                }
                ensure!(
                    catalog
                        .policies
                        .get(&grant.policy.id)
                        .is_some_and(|policy| owns(policy, operator)
                            && policy.revision == grant.policy.revision),
                    "resource_change_requires_policy_owner"
                );
            }
        }
    }
    Ok(())
}

fn visible_resources(
    instance: &Instance,
    operator: &str,
    resources: &day2_capabilities::resources::ResolvedResources,
) -> day2_capabilities::resources::ResolvedResources {
    let mut visible = resources.clone();
    if administrator(instance, operator).is_ok() {
        return visible;
    }
    for slots in visible.operations.values_mut() {
        slots.retain(|_, grant| {
            instance
                .resources
                .as_ref()
                .and_then(|catalog| catalog.policies.get(&grant.policy.id))
                .is_some_and(|policy| owns(policy, operator))
        });
    }
    visible.operations.retain(|_, slots| !slots.is_empty());
    let budgets: std::collections::BTreeSet<_> = visible
        .operations
        .values()
        .flat_map(|slots| slots.values())
        .flat_map(|grant| grant.budgets.iter().map(|reference| reference.id.clone()))
        .collect();
    visible.budgets.retain(|id, _| budgets.contains(id));
    visible
}

pub fn authorize(path: &Path, operator: &str) -> Result<()> {
    admitted_operator(&Instance::load(path)?, operator)
}

fn read_authoring(path: &Path) -> Result<(Instance, Authoring)> {
    let raw = fs::read(path)?;
    ensure!(raw.len() <= 1_048_576, "instance_byte_budget");
    let instance = Instance::from_bytes(&raw)?;
    let value = serde_json::to_value(&instance)?;
    let bindings = value["apps"]
        .as_object()
        .context("instance_apps")?
        .iter()
        .map(|(name, app)| {
            (
                name.clone(),
                app.get("resource_policies").cloned().unwrap_or(json!([])),
            )
        })
        .collect();
    Ok((
        instance,
        Authoring {
            revision: crate::digest(&raw),
            catalog: value.get("resources").cloned().unwrap_or(Value::Null),
            bindings,
        },
    ))
}

pub fn authoring(path: &Path, operator: &str) -> Result<Authoring> {
    let (instance, mut authoring) = read_authoring(path)?;
    admitted_operator(&instance, operator)?;
    if administrator(&instance, operator).is_err() {
        let mut catalog = instance.resources.context("resource_catalog_required")?;
        catalog.policies.retain(|_, policy| owns(policy, operator));
        let apps: std::collections::BTreeSet<_> = catalog
            .policies
            .values()
            .flat_map(|policy| policy.allowed_apps.iter().cloned())
            .collect();
        let resources: std::collections::BTreeSet<_> = catalog
            .policies
            .values()
            .flat_map(|policy| policy.slots.values())
            .flat_map(|slot| {
                slot.allowed_resources
                    .iter()
                    .map(|reference| reference.id.clone())
            })
            .collect();
        let budgets: std::collections::BTreeSet<_> = catalog
            .policies
            .values()
            .flat_map(|policy| policy.slots.values())
            .flat_map(|slot| slot.budgets.iter().map(|reference| reference.id.clone()))
            .collect();
        catalog.resources.retain(|id, _| resources.contains(id));
        let connections: std::collections::BTreeSet<_> = catalog
            .resources
            .values()
            .map(|resource| resource.connection.id.clone())
            .collect();
        catalog.connections.retain(|id, _| connections.contains(id));
        catalog.budgets.retain(|id, _| budgets.contains(id));
        authoring.bindings.retain(|app, _| apps.contains(app));
        for bindings in authoring.bindings.values_mut() {
            if let Some(items) = bindings.as_array_mut() {
                items.retain(|attachment| {
                    attachment["policy"]["id"]
                        .as_str()
                        .is_some_and(|id| catalog.policies.contains_key(id))
                });
            }
        }
        authoring.catalog = serde_json::to_value(catalog)?;
    }
    Ok(authoring)
}

pub fn is_administrator(path: &Path, operator: &str) -> Result<bool> {
    Ok(administrator(&Instance::load(path)?, operator).is_ok())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attach {
    pub revision: String,
    pub bindings: Vec<day2_capabilities::resources::Attachment>,
}

/// Owners edit only their approved templates. Other owners' attachments remain
/// intact and mixed-owner activation requires an installation administrator.
pub fn attach(path: &Path, app: &str, operator: &str, request: &Attach) -> Result<Authoring> {
    let (instance, mut update) = read_authoring(path)?;
    app_operator(&instance, app, operator)?;
    ensure!(
        update.revision == request.revision,
        "resource_authoring_changed"
    );
    let catalog = instance
        .resources
        .as_ref()
        .context("resource_catalog_required")?;
    let mut bindings = request.bindings.clone();
    if administrator(&instance, operator).is_err() {
        for attachment in &bindings {
            ensure!(
                catalog
                    .policies
                    .get(&attachment.policy.id)
                    .is_some_and(|policy| owns(policy, operator)),
                "resource_policy_owner_required"
            );
        }
        bindings.extend(
            instance
                .apps
                .get(app)
                .context("app_not_installed")?
                .resource_policies
                .iter()
                .filter(|attachment| {
                    !catalog
                        .policies
                        .get(&attachment.policy.id)
                        .is_some_and(|policy| owns(policy, operator))
                })
                .cloned(),
        );
    }
    catalog.resolve(app, &bindings, now_ms()?)?;
    update
        .bindings
        .insert(app.into(), serde_json::to_value(bindings)?);
    save(path, operator, &update)?;
    authoring(path, operator)
}

/// Serializes supported authoring writers and atomically replaces the complete
/// shared Instance contract. A stale editor cannot overwrite a newer revision.
pub fn save(path: &Path, operator: &str, update: &Authoring) -> Result<Authoring> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = path.canonicalize()?;
    let parent = path.parent().context("instance_directory")?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(parent.join(".resource-authoring.lock"))?;
    lock.lock()?;
    let (instance, previous) = read_authoring(&path)?;
    admitted_operator(&instance, operator)?;
    ensure!(
        previous.revision == update.revision,
        "resource_authoring_changed"
    );
    ensure!(
        previous.bindings.keys().eq(update.bindings.keys()),
        "resource_app_set_changed"
    );
    if administrator(&instance, operator).is_err() {
        ensure!(
            previous.catalog == update.catalog,
            "resource_catalog_requires_administrator"
        );
        let catalog = instance
            .resources
            .as_ref()
            .context("resource_catalog_required")?;
        for (app, after) in &update.bindings {
            let before = &previous.bindings[app];
            if before == after {
                continue;
            }
            app_operator(&instance, app, operator)?;
            let old: Vec<day2_capabilities::resources::Attachment> =
                serde_json::from_value(before.clone())?;
            let new: Vec<day2_capabilities::resources::Attachment> =
                serde_json::from_value(after.clone())?;
            for attachment in old
                .iter()
                .filter(|item| !new.contains(item))
                .chain(new.iter().filter(|item| !old.contains(item)))
            {
                let policy = catalog
                    .policies
                    .get(&attachment.policy.id)
                    .context("resource_policy_missing")?;
                ensure!(
                    owns(policy, operator)
                        && policy.revision == attachment.policy.revision
                        && policy.allowed_apps.contains(app),
                    "resource_attachment_requires_administrator"
                );
            }
            catalog.resolve(app, &new, now_ms()?)?;
        }
    }
    let mut value = serde_json::to_value(&instance)?;
    value["resources"] = update.catalog.clone();
    for (name, bindings) in &update.bindings {
        value["apps"][name]["resource_policies"] = bindings.clone();
    }
    let raw = serde_json::to_vec_pretty(&value)?;
    ensure!(raw.len() <= 1_048_576, "instance_byte_budget");
    // The shared decoder and resolver are the single policy schema, including
    // pinned revisions and typed resource/action compatibility.
    let next = Instance::from_bytes(&raw)?;
    if let (Some(previous), Some(next)) = (&instance.resources, &next.resources) {
        previous.validate_successor(next)?;
    }
    crate::resource_catalog_history::validate_and_record(
        parent,
        &instance.installation,
        &instance.environment,
        instance.resources.as_ref(),
        next.resources.as_ref(),
    )?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(&raw)?;
    temporary.as_file().sync_all()?;
    temporary.persist(&path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(read_authoring(&path)?.1)
}

fn upgrade(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_resource_reviews(
        id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, author TEXT NOT NULL,
        created_ms INTEGER NOT NULL, authoring_revision TEXT NOT NULL,
        artifact TEXT NOT NULL, expected TEXT NOT NULL, document TEXT NOT NULL,
        note TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS day2_resource_review_decisions(
        review TEXT PRIMARY KEY REFERENCES day2_resource_reviews(id),
        operator TEXT NOT NULL, decided_ms INTEGER NOT NULL,
        decision TEXT NOT NULL CHECK(decision IN ('approve','deny')),
        reason TEXT NOT NULL, receipt TEXT
    ) STRICT;",
    )?;
    for table in ["day2_resource_reviews", "day2_resource_review_decisions"] {
        let key = if table == "day2_resource_reviews" {
            "id"
        } else {
            "review"
        };
        for (suffix, event) in [
            ("update", format!("BEFORE UPDATE ON {table}")),
            ("delete", format!("BEFORE DELETE ON {table}")),
            (
                "replace",
                format!(
                    "BEFORE INSERT ON {table} WHEN EXISTS(SELECT 1 FROM {table} WHERE {key}=NEW.{key})"
                ),
            ),
        ] {
            let name = format!("{table}_no_{suffix}");
            let sql = format!(
                "CREATE TRIGGER {name} {event} BEGIN SELECT RAISE(ABORT,'immutable_resource_review'); END"
            );
            db.execute_batch(&sql.replacen("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1))?;
            crate::audit::validate_trigger(db, &name, &sql)?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub id: String,
    pub expected: AuthorityStamp,
    pub authoring_revision: String,
    pub note: String,
}

fn bounded_note(note: &str) -> Result<()> {
    ensure!(
        !note.trim().is_empty() && note.len() <= 4000 && !note.contains('\0'),
        "resource_review_note_required"
    );
    Ok(())
}

fn proposed_document(
    instance: &Instance,
    runtime: &Runtime,
    active: &AuthorityDocument,
) -> Result<AuthorityDocument> {
    let mut scoped = instance.clone();
    let binding = scoped
        .apps
        .get_mut(runtime.app())
        .context("app_not_installed")?;
    binding.readers = active.readers.clone();
    binding.writers = active.writers.clone();
    binding.authority = active.policy.clone();
    let desired = AuthorityDocument::resolve(&scoped, runtime.app(), runtime.artifact())?;
    // Resource administration cannot modify app memberships, coarse operation
    // rights, artifact selection, or resurrect a disabled application.
    let mut document = active.clone();
    document.resources = desired.resources;
    document.validate(runtime.artifact())?;
    Ok(document)
}

pub fn preview(path: &Path, app: &str, operator: &str) -> Result<Value> {
    let (instance, authoring) = read_authoring(path)?;
    app_operator(&instance, app, operator)?;
    let runtime = Runtime::load(path, app)?;
    let mut db = open(runtime.db())?;
    let tx = db.transaction()?;
    let active = authority_state::current(&tx)?;
    let proposed = proposed_document(&instance, &runtime, &active.document);
    let validation_error = proposed.as_ref().err().map(ToString::to_string);
    let mut documents = vec![&active.document];
    if let Ok(document) = &proposed {
        documents.push(document);
    }
    let review_requires_administrator = may_review(&instance, app, operator, &documents).is_err();
    Ok(
        json!({"app":app,"authoring_revision":authoring.revision,"expected":active.stamp,
        "artifact":active.artifact_id,"active":visible_resources(&instance,operator,&active.document.resources),"proposed":proposed.as_ref().ok().map(|document|visible_resources(&instance,operator,&document.resources)),
        "changed":proposed.as_ref().is_ok_and(|document|active.document.resources != document.resources),"validation_error":validation_error,
        "enabled":active.document.enabled,"usage":if review_requires_administrator {None} else {Some(crate::budget::inspect_in(&tx)?)},"review_requires_administrator":review_requires_administrator,
        "operations":runtime.artifact().contract().operations.iter().map(|operation| &operation.name).collect::<Vec<_>>()}),
    )
}

pub fn propose(path: &Path, app: &str, operator: &str, proposal: &Proposal) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    let (instance, authoring) = read_authoring(path)?;
    app_operator(&instance, app, operator)?;
    bounded_note(&proposal.note)?;
    ensure!(
        !proposal.id.is_empty()
            && proposal.id.len() <= 100
            && proposal
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid_resource_review_id"
    );
    ensure!(
        authoring.revision == proposal.authoring_revision,
        "resource_authoring_changed"
    );
    let runtime = Runtime::load(path, app)?;
    let mut db = open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut db)?;
    upgrade(&tx)?;
    let active = authority_state::current(&tx)?;
    let document = proposed_document(&instance, &runtime, &active.document)?;
    may_propose(&instance, app, operator, &active.document, &document)?;
    let fingerprint = crate::digest(&serde_json::to_vec(&(
        operator,
        proposal,
        &document,
        &active.artifact_id,
    ))?);
    let previous: Option<String> = tx
        .query_row(
            "SELECT fingerprint FROM day2_resource_reviews WHERE id=?1",
            [&proposal.id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(previous) = previous {
        ensure!(
            previous == fingerprint,
            "resource_review_idempotency_conflict"
        );
    } else {
        ensure!(
            active.stamp == proposal.expected,
            "authority_policy_changed"
        );
        tx.execute(
            "INSERT INTO day2_resource_reviews VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                proposal.id,
                fingerprint,
                operator,
                now_ms()?,
                proposal.authoring_revision,
                active.artifact_id,
                serde_json::to_string(&proposal.expected)?,
                serde_json::to_string(&document)?,
                proposal.note
            ],
        )?;
    }
    tx.commit()?;
    reviews(path, app, operator)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub review: String,
    pub decision: String,
    pub reason: String,
    /// Explicit review of combined source, destination, principal and usage.
    pub reviewed_data_movement: bool,
}

pub fn decide(path: &Path, app: &str, operator: &str, decision: &Decision) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    let (instance, _) = read_authoring(path)?;
    app_operator(&instance, app, operator)?;
    ensure!(
        ["approve", "deny"].contains(&decision.decision.as_str()),
        "invalid_resource_review_decision"
    );
    bounded_note(&decision.reason)?;
    let runtime = Runtime::load(path, app)?;
    let mut db = open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut db)?;
    upgrade(&tx)?;
    let previous: Option<(String,String,String,Option<String>)> = tx.query_row("SELECT operator,decision,reason,receipt FROM day2_resource_review_decisions WHERE review=?1", [&decision.review], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    if let Some((actor, action, reason, receipt)) = previous {
        ensure!(
            actor == operator && action == decision.decision && reason == decision.reason,
            "resource_review_already_decided"
        );
        return Ok(
            json!({"decision":action,"receipt":receipt.map(|raw| crate::json::decode::<Value>(raw.as_bytes())).transpose()?}),
        );
    }
    let (artifact, expected, raw): (String, String, String) = tx.query_row(
        "SELECT artifact,expected,document FROM day2_resource_reviews WHERE id=?1",
        [&decision.review],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let document: AuthorityDocument = crate::json::decode(raw.as_bytes())?;
    let current = authority_state::current(&tx)?;
    may_review(&instance, app, operator, &[&current.document, &document])?;
    let receipt = if decision.decision == "approve" {
        ensure!(
            decision.reviewed_data_movement,
            "resource_data_movement_review_required"
        );
        ensure!(
            artifact == runtime.artifact().id(),
            "resource_artifact_changed_repropose"
        );
        ensure!(
            proposed_document(&instance, &runtime, &current.document)? == document,
            "resource_review_binding_changed"
        );
        let change = ApplyAuthority {
            request_id: format!("resource-review-{}", decision.review),
            expected: Some(crate::json::decode(expected.as_bytes())?),
            document,
        };
        Some(authority_state::apply_binding_in(
            &tx,
            &runtime,
            runtime.artifact(),
            &LocalOperator::assert_local(operator)?,
            &change,
        )?)
    } else {
        None
    };
    tx.execute(
        "INSERT INTO day2_resource_review_decisions VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            decision.review,
            operator,
            now_ms()?,
            decision.decision,
            decision.reason,
            receipt.as_ref().map(serde_json::to_string).transpose()?
        ],
    )?;
    tx.commit()?;
    Ok(json!({"decision":decision.decision,"receipt":receipt}))
}

pub fn reviews(path: &Path, app: &str, operator: &str) -> Result<Value> {
    let instance = Instance::load(path)?;
    app_operator(&instance, app, operator)?;
    let runtime = Runtime::load(path, app)?;
    let db = open(runtime.db())?;
    upgrade(&db)?;
    let mut query = db.prepare("SELECT r.id,r.author,r.created_ms,r.note,r.expected,r.document,d.operator,d.decision,d.reason,d.receipt FROM day2_resource_reviews r LEFT JOIN day2_resource_review_decisions d ON r.id=d.review ORDER BY r.created_ms DESC,r.id LIMIT 200")?;
    let rows = query.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, Option<String>>(6)?,
            r.get::<_, Option<String>>(7)?,
            r.get::<_, Option<String>>(8)?,
            r.get::<_, Option<String>>(9)?,
        ))
    })?;
    let mut entries = Vec::new();
    for row in rows {
        let (id, author, created, note, expected, document, reviewer, decision, reason, receipt) =
            row?;
        let document: AuthorityDocument = crate::json::decode(document.as_bytes())?;
        let requires_administrator = may_review(&instance, app, operator, &[&document]).is_err();
        if requires_administrator && author != operator {
            continue;
        }
        entries.push(json!({"id":id,"author":author,"created_ms":created,"note":note,"expected":crate::json::decode::<Value>(expected.as_bytes())?,"resources":visible_resources(&instance,operator,&document.resources),"requires_administrator":requires_administrator,"reviewer":reviewer,"decision":decision,"reason":reason,"receipt":receipt.map(|raw| crate::json::decode::<Value>(raw.as_bytes())).transpose()?}));
    }
    Ok(json!({"app":app,"reviews":entries,"limit":200}))
}

pub fn now_ms() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

/// Reviews serialize with supported catalog writers. A completed delegation
/// revocation therefore precedes every subsequent approval admission.
fn lock_authoring(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = path.canonicalize()?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(
            path.parent()
                .context("instance_directory")?
                .join(".resource-authoring.lock"),
        )?;
    file.lock_shared()?;
    Ok(file)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allocate {
    pub id: String,
    pub budget: String,
    pub limits: day2_capabilities::resources::BudgetLimits,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompanyLedgerIdentity {
    installation: String,
    environment: String,
    allocator: String,
}

fn company_allocator(path: &Path, operator: &LocalOperator) -> Result<crate::budget::Allocator> {
    let instance = Instance::load(path)?;
    let parent = path.parent().context("instance_directory")?;
    let raw = fs::read(parent.join(".resource-company-budget.json"))
        .context("company_budget_setup_required")?;
    ensure!(raw.len() < 4096, "company_budget_identity_budget");
    let identity: CompanyLedgerIdentity = crate::json::decode(&raw)?;
    ensure!(
        identity.installation == instance.installation
            && identity.environment == instance.environment,
        "company_budget_scope_mismatch"
    );
    crate::budget::Allocator::open_expected(
        &parent.join(".state/company-budget.sqlite"),
        operator,
        &identity.allocator,
    )
}

/// Explicit one-time provisioning. Neither a missing central ledger nor an app
/// restore can invoke this implicitly and silently reset the company pool.
pub fn setup_company_budget(path: &Path, operator: &str) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let instance = Instance::load(path)?;
    administrator(&instance, operator)?;
    let path = path.canonicalize()?;
    let parent = path.parent().context("instance_directory")?;
    let operator = LocalOperator::assert_local(operator)?;
    let marker = parent.join(".resource-company-budget.json");
    if marker.exists() {
        return Ok(json!({"allocator":company_allocator(&path,&operator)?.id()?}));
    }
    let state = parent.join(".state");
    fs::create_dir_all(&state)?;
    ensure!(
        !fs::symlink_metadata(&state)?.file_type().is_symlink(),
        "state_directory_symlink"
    );
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    let allocator =
        crate::budget::Allocator::create(&state.join("company-budget.sqlite"), &operator)?;
    let identity = CompanyLedgerIdentity {
        installation: instance.installation,
        environment: instance.environment,
        allocator: allocator.id()?,
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(marker)?;
    file.write_all(&serde_json::to_vec(&identity)?)?;
    file.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    Ok(json!({"allocator":identity.allocator}))
}

/// Installs disjoint company capacity, never a duplicate copy of the company cap.
/// A retry after a central commit imports the same immutable allocation.
pub fn allocate(path: &Path, app: &str, operator: &str, request: &Allocate) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    administrator(&Instance::load(path)?, operator)?;
    let runtime = Runtime::load(path, app)?;
    let operator = LocalOperator::assert_local(operator)?;
    let mut db = open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut db)?;
    let active = authority_state::current(&tx)?;
    let ledger = crate::budget::inspect_in(&tx)?;
    let mut allocator = company_allocator(path, &operator)?;
    let receipt = if let Some(receipt) = allocator.receipt(&request.id)? {
        ensure!(
            receipt.budget_id == request.budget
                && receipt.ledger_id == ledger.ledger_id
                && receipt.limits == request.limits,
            "budget_allocation_conflict"
        );
        receipt
    } else {
        let definition = active
            .document
            .resources
            .budgets
            .get(&request.budget)
            .context("active_budget_missing")?;
        definition.validate()?;
        let now = now_ms()? / 1000;
        let period = i64::try_from(definition.period_seconds)?;
        allocator.allocate(
            &crate::budget::AllocationRequest {
                id: request.id.clone(),
                budget_id: request.budget.clone(),
                definition: definition.clone(),
                window_start: now - now.rem_euclid(period),
                ledger_id: ledger.ledger_id,
                limits: request.limits.clone(),
            },
            &operator,
        )?
    };
    crate::budget::install_allocation_in(&tx, &allocator, &receipt, &operator)?;
    tx.commit()?;
    Ok(json!({"receipt":receipt,"company":allocator.inspect()?}))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recover {
    pub id: String,
    /// New fixed company capacity, charged again to the surviving allocator.
    pub allocations: BTreeMap<String, day2_capabilities::resources::BudgetLimits>,
}

pub fn recover_budget(path: &Path, app: &str, operator: &str, request: &Recover) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    let instance = Instance::load(path)?;
    administrator(&instance, operator)?;
    ensure!(
        !request.id.is_empty() && request.id.len() <= 100,
        "invalid_recovery_id"
    );
    let runtime = Runtime::load(path, app)?;
    let operator = LocalOperator::assert_local(operator)?;
    let mut db = open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut db)?;
    let ledger = crate::budget::prepare_restore_recovery_in(&tx, &operator)?;
    tx.commit()?;
    let mut allocator = if request.allocations.is_empty() {
        None
    } else {
        Some(company_allocator(path, &operator)?)
    };
    let mut receipts = Vec::new();
    for (budget, limits) in &request.allocations {
        let allocation_id = format!("recovery-{}-{budget}", request.id);
        if let Some(receipt) = allocator
            .as_ref()
            .context("company_budget_required")?
            .receipt(&allocation_id)?
        {
            ensure!(
                receipt.budget_id == *budget
                    && receipt.ledger_id == ledger
                    && receipt.limits == *limits,
                "budget_allocation_conflict"
            );
            receipts.push(receipt);
            continue;
        }
        let definition = instance
            .resources
            .as_ref()
            .context("resource_catalog_required")?
            .budgets
            .get(budget)
            .context("resource_budget_missing")?;
        definition.validate()?;
        let now = now_ms()? / 1000;
        let period = i64::try_from(definition.period_seconds)?;
        receipts.push(
            allocator
                .as_mut()
                .context("company_budget_required")?
                .allocate(
                    &crate::budget::AllocationRequest {
                        id: allocation_id,
                        budget_id: budget.clone(),
                        definition: definition.clone(),
                        window_start: now - now.rem_euclid(period),
                        ledger_id: ledger.clone(),
                        limits: limits.clone(),
                    },
                    &operator,
                )?,
        );
    }
    let tx = crate::write_queue::immediate(&mut db)?;
    let ledger = crate::budget::recover_restored_in(&tx, allocator.as_ref(), &receipts, &operator)?;
    let usage = crate::budget::inspect_in(&tx)?;
    tx.commit()?;
    Ok(json!({"ledger":ledger,"usage":usage,"allocations":receipts}))
}

pub fn resolve_overruns(
    path: &Path,
    app: &str,
    operator: &str,
    request: &crate::budget::OverrunResolution,
) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    administrator(&Instance::load(path)?, operator)?;
    let runtime = Runtime::load(path, app)?;
    let mut db = open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut db)?;
    let receipt =
        crate::budget::resolve_overruns_in(&tx, &LocalOperator::assert_local(operator)?, request)?;
    let usage = crate::budget::inspect_in(&tx)?;
    tx.commit()?;
    Ok(json!({"receipt":receipt,"usage":usage}))
}

pub fn reconcile_usage(
    path: &Path,
    app: &str,
    operator: &str,
    request: &crate::budget::UsageReconciliation,
) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    administrator(&Instance::load(path)?, operator)?;
    let runtime = Runtime::load(path, app)?;
    let mut db = open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut db)?;
    authority_state::current(&tx)?;
    crate::budget::upgrade(&tx)?;
    let receipt =
        crate::budget::reconcile_usage_in(&tx, &LocalOperator::assert_local(operator)?, request)?;
    let usage = crate::budget::inspect_in(&tx)?;
    tx.commit()?;
    Ok(json!({"receipt":receipt,"usage":usage}))
}

/// Company allocation review is administrator-only. Unreachable apps are shown
/// as unavailable; their central capacity is never assumed unused.
pub fn company_budget(path: &Path, operator: &str) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    let instance = Instance::load(path)?;
    administrator(&instance, operator)?;
    let operator = LocalOperator::assert_local(operator)?;
    let mut allocator = company_allocator(path, &operator)?;
    let pool = allocator.overview()?;
    let mut apps = BTreeMap::new();
    for app in instance.apps.keys() {
        let inspect = || -> Result<Value> {
            let runtime = Runtime::load(path, app)?;
            ensure!(runtime.db().is_file(), "budget_ledger_unavailable");
            let mut db = open(runtime.db())?;
            let tx = db.transaction()?;
            let usage = crate::budget::inspect_in(&tx)?;
            tx.commit()?;
            Ok(json!({"usage":usage}))
        };
        apps.insert(
            app,
            inspect().unwrap_or_else(|_| json!({"unavailable":true})),
        );
    }
    Ok(json!({"pool":pool,"apps":apps,"now_seconds":now_ms()? / 1000}))
}

pub fn propose_pool_reduction(
    path: &Path,
    operator: &str,
    request: &crate::budget::PoolReductionRequest,
) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    administrator(&Instance::load(path)?, operator)?;
    let operator = LocalOperator::assert_local(operator)?;
    let mut allocator = company_allocator(path, &operator)?;
    // The reviewed current window must still be current on first submission.
    // Cached retries preserve their original window and exact request identity.
    if allocator.reduction(&request.id).is_err() {
        let period = i64::try_from(request.definition.period_seconds)?;
        ensure!(period > 0, "invalid_budget_period");
        let now = now_ms()? / 1000;
        ensure!(
            request.effective_window == now - now.rem_euclid(period),
            "budget_pool_review_window_changed"
        );
    }
    let proposal = allocator.propose_reduction(request, &operator)?;
    Ok(json!({"proposal":proposal}))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnCompanyCapacity {
    pub reduction: String,
    pub ledger_id: String,
}

pub fn return_company_capacity(
    path: &Path,
    app: &str,
    operator: &str,
    request: &ReturnCompanyCapacity,
) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    administrator(&Instance::load(path)?, operator)?;
    let operator = LocalOperator::assert_local(operator)?;
    let runtime = Runtime::load(path, app)?;
    let mut db = open(runtime.db())?;
    let mut allocator = company_allocator(path, &operator)?;
    let tx = crate::write_queue::immediate(&mut db)?;
    authority_state::current(&tx)?;
    crate::budget::upgrade(&tx)?;
    let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM day2_budget_capacity_returns WHERE reduction_id=?1 AND ledger_id=?2)", params![request.reduction, request.ledger_id], |row| row.get(0))?;
    if !exists {
        ensure!(
            crate::budget::inspect_in(&tx)?.ledger_id == request.ledger_id,
            "budget_allocation_ledger_mismatch"
        );
        crate::budget::return_capacity_in(&tx, &allocator, &request.reduction, &operator)?;
    }
    tx.commit()?;
    let receipt =
        allocator.acknowledge_return(&db, &request.reduction, &request.ledger_id, &operator)?;
    Ok(json!({"receipt":receipt,"status":allocator.reduction(&request.reduction)?}))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecidePoolReduction {
    pub reduction: String,
    pub complete: bool,
}

pub fn decide_pool_reduction(
    path: &Path,
    operator: &str,
    request: &DecidePoolReduction,
) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    administrator(&Instance::load(path)?, operator)?;
    let operator = LocalOperator::assert_local(operator)?;
    let receipt = company_allocator(path, &operator)?.decide_reduction(
        &request.reduction,
        request.complete,
        &operator,
    )?;
    Ok(json!({"receipt":receipt}))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportPoolReduction {
    pub reduction: String,
}

pub fn import_pool_reduction(
    path: &Path,
    app: &str,
    operator: &str,
    request: &ImportPoolReduction,
) -> Result<Value> {
    let _authoring_guard = lock_authoring(path)?;
    administrator(&Instance::load(path)?, operator)?;
    let operator = LocalOperator::assert_local(operator)?;
    let runtime = Runtime::load(path, app)?;
    let mut db = open(runtime.db())?;
    let allocator = company_allocator(path, &operator)?;
    let tx = crate::write_queue::immediate(&mut db)?;
    let receipt =
        crate::budget::install_pool_reduction_in(&tx, &allocator, &request.reduction, &operator)?;
    tx.commit()?;
    Ok(json!({"receipt":receipt}))
}
