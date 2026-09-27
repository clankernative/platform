//! Host-issued capability handles. A name resolves only in the current
//! operation's activated bindings, never in a provider-wide resource registry.
use crate::{
    authority_state::{self, AuthorityStamp},
    error::Failure,
    protocol::{Instruction, Observation, Request},
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::resources::{
    Action, BudgetDefinition, BudgetScope, Limits, ResolvedGrant, ResourceTarget, TopicScope,
};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::collections::BTreeSet;

pub const BIND: &str = "resources.bind.v1";
pub const ATTENUATE: &str = "resources.attenuate.v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Claims {
    invocation: String,
    root: String,
    operation: String,
    actor: String,
    artifact: String,
    scope: String,
    authority: AuthorityStamp,
    binding: String,
    grant: ResolvedGrant,
    parent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ResourceUse {
    pub handle: String,
    pub actor: String,
    pub binding: String,
    pub grant: ResolvedGrant,
    pub root: String,
    pub authority: AuthorityStamp,
    pub action: Action,
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub planned_calls: u64,
}

fn one() -> u64 {
    1
}
fn is_one(value: &u64) -> bool {
    *value == 1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    binding: String,
    invocation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportedContractRef {
    pub operation: String,
    pub digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportedQuery {
    pub contract: ImportedContractRef,
    pub input: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attenuation {
    handle: String,
    #[serde(default)]
    actions: Option<BTreeSet<Action>>,
    #[serde(default)]
    topics: Option<TopicScope>,
    #[serde(default)]
    limits: Option<Limits>,
    #[serde(default)]
    expires_at_ms: Option<i64>,
}

pub(crate) fn upgrade(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_resource_handles (
            token TEXT PRIMARY KEY, invocation TEXT NOT NULL REFERENCES day2_invocations(id),
            claims TEXT NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_resource_roots (
            invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id), root TEXT NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_resource_root_budgets (
            root TEXT NOT NULL, id TEXT NOT NULL, definition TEXT NOT NULL,
            PRIMARY KEY(root,id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_resource_uses (
            attempt TEXT PRIMARY KEY, handle TEXT NOT NULL REFERENCES day2_resource_handles(token),
            provenance TEXT NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_resource_correlations (
            attempt TEXT PRIMARY KEY REFERENCES day2_resource_uses(attempt),
            exchanges TEXT NOT NULL
        ) STRICT;
        CREATE TRIGGER IF NOT EXISTS day2_resource_correlations_no_update
        BEFORE UPDATE ON day2_resource_correlations BEGIN SELECT RAISE(ABORT,'provider_correlation_immutable'); END;
        CREATE TRIGGER IF NOT EXISTS day2_resource_correlations_no_delete
        BEFORE DELETE ON day2_resource_correlations BEGIN SELECT RAISE(ABORT,'provider_correlation_immutable'); END;",
    )?;
    Ok(())
}

/// Retain bounded provider support identifiers beside the host attempt. These
/// are diagnostic evidence, never authority to repeat or complete an effect.
pub(crate) fn record_correlation_in(
    connection: &Connection,
    attempt: &str,
    exchanges: &[crate::integrations::ExchangeCorrelation],
) -> Result<()> {
    ensure!(exchanges.len() <= 2, "provider_correlation_budget");
    let encoded = serde_json::to_string(exchanges)?;
    ensure!(encoded.len() <= 4096, "provider_correlation_budget");
    let existing: Option<String> = connection
        .query_row(
            "SELECT exchanges FROM day2_resource_correlations WHERE attempt=?1",
            [attempt],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        ensure!(existing == encoded, "provider_correlation_conflict");
    } else {
        connection.execute(
            "INSERT INTO day2_resource_correlations VALUES(?1,?2)",
            params![attempt, encoded],
        )?;
    }
    Ok(())
}

/// Journal limits include JSON escaping and the original instruction. Retain a
/// small failure when content cannot fit, so known provider usage still settles.
pub(crate) fn bounded_observation(
    mut observation: crate::protocol::Observation,
) -> Result<crate::protocol::Observation> {
    if serde_json::to_vec(&observation)?.len() > 65_536 {
        observation.result.clear();
        observation.error = "provider_result_journal_budget".into();
    }
    ensure!(
        serde_json::to_vec(&observation)?.len() <= 65_536,
        "provider_instruction_journal_budget"
    );
    Ok(observation)
}

pub(crate) fn require_journalable_instruction(
    instruction: &crate::protocol::Instruction,
) -> Result<()> {
    bounded_observation(crate::protocol::Observation {
        instruction: instruction.clone(),
        result: String::new(),
        error: "provider_result_journal_budget".into(),
    })?;
    Ok(())
}

pub(crate) fn root_in(connection: &Connection, invocation: &str) -> Result<String> {
    if let Some(root) = connection
        .query_row(
            "SELECT root FROM day2_resource_roots WHERE invocation=?1",
            [invocation],
            |row| row.get(0),
        )
        .optional()?
    {
        return Ok(root);
    }
    let mut root = invocation.to_owned();
    for _ in 0..128 {
        let parent: Option<String> = connection
            .query_row(
                "SELECT parent FROM day2_command_requests WHERE id=?1",
                [&root],
                |row| row.get(0),
            )
            .optional()?;
        match parent {
            Some(parent) => {
                ensure!(parent != root, "resource_lineage_cycle");
                root = parent;
            }
            None => {
                connection.execute(
                    "INSERT INTO day2_resource_roots VALUES(?1,?2)",
                    params![invocation, root],
                )?;
                return Ok(root);
            }
        }
    }
    anyhow::bail!("resource_lineage_budget")
}

pub(crate) fn inherit_root(connection: &Connection, child: &str, parent: &str) -> Result<()> {
    let root = root_in(connection, parent)?;
    connection.execute(
        "INSERT INTO day2_resource_roots VALUES(?1,?2)",
        params![child, root],
    )?;
    Ok(())
}

/// Root-wide obligations are captured at acceptance, including grants the
/// parent never binds. Descendants can add obligations but cannot omit them.
pub(crate) fn capture_root_budgets(
    connection: &Connection,
    invocation: &str,
    operation: &str,
    authority: &authority_state::ActiveAuthority,
) -> Result<()> {
    let root = root_in(connection, invocation)?;
    if let Some(grants) = authority.document.resources.operations.get(operation) {
        for grant in grants.values() {
            for reference in &grant.budgets {
                let definition = authority
                    .document
                    .resources
                    .budgets
                    .get(&reference.id)
                    .context("resource_budget_missing")?;
                ensure!(
                    definition.revision == reference.revision,
                    "resource_budget_revision_mismatch"
                );
                if definition.scope != BudgetScope::InvocationRoot {
                    continue;
                }
                let encoded = serde_json::to_string(definition)?;
                connection.execute(
                    "INSERT OR IGNORE INTO day2_resource_root_budgets VALUES(?1,?2,?3)",
                    params![root, reference.id, encoded],
                )?;
                let stored: String = connection.query_row(
                    "SELECT definition FROM day2_resource_root_budgets WHERE root=?1 AND id=?2",
                    params![root, reference.id],
                    |row| row.get(0),
                )?;
                ensure!(stored == encoded, "resource_root_budget_changed");
            }
        }
    }
    Ok(())
}

fn issue(connection: &Connection, claims: Claims) -> Result<String> {
    let encoded = serde_json::to_string(&claims)?;
    let seed: Vec<u8> = connection.query_row(
        "SELECT seed FROM day2_id_seeds WHERE invocation=?1",
        [&claims.invocation],
        |row| row.get(0),
    )?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&seed).context("resource_handle_key")?;
    mac.update(b"day2-resource-handle-v1\0");
    mac.update(encoded.as_bytes());
    let digest = mac.finalize().into_bytes();
    let token = format!(
        "resource_{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    connection.execute(
        "INSERT OR IGNORE INTO day2_resource_handles VALUES(?1,?2,?3)",
        params![token, claims.invocation, encoded],
    )?;
    let stored: String = connection.query_row(
        "SELECT claims FROM day2_resource_handles WHERE token=?1",
        [&token],
        |row| row.get(0),
    )?;
    ensure!(stored == encoded, "resource_handle_collision");
    Ok(json!({"token":token}).to_string())
}

fn topic_subset(child: &TopicScope, parent: &TopicScope) -> bool {
    match (child, parent) {
        (_, TopicScope::Any) => true,
        (TopicScope::Only { topics: child }, TopicScope::Only { topics: parent }) => {
            child.is_subset(parent)
        }
        (TopicScope::Only { topics }, TopicScope::Prefix { prefix }) => {
            topics.iter().all(|topic| topic.starts_with(prefix))
        }
        (TopicScope::Prefix { prefix: child }, TopicScope::Prefix { prefix: parent }) => {
            child.starts_with(parent)
        }
        _ => false,
    }
}

fn narrower(child: &ResolvedGrant, parent: &ResolvedGrant) -> bool {
    child.policy == parent.policy
        && child.resource == parent.resource
        && child.connection == parent.connection
        && child.provider == parent.provider
        && child.live == parent.live
        && child.actors == parent.actors
        && child.budgets == parent.budgets
        && child.actions.is_subset(&parent.actions)
        && child.limits.max_request_bytes <= parent.limits.max_request_bytes
        && child.limits.max_response_bytes <= parent.limits.max_response_bytes
        && child.limits.max_calls_per_invocation <= parent.limits.max_calls_per_invocation
        && match (child.expires_at_ms, parent.expires_at_ms) {
            (Some(child), Some(parent)) => child <= parent,
            (_, None) => true,
            (None, Some(_)) => false,
        }
        && match (&child.target, &parent.target) {
            (
                ResourceTarget::NotificationMailbox { topics: child },
                ResourceTarget::NotificationMailbox { topics: parent },
            ) => topic_subset(child, parent),
            (
                ResourceTarget::CartaIssuer { issuer_id: child },
                ResourceTarget::CartaIssuer { issuer_id: parent },
            ) => child == parent,
            (child, parent) => child.is_subset_of(parent),
        }
}

fn load(
    connection: &Connection,
    runtime: &Runtime,
    request: &Request,
    token: &str,
) -> Result<Claims> {
    ensure!(
        token.starts_with("resource_") && token.len() == 73,
        Failure::ResourceForbidden
    );
    let encoded: String = connection
        .query_row(
            "SELECT claims FROM day2_resource_handles WHERE token=?1",
            [token],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(Failure::ResourceForbidden)?;
    let claims: Claims = crate::json::decode(encoded.as_bytes())?;
    let active = authority_state::require_invocation_in(
        connection,
        runtime,
        &request.context.invocation_id,
        &request.operation,
        &request.context.actor,
    )?;
    ensure!(
        claims.invocation == request.context.invocation_id
            && claims.operation == request.operation
            && claims.actor == request.context.actor
            && claims.artifact == runtime.artifact().id()
            && claims.scope == runtime.scope()
            && claims.authority == active.stamp,
        Failure::ResourceForbidden
    );
    let grant = active
        .document
        .resources
        .operations
        .get(&runtime.artifact().route(&request.operation)?.name)
        .and_then(|slots| slots.get(&claims.binding))
        .ok_or(Failure::ResourceForbidden)?;
    ensure!(narrower(&claims.grant, grant), Failure::ResourceForbidden);
    ensure!(
        claims.grant.actors.contains(&request.context.actor),
        Failure::ResourceForbidden
    );
    ensure!(
        claims
            .grant
            .expires_at_ms
            .is_none_or(|expiry| runtime.host().now_ms().is_ok_and(|now| now < expiry)),
        Failure::ResourceAuthorityExpired
    );
    Ok(claims)
}

pub(crate) fn host_operation(
    connection: &Connection,
    runtime: &Runtime,
    request: &Request,
    instruction: &Instruction,
) -> Result<Option<String>> {
    if instruction.model == BIND {
        let binding: Binding = crate::json::decode(instruction.data.as_bytes())?;
        ensure!(
            binding.invocation == request.context.invocation_id,
            Failure::ResourceForbidden
        );
        let active = authority_state::require_invocation_in(
            connection,
            runtime,
            &request.context.invocation_id,
            &request.operation,
            &request.context.actor,
        )?;
        let grant = active
            .document
            .resources
            .operations
            .get(&runtime.artifact().route(&request.operation)?.name)
            .and_then(|slots| slots.get(&binding.binding))
            .ok_or(Failure::ResourceForbidden)?
            .clone();
        ensure!(
            grant.actors.contains(&request.context.actor),
            Failure::ResourceForbidden
        );
        ensure!(
            grant
                .expires_at_ms
                .is_none_or(|expiry| runtime.host().now_ms().is_ok_and(|now| now < expiry)),
            Failure::ResourceAuthorityExpired
        );
        let root = root_in(connection, &request.context.invocation_id)?;
        return Ok(Some(issue(
            connection,
            Claims {
                invocation: request.context.invocation_id.clone(),
                root,
                operation: request.operation.clone(),
                actor: request.context.actor.clone(),
                artifact: runtime.artifact().id().into(),
                scope: runtime.scope().into(),
                authority: active.stamp,
                binding: binding.binding,
                grant,
                parent: None,
            },
        )?));
    }
    if instruction.model == ATTENUATE {
        let attenuation: Attenuation = crate::json::decode(instruction.data.as_bytes())?;
        let mut claims = load(connection, runtime, request, &attenuation.handle)?;
        let parent = claims.grant.clone();
        if let Some(actions) = attenuation.actions {
            claims.grant.actions = actions;
        }
        if let Some(topics) = attenuation.topics {
            match &mut claims.grant.target {
                ResourceTarget::NotificationMailbox { topics: selected }
                | ResourceTarget::OperatorAlertDestination {
                    topics: selected, ..
                } => *selected = topics,
                _ => anyhow::bail!(Failure::ResourceForbidden),
            }
        }
        if let Some(limits) = attenuation.limits {
            claims.grant.limits = limits;
        }
        if let Some(expiry) = attenuation.expires_at_ms {
            claims.grant.expires_at_ms = Some(expiry);
        }
        ensure!(narrower(&claims.grant, &parent), Failure::ResourceForbidden);
        claims.parent = Some(attenuation.handle);
        return Ok(Some(issue(connection, claims)?));
    }
    Ok(None)
}

pub(crate) fn authorize(
    connection: &Connection,
    runtime: &Runtime,
    request: &Request,
    instruction: &Instruction,
    action: Action,
) -> Result<ResourceUse> {
    let value: serde_json::Value = crate::json::decode(instruction.data.as_bytes())?;
    let issued = if value.get("contract").is_some() {
        ensure!(action == Action::DelegateQuery, Failure::ResourceForbidden);
        let imported: ImportedQuery = crate::json::decode(instruction.data.as_bytes())?;
        let package = runtime
            .artifact()
            .contract()
            .imports
            .as_ref()
            .and_then(|imports| imports.operations.get(&imported.contract.operation))
            .ok_or(Failure::ResourceForbidden)?;
        ensure!(
            package.digest == imported.contract.digest
                && package.operation.kind == crate::operation_contract::Kind::Query,
            Failure::ResourceForbidden
        );
        let (app, _) = imported
            .contract
            .operation
            .split_once('.')
            .ok_or(Failure::ResourceForbidden)?;
        ensure!(app != runtime.app(), Failure::ResourceForbidden);
        let active = authority_state::require_invocation_in(
            connection,
            runtime,
            &request.context.invocation_id,
            &request.operation,
            &request.context.actor,
        )?;
        let grants = active
            .document
            .resources
            .operations
            .get(&runtime.artifact().route(&request.operation)?.name)
            .ok_or(Failure::ResourceForbidden)?;
        let mut matches = grants.iter().filter(|(_, grant)| {
            matches!(
                &grant.target,
                ResourceTarget::AppOperation { app: target, operation, .. }
                    if target == app && operation == &imported.contract.operation
            ) && grant.provider == day2_capabilities::resources::Provider::LocalDelegation
                && grant.actions.contains(&Action::DelegateQuery)
        });
        let (binding, grant) = matches.next().ok_or(Failure::ResourceForbidden)?;
        ensure!(matches.next().is_none(), Failure::ResourceForbidden);
        ensure!(
            grant.actors.contains(&request.context.actor),
            Failure::ResourceForbidden
        );
        ensure!(
            grant
                .expires_at_ms
                .is_none_or(|expiry| runtime.host().now_ms().is_ok_and(|now| now < expiry)),
            Failure::ResourceAuthorityExpired
        );
        let root = root_in(connection, &request.context.invocation_id)?;
        let response = issue(
            connection,
            Claims {
                invocation: request.context.invocation_id.clone(),
                root,
                operation: request.operation.clone(),
                actor: request.context.actor.clone(),
                artifact: runtime.artifact().id().into(),
                scope: runtime.scope().into(),
                authority: active.stamp,
                binding: binding.clone(),
                grant: grant.clone(),
                parent: None,
            },
        )?;
        Some(
            serde_json::from_str::<serde_json::Value>(&response)?["token"]
                .as_str()
                .ok_or(Failure::ResourceForbidden)?
                .to_owned(),
        )
    } else {
        None
    };
    let token = issued
        .as_deref()
        .or_else(|| value.get("handle").and_then(|handle| handle.as_str()))
        .ok_or(Failure::ResourceForbidden)?;
    let claims = load(connection, runtime, request, token)?;
    // Nothing an application invokes destroys anything. This is the choke point
    // every app-invoked capability passes through, so the rule is stated once
    // here rather than in each provider's branch — and a grant that names a
    // destroying action still cannot be used to reach it. Removal belongs to the
    // operator retention path, which does not come through an app instruction.
    // See docs/DELETION.md.
    ensure!(!action.destroys_data(), Failure::CapabilityForbidden);
    ensure!(
        claims.grant.actions.contains(&action),
        Failure::ResourceForbidden
    );
    ensure!(
        instruction.data.len() as u64 <= claims.grant.limits.max_request_bytes,
        Failure::ResourceLimitExceeded
    );
    Ok(ResourceUse {
        handle: token.into(),
        actor: claims.actor,
        binding: claims.binding,
        grant: claims.grant,
        root: claims.root,
        authority: claims.authority,
        action,
        planned_calls: 1,
    })
}

pub(crate) fn record_use(
    connection: &Connection,
    attempt: &str,
    resource: &ResourceUse,
) -> Result<()> {
    let provenance = serde_json::to_string(resource)?;
    let existing: Option<String> = connection
        .query_row(
            "SELECT provenance FROM day2_resource_uses WHERE attempt=?1",
            [attempt],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        ensure!(existing == provenance, "resource_attempt_conflict");
        return Ok(());
    }
    // Sibling attenuations share the original grant's invocation counter. Issuing
    // another handle must never multiply the declared allowance.
    let count: i64 = connection.query_row(
        "SELECT coalesce(sum(coalesce(json_extract(u.provenance,'$.planned_calls'),1)),0) FROM day2_resource_uses u JOIN day2_resource_handles h ON h.token=u.handle WHERE h.invocation=(SELECT invocation FROM day2_resource_handles WHERE token=?1) AND json_extract(u.provenance,'$.grant.resource.id')=?2 AND json_extract(u.provenance,'$.grant.policy.id')=?3",
        params![resource.handle,resource.grant.resource.id,resource.grant.policy.id],|row|row.get(0),
    )?;
    ensure!(
        resource.planned_calls > 0
            && u64::try_from(count)?
                .checked_add(resource.planned_calls)
                .is_some_and(|total| total <= resource.grant.limits.max_calls_per_invocation),
        Failure::ResourceLimitExceeded
    );
    connection.execute(
        "INSERT INTO day2_resource_uses VALUES(?1,?2,?3)",
        params![attempt, resource.handle, provenance],
    )?;
    Ok(())
}

pub(crate) fn permits_topic(resource: &ResourceUse, topic: &str) -> bool {
    match &resource.grant.target {
        ResourceTarget::NotificationMailbox {
            topics: TopicScope::Any,
        } => true,
        ResourceTarget::NotificationMailbox {
            topics: TopicScope::Only { topics },
        } => topics.contains(topic),
        ResourceTarget::NotificationMailbox {
            topics: TopicScope::Prefix { prefix },
        } => topic.starts_with(prefix),
        _ => false,
    }
}

pub(crate) fn validate_result(resource: &ResourceUse, result: &str) -> Result<()> {
    ensure!(
        result.len() as u64 <= resource.grant.limits.max_response_bytes,
        Failure::ResourceLimitExceeded
    );
    if resource.action == Action::NotificationsResolve {
        let value: serde_json::Value = crate::json::decode(result.as_bytes())?;
        ensure!(
            value.get("actor").and_then(|actor| actor.as_str()) == Some(resource.actor.as_str()),
            Failure::ResourceForbidden
        );
    }
    if let ResourceTarget::CartaIssuer { issuer_id } = &resource.grant.target
        && resource.action == Action::CartaSnapshot
    {
        let snapshot: crate::carta::Snapshot = crate::json::decode(result.as_bytes())?;
        ensure!(&snapshot.issuer_id == issuer_id, Failure::ResourceForbidden);
    }
    if let ResourceTarget::GoogleDirectory { customer_id, .. } = &resource.grant.target
        && resource.action == Action::GoogleDirectorySnapshot
    {
        let value: serde_json::Value = crate::json::decode(result.as_bytes())?;
        ensure!(
            value.get("customer_id").and_then(|value| value.as_str()) == Some(customer_id),
            Failure::ResourceForbidden
        );
    }
    Ok(())
}

pub(crate) fn reserve_in(
    connection: &Connection,
    runtime: &Runtime,
    request: &Request,
    instruction: &Instruction,
    attempt: &str,
    resource: &ResourceUse,
    quote: ProviderQuote,
) -> Result<crate::budget::Reservation> {
    let active = authority_state::require_invocation_in(
        connection,
        runtime,
        &request.context.invocation_id,
        &request.operation,
        &request.context.actor,
    )?;
    let mut budgets = std::collections::BTreeMap::new();
    for reference in &resource.grant.budgets {
        let definition = active
            .document
            .resources
            .budgets
            .get(&reference.id)
            .context("resource_budget_missing")?;
        ensure!(
            definition.revision == reference.revision,
            "resource_budget_revision_mismatch"
        );
        budgets.insert(reference.id.clone(), definition.clone());
    }
    let obligations = connection
        .prepare("SELECT id,definition FROM day2_resource_root_budgets WHERE root=?1 ORDER BY id")?
        .query_map([&resource.root], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (id, encoded) in obligations {
        let definition: BudgetDefinition = crate::json::decode(encoded.as_bytes())?;
        ensure!(
            definition.scope == BudgetScope::InvocationRoot,
            "resource_root_budget_scope"
        );
        if let Some(existing) = budgets.get(&id) {
            ensure!(existing == &definition, "resource_root_budget_changed");
        }
        budgets.insert(id, definition);
    }
    let installation = runtime
        .scope()
        .rsplit_once('/')
        .context("resource_scope")?
        .0;
    ensure!(
        quote.cost_microunits.is_some()
            || budgets
                .values()
                .all(|budget| budget.limits.cost_microunits.is_none()),
        "provider_monetary_bound_not_qualified"
    );
    let physical_connection = match &resource.grant.live {
        Some(day2_capabilities::integrations::LiveConnection::Slack { workspace_id, .. }) => {
            format!("slack/{workspace_id}")
        }
        Some(day2_capabilities::integrations::LiveConnection::Snowflake { account, .. }) => {
            format!("snowflake/{account}")
        }
        Some(day2_capabilities::integrations::LiveConnection::OpenAi { project_id, .. }) => {
            format!("openai/{project_id}")
        }
        // Endpoint and bucket together: two vendors' buckets may share a name, and
        // a budget keyed on the name alone would pool unrelated spend.
        Some(day2_capabilities::integrations::LiveConnection::ObjectStore {
            endpoint,
            bucket,
            ..
        }) => format!("object_store/{endpoint}/{bucket}"),
        // The organization, not the source: one workspace's rate limit and spend
        // are shared by every view and label read through it, so budgeting per
        // source would let a dozen grants each believe they had the whole budget.
        // The API host. GitHub's real limit is per installation token rather
        // than per host, which this cannot see — so several installations on one
        // host share a budget. That pools conservatively: the error is spending
        // less than allowed, never more.
        Some(day2_capabilities::integrations::LiveConnection::GitHubActions {
            endpoint, ..
        }) => format!("github_actions/{endpoint}"),
        Some(day2_capabilities::integrations::LiveConnection::LinearWork {
            organization_id,
            ..
        }) => format!("linear_work/{organization_id}"),
        None => format!("{:?}", resource.grant.provider),
    };
    crate::budget::reserve_in(
        connection,
        &crate::budget::ReservationRequest {
            id: attempt.into(),
            binding: crate::digest(&serde_json::to_vec(&(resource, instruction))?),
            context: crate::budget::BudgetContext {
                app: runtime.app().into(),
                actor: request.context.actor.clone(),
                connection: format!("{installation}/{physical_connection}"),
                invocation_root: resource.root.clone(),
                now: runtime.host().now_ms()? / 1000,
            },
            budgets,
            quote: crate::budget::Consumption {
                calls: resource.planned_calls,
                bytes: quote
                    .request_bytes
                    .checked_add(resource.grant.limits.max_response_bytes)
                    .context("resource_byte_overflow")?,
                cost_microunits: quote.cost_microunits.unwrap_or(0),
                concurrency: 1,
            },
        },
    )
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProviderQuote {
    pub request_bytes: u64,
    /// None means this adapter does not provide a monetary bound. Such a call
    /// cannot use any money-metered binding or inherited root obligation.
    pub cost_microunits: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ProviderUsage {
    pub calls: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub cost_microunits: u64,
    pub known: bool,
    pub dispatched: bool,
}

pub(crate) fn settle_in(
    connection: &Connection,
    reservation: &crate::budget::Reservation,
    usage: ProviderUsage,
) -> Result<()> {
    if !usage.known {
        // An adapter error alone is not evidence of a final provider outcome.
        // Keep the full quote until a provider-specific reconciler can settle it.
        crate::budget::settle_in(connection, reservation, &crate::budget::Settlement::Unknown)?;
        return Ok(());
    }
    crate::budget::settle_in(
        connection,
        reservation,
        &crate::budget::Settlement::Known {
            actual: crate::budget::Consumption {
                calls: usage.calls,
                bytes: usage
                    .request_bytes
                    .checked_add(usage.response_bytes)
                    .context("resource_byte_overflow")?,
                cost_microunits: usage.cost_microunits,
                concurrency: 0,
            },
        },
    )?;
    Ok(())
}

/// Replayed bytes retain their original handle provenance and must still fit
/// the live grant before they enter pure application code. No provider is called.
pub(crate) fn validate_cached(
    connection: &Connection,
    runtime: &Runtime,
    request: &Request,
    observation: &Observation,
) -> Result<()> {
    if observation.instruction.kind != "observe" && observation.instruction.kind != "external" {
        return Ok(());
    }
    if !observation.error.is_empty() {
        return Ok(());
    }
    if observation.instruction.model == crate::audit::HISTORY {
        // A recorded history page carries no resource. What must still hold is
        // the grant: revoking `audit.history` stops the invocation using what it
        // already read, as revoking any other read does.
        let active = authority_state::require_invocation_in(
            connection,
            runtime,
            &request.context.invocation_id,
            &request.operation,
            &request.context.actor,
        )?;
        return crate::audit::require_history(active.policy()?, runtime, &request.operation);
    }
    if [BIND, ATTENUATE].contains(&observation.instruction.model.as_str()) {
        let result: serde_json::Value = crate::json::decode(observation.result.as_bytes())?;
        let token = result
            .get("token")
            .and_then(|token| token.as_str())
            .context("resource_handle_required")?;
        load(connection, runtime, request, token)?;
    } else {
        let active = authority_state::require_invocation_in(
            connection,
            runtime,
            &request.context.invocation_id,
            &request.operation,
            &request.context.actor,
        )?;
        let capability = crate::capabilities::authorized(
            connection,
            runtime,
            request,
            &observation.instruction,
            active.policy()?,
            "",
        )?;
        validate_result(capability.resource(), &observation.result)?;
    }
    Ok(())
}
