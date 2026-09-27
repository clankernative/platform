//! Shared notification capability and its deterministic semantic model.
//! The local mailbox is a real, separately committed provider store. No live
//! Twilio/Slack credentials or network calls are implied by this local adapter.
use crate::integrations::GRANT_SECONDS;
use crate::{
    protocol::*,
    store::{self, Runtime},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

// Generated from the one provider table; see `day2_capabilities::registry`.
pub use day2_capabilities::registry::{LOCAL_PROVIDER_DATABASES, READS, WRITES};

/// Whether `name` is an observation an operation policy may grant.
///
/// Every provider read, plus the host's own [`crate::audit::HISTORY`]: an
/// application reading its own history is granted exactly like any other read,
/// but it reaches no provider, holds no resource and spends no budget, so it
/// has no place in the provider table.
pub fn observation(name: &str) -> bool {
    READS.contains(&name) || name == crate::audit::HISTORY
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NotificationWorld {
    pub messages: BTreeMap<String, Message>,
    #[serde(default)]
    pub order: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub scope: String,
    pub actor: String,
    pub topic: String,
    pub body: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipient {
    actor: String,
    #[serde(rename = "handle")]
    _handle: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Topic {
    topic: String,
    #[serde(rename = "handle")]
    _handle: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Send {
    actor: String,
    topic: String,
    body: String,
    #[serde(rename = "handle")]
    _handle: String,
}

impl NotificationWorld {
    /// Stable request IDs deduplicate provider acceptance, including acceptance
    /// followed by a lost response. A substituted payload is always rejected.
    pub fn send(&mut self, effect_id: &str, message: Message) -> Result<Value> {
        if let Some(existing) = self.messages.get(effect_id) {
            ensure!(existing == &message, "notification_idempotency_conflict");
        } else {
            self.messages.insert(effect_id.into(), message);
            self.order.push(effect_id.into());
        }
        Ok(
            json!({"id":format!("msg_{}", &crate::digest(effect_id.as_bytes())[7..31]),"status":"accepted"}),
        )
    }

    pub fn latest(&self, scope: &str, actor: &str, topic: &str) -> Value {
        let matching: Vec<_> = self
            .order
            .iter()
            .filter_map(|id| self.messages.get(id).map(|message| (id, message)))
            .filter(|(_, message)| {
                message.scope == scope && message.actor == actor && message.topic == topic
            })
            .collect();
        match matching.last() {
            Some((id, _)) => {
                json!({"id":format!("msg_{}", &crate::digest(id.as_bytes())[7..31]),"status":"accepted","count":matching.len()})
            }
            None => json!({"id":"","status":"none","count":0}),
        }
    }
}

/// Validated adapter input. Only authorization under a database transaction can
/// construct this value; adapters never reload policy after dispatch admission.
pub(crate) struct Authorized {
    action: Action,
    resource: crate::resources::ResourceUse,
    quote: crate::resources::ProviderQuote,
}

enum Action {
    Live(crate::integrations::PreparedCall),
    Carta(crate::carta::Read),
    People(crate::people_providers::Action),
    Recipient(String),
    Latest {
        actor: String,
        topic: String,
    },
    Send(Message),
    /// Another application's answer to a read, fetched inside this instance.
    Delegate(Box<crate::delegation::Call>),
    /// A presigned URL and the object it names. Computed here rather than
    /// dispatched: signing reaches no network, so there is nothing to send and
    /// nothing to await. The key travels with the URL because an upload's key is
    /// the host's to choose, so the application learns it here or not at all.
    Grant {
        url: String,
        key: String,
    },
}

impl Authorized {
    /// The delegated call this authorization resolved to, for tests that need
    /// to see what the grant and the request between them decided.
    #[cfg(test)]
    pub(crate) fn delegated_call(&self) -> Option<&crate::delegation::Call> {
        match &self.action {
            Action::Delegate(call) => Some(call),
            _ => None,
        }
    }

    pub(crate) fn quote(&self) -> crate::resources::ProviderQuote {
        self.quote
    }
    pub(crate) fn resource(&self) -> &crate::resources::ResourceUse {
        &self.resource
    }

    pub(crate) fn retries_are_idempotent(&self) -> bool {
        // The mailbox and explicitly synthetic People providers deduplicate
        // stable effect IDs with a committed payload/result ledger. A future
        // live adapter must explicitly supply deduplication/reconciliation
        // before admitting a second attempt after an unknown outcome.
        matches!(self.action, Action::Send(_))
            || matches!(&self.action, Action::People(action) if action.is_write())
    }
}

pub(crate) fn authorized(
    connection: &Connection,
    runtime: &Runtime,
    request: &Request,
    instruction: &Instruction,
    policy: &crate::authority::Policy,
    // This step's identity within the invocation: the effect's identity on the
    // effect path, the observation's on the read path, empty for a check that
    // will not dispatch. Anything deriving a name that must survive a retry —
    // the object an upload lands on, the invocation a delegated read reaches —
    // takes it from here, and refuses to proceed without one, because a name
    // minted from anything less specific would be minted twice.
    step: &str,
) -> Result<Authorized> {
    let operation = runtime.artifact().route(&request.operation)?;
    let permissions = &policy.operations[&operation.name];
    let allowed = match instruction.decode()? {
        crate::protocol::Step::Observe { capability, .. } => {
            READS.contains(&capability) && permissions.observations.contains(capability)
        }
        crate::protocol::Step::External { capability, .. } => {
            operation.kind == "command"
                && WRITES.contains(&capability)
                && permissions.effects.contains(capability)
        }
        _ => false,
    };
    ensure!(allowed, crate::error::Failure::CapabilityForbidden);
    crate::resources::require_journalable_instruction(instruction)?;
    use day2_capabilities::integrations::LiveConnection;
    use day2_capabilities::resources::{Action as ResourceAction, Provider, ResourceTarget};
    let resource_action = ResourceAction::ALL
        .iter()
        .copied()
        .find(|action| action.capability() == instruction.model.as_str())
        .context("unknown_capability")?;
    let mut resource =
        crate::resources::authorize(connection, runtime, request, instruction, resource_action)?;
    let mut quote = crate::resources::ProviderQuote {
        request_bytes: instruction.data.len() as u64,
        cost_microunits: Some(0),
    };
    let action = match instruction.model.as_str() {
        "slack.read.v1"
        | "slack.post.v1"
        | "snowflake.read.v1"
        | "openai.generate.v1"
        | "linear_work.issues.v1"
        | "linear_work.issue_detail.v1"
        | "linear_work.assignable_users.v1"
        | "linear_work.reassign.v1"
        | "github.job.v1"
        | "github.job_log.v1" => {
            let connection = resource
                .grant
                .live
                .as_ref()
                .ok_or(crate::error::Failure::ResourceForbidden)?;
            let call = crate::integrations::prepare(
                &resource_action,
                connection,
                &resource.grant.target,
                &instruction.data,
                resource.grant.limits.max_request_bytes,
                resource.grant.limits.max_response_bytes,
            )?;
            quote = crate::resources::ProviderQuote {
                request_bytes: call.request_bytes(),
                cost_microunits: call.reserved_monetary_microusd(),
            };
            resource.planned_calls = call.max_calls();
            Action::Live(call)
        }
        "google_directory.snapshot.v1"
        | "google_directory.record.v1"
        | "google_directory.create_user.v1"
        | "google_directory.patch_attributes.v1"
        | "google_directory.ensure_group_member.v1"
        | "linear.ensure_access.v1"
        | "linear.suspend.v1"
        | "operator_alerts.send.v1" => Action::People(crate::people_providers::authorized(
            instruction,
            resource.grant.provider,
            &resource.grant.target,
        )?),
        "carta.snapshot.v1" | "carta.record.v1" => {
            ensure!(
                resource.grant.provider == Provider::SyntheticCarta,
                crate::error::Failure::ResourceForbidden
            );
            let ResourceTarget::CartaIssuer { issuer_id } = &resource.grant.target else {
                anyhow::bail!(crate::error::Failure::ResourceForbidden)
            };
            Action::Carta(crate::carta::authorized(runtime, instruction, issuer_id)?)
        }
        "notifications.recipient.v1" => {
            let input: Recipient = serde_json::from_str(&instruction.data)?;
            ensure!(
                input.actor == request.context.actor,
                crate::error::Failure::ResourceForbidden
            );
            ensure!(
                resource.grant.provider == Provider::LocalNotifications
                    && matches!(
                        resource.grant.target,
                        ResourceTarget::NotificationMailbox { .. }
                    ),
                crate::error::Failure::ResourceForbidden
            );
            Action::Recipient(input.actor)
        }
        "notifications.latest.v1" => {
            let input: Topic = serde_json::from_str(&instruction.data)?;
            ensure!(
                !input.topic.is_empty() && input.topic.len() <= 128,
                "invalid_notification_topic"
            );
            ensure!(
                resource.grant.provider == Provider::LocalNotifications
                    && crate::resources::permits_topic(&resource, &input.topic),
                crate::error::Failure::ResourceForbidden
            );
            Action::Latest {
                actor: request.context.actor.clone(),
                topic: input.topic,
            }
        }
        "object_store.grant_upload.v1"
        | "object_store.grant_download.v1"
        | "object_store.head.v1"
        | "object_store.delete.v1" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct GrantRequest {
                key: String,
                #[serde(rename = "handle")]
                _handle: String,
            }
            let input: GrantRequest = serde_json::from_str(&instruction.data)?;
            let ResourceTarget::ObjectBucket {
                bucket, key_prefix, ..
            } = &resource.grant.target
            else {
                anyhow::bail!(crate::error::Failure::ResourceForbidden)
            };
            let Some(LiveConnection::ObjectStore {
                endpoint,
                region,
                bucket: connected,
                access_key_id,
                ..
            }) = resource.grant.live.as_ref()
            else {
                anyhow::bail!(crate::error::Failure::ResourceForbidden)
            };
            // The prefix is the whole of the authority. A key outside it is
            // refused rather than signed, because a presigned URL is a bearer
            // capability for exactly the object it names: signing one the grant
            // does not cover would hand out access nothing authorized, and no
            // later check can take it back.
            // The grant decides, and it decides before anything is signed.
            ensure!(
                bucket == connected,
                crate::error::Failure::ResourceForbidden
            );
            // The key the application asked for is checked first, so the error
            // is about what it asked for rather than about what the host made
            // of it.
            resource
                .grant
                .target
                .authorizes_object(connected, &input.key)
                .map_err(|_| crate::error::Failure::ResourceForbidden)?;
            let key = if instruction.model == "object_store.grant_upload.v1" {
                unique_upload_key(step, key_prefix, &input.key)?
            } else {
                input.key.clone()
            };
            resource
                .grant
                .target
                .authorizes_object(connected, &key)
                .map_err(|_| crate::error::Failure::ResourceForbidden)?;
            // The signed method is part of the signature, so it is chosen here and
            // cannot be changed by whoever holds the URL afterwards.
            let method = match instruction.model.as_str() {
                "object_store.grant_upload.v1" => "PUT",
                "object_store.head.v1" => "HEAD",
                "object_store.delete.v1" => "DELETE",
                _ => "GET",
            };
            let mounts = crate::integration_host::MountedCredentials::new(runtime.instance_path())?;
            let secret = mounts
                .signing_secret(resource.grant.live.as_ref().expect("checked above"))
                .map_err(|_| crate::error::Failure::ResourceForbidden)?;
            let url = crate::integrations::presign(
                access_key_id,
                secret.as_hmac_key(),
                region,
                method,
                endpoint,
                bucket,
                &key,
                request.context.now,
            )
            .map_err(|_| crate::error::Failure::ResourceForbidden)?;
            // A grant hands the URL to the application, which hands it to whoever
            // is transferring. head and delete use the identical URL themselves
            // and hand back only the answer — same signature, same scope check,
            // different consumer.
            match instruction.model.as_str() {
                "object_store.head.v1" => Action::Live(crate::integrations::object_call(
                    resource.grant.live.as_ref().expect("checked above"),
                    crate::integrations::ObjectOperation::Head,
                    url,
                    resource.grant.limits.max_response_bytes,
                )),
                "object_store.delete.v1" => Action::Live(crate::integrations::object_call(
                    resource.grant.live.as_ref().expect("checked above"),
                    crate::integrations::ObjectOperation::Delete,
                    url,
                    resource.grant.limits.max_response_bytes,
                )),
                _ => Action::Grant { url, key },
            }
        }
        "app.query.v1" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct DelegatedRead {
                input: String,
                #[serde(rename = "handle")]
                _handle: String,
            }
            let (input, pinned_contract) =
                if serde_json::from_str::<serde_json::Value>(&instruction.data)?
                    .get("contract")
                    .is_some()
                {
                    let read: crate::resources::ImportedQuery =
                        crate::json::decode(instruction.data.as_bytes())?;
                    (read.input, Some(read.contract.digest))
                } else {
                    let read: DelegatedRead = crate::json::decode(instruction.data.as_bytes())?;
                    (read.input, None)
                };
            let ResourceTarget::AppOperation {
                app,
                operation,
                schema_digest,
            } = &resource.grant.target
            else {
                anyhow::bail!(crate::error::Failure::ResourceForbidden)
            };
            // Cached-result validation also authorizes this grant, without
            // dispatching or supplying a step. The dispatch boundary requires
            // that identity before it can call either a real or simulated peer.
            Action::Delegate(Box::new(crate::delegation::Call {
                app: app.clone(),
                operation: operation.clone(),
                schema_digest: schema_digest.clone(),
                input,
                contract_digest: pinned_contract,
                // Never the caller's choice. A delegated call runs as the person
                // the caller was already running as.
                actor: request.context.actor.clone(),
                origin: request.context.invocation_id.clone(),
                step: step.to_owned(),
                chain: request.context.caller.join("."),
                caller: runtime.app().to_owned(),
                now: request.context.now,
            }))
        }
        "notifications.send.v1" => {
            let input: Send = serde_json::from_str(&instruction.data)?;
            ensure!(
                input.actor == request.context.actor,
                crate::error::Failure::ResourceForbidden
            );
            ensure!(
                input.actor == request.context.actor
                    && !input.topic.is_empty()
                    && input.topic.len() <= 128
                    && !input.body.is_empty()
                    && input.body.len() <= 8000,
                "invalid_notification"
            );
            ensure!(
                resource.grant.provider == Provider::LocalNotifications
                    && crate::resources::permits_topic(&resource, &input.topic),
                crate::error::Failure::ResourceForbidden
            );
            Action::Send(Message {
                scope: runtime.scope().to_owned(),
                actor: input.actor,
                topic: input.topic,
                body: input.body,
            })
        }
        _ => anyhow::bail!("unknown_capability"),
    };
    Ok(Authorized {
        action,
        resource,
        quote,
    })
}

pub(crate) struct ProviderResult {
    pub result: Result<String>,
    pub usage: crate::resources::ProviderUsage,
    pub correlation: Vec<crate::integrations::ExchangeCorrelation>,
}

impl ProviderResult {
    fn local(result: Result<String>, request_bytes: u64) -> Self {
        let usage = crate::resources::ProviderUsage {
            calls: 1,
            request_bytes,
            response_bytes: result.as_ref().map_or(0, |value| value.len() as u64),
            cost_microunits: 0,
            known: result.is_ok(),
            dispatched: true,
        };
        Self {
            result,
            usage,
            correlation: Vec::new(),
        }
    }

    fn live(runtime: &Runtime, call: &crate::integrations::PreparedCall, attempt: &str) -> Self {
        let outcome = runtime.integrations().execute(call, attempt);
        Self {
            result: outcome.result.map_err(Into::into),
            correlation: outcome.correlation,
            usage: crate::resources::ProviderUsage {
                calls: outcome.calls,
                request_bytes: outcome.request_bytes,
                response_bytes: outcome.response_bytes,
                cost_microunits: outcome.monetary_microusd.unwrap_or(0),
                known: !outcome.outcome_unknown,
                dispatched: outcome.dispatched,
            },
        }
    }
}

pub(crate) fn with_world(
    runtime: &Runtime,
    action: impl FnOnce(&mut NotificationWorld) -> Result<Value>,
) -> Result<String> {
    let path = runtime.db().with_file_name("notifications.sqlite");
    let mut connection = store::open(&path)?;
    let tx = crate::write_queue::immediate(&mut connection)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS notification_world (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL) STRICT; INSERT OR IGNORE INTO notification_world VALUES(1,'{\"messages\":{}}');")?;
    let encoded: String = tx.query_row(
        "SELECT state FROM notification_world WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    ensure!(encoded.len() <= 4_194_304, "notification_world_budget");
    let mut world: NotificationWorld = serde_json::from_str(&encoded)?;
    let result = action(&mut world)?;
    let encoded = serde_json::to_string(&world)?;
    ensure!(encoded.len() <= 4_194_304, "notification_world_budget");
    tx.execute(
        "UPDATE notification_world SET state=?1 WHERE id=1",
        params![encoded],
    )?;
    tx.commit()?;
    Ok(serde_json::to_string(&result)?)
}

/// What an application receives for a grant.
///
/// The key is part of the answer, not an echo of the question: an upload's key
/// is the host's to choose, so this is where the application learns which object
/// its authorization actually names.
fn grant_result(url: &str, key: &str) -> String {
    json!({"url": url, "expires_in": GRANT_SECONDS, "key": key}).to_string()
}

/// The object an upload actually lands on.
///
/// The application asks for a name; the host inserts a segment of its own right
/// after the grant's prefix and returns the result. Overwriting then stops being
/// something to check for and becomes something an application cannot express:
/// no two grants ever name one object, so an upload cannot destroy bytes that
/// are already there. The previous version of an avatar is not lost when a new
/// one is uploaded — it is simply no longer the one the row points at.
///
/// Derived from the effect's identity, which is already the invocation and this
/// effect's position within it, so a replay produces the same key and a retry
/// of the same effect targets the same object rather than scattering copies. It
/// must be the effect rather than anything coarser: two upload grants in one
/// invocation are two effects but one request, and a key derived from the
/// request would name one object for both. The
/// segment goes immediately after the prefix so the key stays inside the grant
/// by construction, and the name — extension included — survives unchanged.
fn unique_upload_key(effect: &str, prefix: &str, requested: &str) -> Result<String> {
    ensure!(!effect.is_empty(), "upload_grant_requires_an_effect");
    let rest = requested
        .strip_prefix(prefix)
        .context("object_key_outside_grant")?;
    let digest = crate::digest(&serde_json::to_vec(&(effect, requested))?);
    let segment = digest
        .strip_prefix("sha256:")
        .context("unexpected digest form")?
        .get(..32)
        .context("short digest")?;
    Ok(format!("{prefix}{segment}/{rest}"))
}

pub(crate) fn observe(runtime: &Runtime, capability: Authorized, attempt: &str) -> ProviderResult {
    let request_bytes = capability.quote.request_bytes;
    let result = match capability.action {
        Action::Live(call) => return ProviderResult::live(runtime, &call, attempt),
        Action::Carta(read) => crate::carta::observe(runtime, read),
        Action::People(action) => crate::people_providers::observe(runtime, action),
        Action::Recipient(actor) => Ok(json!({"actor":actor}).to_string()),
        Action::Latest { actor, topic } => with_world(runtime, |world| {
            Ok(world.latest(runtime.scope(), &actor, &topic))
        }),
        // A grant is computed, not dispatched, so it resolves the same way on
        // both paths: downloading authorizes a read, uploading authorizes a write,
        // and neither reaches the network.
        Action::Grant { url, key } => Ok(grant_result(&url, &key)),
        Action::Delegate(call) => crate::delegation::read(runtime, &call),
        _ => Err(anyhow::anyhow!("unknown_observation_capability")),
    };
    ProviderResult::local(result, request_bytes)
}

pub(crate) fn execute(
    runtime: &Runtime,
    capability: Authorized,
    effect_id: &str,
    attempt: &str,
) -> ProviderResult {
    let request_bytes = capability.quote.request_bytes;
    let result = match capability.action {
        Action::Live(call) => return ProviderResult::live(runtime, &call, attempt),
        Action::Send(message) => with_world(runtime, |world| world.send(effect_id, message)),
        // A grant is computed, not dispatched, so it resolves the same way on
        // both paths: downloading authorizes a read, uploading authorizes a write,
        // and neither reaches the network.
        Action::Grant { url, key } => Ok(grant_result(&url, &key)),
        Action::People(action) => crate::people_providers::execute(runtime, action, effect_id),
        _ => Err(anyhow::anyhow!("unknown_effect_capability")),
    };
    ProviderResult::local(result, request_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_response_loss_and_duplicate_retries_preserve_one_notification() -> Result<()> {
        let mut world = NotificationWorld::default();
        let message = Message {
            scope: "installation/app".into(),
            actor: "alice".into(),
            topic: "report".into(),
            body: "ready".into(),
        };
        let accepted = world.send("stable-effect", message.clone())?;
        let persisted = serde_json::to_string(&world)?;
        let mut restarted: NotificationWorld = serde_json::from_str(&persisted)?;
        assert_eq!(restarted.send("stable-effect", message.clone())?, accepted);
        assert_eq!(restarted.messages.len(), 1);
        assert!(
            restarted
                .send(
                    "stable-effect",
                    Message {
                        body: "different".into(),
                        ..message
                    }
                )
                .is_err()
        );
        assert_eq!(
            restarted.latest("installation/app", "bob", "report")["count"],
            0
        );
        assert_eq!(
            restarted.latest("installation/other", "alice", "report")["count"],
            0
        );
        Ok(())
    }

    /// An upload can never be aimed at an object that already exists.
    ///
    /// This is the object-store half of the platform's deletion stance: an
    /// application cannot destroy bytes with `delete`, so it must not be able to
    /// destroy them by writing over them either. Overwriting is prevented by
    /// making it inexpressible — the host, not the application, decides which
    /// object an upload lands on — rather than by a check that races.
    #[test]
    fn an_upload_key_is_unique_per_effect_and_stays_inside_the_grant() -> Result<()> {
        let first = unique_upload_key("fx_inv1_0", "photos/", "photos/cat.png")?;
        let second = unique_upload_key("fx_inv1_1", "photos/", "photos/cat.png")?;
        let elsewhere = unique_upload_key("fx_inv2_0", "photos/", "photos/cat.png")?;
        assert_ne!(
            first, "photos/cat.png",
            "the host handed back the key the application asked for"
        );
        assert_ne!(first, second, "two uploads in one invocation collide");
        assert_ne!(first, elsewhere, "two invocations collide");

        // An upload grant that cannot say which effect it is does not get a key
        // at all: a key minted from something coarser would be minted twice.
        assert!(unique_upload_key("", "photos/", "photos/cat.png").is_err());

        // Replaying the same invocation must reproduce the same object, or a
        // retry would scatter copies and a replay would not match its trace.
        assert_eq!(
            first,
            unique_upload_key("fx_inv1_0", "photos/", "photos/cat.png")?
        );

        // Inside the grant by construction, and the name the application chose —
        // extension included — survives, so the bucket stays legible.
        assert!(first.starts_with("photos/"), "{first} escaped the prefix");
        assert!(first.ends_with("/cat.png"), "{first} lost the file name");

        // A key the grant does not cover is refused rather than rehomed under
        // the prefix, which would silently widen what the app asked for.
        assert!(unique_upload_key("fx_inv1_0", "photos/", "other/cat.png").is_err());

        // An empty prefix grants the whole bucket; the segment still leads.
        let whole = unique_upload_key("fx_inv1_0", "", "cat.png")?;
        assert!(whole.ends_with("/cat.png") && whole.len() > "cat.png".len() + 1);
        Ok(())
    }

    /// The application is told which object its authorization names.
    ///
    /// Without this it could not find the object again: it asked for one key and
    /// the host signed another.
    #[test]
    fn a_grant_reports_the_object_it_actually_authorizes() -> Result<()> {
        let value: Value = serde_json::from_str(&grant_result(
            "https://bucket.example.com/photos/abc/cat.png?X-Amz-Signature=x",
            "photos/abc/cat.png",
        ))?;
        assert_eq!(value["key"], "photos/abc/cat.png");
        assert_eq!(value["expires_in"], GRANT_SECONDS);
        assert!(value["url"].as_str().context("url")?.contains("cat.png"));
        Ok(())
    }

    /// Nothing an application invokes destroys anything.
    ///
    /// The registry declares which actions destroy data; this pins that the
    /// object-store delete is one of them and that it is the only one, so a new
    /// destroying action cannot arrive unnoticed.
    #[test]
    fn object_deletion_is_the_only_destroying_action_and_is_a_write() {
        use day2_capabilities::resources::Action as ResourceAction;
        let destroying: Vec<_> = ResourceAction::ALL
            .iter()
            .filter(|action| action.destroys_data())
            .map(|action| action.capability())
            .collect();
        assert_eq!(destroying, vec!["object_store.delete.v1"]);
        assert!(
            ResourceAction::ALL
                .iter()
                .all(|action| !action.destroys_data() || action.is_write()),
            "a destroying action that is not a write would skip the write budget"
        );
    }
}
