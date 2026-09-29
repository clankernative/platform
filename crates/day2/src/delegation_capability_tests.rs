//! The seam where a caller's grant becomes a delegated call.
//!
//! `delegation::read` is handed a `Call`. What decides the contents of that
//! `Call` is `capabilities::authorized`, and the field that matters most is the
//! actor: the whole claim of this design is that delegation carries a *request*
//! across an application boundary and never *authority*. A test that built the
//! `Call` itself could not establish that, so this one goes through the grant.
use super::*;
use crate::store::{Runtime, open};
use crate::{
    artifact::LoadedArtifact,
    integration_host,
    operation_contract::{Codec, Kind, OperationSpec, Package, TypeObject},
    protocol::{Instruction, Request},
};
use rusqlite::TransactionBehavior;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::Arc,
};

struct Granted {
    /// Held so the instance outlives the runtime that reads it; never read.
    _directory: tempfile::TempDir,
    caller: Runtime,
    imported_digest: String,
}

impl Granted {
    /// One application holding a grant to read one operation of another.
    ///
    /// Built from a contract rather than a compiled artifact, so this runs in an
    /// ordinary `cargo test` with no fixture environment: what it exercises is
    /// the authorization path, which needs a registered operation and a resolved
    /// grant, not a worker.
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        let state = directory.path().join(".state");
        fs::create_dir_all(&state)?;
        let artifact_directory = directory.path().join("delegation-contract");
        fs::create_dir(&artifact_directory)?;
        let digest = format!("sha256:{}", "1".repeat(64));
        let target = json!({"kind":"app_operation","app":"callee",
            "operation":"callee.list","schema_digest":digest});
        // The operation's own policy must permit the capability before a grant
        // for it can resolve. Two independent gates, and this is the first.
        let policy = json!({"version":1,"admins":[],
            "delegations":{"support":{"authenticated":["support"],
                "may_act_as":{"kind":"actors","actors":["alice"]},"paths":["request"]}},
            "operations":{"ask":{"actors":["alice"],
            "mode":{"kind":"current_state"},"models":{},
            "observations":["app.query.v1"],"effects":[]}}});
        let catalog = json!({"version":1,
            "connections":{"delegation":{"revision":1,"provider":"local_delegation"}},
            "resources":{"callee_list":{"revision":1,
                "connection":{"id":"delegation","revision":1},"target":target}},
            "policies":{"reading":{"revision":1,"owner":"it","actors":["alice"],
                "allowed_apps":["caller"],"max_duration_seconds":null,
                "slots":{"directory":{"kind":"app_operation",
                    "allowed_resources":[{"id":"callee_list","revision":1}],
                    "actions":["delegate_query"],
                    "limits":{"max_request_bytes":16_384,"max_response_bytes":65_536,
                        "max_calls_per_invocation":4},
                    "budgets":[{"id":"reads","revision":1}]}}}},
            "budgets":{"reads":{"revision":1,"scope":"app","period_seconds":3600,
                "limits":{"calls":100,"bytes":1_000_000,"concurrency":1}}}});
        let instance = json!({"installation":"delegationco","environment":"test",
            "resources":catalog,
            "apps":{"caller":{"artifact":artifact_directory,"readers":[],"writers":["alice"],
                "authority":policy,
                "resource_policies":[{"policy":{"id":"reading","revision":1},
                    "operation":"ask","bindings":{"directory":{"id":"callee_list","revision":1}}}]}}});
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let objects = BTreeMap::from([
            (
                "callee.operation.list.input.v1".into(),
                TypeObject {
                    id: "callee.operation.list.input.v1".into(),
                    codec: Codec::RocJsonV1,
                    schema: json!({"fields":{}}),
                    dependencies: BTreeSet::new(),
                },
            ),
            (
                "callee.operation.list.output.v1".into(),
                TypeObject {
                    id: "callee.operation.list.output.v1".into(),
                    codec: Codec::RocJsonV1,
                    schema: json!({"shape":{"record":{"actor":"string"}},"roc_type":"{ actor : Str }"}),
                    dependencies: BTreeSet::new(),
                },
            ),
            (
                "callee.operation.list.error.v1".into(),
                TypeObject {
                    id: "callee.operation.list.error.v1".into(),
                    codec: Codec::RocJsonV1,
                    schema: json!([]),
                    dependencies: BTreeSet::new(),
                },
            ),
        ]);
        let package = Package::derive(
            OperationSpec {
                id: "callee.list".into(),
                version: 1,
                kind: Kind::Query,
                input: "callee.operation.list.input.v1".into(),
                output: "callee.operation.list.output.v1".into(),
                error: "callee.operation.list.error.v1".into(),
                semantics: json!({}),
            },
            &objects,
        )?;
        let imported_digest = package.digest.clone();
        let imports = crate::instance_catalog::ImportedContracts::from_resolved(
            crate::instance_catalog::ResolvedImports {
                operations: BTreeMap::from([("callee.list".into(), package.clone())]),
                types: package.types,
            },
        )?;
        let contract = serde_json::from_value(json!({
            "format":crate::artifact::CURRENT_FORMAT,"roc_version":"delegation-test",
            "worker_digest":"delegation-test","schema_digest":"delegation-test",
            "schema":{"models":{"items":{"fields":{"value":"text"}}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":[{"name":"ask","kind":"command","input_type":"input","output_type":""}],
            "sources":{},"admission":"local-spike-only","imports":imports}))?;
        let caller = Runtime {
            integrations: Arc::new(integration_host::Host::local(&path)?),
            app_calls: None,
            instance_path: path,
            app: "caller".into(),
            db: state.join("caller.sqlite"),
            scope: "delegationco/test/caller".into(),
            hosted_domain: None,
            artifact: Arc::new(LoadedArtifact::from_contract_for_tests(
                "delegation-test".into(),
                artifact_directory,
                contract,
            )),
            host: Arc::new(crate::host::System),
        };
        caller.initialize()?;
        Ok(Self {
            _directory: directory,
            caller,
            imported_digest,
        })
    }
}

#[test]
fn pinned_import_selects_one_grant_without_app_chosen_identity_or_binding() -> Result<()> {
    let granted = Granted::new()?;
    granted
        .caller
        .accept("ask", "alice", "imported", &json!({}), 100)?;
    let request = |digest: &str, extra: serde_json::Value| {
        let mut connection = open(granted.caller.db())?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request = Request {
            operation: "ask".into(),
            input: "{}".into(),
            context: crate::store::invocation_context(&tx, "imported")?,
            observations: Vec::new(),
        };
        let mut data = json!({"contract":{"operation":"callee.list","digest":digest},"input":"{}"});
        data.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let active = crate::authority_state::current(&tx)?;
        let authorized = crate::capabilities::authorized(
            &tx,
            &granted.caller,
            &request,
            &Instruction {
                kind: "observe".into(),
                model: "app.query.v1".into(),
                data: data.to_string(),
                ..Instruction::default()
            },
            active.policy()?,
            "ob_imported_0",
        )?;
        let binding = authorized.resource().binding.clone();
        let call = authorized
            .delegated_call()
            .context("delegated call")?
            .clone();
        tx.commit()?;
        Ok::<_, anyhow::Error>((binding, call))
    };
    let (binding, call) = request(&granted.imported_digest, json!({}))?;
    assert_eq!(binding, "directory");
    assert_eq!(call.actor, "alice");
    assert_eq!(call.app, "callee");
    assert_eq!(call.operation, "callee.list");
    assert_eq!(
        call.contract_digest.as_deref(),
        Some(granted.imported_digest.as_str())
    );
    assert!(request(&format!("sha256:{}", "0".repeat(64)), json!({})).is_err());
    assert!(
        request(
            &granted.imported_digest,
            json!({"contract":{"operation":"callee.other","digest":granted.imported_digest}})
        )
        .is_err()
    );
    assert!(request(&granted.imported_digest, json!({"actor":"mallory"})).is_err());
    assert!(request(&granted.imported_digest, json!({"handle":"forged"})).is_err());
    Ok(())
}

/// The grant decides what may be called; the request decides who is calling.
///
/// The mutation this exists to kill is one line: the capability branch choosing
/// any actor other than `request.context.actor`. Nothing else in the delegation
/// tests can see it, because they hand `delegation::read` a `Call` they built.
#[test]
fn the_grant_decides_what_may_be_called_and_the_request_decides_who_calls_it() -> Result<()> {
    let granted = Granted::new()?;
    let runtime = &granted.caller;
    runtime.accept("ask", "alice", "asking", &json!({}), 100)?;
    let call = granted_call(runtime, "asking", json!({}))?;
    assert_eq!(
        call.actor, "alice",
        "the delegated call did not run as the actor who asked"
    );
    assert_eq!(call.app, "callee");
    assert_eq!(call.operation, "callee.list");
    assert_eq!(
        call.caller, "caller",
        "the callee would not be told which application asked"
    );
    Ok(())
}

fn granted_call(
    runtime: &Runtime,
    id: &str,
    extra: serde_json::Value,
) -> Result<crate::delegation::Call> {
    granted_call_at(runtime, id, extra, &format!("ob_{id}_0"))
}

fn granted_call_at(
    runtime: &Runtime,
    id: &str,
    extra: serde_json::Value,
    step: &str,
) -> Result<crate::delegation::Call> {
    let mut connection = open(runtime.db())?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let request = Request {
        operation: "ask".into(),
        input: "{}".into(),
        context: crate::store::invocation_context(&tx, id)?,
        observations: Vec::new(),
    };
    let bound = crate::resources::host_operation(
        &tx,
        runtime,
        &request,
        &Instruction {
            kind: "observe".into(),
            model: crate::resources::BIND.into(),
            data: json!({"binding":"directory","invocation":id}).to_string(),
            ..Instruction::default()
        },
    )?
    .context("resource binding result")?;
    let token = serde_json::from_str::<serde_json::Value>(&bound)?["token"]
        .as_str()
        .context("handle token")?
        .to_owned();

    let active = crate::authority_state::current(&tx)?;
    let mut data = json!({"handle":token,"input":"{}"});
    data.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let authorized = crate::capabilities::authorized(
        &tx,
        runtime,
        &request,
        &Instruction {
            kind: "observe".into(),
            model: "app.query.v1".into(),
            data: data.to_string(),
            ..Instruction::default()
        },
        active.policy()?,
        step,
    )?;

    Ok(authorized
        .delegated_call()
        .context("a delegated call")?
        .clone())
}

#[test]
fn cached_delegation_authorization_requires_no_dispatch_step_but_a_call_does() -> Result<()> {
    let granted = Granted::new()?;
    granted
        .caller
        .accept("ask", "alice", "cached", &json!({}), 100)?;
    let call = granted_call_at(&granted.caller, "cached", json!({}), "")?;
    assert_eq!(call.actor, "alice");
    assert_eq!(
        crate::delegation::read(&granted.caller, &call)
            .unwrap_err()
            .to_string(),
        "delegated_read_requires_a_step"
    );
    Ok(())
}

#[test]
fn impersonation_delegated_capability_inherits_actor_and_rejects_identity_overrides() -> Result<()>
{
    let granted = Granted::new()?;
    let runtime = &granted.caller;
    runtime.accept_on_behalf_of(
        "ask",
        ActingAs {
            authenticated: "support",
            actor: "alice",
            trigger: crate::audit::Trigger::Request,
        },
        "outer",
        &json!({}),
        100,
    )?;
    runtime.accept_delegated(
        "ask",
        "inner",
        &json!({}),
        100,
        Cause::delegated("alice", "first.second.third", "app:third"),
    )?;
    for (id, chain) in [("outer", ""), ("inner", "first.second.third")] {
        let call = granted_call(runtime, id, json!({}))?;
        assert_eq!(call.actor, "alice");
        assert_eq!(call.chain, chain);
        assert_eq!(call.caller, "caller");
        assert_eq!(call.origin, id);
        for field in [
            "actor",
            "authenticated",
            "delegation_rule",
            "caller",
            "chain",
        ] {
            let mut extra = serde_json::Map::new();
            extra.insert(field.into(), json!("mallory"));
            let error = granted_call(runtime, id, extra.into())
                .err()
                .expect("identity override must fail");
            assert!(
                error
                    .to_string()
                    .starts_with(&format!("unknown field `{field}`")),
                "{error:#}"
            );
        }
    }
    Ok(())
}

/// Acting for someone else, and the two gates it has to pass.
///
/// The rule settles *whose* request this is; the operation's own policy then
/// decides what that principal may do. Both, in that order, and the audit keeps
/// both identities — an entry holding only the effective principal would
/// attribute an administrator's action to the customer.
struct Impersonating {
    _directory: tempfile::TempDir,
    runtime: Runtime,
}

impl Impersonating {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        let state = directory.path().join(".state");
        fs::create_dir_all(&state)?;
        let artifact_directory = directory.path().join("support-contract");
        fs::create_dir(&artifact_directory)?;
        let policy = json!({"version":1,"admins":["boss"],
            "operations":{"look":{"actors":["alice","bob","customer","customer:other","boss","it","app:worker","svc:worker"],
                "mode":{"kind":"current_state"},"models":{},"observations":[],"effects":[]}},
            "delegations":{
                "support": {"authenticated":["alice","bob"],
                    "may_act_as":{"kind":"any_human"},"paths":["request"]},
                "gateway": {"authenticated":["svc:gateway"],
                    "may_act_as":{"kind":"actors","actors":["customer"]},"paths":["ingress"]}}});
        let instance = json!({"installation":"supportco","environment":"test",
            "control":{"version":1,"state_directory":directory.path().join("control"),
                "operators":["it"],"sources":{},"apps":{}},
            "apps":{"support":{"artifact":artifact_directory,"readers":[],
                "writers":["alice","bob","customer","customer:other","boss","it","app:worker","svc:worker","no-access"],
                "authority":policy}}});
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let contract = serde_json::from_value(json!({
            "format":crate::artifact::CURRENT_FORMAT,"roc_version":"support-test",
            "worker_digest":"support-test","schema_digest":"support-test",
            "schema":{"models":{"items":{"fields":{"value":"text"}}},
                "inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":[{"name":"look","kind":"command","input_type":"input","output_type":""}],
            "sources":{},"admission":"local-spike-only"}))?;
        let runtime = Runtime {
            integrations: Arc::new(integration_host::Host::local(&path)?),
            app_calls: None,
            instance_path: path,
            app: "support".into(),
            db: state.join("support.sqlite"),
            scope: "supportco/test/support".into(),
            hosted_domain: None,
            artifact: Arc::new(LoadedArtifact::from_contract_for_tests(
                "support-test".into(),
                artifact_directory,
                contract,
            )),
            host: Arc::new(crate::host::System),
        };
        runtime.initialize()?;
        Ok(Self {
            _directory: directory,
            runtime,
        })
    }

    fn recorded(&self, id: &str) -> Result<(String, String, String)> {
        let connection = open(self.runtime.db())?;
        Ok(connection.query_row(
            "SELECT actor,authenticated,delegation_rule FROM day2_invocations WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?)
    }

    fn admit(
        &self,
        authenticated: &str,
        actor: &str,
        id: &str,
        trigger: crate::audit::Trigger,
    ) -> Result<()> {
        self.runtime.accept_on_behalf_of(
            "look",
            ActingAs {
                authenticated,
                actor,
                trigger,
            },
            id,
            &json!({}),
            100,
        )
    }

    fn refused(&self, result: Result<()>, id: &str, code: &str) -> Result<()> {
        assert_eq!(
            result.expect_err("request must be refused").to_string(),
            code
        );
        let count: i64 = open(self.runtime.db())?.query_row(
            "SELECT count(*) FROM day2_invocations WHERE id=?1",
            [id],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0, "a refused request left an invocation behind");
        Ok(())
    }

    fn change_policy(&self, change: impl FnOnce(&mut crate::authority::Policy)) -> Result<()> {
        let active = crate::authority_state::current(&open(self.runtime.db())?)?;
        let mut document = active.document;
        change(document.policy.as_mut().context("fixture policy")?);
        crate::authority_state::apply(
            &self.runtime,
            &crate::authority_state::LocalOperator::assert_local("it")?,
            &crate::authority_state::ApplyAuthority {
                request_id: format!("policy-{}", active.stamp.revision),
                expected: Some(active.stamp),
                document,
            },
        )?;
        Ok(())
    }

    fn admission(&self, id: &str) -> Result<(String, Option<String>, String)> {
        Ok(open(self.runtime.db())?.query_row(
            "SELECT actor,initiator,outcome FROM day2_audit_events
             WHERE identity=?1 AND kind='admission' ORDER BY sequence DESC LIMIT 1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?)
    }
}

#[test]
fn acting_for_another_principal_needs_a_rule_and_records_both_identities() -> Result<()> {
    let world = Impersonating::new()?;
    let runtime = &world.runtime;
    let trigger = crate::audit::Trigger::Request;

    // Permitted: a support actor acting for an ordinary customer.
    runtime.accept_on_behalf_of(
        "look",
        crate::store::ActingAs {
            authenticated: "alice",
            actor: "customer",
            trigger,
        },
        "ok",
        &json!({}),
        100,
    )?;
    assert_eq!(
        world.recorded("ok")?,
        (
            "customer".to_owned(),
            "alice".to_owned(),
            "support".to_owned()
        ),
        "the invocation did not keep both identities and the rule that allowed it"
    );

    // An operator of this installation is never somebody to act as: a chain
    // through one is ambiguous about who decided, and the authority it carries
    // includes the authority to widen this rule.
    assert!(
        runtime
            .accept_on_behalf_of(
                "look",
                crate::store::ActingAs {
                    authenticated: "alice",
                    actor: "it",
                    trigger
                },
                "operator",
                &json!({}),
                100,
            )
            .is_err(),
        "an installation operator was impersonated"
    );
    // An administrator of this application, likewise.
    assert!(
        runtime
            .accept_on_behalf_of(
                "look",
                crate::store::ActingAs {
                    authenticated: "alice",
                    actor: "boss",
                    trigger
                },
                "admin",
                &json!({}),
                100,
            )
            .is_err(),
        "an application administrator was impersonated"
    );

    // The rule is bound to the path it was written for. A gateway's rule is not
    // exercisable from a session, however well the principals match.
    assert!(
        runtime
            .accept_on_behalf_of(
                "look",
                crate::store::ActingAs {
                    authenticated: "svc:gateway",
                    actor: "customer",
                    trigger
                },
                "wrong-path",
                &json!({}),
                100,
            )
            .is_err(),
        "a rule written for ingress was used from a request"
    );
    runtime.accept_on_behalf_of(
        "look",
        crate::store::ActingAs {
            authenticated: "svc:gateway",
            actor: "customer",
            trigger: crate::audit::Trigger::Ingress,
        },
        "right-path",
        &json!({}),
        100,
    )?;

    // Nobody authorized acting for anybody.
    assert!(
        runtime
            .accept_on_behalf_of(
                "look",
                crate::store::ActingAs {
                    authenticated: "customer",
                    actor: "alice",
                    trigger
                },
                "no-rule",
                &json!({}),
                100,
            )
            .is_err(),
        "an actor with no rule acted for someone else"
    );

    // And the ordinary case stays ordinary: no rule, nothing recorded.
    runtime.accept("look", "alice", "direct", &json!({}), 100)?;
    assert_eq!(
        world.recorded("direct")?,
        ("alice".to_owned(), String::new(), String::new())
    );
    Ok(())
}

#[test]
fn impersonation_retries_bind_requester_path_and_call_chain() -> Result<()> {
    use crate::audit::Trigger;
    let world = Impersonating::new()?;
    world.admit("alice", "customer", "retry", Trigger::Request)?;
    world.admit("alice", "customer", "retry", Trigger::Request)?;
    let original = world.recorded("retry")?;
    for result in [
        world.admit("bob", "customer", "retry", Trigger::Request),
        world
            .runtime
            .accept("look", "customer", "retry", &json!({}), 101),
    ] {
        assert_eq!(result.unwrap_err().to_string(), "idempotency_key_conflict");
        assert_eq!(world.recorded("retry")?, original);
    }

    // The same principal pair and rule may use two paths; switching paths is
    // nevertheless not a retry of the same admission.
    world.change_policy(|policy| {
        policy
            .delegations
            .get_mut("support")
            .unwrap()
            .paths
            .insert("ingress".into());
    })?;
    world.admit("alice", "customer", "path", Trigger::Request)?;
    assert_eq!(
        world
            .admit("alice", "customer", "path", Trigger::Ingress)
            .unwrap_err()
            .to_string(),
        "idempotency_key_conflict"
    );

    world.runtime.accept_delegated(
        "look",
        "hop",
        &json!({}),
        100,
        Cause::delegated("customer", "gateway.caller", "app:caller"),
    )?;
    world.runtime.accept_delegated(
        "look",
        "hop",
        &json!({}),
        101,
        Cause::delegated("customer", "gateway.caller", "app:caller"),
    )?;
    assert_eq!(
        world
            .runtime
            .accept_delegated(
                "look",
                "hop",
                &json!({}),
                102,
                Cause::delegated("customer", "other.caller", "app:caller")
            )
            .unwrap_err()
            .to_string(),
        "idempotency_key_conflict"
    );
    Ok(())
}

#[test]
fn impersonation_completed_retries_cannot_change_the_rule_or_escape_revocation() -> Result<()> {
    use crate::audit::Trigger;
    let world = Impersonating::new()?;
    world.admit("alice", "customer", "completed", Trigger::Request)?;
    // This fixture has no worker: finish the host record directly to exercise
    // the completed-receipt branch, which deliberately permits policy changes.
    open(world.runtime.db())?.execute(
        "UPDATE day2_invocations SET status='success' WHERE id='completed'",
        [],
    )?;
    world.admit("alice", "customer", "completed", Trigger::Request)?;
    for result in [
        world.admit("bob", "customer", "completed", Trigger::Request),
        world
            .runtime
            .accept("look", "customer", "completed", &json!({}), 101),
    ] {
        assert_eq!(result.unwrap_err().to_string(), "idempotency_key_conflict");
    }
    world.change_policy(|policy| {
        let rule = policy.delegations.remove("support").unwrap();
        policy.delegations.insert("replacement".into(), rule);
    })?;
    assert_eq!(
        world
            .admit("alice", "customer", "completed", Trigger::Request)
            .unwrap_err()
            .to_string(),
        "idempotency_key_conflict"
    );
    assert_eq!(world.recorded("completed")?.2, "support");
    world.change_policy(|policy| policy.delegations.clear())?;
    assert_eq!(
        world
            .admit("alice", "customer", "completed", Trigger::Request)
            .unwrap_err()
            .to_string(),
        "forbidden"
    );
    world.refused(
        world.admit("alice", "customer", "revoked", Trigger::Request),
        "revoked",
        "forbidden",
    )?;
    Ok(())
}

#[test]
fn impersonation_rules_are_exact_and_never_lend_the_requesters_permissions() -> Result<()> {
    use crate::audit::Trigger;
    let world = Impersonating::new()?;
    for (id, authenticated, actor, trigger) in [
        ("unknown-requester", "mallory", "customer", Trigger::Request),
        ("wrong-path", "svc:gateway", "customer", Trigger::Request),
        (
            "prefix-requester",
            "svc:gateway:other",
            "customer",
            Trigger::Ingress,
        ),
        (
            "prefix-target",
            "svc:gateway",
            "customer:other",
            Trigger::Ingress,
        ),
        ("no-permission", "alice", "no-access", Trigger::Request),
    ] {
        world.refused(
            world.admit(authenticated, actor, id, trigger),
            id,
            "forbidden",
        )?;
    }
    // Gateway is not a member and cannot run look itself. Its customer can.
    world.admit("svc:gateway", "customer", "gateway", Trigger::Ingress)?;
    world.admit("alice", "customer", "support", Trigger::Request)?;
    Ok(())
}

#[test]
fn impersonation_any_human_excludes_operators_admins_and_service_principals() -> Result<()> {
    use crate::audit::Trigger;
    let world = Impersonating::new()?;
    for (id, target) in [
        ("operator", "it"),
        ("admin", "boss"),
        ("application", "app:worker"),
        ("service", "svc:worker"),
    ] {
        // Prove the ordinary operation is allowed, so another permission check
        // cannot hide a broken impersonation exclusion.
        world.runtime.authorize("look", target)?;
        world.refused(
            world.admit("alice", target, id, Trigger::Request),
            id,
            "forbidden",
        )?;
    }
    world.admit("alice", "customer", "human", Trigger::Request)?;
    Ok(())
}

#[test]
fn impersonation_requires_an_identity_and_same_principal_stays_direct() -> Result<()> {
    use crate::audit::Trigger;
    let world = Impersonating::new()?;
    for (id, authenticated) in [
        ("missing", ""),
        ("whitespace", " alice"),
        ("control", "alice\n"),
    ] {
        world.refused(
            world.admit(authenticated, "customer", id, Trigger::Request),
            id,
            "invalid authority actor",
        )?;
    }
    world.admit("customer", "customer", "direct", Trigger::Request)?;
    world
        .runtime
        .accept("look", "customer", "direct", &json!({}), 101)?;
    let context = invocation_context(&open(world.runtime.db())?, "direct")?;
    assert_eq!(context.actor, "customer");
    assert!(
        context.authenticated.is_empty(),
        "same-principal request was marked as impersonation"
    );
    assert!(context.delegation_rule.is_empty());
    assert_eq!(
        world.admission("direct")?,
        ("customer".into(), Some("customer".into()), "reused".into())
    );
    Ok(())
}

#[test]
fn impersonation_cannot_be_introduced_by_a_schedule_child_or_later_hop() -> Result<()> {
    use crate::audit::Trigger;
    let world = Impersonating::new()?;
    for (id, trigger, caller) in [
        ("schedule", Trigger::Schedule, ""),
        ("child", Trigger::CommandRequest, ""),
        ("request-hop", Trigger::Request, "gateway.caller"),
        ("ingress-hop", Trigger::Ingress, "gateway.caller"),
    ] {
        world.refused(
            world.runtime.accept_with_caller(
                "look",
                "customer",
                id,
                &json!({}),
                100,
                Cause {
                    trigger,
                    actor: "customer",
                    caller,
                    authenticated: "alice",
                    origin: None,
                },
            ),
            id,
            "delegation_only_at_the_outermost_call",
        )?;
    }
    for (id, caller, authenticated) in [
        ("no-chain", "", "app:caller"),
        ("not-application", "gateway.caller", "alice"),
        ("wrong-application", "gateway.caller", "app:other"),
    ] {
        world.refused(
            world.runtime.accept_delegated(
                "look",
                id,
                &json!({}),
                100,
                Cause::delegated("customer", caller, authenticated),
            ),
            id,
            "delegated_call_requires_a_calling_application",
        )?;
    }
    // Inheriting a customer at a delegated hop is allowed without an act-as
    // rule for the application. The caller is authenticated, not promoted.
    world.runtime.accept_delegated(
        "look",
        "inherited",
        &json!({}),
        100,
        Cause::delegated("customer", "gateway.caller", "app:caller"),
    )?;
    let context = invocation_context(&open(world.runtime.db())?, "inherited")?;
    assert_eq!(context.actor, "customer");
    assert_eq!(context.authenticated, "app:caller");
    assert_eq!(context.caller, ["gateway", "caller"]);
    assert!(context.delegation_rule.is_empty());
    Ok(())
}

#[test]
fn impersonation_audit_preserves_both_identities_on_accept_reuse_and_rejection() -> Result<()> {
    use crate::audit::Trigger;
    let world = Impersonating::new()?;
    world.admit("alice", "customer", "audit", Trigger::Request)?;
    assert_eq!(
        world.admission("audit")?,
        ("customer".into(), Some("alice".into()), "accepted".into())
    );
    world.admit("alice", "customer", "audit", Trigger::Request)?;
    assert_eq!(
        world.admission("audit")?,
        ("customer".into(), Some("alice".into()), "reused".into())
    );
    world.refused(
        world.admit("mallory", "customer", "denied", Trigger::Request),
        "denied",
        "forbidden",
    )?;
    assert_eq!(
        world.admission("denied")?,
        ("customer".into(), Some("mallory".into()), "rejected".into())
    );
    let context = invocation_context(&open(world.runtime.db())?, "audit")?;
    assert_eq!(context.actor, "customer");
    assert_eq!(context.authenticated, "alice");
    assert_eq!(context.delegation_rule, "support");
    // Exercise the actual SQLite receipt trigger without needing a Roc worker.
    let db = open(world.runtime.db())?;
    db.execute(
        "INSERT INTO day2_audit(invocation,actor,operation,status,at)
        VALUES('audit','customer','look','success',100)",
        [],
    )?;
    let receipt: (String, String, String) = db.query_row(
        "SELECT actor,initiator,reason FROM day2_audit_events
         WHERE identity='audit' AND kind='invocation'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(
        receipt,
        ("customer".into(), "alice".into(), "support".into())
    );
    Ok(())
}

#[test]
fn impersonation_audit_keeps_the_initiator_and_cause_after_execution_interruption() -> Result<()> {
    use crate::audit::Trigger;
    let world = Impersonating::new()?;
    world.admit("svc:gateway", "customer", "ingress", Trigger::Ingress)?;
    world.runtime.accept_delegated(
        "look",
        "delegated",
        &json!({}),
        100,
        Cause::delegated("customer", "caller", "app:caller"),
    )?;
    for (id, authenticated, trigger) in [
        ("ingress", "svc:gateway", "ingress"),
        ("delegated", "app:caller", "delegated"),
    ] {
        world.runtime.audit_execution_interruption(id)?;
        let recorded: (String, String) = open(world.runtime.db())?.query_row(
            "SELECT initiator,trigger FROM day2_audit_events
             WHERE identity=?1 AND kind='execution_attempt'",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(recorded, (authenticated.into(), trigger.into()));
    }
    Ok(())
}
