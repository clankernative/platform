//! A delegated status read discloses a completed result only under the
//! authority that produced it: the same captured-policy and authority-stamp
//! rule an ordinary receipt follows, so narrowing a grant withholds the old
//! result and restoring the old document does not bring it back.
use super::*;
use crate::{
    delegation::Purpose,
    delegation_wire::{Query, Scope, Signer, TrustedKey, Verifier},
    integration_host,
    protocol::{Context, ExecutionGuard, Request, Trace},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, sync::Arc};

struct Callee {
    _directory: tempfile::TempDir,
    runtime: Runtime,
}

impl Callee {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        let state = directory.path().join(".state");
        fs::create_dir_all(&state)?;
        let artifact_directory = directory.path().join("status-contract");
        fs::create_dir(&artifact_directory)?;
        let policy = json!({"version":1,"admins":[],
            "operations":{"make":{"actors":["alice"],"mode":{"kind":"current_state"},
                "models":{"items":{"read":true,"create":true,"update_fields":["value"],"rows":{"kind":"all"}}},
                "observations":[],"effects":[]}}});
        let instance = json!({"installation":"statusco","environment":"test",
            "control":{"version":1,"state_directory":directory.path().join("control"),
                "operators":["it"],"sources":{},"apps":{}},
            "apps":{"callee":{"artifact":artifact_directory,"readers":[],"writers":["alice"],
                "authority":policy}}});
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let contract = serde_json::from_value(json!({
            "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,"roc_version":"status-test",
            "worker_digest":"status-test","schema_digest":"status-test",
            "schema":{"models":{"items":{"fields":{"value":"text"}}},
                "inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":[{"name":"make","kind":"command","input_type":"input","output_type":""}],
            "sources":{},"admission":"local-spike-only"}))?;
        let inputs = crate::host_inputs::Inputs::default();
        let runtime = Runtime {
            integrations: Arc::new(integration_host::Host::local(&path)?),
            app_calls: None,
            credentials: None,
            connections: None,
            instance_path: path,
            app: "callee".into(),
            db: state.join("callee.sqlite"),
            scope: "statusco/test/callee".into(),
            hosted_domain: None,
            artifact: Arc::new(LoadedArtifact::from_contract_for_tests(
                "status-test".into(),
                artifact_directory,
                contract,
            )),
            host: Arc::new(crate::host::System(inputs.clone())),
            inputs,
        };
        runtime.initialize()?;
        Ok(Self {
            _directory: directory,
            runtime,
        })
    }

    fn source() -> Scope {
        Scope {
            installation: "statusco".into(),
            environment: "test".into(),
            app: "caller".into(),
        }
    }

    /// A delegated invocation completed under the authority active now, as the
    /// callee's executor would have recorded it.
    fn completed(&self, id: &str, receipt: &str, result: Value) -> Result<()> {
        self.runtime.accept("make", "alice", id, &json!({}), 100)?;
        let connection = open(self.runtime.db())?;
        let active = crate::authority_state::current(&connection)?;
        let outcome = Outcome {
            status: "success".into(),
            result,
            error: String::new(),
        };
        let trace = Trace {
            format: 2,
            artifact: self.runtime.artifact().id().into(),
            scope: self.runtime.scope().into(),
            request: Request {
                operation: "make".into(),
                input: "{}".into(),
                context: Context {
                    invocation_id: id.into(),
                    actor: "alice".into(),
                    now: 100,
                    authentication: "delivery".into(),
                    caller: vec!["caller".into()],
                    authenticated: "app:caller".into(),
                    delegation_rule: String::new(),
                },
                observations: Vec::new(),
            },
            outcome: outcome.clone(),
            guard: Some(ExecutionGuard {
                policy: active.policy()?.clone(),
                authority: Some(crate::authority_state::invocation_stamp(&connection, id)?),
                precondition_row: None,
                error: String::new(),
            }),
        };
        connection.execute(
            "UPDATE day2_invocations SET status='success',outcome=?1,trace=?2 WHERE id=?3",
            params![
                serde_json::to_string(&outcome)?,
                serde_json::to_string(&trace)?,
                id
            ],
        )?;
        connection.execute(
            "INSERT INTO day2_app_inbox VALUES(?1,'fingerprint',?2,'alice','make','',?3,100)",
            params![receipt, Self::source().runtime_scope(), id],
        )?;
        Ok(())
    }

    fn status(&self, receipt: &str) -> Result<Value> {
        let source = Self::source();
        let query = Query {
            version: 1,
            purpose: Purpose::Status,
            source_epoch: crate::digest(b"epoch"),
            budget: 1,
            delivery: None,
            source: source.clone(),
            target: Scope {
                app: "callee".into(),
                ..source.clone()
            },
            operation: "make".into(),
            schema_digest: crate::delegation::schema_digest(&self.runtime, "make")?,
            contract_digest: None,
            input: json!({"id":receipt}),
            actor: "alice".into(),
            origin: "caller-root".into(),
            step: "ob_caller_0".into(),
            chain: "entry".into(),
            now: 100,
            issued_at: 100,
            expires_at: 130,
            activation: day2_capabilities::Digest::new(b"active"),
            generation: 1,
            serving: Value::Null,
        };
        let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("test key"))?;
        let signer = Signer::from_pkcs8("caller", key.as_ref())?;
        let verifier = Verifier::new(BTreeMap::from([(
            "caller".into(),
            TrustedKey {
                source,
                public_key: signer.public_key(),
            },
        )]))?;
        let verified = verifier.verify(&signer.sign(&query)?, 100)?;
        Ok(serde_json::from_str(&crate::delegation_commands::status(
            &self.runtime,
            &verified,
        )?)?)
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
}

fn receipt(seed: char) -> String {
    format!("rcp_{}", seed.to_string().repeat(64))
}

#[test]
fn delegated_status_returns_a_result_only_under_its_original_authority() -> Result<()> {
    let callee = Callee::new()?;
    let (first, second) = (receipt('a'), receipt('b'));
    callee.completed("dlg_first", &first, json!({"made":"first"}))?;
    assert_eq!(
        callee.status(&first)?,
        json!({"id":first,"status":"success","output":"{\"made\":\"first\"}"})
    );

    // The operator narrows the field scope. Operation access remains, so the
    // status read is admitted, but the result was produced under wider authority.
    let original = crate::authority_state::current(&open(callee.runtime.db())?)?
        .policy()?
        .clone();
    callee.change_policy(|policy| {
        let grant = policy.operations.get_mut("make").unwrap();
        grant.models.get_mut("items").unwrap().update_fields.clear();
    })?;
    assert_eq!(
        callee.status(&first)?,
        json!({"id":first,"status":"blocked","output":""})
    );

    // A -> B -> A: the restored document is a new revision, so the old result
    // stays withheld while a result produced under it is disclosed.
    callee.change_policy(|policy| *policy = original)?;
    assert_eq!(
        callee.status(&first)?,
        json!({"id":first,"status":"blocked","output":""})
    );
    callee.completed("dlg_second", &second, json!({"made":"second"}))?;
    assert_eq!(
        callee.status(&second)?,
        json!({"id":second,"status":"success","output":"{\"made\":\"second\"}"})
    );
    Ok(())
}
