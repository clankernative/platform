//! The admitted internal-tools library read against independent, scoped
//! control-plane worlds: real resource handles, real authorization and the
//! committed SQLite world. No Roc worker, network request or live-provider
//! qualification is claimed.
use super::{Observed, Variant, check, fixture, worlds_in_scope};
use crate::{
    artifact::{Instance, LoadedArtifact},
    capabilities,
    integrations::simulated::{
        self, INTERNAL_TOOLS_LIBRARY_ENDPOINT, INTERNAL_TOOLS_SIGN_ENDPOINT,
        INTERNAL_TOOLS_TOKEN_ENDPOINT, InternalToolsWorld, ScheduledFault, SimulatedFault, World,
    },
    internal_tools::{
        MAX_APPS, MAX_PAGES, PAGE_SIZE, SIGNING_CALLS, SIGNING_REQUEST_BYTES,
        SIGNING_RESPONSE_BYTES, page_query, service_token_request,
    },
    protocol::{Instruction, Request},
    simulation::Simulation,
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::resources::{Action, Provider};
use serde_json::{Value, json};
use std::{cell::Cell, fs};

const ACTOR: &str = "alice";
const INVOCATION: &str = "internal-tools-coverage";
const ACTION: Action = Action::InternalToolsAppLibrary;
const SERVICE_TOKEN: &str = "coverage-service-token";

fn world(apps: Vec<Value>) -> InternalToolsWorld {
    InternalToolsWorld {
        service_account: "home-reader@coverage.iam.gserviceaccount.com".into(),
        origin: "https://it.coverage.test".into(),
        iap_audience: "https://it.coverage.test/*".into(),
        target_app_id: "it".into(),
        service_token: SERVICE_TOKEN.into(),
        apps,
    }
}

/// A control-plane entry with every field the adapter must ignore.
fn entry(app_id: &str, name: &str, subdomain: Option<&str>) -> Value {
    let mut value = json!({"id":format!("id-{app_id}"),"displayName":name,"appId":app_id,
        "repositorySlug":format!("private/{app_id}"),"customFields":{"cost_center":"secret-cc"},
        "catalogAppPath":"apps/private","owners":[{"email":"owner@private.test"}],
        "viewerCanManageOwners":true,"needsNewOwner":false});
    if let Some(subdomain) = subdomain {
        value["subdomain"] = json!(subdomain);
    }
    value
}

fn variant_world(variant: Variant) -> InternalToolsWorld {
    world(vec![
        entry("quoty", "Quoty", Some("quoty")),
        entry(
            "onsites",
            match variant {
                Variant::A => "Onsites",
                Variant::B => "Offsites",
            },
            Some("onsites"),
        ),
    ])
}

struct Harness {
    _directory: tempfile::TempDir,
    simulation: Simulation,
}

impl Harness {
    fn new(world: InternalToolsWorld) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        let artifact_path = directory.path().join("contract");
        fs::create_dir(&artifact_path)?;
        let connection = |account: &str, origin: &str, target: &str| {
            json!({"revision":1,"provider":"internal_tools","live":{"provider":"internal_tools",
                "service_account":format!("{account}@coverage.iam.gserviceaccount.com"),
                "origin":origin,"iap_audience":format!("{origin}/*"),"target_app_id":target}})
        };
        let resource = |connection: &str, domain: &str| {
            json!({"revision":1,"connection":{"id":connection,"revision":1},
                "target":{"kind":"internal_tools_library","app_domain":domain}})
        };
        let slot = |id: &str| {
            json!({"kind":"internal_tools_library","allowed_resources":[{"id":id,"revision":1}],
            "actions":[ACTION],"limits":{"max_request_bytes":65536,"max_response_bytes":4194304,
                "max_calls_per_invocation":64},"budgets":[{"id":"calls","revision":1}]})
        };
        let instance = json!({"installation":"toolsco","environment":"test","resources":{
            "version":1,"connections":{
                "tools":connection("home-reader","https://it.coverage.test","it"),
                "other_account":connection("other-reader","https://it.coverage.test","it"),
                "other_origin":connection("home-reader","https://it.elsewhere.test","it"),
                "other_target":connection("home-reader","https://it.coverage.test","other")},
            "resources":{"main":resource("tools","coverage.test"),
                "other_domain":resource("tools","elsewhere.test"),
                "other_account":resource("other_account","coverage.test"),
                "other_origin":resource("other_origin","coverage.test"),
                "other_target":resource("other_target","coverage.test")},
            "policies":{"tools":{"revision":1,"owner":"it","actors":[ACTOR],"allowed_apps":["app"],
                "max_duration_seconds":null,"slots":{"main":slot("main"),
                    "other_domain":slot("other_domain"),"other_account":slot("other_account"),
                    "other_origin":slot("other_origin"),
                    "other_target":slot("other_target")}}},
            "budgets":{"calls":{"revision":1,"scope":"app","period_seconds":3600,
                "limits":{"calls":10000,"bytes":1000000000,"concurrency":1}}}},
            "apps":{"app":{"artifact":artifact_path,"readers":[ACTOR],"writers":[ACTOR],
                "authority":{"version":1,"admins":[],"operations":{"tools":{"actors":[ACTOR],
                    "mode":{"kind":"current_state"},"models":{},
                    "observations":[ACTION.capability()],"effects":[]}}},
                "resource_policies":[{"policy":{"id":"tools","revision":1},"operation":"tools",
                    "bindings":{"main":{"id":"main","revision":1},
                        "other_domain":{"id":"other_domain","revision":1},
                        "other_account":{"id":"other_account","revision":1},
                        "other_origin":{"id":"other_origin","revision":1},
                        "other_target":{"id":"other_target","revision":1}}}]}}});
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let admitted = Instance::load(&path)?;
        let artifact = LoadedArtifact::from_contract_for_tests(
            crate::digest(b"admitted-internal-tools-coverage-contract"),
            artifact_path,
            serde_json::from_value(json!({"format":crate::artifact::CURRENT_FORMAT,
                "verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
                "roc_version":"provider-boundary-fixture","worker_digest":"not-executed",
                "schema_digest":crate::digest(b"internal-tools-coverage-schema"),"namespace":"app",
                "schema":{"models":{"items":{"fields":{"value":"text"}}},
                    "inputs":{"empty":{"fields":{}}},"foreign_keys":[]},
                "operations":[{"name":"tools","kind":"command","input_type":"empty","output_type":""}],
                "sources":{},"admission":"local-spike-only"}))?,
        );
        crate::authority_state::AuthorityDocument::resolve_at(&admitted, "app", &artifact, 100000)?;
        let simulation = Simulation::new(
            Runtime::from_artifact_for_tests(
                path,
                "app".into(),
                directory.path().join("app.sqlite"),
                artifact,
            )?,
            [23; 32],
            100000,
        )?;
        simulation.runtime().initialize()?;
        // Every unrelated provider stays fixed across runs.
        let mut worlds = fixture(Variant::A);
        worlds.internal_tools = world;
        simulated::seed(
            simulation.runtime().db(),
            simulation.runtime().scope(),
            &worlds,
        )?;
        Ok(Self {
            _directory: directory,
            simulation,
        })
    }

    fn runtime(&self) -> &Runtime {
        self.simulation.runtime()
    }

    fn provider(&self) -> Result<World<InternalToolsWorld>> {
        let db = rusqlite::Connection::open_with_flags(
            self.runtime()
                .db()
                .with_file_name(Provider::InternalTools.world().unwrap()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let stored: String = db.query_row(
            "SELECT state FROM simulated_provider WHERE scope=?1",
            [self.runtime().scope()],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&stored)?)
    }

    fn schedule(&self, endpoint: &str, fault: SimulatedFault) -> Result<()> {
        simulated::schedule_faults(
            self.runtime().db(),
            self.runtime().scope(),
            Provider::InternalTools.world().unwrap(),
            vec![ScheduledFault {
                endpoint: endpoint.into(),
                remaining: 1,
                fault,
            }],
        )
    }

    fn authorize(
        &self,
        data: Value,
        binding: &str,
        actor: &str,
    ) -> Result<capabilities::Authorized> {
        let runtime = self.runtime();
        runtime.accept("tools", ACTOR, INVOCATION, &json!({}), 100)?;
        let mut db = crate::store::open(runtime.db())?;
        let tx = crate::write_queue::immediate(&mut db)?;
        let active = crate::authority_state::require_invocation_in(
            &tx, runtime, INVOCATION, "tools", ACTOR,
        )?;
        let mut context = crate::store::invocation_context(&tx, INVOCATION)?;
        context.actor = actor.into();
        let request = Request {
            operation: "tools".into(),
            input: "{}".into(),
            context,
            observations: Vec::new(),
        };
        let handle = crate::resources::host_operation(
            &tx,
            runtime,
            &request,
            &Instruction {
                model: crate::resources::BIND.into(),
                data: json!({"binding":binding,"invocation":INVOCATION}).to_string(),
                ..Default::default()
            },
        )?
        .context("resource handle missing")?;
        let handle: Value = serde_json::from_str(&handle)?;
        let mut data = data;
        data.as_object_mut()
            .context("request object")?
            .entry("handle")
            .or_insert(handle["token"].clone());
        let authorized = capabilities::authorized(
            &tx,
            runtime,
            &request,
            &Instruction {
                kind: "observe".into(),
                model: ACTION.capability().into(),
                data: data.to_string(),
                ..Default::default()
            },
            active.policy()?,
            ACTION.capability(),
        )?;
        tx.commit()?;
        Ok(authorized)
    }

    /// One admitted read through `binding`, with the provider result as the
    /// host settles it.
    fn read(&self, binding: &str) -> Result<capabilities::ProviderResult> {
        let authorized = self.authorize(json!({}), binding, ACTOR)?;
        ensure!(
            authorized.resource().grant.provider == Provider::InternalTools
                && authorized.resource().grant.resource.id == binding,
            "wrong admitted internal-tools resource"
        );
        let resource = authorized.resource().clone();
        // The admission transaction has closed before provider I/O.
        let outcome = capabilities::observe(self.runtime(), authorized, "tools-attempt");
        if let Ok(result) = &outcome.result {
            crate::resources::validate_result(&resource, result)?;
        }
        Ok(outcome)
    }

    fn dispatch(&self) -> Result<Observed> {
        let before = worlds_in_scope(self.runtime().db(), self.runtime().scope())?;
        let result = self.read("main")?.result?;
        let after = worlds_in_scope(self.runtime().db(), self.runtime().scope())?;
        Ok(Observed {
            result,
            before,
            after,
        })
    }
}

pub(super) fn observe(action: Action, variant: Variant) -> Result<Observed> {
    ensure!(action == ACTION, "not an internal-tools coverage action");
    Harness::new(variant_world(variant))?.dispatch()
}

fn library(apps: &[(&str, &str, &str)]) -> Value {
    json!({"apps":apps.iter().map(|(app_id, name, url)| json!({"app_id":app_id,"name":name,"url":url}))
        .collect::<Vec<_>>(),"captured_at":100})
}

/// What a page body weighs on the wire, computed independently of the
/// simulation that serves it.
fn page_bytes(apps: &[Value], page: usize, pages: usize) -> usize {
    let items: Vec<_> = apps
        .iter()
        .skip((page - 1) * PAGE_SIZE)
        .take(PAGE_SIZE)
        .collect();
    json!({"items":items,"page":page,"pageSize":PAGE_SIZE,"hasNextPage":page < pages})
        .to_string()
        .len()
}

#[test]
fn the_admitted_read_reflects_its_own_world_and_mutates_none() -> Result<()> {
    check(ACTION, |variant| observe(ACTION, variant)).map_err(anyhow::Error::msg)?;
    let first = observe(ACTION, Variant::A)?;
    let second = observe(ACTION, Variant::B)?;
    for provider in Provider::ALL {
        let key = provider.world().unwrap();
        assert_eq!(
            first.before[key] == second.before[key],
            *provider != Provider::InternalTools
        );
    }
    for wrong_world in [false, true] {
        let calls = Cell::new(0);
        let sabotage = |variant| {
            calls.set(calls.get() + 1);
            let mut actual = observe(ACTION, variant)?;
            actual.result = if wrong_world {
                actual.before[Provider::Slack.world().unwrap()]
                    .clone()
                    .context("foreign world missing")?
            } else {
                "constant-library".into()
            };
            Ok(actual)
        };
        assert!(check(ACTION, sabotage).is_err());
        assert_eq!(calls.get(), 2, "the gate must exercise its observer");
    }
    assert!(
        check(ACTION, |variant| {
            let mut actual = observe(ACTION, variant)?;
            actual.after.insert(
                Provider::InternalTools.world().unwrap(),
                Some("mutated".into()),
            );
            Ok(actual)
        })
        .is_err()
    );
    Ok(())
}

#[test]
fn only_launch_facts_leave_the_control_plane_sorted_deduplicated_and_complete() -> Result<()> {
    let apps = vec![
        entry("zeta", "zeta tools", Some("zeta")),
        entry("quoty", "Quoty", Some("quoty")),
        entry("drafts", "Drafts", None),
        entry("empty", "Empty", Some("")),
        entry("alpha", "Alpha", Some("alpha")),
        // The list moved between pages: the same app twice.
        entry("quoty", "Quoty", Some("quoty")),
        entry("beta", "  beta  ", Some("b")),
    ];
    let harness = Harness::new(world(apps.clone()))?;
    let before = harness.provider()?.world;
    let outcome = harness.read("main")?;
    let result: Value = serde_json::from_str(&outcome.result?)?;
    assert_eq!(
        result,
        library(&[
            ("alpha", "Alpha", "https://alpha.coverage.test/"),
            ("beta", "beta", "https://b.coverage.test/"),
            ("quoty", "Quoty", "https://quoty.coverage.test/"),
            ("zeta", "zeta tools", "https://zeta.coverage.test/"),
        ])
    );
    let text = result.to_string();
    for private in ["owner@private.test", "secret-cc", "private/", "id-quoty"] {
        assert!(!text.contains(private), "{private} left the control plane");
    }
    let state = harness.provider()?;
    assert_eq!(state.world, before, "a read mutates no provider data");
    assert_eq!(
        state.calls,
        vec![
            format!("{INTERNAL_TOOLS_SIGN_ENDPOINT}:home-reader@coverage.iam.gserviceaccount.com"),
            INTERNAL_TOOLS_TOKEN_ENDPOINT.to_owned(),
            format!("{INTERNAL_TOOLS_LIBRARY_ENDPOINT}:{}", page_query(1)),
        ]
    );
    // Metered exactly: signing at its bound, then the bytes each exchange sent
    // and read, computed without the adapter's meter.
    let token = json!({"token_type":"Bearer","expires_in":300,"service_token":SERVICE_TOKEN})
        .to_string()
        .len();
    let usage = outcome.usage;
    assert!(usage.known && usage.dispatched);
    assert_eq!(usage.calls, SIGNING_CALLS + 2);
    assert_eq!(
        usage.request_bytes,
        SIGNING_REQUEST_BYTES + (service_token_request("it").len() + page_query(1).len()) as u64
    );
    assert_eq!(
        usage.response_bytes,
        SIGNING_RESPONSE_BYTES + (token + page_bytes(&apps, 1, 1)) as u64
    );
    assert!(outcome.correlation.is_empty());
    Ok(())
}

#[test]
fn the_app_domain_comes_from_the_binding_never_the_provider() -> Result<()> {
    let harness = Harness::new(variant_world(Variant::A))?;
    let result: Value = serde_json::from_str(&harness.read("other_domain")?.result?)?;
    assert_eq!(
        result,
        library(&[
            ("onsites", "Onsites", "https://onsites.elsewhere.test/"),
            ("quoty", "Quoty", "https://quoty.elsewhere.test/"),
        ])
    );
    Ok(())
}

#[test]
fn another_connection_fails_closed_before_any_provider_exchange() -> Result<()> {
    // Each differs from the world's connection in one field. The audience lies
    // under the origin, so `other_origin` moves both.
    for binding in ["other_account", "other_origin", "other_target"] {
        let harness = Harness::new(variant_world(Variant::A))?;
        let before = harness.provider()?;
        let outcome = harness.read(binding)?;
        assert_eq!(
            outcome.result.unwrap_err().to_string(),
            "internal_tools_connection_mismatch"
        );
        assert_eq!(outcome.usage.calls, 0);
        assert!(!outcome.usage.dispatched);
        assert_eq!(
            harness.provider()?,
            before,
            "{binding}: no exchange recorded"
        );
        // The matching connection still reads the same world.
        assert!(harness.read("main")?.result.is_ok());
    }
    Ok(())
}

#[test]
fn authorization_refuses_a_foreign_actor_handle_or_binding_before_provider_io() -> Result<()> {
    let harness = Harness::new(variant_world(Variant::A))?;
    let before = harness.provider()?;
    assert!(harness.authorize(json!({}), "main", "mallory").is_err());
    assert!(
        harness
            .authorize(json!({"handle":"forged"}), "main", ACTOR)
            .is_err()
    );
    assert!(harness.authorize(json!({}), "unbound", ACTOR).is_err());
    // The app request names nothing but the handle.
    assert!(
        harness
            .authorize(json!({"origin":"https://evil.test"}), "main", ACTOR)
            .is_err()
    );
    assert_eq!(harness.provider()?, before);
    Ok(())
}

struct FaultCase {
    endpoint: &'static str,
    fault: SimulatedFault,
    code: &'static str,
    phase: crate::integrations::ExchangePhase,
    status: Option<u16>,
    calls: u64,
}

fn fault_cases() -> Vec<FaultCase> {
    use crate::integrations::ExchangePhase::*;
    let case = |endpoint, fault, code, phase, status, calls| FaultCase {
        endpoint,
        fault,
        code,
        phase,
        status,
        calls,
    };
    vec![
        case(
            INTERNAL_TOOLS_SIGN_ENDPOINT,
            SimulatedFault::Denied,
            "internal_tools_credential_unavailable",
            InternalToolsSigning,
            None,
            SIGNING_CALLS,
        ),
        case(
            INTERNAL_TOOLS_TOKEN_ENDPOINT,
            SimulatedFault::Denied,
            "internal_tools_service_token_refused",
            InternalToolsServiceToken,
            Some(403),
            SIGNING_CALLS + 1,
        ),
        case(
            INTERNAL_TOOLS_TOKEN_ENDPOINT,
            SimulatedFault::NotJson,
            "internal_tools_response_invalid",
            InternalToolsServiceToken,
            Some(200),
            SIGNING_CALLS + 1,
        ),
        case(
            INTERNAL_TOOLS_LIBRARY_ENDPOINT,
            SimulatedFault::Denied,
            "internal_tools_scope_denied",
            InternalToolsLibrary,
            Some(403),
            SIGNING_CALLS + 2,
        ),
        case(
            INTERNAL_TOOLS_LIBRARY_ENDPOINT,
            SimulatedFault::NotJson,
            "internal_tools_response_invalid",
            InternalToolsLibrary,
            Some(200),
            SIGNING_CALLS + 2,
        ),
        case(
            INTERNAL_TOOLS_LIBRARY_ENDPOINT,
            SimulatedFault::Oversized,
            "internal_tools_response_too_large",
            InternalToolsLibrary,
            Some(200),
            SIGNING_CALLS + 2,
        ),
        case(
            INTERNAL_TOOLS_LIBRARY_ENDPOINT,
            SimulatedFault::RateLimited,
            "internal_tools_rate_limited",
            InternalToolsLibrary,
            Some(429),
            SIGNING_CALLS + 2,
        ),
        case(
            INTERNAL_TOOLS_LIBRARY_ENDPOINT,
            SimulatedFault::ServerError,
            "internal_tools_unavailable",
            InternalToolsLibrary,
            Some(500),
            SIGNING_CALLS + 2,
        ),
        case(
            INTERNAL_TOOLS_LIBRARY_ENDPOINT,
            SimulatedFault::ConnectionLost,
            "internal_tools_unavailable",
            InternalToolsLibrary,
            None,
            SIGNING_CALLS + 2,
        ),
    ]
}

/// One fault, then recovery: the failure is metered and correlated with
/// typed metadata only, and the next read returns the unchanged library.
fn fault_replay(case: &FaultCase) -> Result<Value> {
    let harness = Harness::new(variant_world(Variant::A))?;
    let clean = harness.read("main")?.result?;
    harness.schedule(case.endpoint, case.fault)?;
    let failed = harness.read("main")?;
    let error = failed.result.as_ref().unwrap_err().to_string();
    assert_eq!(error, case.code, "{:?} at {}", case.fault, case.endpoint);
    assert!(failed.usage.known && failed.usage.dispatched);
    assert_eq!(failed.usage.calls, case.calls);
    assert!(failed.usage.response_bytes >= SIGNING_RESPONSE_BYTES);
    if case.fault == SimulatedFault::Oversized {
        // The oversized body was consumed up to the probe byte: it is metered.
        assert!(failed.usage.response_bytes > SIGNING_RESPONSE_BYTES + 1_048_576);
    }
    let [correlation] = failed.correlation.as_slice() else {
        anyhow::bail!("exactly one correlated exchange")
    };
    assert_eq!(correlation.phase, case.phase);
    assert_eq!(correlation.http_status, case.status);
    assert_eq!(
        correlation.page,
        (case.phase == crate::integrations::ExchangePhase::InternalToolsLibrary).then_some(1)
    );
    assert!(correlation.request_id.is_none() && correlation.statement_handle.is_none());
    let evidence = serde_json::to_string(&failed.correlation)? + &error;
    for private in [SERVICE_TOKEN, "simulated", "Quoty", "not json"] {
        assert!(
            !evidence.contains(private),
            "{private} reached the evidence"
        );
    }
    let state = harness.provider()?;
    assert!(state.faults.is_empty(), "the fault was consumed");
    let recovered = harness.read("main")?.result?;
    assert_eq!(recovered, clean);
    Ok(
        json!({"clean":clean,"error":error,"usage":[failed.usage.calls,
        failed.usage.request_bytes,failed.usage.response_bytes],
        "correlation":failed.correlation,"world":harness.provider()?}),
    )
}

#[test]
fn every_scheduled_fault_fails_closed_is_metered_recovers_and_replays() -> Result<()> {
    for case in fault_cases() {
        assert_eq!(fault_replay(&case)?, fault_replay(&case)?);
    }
    Ok(())
}

#[test]
fn a_library_past_the_bound_fails_rather_than_truncating() -> Result<()> {
    let apps = |count: usize| {
        (0..count)
            .map(|index| {
                entry(
                    &format!("app-{index:04}"),
                    &format!("App {index:04}"),
                    Some(&format!("app-{index:04}")),
                )
            })
            .collect::<Vec<_>>()
    };
    let harness = Harness::new(world(apps(MAX_APPS)))?;
    let full: Value = serde_json::from_str(&harness.read("main")?.result?)?;
    assert_eq!(full["apps"].as_array().context("apps")?.len(), MAX_APPS);

    let harness = Harness::new(world(apps(MAX_APPS + 1)))?;
    let outcome = harness.read("main")?;
    assert_eq!(
        outcome.result.unwrap_err().to_string(),
        "internal_tools_app_budget"
    );
    assert_eq!(
        outcome.usage.calls,
        SIGNING_CALLS + 1 + u64::from(MAX_PAGES)
    );
    let state = harness.provider()?;
    assert_eq!(
        state
            .calls
            .iter()
            .filter(|call| call.starts_with(INTERNAL_TOOLS_LIBRARY_ENDPOINT))
            .count(),
        usize::from(MAX_PAGES),
        "no page past the bound is requested"
    );
    Ok(())
}

#[test]
fn a_malformed_entry_fails_the_read_and_never_reaches_the_evidence() -> Result<()> {
    for hostile in [
        entry("quoty", "Quoty", Some("evil.test/x")),
        entry("quoty", "Quoty", Some("Quoty")),
        entry("../quoty", "Quoty", Some("quoty")),
        entry("quoty", "Bad\u{7}Name", Some("quoty")),
        entry("quoty", "   ", Some("quoty")),
        json!({"appId":"quoty","subdomain":"quoty"}),
    ] {
        let harness = Harness::new(world(vec![entry("alpha", "Alpha", Some("alpha")), hostile]))?;
        let outcome = harness.read("main")?;
        let error = outcome.result.unwrap_err().to_string();
        assert_eq!(error, "internal_tools_response_invalid");
        let evidence = serde_json::to_string(&outcome.correlation)? + &error;
        assert!(!evidence.contains("evil") && !evidence.contains("Alpha"));
    }
    Ok(())
}
