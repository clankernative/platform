//! Host-only conformance for `workspace_directory.hierarchy.v2`/`page.v2`: real
//! acceptance, opaque handles, resource budgets and SQLite settlement against the
//! simulated Directory wire world. The pages are staged in the app database for
//! the reading invocation only; no sibling provider store is written.
use super::*;
use crate::{authority_state, integration_host};
use day2_capabilities::{
    integrations::LiveConnection,
    resources::{Action, ResourceTarget},
};
use rusqlite::TransactionBehavior;
use std::collections::BTreeMap;

const ACTOR: &str = "directory-reader@coverage.test";
const CUSTOMER: &str = "Ccoverage";
const SCOPE: &str = "deliveryco/test/app";
const NOW: i64 = 1_700_000_001;
const DELIVERY: &str = "workspace_directory.hierarchy.v2";
const PAGE: &str = "workspace_directory.page.v2";

/// A root plus `children` direct children, in the Google wire shape.
fn hierarchy(children: usize, label: &str) -> Value {
    let mut units = vec![json!({"orgUnitId":"root","name":"Root","orgUnitPath":"/",
        "parentOrgUnitId":null,"parentOrgUnitPath":null})];
    for index in 0..children {
        units.push(json!({"orgUnitId":format!("unit-{index:05}"),"name":format!("{label} {index}"),
            "orgUnitPath":format!("/{label} {index}"),"parentOrgUnitId":"root","parentOrgUnitPath":"/"}));
    }
    json!({"kind":"admin#directory#orgUnits","organizationUnits":units})
}

fn fixture(world: Value) -> Result<(tempfile::TempDir, Runtime)> {
    let directory = tempfile::tempdir()?;
    let instance_path = directory.path().join("instance.json");
    let state = directory.path().join(".state");
    fs::create_dir_all(&state)?;
    let artifact_directory = directory.path().join("delivery-contract");
    fs::create_dir(&artifact_directory)?;
    let live = serde_json::to_value(LiveConnection::WorkspaceDirectory {
        service_account: "directory-reader@company.iam.gserviceaccount.com".into(),
        auth: day2_capabilities::integrations::WorkspaceDirectoryAuth::DirectServiceAccount,
    })?;
    let target = serde_json::to_value(ResourceTarget::WorkspaceDirectory {
        customer_id: CUSTOMER.into(),
    })?;
    let actions = [
        Action::WorkspaceDirectoryHierarchyDelivery,
        Action::WorkspaceDirectoryDeliveryPage,
        Action::WorkspaceDirectoryHierarchy,
        Action::WorkspaceDirectoryPage,
    ];
    let observations: Vec<_> = actions.iter().map(|action| action.capability()).collect();
    let policy = json!({"version":1,"admins":[],"operations":{"run":{"actors":[ACTOR],
        "mode":{"kind":"read"},"models":{},"observations":observations,"effects":[]}}});
    let catalog = json!({"version":1,
        "connections":{"directory":{"revision":1,"provider":"workspace_directory","live":live}},
        "resources":{"directory":{"revision":1,"connection":{"id":"directory","revision":1},"target":target}},
        "policies":{"directory_read":{"revision":1,"owner":"it","actors":[ACTOR],"allowed_apps":["app"],"max_duration_seconds":null,
            "slots":{"directory":{"kind":"workspace_directory","allowed_resources":[{"id":"directory","revision":1}],
                "actions":actions,"limits":{"max_request_bytes":32768,
                    "max_response_bytes":crate::workspace_directory::MAX_RESPONSE_BYTES,"max_calls_per_invocation":5},
                "budgets":[{"id":"directory_budget","revision":1}]}}}},
        "budgets":{"directory_budget":{"revision":1,"scope":"app","period_seconds":3600,
            "limits":{"calls":1000,"bytes":100_000_000,"concurrency":1}}}});
    let instance = json!({"installation":"deliveryco","environment":"test","resources":catalog,
        "apps":{"app":{"artifact":artifact_directory,"readers":[ACTOR],"writers":[ACTOR],"authority":policy,
            "resource_policies":[{"policy":{"id":"directory_read","revision":1},"operation":"run",
                "bindings":{"directory":{"id":"directory","revision":1}}}]}}});
    fs::write(&instance_path, serde_json::to_vec(&instance)?)?;
    let contract = serde_json::from_value(json!({
        "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
        "roc_version":"delivery-test","worker_digest":"delivery-test","schema_digest":"delivery-test",
        "schema":{"models":{"items":{"fields":{"value":"text"}}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
        "operations":[{"name":"run","kind":"query","input_type":"input","output_type":"output"}],
        "sources":{},"admission":"local-spike-only"}))?;
    let inputs = crate::host_inputs::Inputs {
        clock: Arc::new(crate::host_inputs::simulation::VirtualClock(
            std::sync::Mutex::new((
                std::time::Duration::from_secs(NOW as u64),
                std::time::Duration::ZERO,
            )),
        )),
        ..Default::default()
    };
    let runtime = Runtime {
        integrations: Arc::new(integration_host::Host::local(&instance_path)?),
        app_calls: None,
        credentials: None,
        connections: None,
        rolling: false,
        restore_registry_selector: None,
        instance_path,
        app: "app".into(),
        db: state.join("app.sqlite"),
        scope: SCOPE.into(),
        hosted_domain: None,
        artifact: Arc::new(LoadedArtifact::from_contract_for_tests(
            "delivery-test".into(),
            artifact_directory,
            contract,
        )),
        host: Arc::new(crate::host::System(inputs.clone())),
        inputs,
    }
    .with_integrations(integration_host::Host::simulated_providers_with_app_calls(
        &state.join("app.sqlite"),
        SCOPE,
    ));
    runtime.initialize()?;
    crate::integrations::simulated::seed(
        runtime.db(),
        SCOPE,
        &crate::integrations::simulated::SimulatedFixture {
            workspace_directory: crate::integrations::simulated::WorkspaceDirectoryWorld {
                customer_id: CUSTOMER.into(),
                users: BTreeMap::new(),
                hierarchy: world,
            },
            slack: crate::integrations::simulated::SlackWorld {
                workspace_id: "TDELIVERY".into(),
                ..Default::default()
            },
            snowflake: crate::integrations::simulated::SnowflakeWorld {
                account: "delivery-test".into(),
                ..Default::default()
            },
            openai: crate::integrations::simulated::OpenAiWorld {
                project_id: "proj_delivery".into(),
                model: "model-delivery".into(),
                max_input_tokens: 100_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    Ok((directory, runtime))
}

/// One accepted invocation with its own resource handle.
struct Invocation<'a> {
    runtime: &'a Runtime,
    id: String,
    handle: String,
    ordinal: usize,
}

struct Observed {
    result: Result<String>,
    usage: crate::resources::ProviderUsage,
    journaled: Observation,
}

impl<'a> Invocation<'a> {
    fn accept(runtime: &'a Runtime, id: &str) -> Result<Self> {
        runtime.accept("run", ACTOR, id, &json!({}), NOW)?;
        let mut connection = open(runtime.db())?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request = Self::request_in(&tx, id)?;
        let bound = crate::resources::host_operation(
            &tx,
            runtime,
            &request,
            &Instruction {
                kind: "observe".into(),
                model: crate::resources::BIND.into(),
                data: json!({"binding":"directory","invocation":id}).to_string(),
                ..Default::default()
            },
        )?
        .context("directory resource binding")?;
        tx.commit()?;
        let bound: Value = serde_json::from_str(&bound)?;
        Ok(Self {
            runtime,
            id: id.into(),
            handle: bound["token"].as_str().context("opaque handle")?.to_owned(),
            ordinal: 0,
        })
    }

    fn request_in(tx: &Connection, id: &str) -> Result<Request> {
        Ok(Request {
            operation: "run".into(),
            input: "{}".into(),
            context: crate::store::invocation_context(tx, id)?,
            observations: vec![],
        })
    }

    /// Authorize, reserve, observe and settle exactly as preparation does.
    fn observe(&mut self, model: &str, mut data: Value) -> Result<Observed> {
        data["handle"] = json!(self.handle);
        let attempt = format!("{}-{}", self.id, self.ordinal);
        self.ordinal += 1;
        let mut connection = open(self.runtime.db())?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request = Self::request_in(&tx, &self.id)?;
        let active = authority_state::current(&tx)?;
        let instruction = Instruction {
            kind: "observe".into(),
            model: model.into(),
            data: data.to_string(),
            ..Default::default()
        };
        let capability = crate::capabilities::authorized(
            &tx,
            self.runtime,
            &request,
            &instruction,
            active.policy()?,
            &attempt,
        )?;
        crate::resources::record_use(&tx, &attempt, capability.resource())?;
        let reservation = crate::resources::reserve_in(
            &tx,
            self.runtime,
            &request,
            &instruction,
            &attempt,
            capability.resource(),
            capability.quote(),
        )?;
        tx.commit()?;
        let outcome = crate::capabilities::observe(self.runtime, capability, &attempt);
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::resources::settle_in(&tx, &reservation, outcome.usage)?;
        tx.commit()?;
        let journaled = crate::resources::bounded_observation(Observation {
            instruction,
            result: outcome.result.as_ref().cloned().unwrap_or_default(),
            error: String::new(),
        })?;
        Ok(Observed {
            result: outcome.result,
            usage: outcome.usage,
            journaled,
        })
    }

    fn deliver(&mut self) -> Result<(crate::workspace_directory::HierarchyDelivery, Observed)> {
        let observed = self.observe(DELIVERY, json!({}))?;
        let delivery = crate::json::decode(
            observed
                .result
                .as_ref()
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .as_bytes(),
        )?;
        Ok((delivery, observed))
    }

    fn page(&mut self, capture_id: &str, page: u64) -> Result<Observed> {
        self.observe(PAGE, json!({"capture_id":capture_id,"page":page}))
    }
}

fn staged_rows(runtime: &Runtime) -> Result<i64> {
    Ok(open(runtime.db())?.query_row(
        "SELECT count(*) FROM day2_capture_delivery_pages",
        [],
        |row| row.get(0),
    )?)
}

fn provider_calls(runtime: &Runtime) -> Result<usize> {
    crate::integrations::simulated::update_workspace_directory(runtime.db(), SCOPE, |world| {
        Ok(world.calls.len())
    })
}

#[test]
fn delivery_hands_a_complete_hierarchy_to_the_reading_invocation_only() -> Result<()> {
    let (_directory, runtime) = fixture(hierarchy(599, "Team"))?;
    let mut sync = Invocation::accept(&runtime, "sync")?;
    let (delivery, observed) = sync.deliver()?;
    assert_eq!(delivery.customer_id, CUSTOMER);
    assert_eq!(delivery.org_unit_count, 600);
    assert_eq!(
        delivery.page_count, 3,
        "256-unit pages, one create_many each"
    );
    assert_eq!(delivery.captured_at, NOW);
    assert_eq!(observed.usage.calls, 4);
    assert_eq!(
        observed.usage.request_bytes,
        crate::workspace_directory::MAX_CAPTURE_REQUEST_BYTES
    );
    assert_eq!(
        observed.usage.response_bytes,
        crate::workspace_directory::MAX_CAPTURE_RESPONSE_BYTES
    );
    assert!(observed.usage.known && observed.usage.dispatched);
    assert!(observed.journaled.error.is_empty());

    let mut units = Vec::new();
    for page in 0..delivery.page_count {
        let observed = sync.page(&delivery.id, page)?;
        assert_eq!(observed.usage.calls, 0);
        assert_eq!(observed.usage.request_bytes, 0);
        assert_eq!(observed.usage.response_bytes, 0);
        assert!(observed.usage.known && !observed.usage.dispatched);
        assert!(
            observed.journaled.error.is_empty(),
            "a delivered page must fit one journaled observation"
        );
        let decoded: crate::workspace_directory::DeliveryPage =
            crate::json::decode(observed.result?.as_bytes())?;
        assert_eq!(decoded.page, page);
        assert_eq!(decoded.done, page + 1 == delivery.page_count);
        assert!(decoded.items.len() <= crate::capture_delivery::MAX_PAGE_ITEMS);
        units.extend(decoded.items);
    }
    assert_eq!(units.len(), 600);
    assert!(units.windows(2).all(|pair| pair[0].id < pair[1].id));
    assert_eq!(
        sync.page(&delivery.id, delivery.page_count)?
            .result
            .unwrap_err()
            .to_string(),
        "capture_delivery_page_invalid"
    );
    assert_eq!(
        provider_calls(&runtime)?,
        1,
        "pages never reach the provider"
    );

    // Another pending invocation of the same actor and grant cannot read it.
    let mut other = Invocation::accept(&runtime, "other")?;
    assert_eq!(
        other.page(&delivery.id, 0)?.result.unwrap_err().to_string(),
        "capture_delivery_unavailable"
    );

    // Nothing is published beside the app database, and the buffer is released
    // when the invocation's preparation ends.
    assert!(
        !runtime
            .db()
            .with_file_name("workspace_directory.sqlite")
            .exists()
    );
    assert_eq!(staged_rows(&runtime)?, 3);
    runtime.sql_write(|tx| crate::capture_delivery::release(tx, "sync"))?;
    assert_eq!(staged_rows(&runtime)?, 0);
    assert_eq!(
        sync.page(&delivery.id, 0)?.result.unwrap_err().to_string(),
        "capture_delivery_unavailable"
    );

    // The identity is the content: an unchanged hierarchy delivers the same id
    // to a later invocation, so an application can skip an unchanged sync. Every
    // delivery is a provider read; there is no host cache.
    let (again, _) = other.deliver()?;
    assert_eq!(again.id, delivery.id);
    assert_eq!(provider_calls(&runtime)?, 2);
    crate::integrations::simulated::update_workspace_directory(runtime.db(), SCOPE, |world| {
        world.world.hierarchy = hierarchy(599, "Group");
        Ok(())
    })?;
    let mut changed = Invocation::accept(&runtime, "changed")?;
    let (renamed, _) = changed.deliver()?;
    assert_ne!(renamed.id, delivery.id);
    assert_eq!(renamed.org_unit_count, 600);
    Ok(())
}

#[test]
fn delivery_fails_closed_without_staging_and_still_settles_provider_usage() -> Result<()> {
    // The bound is pages an invocation can read. The simulated world store is
    // itself held to the 1 MiB transport decode bound, so exercise the page
    // bound on the same collection pipeline through a fixture port.
    let units = |children: usize| {
        let mut units = vec![crate::workspace_directory::OrgUnit {
            id: "root".into(),
            name: "Root".into(),
            path: "/".into(),
            parent_id: None,
            parent_path: None,
        }];
        units.extend(
            (0..children).map(|index| crate::workspace_directory::OrgUnit {
                id: format!("unit-{index:05}"),
                name: format!("U {index}"),
                path: format!("/U {index}"),
                parent_id: Some("root".into()),
                parent_path: Some("/".into()),
            }),
        );
        units
    };
    let input = crate::workspace_directory::CaptureInput {
        customer_id: CUSTOMER.into(),
        connection_id: "directory@1".into(),
        actor: ACTOR.into(),
        captured_at: NOW,
    };
    let readable = crate::capture_delivery::MAX_PAGES * crate::capture_delivery::MAX_PAGE_ITEMS;
    let (delivery, staged) = crate::workspace_directory::deliver_hierarchy(
        input.clone(),
        &mut crate::workspace_directory::CachedHierarchyPort::new(units(readable - 1), NOW),
    )?;
    assert_eq!(
        delivery.page_count,
        crate::capture_delivery::MAX_PAGES as u64
    );
    assert_eq!(staged.pages.len(), crate::capture_delivery::MAX_PAGES);
    assert_eq!(
        crate::workspace_directory::deliver_hierarchy(
            input,
            &mut crate::workspace_directory::CachedHierarchyPort::new(units(readable), NOW),
        )
        .unwrap_err()
        .to_string(),
        "workspace_directory_delivery_exceeds_invocation"
    );

    // A provider fault stages nothing.
    let (_directory, runtime) = fixture(hierarchy(3, "U"))?;
    use crate::integrations::simulated::{ScheduledFault, SimulatedFault, schedule_faults};
    schedule_faults(
        runtime.db(),
        SCOPE,
        day2_capabilities::resources::Provider::WorkspaceDirectory
            .world()
            .context("directory world")?,
        vec![ScheduledFault {
            endpoint: String::new(),
            remaining: 1,
            fault: SimulatedFault::Denied,
        }],
    )?;
    let mut denied = Invocation::accept(&runtime, "denied")?;
    let failed = denied.observe(DELIVERY, json!({}))?;
    assert_eq!(
        failed.result.unwrap_err().to_string(),
        "workspace_directory_hierarchy_lookup_failed"
    );
    assert_eq!(failed.usage.calls, 4, "provider traffic still settles");
    assert!(failed.usage.known && failed.usage.dispatched);
    assert_eq!(staged_rows(&runtime)?, 0);

    // A retry in the same invocation would exceed its provider call ceiling; a
    // fresh business attempt delivers.
    let Err(refused) = denied.deliver() else {
        bail!("a second delivery fit the invocation call ceiling")
    };
    assert_eq!(
        refused.to_string(),
        crate::error::Failure::ResourceLimitExceeded.to_string()
    );
    let mut denied = Invocation::accept(&runtime, "retried")?;
    let (delivery, _) = denied.deliver()?;

    // A malformed or foreign page request is refused before any read.
    for data in [
        json!({"capture_id":"sha256:short","page":0}),
        json!({"capture_id":delivery.id,"page":0,"offset":0}),
    ] {
        assert!(denied.observe(PAGE, data).is_err());
    }
    Ok(())
}

#[test]
fn v1_capture_and_cache_are_unchanged_beside_v2() -> Result<()> {
    let (_directory, runtime) = fixture(hierarchy(2, "Team"))?;
    let mut legacy = Invocation::accept(&runtime, "legacy")?;
    let captured: Value = serde_json::from_str(
        &legacy
            .observe("workspace_directory.hierarchy.v1", json!({}))?
            .result?,
    )?;
    assert_eq!(
        captured["expires_at"],
        NOW + crate::workspace_directory::SOURCE_TTL_SECONDS
    );
    let page: Value = serde_json::from_str(
        &legacy
            .observe(
                "workspace_directory.page.v1",
                json!({"capture_id":captured["id"],"offset":0}),
            )?
            .result?,
    )?;
    assert_eq!(page["items"].as_array().map(Vec::len), Some(3));
    assert!(
        runtime
            .db()
            .with_file_name("workspace_directory.sqlite")
            .exists()
    );
    // v2 neither reads nor writes the v1 store: it calls the provider even with
    // a live v1 cache entry, and v1 pages cannot address a v2 delivery.
    let mut current = Invocation::accept(&runtime, "current")?;
    let before = provider_calls(&runtime)?;
    let (delivery, _) = current.deliver()?;
    assert_eq!(provider_calls(&runtime)?, before + 1);
    assert_ne!(Value::from(delivery.id.clone()), captured["id"]);
    assert_eq!(
        current
            .observe(
                "workspace_directory.page.v1",
                json!({"capture_id":delivery.id,"offset":0}),
            )?
            .result
            .unwrap_err()
            .to_string(),
        "workspace_directory_capture_missing"
    );
    Ok(())
}
