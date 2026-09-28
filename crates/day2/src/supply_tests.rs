//! The supply gate: every declared world must actually be suppliable.
//!
//! `simulations::supply` answers *how* each provider's world comes into
//! existence, exhaustively, so the question cannot go unanswered. It cannot
//! answer whether the named path **works**: a `world:` string is data and
//! seeding is a function, and the compiler sees a name and a function without
//! being able to tell that the function covers the name.
//!
//! That boundary is worth stating precisely, because it tells a future reader
//! which declarations need a round-trip test and which do not. Declaring a Rust
//! module before writing its file is the *same class* of mistake — a declaration
//! with no supply — and the compiler catches it in under a second, because the
//! supply is a file it must open. It cannot catch the world case because the
//! supply is a function it cannot see through. Where supply is a runtime
//! operation, only a round-trip closes the loop.
//!
//! So this gate enumerates **from the declaration** — `Provider::ALL` — drives
//! each provider's real supply path, and asserts the world exists and reads
//! back. Enumerating from a remembered list is exactly what fails: `mount()`
//! derived its reference from `credential_ref()` and so looked complete while
//! making a declared signing secret impossible to install.
//!
//! It deliberately does not depend on action coverage. A provider whose actions
//! are all `PendingAdapterSeam` in the coverage gate is still checked here —
//! that door is how the original declared-world hole stayed open for providers
//! nobody had chosen to cover.

use super::*;
use crate::{
    people_providers::SyntheticFixture,
    simulations::{Supply, simulation, supply},
};
use day2_capabilities::resources::Provider;
use serde_json::json;

/// A runtime with no instance file and no compiled artifact: this gate is about
/// where provider state lands, not about admission.
fn runtime(directory: &Path) -> Result<Runtime> {
    let artifact_directory = directory.join("supply-contract");
    fs::create_dir_all(&artifact_directory)?;
    let state = directory.join(".state");
    fs::create_dir_all(&state)?;
    let db = state.join("app.sqlite");
    let contract = serde_json::from_value(json!({
        "format":crate::artifact::CURRENT_FORMAT,"roc_version":"supply-test",
        "worker_digest":"supply-test","schema_digest":"supply-test",
        "schema":{"models":{},"inputs":{},"foreign_keys":[]},
        "operations":[],"sources":{},"admission":"local-spike-only"
    }))?;
    Ok(Runtime {
        integrations: Arc::new(crate::integration_host::Host::simulated(
            &db,
            "supplyco/test/app",
        )),
        instance_path: directory.join("instance.json"),
        app: "app".into(),
        db,
        scope: "supplyco/test/app".into(),
        hosted_domain: None,
        artifact: Arc::new(LoadedArtifact::from_contract_for_tests(
            "supply-test".into(),
            artifact_directory,
            contract,
        )),
        host: Arc::new(crate::host::System),
    })
}

fn simulated_fixture() -> crate::integrations::simulated::SimulatedFixture {
    use crate::integrations::simulated::{
        OpenAiWorld, SimulatedFixture, SlackWorld, SnowflakeWorld,
    };
    SimulatedFixture {
        slack_webhook: crate::integrations::simulated::slack_webhook_fixture(),
        delegation: Default::default(),
        gitea_actions: Default::default(),
        github_actions: Default::default(),
        linear_work: Default::default(),
        object_store: Default::default(),
        slack: SlackWorld {
            workspace_id: "T123".into(),
            channels: Default::default(),
            sequence: 0,
        },
        snowflake: SnowflakeWorld {
            account: "org-account".into(),
            views: Default::default(),
        },
        openai: OpenAiWorld {
            project_id: "proj_supply".into(),
            organization_id: None,
            model: "model-supply".into(),
            max_input_tokens: 1000,
        },
    }
}

fn people_fixture() -> SyntheticFixture {
    SyntheticFixture {
        customer_id: "C0supply".into(),
        google: Default::default(),
        organization_id: "org-supply".into(),
        linear: Default::default(),
        destination: "ops@supply.test".into(),
        alerts: Default::default(),
    }
}

/// Drive the provider's own declared supply path. Nothing here creates a world
/// directly: every arm calls the production code that a real operator or a real
/// invocation would call. A test that ran the `CREATE TABLE` itself would be the
/// test supplying the world instead of production supplying it, which is the
/// self-consistency trap this gate exists to catch.
fn drive_supply(runtime: &Runtime, provider: Provider) -> Result<()> {
    match supply(provider) {
        Supply::SimulatedFixture => crate::integrations::simulated::seed(
            runtime.db(),
            runtime.scope(),
            &simulated_fixture(),
        ),
        Supply::CartaCapture => crate::carta::seed_synthetic(
            runtime,
            &crate::carta::SyntheticSnapshot {
                issuer_id: "issuer-supply".into(),
                records: Vec::new(),
            },
        )
        .map(|_| ()),
        Supply::SyntheticPeople => {
            crate::people_providers::seed_synthetic(runtime, &people_fixture())
        }
        // The notification mailbox has no seeding step; the capability creates
        // it on first use. Driving that same path is the only version that
        // measures production rather than the test.
        Supply::CreatedOnDemand => {
            crate::capabilities::with_world(runtime, |_| Ok(json!({}))).map(|_| ())
        }
    }
}

/// A world that exists but holds nothing is not evidence a supply path works.
fn reads_back(path: &Path) -> Result<usize> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    Ok(usize::try_from(tables)?)
}

/// The gate.
#[test]
fn every_declared_world_can_be_supplied_and_reads_back() -> Result<()> {
    for provider in Provider::ALL {
        // A fresh instance per provider: several supply paths seed more than one
        // world at once, and seeding twice is refused by design.
        let directory = tempfile::tempdir()?;
        let runtime = runtime(directory.path())?;
        let world = runtime.db().with_file_name(simulation(*provider));
        assert!(
            !world.exists(),
            "{} world existed before its supply path ran",
            provider.name()
        );
        drive_supply(&runtime, *provider).with_context(|| {
            format!(
                "{} declares {:?} but that path failed — a declared world that \
                 cannot be supplied is the mount() failure one subsystem over",
                provider.name(),
                supply(*provider)
            )
        })?;
        assert!(
            world.is_file(),
            "{} declares world {} and supply path {:?}, but nothing created it",
            provider.name(),
            simulation(*provider),
            supply(*provider)
        );
        assert!(
            reads_back(&world)? > 0,
            "{}'s world was created but holds no tables — supplied in name only",
            provider.name()
        );
    }
    Ok(())
}

/// The supply gate must not be satisfiable by a world nothing created, or it
/// would pass for exactly the case it exists to catch.
#[test]
fn the_gate_rejects_a_world_that_is_never_created() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let runtime = runtime(directory.path())?;
    // Stand in for a provider whose declared supply path does nothing at all.
    let undeclared = runtime
        .db()
        .with_file_name("never-supplied.simulated.sqlite");
    assert!(!undeclared.exists());
    assert!(
        reads_back(&undeclared).is_err(),
        "a world nothing created must not read back"
    );
    Ok(())
}

/// Every provider answers both questions: how its world is bound, and how it is
/// supplied. Both matches are exhaustive, so this checks the answers are
/// distinct rather than that they exist.
#[test]
fn supply_paths_cover_every_provider_without_privileging_one_answer() {
    let mut seen = std::collections::BTreeSet::new();
    for provider in Provider::ALL {
        seen.insert(supply(*provider));
    }
    // If every provider funnelled through one arm, the others would be
    // decorative and the next author would reach for the comfortable one.
    assert!(
        seen.len() >= 3,
        "supply answers collapsed to {seen:?} — legitimate paths must stay legitimate"
    );
}
