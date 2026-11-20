//! Rendering an application's authority from the audiences, owned rows and
//! effects its admitted artifact declares. Reads the `audiences` fixture through
//! `DAY2_TEST_AUDIENCES_ARTIFACT`: `links.list` serves employees, `links.detail`
//! owners, `links.create` nobody, and `links.edit` employees with
//! `.any_owner(Data.links)`. Variants of its contract are edited in memory.
use anyhow::{Context, Result, ensure};
use day2::{
    app_contract::{Audience, Effect},
    artifact::{
        Artifact, Endpoint, EndpointBinding, Instance, LoadedArtifact, Schedule, ScheduleBinding,
    },
    authority::{Mode, Policy, RowFilter, Rows},
    authority_render::{Inputs, Rendered, RenderedAuthority, render},
    authority_state::AuthorityDocument,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &str = "domain:example.com";
const SCHEDULE_ACTOR: &str = "automation@app.invalid";
const ENDPOINT_ACTOR: &str = "webhook@app.invalid";
const ADA: &str = "ada@example.com";
const BOB: &str = "bob@example.com";
const CI: &str = "ci@project.iam.gserviceaccount.com";

fn artifact() -> Result<LoadedArtifact> {
    let artifact = std::env::var_os("DAY2_TEST_AUDIENCES_ARTIFACT")
        .context("run xtask verify or set DAY2_TEST_AUDIENCES_ARTIFACT")?;
    LoadedArtifact::load(std::path::Path::new(&artifact))
}

fn admins() -> RenderedAuthority {
    RenderedAuthority {
        admins: BTreeSet::from([ADA.to_owned(), CI.to_owned()]),
    }
}

fn rendered(
    contract: &Artifact,
    authority: &RenderedAuthority,
    schedules: &BTreeMap<String, ScheduleBinding>,
) -> Result<Rendered> {
    rendered_with(contract, authority, schedules, &BTreeMap::new())
}

fn rendered_with(
    contract: &Artifact,
    authority: &RenderedAuthority,
    schedules: &BTreeMap<String, ScheduleBinding>,
    ingress: &BTreeMap<String, EndpointBinding>,
) -> Result<Rendered> {
    render(
        contract,
        &Inputs {
            hosted_domain: "example.com",
            authority,
            schedules,
            ingress,
        },
    )
}

/// A link row owned by `owner`, with every other field filled.
fn link(contract: &Artifact, owner: &str) -> Value {
    let mut row: serde_json::Map<String, Value> = contract.schema.models["links"]
        .fields
        .keys()
        .map(|field| (field.clone(), json!("x")))
        .collect();
    row.insert("owner".into(), json!(owner));
    Value::Object(row)
}

fn refused(policy: &Policy, operation: &str, actor: &str) -> bool {
    policy.authorize(operation, actor).is_err()
}

fn set(entries: &[&str]) -> BTreeSet<String> {
    entries.iter().map(|entry| (*entry).to_owned()).collect()
}

fn operation<'a>(
    contract: &'a mut Artifact,
    name: &str,
) -> Result<&'a mut day2::app_contract::Operation> {
    contract
        .app_contract
        .as_mut()
        .context("application contract")?
        .operations
        .get_mut(name)
        .with_context(|| format!("{name} contract"))
}

fn effect(kind: &str, model: &str, command: &str, fields: &[&str]) -> Effect {
    Effect {
        command: command.into(),
        kind: kind.into(),
        model: model.into(),
        fields: fields.iter().map(|field| (*field).to_owned()).collect(),
    }
}

#[test]
fn audiences_choose_actors_and_owned_rows_narrow_employee_writes() -> Result<()> {
    let admitted = artifact()?.contract().clone();
    let Rendered {
        readers,
        writers,
        policy,
    } = rendered(&admitted, &admins(), &BTreeMap::new())?;
    ensure!(readers == set(&[DOMAIN]) && writers == set(&[DOMAIN]));
    ensure!(policy.admins == admins().admins && policy.delegations.is_empty());
    let actors = |name: &str| policy.operations[name].actors.clone();
    ensure!(actors("links.list") == set(&[DOMAIN]));
    ensure!(actors("links.edit") == set(&[DOMAIN]));
    ensure!(actors("links.detail") == set(&["owners"]));
    ensure!(actors("links.create").is_empty(), "closed runs for nobody");
    for (name, rule) in &policy.operations {
        let command = name == "links.create" || name == "links.edit";
        let mode = if command {
            Mode::CurrentState
        } else {
            Mode::Read
        };
        ensure!(rule.mode == mode, "{name} mode");
        ensure!(
            rule.commands.is_empty() && rule.effects.is_empty() && rule.observations.is_empty()
        );
        let links = &rule.models["links"];
        ensure!(links.read, "{name} reads links");
        ensure!(
            !links.update_fields.contains("owner"),
            "nobody updates an owner column: {name}"
        );
    }
    let create = &policy.operations["links.create"].models["links"];
    ensure!(create.create && create.update_fields.is_empty() && create.rows == Rows::All);
    let edit = &policy.operations["links.edit"].models["links"];
    ensure!(
        !edit.create
            && edit.update_fields == set(&["destination", "title"])
            && edit.rows == Rows::All,
        "edit declares .any_owner(Data.links), so it reaches every link: {edit:?}"
    );

    // Without the exemption, an employee edits only the links they own.
    let mut narrowed = admitted.clone();
    operation(&mut narrowed, "links.edit")?.any_owner.clear();
    let policy = rendered(&narrowed, &admins(), &BTreeMap::new())?.policy;
    ensure!(
        policy.operations["links.edit"].models["links"].rows
            == Rows::OwnerOrAdmin {
                field: "owner".into()
            }
    );
    ensure!(policy.operations["links.list"].models["links"].rows == Rows::All);
    let owner_only = RowFilter::Owner {
        field: "owner".into(),
        actor: BOB.into(),
    };
    ensure!(policy.read_scope("links.edit", "links", BOB)? == owner_only);
    ensure!(
        policy.read_scope("links.edit", "links", ADA)? == RowFilter::All,
        "an admin edits every link"
    );
    ensure!(policy.read_scope("links.list", "links", BOB)? == RowFilter::All);
    Ok(())
}

#[test]
fn the_rendered_policy_admits_each_audience_and_no_one_else() -> Result<()> {
    let admitted = artifact()?.contract().clone();
    let policy = rendered(&admitted, &admins(), &BTreeMap::new())?.policy;
    ensure!(!refused(&policy, "links.list", BOB) && !refused(&policy, "links.edit", BOB));
    ensure!(refused(&policy, "links.list", "eve@other.example"));
    ensure!(
        !refused(&policy, "links.detail", ADA),
        "owners are the admins"
    );
    ensure!(refused(&policy, "links.detail", BOB));
    ensure!(
        refused(&policy, "links.detail", CI),
        "a service account administers the app but is not an owner"
    );
    for actor in [ADA, BOB, CI] {
        ensure!(
            refused(&policy, "links.create", actor),
            "closed admits nobody"
        );
    }

    // Every grant reaches every row here, since edit is exempt, yet a create
    // must still name its own actor as the link's owner.
    let mut open = admitted.clone();
    operation(&mut open, "links.create")?.audience = Some(Audience::Employees);
    let policy = rendered(&open, &admins(), &BTreeMap::new())?.policy;
    ensure!(
        policy
            .operations
            .values()
            .all(|rule| rule.models.values().all(|grant| grant.rows == Rows::All))
    );
    ensure!(policy.row_owners == BTreeMap::from([("links".to_owned(), "owner".to_owned())]));
    policy.check_create("links.create", "links", BOB, &link(&open, BOB))?;
    ensure!(
        policy
            .check_create("links.create", "links", BOB, &link(&open, ADA))
            .is_err(),
        "an employee cannot create a link in someone else's name"
    );
    Ok(())
}

#[test]
fn internal_commands_run_for_whoever_reaches_them() -> Result<()> {
    let mut contract = artifact()?.contract().clone();
    // `create` becomes internal: the employees' edit requests it, a schedule
    // runs it, and it requests itself.
    let create = operation(&mut contract, "links.create")?;
    create.audience = None;
    create.execution.internal = true;
    create
        .execution
        .effects
        .push(effect("request", "", "links.create", &[]));
    create
        .execution
        .effects
        .push(effect("update", "links", "", &["title"]));
    operation(&mut contract, "links.edit")?
        .execution
        .effects
        .push(effect("request", "", "links.create", &[]));
    let input_type = contract
        .operations
        .iter()
        .find(|operation| operation.name == "links.create")
        .context("create")?
        .input_type
        .clone();
    contract.schedules.push(Schedule {
        name: "nightly".into(),
        operation: "links.create".into(),
        input: "{}".into(),
        input_type,
        interval_ms: 24 * 60 * 60 * 1_000,
        anchor_hour: 3,
        missed: "coalesce".into(),
        catch_up_bound: 0,
    });

    let unbound = rendered(&contract, &admins(), &BTreeMap::new())?;
    ensure!(
        unbound.policy.operations["links.create"].actors == set(&[DOMAIN]),
        "an unbound schedule reaches nothing"
    );
    let schedules = BTreeMap::from([(
        "nightly".to_owned(),
        ScheduleBinding {
            actor: SCHEDULE_ACTOR.into(),
            disabled: false,
        },
    )]);
    let Rendered {
        readers,
        writers,
        policy,
    } = rendered(&contract, &admins(), &schedules)?;
    ensure!(readers == set(&[DOMAIN]));
    ensure!(writers == set(&[DOMAIN, SCHEDULE_ACTOR]));
    let create = &policy.operations["links.create"];
    ensure!(create.actors == set(&[DOMAIN, SCHEDULE_ACTOR]));
    ensure!(create.commands == set(&["links.create"]));
    ensure!(policy.operations["links.edit"].commands == set(&["links.create"]));
    ensure!(
        create.models["links"].rows
            == Rows::OwnerOrAdmin {
                field: "owner".into()
            },
        "an internal command's writes are narrowed like its employees' are"
    );
    ensure!(policy.operations["links.detail"].actors == set(&["owners"]));

    let stray = BTreeMap::from([(
        "hourly".to_owned(),
        ScheduleBinding {
            actor: SCHEDULE_ACTOR.into(),
            disabled: false,
        },
    )]);
    let error = format!("{:#}", rendered(&contract, &admins(), &stray).unwrap_err());
    ensure!(
        error.contains("schedule binding names no declared schedule: hourly"),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_chain_of_internal_commands_runs_for_its_schedule_and_endpoint() -> Result<()> {
    let mut contract = artifact()?.contract().clone();
    // A schedule runs create, which requests edit; an endpoint delivers to
    // edit directly. Both become internal; only the queries stay public.
    for name in ["links.create", "links.edit"] {
        let command = operation(&mut contract, name)?;
        command.audience = None;
        command.execution.internal = true;
    }
    operation(&mut contract, "links.create")?
        .execution
        .effects
        .push(effect("request", "", "links.edit", &[]));
    let input_type = |name: &str| {
        contract
            .operations
            .iter()
            .find(|operation| operation.name == name)
            .map(|operation| operation.input_type.clone())
            .with_context(|| format!("{name} input"))
    };
    let (create_input, edit_input) = (input_type("links.create")?, input_type("links.edit")?);
    contract.schedules.push(Schedule {
        name: "nightly".into(),
        operation: "links.create".into(),
        input: "{}".into(),
        input_type: create_input,
        interval_ms: 24 * 60 * 60 * 1_000,
        anchor_hour: 3,
        missed: "coalesce".into(),
        catch_up_bound: 0,
    });
    contract.ingress.push(Endpoint {
        name: "hook".into(),
        operation: "links.edit".into(),
        input_type: edit_input,
        provider: "slack.events.v1".into(),
    });
    let schedules = BTreeMap::from([(
        "nightly".to_owned(),
        ScheduleBinding {
            actor: SCHEDULE_ACTOR.into(),
            disabled: false,
        },
    )]);
    // A paused endpoint keeps its actor's grants, so resuming it needs no
    // new activation.
    let ingress = BTreeMap::from([(
        "hook".to_owned(),
        EndpointBinding {
            actor: ENDPOINT_ACTOR.into(),
            connection: day2_capabilities::resources::VersionRef {
                id: "slack".into(),
                revision: 1,
            },
            disabled: true,
        },
    )]);
    let Rendered {
        readers,
        writers,
        policy,
    } = rendered_with(&contract, &admins(), &schedules, &ingress)?;
    ensure!(readers == set(&[DOMAIN]));
    ensure!(writers == set(&[DOMAIN, SCHEDULE_ACTOR, ENDPOINT_ACTOR]));
    ensure!(policy.operations["links.create"].actors == set(&[SCHEDULE_ACTOR]));
    ensure!(
        policy.operations["links.edit"].actors == set(&[SCHEDULE_ACTOR, ENDPOINT_ACTOR]),
        "edit runs for the schedule that reaches it through create, and for its endpoint"
    );
    ensure!(
        policy.operations["links.edit"].models["links"].rows == Rows::All,
        "edit keeps its .any_owner exemption as an internal command"
    );
    ensure!(!refused(&policy, "links.edit", SCHEDULE_ACTOR) && refused(&policy, "links.edit", BOB));
    Ok(())
}

#[test]
fn a_request_its_target_audience_does_not_cover_is_refused_at_render_and_admission() -> Result<()> {
    let admitted = artifact()?.contract().clone();
    let request = |requester: Audience, target: Audience| -> Result<Artifact> {
        let mut contract = admitted.clone();
        operation(&mut contract, "links.create")?.audience = Some(target);
        let edit = operation(&mut contract, "links.edit")?;
        edit.audience = Some(requester);
        edit.execution
            .effects
            .push(effect("request", "", "links.create", &[]));
        Ok(contract)
    };
    // Owners are people at the domain, so an Owners command may request an
    // Employees one; edit is then no longer narrowed, so it drops .any_owner.
    let mut covered = request(Audience::Owners, Audience::Employees)?;
    operation(&mut covered, "links.edit")?.any_owner.clear();
    rendered(&covered, &admins(), &BTreeMap::new())?;
    day2::operation_catalog::Catalog::from_artifact(&covered)?;

    let uncovered = request(Audience::Employees, Audience::Owners)?;
    let error = format!(
        "{:#}",
        rendered(&uncovered, &admins(), &BTreeMap::new()).unwrap_err()
    );
    ensure!(
        error.contains("links.edit requests links.create, which domain:example.com may not run"),
        "{error}"
    );
    let error = match day2::operation_catalog::Catalog::from_artifact(&uncovered) {
        Ok(_) => String::new(),
        Err(error) => format!("{error:#}"),
    };
    ensure!(
        error.contains("no installation could render") && error.contains("may not run"),
        "admission renders the contract and refuses it when it is built: {error}"
    );
    Ok(())
}

#[test]
fn an_operation_reaches_only_the_effects_and_observations_it_declares() -> Result<()> {
    let mut contract = artifact()?.contract().clone();
    let edit = operation(&mut contract, "links.edit")?;
    edit.execution
        .effects
        .push(effect("external", "", "slack.post.v1", &[]));
    edit.observations = vec!["audit.history.v1".into()];
    operation(&mut contract, "links.list")?.observations =
        vec!["workspace_directory.user_path.v1".into()];
    let policy = rendered(&contract, &admins(), &BTreeMap::new())?.policy;
    let edit = &policy.operations["links.edit"];
    ensure!(edit.effects == set(&["slack.post.v1"]));
    ensure!(edit.observations == set(&["audit.history.v1"]));
    let list = &policy.operations["links.list"];
    ensure!(
        list.effects.is_empty() && list.observations == set(&["workspace_directory.user_path.v1"])
    );
    ensure!(policy.operations["links.create"].observations.is_empty());
    Ok(())
}

#[test]
fn rendering_refuses_a_contract_without_audiences_and_unusable_admins() -> Result<()> {
    let admitted = artifact()?.contract().clone();
    let mut before = admitted.clone();
    for definition in before
        .app_contract
        .as_mut()
        .context("application contract")?
        .operations
        .values_mut()
    {
        definition.audience = None;
    }
    let error = format!(
        "{:#}",
        rendered(&before, &admins(), &BTreeMap::new()).unwrap_err()
    );
    ensure!(
        error.contains("declares no operation audiences"),
        "an application built before audiences has no policy to render: {error}"
    );
    for (admins, refused) in [
        (set(&[CI]), "at least one individual administrator"),
        (set(&[ADA, "owners"]), "names this app's owners"),
        (set(&[ADA, DOMAIN]), "names a set of people"),
        (
            set(&[ADA, "eve@other.example"]),
            "is not at the hosted domain example.com",
        ),
    ] {
        let error = format!(
            "{:#}",
            rendered(&admitted, &RenderedAuthority { admins }, &BTreeMap::new()).unwrap_err()
        );
        ensure!(error.contains(refused), "{refused}: {error}");
    }
    Ok(())
}

#[test]
fn activation_renders_the_authority_an_instance_binding_asks_for() -> Result<()> {
    let artifact = artifact()?;
    let instance = |binding: serde_json::Value, identity: bool| {
        let mut instance = serde_json::json!({
            "installation": "test",
            "environment": "test",
            "apps": {"app": binding},
        });
        if identity {
            instance["identity"] =
                serde_json::json!({"scheme": "google_iap", "hosted_domain": "example.com"});
        }
        Instance::from_bytes(&serde_json::to_vec(&instance)?)
    };
    let directory = artifact.directory().to_string_lossy().into_owned();
    let binding = serde_json::json!({
        "artifact": directory,
        "readers": [],
        "writers": [],
        "rendered_authority": {"admins": ["ada@example.com"]},
    });
    let installed = instance(binding.clone(), true)?;
    let document = AuthorityDocument::resolve(&installed, "app", &artifact)?;
    let expected = rendered(
        artifact.contract(),
        &RenderedAuthority {
            admins: set(&["ada@example.com"]),
        },
        &BTreeMap::new(),
    )?;
    ensure!(document.policy.as_ref() == Some(&expected.policy));
    ensure!(document.readers == expected.readers && document.writers == expected.writers);
    ensure!(document.hosted_domain.as_deref() == Some("example.com"));

    let error = format!("{:#}", instance(binding.clone(), false).unwrap_err());
    ensure!(
        error.contains("needs the installation's identity provider"),
        "{error}"
    );
    let mut explicit = binding.clone();
    explicit["readers"] = serde_json::json!([DOMAIN]);
    let error = format!("{:#}", instance(explicit, true).unwrap_err());
    ensure!(
        error.contains("replaces authority, readers and writers"),
        "{error}"
    );
    let mut nobody = binding;
    nobody["rendered_authority"]["admins"] = serde_json::json!([]);
    let error = format!("{:#}", instance(nobody, true).unwrap_err());
    ensure!(
        error.contains("at least one individual administrator"),
        "{error}"
    );
    Ok(())
}
