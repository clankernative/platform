//! An application's authority, rendered from what its artifact declares.
//!
//! An installation that serves an application behind its identity provider can
//! name only the application's administrators ([`RenderedAuthority`] in its
//! binding). Activation then renders the rest from the exact artifact being
//! activated, so the policy always names that build's operations and no file
//! hand-tunes who may do what:
//!
//! - **Who runs an operation** is its audience. `Employees` is the hosted domain
//!   the identity provider verifies, `Owners` is [`OWNERS`] (the policy's
//!   individual administrators, read when each call is decided) and `Closed` is
//!   nobody. An internal command runs for whoever reaches it: the actors of
//!   every operation that requests it and the actor bound to each schedule or
//!   ingress endpoint that runs it, followed through further requests. A
//!   command nothing reaches is closed.
//! - **What it reaches** is what it declares: the commands it requests, the
//!   observations it lists with `.observes` and, for a command, its external
//!   effects. Nothing else.
//! - **Models.** Every operation reads every model. A command creates and
//!   updates exactly what its effects declare, and soft deletion uses the
//!   model's update authority, as everywhere. An owned model's owner column is
//!   never updatable. A command that updates or soft-deletes an owned model
//!   reaches only the caller's rows unless it declares `.any_owner(model)`.
//!   Administrators reach every row, so this narrows employees and the internal
//!   commands they, schedules and endpoints reach.
//! - **Membership.** The hosted domain reads and writes. The actor bound to each
//!   schedule and endpoint also writes, through the commands it runs.
//! - **No delegations.** Acting for someone else stays an explicit policy.
//!
//! A contract built before audiences existed declares none and is refused.

use crate::{
    app_contract::{Audience, Effect},
    artifact::{Artifact, EndpointBinding, ScheduleBinding},
    authority::{
        DOMAIN_PREFIX, Mode, ModelGrant, OWNER_BUDGET, OWNERS, OperationPolicy, Policy, Rows,
        TextConstraint, in_domain, individual, valid_actor,
    },
    schema::{Kind, Record, Schema},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The administrators of an application whose authority is rendered: its
/// owners and any service that maintains it. The [`OWNERS`] entry admits the
/// individual people among them; every administrator reads the platform audit
/// log and reaches every owned row.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenderedAuthority {
    pub admins: BTreeSet<String>,
}

impl RenderedAuthority {
    /// Every person among the admins belongs to `hosted_domain`, as
    /// `day2 platform owners add` requires: rendered membership admits only that
    /// domain, so anyone else could never run an Owners operation. A service
    /// account may join them, as an administrator only.
    pub fn validate(&self, hosted_domain: &str) -> Result<()> {
        ensure!(
            self.admins.len() <= OWNER_BUDGET,
            "rendered authority admin budget"
        );
        for admin in &self.admins {
            valid_actor(admin).with_context(|| format!("rendered authority admin {admin:?}"))?;
            ensure!(
                !individual(admin) || in_domain(admin, hosted_domain),
                "rendered authority admin {admin:?} is not at the hosted domain {hosted_domain}"
            );
        }
        ensure!(
            self.admins.iter().any(|admin| individual(admin)),
            "rendered authority needs at least one individual administrator: nobody else can \
             run an Owners operation or read the platform audit log"
        );
        Ok(())
    }
}

/// What an installation contributes to a rendered authority. Everything else
/// comes from the artifact.
pub struct Inputs<'a> {
    /// The hosted domain the installation's identity provider verifies.
    pub hosted_domain: &'a str,
    pub authority: &'a RenderedAuthority,
    pub schedules: &'a BTreeMap<String, ScheduleBinding>,
    pub ingress: &'a BTreeMap<String, EndpointBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    pub readers: BTreeSet<String>,
    pub writers: BTreeSet<String>,
    pub policy: Policy,
}

pub fn render(contract: &Artifact, inputs: &Inputs<'_>) -> Result<Rendered> {
    inputs.authority.validate(inputs.hosted_domain)?;
    let definition = contract
        .app_contract
        .as_ref()
        .context("rendered authority needs an application contract")?;
    let public = definition
        .operations
        .values()
        .any(|operation| !operation.execution.internal);
    ensure!(
        !public || definition.declares_audiences()?,
        "this artifact declares no operation audiences: it was built before they existed, so its \
         authority cannot be rendered; rebuild it with the current SDK"
    );
    let domain = format!("{DOMAIN_PREFIX}{}", inputs.hosted_domain);
    let declared = |name: &str| {
        definition
            .operations
            .get(name)
            .with_context(|| format!("operation {name} has no application contract"))
    };

    let mut actors = BTreeMap::new();
    for operation in &contract.operations {
        let seed = match declared(&operation.name)?.audience {
            Some(Audience::Employees) => BTreeSet::from([domain.clone()]),
            Some(Audience::Owners) => BTreeSet::from([OWNERS.to_owned()]),
            Some(Audience::Closed) | None => BTreeSet::new(),
        };
        actors.insert(operation.name.as_str(), seed);
    }
    let mut bound = BTreeSet::new();
    let schedules = inputs.schedules.iter().map(|(name, binding)| {
        let schedule = contract
            .schedules
            .iter()
            .find(|schedule| schedule.name == *name)
            .with_context(|| format!("schedule binding names no declared schedule: {name}"))?;
        anyhow::Ok((schedule.operation.as_str(), &binding.actor))
    });
    let endpoints = inputs.ingress.iter().map(|(name, binding)| {
        let endpoint = contract
            .ingress
            .iter()
            .find(|endpoint| endpoint.name == *name)
            .with_context(|| format!("ingress binding names no declared endpoint: {name}"))?;
        anyhow::Ok((endpoint.operation.as_str(), &binding.actor))
    });
    for entry in schedules.chain(endpoints) {
        let (operation, actor) = entry?;
        actors
            .get_mut(operation)
            .with_context(|| format!("bound operation is not in the artifact: {operation}"))?
            .insert(actor.clone());
        bound.insert(actor.clone());
    }
    // An internal command runs as whoever reached it, so it takes the actors of
    // everything that requests it, to a fixed point: requests can form cycles.
    let (internal, public): (Vec<(&str, &str)>, Vec<_>) = definition
        .operations
        .iter()
        .flat_map(|(name, operation)| {
            operation
                .execution
                .effects
                .iter()
                .filter(|effect| effect.kind == "request")
                .map(move |effect| (name.as_str(), effect.command.as_str()))
        })
        .partition(|(_, command)| contract.internal_command(command));
    loop {
        let mut changed = false;
        for (from, to) in &internal {
            let reaching = actors.get(from).cloned().unwrap_or_default();
            let target = actors
                .get_mut(to)
                .with_context(|| format!("requested command is not in the artifact: {to}"))?;
            for actor in reaching {
                changed |= target.insert(actor);
            }
        }
        if !changed {
            break;
        }
    }
    // A requested public command keeps its own audience, and a child runs as
    // the actor that reached its parent. A request its target's audience does
    // not cover would fail on every call, so it is refused here instead.
    for (from, to) in &public {
        let target = actors
            .get(to)
            .with_context(|| format!("requested command is not in the artifact: {to}"))?;
        for actor in actors.get(from).into_iter().flatten() {
            ensure!(
                target.contains(actor) || (actor == OWNERS && target.contains(&domain)),
                "{from} requests {to}, which {actor} may not run: give {to} an audience that \
                 covers everyone who reaches {from}, or make it internal"
            );
        }
    }

    let mut operations = BTreeMap::new();
    for operation in &contract.operations {
        let definition = declared(&operation.name)?;
        let command = match operation.kind.as_str() {
            "query" => false,
            "command" => true,
            _ => bail!("unsupported operation kind: {}", operation.name),
        };
        let effects = &definition.execution.effects;
        let models = contract
            .schema
            .models
            .iter()
            .map(|(model, record)| {
                let mut grant = declared_grant(command, model, record, effects);
                if let Some(column) = contract.schema.owners.get(model) {
                    grant.update_fields.remove(column);
                    if command && writes(effects, model) && !definition.any_owner.contains(model) {
                        grant.rows = Rows::OwnerOrAdmin {
                            field: column.clone(),
                        };
                    }
                }
                (model.clone(), grant)
            })
            .collect();
        operations.insert(
            operation.name.clone(),
            OperationPolicy {
                actors: actors.remove(operation.name.as_str()).unwrap_or_default(),
                mode: if command {
                    Mode::CurrentState
                } else {
                    Mode::Read
                },
                models,
                commands: effects
                    .iter()
                    .filter(|effect| effect.kind == "request")
                    .map(|effect| effect.command.clone())
                    .collect(),
                observations: definition.observations.iter().cloned().collect(),
                effects: effects
                    .iter()
                    .filter(|effect| command && effect.kind == "external")
                    .map(|effect| effect.command.clone())
                    .collect(),
            },
        );
    }
    let policy = Policy {
        row_owners: contract.schema.owners.clone(),
        version: 1,
        admins: inputs.authority.admins.clone(),
        operations,
        constraints: text_constraints(&contract.schema),
        delegations: BTreeMap::new(),
    };
    policy.validate(&contract.operations, &contract.schema)?;
    policy.validate_domains(Some(inputs.hosted_domain))?;
    let readers = BTreeSet::from([domain]);
    let mut writers = readers.clone();
    writers.extend(bound);
    Ok(Rendered {
        readers,
        writers,
        policy,
    })
}

/// Render `contract` as an installation would, with every declared schedule
/// and endpoint bound, so a contract that no installation could activate is
/// refused when it is built rather than when it is deployed.
pub(crate) fn check(contract: &Artifact) -> Result<()> {
    const DOMAIN: &str = "example.invalid";
    let actor = format!("automation@{DOMAIN}");
    let schedules = contract
        .schedules
        .iter()
        .map(|schedule| {
            (
                schedule.name.clone(),
                ScheduleBinding {
                    actor: actor.clone(),
                    disabled: false,
                },
            )
        })
        .collect();
    let ingress = contract
        .ingress
        .iter()
        .map(|endpoint| {
            (
                endpoint.name.clone(),
                EndpointBinding {
                    actor: actor.clone(),
                    connection: day2_capabilities::resources::VersionRef {
                        id: endpoint.name.clone(),
                        revision: 1,
                    },
                    disabled: false,
                },
            )
        })
        .collect();
    render(
        contract,
        &Inputs {
            hosted_domain: DOMAIN,
            authority: &RenderedAuthority {
                admins: BTreeSet::from([format!("owner@{DOMAIN}")]),
            },
            schedules: &schedules,
            ingress: &ingress,
        },
    )
    .context("no installation could render this application's authority")?;
    Ok(())
}

/// Whether `effects` update or soft-delete rows of `model`: the writes an
/// owner column narrows, and the ones `.any_owner` exempts.
pub(crate) fn writes(effects: &[Effect], model: &str) -> bool {
    effects.iter().any(|effect| {
        effect.model == model
            && matches!(
                effect.kind.as_str(),
                "update" | "update_created" | "soft_delete"
            )
    })
}

/// The model access an operation's declared effects need, over every row.
///
/// Every operation reads every model. A command creates what it declares and
/// updates the fields it declares. Native soft deletion uses the model's update
/// authority; the execution contract still forbids undeclared field updates.
pub(crate) fn declared_grant(
    command: bool,
    model: &str,
    record: &Record,
    effects: &[Effect],
) -> ModelGrant {
    let declared: Vec<_> = effects
        .iter()
        .filter(|effect| effect.model == model)
        .collect();
    let deletion = command && declared.iter().any(|effect| effect.kind == "soft_delete");
    ModelGrant {
        read: true,
        create: command && declared.iter().any(|effect| effect.kind == "create"),
        update_fields: if deletion {
            record.fields.keys().cloned().collect()
        } else if command {
            declared
                .iter()
                .filter(|effect| matches!(effect.kind.as_str(), "update" | "update_created"))
                .flat_map(|effect| effect.fields.iter().cloned())
                .collect()
        } else {
            BTreeSet::new()
        },
        rows: Rows::All,
    }
}

/// The platform's bound on every domain-typed text field.
pub(crate) fn text_constraints(
    schema: &Schema,
) -> BTreeMap<String, BTreeMap<String, TextConstraint>> {
    schema
        .models
        .iter()
        .filter_map(|(name, model)| {
            let fields: BTreeMap<_, _> = model
                .fields
                .iter()
                .filter(|(_, kind)| matches!(kind, Kind::TextDomain { .. }))
                .map(|(field, _)| {
                    (
                        field.clone(),
                        TextConstraint {
                            nonempty: false,
                            max_bytes: 16_384,
                        },
                    )
                })
                .collect();
            (!fields.is_empty()).then(|| (name.clone(), fields))
        })
        .collect()
}
