//! Platform-owned local fixtures and deterministic command campaigns. App modules
//! return pure values; only the ordinary command runtime can apply them.
use crate::{
    artifact::{AppBinding, Instance, LoadedArtifact},
    authority::{Mode, ModelGrant, OperationPolicy, Policy, Rows, TextConstraint},
    properties,
    store::{Fault, Runtime},
    worker::Worker,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub const ACTOR: &str = "developer";
pub const DEFAULT_SEED: u64 = 0xDA72_2026;
pub const DEFAULT_CASES: u64 = 16;
const MAX_STEPS: usize = 128;

/// A selected callee's checked example, used only by disposable verification.
/// The target and schema pin also authorize the caller's simulated read.
#[derive(Clone, Debug)]
pub struct ImportedQueryFixture {
    pub app: String,
    pub operation: String,
    pub schema_digest: String,
    pub request: String,
    pub response: String,
}

pub fn imported_query_fixtures(
    instance_path: &Path,
    imports: &crate::instance_catalog::ImportedContracts,
) -> Result<Vec<ImportedQueryFixture>> {
    let instance_path = instance_path.canonicalize()?;
    let instance = Instance::load(&instance_path)?;
    let parent = instance_path.parent().context("instance directory")?;
    let mut fixtures = Vec::new();
    for (operation, package) in &imports.operations {
        if package.operation.kind != crate::operation_contract::Kind::Query {
            continue;
        }
        let app = instance
            .apps
            .keys()
            .find(|name| operation.starts_with(&format!("{name}.")))
            .context("imported query app is not selected")?;
        let selected = &instance.apps[app];
        let artifact = LoadedArtifact::load(&parent.join(&selected.artifact))?;
        ensure!(
            artifact.contract().namespace == *app,
            "imported query namespace changed"
        );
        let export = artifact
            .contract()
            .export_manifest
            .as_ref()
            .and_then(|manifest| manifest.exports.get(operation))
            .context("imported query is not exported")?;
        ensure!(export == package, "imported query contract changed");
        let definition = artifact
            .contract()
            .app_contract
            .as_ref()
            .context("imported query definitions missing")?
            .operations
            .get(operation)
            .context("imported query definition missing")?;
        fixtures.push(ImportedQueryFixture {
            app: app.clone(),
            operation: operation.clone(),
            schema_digest: crate::delegation::schema_digest_for_artifact(&artifact, operation)?,
            request: definition.request_example.clone(),
            response: definition.response_example.clone(),
        });
    }
    Ok(fixtures)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub operation: String,
    pub input: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Example {
    pub name: String,
    pub steps: Vec<Step>,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub generator: String,
    pub operation: String,
    pub seed: String,
    pub input: String,
    pub error: String,
}

fn exchange(artifact: &LoadedArtifact, request: &str) -> Result<Vec<u8>> {
    let executable = artifact.materialize_worker()?;
    Worker::start(&executable)?.exchange(request.as_bytes())
}

fn verification(
    artifact: &LoadedArtifact,
    action: &str,
    operation: &str,
    snapshot: &Value,
    before: &Value,
    output: &Value,
    seed: u64,
) -> Result<String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        value: String,
        error: String,
    }
    let request = format!(
        "verify:{}",
        json!({ "action": action, "operation": operation, "snapshot": snapshot.to_string(), "before": before.to_string(), "output": output.to_string(), "seed": seed })
    );
    let bytes = exchange(artifact, &request)?;
    ensure!(
        bytes == exchange(artifact, &request)?,
        "verification callback is not deterministic"
    );
    let reply: Reply = serde_json::from_slice(&bytes)?;
    ensure!(
        reply.error.is_empty(),
        "{operation} {action} verification failed: {}",
        reply.error
    );
    Ok(reply.value)
}

pub fn examples(artifact: &LoadedArtifact) -> Result<Vec<Example>> {
    if artifact.contract().format < 12
        && !artifact.contract().sources.contains_key("app/Examples.roc")
    {
        return Ok(Vec::new());
    }
    let values: Vec<Example> = serde_json::from_slice(&exchange(artifact, "examples")?)?;
    ensure!(values.len() <= 16, "invalid example catalog size");
    let mut names = BTreeSet::new();
    let mut total = 0;
    for example in &values {
        crate::schema::identifier(&example.name)?;
        ensure!(names.insert(&example.name), "duplicate example name");
        ensure!(
            example.error.is_empty(),
            "example {} failed: {}",
            example.name,
            example.error
        );
        ensure!(!example.steps.is_empty(), "empty example: {}", example.name);
        total += example.steps.len();
        ensure!(total <= MAX_STEPS, "example step budget");
        for step in &example.steps {
            validate_step(artifact, step)?;
        }
    }
    Ok(values)
}

pub fn samples(artifact: &LoadedArtifact, seed: u64, count: u64) -> Result<Vec<Sample>> {
    ensure!((1..=100).contains(&count), "generator count must be 1..100");
    if let Some(definition) = &artifact.contract().app_contract {
        ensure!(
            definition.operations.len() * count as usize <= MAX_STEPS,
            "verification obligation budget"
        );
        return Ok((0..count)
            .flat_map(|index| {
                definition.operations.keys().map(move |name| Sample {
                    generator: name.replace('.', "_"),
                    operation: name.clone(),
                    seed: seed.wrapping_add(index).to_string(),
                    input: String::new(),
                    error: String::new(),
                })
            })
            .collect());
    }
    if !artifact
        .contract()
        .sources
        .contains_key("app/Generators.roc")
    {
        return Ok(Vec::new());
    }
    let request = format!("generate:{seed}:{count}");
    let bytes = exchange(artifact, &request)?;
    // Re-evaluate independently; ambient state or unstable output cannot seed a run.
    ensure!(
        bytes == exchange(artifact, &request)?,
        "generator is not deterministic"
    );
    let values: Vec<Sample> = serde_json::from_slice(&bytes)?;
    ensure!(
        !values.is_empty() && values.len() <= MAX_STEPS,
        "invalid generated case count"
    );
    let mut actual: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    let mut operations = BTreeMap::new();
    for sample in &values {
        crate::schema::identifier(&sample.generator)?;
        ensure!(
            sample.error.is_empty(),
            "generator {} failed: {}",
            sample.generator,
            sample.error
        );
        validate_step(
            artifact,
            &Step {
                operation: sample.operation.clone(),
                input: sample.input.clone(),
            },
        )?;
        let case_seed: u64 = sample.seed.parse().context("invalid generated seed")?;
        ensure!(
            sample.seed == case_seed.to_string(),
            "noncanonical generated seed"
        );
        actual.entry(&sample.generator).or_default().push(case_seed);
        if let Some(operation) = operations.insert(&sample.generator, &sample.operation) {
            ensure!(
                operation == &sample.operation,
                "generator changed operation"
            );
        }
    }
    let expected: Vec<_> = (0..count).map(|i| seed.wrapping_add(i)).collect();
    ensure!(
        actual.len() <= 16 && actual.values().all(|seeds| *seeds == expected),
        "incomplete or duplicate generated cases"
    );
    Ok(values)
}

fn validate_step(artifact: &LoadedArtifact, step: &Step) -> Result<()> {
    ensure!(step.input.len() <= 65_536, "example input budget");
    let operation = artifact.route(&step.operation)?;
    ensure!(
        operation.name == step.operation
            && (operation.kind == "command" || operation.kind == "query"),
        "verification requires a declared command or query"
    );
    let input: Value = serde_json::from_str(&step.input)?;
    artifact
        .contract()
        .schema
        .inputs
        .get(&operation.input_type)
        .context("example input schema")?
        .validate_input(&input)
}

/// A disposable local profile. It is never installed into an existing instance
/// and is not a template for production authority. Explicit operator policy can
/// be supplied instead for a representative authorization campaign.
pub fn local_policy(artifact: &LoadedArtifact) -> Result<Policy> {
    local_policy_for(artifact, ACTOR)
}

pub fn local_policy_for(artifact: &LoadedArtifact, actor: &str) -> Result<Policy> {
    let mut operations = BTreeMap::new();
    for operation in &artifact.contract().operations {
        let mode = match operation.kind.as_str() {
            "query" => Mode::Read,
            "command" => Mode::CurrentState,
            _ => anyhow::bail!("unsupported operation kind"),
        };
        let models = artifact
            .contract()
            .schema
            .models
            .iter()
            .map(|(name, model)| {
                let write = operation.kind == "command";
                (
                    name.clone(),
                    ModelGrant {
                        read: true,
                        create: operation.kind == "command",
                        update_fields: if write {
                            model.fields.keys().cloned().collect()
                        } else {
                            BTreeSet::new()
                        },
                        rows: Rows::All,
                    },
                )
            })
            .collect();
        operations.insert(
            operation.name.clone(),
            OperationPolicy {
                observations: crate::capabilities::READS
                    .iter()
                    .copied()
                    .chain([crate::audit::HISTORY])
                    .map(Into::into)
                    .collect(),
                effects: if operation.kind == "command" {
                    crate::capabilities::WRITES
                        .iter()
                        .map(|name| (*name).into())
                        .collect()
                } else {
                    BTreeSet::new()
                },
                commands: artifact
                    .contract()
                    .app_contract
                    .as_ref()
                    .and_then(|definition| definition.operations.get(&operation.name))
                    .map(|definition| {
                        definition
                            .execution
                            .effects
                            .iter()
                            .filter(|effect| effect.kind == "request")
                            .map(|effect| effect.command.clone())
                            .collect()
                    })
                    .unwrap_or_default(),
                actors: BTreeSet::from([actor.into()]),
                mode,
                models,
            },
        );
    }
    let policy = Policy {
        version: 1,
        // The development actor owns a disposable instance, which is what lets
        // it read that instance's platform audit log. Rows are granted to every
        // operation below regardless, so owning them bypasses nothing further.
        admins: BTreeSet::from([actor.into()]),
        // A disposable development instance grants nobody the right to act as
        // anybody: impersonation is an operator's decision about real people.
        delegations: BTreeMap::new(),
        operations,
        constraints: artifact
            .contract()
            .schema
            .models
            .iter()
            .filter_map(|(name, model)| {
                let fields: BTreeMap<_, _> = model
                    .fields
                    .iter()
                    .filter(|(_, kind)| matches!(kind, crate::schema::Kind::TextDomain { .. }))
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
            .collect(),
    };
    policy.validate(&artifact.contract().operations, &artifact.contract().schema)?;
    Ok(policy)
}

/// Explicit authority authoring for disposable local verification only. Callers
/// select the invoking-actor mailbox topics and exact synthetic issuer. Runtime
/// loading and production activation never synthesize these grants.
pub fn local_resource_fixture(
    app: &str,
    policy: &Policy,
    notification_topics: Option<day2_capabilities::resources::TopicScope>,
    carta_issuer: Option<&str>,
) -> Result<(
    day2_capabilities::resources::Catalog,
    Vec<day2_capabilities::resources::Attachment>,
)> {
    use day2_capabilities::resources::*;
    let mut catalog = Catalog {
        version: 1,
        connections: BTreeMap::new(),
        resources: BTreeMap::new(),
        policies: BTreeMap::new(),
        budgets: BTreeMap::new(),
        credentials: Default::default(),
    };
    let mut attachments = Vec::new();
    for (operation_name, operation) in &policy.operations {
        if operation.actors.is_empty() {
            continue;
        }
        let mut slots = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        let families = [
            (
                "notifications",
                ResourceKind::NotificationMailbox,
                Provider::LocalNotifications,
                notification_topics
                    .clone()
                    .map(|topics| ResourceTarget::NotificationMailbox { topics }),
                vec![
                    Action::NotificationsResolve,
                    Action::NotificationsLatest,
                    Action::NotificationsSend,
                ],
            ),
            (
                "carta",
                ResourceKind::CartaIssuer,
                Provider::SyntheticCarta,
                carta_issuer.map(|issuer_id| ResourceTarget::CartaIssuer {
                    issuer_id: issuer_id.into(),
                }),
                vec![Action::CartaSnapshot, Action::CartaRecord],
            ),
        ];
        for (name, kind, provider, target, actions) in families {
            let Some(target) = target else { continue };
            let actions: BTreeSet<_> = actions
                .into_iter()
                .filter(|action| {
                    if action.is_write() {
                        operation.effects.contains(action.capability())
                    } else {
                        operation.observations.contains(action.capability())
                    }
                })
                .collect();
            if actions.is_empty() {
                continue;
            }
            let resource = VersionRef {
                id: name.into(),
                revision: 1,
            };
            catalog.connections.insert(
                name.into(),
                ConnectionDefinition {
                    live: None,
                    revision: 1,
                    provider,
                },
            );
            catalog.resources.insert(
                name.into(),
                ResourceDefinition {
                    revision: 1,
                    connection: resource.clone(),
                    target,
                },
            );
            slots.insert(
                name.into(),
                PolicySlot {
                    kind,
                    allowed_resources: BTreeSet::from([resource.clone()]),
                    actions,
                    limits: Limits {
                        max_request_bytes: 65_536,
                        max_response_bytes: 1_048_576,
                        max_calls_per_invocation: 20_000,
                    },
                    budgets: Vec::new(),
                },
            );
            bindings.insert(name.into(), resource);
        }
        if slots.is_empty() {
            continue;
        }
        let reusable = ReusablePolicy {
            revision: 1,
            owner: "local-fixture-operator".into(),
            delegates: BTreeSet::new(),
            actors: operation.actors.clone(),
            allowed_apps: BTreeSet::from([app.into()]),
            slots,
            max_duration_seconds: None,
        };
        let policy_id = format!(
            "fixture_{}",
            &crate::digest(&serde_json::to_vec(&reusable)?)[7..31]
        );
        catalog.policies.insert(policy_id.clone(), reusable);
        attachments.push(Attachment {
            policy: VersionRef {
                id: policy_id,
                revision: 1,
            },
            operation: operation_name.clone(),
            bindings,
            actors: None,
            expires_at_ms: None,
        });
    }
    catalog.validate()?;
    Ok((catalog, attachments))
}

pub fn create(artifact_path: &Path, directory: &Path, policy: Option<Policy>) -> Result<Runtime> {
    create_for(artifact_path, directory, policy, ACTOR)
}

/// Whether this artifact is the work-compliance queue.
///
/// Keyed on the operation namespace rather than on declared capabilities,
/// because the capabilities that need granting here are *reads*. An application
/// declares external effects in its execution contract, which is what
/// `uses_synthetic_fixture` can match on; it declares no such thing for a
/// provider it only reads, so there is nothing capability-shaped to detect.
///
/// Explicit and greppable is the point. Like the People Ops fixture below, this
/// is a disposable development authority and production never infers grants from
/// what an application happens to call.
fn work_compliance_reads_linear(policy: &Policy) -> bool {
    policy
        .operations
        .keys()
        .any(|name| name.starts_with("work_compliance."))
}

/// Whether any operation here declares a GitHub Actions read.
///
/// Keyed on the declared capability rather than on an app name, because both
/// actions are reads that any CI-watching application may want — unlike the
/// Linear work sources below, whose binding names are specific to one app.
fn reads_github_actions(policy: &Policy) -> bool {
    policy.operations.values().any(|operation| {
        operation.observations.contains("github.job.v1")
            || operation.observations.contains("github.job_log.v1")
    })
}

/// Explicit GitHub Actions disposable authority.
///
/// One repository, because a grant names one repository — that is the whole of
/// the authority, and it is what stops a CI watcher reading logs from a
/// repository nobody granted it. The connection carries a real endpoint so the
/// simulation intercepts at the transport seam rather than by the connection
/// being absent, exactly as the other live providers do.
pub fn github_actions_resource_fixture(
    app: &str,
    policy: &Policy,
) -> Result<(
    day2_capabilities::resources::Catalog,
    Vec<day2_capabilities::resources::Attachment>,
)> {
    use day2_capabilities::resources::*;
    let (mut catalog, mut attachments) = local_resource_fixture(app, policy, None, None)?;
    for (operation_name, operation) in &policy.operations {
        if operation.actors.is_empty() {
            continue;
        }
        let actions: BTreeSet<_> = [Action::GitHubJob, Action::GitHubJobLog]
            .into_iter()
            .filter(|action| operation.observations.contains(action.capability()))
            .collect();
        if actions.is_empty() {
            continue;
        }
        let name = "github_actions";
        let resource = VersionRef {
            id: name.into(),
            revision: 1,
        };
        catalog.connections.insert(
            name.into(),
            ConnectionDefinition {
                live: Some(
                    day2_capabilities::integrations::LiveConnection::GitHubActions {
                        credential_ref: VersionRef {
                            id: "github_installation_token".into(),
                            revision: 1,
                        },
                        endpoint: "https://api.github.test".into(),
                    },
                ),
                revision: 1,
                provider: Provider::GitHubActions,
            },
        );
        catalog.resources.insert(
            name.into(),
            ResourceDefinition {
                revision: 1,
                connection: resource.clone(),
                target: ResourceTarget::GitHubRepository {
                    owner: "synthetic-org".into(),
                    repo: "synthetic-repo".into(),
                },
            },
        );
        let reusable = ReusablePolicy {
            revision: 1,
            owner: "local-fixture-operator".into(),
            delegates: BTreeSet::new(),
            actors: operation.actors.clone(),
            allowed_apps: BTreeSet::from([app.into()]),
            slots: BTreeMap::from([(
                name.to_owned(),
                PolicySlot {
                    kind: ResourceKind::GitHubRepository,
                    allowed_resources: BTreeSet::from([resource.clone()]),
                    actions,
                    limits: Limits {
                        max_request_bytes: 65_536,
                        max_response_bytes: 1_048_576,
                        max_calls_per_invocation: 20_000,
                    },
                    budgets: Vec::new(),
                },
            )]),
            max_duration_seconds: None,
        };
        let policy_id = format!(
            "fixture_{}",
            &crate::digest(&serde_json::to_vec(&reusable)?)[7..31]
        );
        catalog.policies.insert(policy_id.clone(), reusable);
        attachments.push(Attachment {
            policy: VersionRef {
                id: policy_id,
                revision: 1,
            },
            operation: operation_name.clone(),
            bindings: BTreeMap::from([(name.to_owned(), resource)]),
            actors: None,
            expires_at_ms: None,
        });
    }
    catalog.validate()?;
    Ok((catalog, attachments))
}

pub fn gitea_actions_resource_fixture(
    app: &str,
    policy: &Policy,
) -> Result<(
    day2_capabilities::resources::Catalog,
    Vec<day2_capabilities::resources::Attachment>,
)> {
    use day2_capabilities::resources::*;
    let (mut catalog, mut attachments) = local_resource_fixture(app, policy, None, None)?;
    for (operation_name, operation) in &policy.operations {
        if operation.actors.is_empty() {
            continue;
        }
        let actions: BTreeSet<_> = [
            Action::GiteaRuns,
            Action::GiteaRun,
            Action::GiteaRunJobs,
            Action::GiteaJob,
            Action::GiteaJobLog,
            Action::GiteaRunners,
        ]
        .into_iter()
        .filter(|action| operation.observations.contains(action.capability()))
        .collect();
        if actions.is_empty() {
            continue;
        }
        for (name, owner) in [
            ("gitea_actions", "synthetic-org"),
            ("gitea_internal_tools", "synthetic-tools"),
        ] {
            let resource = VersionRef {
                id: name.into(),
                revision: 1,
            };
            catalog.connections.insert(
                name.into(),
                ConnectionDefinition {
                    live: Some(
                        day2_capabilities::integrations::LiveConnection::GiteaActions {
                            signing_secret_ref: None,
                            credential_ref: VersionRef {
                                id: "gitea_token".into(),
                                revision: 1,
                            },
                            endpoint: "https://git.example.test".into(),
                        },
                    ),
                    revision: 1,
                    provider: Provider::GiteaActions,
                },
            );
            catalog.resources.insert(
                name.into(),
                ResourceDefinition {
                    revision: 1,
                    connection: resource.clone(),
                    target: ResourceTarget::GiteaOrganization {
                        owner: owner.into(),
                    },
                },
            );
            let reusable = ReusablePolicy {
                revision: 1,
                owner: "local-fixture-operator".into(),
                delegates: BTreeSet::new(),
                actors: operation.actors.clone(),
                allowed_apps: BTreeSet::from([app.into()]),
                slots: BTreeMap::from([(
                    name.to_owned(),
                    PolicySlot {
                        kind: ResourceKind::GiteaOrganization,
                        allowed_resources: BTreeSet::from([resource.clone()]),
                        actions: actions.clone(),
                        limits: Limits {
                            max_request_bytes: 65_536,
                            max_response_bytes: 1_048_576,
                            max_calls_per_invocation: 20_000,
                        },
                        budgets: Vec::new(),
                    },
                )]),
                max_duration_seconds: None,
            };
            let policy_id = format!(
                "fixture_{}",
                &crate::digest(&serde_json::to_vec(&reusable)?)[7..31]
            );
            catalog.policies.insert(policy_id.clone(), reusable);
            attachments.push(Attachment {
                policy: VersionRef {
                    id: policy_id,
                    revision: 1,
                },
                operation: operation_name.clone(),
                bindings: BTreeMap::from([(name.to_owned(), resource)]),
                actors: None,
                expires_at_ms: None,
            });
        }
    }
    catalog.validate()?;
    Ok((catalog, attachments))
}

/// Explicit work-compliance disposable authority.
///
/// One resource per configured Linear source, because a grant names one source:
/// that is the whole of the authority, and it is what stops a compliance queue
/// reading any other view in the workspace. The connection carries no live
/// endpoint, so a disposable instance is served by the simulation rather than
/// reaching Linear.
pub fn linear_work_resource_fixture(
    app: &str,
    policy: &Policy,
) -> Result<(
    day2_capabilities::resources::Catalog,
    Vec<day2_capabilities::resources::Attachment>,
)> {
    use day2_capabilities::{integrations::LinearWorkSource, resources::*};
    let (mut catalog, mut attachments) = local_resource_fixture(app, policy, None, None)?;
    let view = |key: &str, name: &str| LinearWorkSource::CustomView {
        view_id: format!("synthetic-view-{key}"),
        name: name.into(),
        url: format!("https://linear.app/synthetic/view/synthetic-view-{key}"),
    };
    let families = [
        ("linear_standup", view("standup", "Product Owners Standup")),
        ("linear_harry_asks", view("harry-asks", "Harry Asks")),
        (
            "linear_sessions_bugs",
            view("sessions-bugs", "Sessions bugs"),
        ),
        // The incident source is a label rather than a saved view, exactly as it
        // is in the service this replaces.
        (
            "linear_incident_follow_up",
            LinearWorkSource::Label {
                label: "incident-follow-up".into(),
            },
        ),
    ];
    for (operation_name, operation) in &policy.operations {
        if operation.actors.is_empty() {
            continue;
        }
        let mut slots = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        for (name, source) in &families {
            // Only what this operation actually declares. A queue read has no
            // business holding the reassignment write.
            let actions: BTreeSet<_> = [
                Action::LinearWorkIssues,
                Action::LinearWorkIssueDetail,
                Action::LinearWorkAssignableUsers,
                Action::LinearWorkReassign,
            ]
            .into_iter()
            .filter(|action| {
                if action.is_write() {
                    operation.effects.contains(action.capability())
                } else {
                    operation.observations.contains(action.capability())
                }
            })
            .collect();
            if actions.is_empty() {
                continue;
            }
            let resource = VersionRef {
                id: (*name).into(),
                revision: 1,
            };
            catalog.connections.insert(
                (*name).into(),
                ConnectionDefinition {
                    // A live provider, so the connection is a real one — the
                    // simulation intercepts at the transport seam rather than by
                    // the connection being absent, exactly as it does for Slack.
                    // A disposable instance therefore exercises the same adapter
                    // the deployed one will.
                    live: Some(
                        day2_capabilities::integrations::LiveConnection::LinearWork {
                            credential_ref: VersionRef {
                                id: "linear_work_token".into(),
                                revision: 1,
                            },
                            organization_id: "synthetic-linear-work-1".into(),
                        },
                    ),
                    revision: 1,
                    provider: Provider::LinearWork,
                },
            );
            catalog.resources.insert(
                (*name).into(),
                ResourceDefinition {
                    revision: 1,
                    connection: resource.clone(),
                    target: ResourceTarget::LinearIssueSource {
                        source: source.clone(),
                    },
                },
            );
            slots.insert(
                (*name).into(),
                PolicySlot {
                    kind: ResourceKind::LinearIssueSource,
                    allowed_resources: BTreeSet::from([resource.clone()]),
                    actions,
                    limits: Limits {
                        max_request_bytes: 65_536,
                        max_response_bytes: 1_048_576,
                        max_calls_per_invocation: 20_000,
                    },
                    budgets: Vec::new(),
                },
            );
            bindings.insert((*name).into(), resource);
        }
        if slots.is_empty() {
            continue;
        }
        let reusable = ReusablePolicy {
            revision: 1,
            owner: "local-fixture-operator".into(),
            delegates: BTreeSet::new(),
            actors: operation.actors.clone(),
            allowed_apps: BTreeSet::from([app.into()]),
            slots,
            max_duration_seconds: None,
        };
        let policy_id = format!(
            "fixture_{}",
            &crate::digest(&serde_json::to_vec(&reusable)?)[7..31]
        );
        catalog.policies.insert(policy_id.clone(), reusable);
        attachments.push(Attachment {
            policy: VersionRef {
                id: policy_id,
                revision: 1,
            },
            operation: operation_name.clone(),
            bindings,
            actors: None,
            expires_at_ms: None,
        });
    }
    catalog.validate()?;
    Ok((catalog, attachments))
}

/// Explicit People Ops disposable authority, paired with synthetic_example().
/// Production loading never infers these targets or grants from app capabilities.
pub fn people_resource_fixture(
    app: &str,
    policy: &Policy,
) -> Result<(
    day2_capabilities::resources::Catalog,
    Vec<day2_capabilities::resources::Attachment>,
)> {
    use day2_capabilities::resources::*;
    let (mut catalog, mut attachments) = local_resource_fixture(app, policy, None, None)?;
    let families = [
        (
            "google_directory",
            Provider::SyntheticGoogleDirectory,
            ResourceTarget::GoogleDirectory {
                customer_id: "synthetic-customer-1".into(),
                email_domain: "exampleco.example".into(),
                org_unit_prefix: "/".into(),
                groups: BTreeMap::from([
                    ("engineering".into(), "engineering@exampleco.example".into()),
                    (
                        "engineering@exampleco.example".into(),
                        "engineering@exampleco.example".into(),
                    ),
                    ("growth".into(), "growth@exampleco.example".into()),
                    (
                        "growth@exampleco.example".into(),
                        "growth@exampleco.example".into(),
                    ),
                ]),
            },
            vec![
                Action::GoogleDirectorySnapshot,
                Action::GoogleDirectoryRecord,
                Action::GoogleDirectoryCreateUser,
                Action::GoogleDirectoryPatchAttributes,
                Action::GoogleDirectoryEnsureGroupMember,
            ],
        ),
        (
            "linear",
            Provider::SyntheticLinear,
            ResourceTarget::LinearOrganization {
                organization_id: "synthetic-linear-1".into(),
                email_domain: "exampleco.example".into(),
            },
            vec![Action::LinearEnsureAccess, Action::LinearSuspend],
        ),
        (
            "operator_alerts",
            Provider::SyntheticOperatorAlerts,
            ResourceTarget::OperatorAlertDestination {
                destination: "synthetic-people-operator".into(),
                topics: TopicScope::Only {
                    topics: BTreeSet::from(["people_ops".into()]),
                },
            },
            vec![Action::OperatorAlertsSend],
        ),
    ];
    for (operation_name, operation) in &policy.operations {
        if operation.actors.is_empty() {
            continue;
        }
        let mut slots = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        for (name, provider, target, actions) in &families {
            let actions: BTreeSet<_> = actions
                .iter()
                .copied()
                .filter(|action| {
                    if action.is_write() {
                        operation.effects.contains(action.capability())
                    } else {
                        operation.observations.contains(action.capability())
                    }
                })
                .collect();
            if actions.is_empty() {
                continue;
            }
            let resource = VersionRef {
                id: (*name).into(),
                revision: 1,
            };
            catalog.connections.insert(
                (*name).into(),
                ConnectionDefinition {
                    live: None,
                    revision: 1,
                    provider: *provider,
                },
            );
            catalog.resources.insert(
                (*name).into(),
                ResourceDefinition {
                    revision: 1,
                    connection: resource.clone(),
                    target: target.clone(),
                },
            );
            slots.insert(
                (*name).into(),
                PolicySlot {
                    kind: target.kind(),
                    allowed_resources: BTreeSet::from([resource.clone()]),
                    actions,
                    limits: Limits {
                        max_request_bytes: 16_384,
                        max_response_bytes: 16_384,
                        max_calls_per_invocation: 256,
                    },
                    budgets: Vec::new(),
                },
            );
            bindings.insert((*name).into(), resource);
        }
        if slots.is_empty() {
            continue;
        }
        let reusable = ReusablePolicy {
            revision: 1,
            owner: "local-fixture-operator".into(),
            delegates: BTreeSet::new(),
            actors: operation.actors.clone(),
            allowed_apps: BTreeSet::from([app.into()]),
            slots,
            max_duration_seconds: None,
        };
        let policy_id = format!(
            "people_fixture_{}",
            &crate::digest(&serde_json::to_vec(&reusable)?)[7..31]
        );
        catalog.policies.insert(policy_id.clone(), reusable);
        attachments.push(Attachment {
            policy: VersionRef {
                id: policy_id,
                revision: 1,
            },
            operation: operation_name.clone(),
            bindings,
            actors: None,
            expires_at_ms: None,
        });
    }
    catalog.validate()?;
    Ok((catalog, attachments))
}

/// Shared exact fixture authoring for initial creation and managed rebuilds.
/// People resources are an explicit canary addition only for declaring artifacts.
pub fn resource_fixture_for_artifact(
    app: &str,
    artifact: &LoadedArtifact,
    policy: &Policy,
) -> Result<(
    day2_capabilities::resources::Catalog,
    Vec<day2_capabilities::resources::Attachment>,
)> {
    resource_fixture_for_artifact_with_imports(app, artifact, policy, &[])
}

fn resource_fixture_for_artifact_with_imports(
    app: &str,
    artifact: &LoadedArtifact,
    policy: &Policy,
    imports: &[ImportedQueryFixture],
) -> Result<(
    day2_capabilities::resources::Catalog,
    Vec<day2_capabilities::resources::Attachment>,
)> {
    use day2_capabilities::resources::*;
    let (mut catalog, mut attachments) = local_resource_fixture(
        app,
        policy,
        Some(day2_capabilities::resources::TopicScope::Any),
        Some("synthetic-issuer-1"),
    )?;
    if policy.operations.values().any(|op| {
        op.observations
            .iter()
            .any(|name| name.starts_with("gitea."))
    }) {
        let (gitea, gitea_attachments) = gitea_actions_resource_fixture(app, policy)?;
        catalog.connections.extend(gitea.connections);
        catalog.resources.extend(gitea.resources);
        catalog.policies.extend(gitea.policies);
        attachments.extend(gitea_attachments);
    }
    for (operation_name, operation) in &policy.operations {
        if operation.actors.is_empty() || !operation.effects.contains("slack_webhook.post.v1") {
            continue;
        }
        use day2_capabilities::resources::*;
        let name = "slack_alerts";
        let resource = VersionRef {
            id: name.into(),
            revision: 1,
        };
        catalog.connections.insert(
            name.into(),
            ConnectionDefinition {
                revision: 1,
                provider: Provider::SlackWebhook,
                live: Some(
                    day2_capabilities::integrations::LiveConnection::SlackWebhook {
                        credential_ref: VersionRef {
                            id: "slack_webhook_url".into(),
                            revision: 1,
                        },
                    },
                ),
            },
        );
        catalog.resources.insert(
            name.into(),
            ResourceDefinition {
                revision: 1,
                connection: resource.clone(),
                target: ResourceTarget::SlackWebhookDestination {
                    endpoint_sha256: crate::integrations::simulated::slack_webhook_digest(),
                },
            },
        );
        let reusable = ReusablePolicy {
            revision: 1,
            owner: "local-fixture-operator".into(),
            delegates: BTreeSet::new(),
            actors: operation.actors.clone(),
            allowed_apps: BTreeSet::from([app.into()]),
            max_duration_seconds: None,
            slots: BTreeMap::from([(
                name.into(),
                PolicySlot {
                    kind: ResourceKind::SlackWebhookDestination,
                    allowed_resources: BTreeSet::from([resource.clone()]),
                    actions: BTreeSet::from([Action::SlackWebhookPost]),
                    limits: Limits {
                        max_request_bytes: 65_536,
                        max_response_bytes: 65_536,
                        max_calls_per_invocation: 8,
                    },
                    budgets: vec![],
                },
            )]),
        };
        let policy_id = format!(
            "fixture_{}",
            &crate::digest(&serde_json::to_vec(&reusable)?)[7..31]
        );
        catalog.policies.insert(policy_id.clone(), reusable);
        attachments.push(Attachment {
            policy: VersionRef {
                id: policy_id,
                revision: 1,
            },
            operation: operation_name.clone(),
            bindings: BTreeMap::from([(name.into(), resource)]),
            actors: None,
            expires_at_ms: None,
        });
    }
    if reads_github_actions(policy) {
        let (github, github_attachments) = github_actions_resource_fixture(app, policy)?;
        catalog.connections.extend(github.connections);
        catalog.resources.extend(github.resources);
        catalog.policies.extend(github.policies);
        catalog.budgets.extend(github.budgets);
        attachments.extend(github_attachments);
    }
    if work_compliance_reads_linear(policy) {
        let (work, work_attachments) = linear_work_resource_fixture(app, policy)?;
        catalog.connections.extend(work.connections);
        catalog.resources.extend(work.resources);
        catalog.policies.extend(work.policies);
        catalog.budgets.extend(work.budgets);
        attachments.extend(work_attachments);
    }
    if crate::people_providers::uses_synthetic_fixture(artifact) {
        let (people, people_attachments) = people_resource_fixture(app, policy)?;
        catalog.connections.extend(people.connections);
        catalog.resources.extend(people.resources);
        catalog.policies.extend(people.policies);
        catalog.budgets.extend(people.budgets);
        attachments.extend(people_attachments);
    }
    if !imports.is_empty() {
        catalog.connections.insert(
            "imported_queries".into(),
            ConnectionDefinition {
                revision: 1,
                provider: Provider::LocalDelegation,
                live: None,
            },
        );
        let mut imported_resources = BTreeMap::new();
        for import in imports {
            let id = format!(
                "import_{}",
                &crate::digest(&serde_json::to_vec(&(&import.app, &import.operation))?)[7..31]
            );
            ensure!(
                imported_resources
                    .insert(import.operation.clone(), id.clone())
                    .is_none(),
                "duplicate imported query fixture"
            );
            catalog.resources.insert(
                id,
                ResourceDefinition {
                    revision: 1,
                    connection: VersionRef {
                        id: "imported_queries".into(),
                        revision: 1,
                    },
                    target: ResourceTarget::AppOperation {
                        app: import.app.clone(),
                        operation: import.operation.clone(),
                        schema_digest: import.schema_digest.clone(),
                    },
                },
            );
        }
        for (operation_name, operation) in &policy.operations {
            if operation.actors.is_empty() || !operation.observations.contains("app.query.v1") {
                continue;
            }
            let bindings: BTreeMap<_, _> = imported_resources
                .values()
                .map(|id| {
                    (
                        id.clone(),
                        VersionRef {
                            id: id.clone(),
                            revision: 1,
                        },
                    )
                })
                .collect();
            let slots = bindings
                .iter()
                .map(|(name, resource)| {
                    (
                        name.clone(),
                        PolicySlot {
                            kind: ResourceKind::AppOperation,
                            allowed_resources: BTreeSet::from([resource.clone()]),
                            actions: BTreeSet::from([Action::DelegateQuery]),
                            limits: Limits {
                                max_request_bytes: 16_384,
                                max_response_bytes: 65_536,
                                max_calls_per_invocation: 4,
                            },
                            budgets: Vec::new(),
                        },
                    )
                })
                .collect();
            let policy_id = format!(
                "imported_{}",
                &crate::digest(operation_name.as_bytes())[7..31]
            );
            catalog.policies.insert(
                policy_id.clone(),
                ReusablePolicy {
                    revision: 1,
                    owner: "local-fixture-operator".into(),
                    delegates: BTreeSet::new(),
                    actors: operation.actors.clone(),
                    allowed_apps: BTreeSet::from([app.into()]),
                    slots,
                    max_duration_seconds: None,
                },
            );
            attachments.push(Attachment {
                policy: VersionRef {
                    id: policy_id,
                    revision: 1,
                },
                operation: operation_name.clone(),
                bindings,
                actors: None,
                expires_at_ms: None,
            });
        }
    }
    // An exact disposable peer for the request-identity conformance query.
    // The native HTTP suite supplies a real callee and its actual schema pin.
    // Keep this outside local_resource_fixture: provider helpers also call that
    // function to initialize empty catalogs, which must remain empty.
    if artifact.contract().namespace == "delegation"
        && let Some(operation) = policy.operations.get("delegation.forward")
        && !operation.actors.is_empty()
        && operation.observations.contains("app.query.v1")
    {
        use serde_json::json;
        let peer: day2_capabilities::resources::Catalog = serde_json::from_value(json!({
            "version":1,
            "connections":{"delegation":{"revision":1,"provider":"local_delegation"}},
            "resources":{"delegation":{"revision":1,"connection":{"id":"delegation","revision":1},
                "target":{"kind":"app_operation","app":"fixture_peer","operation":"fixture.query",
                    "schema_digest":crate::digest(b"disposable-delegation-conformance-peer")}}},
            "policies":{"conformance_peer":{"revision":1,"owner":"local-fixture-operator",
                "actors":operation.actors,"allowed_apps":[app],
                "slots":{"delegation":{"kind":"app_operation","allowed_resources":[{"id":"delegation","revision":1}],
                    "actions":["delegate_query"],"limits":{"max_request_bytes":16384,"max_response_bytes":65536,"max_calls_per_invocation":4},"budgets":[]}}}},
            "budgets":{}
        }))?;
        catalog.connections.extend(peer.connections);
        catalog.resources.extend(peer.resources);
        catalog.policies.extend(peer.policies);
        attachments.push(serde_json::from_value(json!({
                    "policy":{"id":"conformance_peer","revision":1},"operation":"delegation.forward",
                    "bindings":{"delegation":{"id":"delegation","revision":1}}}))?);
    }
    catalog.validate()?;
    Ok((catalog, attachments))
}

#[cfg(test)]
mod people_resource_tests {
    use super::*;

    #[test]
    fn fixture_resolves_only_declared_people_actions_and_fixed_targets() -> Result<()> {
        use day2_capabilities::resources::{Action, ResourceTarget, TopicScope};
        let operation = |observations: &[&str], effects: &[&str]| OperationPolicy {
            actors: BTreeSet::from(["operator".into()]),
            mode: Mode::CurrentState,
            models: BTreeMap::new(),
            commands: BTreeSet::new(),
            observations: observations.iter().map(|name| (*name).into()).collect(),
            effects: effects.iter().map(|name| (*name).into()).collect(),
        };
        let policy = Policy {
            version: 1,
            admins: BTreeSet::new(),
            delegations: Default::default(),
            constraints: BTreeMap::new(),
            operations: BTreeMap::from([
                (
                    "people.directory".into(),
                    operation(
                        &["google_directory.snapshot.v1", "google_directory.record.v1"],
                        &[],
                    ),
                ),
                (
                    "people.onboard".into(),
                    operation(
                        &[],
                        &[
                            "google_directory.create_user.v1",
                            "linear.ensure_access.v1",
                            "operator_alerts.send.v1",
                        ],
                    ),
                ),
                ("people.local".into(), operation(&[], &[])),
            ]),
        };
        let (catalog, attachments) = people_resource_fixture("people", &policy)?;
        let resolved = catalog.resolve("people", &attachments, 1)?;
        assert_eq!(resolved.operations.len(), 2);
        assert_eq!(
            resolved.operations["people.directory"]["google_directory"].actions,
            BTreeSet::from([
                Action::GoogleDirectorySnapshot,
                Action::GoogleDirectoryRecord
            ])
        );
        assert_eq!(
            resolved.operations["people.onboard"]["google_directory"].actions,
            BTreeSet::from([Action::GoogleDirectoryCreateUser])
        );
        assert_eq!(
            resolved.operations["people.onboard"]["operator_alerts"].target,
            ResourceTarget::OperatorAlertDestination {
                destination: "synthetic-people-operator".into(),
                topics: TopicScope::Only {
                    topics: BTreeSet::from(["people_ops".into()])
                }
            }
        );
        assert!(catalog.resolve("different-app", &attachments, 1).is_err());
        Ok(())
    }
}

pub fn create_for(
    artifact_path: &Path,
    directory: &Path,
    policy: Option<Policy>,
    actor: &str,
) -> Result<Runtime> {
    create_for_with_imports(artifact_path, directory, policy, actor, &[])
}

fn create_for_with_imports(
    artifact_path: &Path,
    directory: &Path,
    policy: Option<Policy>,
    actor: &str,
    imports: &[ImportedQueryFixture],
) -> Result<Runtime> {
    use std::{io::Write, os::unix::fs::PermissionsExt};
    let artifact_path = artifact_path.canonicalize()?;
    let artifact = LoadedArtifact::load(&artifact_path)?;
    // Caller chooses a new directory: there is no implicit reset or policy rewrite.
    fs::create_dir(directory).context("local development requires a new output directory")?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let path = directory.join("instance.json");
    let mut instance = Instance {
        installation: "localdev".into(),
        environment: "disposable".into(),
        branding: None,
        control: None,
        resources: None,
        // Development signs in with the printed link, which an identity
        // declaration would refuse.
        identity: None,
        security_shell: None,
        apps: BTreeMap::from([(
            "app".into(),
            AppBinding {
                security: None,
                runtime: None,
                artifact: artifact_path
                    .to_str()
                    .context("artifact path UTF-8")?
                    .into(),
                readers: BTreeSet::from([actor.into()]),
                writers: BTreeSet::from([actor.into()]),
                authority: Some(policy.unwrap_or(local_policy_for(&artifact, actor)?)),
                resource_policies: Vec::new(),
                credential_families: Default::default(),
                oauth_connections: Default::default(),
                // Nothing is ever removed from a development instance either.
                // A retention policy is an operator's decision about real
                // records, and a default here would teach the opposite.
                retention: BTreeMap::new(),
                // Journal compaction follows the platform default.
                journal: None,
                edge: None,
                // A disposable development instance binds every declared schedule
                // to the development actor, so schedules are exercised here rather
                // than first discovered in an environment that matters.
                schedules: artifact
                    .contract()
                    .schedules
                    .iter()
                    .map(|schedule| {
                        (
                            schedule.name.clone(),
                            crate::artifact::ScheduleBinding {
                                actor: actor.into(),
                                disabled: false,
                            },
                        )
                    })
                    .collect(),
                // Local development binds no endpoints: a delivery needs a real
                // provider signature, which a disposable instance cannot supply.
                ingress: BTreeMap::new(),
            },
        )]),
    };
    let (resources, attachments) = resource_fixture_for_artifact_with_imports(
        "app",
        &artifact,
        instance.apps["app"]
            .authority
            .as_ref()
            .expect("explicit local policy"),
        imports,
    )?;
    instance.resources = Some(resources);
    // Static disposable pins for metadata verification, with no key provider
    // or lifecycle readiness. These never qualify production credential use.
    credential_metadata_fixture(&mut instance, &artifact)?;
    instance
        .apps
        .get_mut("app")
        .expect("local app")
        .resource_policies = attachments;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&serde_json::to_vec_pretty(&instance)?)?;
    file.sync_all()?;
    let runtime = Runtime::load(&path, "app")?;
    runtime.initialize()?;
    // A disposable instance serves live providers from their committed offline
    // worlds rather than from the network.
    //
    // Not a convenience. A development instance that could reach Slack or Linear
    // would post to a real channel and reassign a real issue the first time
    // someone exercised a command, and its verification would depend on a
    // workspace nobody controls. The simulation intercepts at the transport seam,
    // so the same adapter runs here as in the deployed instance — only the socket
    // differs. Synthetic providers are unaffected: they never reach this host.
    let database = runtime.db().to_path_buf();
    let scope = runtime.scope().to_owned();
    let mut worlds = disposable_provider_worlds();
    for import in imports {
        let key = crate::integrations::simulated::DelegationWorld::key(
            &import.app,
            &import.operation,
            &import.request,
        );
        ensure!(
            worlds
                .delegation
                .reads
                .insert(key, import.response.clone())
                .is_none(),
            "duplicate delegated read fixture"
        );
    }
    crate::integrations::simulated::seed(&database, &scope, &worlds)?;
    Ok(runtime.with_integrations(crate::integration_host::Host::simulated(&database, &scope)))
}

fn credential_metadata_fixture(instance: &mut Instance, artifact: &LoadedArtifact) -> Result<()> {
    use day2_capabilities::{
        BindingRef, Digest, Name,
        credentials::*,
        oauth::{ResourceAudienceRef, SecurityOriginRef},
    };
    let name = |value: &str| Name::try_from(value.to_owned());
    let pin = |value: &str| BindingRef::pin(name(value)?, &"disposable-metadata-only");
    for family in &artifact.contract().credential_manifest {
        let policy = ManagementPolicy {
            identity_authority: pin("disposable-identity")?,
            issue: ManagementPredicate::Creator,
            read_metadata: ManagementPredicate::Creator,
            rotate: ManagementPredicate::Creator,
            revoke: ManagementPredicate::Creator,
        };
        let binding = CredentialFamilyBinding {
            namespace: Namespace {
                installation: name(&instance.installation)?,
                environment: name(&instance.environment)?,
                app: name("app")?,
                binding_generation: 1,
            },
            family: family.id.clone(),
            approved_authority: BindingRef {
                id: family.id.clone(),
                revision: Digest::of(&("credential-approved-authority-v1", &family.roots))?,
            },
            management: BindingRef::pin(family.id.clone(), &policy)?,
            rotation: RotationProfile::AtomicReplace,
            delivery: DeliveryProfile::AuthenticatedCreatorReveal,
            verifier: pin("disposable-verifier")?,
            custody: pin("disposable-custody")?,
            security_shell: SecurityOriginRef(pin("disposable-security")?),
            audience: ResourceAudienceRef(pin("disposable-audience")?),
            epoch_store: pin("disposable-epoch")?,
            max_lifetime_seconds: family.lifetime_seconds,
            reveal_window_seconds: 300,
            quota: pin("disposable-quota")?,
        };
        let catalog = &mut instance
            .resources
            .as_mut()
            .context("disposable resource catalog")?
            .credentials;
        catalog.management.insert(family.id.as_str().into(), policy);
        catalog
            .approved_authority
            .insert(family.id.as_str().into(), family.roots.clone());
        instance
            .apps
            .get_mut("app")
            .context("disposable app")?
            .credential_families
            .insert(family.id.as_str().into(), binding);
    }
    Ok(())
}

/// The offline provider worlds a disposable instance starts with.
///
/// Deliberately small and obviously synthetic. It exists so that an application
/// exercising a live provider has something to read during development and
/// build-time verification; it is not a model of anyone's real workspace, and
/// nothing about a real one should ever be reproduced here.
///
/// The Linear issues are shaped to be *useful* to the thing reading them: one
/// with a due date and an owner, one with neither, so a compliance policy that
/// looks for missing owners and missing due dates has both cases present rather
/// than only the healthy one.
fn disposable_provider_worlds() -> crate::integrations::simulated::SimulatedFixture {
    use crate::integrations::simulated::*;
    let issue = |id: &str, identifier: &str, owner: &str, due: i64, view: &str| LinearIssue {
        id: id.into(),
        identifier: identifier.into(),
        title: format!("Synthetic {identifier}"),
        url: format!("https://linear.app/synthetic/issue/{identifier}"),
        due_date: if due < 0 {
            String::new()
        } else {
            "2026-01-31".into()
        },
        state_name: "In Progress".into(),
        state_type: "started".into(),
        assignee_id: if owner.is_empty() {
            String::new()
        } else {
            format!("member-{owner}")
        },
        assignee_name: owner.into(),
        created_at: "2026-01-05T20:00:00.000Z".into(),
        updated_at: "2026-01-10T20:00:00.000Z".into(),
        // The first issue carries the incident label as well as its view, so it
        // is reached by two sources and the collapse path is exercised rather
        // than assumed. An issue seen once by one source proves nothing about
        // deduplication.
        labels: if id == "linear-1" {
            vec!["Product Owners Standup".into(), "incident-follow-up".into()]
        } else {
            vec!["Product Owners Standup".into()]
        },
        view_ids: vec![view.into()],
    };
    SimulatedFixture {
        slack_webhook: crate::integrations::simulated::slack_webhook_fixture(),
        // Exact disposable peer, not a fallback for arbitrary delegated reads.
        // Native request-identity conformance installs and calls a real callee.
        delegation: DelegationWorld {
            reads: BTreeMap::from([(
                DelegationWorld::key("fixture_peer", "fixture.query", "{}"),
                "{}".into(),
            )]),
        },
        // One finished job and one still running, so a watcher has both the
        // case it closes and the case it leaves open.
        gitea_actions: crate::integrations::simulated::gitea_development_fixture(),
        github_actions: GitHubActionsWorld {
            owner: "synthetic-org".into(),
            repo: "synthetic-repo".into(),
            jobs: vec![
                GitHubJob {
                    id: "101".into(),
                    name: "build".into(),
                    status: "completed".into(),
                    conclusion: "success".into(),
                    started_at: "2026-01-02T11:00:00Z".into(),
                    completed_at: "2026-01-02T11:30:00Z".into(),
                    log_url: "https://pipelines.synthetic.example/logs/101".into(),
                },
                GitHubJob {
                    id: "102".into(),
                    name: "test".into(),
                    status: "in_progress".into(),
                    conclusion: String::new(),
                    started_at: "2026-01-02T11:05:00Z".into(),
                    completed_at: String::new(),
                    // A running job has no log to hand out yet.
                    log_url: String::new(),
                },
            ],
        },
        linear_work: LinearWorkWorld {
            team_name: "Synthetic".into(),
            issues: vec![
                issue("linear-1", "SYN-1", "ada", 1, "synthetic-view-standup"),
                // No owner and no due date: the shape the policies exist to find.
                issue("linear-2", "SYN-2", "", -1, "synthetic-view-standup"),
            ],
            members: vec![
                LinearMember {
                    id: "member-ada".into(),
                    name: "ada".into(),
                    email: "ada@synthetic.example".into(),
                },
                LinearMember {
                    id: "member-grace".into(),
                    name: "grace".into(),
                    email: "grace@synthetic.example".into(),
                },
            ],
        },
        object_store: ObjectStoreWorld::default(),
        slack: SlackWorld {
            workspace_id: "T0SYNTHETIC".into(),
            channels: BTreeMap::new(),
            sequence: 0,
        },
        snowflake: SnowflakeWorld {
            account: "synthetic-account".into(),
            views: BTreeMap::new(),
        },
        openai: OpenAiWorld {
            project_id: "proj_synthetic".into(),
            organization_id: None,
            model: "model-synthetic".into(),
            max_input_tokens: 100_000,
        },
    }
}

#[derive(Debug, Serialize)]
pub struct Evidence {
    pub format: u32,
    pub artifact: String,
    pub seed: String,
    pub requested_cases_per_generator: u64,
    pub examples: usize,
    pub generated: usize,
    pub checks: Vec<String>,
    pub traces: Vec<crate::protocol::Trace>,
    pub snapshot: Value,
    pub failure: Option<String>,
    pub obligations: BTreeMap<String, u64>,
    pub verification_complete: bool,
    pub error_traces: Vec<crate::protocol::Trace>,
}

/// In-memory capabilities for Check.roc. Native receipts cannot claim omitted
/// examples, generated cases, replay checks, or incomplete command/property checks.
pub struct Campaign {
    pub runtime: Runtime,
    pub evidence: Evidence,
    example: Option<String>,
    actor: String,
    include_examples: bool,
    catalog: Option<Vec<Example>>,
    selected: BTreeSet<String>,
    queue: std::collections::VecDeque<Step>,
    sampled: bool,
    empty_checked: bool,
    active: Option<Active>,
    complete: bool,
    obligations: std::collections::VecDeque<Sample>,
    prepared: bool,
    errors_checked: bool,
}

struct Active {
    step: Step,
    id: String,
    now: i64,
    outcome: crate::protocol::Outcome,
    before: Value,
    checks: BTreeSet<String>,
    initial: Value,
    obligation: bool,
}

impl Campaign {
    pub fn new(runtime: Runtime, example: Option<&str>, seed: u64, count: u64) -> Result<Self> {
        Self::for_actor(runtime, example, seed, count, "developer", true)
    }

    pub fn for_actor(
        runtime: Runtime,
        example: Option<&str>,
        seed: u64,
        count: u64,
        actor: &str,
        include_examples: bool,
    ) -> Result<Self> {
        ensure!(count <= 100, "generator count budget");
        // Campaigns explicitly provide shared synthetic capability worlds. This
        // setup never runs in ordinary Runtime loading or local web serving.
        crate::carta::seed_verification_if_unconfigured(&runtime)?;
        crate::people_providers::seed_verification_if_unconfigured(&runtime)?;
        Ok(Self {
            evidence: Evidence {
                format: 1,
                artifact: runtime.artifact().id().to_owned(),
                seed: seed.to_string(),
                requested_cases_per_generator: count,
                examples: 0,
                generated: 0,
                checks: Vec::new(),
                traces: Vec::new(),
                snapshot: json!({}),
                failure: None,
                obligations: BTreeMap::new(),
                verification_complete: false,
                error_traces: Vec::new(),
            },
            runtime,
            example: example.map(str::to_owned),
            actor: actor.into(),
            include_examples,
            catalog: None,
            selected: BTreeSet::new(),
            queue: std::collections::VecDeque::new(),
            sampled: false,
            empty_checked: false,
            active: None,
            complete: false,
            obligations: std::collections::VecDeque::new(),
            prepared: false,
            errors_checked: false,
        })
    }

    pub fn effect(&mut self, request: crate::automation::Request) -> Result<Value> {
        ensure!(!self.complete, "development campaign already complete");
        let parameters: Value = request.decode()?;
        if !["dev-example", "dev-invoke"].contains(&request.action.as_str()) {
            ensure!(
                parameters == json!({}),
                "development capability accepts no parameters"
            );
        }
        let evidence_dir = self
            .runtime
            .instance_path()
            .parent()
            .context("development directory")?
            .to_path_buf();
        match request.action.as_str() {
            "dev-properties" => {
                properties::require(
                    self.runtime.artifact(),
                    &self.runtime.inspect()?,
                    &evidence_dir,
                )?;
                if let Some(active) = self.active.as_mut() {
                    let phase = if active.checks.contains("drain") {
                        "properties-after"
                    } else {
                        "properties-before"
                    };
                    ensure!(
                        active.checks.insert(phase.into()),
                        "duplicate property phase"
                    );
                } else {
                    ensure!(
                        !self.empty_checked && self.evidence.traces.is_empty(),
                        "initial properties already checked"
                    );
                    self.empty_checked = true;
                    self.evidence.checks.push("empty-state-properties".into());
                }
            }
            "dev-examples" => {
                ensure!(self.catalog.is_none(), "example catalog already read");
                let catalog = if self.include_examples {
                    examples(self.runtime.artifact())?
                } else {
                    Vec::new()
                };
                // An artifact-owned example can exercise scheduled/private work
                // only with the offline provider host. This never changes the
                // public operation lookup used by HTTP, CLI or MCP.
                ensure!(
                    self.runtime.integrations().is_simulated()
                        || catalog
                            .iter()
                            .flat_map(|example| &example.steps)
                            .all(|step| {
                                !self
                                    .runtime
                                    .artifact()
                                    .contract()
                                    .internal_command(&step.operation)
                            }),
                    "internal_examples_require_simulated_providers"
                );
                let result = serde_json::to_value(&catalog)?;
                self.catalog = Some(catalog);
                return Ok(result);
            }
            "dev-example" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Selection {
                    name: String,
                }
                let selected: Selection = request.decode()?;
                ensure!(
                    self.queue.is_empty() && self.active.is_none(),
                    "previous example incomplete"
                );
                ensure!(
                    self.example
                        .as_ref()
                        .is_none_or(|name| *name == selected.name),
                    "example outside requested selection"
                );
                let example = self
                    .catalog
                    .as_ref()
                    .context("example catalog required")?
                    .iter()
                    .find(|example| example.name == selected.name)
                    .context("unknown example")?;
                ensure!(
                    self.selected.insert(selected.name),
                    "duplicate selected example"
                );
                self.queue.extend(example.steps.iter().cloned());
                self.evidence.examples += 1;
            }
            "dev-samples" => {
                ensure!(
                    !self.sampled && self.queue.is_empty() && self.active.is_none(),
                    "generated campaign already started or example incomplete"
                );
                let values = samples(
                    self.runtime.artifact(),
                    self.evidence.seed.parse()?,
                    self.evidence.requested_cases_per_generator,
                )?;
                ensure!(
                    self.evidence.traces.len() + values.len() <= MAX_STEPS,
                    "development campaign step budget"
                );
                self.queue.extend(values.iter().map(|sample| Step {
                    operation: sample.operation.clone(),
                    input: sample.input.clone(),
                }));
                self.sampled = true;
                if self.runtime.artifact().contract().app_contract.is_some() {
                    self.obligations.extend(values.iter().cloned());
                }
                self.evidence.generated = values.len();
                return Ok(serde_json::to_value(values)?);
            }
            "dev-prepare-sample" => {
                ensure!(
                    self.active.is_none() && !self.prepared,
                    "sample already prepared"
                );
                let step = self
                    .queue
                    .front_mut()
                    .context("missing verification sample")?;
                if let Some(sample) = self.obligations.front() {
                    ensure!(
                        step.operation == sample.operation && step.input.is_empty(),
                        "verification schedule mismatch"
                    );
                    step.input = verification(
                        self.runtime.artifact(),
                        "input",
                        &sample.operation,
                        &self.runtime.inspect()?,
                        &json!({}),
                        &Value::Null,
                        sample.seed.parse()?,
                    )?;
                }
                self.prepared = true;
                return Ok(serde_json::to_value(step)?);
            }
            "dev-invoke" => {
                ensure!(
                    self.empty_checked && self.active.is_none(),
                    "properties or previous step incomplete"
                );
                ensure!(
                    self.evidence.traces.len() < MAX_STEPS,
                    "development campaign step budget"
                );
                let step: Step = request.decode()?;
                let expected = self
                    .queue
                    .pop_front()
                    .context("command outside selected examples/generators")?;
                ensure!(
                    step.operation == expected.operation && step.input == expected.input,
                    "command differs from selected case"
                );
                let obligation = self.prepared && self.obligations.pop_front().is_some();
                if !obligation {
                    validate_step(self.runtime.artifact(), &step)?;
                }
                let index = self.evidence.traces.len();
                let id = format!("example-{index}");
                let now = 1_700_000_000 + index as i64;
                let input: Value = serde_json::from_str(&step.input)?;
                let initial = self.runtime.inspect()?;
                self.prepared = false;
                // Internal definitions also have mandatory app-owned verification.
                // Only this artifact-bound campaign can admit those generated samples.
                let internal_example = !obligation
                    && self
                        .runtime
                        .artifact()
                        .contract()
                        .internal_command(&step.operation);
                ensure!(
                    !internal_example || self.runtime.integrations().is_simulated(),
                    "internal_examples_require_simulated_providers"
                );
                if obligation || internal_example {
                    self.runtime.accept_route(
                        &step.operation,
                        &self.actor,
                        &id,
                        &input,
                        now,
                        crate::audit::Trigger::Request,
                    )?;
                } else {
                    self.runtime
                        .accept(&step.operation, &self.actor, &id, &input, now)?;
                }
                let mut outcome = self.runtime.execute(&id, Fault::None)?;
                for _ in 0..32 {
                    if outcome.status != "pending" {
                        break;
                    }
                    outcome = self.runtime.execute(&id, Fault::None)?;
                }
                self.evidence.traces.push(self.runtime.trace(&id)?);
                ensure!(
                    outcome.status == "success",
                    "example command {} rejected: {}",
                    step.operation,
                    outcome.error
                );
                self.active = Some(Active {
                    step,
                    id,
                    now,
                    outcome,
                    before: self.runtime.inspect()?,
                    checks: BTreeSet::new(),
                    initial,
                    obligation,
                });
            }
            "dev-assert" => {
                let active = self.active.as_mut().context("active operation required")?;
                if active.obligation {
                    verification(
                        self.runtime.artifact(),
                        "check",
                        &active.step.operation,
                        &active.before,
                        &active.initial,
                        &active.outcome.result,
                        0,
                    )?;
                    *self
                        .evidence
                        .obligations
                        .entry(active.step.operation.clone())
                        .or_default() += 1;
                }
                ensure!(
                    active.checks.insert("assert".into()),
                    "duplicate operation assertion"
                );
            }
            "dev-errors" => {
                ensure!(
                    self.active.is_none() && self.queue.is_empty() && !self.errors_checked,
                    "error verification phase order"
                );
                if let Some(definition) = &self.runtime.artifact().contract().app_contract {
                    for (code, error) in &definition.errors {
                        for target in error.targets() {
                            let verification_key = error.verification_key(target);
                            for index in 0..self.evidence.requested_cases_per_generator {
                                let before = self.runtime.inspect()?;
                                let input = verification(
                                    self.runtime.artifact(),
                                    "error-input",
                                    &verification_key,
                                    &before,
                                    &json!({}),
                                    &Value::Null,
                                    self.evidence.seed.parse::<u64>()?.wrapping_add(index),
                                )?;
                                let input: Value = serde_json::from_str(&input)?;
                                let id = format!("failure-{}", self.evidence.error_traces.len());
                                // These typed, admitted cases have the same access
                                // to internal workers as ordinary generated checks.
                                self.runtime.accept_route(
                                    &target.operation,
                                    &self.actor,
                                    &id,
                                    &input,
                                    1_700_100_000 + index as i64,
                                    crate::audit::Trigger::Request,
                                )?;
                                // A business-error witness must reject before
                                // provider dispatch; do not advance a pending
                                // effects phase merely to obtain a later error.
                                let outcome = self.runtime.execute(&id, Fault::None)?;
                                let trace = self.runtime.trace(&id)?;
                                self.evidence.error_traces.push(trace.clone());
                                ensure!(
                                    outcome.status == "failure"
                                        && &outcome.error == code
                                        && self.runtime.inspect()? == before
                                        && trace
                                            .request
                                            .observations
                                            .iter()
                                            .all(|observation| observation.instruction.kind
                                                != "external"),
                                    "required application failure scenario did not reject atomically: {verification_key}"
                                );
                                crate::store::replay(self.runtime.artifact(), &trace)?;
                                self.runtime.accept_route(
                                    &target.operation,
                                    &self.actor,
                                    &id,
                                    &input,
                                    1_700_100_000 + index as i64,
                                    crate::audit::Trigger::Request,
                                )?;
                                ensure!(
                                    self.runtime.execute(&id, Fault::None)? == outcome
                                        && self.runtime.inspect()? == before,
                                    "application failure retry changed outcome or state"
                                );
                                properties::require(
                                    self.runtime.artifact(),
                                    &before,
                                    &evidence_dir,
                                )?;
                                *self
                                    .evidence
                                    .obligations
                                    .entry(format!("error:{verification_key}"))
                                    .or_default() += 1;
                            }
                        }
                    }
                }
                self.errors_checked = true;
            }
            "dev-replay" => {
                let active = self.active.as_mut().context("active command required")?;
                crate::store::replay(
                    self.runtime.artifact(),
                    self.evidence.traces.last().context("command trace")?,
                )?;
                ensure!(
                    active.checks.insert("replay".into()),
                    "duplicate replay check"
                );
            }
            "dev-duplicate" => {
                let active = self.active.as_mut().context("active command required")?;
                let duplicate = if self
                    .runtime
                    .artifact()
                    .contract()
                    .internal_command(&active.step.operation)
                {
                    self.runtime.accept_route(
                        &active.step.operation,
                        &self.actor,
                        &active.id,
                        &serde_json::from_str(&active.step.input)?,
                        active.now,
                        crate::audit::Trigger::Request,
                    )?;
                    self.runtime.execute(&active.id, Fault::None)?
                } else {
                    self.runtime.invoke(
                        &active.step.operation,
                        &self.actor,
                        &active.id,
                        &serde_json::from_str(&active.step.input)?,
                        active.now,
                        Fault::None,
                    )?
                };
                ensure!(
                    active.outcome == duplicate && active.before == self.runtime.inspect()?,
                    "duplicate command changed state or outcome"
                );
                ensure!(
                    active.checks.insert("duplicate".into()),
                    "duplicate duplicate-delivery check"
                );
            }
            "dev-invalid" => {
                let active = self.active.as_mut().context("active command required")?;
                let mut malformed: Value = serde_json::from_str(&active.step.input)?;
                malformed
                    .as_object_mut()
                    .context("command input record")?
                    .insert("$unexpected".into(), Value::Bool(true));
                let rejected = self.runtime.accept_route(
                    &active.step.operation,
                    &self.actor,
                    &format!("invalid-{}", self.evidence.traces.len() - 1),
                    &malformed,
                    active.now,
                    crate::audit::Trigger::Request,
                );
                ensure!(
                    rejected
                        .as_ref()
                        .is_err_and(|error| error.to_string() == "missing or unknown fields"),
                    "malformed input did not fail schema admission"
                );
                ensure!(
                    active.before == self.runtime.inspect()?,
                    "rejected input changed app state"
                );
                ensure!(
                    active.checks.insert("invalid".into()),
                    "duplicate malformed-input check"
                );
            }
            "dev-drain" => {
                let active = self.active.as_mut().context("active command required")?;
                ensure!(
                    active.checks.contains("properties-before"),
                    "pre-completion properties required"
                );
                let commands = crate::invocations::drain(&self.runtime, 256)?;
                if let Some(failed) = commands.iter().find(|command| command.status != "success") {
                    // Name the command and its error: "did not succeed" alone
                    // sends the author back to the whole application.
                    bail!(
                        "development command did not succeed: {} returned {} ({})",
                        failed.operation,
                        failed.status,
                        failed.error
                    );
                }
                ensure!(
                    active.checks.insert("drain".into()),
                    "commands already drained"
                );
            }
            "dev-step-complete" => {
                let active = self.active.as_ref().context("active command required")?;
                ensure!(
                    [
                        "replay",
                        "duplicate",
                        "invalid",
                        "properties-before",
                        "drain",
                        "properties-after",
                        "assert"
                    ]
                    .iter()
                    .all(|check| active.checks.contains(*check)),
                    "incomplete command verification"
                );
                self.active = None;
            }
            "dev-finish" => {
                ensure!(
                    self.empty_checked && self.active.is_none() && self.queue.is_empty(),
                    "incomplete development campaign"
                );
                let catalog = self.catalog.as_ref().context("example catalog required")?;
                let expected: BTreeSet<_> = catalog
                    .iter()
                    .filter(|entry| self.example.as_ref().is_none_or(|name| *name == entry.name))
                    .map(|entry| entry.name.clone())
                    .collect();
                ensure!(
                    self.selected == expected && (self.example.is_none() || !expected.is_empty()),
                    "example selection incomplete"
                );
                ensure!(
                    self.sampled == (self.evidence.requested_cases_per_generator > 0),
                    "generated campaign incomplete"
                );
                if let Some(definition) = &self.runtime.artifact().contract().app_contract {
                    ensure!(
                        self.errors_checked && self.obligations.is_empty(),
                        "required verification omitted"
                    );
                    if self.evidence.requested_cases_per_generator > 0 {
                        let expected: BTreeMap<_, _> = definition
                            .operations
                            .keys()
                            .cloned()
                            .chain(definition.errors.values().flat_map(|error| {
                                error.targets().map(|target| {
                                    format!("error:{}", error.verification_key(target))
                                })
                            }))
                            .map(|name| (name, self.evidence.requested_cases_per_generator))
                            .collect();
                        ensure!(
                            self.evidence.obligations == expected,
                            "verification obligations incomplete"
                        );
                        self.evidence.verification_complete = true;
                    }
                }
                self.evidence.snapshot = self.runtime.inspect()?;
                if !self.evidence.traces.is_empty() {
                    self.evidence.checks.extend(
                        [
                            "command-trace-replay",
                            "duplicate-delivery",
                            "schema-invalid-input-rejection",
                            "properties-after-each-command-and-completion",
                        ]
                        .map(str::to_owned),
                    );
                }
                self.complete = true;
                self.persist(None)?;
                return Ok(
                    json!({"artifact":self.evidence.artifact,"seed":self.evidence.seed,"examples":self.evidence.examples,"generated":self.evidence.generated,"checks":self.evidence.checks,"evidence":evidence_dir.join("development.json"),"instance":self.runtime.instance_path()}),
                );
            }
            _ => anyhow::bail!("unknown development capability: {}", request.action),
        }
        Ok(json!({}))
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn persist(&mut self, failure: Option<String>) -> Result<()> {
        if failure.is_some() {
            self.evidence.failure = failure;
        }
        fs::write(
            self.runtime
                .instance_path()
                .parent()
                .context("development directory")?
                .join("development.json"),
            serde_json::to_vec_pretty(&self.evidence)?,
        )?;
        Ok(())
    }
}

/// Compatibility API for native conformance callers. The same Roc campaign used
/// by CLI and CI decides every example, generated case and verification phase.
pub fn exercise(
    runtime: &Runtime,
    example_name: Option<&str>,
    seed: u64,
    count: u64,
) -> Result<Evidence> {
    let mut campaign = Campaign::new(runtime.clone(), example_name, seed, count)?;
    let outcome = crate::automation::run(
        &crate::automation::runner()?,
        &["exercise", example_name.unwrap_or(""), &count.to_string()],
        |request| campaign.effect(request),
    );
    campaign.persist(outcome.as_ref().err().map(|error| format!("{error:#}")))?;
    outcome?;
    ensure!(campaign.complete, "workflow omitted campaign completion");
    Ok(campaign.evidence)
}

pub fn verify(artifact: &Path, directory: &Path, seed: u64, count: u64) -> Result<Evidence> {
    verify_with_runner(
        artifact,
        directory,
        seed,
        count,
        &crate::automation::runner()?,
    )
}

pub fn verify_with_runner(
    artifact: &Path,
    directory: &Path,
    seed: u64,
    count: u64,
    runner: &Path,
) -> Result<Evidence> {
    verify_with_runner_imports(artifact, directory, seed, count, runner, &[])
}

pub fn verify_with_runner_imports(
    artifact: &Path,
    directory: &Path,
    seed: u64,
    count: u64,
    runner: &Path,
    imports: &[ImportedQueryFixture],
) -> Result<Evidence> {
    ensure!(
        (1..=100).contains(&count),
        "verification requires positive bounded cases"
    );
    let mut campaign = Campaign::new(
        create_for_with_imports(artifact, directory, None, ACTOR, imports)?,
        None,
        seed,
        count,
    )?;
    let outcome =
        crate::automation::run(runner, &["exercise", "", &count.to_string()], |request| {
            campaign.effect(request)
        });
    campaign.persist(outcome.as_ref().err().map(|error| format!("{error:#}")))?;
    outcome?;
    ensure!(
        campaign.complete && campaign.evidence.verification_complete,
        "workflow omitted required verification"
    );
    Ok(campaign.evidence)
}
