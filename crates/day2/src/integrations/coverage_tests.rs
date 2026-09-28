//! The coverage gate: proves a declared simulation is *real*, not merely present.
//!
//! The mandate in `crate::simulations` guarantees a provider **declares** a
//! world and **binds** it. It cannot guarantee anything **serves** that world —
//! a provider declaring `world: "stripe.simulated.sqlite"` with nothing behind
//! it compiles and passes both const assertions, because they prove a name
//! exists. This module closes that hole behaviourally:
//!
//! > Every declared action, invoked in the offline lane, produces a result that
//! > depends on the contents of the world **its own provider** declares.
//!
//! Mechanically: seed two worlds that differ, invoke the same action against
//! each, require the results to differ. One property catches three distinct
//! failures that the type system cannot see:
//!
//! - **Nothing serves the world.** Neither invocation reflects any world, so the
//!   two results do not differ and the gate fails on that provider's first action.
//! - **The simulation returns a constant.** Same outcome: the result does not
//!   move when the world does.
//! - **The action is served out of another provider's world.** Changing *its
//!   own* declared world leaves the result unmoved, so the gate fails. This is
//!   the case a coverage *count* cannot see: counting proves the action ran,
//!   never that it ran against the right state. Attribution is the difference.
//!
//! Phrased as "depends on the contents" rather than "changed the world" because
//! the read actions — `slack.read`, `snowflake.read` — write nothing. It is also
//! strictly stronger than "did not error": an action that errors identically
//! against two different worlds has not demonstrated a world at all.
//!
//! Scope, stated rather than implied: this covers the three providers simulated
//! at the *transport* seam. The five synthetic providers are served at the
//! *adapter* seam and need the instance/policy harness to invoke; they are not
//! yet covered here. `every_provider_is_covered_or_declared_pending` fails if a
//! provider is neither covered nor on the explicit pending list, so the gap is
//! visible and shrinking rather than silent.

use super::*;
use crate::integrations::simulated::{
    GitHubActionsWorld, GitHubJob, LinearIssue, LinearMember, LinearWorkWorld, ObjectStoreWorld,
    OpenAiWorld, SimulatedCredentials, SimulatedFixture, SimulatedTransport, SlackChannelWorld,
    SlackMessage, SlackWorld, SnowflakeViewWorld, SnowflakeWorld, StoredObject, seed,
};
use anyhow::{Context, Result};
use day2_capabilities::{
    integrations::{LiveConnection, OpenAiText, SlackChannel, SnowflakeScalarType, SnowflakeView},
    resources::{Action, Provider, ResourceTarget, VersionRef},
};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SCOPE: &str = "coverage/app";

/// How an action demonstrates that its declared world is real.
///
/// This is declared per action rather than derived from `Action::is_write()`,
/// because those are different properties and conflating them is a trap this
/// gate walked into. `is_write()` answers *does this need effect admission and a
/// write budget* — the registry says so explicitly, because a miscategorised
/// write is admitted without one. It does **not** answer *does this mutate
/// provider state*. `openai.generate.v1` is a write by the first definition and
/// not by the second: it is billable, and it is stateless (`store:false`). A
/// gate keyed off `is_write()` demands that generation leave a trace in a world,
/// which is untrue of the provider being simulated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Demonstration {
    /// The returned result differs when the world differs.
    ResultReflectsWorld,
    /// The effect lands in the provider's own world, and in no other.
    EffectLandsInWorld,
    /// Served at the adapter seam, which this gate cannot yet drive — those
    /// providers need the instance/policy harness. Visible and shrinking rather
    /// than silent: the match below is exhaustive, so a new action must say
    /// which of these it is before it compiles.
    PendingAdapterSeam,
    /// The action makes no provider call: it computes an authorization locally
    /// from the credential and the clock, so there is no world to reflect and no
    /// effect to land. A presigned URL is the case.
    ///
    /// Correctness of the signature is established by a vendor-published vector
    /// (`object_store::tests`), which is a stronger base than anything this gate
    /// could generate.
    ///
    /// What this arm checks is *scope*: that the grant refuses to authorize an
    /// object it does not cover. That is the one property a signing vector cannot
    /// establish — a correct signature over the wrong object is still wrong, and
    /// a presigned URL cannot be recalled once handed to a client.
    LocalAuthorization,
}

fn demonstration(action: Action) -> Demonstration {
    match action {
        Action::SlackRead | Action::SnowflakeRead => Demonstration::ResultReflectsWorld,
        Action::SlackPost | Action::SlackWebhookPost => Demonstration::EffectLandsInWorld,
        // Head reads the object record; a grant refuses a key the world does not
        // hold, so both depend on the world's contents rather than only on config.
        // Both grants are pure: a signature over the credential, key and clock,
        // with no request to the store at all.
        Action::ObjectStoreGrantUpload | Action::ObjectStoreGrantDownload => {
            Demonstration::LocalAuthorization
        }
        // These two do reach the store, so they are held to the stronger standard:
        // the answer has to move with the world's contents, and the deletion has to
        // be visible in the world afterwards.
        Action::ObjectStoreHead => Demonstration::ResultReflectsWorld,
        Action::ObjectStoreDelete => Demonstration::EffectLandsInWorld,
        // Three reads whose answers are the workspace's contents, and one write
        // that moves ownership of an issue and must be visible afterwards.
        Action::LinearWorkIssues
        | Action::LinearWorkIssueDetail
        | Action::LinearWorkAssignableUsers => Demonstration::ResultReflectsWorld,
        // Both are reads whose answers are the repository's contents: a job's
        // conclusion, and where its log lives.
        Action::GitHubJob | Action::GitHubJobLog => Demonstration::ResultReflectsWorld,
        Action::GiteaRuns | Action::GiteaRun | Action::GiteaRunJobs | Action::GiteaJob | Action::GiteaJobLog | Action::GiteaRunners => Demonstration::ResultReflectsWorld,
        Action::LinearWorkReassign => Demonstration::EffectLandsInWorld,
        // Billable but stateless: its dependence on the world is visible in the
        // usage the simulated account reports, not in a record it leaves behind.
        Action::OpenAiGenerate => Demonstration::ResultReflectsWorld,
        Action::NotificationsResolve
        | Action::NotificationsLatest
        | Action::NotificationsSend
        | Action::CartaSnapshot
        | Action::CartaRecord
        | Action::GoogleDirectorySnapshot
        | Action::GoogleDirectoryRecord
        | Action::GoogleDirectoryCreateUser
        | Action::GoogleDirectoryPatchAttributes
        | Action::GoogleDirectoryEnsureGroupMember
        | Action::LinearEnsureAccess
        | Action::LinearSuspend
        | Action::OperatorAlertsSend
        // A delegated read is answered by the callee application, not by a
        // transport this gate can drive: there is no socket to seed two worlds
        // behind. Pending here rather than silently absent, and it shrinks when
        // the delegation harness can stand up a second application.
        | Action::DelegateQuery => Demonstration::PendingAdapterSeam,
    }
}

/// Which of two distinguishable worlds to seed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Variant {
    A,
    B,
}

/// Two worlds that differ only in the provider under test, so a result that
/// moves between them moved because *that* provider's world moved.
fn fixture(variant: Variant) -> SimulatedFixture {
    let (text, row, model_seed, input_ceiling) = match variant {
        Variant::A => ("alpha message", "ada", "alpha", 100_000),
        Variant::B => ("beta message", "grace", "beta", 2),
    };
    let (object_size, object_etag) = match variant {
        Variant::A => (11, "etag-alpha"),
        Variant::B => (22, "etag-beta"),
    };
    let (owner, owner_name, issue_title) = match variant {
        Variant::A => ("member-ada", "Ada", "alpha issue"),
        Variant::B => ("member-grace", "Grace", "beta issue"),
    };
    let (conclusion, log) = match variant {
        Variant::A => ("success", "https://pipelines.example/logs/alpha"),
        Variant::B => ("failure", "https://pipelines.example/logs/beta"),
    };
    SimulatedFixture {
        slack_webhook: crate::integrations::simulated::slack_webhook_fixture(),
        delegation: Default::default(),
        // The job's conclusion and its log location differ between the worlds,
        // so neither read can answer from anywhere but the world it was given.
        gitea_actions: super::simulated::gitea_actions_fixture(
            "coverage-org",
            "coverage-repo",
            conclusion,
        ),
        github_actions: GitHubActionsWorld {
            owner: "coverage-org".into(),
            repo: "coverage-repo".into(),
            jobs: vec![GitHubJob {
                id: "7".into(),
                name: "build".into(),
                status: "completed".into(),
                conclusion: conclusion.into(),
                started_at: "2026-01-02T11:00:00Z".into(),
                completed_at: "2026-01-02T11:30:00Z".into(),
                log_url: log.into(),
            }],
        },
        // The tracked issue differs between the worlds in both its title and its
        // owner, so a read whose answer did not come from the world cannot
        // produce different ones — and a reassignment has somewhere to land.
        linear_work: LinearWorkWorld {
            team_name: "Core".into(),
            issues: vec![LinearIssue {
                id: "issue-1".into(),
                identifier: "ENG-1".into(),
                title: issue_title.into(),
                url: "https://linear.app/exampleco/issue/ENG-1".into(),
                due_date: String::new(),
                state_name: "In Progress".into(),
                state_type: "started".into(),
                assignee_id: owner.into(),
                assignee_name: owner_name.into(),
                created_at: "2026-09-01T00:00:00.000Z".into(),
                updated_at: "2026-09-10T00:00:00.000Z".into(),
                labels: vec!["incident-follow-up".into()],
                view_ids: vec!["view-standup".into()],
            }],
            members: vec![
                LinearMember {
                    id: "member-ada".into(),
                    name: "Ada".into(),
                    email: "ada@example.test".into(),
                },
                LinearMember {
                    id: "member-grace".into(),
                    name: "Grace".into(),
                    email: "grace@example.test".into(),
                },
            ],
        },
        // The object under test differs between the two worlds, so a HEAD whose
        // answer did not come from the world cannot produce different sizes.
        object_store: ObjectStoreWorld {
            bucket: "coverage-bucket".into(),
            objects: BTreeMap::from([(
                "reports/coverage.txt".into(),
                StoredObject {
                    size: object_size,
                    etag: object_etag.into(),
                    content_type: String::new(),
                },
            )]),
        },
        slack: SlackWorld {
            workspace_id: "T123".into(),
            channels: BTreeMap::from([(
                "C123".into(),
                SlackChannelWorld {
                    messages: vec![SlackMessage {
                        text: text.into(),
                        timestamp: "1700000001.000000".into(),
                    }],
                    archived: false,
                },
            )]),
            sequence: 0,
        },
        snowflake: SnowflakeWorld {
            account: "org-account".into(),
            views: BTreeMap::from([(
                "APP_DB.PUBLIC.APP_VIEW".into(),
                SnowflakeViewWorld {
                    columns: vec!["NAME".into(), "TEAM".into()],
                    rows: vec![vec![Some(row.into()), Some("core".into())]],
                },
            )]),
        },
        openai: OpenAiWorld {
            project_id: "proj_test".into(),
            organization_id: None,
            // The model name is part of the world, so a generation served from
            // a different account's world is visible in the result.
            model: format!("model-{model_seed}"),
            // The ceiling the simulated account reports usage against. Varying
            // it makes a generation's reported input_tokens move with the world.
            max_input_tokens: input_ceiling,
        },
    }
}

fn reference() -> VersionRef {
    VersionRef {
        id: "coverage".into(),
        revision: 1,
    }
}

/// The connection and target for an action, plus the app input that invokes it.
fn invocation(action: Action, variant: Variant) -> (LiveConnection, ResourceTarget, Value) {
    match action {
        Action::SlackWebhookPost => (
            LiveConnection::SlackWebhook {
                credential_ref: reference(),
            },
            ResourceTarget::SlackWebhookDestination {
                endpoint_sha256: super::simulated::slack_webhook_digest(),
            },
            json!({"handle":"opaque","text":"posted by the coverage gate"}),
        ),
        Action::SlackRead | Action::SlackPost => (
            LiveConnection::Slack {
                credential_ref: reference(),
                signing_secret_ref: None,
                workspace_id: "T123".into(),
            },
            ResourceTarget::SlackChannel {
                channel: SlackChannel {
                    channel_id: "C123".into(),
                },
            },
            if action == Action::SlackRead {
                json!({"handle":"opaque","limit":10})
            } else {
                json!({"handle":"opaque","text":"posted by the coverage gate"})
            },
        ),
        Action::SnowflakeRead => (
            LiveConnection::Snowflake {
                credential_ref: reference(),
                account: "org-account".into(),
                role: "READER".into(),
                warehouse: "WH".into(),
            },
            ResourceTarget::SnowflakeView {
                query: SnowflakeView {
                    database: "APP_DB".into(),
                    schema: "PUBLIC".into(),
                    view: "APP_VIEW".into(),
                    columns: vec!["NAME".into()],
                    filters: BTreeMap::from([("TEAM".into(), SnowflakeScalarType::Text)]),
                    max_rows: 10,
                },
            },
            json!({"handle":"opaque","parameters":[{"name":"TEAM","kind":"text","value":"core"}]}),
        ),
        Action::OpenAiGenerate => (
            LiveConnection::OpenAi {
                credential_ref: reference(),
                project_id: "proj_test".into(),
                organization_id: None,
            },
            ResourceTarget::OpenAiText {
                profile: OpenAiText {
                    // Matches the world's model for this variant, so the profile
                    // and the simulated account agree in both runs.
                    model: format!(
                        "model-{}",
                        if variant == Variant::A {
                            "alpha"
                        } else {
                            "beta"
                        }
                    ),
                    max_input_bytes: 2048,
                    max_input_tokens: 100_000,
                    max_output_tokens: 1000,
                    input_nanos_per_token: 1250,
                    output_nanos_per_token: 10_000,
                },
            },
            json!({"handle":"opaque","text":"generate for the coverage gate","max_output_tokens":64}),
        ),
        Action::GiteaRuns
        | Action::GiteaRun
        | Action::GiteaRunJobs
        | Action::GiteaJob
        | Action::GiteaJobLog
        | Action::GiteaRunners => (
            LiveConnection::GiteaActions {
                signing_secret_ref: None,
                credential_ref: reference(),
                endpoint: "https://git.example.test".into(),
            },
            ResourceTarget::GiteaOrganization {
                owner: "coverage-org".into(),
            },
            if matches!(action, Action::GiteaRuns | Action::GiteaRunners) {
                json!({"handle":"opaque"})
            } else {
                json!({"handle":"opaque","repo":"coverage-repo","id":7})
            },
        ),
        Action::GitHubJob | Action::GitHubJobLog => (
            LiveConnection::GitHubActions {
                credential_ref: reference(),
                endpoint: "https://api.github.test".into(),
            },
            ResourceTarget::GitHubRepository {
                owner: "coverage-org".into(),
                repo: "coverage-repo".into(),
            },
            json!({"handle":"opaque","job_id":"7"}),
        ),
        Action::LinearWorkIssues
        | Action::LinearWorkIssueDetail
        | Action::LinearWorkAssignableUsers
        | Action::LinearWorkReassign => (
            LiveConnection::LinearWork {
                credential_ref: reference(),
                organization_id: "org-coverage".into(),
            },
            ResourceTarget::LinearIssueSource {
                source: day2_capabilities::integrations::LinearWorkSource::CustomView {
                    view_id: "view-standup".into(),
                    name: "Product Owners Standup".into(),
                    url: "https://linear.app/exampleco/view/view-standup".into(),
                },
            },
            match action {
                Action::LinearWorkIssues => json!({"handle":"opaque","after":""}),
                Action::LinearWorkReassign => json!({
                    "handle":"opaque","issue_id":"issue-1",
                    // Reassign to the *other* world's owner, so the effect is a
                    // real change in both variants rather than a no-op in one.
                    "assignee_id": if variant == Variant::A {
                        "member-grace"
                    } else {
                        "member-ada"
                    },
                }),
                _ => json!({"handle":"opaque","issue_id":"issue-1"}),
            },
        ),
        Action::ObjectStoreHead | Action::ObjectStoreDelete => (
            LiveConnection::ObjectStore {
                credential_ref: reference(),
                endpoint: "https://s3.example.com".into(),
                region: "us-east-1".into(),
                bucket: "coverage-bucket".into(),
                access_key_id: "AKIACOVERAGE".into(),
            },
            ResourceTarget::ObjectBucket {
                bucket: "coverage-bucket".into(),
                key_prefix: "reports/".into(),
            },
            json!({"handle":"opaque","key":"reports/coverage.txt"}),
        ),
        other => panic!("action {other:?} is not served at the transport seam"),
    }
}

/// The committed *provider state* of every world beside `database`, keyed by
/// world file.
///
/// Two deliberate narrowings. It reads the stored row rather than hashing the
/// file, so incidental SQLite journal churn is not mistaken for an effect. And
/// it projects the `world` field alone, dropping the simulation's own
/// bookkeeping — `calls` and `faults` — because those move on every request
/// including reads. A read that appends to the call log has not changed the
/// provider; conflating the two would make every read look like a write.
fn worlds(database: &std::path::Path) -> Result<BTreeMap<&'static str, Option<String>>> {
    let mut state = BTreeMap::new();
    for provider in Provider::ALL {
        let world = provider.world().expect("every provider declares a world");
        let path = database.with_file_name(world);
        let stored = if path.is_file() {
            let connection = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let stored: Option<String> = connection
                .query_row(
                    "SELECT state FROM simulated_provider WHERE scope=?1",
                    [SCOPE],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            stored
                .map(|state| -> Result<String> {
                    let value: serde_json::Value = serde_json::from_str(&state)?;
                    Ok(value
                        .get("world")
                        .context("simulated world state missing its provider field")?
                        .to_string())
                })
                .transpose()?
        } else {
            None
        };
        state.insert(world, stored);
    }
    Ok(state)
}

struct Observed {
    result: String,
    before: BTreeMap<&'static str, Option<String>>,
    after: BTreeMap<&'static str, Option<String>>,
}

impl Observed {
    /// World files whose committed state the invocation changed.
    fn changed(&self) -> Vec<&'static str> {
        self.before
            .iter()
            .filter(|(world, prior)| self.after.get(*world) != Some(prior))
            .map(|(world, _)| *world)
            .collect()
    }
}

/// Invoke one action against one seeded world, through the real adapter, and
/// capture both what it returned and what it changed.
fn observe(action: Action, variant: Variant) -> Result<Observed> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("app.sqlite");
    seed(&database, SCOPE, &fixture(variant))?;
    let (connection, target, input) = invocation(action, variant);
    // An object request is signed where the grant's scope check happens rather
    // than built by `prepare`, because signing needs the secret. Driving it the
    // way production does — presign, then call — is what keeps this a measurement
    // of the adapter instead of of a parallel path invented for the test.
    let call = if let Action::ObjectStoreHead | Action::ObjectStoreDelete = action {
        let operation = if action == Action::ObjectStoreHead {
            super::ObjectOperation::Head
        } else {
            super::ObjectOperation::Delete
        };
        let method = if action == Action::ObjectStoreHead {
            "HEAD"
        } else {
            "DELETE"
        };
        let key = input["key"]
            .as_str()
            .context("the invocation names a key")?;
        let url = super::presign(
            "AKIACOVERAGE",
            "coverage-secret",
            "us-east-1",
            method,
            "https://s3.example.com",
            "coverage-bucket",
            key,
            1_700_000_000,
        )
        .map_err(|error| anyhow::anyhow!("presign failed for {action:?}: {error}"))?;
        super::object_call(&connection, operation, url, 65_536)
    } else {
        prepare(
            &action,
            &connection,
            &target,
            &input.to_string(),
            65_536,
            65_536,
        )
        .map_err(|error| anyhow::anyhow!("prepare failed for {action:?}: {error}"))?
    };
    let before = worlds(&database)?;
    let outcome = execute(
        &call,
        &SimulatedCredentials::new(true),
        &SimulatedTransport::new(&database, SCOPE),
        "coverage-attempt",
    );
    let result = outcome
        .result
        .map_err(|error| anyhow::anyhow!("{action:?} failed offline: {error}"))?;
    let after = worlds(&database)?;
    Ok(Observed {
        result,
        before,
        after,
    })
}

/// The gate's decision for one action, as a value rather than a panic, so the
/// saboteur below can feed it a rigged observation and assert it is rejected.
/// A gate that cannot be shown to fail is indistinguishable from one that has
/// silently stopped checking — which is the failure Phase 4 exists to prevent.
fn check(
    action: Action,
    observe: impl Fn(Variant) -> Result<Observed>,
) -> std::result::Result<(), String> {
    let own = action
        .provider()
        .world()
        .expect("every provider declares a world");
    let run = |variant| observe(variant).map_err(|error| format!("{action:?}: {error:#}"));
    match demonstration(action) {
        Demonstration::PendingAdapterSeam => Ok(()),
        Demonstration::LocalAuthorization => {
            // The grant, not the signature. A key beneath the prefix is
            // authorized and one outside it is refused; if that ever inverts,
            // every grant this provider issues becomes unbounded.
            let granted = day2_capabilities::resources::ResourceTarget::ObjectBucket {
                bucket: "coverage-bucket".into(),
                key_prefix: "granted/".into(),
            };
            let inside = granted
                .authorizes_object("coverage-bucket", "granted/object")
                .is_ok();
            let outside = granted
                .authorizes_object("coverage-bucket", "ungranted/object")
                .is_err();
            let other_bucket = granted
                .authorizes_object("another-bucket", "granted/object")
                .is_err();
            if inside && outside && other_bucket {
                Ok(())
            } else {
                Err(format!(
                    "{action:?} is a local authorization but its grant does not \
                     bound what it authorizes: inside={inside} outside={outside} \
                     other_bucket={other_bucket}"
                ))
            }
        }
        Demonstration::EffectLandsInWorld => {
            let changed = run(Variant::A)?.changed();
            if changed == vec![own] {
                Ok(())
            } else {
                Err(format!(
                    "{action:?} must commit its effect to {own} and to nothing else, but \
                     changed {changed:?} — a write that lands in no world has not \
                     demonstrated one, and a write landing in another provider's world is \
                     not served by what it declares"
                ))
            }
        }
        Demonstration::ResultReflectsWorld => {
            if run(Variant::A)?.result != run(Variant::B)?.result {
                Ok(())
            } else {
                Err(format!(
                    "{action:?} produced the same result against two different worlds — its \
                     declared world ({own}) is not demonstrably what serves it"
                ))
            }
        }
    }
}

/// The gate. Every action must demonstrate its own declared world, in the way
/// it declares. Reads and writes demonstrate differently, and the first version
/// of this gate conflated them: it required a write's *returned value* to move
/// with the world, and failed on `SlackPost`, correctly, against itself. A Slack
/// post returns `{channel, ts}` where `ts` comes from the provider's sequence
/// counter, not the channel's history.
#[test]
fn every_action_demonstrates_its_own_declared_world() -> Result<()> {
    let mut checked = 0;
    for action in Action::ALL.iter().copied() {
        if demonstration(action) == Demonstration::PendingAdapterSeam {
            continue;
        }
        if let Err(failure) = check(action, |variant| observe(action, variant)) {
            panic!("{failure}");
        }
        checked += 1;
    }
    assert!(checked > 0, "no actions checked");
    Ok(())
}

/// Every provider is covered or explicitly pending, never silently absent. This
/// is what stops the gate quietly shrinking to whatever still passes.
#[test]
fn every_provider_is_covered_or_declared_pending() {
    for provider in Provider::ALL {
        let actions: Vec<_> = Action::ALL
            .iter()
            .copied()
            .filter(|action| action.provider() == *provider)
            .collect();
        assert!(
            !actions.is_empty(),
            "{} declares no actions",
            provider.name()
        );
        let pending = actions
            .iter()
            .all(|action| demonstration(*action) == Demonstration::PendingAdapterSeam);
        let covered = actions
            .iter()
            .all(|action| demonstration(*action) != Demonstration::PendingAdapterSeam);
        assert!(
            pending || covered,
            "{} mixes covered and pending actions; a provider is demonstrated \
             as a whole or not at all",
            provider.name()
        );
    }
}

/// The saboteur. Each way a simulation can be fake must actually be rejected —
/// run against the real gate logic, not asserted in a comment.
#[test]
fn the_gate_rejects_each_way_a_simulation_can_be_fake() -> Result<()> {
    let empty = || -> BTreeMap<&'static str, Option<String>> {
        Provider::ALL
            .iter()
            .map(|provider| (provider.world().expect("world"), None))
            .collect()
    };

    // A world-indifferent read: the same answer whichever world was seeded.
    // This is what a constant-returning simulation looks like, and what a world
    // nothing serves looks like once its failure is identical in both runs.
    let constant = |_variant| {
        Ok(Observed {
            result: "always the same".into(),
            before: empty(),
            after: empty(),
        })
    };
    assert!(
        check(Action::SlackRead, constant).is_err(),
        "a constant read must be rejected"
    );

    // A write that lands nowhere: nothing serves the world it declares.
    let landless = |_variant| {
        Ok(Observed {
            result: "accepted".into(),
            before: empty(),
            after: empty(),
        })
    };
    assert!(
        check(Action::SlackPost, landless).is_err(),
        "a write landing in no world must be rejected"
    );

    // A write served out of another provider's store. Its action ran and its
    // result looks fine; only naming the expected world catches it. This is the
    // case a coverage count cannot see.
    let misattributed = |_variant| {
        let mut after = empty();
        after.insert(
            Provider::Snowflake.world().expect("world"),
            Some("state that belongs to another provider".into()),
        );
        Ok(Observed {
            result: "accepted".into(),
            before: empty(),
            after,
        })
    };
    assert!(
        check(Action::SlackPost, misattributed).is_err(),
        "a write landing in another provider's world must be rejected"
    );

    // And the gate must still pass a simulation that genuinely demonstrates its
    // world, or the checks above would be satisfied by a gate that fails always.
    let honest = |variant| observe(Action::SlackPost, variant);
    assert!(
        check(Action::SlackPost, honest).is_ok(),
        "the real simulation must pass the same gate the saboteurs fail"
    );
    Ok(())
}
