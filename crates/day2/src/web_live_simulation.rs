//! Seeded, replayable schedules exercise the production subscription decisions.
use super::*;
use crate::host_inputs::{
    LiveTicks, TickStream,
    simulation::{SeededEntropy, VirtualClock},
};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, sync::Mutex};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    wall: u64,
    wall_after: u64,
    monotonic_ms: u64,
    revision: i64,
    before: u64,
    after: u64,
    text: String,
    new_origin: bool,
}

struct ScriptedTicks {
    clock: Arc<VirtualClock>,
    steps: Arc<Mutex<VecDeque<Step>>>,
}

impl LiveTicks for ScriptedTicks {
    fn start(&self, _: Duration) -> Box<dyn TickStream> {
        Box::new(Self {
            clock: self.clock.clone(),
            steps: self.steps.clone(),
        })
    }
}

impl TickStream for ScriptedTicks {
    fn next(&mut self) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let step = self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted tick");
            *self.clock.0.lock().unwrap() = (
                Duration::from_secs(step.wall),
                Duration::from_millis(step.monotonic_ms),
            );
        })
    }
}

fn state() -> SubscriptionState {
    SubscriptionState {
        actor: "alice".into(),
        session: "session".into(),
        revision: 1,
        authority: AuthorityStamp {
            epoch: "admission".into(),
            revision: 1,
        },
        regions: BTreeMap::from([("data".into(), "initial".into())]),
        document_image_origins: BTreeSet::new(),
        needs_image_refresh: false,
        refreshed: Duration::ZERO,
        refresh: Some(Duration::from_secs(5)),
    }
}

fn session() -> Session {
    Session {
        hash: "session".into(),
        actor: "alice".into(),
        expires: 700,
        origin: None,
    }
}

fn stamp(revision: u64) -> AuthorityStamp {
    AuthorityStamp {
        epoch: "admission".into(),
        revision,
    }
}

// The same pre-render / post-render authority fences as the native pump, with
// observed values instead of database and renderer effects.
fn evaluate(
    state: &mut SubscriptionState,
    step: &Step,
    clock: &dyn Clock,
) -> Result<Option<String>> {
    let wall = clock.wall_time()?.as_secs().try_into()?;
    state.authorize(&session(), &stamp(step.before), wall)?;
    if !state.needs_refresh(step.revision, clock.monotonic()) {
        return Ok(None);
    }
    state.authorize(&session(), &stamp(step.after), step.wall_after.try_into()?)?;
    state.rendered(
        step.revision,
        clock.monotonic(),
        BTreeMap::from([("data".into(), step.text.clone())]),
        &if step.new_origin {
            vec!["https://new.example.test".into()]
        } else {
            vec![]
        },
        "/reports",
    )
}

async fn replay(steps: &[Step]) -> Result<()> {
    let clock = Arc::new(VirtualClock(Mutex::new((
        Duration::from_secs(100),
        Duration::ZERO,
    ))));
    let scheduler = ScriptedTicks {
        clock: clock.clone(),
        steps: Arc::new(Mutex::new(steps.to_vec().into())),
    };
    let mut ticks = scheduler.start(CHECK_INTERVAL);
    let mut actual = state();
    // Independent reference expectations: integer deadlines and explicit fence
    // order. It never calls needs_refresh/rendered/authorize to derive answers.
    let (mut revision, mut refreshed_ms, mut text, mut image_notice) =
        (1, 0, "initial".to_owned(), false);
    for step in steps {
        ticks.next().await;
        let before = serde_json::to_value((
            &actual.regions,
            actual.revision,
            actual.refreshed.as_millis(),
            actual.needs_image_refresh,
        ))?;
        let result = evaluate(&mut actual, step, clock.as_ref());
        let due = step.revision != revision || step.monotonic_ms >= refreshed_ms + 5000;
        let refused = step.wall >= 700
            || step.before != 1
            || (due && (step.wall_after >= 700 || step.after != 1));
        if refused {
            ensure!(
                result.is_err(),
                "expected authority/session refusal: {step:?}"
            );
            ensure!(
                serde_json::to_value((
                    &actual.regions,
                    actual.revision,
                    actual.refreshed.as_millis(),
                    actual.needs_image_refresh
                ))? == before,
                "refusal mutated subscription state"
            );
            break;
        }
        let patch = result?;
        let changed = due && (step.text != text || step.new_origin != image_notice);
        ensure!(
            patch.is_some() == changed,
            "patch decision diverged: {step:?}"
        );
        if let Some(patch) = patch {
            ensure!(!patch.contains("<form"), "live patch replaced draft");
            ensure!(
                patch.starts_with("event: datastar-patch-elements\ndata: mode outer\n"),
                "wrong patch transport"
            );
            if step.new_origin != image_notice {
                ensure!(
                    patch.contains("day2-live-status"),
                    "missing CSP refresh notice"
                );
            }
        }
        if due {
            revision = step.revision;
            refreshed_ms = step.monotonic_ms;
            text = step.text.clone();
            image_notice = step.new_origin;
        }
        ensure!(
            actual.revision == revision
                && actual.refreshed.as_millis() == u128::from(refreshed_ms)
                && actual.regions["data"] == text
                && actual.needs_image_refresh == image_notice,
            "reference state diverged: {step:?}"
        );
    }
    Ok(())
}

fn schedule(seed: u64) -> Result<Vec<Step>> {
    let entropy = SeededEntropy::new(seed);
    let (mut elapsed, mut revision) = (0, 1);
    let mut steps = Vec::new();
    for index in 0..48 {
        let mut bytes = [0; 4];
        entropy.fill(&mut bytes)?;
        elapsed += u64::from(bytes[0]) * 25;
        revision += i64::from(bytes[1] % 3 == 0);
        steps.push(Step {
            // Wall rollback cannot suppress a monotonic refresh.
            wall: if index == 47 {
                700
            } else {
                100 + u64::from(bytes[2])
            },
            wall_after: if index == 46 {
                700
            } else {
                100 + u64::from(bytes[2])
            },
            monotonic_ms: elapsed,
            revision,
            before: 1,
            after: if index > 32 && bytes[3] % 7 == 0 {
                2
            } else {
                1
            },
            text: format!("version-{revision}"),
            new_origin: bytes[3] % 2 == 0,
        });
    }
    Ok(steps)
}

#[test]
fn seeded_live_schedules_match_independent_reference_and_replay() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    if let Some(path) = std::env::var_os("DAY2_WEB_LIVE_REPLAY") {
        let steps: Vec<Step> = serde_json::from_slice(&std::fs::read(path)?)?;
        return runtime.block_on(replay(&steps));
    }
    use proptest::{
        prelude::*,
        test_runner::{Config, RngSeed, TestRunner},
    };
    let mut runner = TestRunner::new(Config {
        cases: 64,
        rng_seed: RngSeed::Fixed(130),
        failure_persistence: None, // Full schedules are persisted below, including shrinks.
        ..Config::default()
    });
    runner
        .run(&any::<u64>(), |seed| {
            let steps = schedule(seed).unwrap();
            let bytes = serde_json::to_vec(&steps).unwrap();
            let decoded = serde_json::from_slice::<Vec<Step>>(&bytes).unwrap();
            let result = runtime.block_on(replay(&decoded));
            if let Err(error) = result {
                // Persist the entire observation schedule, not just a random seed.
                let directory = std::path::Path::new("target/day2-web-live-replays");
                std::fs::create_dir_all(directory).unwrap();
                let path = directory.join(format!("seed-{seed}.json"));
                std::fs::write(&path, bytes).unwrap();
                return Err(TestCaseError::fail(format!(
                    "{error:#}; replay with DAY2_WEB_LIVE_REPLAY={}",
                    path.display()
                )));
            }
            prop_assert!(runtime.block_on(replay(&steps)).is_ok());
            Ok(())
        })
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(())
}

#[tokio::test]
async fn virtual_wall_expiration_monotonic_refresh_and_post_render_revocation_order() -> Result<()>
{
    let base = Step {
        wall: 100,
        wall_after: 100,
        monotonic_ms: 4999,
        revision: 1,
        before: 1,
        after: 1,
        text: "fresh".into(),
        new_origin: false,
    };
    let steps = [
        base.clone(),
        Step {
            wall: 50,
            monotonic_ms: 5000,
            ..base.clone()
        },
        Step {
            wall: 699,
            monotonic_ms: 5001,
            revision: 2,
            after: 2,
            text: "must not escape".into(),
            ..base.clone()
        },
    ];
    replay(&steps).await?;
    // Exact expiry is denied even on an otherwise idle subscription.
    replay(&[Step {
        wall: 700,
        ..base.clone()
    }])
    .await?;
    replay(&[Step {
        before: 2,
        ..base.clone()
    }])
    .await?;
    replay(&[Step {
        wall: 699,
        wall_after: 700,
        revision: 2,
        ..base
    }])
    .await?;
    let mut actual = state();
    let original = actual.regions.clone();
    assert!(
        actual
            .rendered(2, Duration::from_secs(10), BTreeMap::new(), &[], "/")
            .is_err()
    );
    assert_eq!(actual.regions, original);
    assert_eq!(actual.revision, 1);
    let mut other_session = session();
    other_session.actor = "bob".into();
    assert!(actual.authorize(&other_session, &stamp(1), 100).is_err());
    other_session = session();
    other_session.hash = "replacement-session".into();
    assert!(actual.authorize(&other_session, &stamp(1), 100).is_err());
    assert!(
        actual
            .authorize(
                &session(),
                &AuthorityStamp {
                    epoch: "restored".into(),
                    revision: 1
                },
                100
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn development_grant_uses_explicit_entropy_and_exact_600_second_wall_deadline() -> Result<()> {
    let clock = VirtualClock(Mutex::new((Duration::from_secs(100), Duration::ZERO)));
    let (grant, token) = Grant::issue("alice", &SeededEntropy::new(130), &clock)?;
    let (_, replay) = Grant::issue("alice", &SeededEntropy::new(130), &clock)?;
    assert_eq!(token, replay);
    assert_eq!(grant.expires, 700);
    assert!(grant.accepts(&token, 699));
    assert!(!grant.accepts(&token, 700));
    assert!(!grant.accepts("wrong", 100));
    Ok(())
}
