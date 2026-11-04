//! Seeded, replayable schedules exercise the production subscription decisions.
use super::*;
use crate::host_inputs::{
    LiveTicks, TickStream,
    simulation::{SeededEntropy, VirtualClock},
};
use serde::{Deserialize, Serialize};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    sync::Mutex,
};

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
        refresh_url: "/reports".into(),
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

struct ScriptedRefreshInputs<'a> {
    step: &'a Step,
    clock: &'a VirtualClock,
    rendered: Cell<bool>,
    observations: RefCell<Vec<&'static str>>,
}

impl<'a> ScriptedRefreshInputs<'a> {
    fn new(step: &'a Step, clock: &'a VirtualClock) -> Self {
        Self {
            step,
            clock,
            rendered: Cell::new(false),
            observations: RefCell::new(Vec::new()),
        }
    }
}

impl RefreshInputs for ScriptedRefreshInputs<'_> {
    fn session(&self, _: i64) -> Result<Session> {
        self.observations.borrow_mut().push("session");
        Ok(session())
    }

    fn authority(&self, _: &str) -> Result<AuthorityStamp> {
        self.observations.borrow_mut().push("authority");
        Ok(stamp(if self.rendered.get() {
            self.step.after
        } else {
            self.step.before
        }))
    }

    fn revision(&self) -> Result<i64> {
        self.observations.borrow_mut().push("revision");
        Ok(self.step.revision)
    }

    fn render(&self, _: &Session, _: i64) -> Result<RenderedPage> {
        self.observations.borrow_mut().push("render");
        self.rendered.set(true);
        self.clock.0.lock().unwrap().0 = Duration::from_secs(self.step.wall_after);
        Ok(RenderedPage {
            regions: BTreeMap::from([("data".into(), self.step.text.clone())]),
            image_origins: if self.step.new_origin {
                vec!["https://new.example.test".into()]
            } else {
                vec![]
            },
        })
    }
}

const MAX_STEPS: usize = 48;
const MAX_REPLAY_BYTES: u64 = 65_536;

async fn replay(steps: &[Step]) -> Result<()> {
    ensure!(
        !steps.is_empty() && steps.len() <= MAX_STEPS,
        "live_replay_step_budget"
    );
    for step in steps {
        ensure!(
            step.wall <= i64::MAX as u64 && step.wall_after <= i64::MAX as u64,
            "live_replay_wall_budget"
        );
        ensure!(step.text.len() <= 256, "live_replay_text_budget");
    }
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
        let inputs = ScriptedRefreshInputs::new(step, clock.as_ref());
        let result = actual.refresh(&inputs, clock.as_ref());
        let due =
            step.revision != revision || step.monotonic_ms.saturating_sub(refreshed_ms) >= 5000;
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
            let expected = if step.text != text {
                step.text.as_str()
            } else {
                ""
            };
            ensure!(patch.starts_with(expected), "wrong changed region");
            if step.new_origin != image_notice {
                ensure!(
                    patch.contains("day2-live-status"),
                    "missing CSP refresh notice"
                );
                ensure!(
                    patch.contains("Some new images need a page refresh") == step.new_origin,
                    "wrong CSP refresh notice state"
                );
            } else {
                ensure!(patch == expected, "unexpected changed markup");
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
    for index in 0..MAX_STEPS {
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
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(MAX_REPLAY_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_REPLAY_BYTES,
            "live_replay_byte_budget"
        );
        let steps: Vec<Step> = serde_json::from_slice(&bytes)?;
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
                let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../artifacts/day2-web-live-replays");
                std::fs::create_dir_all(&directory).unwrap();
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
            .rendered(2, Duration::from_secs(10), BTreeMap::new(), &[])
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

#[test]
fn shared_refresh_rejects_revocation_and_expiry_during_render_before_publishing() -> Result<()> {
    for (after, wall_after, expected_observations) in [
        (
            2,
            699,
            vec![
                "session",
                "authority",
                "revision",
                "render",
                "session",
                "authority",
            ],
        ),
        (
            1,
            700,
            vec!["session", "authority", "revision", "render", "session"],
        ),
    ] {
        let step = Step {
            wall: 699,
            wall_after,
            monotonic_ms: 5000,
            revision: 2,
            before: 1,
            after,
            text: "must not escape".into(),
            new_origin: true,
        };
        let clock = VirtualClock(Mutex::new((
            Duration::from_secs(step.wall),
            Duration::from_millis(step.monotonic_ms),
        )));
        let inputs = ScriptedRefreshInputs::new(&step, &clock);
        let mut actual = state();
        let original = actual.regions.clone();
        let error = actual.refresh(&inputs, &clock).unwrap_err();
        assert_eq!(
            crate::error::classify(&error).category(),
            if after != 1 {
                crate::error::Category::Conflict
            } else {
                crate::error::Category::Authentication
            }
        );
        assert!(inputs.rendered.get());
        assert_eq!(*inputs.observations.borrow(), expected_observations);
        assert_eq!(actual.regions, original);
        assert_eq!(actual.revision, 1);
        assert_eq!(actual.refreshed, Duration::ZERO);
        assert!(!actual.needs_image_refresh);
    }
    Ok(())
}

/// Transport scheduling is separate from refresh authorization above. These
/// histories poll the actual production body and use real bounded channels.
mod transport_histories {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    const CONNECTIONS: u8 = 5;
    const MAX_EVENTS: usize = 128;
    const MAX_BYTES: u64 = 2 << 20;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Frame {
        Initial(u8),
        Patch(u8, u8),
        Heartbeat,
        Clear,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "kind", deny_unknown_fields)]
    enum Event {
        Open { connection: u8 },
        Patch { connection: u8, value: u8 },
        Heartbeat { connection: u8 },
        Revoke { connection: u8 },
        StopProducer { connection: u8 },
        LoseTerminal { connection: u8 },
        DropReceiver { connection: u8 },
        Poll { connection: u8 },
    }

    impl Event {
        fn connection(&self) -> u8 {
            match *self {
                Self::Open { connection }
                | Self::Patch { connection, .. }
                | Self::Heartbeat { connection }
                | Self::Revoke { connection }
                | Self::StopProducer { connection }
                | Self::LoseTerminal { connection }
                | Self::DropReceiver { connection }
                | Self::Poll { connection } => connection,
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Decision {
        Applied,
        Full,
        Closed,
        Unavailable,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Read {
        Pending,
        Frame(Frame),
        Interrupted,
        Eof,
        Absent,
        InvalidFrame,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Control {
        Correct,
        DataBeforeRevocation,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Program {
        format: u8,
        sources: String,
        seed: u64,
        events: Vec<Event>,
    }

    fn sources() -> String {
        crate::digest(
            concat!(
                include_str!("web_live.rs"),
                include_str!("web_live_simulation.rs")
            )
            .as_bytes(),
        )
    }

    fn validate(program: &Program) -> Result<()> {
        ensure!(
            program.format == 1 && program.sources == sources(),
            "live_transport_replay_identity"
        );
        ensure!(
            !program.events.is_empty() && program.events.len() <= MAX_EVENTS,
            "live_transport_event_bound"
        );
        for event in &program.events {
            ensure!(
                event.connection() < CONNECTIONS,
                "live_transport_connection_bound"
            );
            if let Event::Patch { value, .. } = event {
                ensure!(*value < 16, "live_transport_value_bound");
            }
        }
        Ok(())
    }

    // Fixed public fixture input. The model does not use the production SSE
    // encoder; its independent parser checks one event and reconstructs input.
    fn markup(frame: Frame) -> String {
        match frame {
            Frame::Initial(generation) => format!("<div id=\"data\">initial-{generation}</div>"),
            Frame::Patch(generation, value) => format!(
                "<div id=\"data\">patch-{generation}-{value}\r\n\nevent: forged\nid: forged</div>"
            ),
            Frame::Clear => {
                "<div id=\"data\"></div><div id=\"day2-live-status\">Stopped</div>".into()
            }
            Frame::Heartbeat => unreachable!("heartbeat has no HTML"),
        }
    }

    fn wire(frame: Frame) -> String {
        if frame == Frame::Heartbeat {
            ": keep-alive\n\n".into()
        } else {
            elements(&markup(frame), "outer")
        }
    }

    fn decode_wire(bytes: &str) -> Result<Frame> {
        if bytes == ": keep-alive\n\n" {
            return Ok(Frame::Heartbeat);
        }
        ensure!(
            bytes.len() <= 1024 && !bytes.contains('\r'),
            "live_transport_wire_bound"
        );
        let content = bytes
            .strip_suffix("\n\n")
            .context("live_transport_frame_end")?;
        let mut lines = content.split('\n');
        ensure!(
            lines.next() == Some("event: datastar-patch-elements")
                && lines.next() == Some("data: mode outer"),
            "live_transport_event_header"
        );
        let text = lines
            .map(|line| {
                line.strip_prefix("data: elements ")
                    .context("live_transport_data_field")
            })
            .collect::<Result<Vec<_>>>()?
            .join("\n");
        for frame in
            [Frame::Clear]
                .into_iter()
                .chain((0..CONNECTIONS).map(Frame::Initial))
                .chain((0..CONNECTIONS).flat_map(|generation| {
                    (0..16).map(move |value| Frame::Patch(generation, value))
                }))
        {
            if text == markup(frame).replace('\r', "&#13;") {
                return Ok(frame);
            }
        }
        anyhow::bail!("live_transport_unknown_fixture_frame")
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reference {
        producer: bool,
        terminal_sender: bool,
        terminal_slot: bool,
        terminal_value: bool,
        receiver: bool,
        receiver_closed: bool,
        ended: bool,
        waiting: bool,
        queue: VecDeque<Frame>,
        delivered: Vec<Frame>,
    }

    impl Reference {
        fn new(connection: u8) -> Self {
            Self {
                producer: true,
                terminal_sender: true,
                terminal_slot: true,
                terminal_value: false,
                receiver: true,
                receiver_closed: false,
                ended: false,
                waiting: false,
                queue: VecDeque::from([Frame::Initial(connection)]),
                delivered: vec![],
            }
        }

        fn stop(&mut self) {
            self.producer = false;
            self.terminal_sender = false;
            self.receiver_closed = true;
        }

        fn send(&mut self, frame: Frame) -> Decision {
            if !self.producer {
                return Decision::Unavailable;
            }
            if !self.receiver || self.receiver_closed {
                self.stop();
                return Decision::Closed;
            }
            if !self.queue.is_empty() {
                self.stop();
                return Decision::Full;
            }
            self.queue.push_back(frame);
            Decision::Applied
        }

        fn poll(&mut self, control: Control) -> Read {
            if !self.receiver {
                return Read::Absent;
            }
            if self.ended {
                return Read::Eof;
            }
            if self.terminal_value
                && (control != Control::DataBeforeRevocation || self.queue.is_empty())
            {
                self.terminal_value = false;
                self.queue.clear();
                self.receiver_closed = true;
                self.ended = true;
                self.delivered.push(Frame::Clear);
                return Read::Frame(Frame::Clear);
            }
            if !self.terminal_sender && !self.terminal_value {
                self.terminal_slot = false;
            }
            if let Some(frame) = self.queue.pop_front() {
                self.delivered.push(frame);
                return Read::Frame(frame);
            }
            if !self.producer {
                self.ended = true;
                return Read::Interrupted;
            }
            self.waiting = true;
            Read::Pending
        }

        fn observation(&self) -> Value {
            json!({"body":self.receiver,"ended":self.receiver.then_some(self.ended),
                "queued":if self.receiver {self.queue.len()} else {0},
                "receiver_closed":self.receiver.then_some(self.receiver_closed),
                "terminal_slot":self.receiver.then_some(self.terminal_slot),
                "producer":self.producer,"sender_closed":self.producer.then_some(!self.receiver || self.receiver_closed),
                "terminal_sender":self.terminal_sender,"terminal_sender_closed":self.terminal_sender.then_some(!self.receiver),
                "delivered":self.delivered})
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Expected {
        decision: Decision,
        read: Option<Read>,
        wake_required: bool,
    }

    fn reference_step(
        model: &mut BTreeMap<u8, Reference>,
        event: &Event,
        control: Control,
    ) -> Expected {
        let connection = event.connection();
        if matches!(event, Event::Open { .. }) {
            if model.contains_key(&connection) {
                return Expected {
                    decision: Decision::Unavailable,
                    read: None,
                    wake_required: false,
                };
            }
            model.insert(connection, Reference::new(connection));
            return Expected {
                decision: Decision::Applied,
                read: None,
                wake_required: false,
            };
        }
        let Some(state) = model.get_mut(&connection) else {
            return Expected {
                decision: Decision::Unavailable,
                read: None,
                wake_required: false,
            };
        };
        let waiting = state.waiting;
        let mut wake = false;
        let mut read = None;
        let decision = match *event {
            Event::Patch { value, .. } | Event::Heartbeat { connection: value } => {
                let frame = if matches!(event, Event::Heartbeat { .. }) {
                    Frame::Heartbeat
                } else {
                    Frame::Patch(connection, value)
                };
                let decision = state.send(frame);
                wake = decision == Decision::Applied
                    || decision == Decision::Full
                    || decision == Decision::Closed;
                decision
            }
            Event::Revoke { .. } => {
                if !state.terminal_sender {
                    Decision::Unavailable
                } else {
                    state.terminal_sender = false;
                    wake = true;
                    if state.receiver {
                        state.terminal_value = true;
                        Decision::Applied
                    } else {
                        Decision::Closed
                    }
                }
            }
            Event::StopProducer { .. } => {
                state.stop();
                wake = true;
                Decision::Applied
            }
            Event::LoseTerminal { .. } => {
                if !state.terminal_sender {
                    Decision::Unavailable
                } else {
                    state.terminal_sender = false;
                    wake = true;
                    Decision::Applied
                }
            }
            Event::DropReceiver { .. } => {
                if !state.receiver {
                    Decision::Unavailable
                } else {
                    state.receiver = false;
                    state.receiver_closed = true;
                    state.queue.clear();
                    state.waiting = false;
                    Decision::Applied
                }
            }
            Event::Poll { .. } => {
                state.waiting = false;
                read = Some(state.poll(control));
                Decision::Applied
            }
            Event::Open { .. } => unreachable!(),
        };
        let wake_required = waiting && wake && state.receiver && !state.ended;
        if wake {
            state.waiting = false;
        }
        Expected {
            decision,
            read,
            wake_required,
        }
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Transport {
        body: Option<LiveBody>,
        sender: Option<mpsc::Sender<String>>,
        terminal: Option<oneshot::Sender<String>>,
        wake: Arc<WakeCount>,
        delivered: Vec<Frame>,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Actual {
        decision: Decision,
        read: Option<Read>,
        wire: Option<String>,
        woke: bool,
    }

    impl Transport {
        fn new(connection: u8) -> Result<Self> {
            let (sender, receiver) = mpsc::channel(1);
            let (terminal_sender, terminal) = oneshot::channel();
            sender.try_send(wire(Frame::Initial(connection)))?;
            Ok(Self {
                body: Some(LiveBody {
                    receiver,
                    terminal: Some(terminal),
                    ended: false,
                }),
                sender: Some(sender),
                terminal: Some(terminal_sender),
                wake: Arc::new(WakeCount::default()),
                delivered: vec![],
            })
        }

        fn stop(&mut self) {
            self.sender.take();
            self.terminal.take();
        }

        fn send(&mut self, frame: Frame) -> Decision {
            let Some(sender) = &self.sender else {
                return Decision::Unavailable;
            };
            match sender.try_send(wire(frame)) {
                Ok(()) => Decision::Applied,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.stop();
                    Decision::Full
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.stop();
                    Decision::Closed
                }
            }
        }

        fn event(&mut self, event: &Event) -> Actual {
            self.wake.0.store(0, Ordering::SeqCst);
            let mut read = None;
            let mut bytes = None;
            let decision = match *event {
                Event::Patch { connection, value } => self.send(Frame::Patch(connection, value)),
                Event::Heartbeat { .. } => self.send(Frame::Heartbeat),
                Event::Revoke { .. } => match self.terminal.take() {
                    None => Decision::Unavailable,
                    Some(sender) => {
                        if sender.send(wire(Frame::Clear)).is_ok() {
                            Decision::Applied
                        } else {
                            Decision::Closed
                        }
                    }
                },
                Event::StopProducer { .. } => {
                    self.stop();
                    Decision::Applied
                }
                Event::LoseTerminal { .. } => {
                    if self.terminal.take().is_some() {
                        Decision::Applied
                    } else {
                        Decision::Unavailable
                    }
                }
                Event::DropReceiver { .. } => {
                    if self.body.take().is_some() {
                        Decision::Applied
                    } else {
                        Decision::Unavailable
                    }
                }
                Event::Poll { .. } => {
                    read = Some(if let Some(body) = &mut self.body {
                        let waker = Waker::from(self.wake.clone());
                        let mut context = TaskContext::from_waker(&waker);
                        match tokio_stream::Stream::poll_next(Pin::new(body), &mut context) {
                            Poll::Pending => Read::Pending,
                            Poll::Ready(None) => Read::Eof,
                            Poll::Ready(Some(Err(_))) => Read::Interrupted,
                            Poll::Ready(Some(Ok(value))) => {
                                let parsed = decode_wire(&value).ok();
                                bytes = Some(value);
                                if let Some(frame) = parsed {
                                    self.delivered.push(frame);
                                    Read::Frame(frame)
                                } else {
                                    Read::InvalidFrame
                                }
                            }
                        }
                    } else {
                        Read::Absent
                    });
                    Decision::Applied
                }
                Event::Open { .. } => Decision::Unavailable,
            };
            Actual {
                decision,
                read,
                wire: bytes,
                woke: self.wake.0.load(Ordering::SeqCst) > 0,
            }
        }

        fn observation(&self) -> Value {
            json!({"body":self.body.is_some(),"ended":self.body.as_ref().map(|body|body.ended),
                "queued":self.body.as_ref().map_or(0,|body|body.receiver.len()),
                "receiver_closed":self.body.as_ref().map(|body|body.receiver.is_closed()),
                "terminal_slot":self.body.as_ref().map(|body|body.terminal.is_some()),
                "producer":self.sender.is_some(),"sender_closed":self.sender.as_ref().map(|sender|sender.is_closed()),
                "terminal_sender":self.terminal.is_some(),"terminal_sender_closed":self.terminal.as_ref().map(|sender|sender.is_closed()),
                "delivered":self.delivered})
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Record {
        expected: BTreeMap<u8, Reference>,
        step: Expected,
        actual: Actual,
        observed: BTreeMap<u8, Value>,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Replay {
        program: Program,
        control: Control,
        records: Vec<Record>,
        failed_at: Option<usize>,
    }

    fn run(program: &Program, control: Control) -> Result<Replay> {
        validate(program)?;
        let mut model = BTreeMap::new();
        let mut world = BTreeMap::<u8, Transport>::new();
        let mut records = vec![];
        for (index, event) in program.events.iter().enumerate() {
            let expected = reference_step(&mut model, event, control);
            let connection = event.connection();
            let actual = if matches!(event, Event::Open { .. }) && !world.contains_key(&connection)
            {
                world.insert(connection, Transport::new(connection)?);
                Actual {
                    decision: Decision::Applied,
                    read: None,
                    wire: None,
                    woke: false,
                }
            } else if let Some(transport) = world.get_mut(&connection) {
                transport.event(event)
            } else {
                Actual {
                    decision: Decision::Unavailable,
                    read: None,
                    wire: None,
                    woke: false,
                }
            };
            let observed = world
                .iter()
                .map(|(id, transport)| (*id, transport.observation()))
                .collect::<BTreeMap<_, _>>();
            let predicted = model
                .iter()
                .map(|(id, state)| (*id, state.observation()))
                .collect::<BTreeMap<_, _>>();
            let failed = actual.decision != expected.decision
                || actual.read != expected.read
                || expected.wake_required && !actual.woke
                || observed != predicted;
            records.push(Record {
                expected: model.clone(),
                step: expected,
                actual,
                observed,
            });
            if failed {
                return Ok(Replay {
                    program: program.clone(),
                    control,
                    records,
                    failed_at: Some(index),
                });
            }
        }
        Ok(Replay {
            program: program.clone(),
            control,
            records,
            failed_at: None,
        })
    }

    fn generated(seed: u64) -> Program {
        let mut events = vec![
            Event::Open { connection: 0 },
            Event::Poll { connection: 0 },
            Event::Poll { connection: 0 },
            Event::Patch {
                connection: 0,
                value: 1,
            },
            Event::Revoke { connection: 0 },
            Event::Poll { connection: 0 },
            Event::Poll { connection: 0 },
            Event::Open { connection: 0 },
            Event::Patch {
                connection: 0,
                value: 2,
            },
            Event::Open { connection: 1 },
            Event::Poll { connection: 1 },
            Event::Poll { connection: 1 },
            Event::Patch {
                connection: 1,
                value: 3,
            },
            Event::Patch {
                connection: 1,
                value: 4,
            },
            Event::Poll { connection: 1 },
            Event::Poll { connection: 1 },
            Event::Poll { connection: 1 },
            Event::Open { connection: 2 },
            Event::Poll { connection: 2 },
            Event::Poll { connection: 2 },
            Event::StopProducer { connection: 2 },
            Event::Poll { connection: 2 },
            Event::Poll { connection: 2 },
            Event::Open { connection: 3 },
            Event::DropReceiver { connection: 3 },
            Event::Patch {
                connection: 3,
                value: 5,
            },
            Event::Revoke { connection: 3 },
            Event::Poll { connection: 3 },
            Event::Open { connection: 4 },
            Event::Poll { connection: 4 },
            Event::Poll { connection: 4 },
            Event::LoseTerminal { connection: 4 },
            Event::Poll { connection: 4 },
            Event::Heartbeat { connection: 4 },
            Event::Poll { connection: 4 },
        ];
        let mut random = seed;
        for _ in 0..32 {
            random = random
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let connection = ((random >> 32) % u64::from(CONNECTIONS)) as u8;
            events.push(match random % 8 {
                0 => Event::Open { connection },
                1 => Event::Patch {
                    connection,
                    value: ((random >> 40) % 16) as u8,
                },
                2 => Event::Heartbeat { connection },
                3 => Event::Revoke { connection },
                4 => Event::StopProducer { connection },
                5 => Event::LoseTerminal { connection },
                6 => Event::DropReceiver { connection },
                _ => Event::Poll { connection },
            });
        }
        for connection in 0..CONNECTIONS {
            events.push(Event::StopProducer { connection });
            for _ in 0..3 {
                events.push(Event::Poll { connection });
            }
        }
        Program {
            format: 1,
            sources: sources(),
            seed,
            events,
        }
    }

    fn retain(replay: &Replay) -> Result<std::path::PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let root = std::path::Path::new("/tmp/dst-platform-host-loops/live-transport");
        std::fs::create_dir_all(root)?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        let file = tempfile::Builder::new()
            .prefix("replay-")
            .suffix(".json")
            .tempfile_in(root)?;
        let bytes = serde_json::to_vec(replay)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "live_transport_replay_byte_bound"
        );
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))?;
        std::fs::write(file.path(), bytes)?;
        let (_, path) = file.keep()?;
        Ok(path)
    }

    fn read_replay(path: &std::path::Path) -> Result<Replay> {
        use std::io::Read;
        ensure!(
            std::fs::symlink_metadata(path)?.file_type().is_file(),
            "live_transport_replay_regular_file"
        );
        let mut bytes = vec![];
        std::fs::File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "live_transport_replay_byte_bound"
        );
        let replay: Replay = crate::json::decode_evidence(&bytes)?;
        ensure!(
            replay.records.len() <= MAX_EVENTS,
            "live_transport_record_bound"
        );
        validate(&replay.program)?;
        Ok(replay)
    }

    #[test]
    fn transport_histories_match_independent_queue_and_terminal_model_twice() -> Result<()> {
        for seed in (0..32).chain([71]) {
            let program = generated(seed);
            ensure!(
                program.events.len() == 87,
                "live_transport_declared_event_count"
            );
            let first = run(&program, Control::Correct)?;
            let second = run(&program, Control::Correct)?;
            if first.failed_at.is_some() || first != second {
                let a = retain(&first)?;
                let b = retain(&second)?;
                anyhow::bail!(
                    "live transport divergence; first={} second={}",
                    a.display(),
                    b.display()
                );
            }
            ensure!(
                first.records.len() == program.events.len(),
                "live_transport_incomplete_history"
            );
        }
        Ok(())
    }

    #[test]
    fn wrong_terminal_priority_is_retained_replayed_and_source_bound() -> Result<()> {
        let mut program = generated(71);
        program.events.truncate(8);
        let first = run(&program, Control::DataBeforeRevocation)?;
        ensure!(
            first.failed_at == Some(5),
            "live_transport_false_oracle_escaped"
        );
        let second = run(&program, Control::DataBeforeRevocation)?;
        ensure!(first == second, "live_transport_failure_not_repeatable");
        let path = retain(&first)?;
        let saved = read_replay(&path)?;
        ensure!(
            run(&saved.program, saved.control)? == saved,
            "live_transport_saved_failure_changed"
        );
        let mut changed = saved.clone();
        changed.records[5].actual.read = Some(Read::Eof);
        ensure!(
            run(&changed.program, changed.control)? != changed,
            "live_transport_false_observation_accepted"
        );
        let mut source = saved.program;
        source.sources = "sha256:foreign".into();
        ensure!(
            run(&source, Control::Correct).is_err(),
            "live_transport_foreign_source_accepted"
        );
        Ok(())
    }

    #[test]
    fn saved_transport_input_is_closed_bounded_and_replayed_twice() -> Result<()> {
        let program = generated(71);
        let encoded = serde_json::to_string(&program)?;
        let duplicate = encoded.replacen("\"seed\":71", "\"seed\":71,\"seed\":0", 1);
        ensure!(
            duplicate != encoded
                && crate::json::decode_evidence::<Program>(duplicate.as_bytes()).is_err(),
            "live_transport_duplicate_input_accepted"
        );
        let mut value = serde_json::to_value(&program)?;
        value["events"][0]["unknown"] = json!(true);
        ensure!(
            crate::json::decode_evidence::<Program>(&serde_json::to_vec(&value)?).is_err(),
            "live_transport_unknown_input_accepted"
        );
        let mut large = program.clone();
        large.events = vec![Event::Poll { connection: 0 }; MAX_EVENTS + 1];
        ensure!(
            validate(&large).is_err(),
            "live_transport_oversized_program_accepted"
        );
        large.events = vec![Event::Open {
            connection: CONNECTIONS,
        }];
        ensure!(
            validate(&large).is_err(),
            "live_transport_foreign_connection_accepted"
        );
        if let Some(path) = std::env::var_os("DAY2_WEB_TRANSPORT_REPLAY") {
            let saved = read_replay(std::path::Path::new(&path))?;
            ensure!(
                run(&saved.program, saved.control)? == saved
                    && run(&saved.program, saved.control)? == saved,
                "live_transport_external_replay_changed"
            );
        }
        Ok(())
    }

    fn path_is(expression: &syn::Expr, expected: &str) -> bool {
        matches!(expression, syn::Expr::Path(path) if path.qself.is_none() && path.path.segments.len()==1 && path.path.is_ident(expected))
    }

    fn field_is(value: &syn::ExprStruct, name: &str, check: impl Fn(&syn::Expr) -> bool) -> bool {
        value.fields.iter().any(|field| {
            matches!(&field.member,syn::Member::Named(member) if member==name) && check(&field.expr)
        })
    }

    fn outer_elements(expression: &syn::Expr) -> bool {
        matches!(expression,syn::Expr::Call(call) if path_is(&call.func,"elements") && call.args.len()==2 && matches!(&call.args[1],syn::Expr::Lit(literal) if matches!(&literal.lit,syn::Lit::Str(text) if text.value()=="outer")))
    }

    #[derive(Default)]
    struct Factory {
        channels: usize,
        bounded: usize,
        terminals: usize,
        bodies: usize,
        bound_bodies: usize,
        work: usize,
        initial: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for Factory {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = node.func.as_ref() {
                let parts = path
                    .path
                    .segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .collect::<Vec<_>>();
                if parts == ["mpsc", "channel"] {
                    self.channels += 1;
                    if node.args.len() == 1
                        && matches!(&node.args[0],syn::Expr::Lit(literal) if matches!(&literal.lit,syn::Lit::Int(size) if size.base10_parse::<u8>().ok()==Some(1)))
                    {
                        self.bounded += 1;
                    }
                }
                if parts == ["oneshot", "channel"] && node.args.is_empty() {
                    self.terminals += 1;
                }
            }
            syn::visit::visit_expr_call(self, node);
        }
        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            if node.path.is_ident("LiveBody") {
                self.bodies += 1;
                if field_is(node, "receiver", |expr| path_is(expr, "receiver"))
                    && field_is(
                        node,
                        "terminal",
                        |expr| matches!(expr,syn::Expr::Call(call) if path_is(&call.func,"Some") && call.args.len()==1 && path_is(&call.args[0],"terminal")),
                    )
                    && field_is(
                        node,
                        "ended",
                        |expr| matches!(expr,syn::Expr::Lit(literal) if matches!(&literal.lit,syn::Lit::Bool(flag) if !flag.value)),
                    )
                {
                    self.bound_bodies += 1;
                }
            }
            if node.path.is_ident("LiveWork")
                && field_is(node, "sender", |expr| path_is(expr, "sender"))
                && field_is(node, "terminal", |expr| path_is(expr, "terminal_sender"))
            {
                self.work += 1;
            }
            syn::visit::visit_expr_struct(self, node);
        }
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if node.method == "try_send"
                && path_is(&node.receiver, "sender")
                && node.args.len() == 1
                && outer_elements(&node.args[0])
            {
                self.initial += 1;
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }

    #[derive(Default)]
    struct Producer {
        full_exit: usize,
        terminal: usize,
        classifications: usize,
    }
    struct MatchesArgs {
        subject: syn::Expr,
        pattern: syn::Pat,
    }
    impl syn::parse::Parse for MatchesArgs {
        fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
            let subject = input.parse()?;
            input.parse::<syn::Token![,]>()?;
            let pattern = syn::Pat::parse_multi(input)?;
            if input.peek(syn::Token![,]) {
                input.parse::<syn::Token![,]>()?;
            }
            Ok(Self { subject, pattern })
        }
    }
    impl<'ast> syn::visit::Visit<'ast> for Producer {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            if matches!(node.cond.as_ref(),syn::Expr::MethodCall(check) if check.method=="is_err" && check.args.is_empty() && matches!(check.receiver.as_ref(),syn::Expr::MethodCall(send) if send.method=="try_send" && path_is(&send.receiver,"sender")))
                && node.then_branch.stmts.len() == 1
                && matches!(
                    &node.then_branch.stmts[0],
                    syn::Stmt::Expr(syn::Expr::Break(_), _)
                )
            {
                self.full_exit += 1;
            }
            syn::visit::visit_expr_if(self, node);
        }
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if node.method == "send"
                && path_is(&node.receiver, "terminal")
                && node.args.len() == 1
                && outer_elements(&node.args[0])
            {
                self.terminal += 1;
            }
            syn::visit::visit_expr_method_call(self, node);
        }
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if node.path.is_ident("matches")
                && let Ok(args) = syn::parse2::<MatchesArgs>(node.tokens.clone())
            {
                let subject = matches!(&args.subject,syn::Expr::MethodCall(call) if call.method=="category" && call.args.is_empty() && path_is(&call.receiver,"classified"));
                if let syn::Pat::Or(pattern) = args.pattern {
                    let mut categories = pattern
                        .cases
                        .iter()
                        .filter_map(|pattern| {
                            if let syn::Pat::Path(path) = pattern {
                                let parts = path
                                    .path
                                    .segments
                                    .iter()
                                    .map(|part| part.ident.to_string())
                                    .collect::<Vec<_>>();
                                if parts.len() == 4 && parts[..3] == ["crate", "error", "Category"]
                                {
                                    Some(parts[3].clone())
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();
                    categories.sort();
                    if subject
                        && pattern.cases.len() == 4
                        && categories == ["Authentication", "Conflict", "Forbidden", "NotFound"]
                    {
                        self.classifications += 1;
                    }
                }
            }
            syn::visit::visit_macro(self, node);
        }
    }

    fn production_wiring(source: &str) -> bool {
        use syn::visit::Visit;
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let mut factories = vec![];
        let mut producers = vec![];
        for item in &file.items {
            if let syn::Item::Impl(implementation) = item
                && let syn::Type::Path(owner) = implementation.self_ty.as_ref()
            {
                for item in &implementation.items {
                    if let syn::ImplItem::Fn(method) = item {
                        if owner.path.is_ident("Host") && method.sig.ident == "live_response" {
                            let mut visitor = Factory::default();
                            visitor.visit_block(&method.block);
                            factories.push(visitor);
                        }
                        if owner.path.is_ident("Subscription") && method.sig.ident == "run" {
                            let mut visitor = Producer::default();
                            visitor.visit_block(&method.block);
                            producers.push(visitor);
                        }
                    }
                }
            }
        }
        factories.len() == 1
            && producers.len() == 1
            && factories.iter().all(|v| {
                v.channels == 1
                    && v.bounded == 1
                    && v.terminals == 1
                    && v.bodies == 1
                    && v.bound_bodies == 1
                    && v.work == 1
                    && v.initial == 1
            })
            && producers
                .iter()
                .all(|v| v.full_exit == 2 && v.terminal == 1 && v.classifications == 1)
    }

    #[test]
    fn transport_fixture_is_bound_to_actual_factory_and_producer_wiring() -> Result<()> {
        let source = include_str!("web_live.rs");
        ensure!(
            production_wiring(source),
            "live_transport_actual_wiring_changed"
        );
        let start = source
            .find("pub(super) fn live_response(")
            .context("live factory")?;
        for (before, after) in [
            ("mpsc::channel(1)", "mpsc::channel(2)"),
            ("terminal: Some(terminal)", "terminal: None"),
            ("terminal: terminal_sender", "terminal: unrelated_terminal"),
            (
                "sender.try_send(event).is_err()",
                "sender.try_send(event).is_ok()",
            ),
            (
                "terminal.send(elements(&cleared, \"outer\"))",
                "unrelated_terminal.send(elements(&cleared, \"outer\"))",
            ),
            (
                "crate::error::Category::Authentication",
                "crate::error::Category::Internal",
            ),
        ] {
            let offset = start
                + source[start..]
                    .find(before)
                    .context("live transport actual mutant")?;
            let mut mutant = source.to_owned();
            mutant.replace_range(offset..offset + before.len(), after);
            ensure!(
                !production_wiring(&mutant),
                "live_transport_wiring_mutant_escaped"
            );
        }
        Ok(())
    }
}
