//! Independent protocol oracle + seeded, persisted logical replay. The oracle
//! knows only phases, revisions and admission facts, not Creation's transitions.
use super::{
    Options, SourceFile,
    core::Node,
    simulation::{Memory, SeededEntropy},
};
use anyhow::{Result, ensure};
use proptest::{
    prelude::*,
    test_runner::{Config, RngSeed, TestRunner},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Action {
    Write,
    Identity,
    Build,
    Built,
    Publish,
    Tamper,
    WrongSource,
    WrongNamespace,
    WrongArtifact,
    Collision,
    EntropyFailure,
    AdmissionFailure,
    ArtifactTamper,
}

const ORDER: [Action; 5] = [
    Action::Write,
    Action::Identity,
    Action::Build,
    Action::Built,
    Action::Publish,
];

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Replay {
    format: u32,
    seed: u64,
    actions: Vec<Action>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReferencePhase {
    Captured,
    Written,
    Identified,
    Building,
    Built,
    Published,
    Failed,
}

struct Reference {
    phase: ReferencePhase,
    revision: u32,
    captured: u32,
    namespace: bool,
    artifact_revision: u32,
    built_artifact: u32,
    occupied: bool,
    entropy_failure: bool,
    admission_failure: bool,
    publications: usize,
}

impl Reference {
    fn new() -> Self {
        Self {
            phase: ReferencePhase::Captured,
            revision: 0,
            captured: 0,
            namespace: true,
            artifact_revision: 0,
            built_artifact: 0,
            occupied: false,
            entropy_failure: false,
            admission_failure: false,
            publications: 0,
        }
    }

    fn step(&mut self, action: Action) -> bool {
        use Action::*;
        use ReferencePhase as P;
        match action {
            Tamper => {
                self.revision += 1;
                return true;
            }
            WrongNamespace => {
                self.namespace = false;
                return true;
            }
            Collision => {
                self.occupied = true;
                return true;
            }
            EntropyFailure => {
                self.entropy_failure = true;
                return true;
            }
            AdmissionFailure => {
                self.admission_failure = true;
                return true;
            }
            ArtifactTamper => {
                self.artifact_revision += 1;
                return true;
            }
            _ => {}
        }
        let unchanged = self.revision == self.captured;
        let accepted = match action {
            Write => self.phase == P::Captured && unchanged,
            Identity => self.phase == P::Written && unchanged && !self.entropy_failure,
            Build => self.phase == P::Identified && unchanged,
            Built => {
                self.phase == P::Building && unchanged && self.namespace && !self.admission_failure
            }
            Publish => {
                self.phase == P::Built
                    && unchanged
                    && self.namespace
                    && !self.admission_failure
                    && self.artifact_revision == self.built_artifact
                    && !self.occupied
            }
            WrongSource | WrongArtifact => false,
            _ => unreachable!(),
        };
        if !accepted {
            self.phase = P::Failed;
            return false;
        }
        self.phase = match action {
            Write => P::Written,
            Identity => P::Identified,
            Build => P::Building,
            Built => {
                self.built_artifact = self.artifact_revision;
                P::Built
            }
            Publish => {
                self.occupied = true;
                self.publications += 1;
                P::Published
            }
            _ => unreachable!(),
        };
        self.captured = self.revision;
        true
    }
}

pub(super) fn options() -> Options {
    Options {
        destination: PathBuf::from("fresh-app"),
        name: "starter".into(),
        ui: "none".into(),
        bundle: "".into(),
        bundle_sha256: "".into(),
    }
}

pub(super) fn sources() -> Vec<SourceFile> {
    vec![
        SourceFile {
            path: "App.roc".into(),
            content: "App :: [].{ definition = { namespace: \"starter\" } }\n".into(),
        },
        SourceFile {
            path: "README.md".into(),
            content: "captured".into(),
        },
    ]
}

// Deliberately do not call Registry or SeededEntropy to compute the reference
// registration. This oracle describes the single starter model independently.
fn reference_identity_bytes(seed: u64) -> String {
    let mut state = seed;
    let mut key = String::new();
    for _ in 0..16 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        key.push_str(&format!("{:02x}", state >> 56));
    }
    format!(
        "{{\n  \"format\": 1,\n  \"models\": [\n    {{\n      \"identity\": {{\n        \"key\": \"{key}\",\n        \"prefix\": \"sta\"\n      }},\n      \"table\": \"starters\",\n      \"roc_type\": \"Models.StarterRecord\",\n      \"retired\": false\n    }}\n  ]\n}}"
    )
}

fn replay(history: &Replay) -> Result<Vec<Value>> {
    ensure!(
        history.format == 1 && history.actions.len() <= 128,
        "unsupported/budget replay"
    );
    let artifact = Path::new("/admitted-artifact");
    let mut creation = Memory::begin(&options())?;
    creation.port.verified(artifact, "starter");
    let mut entropy = SeededEntropy::new(history.seed);
    let mut model = Reference::new();
    let mut trace = Vec::new();
    for (index, action) in history.actions.iter().copied().enumerate() {
        let expected = model.step(action);
        let before = creation.port.publications;
        let actual = match action {
            Action::Write => creation.write_files(sources()).is_ok(),
            Action::Identity => creation
                .identity("starters", "Models.StarterRecord", &entropy)
                .is_ok(),
            Action::Build => creation
                .check_build_source(Path::new("/captured-source"))
                .is_ok(),
            Action::Built => creation.built(artifact).is_ok(),
            Action::Publish => creation.publish(artifact).is_ok(),
            Action::WrongSource => creation
                .check_build_source(Path::new("/wrong-source"))
                .is_ok(),
            Action::WrongArtifact => creation.publish(Path::new("/wrong-artifact")).is_ok(),
            Action::Tamper => {
                creation.port.tree.0.insert(
                    "README.md".into(),
                    Node::File(format!("tamper-{index}").into_bytes()),
                );
                true
            }
            Action::WrongNamespace => {
                creation.port.admitted.get_mut(artifact).unwrap().namespace = "other".into();
                true
            }
            Action::Collision => {
                creation.port.occupied = true;
                true
            }
            Action::EntropyFailure => {
                entropy.fail = true;
                true
            }
            Action::AdmissionFailure => {
                creation.port.fail_admission = true;
                true
            }
            Action::ArtifactTamper => {
                creation
                    .port
                    .admitted
                    .get_mut(artifact)
                    .unwrap()
                    .identity
                    .push('x');
                true
            }
        };
        ensure!(
            actual == expected,
            "step {index} {action:?}: actual {actual}, reference {expected}"
        );
        ensure!(
            creation.port.publications == model.publications,
            "step {index}: publication count mismatch"
        );
        if !actual {
            ensure!(
                creation.port.publications == before,
                "publication on failure at {index}"
            );
        }
        let registry = creation
            .port
            .tree
            .0
            .get(day2::identity::REGISTRY_FILE)
            .map(|node| {
                let Node::File(bytes) = node else {
                    panic!("registry not regular")
                };
                String::from_utf8(bytes.clone()).unwrap()
            });
        if let Some(registry) = &registry {
            ensure!(
                *registry == reference_identity_bytes(history.seed),
                "independent model bytes mismatch at {index}"
            );
        }
        trace.push(json!({"action":action,"accepted":actual,"publications":creation.port.publications,"registry":registry}));
    }
    Ok(trace)
}

fn persist_failure(history: &Replay, error: &str) -> Result<PathBuf> {
    let directory = std::env::temp_dir().join("day2-app-creation-replays");
    fs::create_dir_all(&directory)?;
    let directory = directory.canonicalize()?;
    let authored = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    ensure!(
        !directory.starts_with(authored),
        "replay failures must stay outside authored tree"
    );
    let bytes = serde_json::to_vec_pretty(&json!({"history":history,"failure":error,
        "replay":"DAY2_CREATION_REPLAY=<path> cargo test --locked -p day2-ops --lib app_create::state_machine::replay_saved_creation_history -- --exact"}))?;
    let digest = super::sha(&bytes).replace(':', "-");
    let path = directory.join(format!("{digest}.json"));
    fs::write(&path, bytes)?;
    Ok(path)
}

fn checked_replay(history: &Replay) -> Result<Vec<Value>> {
    let result = replay(history);
    if let Err(error) = &result {
        let path = persist_failure(history, &format!("{error:#}"))?;
        eprintln!("creation replay failure: {}", path.display());
    }
    result
}

#[test]
fn same_seed_logical_trace_and_model_identity_bytes_are_identical() -> Result<()> {
    let history = Replay {
        format: 1,
        seed: 130,
        actions: ORDER.to_vec(),
    };
    let first = checked_replay(&history)?;
    ensure!(
        first.last().unwrap()["publications"] == 1,
        "success path not published"
    );
    ensure!(
        serde_json::to_vec(&first)? == serde_json::to_vec(&checked_replay(&history)?)?,
        "non-deterministic replay"
    );
    Ok(())
}

#[test]
fn adversarial_phase_and_evidence_schedules_never_publish_on_failure() -> Result<()> {
    // Insert tampering at every boundary, and invalid operations at every phase.
    for prefix in 0..=4 {
        for attack in [
            Action::Tamper,
            Action::WrongSource,
            Action::WrongArtifact,
            Action::AdmissionFailure,
        ] {
            let mut actions = ORDER[..prefix].to_vec();
            actions.push(attack);
            actions.extend_from_slice(&ORDER[prefix..]);
            let trace = checked_replay(&Replay {
                format: 1,
                seed: 87,
                actions,
            })?;
            ensure!(
                trace.last().unwrap()["publications"] == 0,
                "attack published"
            );
        }
    }
    for (prefix, attack) in [
        (1, Action::EntropyFailure),
        (3, Action::WrongNamespace),
        (4, Action::WrongNamespace),
        (4, Action::ArtifactTamper),
        (4, Action::Collision),
        (4, Action::Publish),
    ] {
        let mut actions = ORDER[..prefix].to_vec();
        actions.push(attack);
        actions.extend_from_slice(&ORDER[prefix..]);
        checked_replay(&Replay {
            format: 1,
            seed: 87,
            actions,
        })?;
    }
    Ok(())
}

#[test]
fn seeded_independent_reference_creation_state_machine() -> Result<()> {
    let strategy = (0usize..=5, prop::collection::vec(0u8..13, 0..64));
    for seed in [0u64, 87, 130, 0x87ee050] {
        let mut runner = TestRunner::new(Config {
            cases: 256,
            rng_seed: RngSeed::Fixed(seed),
            failure_persistence: None,
            ..Config::default()
        });
        let result = runner.run(&strategy, |(prefix, schedule)| {
            let mut actions = ORDER[..prefix].to_vec();
            let all = [
                Action::Write,
                Action::Identity,
                Action::Build,
                Action::Built,
                Action::Publish,
                Action::Tamper,
                Action::WrongSource,
                Action::WrongNamespace,
                Action::WrongArtifact,
                Action::Collision,
                Action::EntropyFailure,
                Action::AdmissionFailure,
                Action::ArtifactTamper,
            ];
            actions.extend(schedule.into_iter().map(|a| all[a as usize]));
            let history = Replay {
                format: 1,
                seed,
                actions,
            };
            let trace =
                checked_replay(&history).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
            let again =
                checked_replay(&history).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
            if serde_json::to_vec(&trace).unwrap() != serde_json::to_vec(&again).unwrap() {
                let path =
                    persist_failure(&history, "same-seed logical trace or model bytes differ")
                        .map_err(|e| {
                            TestCaseError::fail(format!("persist creation replay: {e:#}"))
                        })?;
                return Err(TestCaseError::fail(format!(
                    "non-deterministic replay: {}",
                    path.display()
                )));
            }
            Ok(())
        });
        ensure!(result.is_ok(), "seed {seed}: {result:?}");
    }
    Ok(())
}

#[test]
fn replay_saved_creation_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_CREATION_REPLAY") else {
        return Ok(());
    };
    let saved: Value = serde_json::from_slice(&fs::read(path)?)?;
    let history: Replay = serde_json::from_value(saved["history"].clone())?;
    checked_replay(&history)?;
    Ok(())
}

#[test]
fn failed_replay_is_persisted_outside_authored_tree_and_roundtrips() -> Result<()> {
    let history = Replay {
        format: 1,
        seed: 130,
        actions: ORDER.to_vec(),
    };
    let path = persist_failure(&history, "persistence conformance fixture")?;
    let saved: Value = serde_json::from_slice(&fs::read(path)?)?;
    let loaded: Replay = serde_json::from_value(saved["history"].clone())?;
    ensure!(
        checked_replay(&history)? == checked_replay(&loaded)?,
        "saved replay differs"
    );
    Ok(())
}
