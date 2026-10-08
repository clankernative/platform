//! No-OS replay world: ports report scheduled effects, production decides admission.
// Assertion failures emit complete JSON replay records; the separate file adapter
// conformance below also persists a replay corpus without adding OS effects to run().
use super::port::SimulatedAssembler;
use super::*;
use std::{cell::RefCell, rc::Rc};

const SOURCE: &[u8] = b"<main>source</main>";
const EXPANDED: &[u8] = b"<main>expanded</main>";
const CSS: &[u8] = b"body {}";
const UNUSED: &[u8] = b"/* app owned */";
const CONSUMED: &[u8] = b"provider syntax";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum Fault {
    None,
    Timeout,
    Rejected,
    TamperAfterAssembly,
    TamperUnused,
    IncompleteCapture,
    ResourceCollision,
    DirectoryCollision,
    ParentCollision,
    ConsumedOutput,
    StagingFailure,
    TamperBeforePublication,
}

const FAULTS: [Fault; 12] = [
    Fault::None,
    Fault::Timeout,
    Fault::Rejected,
    Fault::TamperAfterAssembly,
    Fault::TamperUnused,
    Fault::IncompleteCapture,
    Fault::ResourceCollision,
    Fault::DirectoryCollision,
    Fault::ParentCollision,
    Fault::ConsumedOutput,
    Fault::StagingFailure,
    Fault::TamperBeforePublication,
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Schedule {
    seed: u64,
    fault: Fault,
    provider_ticks: u64,
}

#[derive(Default)]
struct State {
    snapshot: UiSnapshot,
    captures: usize,
    events: Vec<String>,
}

struct Provider {
    schedule: Schedule,
    state: Rc<RefCell<State>>,
    protocol: SimulatedAssembler,
}

impl UiAssembler for Provider {
    fn assemble(
        &self,
        request: &AssemblyRequest,
    ) -> std::result::Result<Envelope, AssemblyFailure> {
        let mut state = self.state.borrow_mut();
        state
            .events
            .push(format!("provider:{}", self.schedule.provider_ticks));
        match self.schedule.fault {
            Fault::Timeout => return Err(AssemblyFailure::Timeout),
            Fault::Rejected => {
                return Err(AssemblyFailure::ProviderRejected(
                    "scheduled refusal".into(),
                ));
            }
            Fault::TamperAfterAssembly => {
                state
                    .snapshot
                    .files
                    .insert("pages/index.html".into(), b"tampered".to_vec());
            }
            Fault::TamperUnused => {
                state
                    .snapshot
                    .files
                    .insert("app.js".into(), b"tampered".to_vec());
            }
            _ => {}
        }
        self.protocol.assemble(request)
    }
}

struct Publication {
    schedule: Schedule,
    state: Rc<RefCell<State>>,
}

impl UiPublication for Publication {
    fn capture(&mut self) -> Result<UiSnapshot> {
        let mut state = self.state.borrow_mut();
        state.captures += 1;
        let count = state.captures;
        state.events.push(format!("capture:{count}"));
        if self.schedule.fault == Fault::TamperBeforePublication && count == 3 {
            state
                .snapshot
                .files
                .insert("provider.css".into(), b"intruder".to_vec());
        }
        let mut snapshot = state.snapshot.clone();
        if self.schedule.fault == Fault::IncompleteCapture {
            // Unclaimed resources still must be present in the complete host capture.
            snapshot.files.remove("app.js");
        }
        Ok(snapshot)
    }

    fn publish(&mut self, expected: &UiSnapshot, plan: &PublicationPlan) -> Result<()> {
        self.state.borrow_mut().events.push("stage".into());
        if self.schedule.fault == Fault::StagingFailure {
            bail!("scheduled staging failure");
        }
        plan.revalidate(expected, &self.capture()?)?;
        let mut state = self.state.borrow_mut();
        // Mechanical application only: collision/admission/revalidation decisions
        // above use the same pure code as FilePublication, not mock-local policy.
        for (path, bytes) in &plan.writes {
            state.snapshot.files.insert(path.clone(), bytes.clone());
        }
        for path in &plan.removes {
            state.snapshot.files.remove(path);
        }
        state.events.push("publish".into());
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Replay {
    schedule: Schedule,
    events: Vec<String>,
    error: Option<String>,
    files: BTreeMap<String, Vec<u8>>,
    hashes: BTreeMap<String, String>,
}

fn run(schedule: Schedule) -> Replay {
    let package = BTreeMap::from([("style.css".into(), CSS.to_vec())]);
    let package_inputs = vec![Input {
        path: "style.css".into(),
        digest: sha(CSS),
        bytes: CSS.len(),
    }];
    let lock = Lock {
        schema_version: 1,
        provider: "replay-provider".into(),
        package: LockedPackage {
            name: "opaque".into(),
            version: "1".into(),
            path: "../package".into(),
            digest: manifest_digest(&package_inputs).unwrap(),
            inputs: package_inputs,
        },
    };
    let mut files = BTreeMap::from([
        ("pages/index.html".into(), SOURCE.to_vec()),
        ("app.js".into(), UNUSED.to_vec()),
        ("source.txt".into(), CONSUMED.to_vec()),
        ("ui.lock.json".into(), serde_json::to_vec(&lock).unwrap()),
    ]);
    let mut directories = BTreeSet::from(["pages".into()]);
    match schedule.fault {
        Fault::ResourceCollision => {
            files.insert("provider.css".into(), b"app owned".to_vec());
        }
        Fault::DirectoryCollision => {
            directories.insert("provider.css".into());
        }
        Fault::ParentCollision => {
            files.insert("nested".into(), b"not a directory".to_vec());
        }
        _ => {}
    }
    let mut hashes = files
        .iter()
        .map(|(path, bytes)| (format!("app/ui/{path}"), sha(bytes)))
        .collect::<BTreeMap<_, _>>();
    let request = AssemblyRequest {
        schema_version: 1,
        assembly_protocol: 2,
        provider: lock.provider.clone(),
        target: AssemblyTarget {
            binding_abi: 2,
            template_engine: "minijinja-2.12.0".into(),
        },
        // Opaque handles supplied by adapter composition, never entropy in decisions.
        package: LockedPackage {
            path: "opaque-package-handle".into(),
            ..lock.package.clone()
        },
        ui: "opaque-ui-handle".into(),
    };
    let consumed = if schedule.fault == Fault::ConsumedOutput {
        "ui/pages/index.html"
    } else {
        "ui/source.txt"
    };
    let resource = if schedule.fault == Fault::ParentCollision {
        "ui/nested/provider.css"
    } else {
        "ui/provider.css"
    };
    let response = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1, "ok": true, "command": "assemble", "diagnostics": [],
        "data": {
            "schemaVersion": 1, "runtimeAbi": 2, "templateEngine": "minijinja-2.12.0",
            "packageDigest": lock.package.digest,
            "templates": {"pages/index.html": std::str::from_utf8(EXPANDED).unwrap()},
            "resources": [{"path":resource,"source":"style.css","content":null,
                "digest":sha(CSS),"bytes":CSS.len(),"kind":"stylesheet"}],
            "inputs": [
                {"path":"package/style.css","digest":sha(CSS),"bytes":CSS.len()},
                {"path":"ui/pages/index.html","digest":sha(SOURCE),"bytes":SOURCE.len()},
                {"path":"ui/source.txt","digest":sha(CONSUMED),"bytes":CONSUMED.len()}
            ],
            "consumedInputs": [consumed]
        }
    }))
    .unwrap();
    let state = Rc::new(RefCell::new(State {
        snapshot: UiSnapshot {
            files: files.clone(),
            directories,
        },
        ..State::default()
    }));
    let provider = Provider {
        schedule: schedule.clone(),
        state: state.clone(),
        protocol: SimulatedAssembler {
            expected_request: request.clone(),
            recorded_response: response,
        },
    };
    let mut publication = Publication {
        schedule: schedule.clone(),
        state: state.clone(),
    };
    let original_hashes = hashes.clone();
    let result = assemble_and_stage(
        &provider,
        &mut publication,
        &request,
        &lock,
        &package,
        &mut hashes,
    );
    let state = state.borrow();
    let replay = Replay {
        schedule: schedule.clone(),
        events: state.events.clone(),
        error: result.as_ref().err().map(|error| format!("{error:#}")),
        files: state.snapshot.files.clone(),
        hashes,
    };
    // Independent reference expectations do not use the production plan or validator.
    let success = schedule.fault == Fault::None;
    let mut expected_files = files;
    let mut expected_hashes = original_hashes;
    match schedule.fault {
        Fault::None => {
            expected_files.insert("pages/index.html".into(), EXPANDED.to_vec());
            expected_files.insert("provider.css".into(), CSS.to_vec());
            expected_files.remove("source.txt");
            expected_hashes.insert("ui/package".into(), lock.package.digest.clone());
            expected_hashes.insert("app/ui/pages/index.html".into(), sha(EXPANDED));
            expected_hashes.insert("app/ui/provider.css".into(), sha(CSS));
            expected_hashes.insert("ui-source/app/ui/pages/index.html".into(), sha(SOURCE));
            expected_hashes.insert("ui-source/app/ui/source.txt".into(), sha(CONSUMED));
        }
        Fault::TamperAfterAssembly => {
            expected_files.insert("pages/index.html".into(), b"tampered".to_vec());
        }
        Fault::TamperUnused => {
            expected_files.insert("app.js".into(), b"tampered".to_vec());
        }
        Fault::TamperBeforePublication => {
            expected_files.insert("provider.css".into(), b"intruder".to_vec());
        }
        _ => {}
    }
    let trace = serde_json::to_string(&replay).unwrap();
    assert_eq!(result.is_ok(), success, "replay: {trace}");
    assert_eq!(replay.files, expected_files, "replay: {trace}");
    assert_eq!(replay.hashes, expected_hashes, "replay: {trace}");
    assert_eq!(
        replay.events.iter().any(|event| event == "publish"),
        success,
        "replay: {trace}"
    );
    replay
}

#[test]
fn seeded_fault_schedules_replay_without_os_effects() {
    for seed in 0..64u64 {
        let mut random = seed;
        let mut scheduled = FAULTS.to_vec();
        for index in (1..scheduled.len()).rev() {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            scheduled.swap(index, (random % (index as u64 + 1)) as usize);
        }
        for fault in scheduled {
            let schedule = Schedule {
                seed,
                fault,
                provider_ticks: random % 100,
            };
            let first = run(schedule);
            let bytes = serde_json::to_vec(&first).unwrap();
            let recorded: Replay = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                run(recorded.schedule),
                first,
                "replay: {}",
                String::from_utf8(bytes).unwrap()
            );
        }
    }
}

#[test]
fn real_file_replay_corpus_is_persisted_and_roundtrips() {
    use std::{fs, io::Write};
    let corpus = FAULTS
        .into_iter()
        .map(|fault| {
            run(Schedule {
                seed: 87,
                fault,
                provider_ticks: 13,
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec_pretty(&corpus).unwrap();
    let mut file = tempfile::Builder::new()
        .prefix("ui-assembly-replay-")
        .suffix(".json")
        .tempfile()
        .unwrap();
    file.write_all(&bytes).unwrap();
    let (_file, path) = file.keep().unwrap();
    let recorded: Vec<Replay> = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for trace in recorded {
        assert_eq!(run(trace.schedule.clone()), trace);
    }
    eprintln!("UI assembly replay corpus: {}", path.display());
}
