//! A seeded campaign of the share against an independent ordered model,
//! modelled on the Linear campaign (docs/LINEAR-SIMULATION.md): fixed seeds,
//! every history run twice and compared, and a model that predicts every
//! answer and every permission the world holds after every step. Histories
//! compose meetings and rejoins, artifact progression, duplicate deliveries,
//! forged organizers, aliases and unknown groups, another event of the same
//! owner, a calendar leaving play, restricted sharing, and faults on the
//! create that the attempt reconciles. A history ends at its first unknown
//! outcome: its reservation stays held until an operator reconciles it,
//! which the campaign does not model. Failure bundles hold only a format,
//! the campaign digest and the seed.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const SEEDS: u64 = 6;
const STEPS: usize = 40;
const ENGINEERING: &str = "engineering@synthetic.example";
const PLATFORM: &str = "platform@synthetic.example";
/// An alias of engineering, and a group nobody has.
const ALIAS: &str = "eng-alias@synthetic.example";
const MISSING: &str = "missing@synthetic.example";
const GROUPS: [&str; 5] = [
    ENGINEERING,
    PLATFORM,
    "empty@synthetic.example",
    ALIAS,
    MISSING,
];

/// The oracle: every artifact the campaign shares, written out rather than
/// parsed from its name, with the event it belongs to and that event's
/// derived owner.
struct Artifact {
    name: &'static str,
    record: &'static str,
    collection: &'static str,
    id: &'static str,
    event: &'static str,
    owner: &'static str,
}

const fn artifact(
    name: &'static str,
    record: &'static str,
    collection: &'static str,
    id: &'static str,
    event: &'static str,
    owner: &'static str,
) -> Artifact {
    Artifact {
        name,
        record,
        collection,
        id,
        event,
        owner,
    }
}

const ADA: &str = "ada@synthetic.example";
const ARTIFACTS: [Artifact; 6] = [
    artifact(
        "conferenceRecords/conf-standup-1/recordings/rec-1",
        "conf-standup-1",
        "recordings",
        "rec-1",
        "standup0001",
        ADA,
    ),
    artifact(
        "conferenceRecords/conf-standup-1/transcripts/tr-1",
        "conf-standup-1",
        "transcripts",
        "tr-1",
        "standup0001",
        ADA,
    ),
    artifact(
        "conferenceRecords/conf-standup-1/smartNotes/note-1",
        "conf-standup-1",
        "smartNotes",
        "note-1",
        "standup0001",
        ADA,
    ),
    artifact(
        "conferenceRecords/conf-standup-2/recordings/rec-2",
        "conf-standup-2",
        "recordings",
        "rec-2",
        "standup0001",
        ADA,
    ),
    artifact(
        "conferenceRecords/conf-planning-1/recordings/rec-p",
        "conf-planning-1",
        "recordings",
        "rec-p",
        "planning0004",
        ADA,
    ),
    artifact(
        "conferenceRecords/conf-review-1/recordings/rec-r",
        "conf-review-1",
        "recordings",
        "rec-r",
        "review0002",
        "grace@synthetic.example",
    ),
];
const EVENTS: [&str; 4] = ["standup0001", "planning0004", "review0002", "forged0001"];

/// The world the model is independent of: the development organization, an
/// event whose in-domain organizer did not create it, a second meeting of
/// ada's with its own space, an alias of engineering, and a recording of the
/// review that Meet has only started. Sharing one of ada's artifacts under
/// the other of her events is refused only by the check that the artifact's
/// record belongs to the event: as ada, Meet and Drive would both allow it.
fn organization() -> GoogleWorkspaceWorld {
    let mut world = simulated::google_workspace_development_fixture();
    let calendar = world.calendars.get_mut(CALENDAR).unwrap();
    let mut forged = calendar.events[0].clone();
    forged.id = "forged0001".into();
    forged.creator = Some("grace@synthetic.example".into());
    let mut planning = calendar.events[0].clone();
    planning.id = "planning0004".into();
    planning.start = Some(simulated::GoogleTime::at("2026-01-08T09:00:00Z"));
    planning.end = Some(simulated::GoogleTime::at("2026-01-08T09:30:00Z"));
    planning.conference_id = Some("pqr-stuv-wxy".into());
    calendar.events.extend([forged, planning]);
    world.spaces.insert(
        "spacePlanning1".into(),
        simulated::GoogleSpace {
            meeting_code: "pqr-stuv-wxy".into(),
            owner: ADA.into(),
        },
    );
    world.conference_records.insert(
        "conf-planning-1".into(),
        simulated::GoogleConferenceRecord {
            space: "spacePlanning1".into(),
            start_time: "2026-01-08T09:01:00Z".into(),
            recordings: vec![simulated::GoogleArtifact {
                id: "rec-p".into(),
                state: "ENDED".into(),
                file: None,
            }],
            ..Default::default()
        },
    );
    world
        .conference_records
        .get_mut("conf-review-1")
        .unwrap()
        .recordings
        .push(simulated::GoogleArtifact {
            id: "rec-r".into(),
            state: "STARTED".into(),
            file: None,
        });
    world
        .groups
        .get_mut(ENGINEERING)
        .unwrap()
        .aliases
        .insert(ALIAS.into());
    world
}

/// What the model knows: each artifact's state, whether the calendar is in
/// play, whether sharing is restricted, and every share that has landed.
struct Model {
    states: BTreeMap<&'static str, &'static str>,
    in_play: bool,
    restricted: bool,
    shared: BTreeSet<(&'static str, &'static str)>,
}

impl Model {
    fn new() -> Self {
        Self {
            states: ARTIFACTS
                .iter()
                .zip([
                    "FILE_GENERATED",
                    "FILE_GENERATED",
                    "ENDED",
                    "STARTED",
                    "ENDED",
                    "STARTED",
                ])
                .map(|(artifact, state)| (artifact.name, state))
                .collect(),
            in_play: true,
            restricted: false,
            shared: BTreeSet::new(),
        }
    }

    /// The answer a share must give, and whether a permission lands.
    fn share(
        &mut self,
        event: &str,
        artifact: &Artifact,
        group: &'static str,
        fault: Option<SimulatedFault>,
    ) -> &'static str {
        if !self.in_play {
            return "NotShared";
        }
        if event == "forged0001" {
            return "NoOwner";
        }
        match group {
            ALIAS => return "GroupNotPrimary",
            MISSING => return "GroupNotFound",
            _ => {}
        }
        if artifact.event != event {
            return "NotFound";
        }
        if self.states[artifact.name] != "FILE_GENERATED" {
            return "NotReady";
        }
        let key = (artifact.name, group);
        if self.shared.contains(&key) {
            return "AlreadyShared";
        }
        // A served create lands unless sharing is restricted; the attempt
        // lists again whenever it cannot read the answer.
        let lands = !self.restricted;
        let answer = match fault {
            None if self.restricted => "SharingRefused",
            None | Some(SimulatedFault::ReplyLost) if lands => "Shared",
            Some(SimulatedFault::Conflict) if lands => "AlreadyShared",
            Some(SimulatedFault::Denied) => return "denied",
            _ => return "share_outcome_unknown",
        };
        if lands && answer != "SharingRefused" {
            self.shared.insert(key);
        }
        answer
    }

    fn advance(&mut self, artifact: &'static str) {
        let next = match self.states[artifact] {
            "STARTED" => "ENDED",
            _ => "FILE_GENERATED",
        };
        self.states.insert(artifact, next);
    }
}

/// The world's group permissions as `(file, group, created by)`.
fn group_permissions(world: &World) -> Vec<(String, String, String)> {
    let state = world.state().world;
    let mut found = Vec::new();
    for (file, item) in &state.drive_files {
        for permission in item.permissions.iter().filter(|p| p.kind == "group") {
            found.push((
                file.clone(),
                permission.email_address.clone().unwrap_or_default(),
                permission.created_by.clone().unwrap_or_default(),
            ));
        }
    }
    found.sort();
    found
}

/// The file Meet named for an artifact, looked up by the oracle's record,
/// collection and ID.
fn file_of(world: &World, artifact: &Artifact) -> Option<String> {
    let state = world.state().world;
    let record = state.conference_records.get(artifact.record)?;
    let artifacts = match artifact.collection {
        "recordings" => &record.recordings,
        "smartNotes" => &record.smart_notes,
        _ => &record.transcripts,
    };
    artifacts
        .iter()
        .find(|item| item.id == artifact.id)?
        .file
        .clone()
}

/// The world's group permissions must be exactly the model's shares: each a
/// group `reader` in a grantee domain, on the file Meet named for that
/// artifact of that event, created as that event's derived owner, and never
/// twice.
fn check(world: &World, model: &Model) -> Result<()> {
    let state = world.state().world;
    let mut expected: Vec<(String, String, String)> = model
        .shared
        .iter()
        .map(|(name, group)| {
            let artifact = ARTIFACTS.iter().find(|item| item.name == *name).unwrap();
            (
                file_of(world, artifact).unwrap_or_default(),
                (*group).to_owned(),
                artifact.owner.to_owned(),
            )
        })
        .collect();
    expected.sort();
    for found in state.drive_files.values() {
        for permission in found.permissions.iter().filter(|p| p.kind == "group") {
            ensure!(
                permission.role == "reader"
                    && !permission.deleted
                    && permission
                        .email_address
                        .as_deref()
                        .is_some_and(|group| group.ends_with("@synthetic.example")),
                "a permission the platform must never create"
            );
        }
    }
    let actual = group_permissions(world);
    ensure!(
        actual == expected,
        "world {actual:?} differs from model {expected:?}"
    );
    Ok(())
}

/// One history: a fixed prefix that witnesses every definite outcome, then
/// seeded steps until `STEPS` or the first unknown outcome. Each step's
/// observation is its kind and answer.
fn history(seed: u64) -> Result<Vec<String>> {
    let world = World::new(organization());
    let mut model = Model::new();
    let mut observed = Vec::new();
    let mut random = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut next = |bound: usize| {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        (random % bound as u64) as usize
    };
    let share = |world: &World,
                 model: &mut Model,
                 event: &'static str,
                 artifact: &Artifact,
                 group: &'static str,
                 fault: Option<SimulatedFault>|
     -> Result<String> {
        if let Some(fault) = fault {
            world.fault(simulated::GOOGLE_DRIVE_SHARE_ENDPOINT, fault);
        }
        let before = group_permissions(world);
        let (result, meter) = world.observe(&super::share::share(event, artifact.name, group));
        let expected = model.share(event, artifact, group, fault);
        let answered = super::share::answer(&result);
        // The world first, whatever the answer: `Shared` only when the group
        // held nothing on that file before the attempt, and then exactly the
        // permissions the model predicts.
        let file = file_of(world, artifact).unwrap_or_default();
        ensure!(
            answered != "Shared"
                || !before
                    .iter()
                    .any(|(held, holder, _)| *held == file && holder == group),
            "Shared for a permission that already existed: {event} {}",
            artifact.name
        );
        check(world, model)?;
        ensure!(
            answered == expected,
            "share {event} {} {group} {fault:?}: {answered} != {expected}",
            artifact.name
        );
        ensure!(meter.unknown == (expected == "share_outcome_unknown"));
        // A fault the share never reached stays queued; clear it.
        simulated::update_google_workspace(&world.database, SCOPE, |state| {
            state.faults.clear();
            Ok(())
        })?;
        Ok(answered)
    };
    let in_play = |world: &World, model: &mut Model, play: bool| -> Result<String> {
        simulated::update_google_workspace(&world.database, SCOPE, |state| {
            // Out of play the reader still sees the calendar, with a rule
            // that does not put it in play.
            let acl = &mut state.world.calendars.get_mut(CALENDAR).unwrap().acl;
            acl.retain(|rule| rule.scope_value.as_deref() != Some(READER));
            acl.push(rule(
                "user",
                Some(READER),
                if play { "writer" } else { "reader" },
            ));
            Ok(())
        })?;
        model.in_play = play;
        Ok(if play { "in_play" } else { "out_of_play" }.into())
    };
    // Restricted sharing trusts only a domain no group is in.
    let restrict = |world: &World, model: &mut Model, restricted: bool| -> Result<String> {
        simulated::update_google_workspace(&world.database, SCOPE, |state| {
            state.world.drive_trusted_domains = if restricted {
                BTreeSet::from(["other.example".to_owned()])
            } else {
                BTreeSet::new()
            };
            Ok(())
        })?;
        model.restricted = restricted;
        Ok(if restricted {
            "restricted"
        } else {
            "unrestricted"
        }
        .into())
    };
    let [rec1, tr1, _, rec2, recp, recr] = &ARTIFACTS;
    let (standup, planning) = ("standup0001", "planning0004");
    use SimulatedFault::{Conflict, Denied, ReplyLost};
    // Every definite outcome once: a duplicate delivery, a foreign artifact
    // under each of the other events (first one of ada's own other meeting,
    // which she could share, to a group it is not yet shared with), refused
    // groups, the calendar out of play, restricted sharing, and a lost reply
    // and a conflict that the attempt reconciles.
    for (event, artifact, group, fault) in [
        (standup, rec1, ENGINEERING, None),
        (standup, rec1, ENGINEERING, None),
        (standup, rec2, ENGINEERING, None),
        ("forged0001", rec1, PLATFORM, None),
        (planning, rec1, PLATFORM, None),
        (standup, recr, ENGINEERING, None),
        (standup, recp, ENGINEERING, None),
        (standup, tr1, ALIAS, None),
        (standup, tr1, MISSING, None),
    ] {
        observed.push(share(&world, &mut model, event, artifact, group, fault)?);
    }
    observed.push(in_play(&world, &mut model, false)?);
    observed.push(share(&world, &mut model, standup, tr1, ENGINEERING, None)?);
    observed.push(in_play(&world, &mut model, true)?);
    observed.push(restrict(&world, &mut model, true)?);
    observed.push(share(&world, &mut model, standup, tr1, ENGINEERING, None)?);
    observed.push(share(&world, &mut model, standup, rec1, ENGINEERING, None)?);
    observed.push(restrict(&world, &mut model, false)?);
    for (artifact, group, fault) in [
        (tr1, ENGINEERING, Some(ReplyLost)),
        (tr1, ENGINEERING, None),
        (tr1, PLATFORM, Some(Conflict)),
        (rec1, PLATFORM, Some(Denied)),
    ] {
        observed.push(share(&world, &mut model, standup, artifact, group, fault)?);
    }
    while observed.len() < STEPS {
        match next(12) {
            0 | 1 => {
                let artifact = ARTIFACTS[next(ARTIFACTS.len())].name;
                if model.states[artifact] == "FILE_GENERATED" {
                    continue;
                }
                simulated::update_google_workspace(&world.database, SCOPE, |state| {
                    simulated::google_meet_advance(&mut state.world, artifact)
                })?;
                model.advance(artifact);
                observed.push(format!("advance {artifact}"));
            }
            2 => {
                let play = !model.in_play;
                observed.push(in_play(&world, &mut model, play)?);
            }
            3 => {
                let restricted = !model.restricted;
                observed.push(restrict(&world, &mut model, restricted)?);
            }
            choice => {
                let artifact = &ARTIFACTS[next(ARTIFACTS.len())];
                let group = GROUPS[next(GROUPS.len())];
                // Mostly the artifact's own event, sometimes any other.
                let event = if choice < 6 {
                    EVENTS[next(EVENTS.len())]
                } else {
                    artifact.event
                };
                let fault = [
                    None,
                    None,
                    None,
                    None,
                    Some(ReplyLost),
                    Some(Conflict),
                    Some(Denied),
                    Some(SimulatedFault::ServerError),
                    Some(SimulatedFault::ConnectionLost),
                ][next(9)];
                let answered = share(&world, &mut model, event, artifact, group, fault)?;
                observed.push(answered.clone());
                // The effect holds its budget until an operator reconciles
                // it; nothing more runs on it.
                if answered == "share_outcome_unknown" {
                    break;
                }
                // A duplicate delivery of what just landed finds it.
                if answered == "Shared" && next(2) == 0 {
                    observed.push(share(&world, &mut model, event, artifact, group, None)?);
                }
            }
        }
    }
    Ok(observed)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaySeed {
    format: u32,
    campaign_source: String,
    seed: u64,
}

fn campaign_source() -> String {
    crate::digest(include_bytes!("google_workspace_campaign_tests.rs"))
}

fn checked_history(seed: u64) -> Result<Vec<String>> {
    let result = (|| {
        let first = history(seed)?;
        ensure!(history(seed)? == first, "share history is not replayable");
        Ok(first)
    })();
    if result.is_err() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/google-workspace-share-simulation");
        std::fs::create_dir_all(&root)?;
        let directory = tempfile::Builder::new()
            .prefix("failure-")
            .tempdir_in(root)?
            .keep();
        std::fs::write(
            directory.join("failure.json"),
            serde_json::to_vec(&ReplaySeed {
                format: 1,
                campaign_source: campaign_source(),
                seed,
            })?,
        )?;
    }
    result
}

fn replay_seed(bytes: &[u8]) -> Result<u64> {
    ensure!(bytes.len() <= 4096, "share replay byte bound");
    let value: ReplaySeed = crate::json::decode(bytes)?;
    ensure!(
        value.format == 1 && value.campaign_source == campaign_source(),
        "share replay source or format differs"
    );
    Ok(value.seed)
}

#[test]
fn seeded_share_histories_match_the_independent_model_and_replay() -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut complete = 0;
    for seed in 0..SEEDS {
        let observed = checked_history(seed)?;
        ensure!(
            observed.len() >= STEPS
                || observed.last().map(String::as_str) == Some("share_outcome_unknown"),
            "share campaign incomplete"
        );
        complete += usize::from(observed.len() >= STEPS);
        seen.extend(observed.into_iter().filter(|step| !step.contains(' ')));
    }
    ensure!(complete > 0, "every share history ended early");
    for outcome in [
        "Shared",
        "AlreadyShared",
        "NotReady",
        "NoOwner",
        "NotFound",
        "NotShared",
        "GroupNotPrimary",
        "GroupNotFound",
        "SharingRefused",
        "share_outcome_unknown",
        "denied",
        "in_play",
        "out_of_play",
        "restricted",
        "unrestricted",
    ] {
        ensure!(
            seen.contains(outcome),
            "the campaign never observed {outcome}"
        );
    }
    // Bundles hold the format, the digest and the seed, and nothing else.
    let mut bundle = serde_json::json!({"format":1,"campaign_source":campaign_source(),"seed":3});
    ensure!(replay_seed(&serde_json::to_vec(&bundle)?)? == 3);
    bundle["provider_payload"] = serde_json::json!("forbidden");
    ensure!(replay_seed(&serde_json::to_vec(&bundle)?).is_err());
    bundle = serde_json::json!({"format":1,"campaign_source":"changed","seed":3});
    ensure!(replay_seed(&serde_json::to_vec(&bundle)?).is_err());
    Ok(())
}

#[test]
fn replay_saved_share_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_GOOGLE_WORKSPACE_SHARE_REPLAY") else {
        return Ok(());
    };
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    checked_history(replay_seed(&bytes)?)?;
    Ok(())
}
