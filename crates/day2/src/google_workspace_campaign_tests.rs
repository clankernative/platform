//! A seeded campaign of the share against an independent ordered model, as
//! the Linear campaign runs (docs/LINEAR-SIMULATION.md): fixed seeds, every
//! history run twice and compared, and a model that predicts every
//! permission the world holds after every step. Histories compose meetings
//! and rejoins, artifact progression, faults (lost replies among them),
//! duplicate deliveries, forged organizers, another event's artifacts and a
//! calendar leaving play. Failure bundles hold only a format, the campaign
//! digest and the seed.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const SEEDS: u64 = 6;
const STEPS: usize = 30;
const GROUPS: [&str; 3] = [
    "engineering@synthetic.example",
    "platform@synthetic.example",
    "empty@synthetic.example",
];

/// Every artifact the campaign shares, the event it belongs to, and that
/// event's derived owner.
const ARTIFACTS: [(&str, &str, &str); 5] = [
    (
        "conferenceRecords/conf-standup-1/recordings/rec-1",
        "standup0001",
        "ada@synthetic.example",
    ),
    (
        "conferenceRecords/conf-standup-1/transcripts/tr-1",
        "standup0001",
        "ada@synthetic.example",
    ),
    (
        "conferenceRecords/conf-standup-1/smartNotes/note-1",
        "standup0001",
        "ada@synthetic.example",
    ),
    (
        "conferenceRecords/conf-standup-2/recordings/rec-2",
        "standup0001",
        "ada@synthetic.example",
    ),
    (
        "conferenceRecords/conf-review-1/recordings/rec-r",
        "review0002",
        "grace@synthetic.example",
    ),
];

/// The world the model is independent of: the development organization, an
/// event whose in-domain organizer did not create it, and a recording of the
/// review that Meet has only started.
fn organization() -> GoogleWorkspaceWorld {
    let mut world = simulated::google_workspace_development_fixture();
    let calendar = world.calendars.get_mut(CALENDAR).unwrap();
    let mut forged = calendar.events[0].clone();
    forged.id = "forged0001".into();
    forged.creator = Some("grace@synthetic.example".into());
    calendar.events.push(forged);
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
}

/// What the model knows: each artifact's state, whether the calendar is in
/// play, and every share that has landed.
struct Model {
    states: BTreeMap<&'static str, &'static str>,
    in_play: bool,
    shared: BTreeSet<(&'static str, &'static str)>,
}

impl Model {
    fn new() -> Self {
        Self {
            states: BTreeMap::from([
                (ARTIFACTS[0].0, "FILE_GENERATED"),
                (ARTIFACTS[1].0, "FILE_GENERATED"),
                (ARTIFACTS[2].0, "ENDED"),
                (ARTIFACTS[3].0, "STARTED"),
                (ARTIFACTS[4].0, "STARTED"),
            ]),
            in_play: true,
            shared: BTreeSet::new(),
        }
    }

    /// The answer a share must give, and whether a permission lands.
    fn share(
        &mut self,
        event: &str,
        artifact: &'static str,
        group: &'static str,
        fault: Option<SimulatedFault>,
    ) -> &'static str {
        let owned_by = ARTIFACTS
            .iter()
            .find(|(name, ..)| *name == artifact)
            .unwrap()
            .1;
        if !self.in_play {
            return "NotShared";
        }
        if event == "forged0001" {
            return "NoOwner";
        }
        if owned_by != event {
            return "NotFound";
        }
        if self.states[artifact] != "FILE_GENERATED" {
            return "NotReady";
        }
        if self.shared.contains(&(artifact, group)) {
            return "AlreadyShared";
        }
        match fault {
            // Served, so the permission lands; the reply is lost.
            Some(SimulatedFault::ReplyLost) => {
                self.shared.insert((artifact, group));
                "share_outcome_unknown"
            }
            // Refused before it was served: nothing lands, nothing is known.
            Some(SimulatedFault::ServerError) => "share_outcome_unknown",
            Some(_) => "denied",
            None => {
                self.shared.insert((artifact, group));
                "Shared"
            }
        }
    }

    fn advance(&mut self, artifact: &'static str) {
        let next = match self.states[artifact] {
            "STARTED" => "ENDED",
            _ => "FILE_GENERATED",
        };
        self.states.insert(artifact, next);
    }
}

fn answer(result: &Result<String>) -> String {
    match result {
        Ok(json) => {
            let value: serde_json::Value = serde_json::from_str(json).unwrap();
            value
                .as_str()
                .map(str::to_owned)
                .or_else(|| value.as_object().and_then(|map| map.keys().next().cloned()))
                .unwrap_or_default()
        }
        Err(error) => error
            .to_string()
            .trim_start_matches("google_workspace_")
            .to_owned(),
    }
}

/// The world's group permissions must be exactly the model's shares: each a
/// group `reader` in a grantee domain, on the file Meet named for that
/// artifact of that event, created as that event's derived owner, and never
/// twice.
fn check(world: &World, model: &Model) -> Result<()> {
    let state = world.state().world;
    let file_of = |artifact: &str| -> Option<String> {
        let (record, collection, id) = crate::google_workspace_meet::parse_artifact_name(artifact)?;
        let record = &state.conference_records[record];
        let artifacts = match collection.segment() {
            "recordings" => &record.recordings,
            "smartNotes" => &record.smart_notes,
            _ => &record.transcripts,
        };
        artifacts.iter().find(|item| item.id == id)?.file.clone()
    };
    let mut expected: Vec<(String, String, String)> = model
        .shared
        .iter()
        .map(|(artifact, group)| {
            let owner = ARTIFACTS
                .iter()
                .find(|(name, ..)| name == artifact)
                .unwrap()
                .2;
            (
                file_of(artifact).unwrap_or_default(),
                (*group).to_owned(),
                owner.to_owned(),
            )
        })
        .collect();
    expected.sort();
    let mut actual = Vec::new();
    for (file, found) in &state.drive_files {
        for permission in found.permissions.iter().filter(|p| p.kind == "group") {
            let group = permission.email_address.clone().unwrap_or_default();
            ensure!(
                permission.role == "reader"
                    && !permission.deleted
                    && group.ends_with("@synthetic.example"),
                "a permission the platform must never create"
            );
            actual.push((
                file.clone(),
                group,
                permission.created_by.clone().unwrap_or_default(),
            ));
        }
    }
    actual.sort();
    ensure!(
        actual == expected,
        "world {actual:?} differs from model {expected:?}"
    );
    Ok(())
}

/// One history: a fixed prefix that witnesses every outcome, then seeded
/// steps. Each step's observation is its kind and answer.
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
                 artifact: &'static str,
                 group: &'static str,
                 fault: Option<SimulatedFault>|
     -> Result<String> {
        if let Some(fault) = fault {
            world.fault(simulated::GOOGLE_DRIVE_SHARE_ENDPOINT, fault);
        }
        let plan = super::share::share(event, artifact, group);
        let (result, meter) = world.observe(&plan);
        let expected = model.share(event, artifact, group, fault);
        let answered = answer(&result);
        ensure!(
            answered == expected,
            "share {event} {artifact} {group} {fault:?}: {answered} != {expected}"
        );
        ensure!(meter.unknown == (expected == "share_outcome_unknown"));
        // A fault the share never reached stays queued; clear it.
        simulated::update_google_workspace(&world.database, SCOPE, |state| {
            state.faults.clear();
            Ok(())
        })?;
        check(world, model)?;
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
    let [rec1, tr1, _, rec2, recr] = ARTIFACTS.map(|(name, ..)| name);
    let [eng, platform, _] = GROUPS;
    // Every outcome once, including a duplicate delivery and a reply lost
    // after the permission landed, and its retry.
    observed.push(share(&world, &mut model, "standup0001", rec1, eng, None)?);
    observed.push(share(&world, &mut model, "standup0001", rec1, eng, None)?);
    observed.push(share(&world, &mut model, "standup0001", rec2, eng, None)?);
    observed.push(share(
        &world,
        &mut model,
        "forged0001",
        rec1,
        platform,
        None,
    )?);
    observed.push(share(&world, &mut model, "standup0001", recr, eng, None)?);
    observed.push(in_play(&world, &mut model, false)?);
    observed.push(share(&world, &mut model, "standup0001", tr1, eng, None)?);
    observed.push(in_play(&world, &mut model, true)?);
    let lost = Some(SimulatedFault::ReplyLost);
    observed.push(share(&world, &mut model, "standup0001", tr1, eng, lost)?);
    observed.push(share(&world, &mut model, "standup0001", tr1, eng, None)?);
    let failed = Some(SimulatedFault::ServerError);
    observed.push(share(
        &world,
        &mut model,
        "standup0001",
        tr1,
        platform,
        failed,
    )?);
    let denied = Some(SimulatedFault::Denied);
    observed.push(share(
        &world,
        &mut model,
        "standup0001",
        tr1,
        platform,
        denied,
    )?);
    while observed.len() < STEPS {
        match next(10) {
            0 | 1 => {
                let artifact = ARTIFACTS[next(ARTIFACTS.len())].0;
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
            choice => {
                let (artifact, event, _) = ARTIFACTS[next(ARTIFACTS.len())];
                let group = GROUPS[next(GROUPS.len())];
                let event = match choice {
                    3 => "forged0001",
                    4 if event == "standup0001" => "review0002",
                    4 => "standup0001",
                    _ => event,
                };
                let fault = [
                    None,
                    None,
                    None,
                    Some(SimulatedFault::ReplyLost),
                    Some(SimulatedFault::ServerError),
                    Some(SimulatedFault::Denied),
                ][next(6)];
                let answered = share(&world, &mut model, event, artifact, group, fault)?;
                observed.push(answered.clone());
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
    for seed in 0..SEEDS {
        let observed = checked_history(seed)?;
        ensure!(observed.len() >= STEPS, "share campaign incomplete");
        seen.extend(observed.into_iter().filter(|step| !step.contains(' ')));
    }
    for outcome in [
        "Shared",
        "AlreadyShared",
        "NotReady",
        "NoOwner",
        "NotFound",
        "NotShared",
        "share_outcome_unknown",
        "denied",
        "in_play",
        "out_of_play",
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
