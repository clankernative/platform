//! Explicit live Google Workspace qualification. An operator runs it with a
//! reviewed, expiring profile and an owner-private file holding their own
//! short-lived access token; it is never part of verify.
//! `ops/GoogleWorkspaceQualification.roc` owns step order through
//! `ops/Runner.roc`. This session supplies only the closed native steps:
//! opening the bounded inputs, each probe step of
//! [`day2::google_workspace_qualification`], which enforces its own
//! preconditions, dropping the run, and the mandatory evidence guards. The
//! receipt holds counts, closed classifications and reviewed names only, and
//! every run reports `provider_qualified: false` until a reviewer accepts its
//! evidence.
use super::*;
use crate::qualification_evidence as evidence;
use day2::{
    automation::Request,
    google_workspace_qualification::{self as qualification, Admitted, Step},
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const RECEIPT: &str = "receipt.json";
/// Written before the share step can send its create, so a run killed later
/// still shows that a permission may exist.
const SHARE_STARTED: &str = "share-started.json";
const PREFIX: &str = "google-workspace-qualification-";

/// One run's provider steps.
pub trait Qualify {
    fn step(&mut self, step: Step) -> Result<Value>;
    fn finish(self: Box<Self>) -> Result<Value>;
}

impl Qualify for qualification::Qualification {
    fn step(&mut self, step: Step) -> Result<Value> {
        qualification::Qualification::step(self, step)
    }

    fn finish(self: Box<Self>) -> Result<Value> {
        qualification::Qualification::finish(*self)
    }
}

/// The provider capability: a run of an admitted profile with the operator's
/// token.
pub type Start = dyn FnMut(Admitted, String) -> Result<Box<dyn Qualify>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Start,
    Running,
    Discarded,
    Complete,
    Failed,
}

pub struct Session {
    profile_path: PathBuf,
    token_path: PathBuf,
    evidence: PathBuf,
    phase: Phase,
    token: Option<String>,
    /// Every string of the profile, which the receipt may not contain.
    values: Vec<String>,
    run: Option<Box<dyn Qualify>>,
    receipt: Option<Value>,
    start: Box<Start>,
}

impl Session {
    pub fn new(profile: &Path, token: &Path, evidence: &Path, start: Box<Start>) -> Self {
        Self {
            profile_path: profile.into(),
            token_path: token.into(),
            evidence: evidence.into(),
            phase: Phase::Start,
            token: None,
            values: Vec::new(),
            run: None,
            receipt: None,
            start,
        }
    }

    /// One recipe step, with no arguments. Open, discard and receipt run once
    /// and in that order around the run's own steps, whose preconditions the
    /// run enforces. A failed step closes the session: the run, with its port
    /// and every provider value it held, and the token are dropped.
    pub fn effect(&mut self, request: Request) -> Result<Value> {
        ensure!(request.protocol == 1, "unsupported workflow protocol");
        ensure!(
            request.decode::<Value>()? == json!({}),
            "google workspace qualification steps accept only an empty object"
        );
        let unsupported = || {
            anyhow::anyhow!(
                "unsupported google workspace qualification step: {}",
                request.action
            )
        };
        let name = request
            .action
            .strip_prefix(PREFIX)
            .ok_or_else(unsupported)?;
        let (expected, next, step) = match name {
            "open" => (Phase::Start, Phase::Running, None),
            "discard" => (Phase::Running, Phase::Discarded, None),
            "receipt" => (Phase::Discarded, Phase::Complete, None),
            other => (
                Phase::Running,
                Phase::Running,
                Some(Step::named(other).ok_or_else(unsupported)?),
            ),
        };
        ensure!(
            self.phase == expected,
            "google workspace qualification step out of order or replayed"
        );
        // Fence before any filesystem or provider operation.
        self.phase = Phase::Failed;
        let result = match (name, step) {
            ("open", _) => self.open(),
            ("discard", _) => self.discard(),
            ("receipt", _) => self.publish(),
            (_, Some(step)) => self.step(step),
            _ => Err(unsupported()),
        };
        match result {
            Ok(value) => {
                self.phase = next;
                Ok(value)
            }
            Err(error) => {
                self.run = None;
                self.token = None;
                self.values.clear();
                self.receipt = None;
                Err(error)
            }
        }
    }

    /// Admit the profile from its exact bytes, then read and shape-check the
    /// token, and only then create the new owner-private evidence directory
    /// and the run.
    fn open(&mut self) -> Result<Value> {
        let profile = evidence::bounded(&self.profile_path, false)?;
        let admitted = qualification::admit(&profile, evidence::now()?)?;
        let token = String::from_utf8(evidence::bounded(&self.token_path, true)?)
            .context("token encoding")?
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        qualification::token_shape(&token)?;
        evidence::create_directory(&self.evidence)?;
        self.values = admitted.values();
        self.run = Some((self.start)(admitted, token.clone())?);
        self.token = Some(token);
        Ok(json!({}))
    }

    /// One of the run's steps. Before the share, a durable marker records that
    /// a create may be sent.
    fn step(&mut self, step: Step) -> Result<Value> {
        let run = self.run.as_mut().context("run not opened")?;
        if step == Step::Share {
            evidence::publish(
                &self.evidence,
                SHARE_STARTED,
                &serde_json::to_vec(&json!({"format":1,"share_started_at":evidence::now()?}))?,
            )?;
        }
        run.step(step)
    }

    /// End the run: its receipt is kept, and the run, with the port, its copy
    /// of the token and every provider value it held, is dropped.
    fn discard(&mut self) -> Result<Value> {
        let run = self.run.take().context("run not opened")?;
        self.receipt = Some(run.finish()?);
        Ok(json!({}))
    }

    /// The mandatory evidence guards, then a create-new 0600 receipt. The
    /// receipt may hold none of the token or the profile's own values: each
    /// fixture is named by its role, never its address or ID.
    fn publish(&mut self) -> Result<Value> {
        let receipt = self.receipt.take().context("receipt not collected")?;
        let token = self.token.take().context("token not opened")?;
        let values = std::mem::take(&mut self.values);
        ensure!(self.run.is_none(), "run not discarded");
        ensure!(
            receipt["provider_qualified"] == false,
            "unexpected provider qualification claim"
        );
        let bytes = serde_json::to_vec_pretty(&receipt)?;
        evidence::refuse_containing(
            &bytes,
            &token,
            "receipt refused: it contains the access token",
        )?;
        drop(token);
        for value in values.iter().filter(|value| !value.is_empty()) {
            evidence::refuse_containing(
                &bytes,
                value,
                "receipt refused: it contains a profile value",
            )?;
        }
        evidence::publish(&self.evidence, RECEIPT, &bytes)?;
        Ok(json!({ "creates_sent": receipt["creates_sent"] }))
    }

    pub fn finish(&self) -> Result<PathBuf> {
        ensure!(
            self.phase == Phase::Complete,
            "google workspace qualification incomplete"
        );
        Ok(self.evidence.join(RECEIPT))
    }
}

pub fn execute(root: &Path, profile: &Path, token: &Path, evidence: &Path) -> Result<()> {
    let runner = workflows::build(root)?;
    let mut session = Session::new(
        profile,
        token,
        evidence,
        Box::new(|admitted, token| {
            // The one reviewed call site of the native run.
            Ok(
                Box::new(qualification::Qualification::native(admitted, token)?)
                    as Box<dyn Qualify>,
            )
        }),
    );
    day2::automation::run(&runner, &["google-workspace-qualification"], |request| {
        session.effect(request)
    })?;
    let receipt = session.finish()?;
    println!(
        "google workspace qualification receipt: {}",
        receipt.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    const TOKEN: &str = "operator-token-for-tests";
    /// The recipe's order when the first check finds the permission.
    const STEPS: [&str; 11] = [
        "google-workspace-qualification-open",
        "google-workspace-qualification-directory",
        "google-workspace-qualification-calendars",
        "google-workspace-qualification-events",
        "google-workspace-qualification-event",
        "google-workspace-qualification-conferences",
        "google-workspace-qualification-share-alias",
        "google-workspace-qualification-share",
        "google-workspace-qualification-check",
        "google-workspace-qualification-discard",
        "google-workspace-qualification-receipt",
    ];

    fn request(action: &str, input: &str) -> Request {
        Request {
            protocol: 1,
            action: action.into(),
            input: input.into(),
        }
    }

    struct Inputs {
        directory: tempfile::TempDir,
        profile: PathBuf,
        token: PathBuf,
        evidence: PathBuf,
    }

    /// The rehearsal profile and a token file, without seeding a world.
    fn inputs(profile: &[u8], token: &str) -> Result<Inputs> {
        let directory = tempfile::tempdir()?;
        let profile_path = directory.path().join("profile.json");
        fs::write(&profile_path, profile)?;
        let token_path = directory.path().join("token");
        fs::write(&token_path, format!("{token}\n"))?;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))?;
        let evidence = directory.path().join("evidence");
        Ok(Inputs {
            directory,
            profile: profile_path,
            token: token_path,
            evidence,
        })
    }

    /// A run that answers fixed values and records whether it was dropped.
    struct Fake {
        receipt: Value,
        fail: Option<Step>,
        dropped: std::rc::Rc<std::cell::Cell<bool>>,
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    impl Qualify for Fake {
        fn step(&mut self, step: Step) -> Result<Value> {
            ensure!(self.fail != Some(step), "{step:?} failed");
            Ok(match step {
                Step::Share => json!({"check":true}),
                Step::Check => json!({"visible":true}),
                _ => json!({}),
            })
        }

        fn finish(self: Box<Self>) -> Result<Value> {
            Ok(self.receipt.clone())
        }
    }

    fn fake(
        inputs: &Inputs,
        receipt: Value,
        fail: Option<Step>,
    ) -> (Session, std::rc::Rc<std::cell::Cell<bool>>) {
        let dropped = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = dropped.clone();
        let session = Session::new(
            &inputs.profile,
            &inputs.token,
            &inputs.evidence,
            Box::new(move |_, _| {
                Ok(Box::new(Fake {
                    receipt: receipt.clone(),
                    fail,
                    dropped: observed.clone(),
                }) as Box<dyn Qualify>)
            }),
        );
        (session, dropped)
    }

    /// The whole session against the simulated organization: the recipe's
    /// steps in order, one write, the marker before it, and a private receipt
    /// with no profile value or token.
    #[test]
    fn the_session_runs_end_to_end_and_publishes_a_private_receipt() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (database, profile, token) = qualification::simulated_rehearsal(directory.path())?;
        let inputs = inputs(&profile, &token)?;
        let mut session = Session::new(
            &inputs.profile,
            &inputs.token,
            &inputs.evidence,
            Box::new(move |admitted, token| {
                Ok(Box::new(qualification::Qualification::simulated(
                    admitted,
                    token,
                    &database,
                    "qualification",
                )?) as Box<dyn Qualify>)
            }),
        );
        for step in STEPS {
            session.effect(request(step, "{}"))?;
        }
        let path = session.finish()?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(&inputs.evidence)?.permissions().mode() & 0o777,
            0o700
        );
        let marker = inputs.evidence.join(SHARE_STARTED);
        assert_eq!(fs::metadata(&marker)?.permissions().mode() & 0o777, 0o600);
        let written: Value = serde_json::from_slice(&fs::read(&path)?)?;
        assert_eq!(written["creates_sent"], 1);
        assert_eq!(written["provider_qualified"], false);
        assert_eq!(written["profile_digest"], day2::digest(&profile));
        Ok(())
    }

    #[test]
    fn steps_are_refused_out_of_order_with_arguments_unknown_or_replayed() -> Result<()> {
        let inputs = inputs(&qualification::simulated_profile()?, TOKEN)?;
        let (mut session, _) = fake(&inputs, json!({"provider_qualified":false}), None);
        assert!(session.finish().is_err());
        for step in &STEPS[1..] {
            assert!(session.effect(request(step, "{}")).is_err(), "{step}");
        }
        let (mut session, _) = fake(&inputs, json!({"provider_qualified":false}), None);
        for refused in [
            request(STEPS[0], r#"{"profile":"other.json"}"#),
            request("google-workspace-qualification-retry", "{}"),
            request("carta-qualification-open", "{}"),
        ] {
            assert!(session.effect(refused).is_err());
        }
        assert!(!inputs.evidence.exists(), "nothing ran");
        let (mut session, _) = fake(&inputs, json!({"provider_qualified":false}), None);
        session.effect(request(STEPS[0], "{}"))?;
        assert!(session.effect(request(STEPS[0], "{}")).is_err(), "replayed");
        Ok(())
    }

    #[test]
    fn evidence_guards_refuse_a_claim_the_token_or_a_profile_value() -> Result<()> {
        let profile = qualification::simulated_profile()?;
        let unshared: Value = serde_json::from_slice(&profile)?;
        for (receipt, expected) in [
            (
                json!({"provider_qualified":true}),
                "unexpected provider qualification claim",
            ),
            (
                json!({"provider_qualified":false,"note":format!("x{TOKEN}x")}),
                "receipt refused: it contains the access token",
            ),
            (
                json!({"provider_qualified":false,"note":unshared["calendars"]["unshared"]}),
                "receipt refused: it contains a profile value",
            ),
        ] {
            let inputs = inputs(&profile, TOKEN)?;
            let (mut session, _) = fake(&inputs, receipt, None);
            for step in &STEPS[..10] {
                session.effect(request(step, "{}"))?;
            }
            let error = session
                .effect(request(STEPS[10], "{}"))
                .unwrap_err()
                .to_string();
            assert_eq!(error, expected);
            assert!(!inputs.evidence.join(RECEIPT).exists());
            assert!(session.finish().is_err());
        }
        Ok(())
    }

    #[test]
    fn a_failed_step_drops_the_run_and_closes_the_session() -> Result<()> {
        let inputs = inputs(&qualification::simulated_profile()?, TOKEN)?;
        let (mut session, dropped) = fake(&inputs, json!({}), Some(Step::Share));
        for step in &STEPS[..7] {
            session.effect(request(step, "{}"))?;
        }
        assert!(!dropped.get());
        assert!(session.effect(request(STEPS[7], "{}")).is_err());
        assert!(dropped.get(), "the run is dropped");
        assert!(
            inputs.evidence.join(SHARE_STARTED).exists(),
            "the marker precedes the create"
        );
        assert!(
            session.effect(request(STEPS[8], "{}")).is_err(),
            "a failed session stays closed"
        );
        Ok(())
    }

    #[test]
    fn inputs_are_admitted_before_the_token_is_read_or_evidence_created() -> Result<()> {
        let profile = qualification::simulated_profile()?;
        let opens = |inputs: &Inputs| {
            let (mut session, _) = fake(inputs, json!({}), None);
            session.effect(request(STEPS[0], "{}"))
        };
        // An expired profile is refused without touching the token.
        let mut expired: Value = serde_json::from_slice(&profile)?;
        expired["expires_at"] = json!(1);
        let inputs = inputs(&serde_json::to_vec(&expired)?, TOKEN)?;
        fs::remove_file(&inputs.token)?;
        assert_eq!(
            opens(&inputs).unwrap_err().to_string(),
            "google_workspace_qualification_profile_expired"
        );
        // A key file or other non-token is refused before evidence exists.
        let inputs = self::inputs(&profile, r#"{"type":"service_account"}"#)?;
        assert_eq!(
            opens(&inputs).unwrap_err().to_string(),
            "google_workspace_qualification_token_invalid"
        );
        assert!(!inputs.evidence.exists());
        // A group-readable token, a linked token, an oversized profile and an
        // existing evidence directory are each refused.
        let inputs = self::inputs(&profile, TOKEN)?;
        fs::set_permissions(&inputs.token, fs::Permissions::from_mode(0o640))?;
        assert!(opens(&inputs).is_err());
        let mut inputs = self::inputs(&profile, TOKEN)?;
        let linked = inputs.directory.path().join("linked");
        std::os::unix::fs::symlink(&inputs.token, &linked)?;
        inputs.token = linked;
        assert!(opens(&inputs).is_err());
        let inputs = self::inputs(&vec![b' '; evidence::MAX_INPUT_BYTES as usize + 1], TOKEN)?;
        assert!(opens(&inputs).is_err());
        let inputs = self::inputs(&profile, TOKEN)?;
        fs::create_dir(&inputs.evidence)?;
        assert!(opens(&inputs).is_err());
        Ok(())
    }
}
