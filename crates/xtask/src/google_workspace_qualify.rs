//! Explicit live Google Workspace qualification. An operator runs it with a
//! reviewed, expiring profile and an owner-private file holding their own
//! short-lived access token; it is never part of verify.
//! `ops/GoogleWorkspaceQualification.roc` owns step order through
//! `ops/Runner.roc`. This session supplies only the narrow native
//! capabilities: reading the bounded inputs, the read probes, the one write,
//! dropping the run and the mandatory evidence guards. The provider side is
//! [`day2::google_workspace_qualification`]. The receipt holds counts, closed
//! classifications and reviewed names only, and every run reports
//! `provider_qualified: false` until a reviewer accepts its evidence.
use super::*;
use day2::{automation::Request, google_workspace_qualification::QualificationProfile};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_INPUT_BYTES: u64 = 16 * 1024;
const RECEIPT: &str = "receipt.json";

/// A bounded regular file read from the opened descriptor, never through a link.
fn bounded(path: &Path, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() <= MAX_INPUT_BYTES
            && (!private || metadata.permissions().mode() & 0o077 == 0),
        "{} must be a bounded{} regular file",
        path.display(),
        if private { " owner-private" } else { "" }
    );
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_INPUT_BYTES, "input byte budget");
    Ok(bytes)
}

fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

/// One run's provider steps, in the order the recipe calls them.
pub trait Qualify {
    fn read(&mut self) -> Result<Value>;
    fn share(&mut self) -> Result<Value>;
    fn finish(self: Box<Self>) -> Result<Value>;
}

impl Qualify for day2::google_workspace_qualification::Qualification {
    fn read(&mut self) -> Result<Value> {
        day2::google_workspace_qualification::Qualification::read(self)
    }

    fn share(&mut self) -> Result<Value> {
        day2::google_workspace_qualification::Qualification::share(self)
    }

    fn finish(self: Box<Self>) -> Result<Value> {
        day2::google_workspace_qualification::Qualification::finish(*self)
    }
}

/// The provider capability: a run of `profile` with the operator's token.
pub type Start = dyn FnMut(QualificationProfile, String) -> Result<Box<dyn Qualify>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Start,
    Opened,
    Read,
    Shared,
    Discarded,
    Complete,
    Failed,
}

pub struct Session {
    profile_path: PathBuf,
    token_path: PathBuf,
    evidence: PathBuf,
    phase: Phase,
    profile: Option<QualificationProfile>,
    token: Option<String>,
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
            profile: None,
            token: None,
            run: None,
            receipt: None,
            start,
        }
    }

    /// One recipe step. Steps run once, in order, and accept no arguments. A
    /// failed step closes the session: the run, with the port and every
    /// provider value it held, and the token are dropped.
    pub fn effect(&mut self, request: Request) -> Result<Value> {
        ensure!(request.protocol == 1, "unsupported workflow protocol");
        ensure!(
            request.decode::<Value>()? == json!({}),
            "google workspace qualification steps accept only an empty object"
        );
        let (expected, next) = match request.action.as_str() {
            "google-workspace-qualification-open" => (Phase::Start, Phase::Opened),
            "google-workspace-qualification-read" => (Phase::Opened, Phase::Read),
            "google-workspace-qualification-share" => (Phase::Read, Phase::Shared),
            "google-workspace-qualification-discard" => (Phase::Shared, Phase::Discarded),
            "google-workspace-qualification-receipt" => (Phase::Discarded, Phase::Complete),
            other => anyhow::bail!("unsupported google workspace qualification step: {other}"),
        };
        ensure!(
            self.phase == expected,
            "google workspace qualification step out of order or replayed"
        );
        // Fence before any filesystem or provider operation.
        self.phase = Phase::Failed;
        let result = match next {
            Phase::Opened => self.open(),
            Phase::Read => self.read(),
            Phase::Shared => self.share(),
            Phase::Discarded => self.discard(),
            _ => self.publish(),
        };
        match result {
            Ok(value) => {
                self.phase = next;
                Ok(value)
            }
            Err(error) => {
                self.run = None;
                self.token = None;
                self.receipt = None;
                Err(error)
            }
        }
    }

    /// Read and admit the profile, then read the token, then create the new
    /// owner-private evidence directory.
    fn open(&mut self) -> Result<Value> {
        let profile: QualificationProfile =
            day2::json::decode(&bounded(&self.profile_path, false)?)?;
        day2::google_workspace_qualification::admit(&profile, now()?)?;
        let token = String::from_utf8(bounded(&self.token_path, true)?)
            .context("token encoding")?
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&self.evidence)
            .context("evidence directory must be new")?;
        self.profile = Some(profile);
        self.token = Some(token);
        Ok(json!({}))
    }

    /// Every read probe; nothing is written.
    fn read(&mut self) -> Result<Value> {
        let profile = self.profile.clone().context("profile not opened")?;
        let token = self.token.clone().context("token not opened")?;
        let mut run = (self.start)(profile, token)?;
        let result = run.read()?;
        self.run = Some(run);
        Ok(result)
    }

    /// The one write and its visibility checks.
    fn share(&mut self) -> Result<Value> {
        self.run.as_mut().context("reads not run")?.share()
    }

    /// End the run: its receipt is kept, and the run, with the port, its copy
    /// of the token and every provider value it held, is dropped.
    fn discard(&mut self) -> Result<Value> {
        let run = self.run.take().context("reads not run")?;
        self.receipt = Some(run.finish()?);
        Ok(json!({}))
    }

    /// The mandatory evidence guards, then a create-new 0600 receipt. The
    /// receipt may hold none of the token or the profile's own values: each
    /// fixture is named by its role, never its address or ID.
    fn publish(&mut self) -> Result<Value> {
        let receipt = self.receipt.take().context("receipt not collected")?;
        let token = self.token.take().context("token not opened")?;
        let profile = self.profile.take().context("profile not opened")?;
        ensure!(self.run.is_none(), "run not discarded");
        ensure!(
            receipt["provider_qualified"] == false,
            "unexpected provider qualification claim"
        );
        let bytes = serde_json::to_vec_pretty(&receipt)?;
        let contains = |value: &str| {
            bytes
                .windows(value.len())
                .any(|window| window == value.as_bytes())
        };
        ensure!(
            !token.is_empty() && !contains(&token),
            "receipt refused: it contains the access token"
        );
        drop(token);
        let mut pending = vec![serde_json::to_value(&profile)?];
        while let Some(value) = pending.pop() {
            match value {
                Value::String(text) => ensure!(
                    !contains(&text),
                    "receipt refused: it contains a profile value"
                ),
                Value::Array(items) => pending.extend(items),
                Value::Object(map) => pending.extend(map.into_iter().map(|(_, value)| value)),
                _ => {}
            }
        }
        let path = self.evidence.join(RECEIPT);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(&self.evidence)?.sync_all()?;
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
        Box::new(|profile, token| {
            Ok(
                Box::new(day2::google_workspace_qualification::Qualification::native(
                    profile, token,
                )?) as Box<dyn Qualify>,
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

    const STEPS: [&str; 5] = [
        "google-workspace-qualification-open",
        "google-workspace-qualification-read",
        "google-workspace-qualification-share",
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

    /// The simulated organization, its profile and a token it accepts, as
    /// the session's input files.
    struct Inputs {
        _directory: tempfile::TempDir,
        database: PathBuf,
        profile: PathBuf,
        token: PathBuf,
        evidence: PathBuf,
    }

    fn inputs() -> Result<Inputs> {
        let directory = tempfile::tempdir()?;
        let (database, profile, token) =
            day2::google_workspace_qualification::simulated_rehearsal(directory.path())?;
        let profile_path = directory.path().join("profile.json");
        fs::write(&profile_path, serde_json::to_vec(&profile)?)?;
        let token_path = directory.path().join("token");
        fs::write(&token_path, format!("{token}\n"))?;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))?;
        let evidence = directory.path().join("evidence");
        Ok(Inputs {
            _directory: directory,
            database,
            profile: profile_path,
            token: token_path,
            evidence,
        })
    }

    /// The real run against the simulated organization.
    fn simulated(inputs: &Inputs) -> Session {
        let database = inputs.database.clone();
        Session::new(
            &inputs.profile,
            &inputs.token,
            &inputs.evidence,
            Box::new(move |profile, token| {
                Ok(Box::new(
                    day2::google_workspace_qualification::Qualification::simulated(
                        profile,
                        token,
                        &database,
                        "qualification",
                    )?,
                ) as Box<dyn Qualify>)
            }),
        )
    }

    /// A run that answers fixed values and records whether it was dropped.
    struct Fake {
        receipt: Value,
        fail_share: bool,
        dropped: std::rc::Rc<std::cell::Cell<bool>>,
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    impl Qualify for Fake {
        fn read(&mut self) -> Result<Value> {
            Ok(json!({}))
        }

        fn share(&mut self) -> Result<Value> {
            ensure!(!self.fail_share, "share failed");
            Ok(json!({}))
        }

        fn finish(self: Box<Self>) -> Result<Value> {
            Ok(self.receipt.clone())
        }
    }

    fn fake(
        inputs: &Inputs,
        receipt: Value,
        fail_share: bool,
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
                    fail_share,
                    dropped: observed.clone(),
                }) as Box<dyn Qualify>)
            }),
        );
        (session, dropped)
    }

    /// The whole session against the simulated organization: steps in order,
    /// one write, and a private receipt with no profile value or token.
    #[test]
    fn the_session_runs_end_to_end_and_publishes_a_private_receipt() -> Result<()> {
        let inputs = inputs()?;
        let mut session = simulated(&inputs);
        assert!(session.finish().is_err());
        for step in &STEPS[1..] {
            assert!(session.effect(request(step, "{}")).is_err(), "{step}");
        }
        assert!(
            session
                .effect(request(STEPS[0], r#"{"profile":"other.json"}"#))
                .is_err(),
            "workflow-selected arguments are refused"
        );
        assert!(!inputs.evidence.exists(), "nothing ran");
        let mut session = simulated(&inputs);
        for step in STEPS {
            session.effect(request(step, "{}"))?;
        }
        assert!(session.effect(request(STEPS[4], "{}")).is_err(), "replayed");
        let path = session.finish()?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(&inputs.evidence)?.permissions().mode() & 0o777,
            0o700
        );
        let written: Value = serde_json::from_slice(&fs::read(&path)?)?;
        assert_eq!(written["creates_sent"], 1);
        assert_eq!(written["provider_qualified"], false);
        Ok(())
    }

    #[test]
    fn evidence_guards_refuse_a_claim_the_token_or_a_profile_value() -> Result<()> {
        let token = fs::read_to_string(inputs()?.token)?;
        let profile: Value = serde_json::from_slice(&fs::read(inputs()?.profile)?)?;
        for (receipt, expected) in [
            (
                json!({"provider_qualified":true}),
                "unexpected provider qualification claim",
            ),
            (
                json!({"provider_qualified":false,"note":format!("x{}x", token.trim_end())}),
                "receipt refused: it contains the access token",
            ),
            (
                json!({"provider_qualified":false,"note":profile["calendars"]["unshared"]}),
                "receipt refused: it contains a profile value",
            ),
        ] {
            let inputs = inputs()?;
            let (mut session, _) = fake(&inputs, receipt, false);
            for step in &STEPS[..4] {
                session.effect(request(step, "{}"))?;
            }
            let error = session
                .effect(request(STEPS[4], "{}"))
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
        let inputs = inputs()?;
        let (mut session, dropped) = fake(&inputs, json!({}), true);
        session.effect(request(STEPS[0], "{}"))?;
        session.effect(request(STEPS[1], "{}"))?;
        assert!(!dropped.get());
        assert!(session.effect(request(STEPS[2], "{}")).is_err());
        assert!(dropped.get(), "the run is dropped");
        assert!(
            session.effect(request(STEPS[3], "{}")).is_err(),
            "a failed session stays closed"
        );
        Ok(())
    }

    #[test]
    fn inputs_are_admitted_before_the_token_is_read_or_evidence_created() -> Result<()> {
        // An expired profile is refused without touching the token.
        let inputs = inputs()?;
        let mut profile: Value = serde_json::from_slice(&fs::read(&inputs.profile)?)?;
        profile["expires_at"] = json!(1);
        fs::write(&inputs.profile, serde_json::to_vec(&profile)?)?;
        fs::remove_file(&inputs.token)?;
        let (mut session, _) = fake(&inputs, json!({}), false);
        assert_eq!(
            session
                .effect(request(STEPS[0], "{}"))
                .unwrap_err()
                .to_string(),
            "google_workspace_qualification_profile_expired"
        );
        assert!(!inputs.evidence.exists());
        // A group-readable token, a linked token, an oversized profile and an
        // existing evidence directory are each refused.
        let inputs = self::inputs()?;
        fs::set_permissions(&inputs.token, fs::Permissions::from_mode(0o640))?;
        let (mut session, _) = fake(&inputs, json!({}), false);
        assert!(session.effect(request(STEPS[0], "{}")).is_err());
        let inputs = self::inputs()?;
        let linked = inputs.token.with_file_name("linked");
        std::os::unix::fs::symlink(&inputs.token, &linked)?;
        let (mut session, _) = fake(&inputs, json!({}), false);
        session.token_path = linked;
        assert!(session.effect(request(STEPS[0], "{}")).is_err());
        let inputs = self::inputs()?;
        fs::write(&inputs.profile, vec![b' '; MAX_INPUT_BYTES as usize + 1])?;
        let (mut session, _) = fake(&inputs, json!({}), false);
        assert!(session.effect(request(STEPS[0], "{}")).is_err());
        let inputs = self::inputs()?;
        fs::create_dir(&inputs.evidence)?;
        let (mut session, _) = fake(&inputs, json!({}), false);
        assert!(session.effect(request(STEPS[0], "{}")).is_err());
        Ok(())
    }
}
