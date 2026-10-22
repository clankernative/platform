//! Explicit live Carta qualification. An operator runs it with a reviewed
//! playground profile and a private secret file; it is never part of verify.
//! `ops/CartaQualification.roc` owns step order through `ops/Runner.roc`. This
//! session supplies only the narrow native capabilities: reading the bounded
//! inputs, the private scratch store, the provider adapter
//! ([`day2::carta_qualification::qualify`]) and the mandatory evidence guards.
//! The receipt holds counts, closed classifications and reviewed names only,
//! and every run reports `provider_qualified: false` until a reviewer accepts
//! its evidence.
use super::*;
use day2::{automation::Request, carta_qualification::QualificationProfile};
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

/// The provider capability: one capture of `profile` with `secret` into the
/// scratch store at the given path, returning the receipt.
pub type Collect = dyn FnMut(&QualificationProfile, String, &Path) -> Result<Value>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Start,
    Opened,
    Scratch,
    Collected,
    Discarded,
    Complete,
    Failed,
}

pub struct Session {
    profile_path: PathBuf,
    secret_path: PathBuf,
    evidence: PathBuf,
    phase: Phase,
    profile: Option<QualificationProfile>,
    secret: Option<String>,
    scratch: Option<tempfile::TempDir>,
    receipt: Option<Value>,
    collect: Box<Collect>,
}

impl Session {
    pub fn new(profile: &Path, secret: &Path, evidence: &Path, collect: Box<Collect>) -> Self {
        Self {
            profile_path: profile.into(),
            secret_path: secret.into(),
            evidence: evidence.into(),
            phase: Phase::Start,
            profile: None,
            secret: None,
            scratch: None,
            receipt: None,
            collect,
        }
    }

    /// One recipe step. Steps run once, in order, and accept no arguments. A
    /// failed step closes the session: the secret is dropped and the scratch
    /// store, which holds real records, is deleted.
    pub fn effect(&mut self, request: Request) -> Result<Value> {
        ensure!(request.protocol == 1, "unsupported workflow protocol");
        ensure!(
            request.decode::<Value>()? == json!({}),
            "carta qualification steps accept only an empty object"
        );
        let (expected, next) = match request.action.as_str() {
            "carta-qualification-open" => (Phase::Start, Phase::Opened),
            "carta-qualification-scratch" => (Phase::Opened, Phase::Scratch),
            "carta-qualification-collect" => (Phase::Scratch, Phase::Collected),
            "carta-qualification-discard" => (Phase::Collected, Phase::Discarded),
            "carta-qualification-receipt" => (Phase::Discarded, Phase::Complete),
            other => anyhow::bail!("unsupported carta qualification step: {other}"),
        };
        ensure!(
            self.phase == expected,
            "carta qualification step out of order or replayed"
        );
        // Fence before any filesystem or provider operation.
        self.phase = Phase::Failed;
        let result = match next {
            Phase::Opened => self.open(),
            Phase::Scratch => self.create_scratch(),
            Phase::Collected => self.collect(),
            Phase::Discarded => self.discard(),
            _ => self.publish(),
        };
        match result {
            Ok(value) => {
                self.phase = next;
                Ok(value)
            }
            Err(error) => {
                self.secret = None;
                self.receipt = None;
                // Dropping the guard deletes the scratch store.
                self.scratch = None;
                Err(error)
            }
        }
    }

    /// Read and admit the inputs, then create the new owner-private evidence
    /// directory. The profile is admitted before the secret is read.
    fn open(&mut self) -> Result<Value> {
        let profile: QualificationProfile =
            day2::json::decode(&bounded(&self.profile_path, false)?)?;
        day2::carta_qualification::admit(&profile, now()?)?;
        let secret = String::from_utf8(bounded(&self.secret_path, true)?)
            .context("secret encoding")?
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&self.evidence)
            .context("evidence directory must be new")?;
        self.profile = Some(profile);
        self.secret = Some(secret);
        Ok(json!({}))
    }

    /// The scratch store's private directory inside the evidence directory.
    fn create_scratch(&mut self) -> Result<Value> {
        self.scratch = Some(tempfile::tempdir_in(&self.evidence)?);
        Ok(json!({}))
    }

    fn collect(&mut self) -> Result<Value> {
        let profile = self.profile.as_ref().context("profile not opened")?;
        let secret = self.secret.clone().context("secret not opened")?;
        let scratch = self.scratch.as_ref().context("scratch not created")?;
        let receipt = (self.collect)(profile, secret, &scratch.path().join("carta.sqlite"))?;
        let outcome = receipt["outcome"]
            .as_str()
            .context("qualification outcome missing")?
            .to_owned();
        self.receipt = Some(receipt);
        Ok(json!({ "outcome": outcome }))
    }

    /// Delete the scratch store and prove it is gone before any evidence is
    /// published.
    fn discard(&mut self) -> Result<Value> {
        let scratch = self.scratch.take().context("scratch not created")?;
        let path = scratch.path().to_path_buf();
        scratch.close().context("discard scratch store")?;
        ensure!(
            matches!(fs::symlink_metadata(&path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "scratch store still present"
        );
        Ok(json!({}))
    }

    /// The mandatory evidence guards, then a create-new 0600 receipt.
    fn publish(&mut self) -> Result<Value> {
        let receipt = self.receipt.take().context("receipt not collected")?;
        let secret = self.secret.take().context("secret not opened")?;
        ensure!(self.scratch.is_none(), "scratch store not discarded");
        ensure!(
            receipt["provider_qualified"] == false,
            "unexpected provider qualification claim"
        );
        let bytes = serde_json::to_vec_pretty(&receipt)?;
        ensure!(
            !secret.is_empty()
                && !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
            "receipt refused: it contains the client secret"
        );
        drop(secret);
        let path = self.evidence.join(RECEIPT);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(&self.evidence)?.sync_all()?;
        Ok(json!({ "outcome": receipt["outcome"] }))
    }

    pub fn finish(&self) -> Result<PathBuf> {
        ensure!(
            self.phase == Phase::Complete,
            "carta qualification incomplete"
        );
        Ok(self.evidence.join(RECEIPT))
    }
}

pub fn execute(root: &Path, profile: &Path, secret: &Path, evidence: &Path) -> Result<()> {
    let runner = workflows::build(root)?;
    let mut session = Session::new(
        profile,
        secret,
        evidence,
        Box::new(day2::carta_qualification::qualify),
    );
    let result = day2::automation::run(&runner, &["carta-qualification"], |request| {
        session.effect(request)
    })?;
    let receipt = session.finish()?;
    println!(
        "carta qualification {}: {}",
        result["outcome"].as_str().unwrap_or("unknown"),
        receipt.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "SYNTHETIC_NEVER_EXPORT_CARTA_SECRET";
    const STEPS: [&str; 5] = [
        "carta-qualification-open",
        "carta-qualification-scratch",
        "carta-qualification-collect",
        "carta-qualification-discard",
        "carta-qualification-receipt",
    ];

    fn request(action: &str, input: &str) -> Request {
        Request {
            protocol: 1,
            action: action.into(),
            input: input.into(),
        }
    }

    struct Inputs {
        _directory: tempfile::TempDir,
        profile: PathBuf,
        secret: PathBuf,
        evidence: PathBuf,
    }

    fn inputs(environment: &str) -> Result<Inputs> {
        let directory = tempfile::tempdir()?;
        let profile = directory.path().join("profile.json");
        fs::write(
            &profile,
            serde_json::to_vec(
                &json!({"format":1,"environment":environment,"client_id":"client",
                "issuer_id":"42","children":"omit","max_pages_per_collection":1,
                "expires_at":i64::MAX}),
            )?,
        )?;
        let secret = directory.path().join("secret");
        fs::write(&secret, format!("{SECRET}\n"))?;
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))?;
        let evidence = directory.path().join("evidence");
        Ok(Inputs {
            _directory: directory,
            profile,
            secret,
            evidence,
        })
    }

    /// A provider capability that records the scratch path and writes a record
    /// into it, as a real capture would.
    type Seen = std::rc::Rc<std::cell::RefCell<Option<PathBuf>>>;

    fn fake(
        scratch: Seen,
        receipt: Value,
    ) -> impl FnMut(&QualificationProfile, String, &Path) -> Result<Value> {
        move |profile, secret, path| {
            assert_eq!(profile.client_id, "client");
            assert_eq!(
                secret, SECRET,
                "the secret file's trailing newline is trimmed"
            );
            fs::write(path, "real records")?;
            *scratch.borrow_mut() = Some(path.to_path_buf());
            Ok(receipt.clone())
        }
    }

    #[test]
    fn steps_are_refused_out_of_order_with_arguments_or_replayed() -> Result<()> {
        let inputs = inputs("playground")?;
        let scratch = Seen::default();
        let collect = fake(
            scratch.clone(),
            json!({"outcome":"captured","provider_qualified":false}),
        );
        let mut session = Session::new(
            &inputs.profile,
            &inputs.secret,
            &inputs.evidence,
            Box::new(collect),
        );
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
        assert!(
            session
                .effect(request("carta-qualification-retry", "{}"))
                .is_err()
        );
        assert!(!inputs.evidence.exists(), "nothing ran");
        session.effect(request(STEPS[0], "{}"))?;
        assert!(session.effect(request(STEPS[0], "{}")).is_err(), "replayed");
        Ok(())
    }

    #[test]
    fn steps_run_in_order_discard_scratch_and_publish_a_private_receipt() -> Result<()> {
        let inputs = inputs("playground")?;
        let scratch = Seen::default();
        let collect = fake(
            scratch.clone(),
            json!({"outcome":"captured","provider_qualified":false}),
        );
        let mut session = Session::new(
            &inputs.profile,
            &inputs.secret,
            &inputs.evidence,
            Box::new(collect),
        );
        for step in STEPS {
            session.effect(request(step, "{}"))?;
        }
        let path = session.finish()?;
        let scratch = scratch.borrow().clone().context("scratch used")?;
        assert!(!scratch.exists(), "the scratch store is discarded");
        assert!(!scratch.parent().context("scratch directory")?.exists());
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(&inputs.evidence)?.permissions().mode() & 0o777,
            0o700
        );
        let entries: Vec<_> = fs::read_dir(&inputs.evidence)?.collect::<Result<_, _>>()?;
        assert_eq!(entries.len(), 1, "only the receipt remains");
        let written: Value = serde_json::from_slice(&fs::read(&path)?)?;
        assert_eq!(written["outcome"], "captured");
        Ok(())
    }

    #[test]
    fn evidence_guards_refuse_a_qualification_claim_or_a_leaked_secret() -> Result<()> {
        for (receipt, expected) in [
            (
                json!({"outcome":"captured","provider_qualified":true}),
                "unexpected provider qualification claim",
            ),
            (
                json!({"outcome":"captured","provider_qualified":false,"note":format!("x{SECRET}x")}),
                "receipt refused: it contains the client secret",
            ),
        ] {
            let inputs = inputs("playground")?;
            let scratch = Seen::default();
            let collect = fake(scratch.clone(), receipt);
            let mut session = Session::new(
                &inputs.profile,
                &inputs.secret,
                &inputs.evidence,
                Box::new(collect),
            );
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
    fn a_failed_collection_deletes_the_scratch_store_and_closes_the_session() -> Result<()> {
        let inputs = inputs("playground")?;
        let seen = std::rc::Rc::new(std::cell::RefCell::new(None));
        let observed = seen.clone();
        let collect = move |_: &QualificationProfile, _: String, path: &Path| -> Result<Value> {
            fs::write(path, "real records")?;
            *observed.borrow_mut() = Some(path.to_path_buf());
            anyhow::bail!("collection failed")
        };
        let mut session = Session::new(
            &inputs.profile,
            &inputs.secret,
            &inputs.evidence,
            Box::new(collect),
        );
        session.effect(request(STEPS[0], "{}"))?;
        session.effect(request(STEPS[1], "{}"))?;
        assert!(session.effect(request(STEPS[2], "{}")).is_err());
        let scratch = seen.borrow().clone().context("scratch used")?;
        assert!(!scratch.exists());
        assert!(
            session.effect(request(STEPS[3], "{}")).is_err(),
            "a failed session stays closed"
        );
        Ok(())
    }

    #[test]
    fn inputs_are_admitted_before_the_secret_is_read_or_evidence_created() -> Result<()> {
        // A production profile is refused without touching the secret.
        let inputs = inputs("production")?;
        fs::remove_file(&inputs.secret)?;
        let scratch = Seen::default();
        let collect = fake(scratch.clone(), json!({}));
        let mut session = Session::new(
            &inputs.profile,
            &inputs.secret,
            &inputs.evidence,
            Box::new(collect),
        );
        assert_eq!(
            session
                .effect(request(STEPS[0], "{}"))
                .unwrap_err()
                .to_string(),
            "carta_qualification_requires_playground"
        );
        assert!(!inputs.evidence.exists());
        // A group-readable secret and an existing evidence directory are refused.
        let inputs = self::inputs("playground")?;
        fs::set_permissions(&inputs.secret, fs::Permissions::from_mode(0o640))?;
        let collect = fake(scratch.clone(), json!({}));
        let mut session = Session::new(
            &inputs.profile,
            &inputs.secret,
            &inputs.evidence,
            Box::new(collect),
        );
        assert!(session.effect(request(STEPS[0], "{}")).is_err());
        let inputs = self::inputs("playground")?;
        fs::create_dir(&inputs.evidence)?;
        let collect = fake(scratch.clone(), json!({}));
        let mut session = Session::new(
            &inputs.profile,
            &inputs.secret,
            &inputs.evidence,
            Box::new(collect),
        );
        assert!(session.effect(request(STEPS[0], "{}")).is_err());
        Ok(())
    }
}
