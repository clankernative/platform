//! The `day2 platform maintain` request a deploy hands the app SDK's operator,
//! with the values the instance's earlier `maintain.sh` gathered: the derived
//! names, the live workload's image and artifact, the candidate's target and
//! tooling, the apply identity as the operator, and the attempt's private
//! paths. The bytes are canonical (Python's `json.dumps(value, sort_keys=True)`
//! and a newline): the operator reads only values, and the activation
//! checkpoint binds the digest of exactly these bytes.
use crate::instance_source::{commit, identifier, lower_hex};
use crate::maintenance;
use anyhow::{Context, Result, bail, ensure};
use day2::python_json::{self, Layout};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// The parent of an attempt's private directories. Fixed, never `$TMPDIR`, so
/// the saved bytes of an activation name paths a later job can recreate.
pub const TMP: &str = "/tmp";

/// The stack's state claim, created by `app-edge`.
pub const PVC: &str = "data";

/// The pod label the tenancy stack admits for non-serving app pods. The key is
/// the stacks' existing constant.
pub const POD_LABEL_KEY: &str = "internal-tools.wonderly.io/service";
pub const POD_LABEL_VALUE: &str = "background";

/// The alphabet of an attempt suffix: Python `tempfile`'s, so the archive's
/// top-level directory keeps the shape `mkdtemp` gave it.
pub const SUFFIX_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
pub const SUFFIX_LENGTH: usize = 8;

/// The app's namespace, `app-<app>`.
pub fn namespace(app: &str) -> String {
    format!("app-{app}")
}

/// The day2-app stack's workload, `day2-<app>`.
pub fn workload(app: &str) -> String {
    format!("day2-{app}")
}

/// The workload's instance ConfigMap.
pub fn configmap(app: &str) -> String {
    format!("day2-{app}-instance")
}

/// The scheduled off-cluster backup's CronJob.
pub fn cronjob(app: &str) -> String {
    format!("day2-{app}-backup")
}

/// The workload's only pod.
pub fn pod(app: &str) -> String {
    format!("day2-{app}-0")
}

/// The app's backup bucket, `<project>-<app>-backups`.
pub fn backup_bucket(project: &str, app: &str) -> String {
    format!("{project}-{app}-backups")
}

/// `deploy-<commit>-<the first 16 hex digits of the target image's digest>`, as
/// the earlier controller named every activation.
pub fn request_id(source_commit: &str, image: &str) -> Result<String> {
    let digest = image
        .rsplit_once("@sha256:")
        .map(|(_, hex)| hex)
        .filter(|hex| lower_hex(hex, 64))
        .context("the target image must be pinned by digest")?;
    ensure!(commit(source_commit), "invalid release source commit");
    Ok(format!("deploy-{source_commit}-{}", &digest[..16]))
}

/// An attempt suffix: 8 characters of the suffix alphabet.
pub fn suffix(value: &str) -> bool {
    value.len() == SUFFIX_LENGTH && value.bytes().all(|byte| SUFFIX_ALPHABET.contains(&byte))
}

/// A suffix from secure random bytes, by rejection sampling.
pub fn random_suffix() -> Result<String> {
    use ring::rand::SecureRandom;
    let random = ring::rand::SystemRandom::new();
    let limit = (256 / SUFFIX_ALPHABET.len() * SUFFIX_ALPHABET.len()) as u8;
    let mut out = String::new();
    while out.len() < SUFFIX_LENGTH {
        let mut byte = [0_u8; 1];
        random
            .fill(&mut byte)
            .map_err(|_| anyhow::anyhow!("no secure random source"))?;
        if byte[0] < limit {
            out.push(SUFFIX_ALPHABET[usize::from(byte[0]) % SUFFIX_ALPHABET.len()] as char);
        }
    }
    Ok(out)
}

/// One attempt's private paths under `/tmp`: the operator's backup directory,
/// whose name is the archive's top-level directory, and the directory holding
/// the activation's desired instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub app: String,
    pub suffix: String,
}

impl Attempt {
    pub fn new(app: &str, suffix: &str) -> Result<Self> {
        ensure!(identifier(app), "invalid deployment app ID");
        ensure!(self::suffix(suffix), "invalid deploy attempt suffix");
        Ok(Self {
            app: app.to_owned(),
            suffix: suffix.to_owned(),
        })
    }

    /// `/tmp/day2-<app>-backup-<suffix>`.
    pub fn backup_dir(&self) -> PathBuf {
        Path::new(TMP).join(format!("day2-{}-backup-{}", self.app, self.suffix))
    }

    /// `/tmp/day2-<app>-activation-<suffix>`.
    pub fn activation_dir(&self) -> PathBuf {
        Path::new(TMP).join(format!("day2-{}-activation-{}", self.app, self.suffix))
    }

    /// `/tmp/day2-<app>-activation-<suffix>/desired-instance.json`.
    pub fn target_instance(&self) -> PathBuf {
        self.activation_dir().join("desired-instance.json")
    }

    /// The attempt a saved request's paths name, which must be exactly this
    /// shape for `app`, with one suffix.
    pub fn of_request(app: &str, request: &Value) -> Result<Self> {
        let backup = request["backup_dir"]
            .as_str()
            .context("the saved request names no backup directory")?;
        let prefix = format!("{TMP}/day2-{app}-backup-");
        let suffix = backup
            .strip_prefix(&prefix)
            .filter(|rest| self::suffix(rest))
            .context("the saved request's backup directory is not a deploy attempt's")?;
        let attempt = Self::new(app, suffix)?;
        ensure!(
            request["target"]["instance"].as_str() == attempt.target_instance().to_str()
                && request["backup_dir"].as_str() == attempt.backup_dir().to_str(),
            "the saved request's paths are not one deploy attempt's"
        );
        Ok(attempt)
    }
}

/// What the maintenance session runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Backup,
    Activate,
    /// Recovery when activate's own stamp step failed: the same bytes as
    /// activate's request.
    MarkActivated,
}

impl Operation {
    pub fn name(self) -> &'static str {
        match self {
            Self::Backup => "backup",
            Self::Activate => "activate",
            Self::MarkActivated => "mark-activated",
        }
    }

    fn maintenance(self) -> Result<maintenance::Operation> {
        maintenance::Operation::parse(self.name())
    }
}

/// What the live workload runs, read before anything stops.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Live {
    pub app_image: String,
    pub artifact_id: String,
}

/// The activation's target: the candidate and its desired instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub app_image: String,
    pub artifact_id: String,
    pub request_id: String,
}

/// The instance names a request needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Names {
    pub app: String,
    pub apply_identity: String,
    pub tooling_image: String,
}

/// The request's value: maintain.sh's fields and values for `operation`.
/// `target` is for activate and mark-activated only.
pub fn value(
    operation: Operation,
    names: &Names,
    live: &Live,
    attempt: &Attempt,
    target: Option<&Target>,
) -> Result<Value> {
    ensure!(attempt.app == names.app, "the attempt is another app's");
    let mut request = json!({
        "namespace": namespace(&names.app),
        "statefulset": workload(&names.app),
        "configmap": configmap(&names.app),
        "app": names.app,
        "pvc": PVC,
        "app_image": live.app_image,
        "artifact_id": live.artifact_id,
        "tooling_image": names.tooling_image,
        "operator": names.apply_identity,
        "pod_label": {"key": POD_LABEL_KEY, "value": POD_LABEL_VALUE},
        "yes": true,
        "backup_dir": attempt.backup_dir(),
    });
    match (operation, target) {
        (Operation::Backup, None) => {}
        (Operation::Activate | Operation::MarkActivated, Some(target)) => {
            request["request_id"] = json!(target.request_id);
            request["target"] = json!({
                "instance": attempt.target_instance(),
                "app_image": target.app_image,
                "artifact_id": target.artifact_id,
            });
        }
        _ => bail!("only activate and mark-activated take a target"),
    }
    Ok(request)
}

/// The canonical bytes, checked as the operator will check them: the request
/// must be one `day2 platform maintain <operation>` accepts.
pub fn encode(operation: Operation, value: &Value) -> Result<Vec<u8>> {
    let mut bytes = python_json::dumps(value, Layout::Default)?;
    bytes.push(b'\n');
    check(operation, &bytes)?;
    Ok(bytes)
}

/// Whether `bytes` are a request the maintenance session accepts for
/// `operation`, before any cluster read.
pub fn check(operation: Operation, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 65_536, "maintenance request file size");
    let request: maintenance::Request = day2::json::decode(bytes)?;
    request.validate(operation.maintenance()?)
}
