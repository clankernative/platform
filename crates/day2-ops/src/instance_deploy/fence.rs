//! The migration fence, as a deploy sees it from outside the maintenance
//! session: what the live workload says (its image, the activated-image stamp
//! and the activation checkpoint, and the state claim), which path a run takes,
//! how much time the rest of that path may need, and what a failure left behind.
//! Everything here is pure; the session reads the cluster and calls it.
use crate::maintenance::activation::{self, ANNOTATION, Intent};
use anyhow::{Context, Result, ensure};
use serde_json::Value;

/// The live workload, read before anything stops and again after a failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workload {
    /// The template's `day2` container image.
    pub image: String,
    pub replicas: u64,
    pub ready_replicas: u64,
    /// `day2.dev/activated-image`.
    pub stamp: Option<String>,
    /// `day2.dev/activation`, when present. A checkpoint this CLI cannot read
    /// fails the read.
    pub checkpoint: Option<Checkpoint>,
}

/// The phase of an activation checkpoint, as the operator records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    Stopped,
    Fenced,
    Recovering,
    Restored,
    Activated,
}

impl From<&activation::Phase> for Phase {
    fn from(phase: &activation::Phase) -> Self {
        match phase {
            activation::Phase::Prepared => Self::Prepared,
            activation::Phase::Stopped => Self::Stopped,
            activation::Phase::Fenced => Self::Fenced,
            activation::Phase::Recovering => Self::Recovering,
            activation::Phase::Restored => Self::Restored,
            activation::Phase::Activated => Self::Activated,
        }
    }
}

/// The activation checkpoint's fields a deploy uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub phase: Phase,
    pub request_digest: String,
    pub target_instance_digest: String,
}

impl Checkpoint {
    /// Not restored or activated: an activation owns the workload.
    pub fn active(&self) -> bool {
        !matches!(self.phase, Phase::Restored | Phase::Activated)
    }
}

/// The app's state claim (`data`, which `app-edge` creates). Its storage class
/// binds on first use, so an unbound claim has never held data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    Absent,
    Unbound,
    Bound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    pub workload: Option<Workload>,
    pub claim: Claim,
}

impl Workload {
    /// From the StatefulSet as `kubectl get -o json` prints it. Its first
    /// container must be `day2` (the earlier `maintain.sh` read the first one,
    /// the controller the one named `day2`); an unreadable checkpoint fails.
    pub fn read(statefulset: &Value) -> Result<Self> {
        let containers = statefulset["spec"]["template"]["spec"]["containers"]
            .as_array()
            .context("the workload has no containers")?;
        let first = containers
            .first()
            .context("the workload has no containers")?;
        ensure!(
            first["name"] == "day2",
            "the workload's first container is not day2"
        );
        let image = first["image"]
            .as_str()
            .context("the workload's day2 container has no image")?
            .to_owned();
        let replicas = statefulset["spec"]["replicas"]
            .as_u64()
            .context("the workload has no replica count")?;
        let ready_replicas = statefulset["status"]["readyReplicas"].as_u64().unwrap_or(0);
        let stamp = match &statefulset["metadata"]["annotations"][crate::maintenance::ACTIVATED] {
            Value::Null => None,
            Value::String(value) => Some(value.clone()),
            _ => anyhow::bail!("the workload's activated-image stamp is not a string"),
        };
        let checkpoint = Intent::read(statefulset)
            .with_context(|| format!("unrecognized {ANNOTATION} checkpoint"))?
            .map(|intent| Checkpoint {
                phase: Phase::from(&intent.phase),
                request_digest: intent.request_digest,
                target_instance_digest: intent.target_instance_digest,
            });
        Ok(Self {
            image,
            replicas,
            ready_replicas,
            stamp,
            checkpoint,
        })
    }
}

impl Claim {
    /// From the PVC as `kubectl get --ignore-not-found -o json` prints it
    /// (nothing when absent). Only a `Pending` claim with no volume is unbound.
    pub fn read(pvc: Option<&Value>) -> Self {
        match pvc {
            None => Self::Absent,
            Some(pvc)
                if pvc["status"]["phase"] == "Pending"
                    && pvc["spec"]["volumeName"].as_str().is_none_or(str::is_empty) =>
            {
                Self::Unbound
            }
            Some(_) => Self::Bound,
        }
    }
}

/// What a run does, chosen from the live workload before anything changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// Render the target, back up, archive, activate, then apply and roll.
    Fresh,
    /// Activated for this candidate but not rolled: apply and roll.
    Activated,
    /// Already running this candidate's image: apply and read back.
    Serving,
    /// No workload and a never-bound claim: a first install (apply and roll).
    Install,
}

impl Path {
    pub fn name(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Activated => "activated",
            Self::Serving => "serving",
            Self::Install => "install",
        }
    }
}

/// How a run ended when it did not deploy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Exit 7: a transient read failed and this run changed nothing.
    Unavailable,
    /// Exit 6: before the migration fence; the app was not touched or was
    /// restored on its image (the message says when it needs recovery).
    Failed,
    /// Exit 8: after the migration fence, in this run or an earlier one. The
    /// old image never restarts; only a rerun of the same candidate rolls
    /// forward.
    Fenced,
}

/// A refusal of the path itself, before anything changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub class: Class,
    pub message: String,
}

fn refuse(class: Class, message: impl Into<String>) -> Refusal {
    Refusal {
        class,
        message: message.into(),
    }
}

/// The path for the candidate image `target`.
pub fn choose(observed: &Observed, target: &str) -> std::result::Result<Path, Refusal> {
    let Some(workload) = &observed.workload else {
        return match observed.claim {
            Claim::Unbound => Ok(Path::Install),
            Claim::Bound => Err(refuse(
                Class::Failed,
                "the app's state volume is bound but it has no workload: a workload over existing data must be \
                 activated, not installed; restore the workload or recover the app by hand",
            )),
            Claim::Absent => Err(refuse(
                Class::Failed,
                "the app has no state volume (PVC data): apply the instance's app-edge root first",
            )),
        };
    };
    if let Some(checkpoint) = workload.checkpoint.as_ref().filter(|c| c.active()) {
        return match checkpoint.phase {
            Phase::Fenced | Phase::Recovering => Err(refuse(
                Class::Fenced,
                "activation_recovery_required: an activation passed the migration fence and this deploy holds \
                 no saved request for it; recover it with day2 platform maintain recover <journal> from the \
                 deployment's archive, then resume that exact activation",
            )),
            _ => Err(refuse(
                Class::Failed,
                "activation_recovery_required: an earlier activation stopped before the migration fence without \
                 restoring the app; run day2 platform maintain recover <journal> from the deployment's archive",
            )),
        };
    }
    if workload.image == target {
        return Ok(Path::Serving);
    }
    match &workload.stamp {
        Some(stamp) if stamp == target => Ok(Path::Activated),
        Some(stamp) if *stamp != workload.image => Err(refuse(
            Class::Fenced,
            format!(
                "the app is activated for another image ({stamp}) that was never rolled; roll that activation \
                 forward before deploying another candidate"
            ),
        )),
        _ => Ok(Path::Fresh),
    }
}

/// Each step's worst case, in seconds. The deadline check sums the steps a path
/// has left; every one is a hard deadline its step enforces.
pub mod budget {
    /// One `kubectl get`.
    pub const KUBECTL_READ: u64 = 60;
    /// How long a maintenance session gets after its SIGINT to clean up and
    /// restore the app before its process group is killed.
    pub const MAINTAIN_GRACE: u64 = 300;
    /// `day2 platform maintain backup`.
    pub const BACKUP: u64 = 1200;
    /// `day2 platform maintain activate`; with its grace it ends before the
    /// maintenance pod's own one-hour deadline.
    pub const ACTIVATE: u64 = 2700;
    const _: () = assert!(
        ACTIVATE + MAINTAIN_GRACE < 3600,
        "within the maintenance pod's deadline"
    );
    /// One phase's `gcloud storage cp --recursive`, then its listing.
    pub const ARCHIVE_UPLOAD: u64 = 600;
    pub const ARCHIVE_LIST: u64 = 60;
    /// The day2-app apply in deploy mode: the state lock wait, the plan, the
    /// apply and the interrupt grace.
    pub const APPLY_LOCK_WAIT: u64 = 120;
    pub const APPLY_PLAN: u64 = 600;
    pub const APPLY_APPLY: u64 = 900;
    pub const APPLY_GRACE: u64 = 60;
    pub const APPLY: u64 = APPLY_LOCK_WAIT + APPLY_PLAN + APPLY_APPLY + APPLY_GRACE;
    /// `kubectl rollout status --timeout=600s`, and its process deadline.
    pub const ROLLOUT_WAIT: u64 = 600;
    pub const ROLLOUT: u64 = ROLLOUT_WAIT + 60;
    /// The readback: the StatefulSet, its pod, the ConfigMap and the CronJob.
    pub const READBACK: u64 = 4 * KUBECTL_READ;
    /// The read after a failure.
    pub const CLASSIFY: u64 = KUBECTL_READ;
    pub const ARCHIVE: u64 = ARCHIVE_UPLOAD + ARCHIVE_LIST;
}

/// The worst case of what `path` has left from its deadline check, which runs
/// just before its first step that stops or rolls the app.
pub fn remaining(path: Path) -> u64 {
    use budget::*;
    let roll = APPLY + ROLLOUT + READBACK + CLASSIFY;
    match path {
        Path::Fresh => {
            (BACKUP + MAINTAIN_GRACE) + ARCHIVE + (ACTIVATE + MAINTAIN_GRACE) + roll + ARCHIVE
        }
        Path::Activated | Path::Serving | Path::Install => roll,
    }
}

/// Refuse to start what cannot finish: `now` plus the path's remaining worst
/// case must not pass `deadline` (unix seconds).
pub fn within(now: u64, deadline: Option<u64>, path: Path) -> Result<()> {
    let Some(deadline) = deadline else {
        return Ok(());
    };
    let needed = remaining(path);
    ensure!(
        now.saturating_add(needed) <= deadline,
        "deploy_deadline: the {} path needs up to {needed} s, but the job's deadline is {} s away; retry with \
         more time",
        path.name(),
        deadline.saturating_sub(now)
    );
    Ok(())
}

/// Where a run was when it failed, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Prepare,
    Operator,
    Credentials,
    Observe,
    Target,
    Deadline,
    Backup,
    ArchiveBefore,
    Activate,
    Apply,
    Rollout,
    Readback,
    ArchiveAfter,
}

/// What a failed run knew.
#[derive(Clone, Debug)]
pub struct Failure<'a> {
    pub stage: Stage,
    /// The error is a transient read.
    pub retryable: bool,
    pub path: Option<Path>,
    /// A step that stops or rolls the app started in this run.
    pub mutated: bool,
    /// This run's activate session succeeded.
    pub activated: bool,
    /// The readback passed (only the final archive failed).
    pub verified: bool,
    /// The image the workload ran before this run changed anything.
    pub original: Option<&'a str>,
    pub target: &'a str,
    /// The workload read after the failure; `None` when that read failed.
    pub after: Option<&'a Observed>,
}

/// The class of a failed run and what it says about the app, from the cluster
/// read after the failure, never from the failure's text.
pub fn classify(failure: &Failure<'_>) -> (Class, &'static str) {
    let earlier_fence = failure.path == Some(Path::Activated);
    if !failure.mutated {
        return if failure.retryable {
            (Class::Unavailable, "nothing was stopped")
        } else if earlier_fence {
            (
                Class::Fenced,
                "the app is still stopped after an earlier migration fence; rerun this candidate",
            )
        } else {
            (Class::Failed, "nothing was stopped")
        };
    }
    let Some(after) = failure.after else {
        return (
            Class::Fenced,
            "the app's workload could not be read after the failure; treat it as past the migration fence",
        );
    };
    let Some(workload) = &after.workload else {
        return if failure.path == Some(Path::Install) {
            (Class::Failed, "the first install did not finish")
        } else {
            (
                Class::Fenced,
                "the app's workload is gone; treat it as past the migration fence",
            )
        };
    };
    match workload.checkpoint.as_ref().map(|c| &c.phase) {
        Some(Phase::Fenced | Phase::Recovering) => {
            return (
                Class::Fenced,
                "the app is stopped after the migration fence; it never restarts on its old image",
            );
        }
        Some(Phase::Prepared | Phase::Stopped) => {
            return (
                Class::Failed,
                "activation_recovery_required: the app stopped before the migration fence and was not restored; \
                 run day2 platform maintain recover <journal> from the deployment's archive",
            );
        }
        _ => {}
    }
    if failure.path == Some(Path::Install) {
        return (Class::Failed, "the first install did not finish");
    }
    if failure.stage == Stage::ArchiveAfter && failure.verified {
        return (
            Class::Failed,
            "the app serves the target, but its evidence was not archived",
        );
    }
    if failure.activated || earlier_fence || failure.path == Some(Path::Serving) {
        return (
            Class::Fenced,
            "the app's store runs the target after the migration fence; it never restarts on its old image",
        );
    }
    if workload.stamp.as_deref() == Some(failure.target) && workload.image != failure.target {
        return (
            Class::Fenced,
            "the app is activated for the target but not rolled",
        );
    }
    if Some(workload.image.as_str()) == failure.original {
        return if workload.replicas >= 1 {
            (Class::Failed, "the app was restored on its image")
        } else {
            (
                Class::Failed,
                "activation_recovery_required: the app is stopped on its image (0 replicas) and was not \
                 restored; run day2 platform maintain recover <journal> from the deployment's archive or \
                 restore its replica",
            )
        };
    }
    (
        Class::Fenced,
        "the app's workload is in an unexpected state; treat it as past the migration fence",
    )
}
