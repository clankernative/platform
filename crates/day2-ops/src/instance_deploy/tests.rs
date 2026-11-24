//! Tests for `day2 instance deploy`. Every fixture is synthetic.
use super::archive::{self, Entry};
use super::fence::{self, Claim, Class, Failure, Observed, Path, Phase, Stage, Workload, budget};
use super::request::{self, Attempt, Live, Names, Operation, Target};
use anyhow::Result;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt};

const REGISTRY: &str = "us-central1-docker.pkg.dev/exampleco-tools";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const APPLY_IDENTITY: &str = "tools-infra@exampleco-tools.iam.gserviceaccount.com";
const LIVE_ARTIFACT: &str = "abababababababababababababababababababababababababababababababab";
const TARGET_ARTIFACT: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn image(name: &str, fill: &str) -> String {
    format!("{REGISTRY}/links/{name}@sha256:{}", fill.repeat(64))
}

fn names() -> Names {
    Names {
        app: "links".into(),
        apply_identity: APPLY_IDENTITY.into(),
        tooling_image: image("day2-tooling", "2"),
    }
}

fn live() -> Live {
    Live {
        app_image: image("links", "a"),
        artifact_id: LIVE_ARTIFACT.into(),
    }
}

fn target() -> Target {
    Target {
        app_image: image("links", "e"),
        artifact_id: TARGET_ARTIFACT.into(),
        request_id: request::request_id(COMMIT, &image("links", "e")).unwrap(),
    }
}

fn attempt() -> Attempt {
    Attempt::new("links", "ab12cd_9").unwrap()
}

/// What the earlier `maintain.sh activate` wrote for the same app, live
/// workload and target: `json.dump(request, f, indent=1)` in its insertion
/// order, with no final newline. Its two paths came from `mktemp`.
const MAINTAIN_SH_ACTIVATE: &str = r#"{
 "namespace": "app-links",
 "statefulset": "day2-links",
 "configmap": "day2-links-instance",
 "app": "links",
 "pvc": "data",
 "app_image": "us-central1-docker.pkg.dev/exampleco-tools/links/links@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "artifact_id": "abababababababababababababababababababababababababababababababab",
 "tooling_image": "us-central1-docker.pkg.dev/exampleco-tools/links/day2-tooling@sha256:2222222222222222222222222222222222222222222222222222222222222222",
 "operator": "tools-infra@exampleco-tools.iam.gserviceaccount.com",
 "pod_label": {
  "key": "internal-tools.wonderly.io/service",
  "value": "background"
 },
 "yes": true,
 "backup_dir": "/tmp/day2-links-backup-k2x_9qzp",
 "request_id": "deploy-0123456789abcdef0123456789abcdef01234567-eeeeeeeeeeeeeeee",
 "target": {
  "instance": "/tmp/tmp.Wq0RbXc3fT/desired-instance.json",
  "app_image": "us-central1-docker.pkg.dev/exampleco-tools/links/links@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "artifact_id": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
 }
}"#;

/// `maintain.sh backup` for the same app and live workload.
const MAINTAIN_SH_BACKUP: &str = r#"{
 "namespace": "app-links",
 "statefulset": "day2-links",
 "configmap": "day2-links-instance",
 "app": "links",
 "pvc": "data",
 "app_image": "us-central1-docker.pkg.dev/exampleco-tools/links/links@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "artifact_id": "abababababababababababababababababababababababababababababababab",
 "tooling_image": "us-central1-docker.pkg.dev/exampleco-tools/links/day2-tooling@sha256:2222222222222222222222222222222222222222222222222222222222222222",
 "operator": "tools-infra@exampleco-tools.iam.gserviceaccount.com",
 "pod_label": {
  "key": "internal-tools.wonderly.io/service",
  "value": "background"
 },
 "yes": true,
 "backup_dir": "/tmp/day2-links-backup-k2x_9qzp"
}"#;

/// maintain.sh's request with its random paths replaced by this attempt's.
fn maintain_sh(raw: &str, attempt: &Attempt) -> Value {
    let mut value: Value = serde_json::from_str(raw).unwrap();
    value["backup_dir"] = json!(attempt.backup_dir());
    if value.get("target").is_some() {
        value["target"]["instance"] = json!(attempt.target_instance());
    }
    value
}

#[test]
fn requests_carry_maintain_sh_values_for_backup_and_activate() -> Result<()> {
    let attempt = attempt();
    let backup = request::value(Operation::Backup, &names(), &live(), &attempt, None)?;
    assert_eq!(backup, maintain_sh(MAINTAIN_SH_BACKUP, &attempt));
    let activate = request::value(
        Operation::Activate,
        &names(),
        &live(),
        &attempt,
        Some(&target()),
    )?;
    assert_eq!(activate, maintain_sh(MAINTAIN_SH_ACTIVATE, &attempt));
    // mark-activated takes the same request as activate.
    assert_eq!(
        request::value(
            Operation::MarkActivated,
            &names(),
            &live(),
            &attempt,
            Some(&target())
        )?,
        activate
    );
    // Only targeted operations take a target, and they need one.
    assert!(
        request::value(
            Operation::Backup,
            &names(),
            &live(),
            &attempt,
            Some(&target())
        )
        .is_err()
    );
    assert!(request::value(Operation::Activate, &names(), &live(), &attempt, None).is_err());
    let other = Attempt::new("notes", "ab12cd_9")?;
    assert!(request::value(Operation::Backup, &names(), &live(), &other, None).is_err());
    Ok(())
}

#[test]
fn request_bytes_are_canonical_and_the_operator_accepts_them() -> Result<()> {
    let attempt = attempt();
    let backup = request::value(Operation::Backup, &names(), &live(), &attempt, None)?;
    let bytes = request::encode(Operation::Backup, &backup)?;
    let expected = format!(
        concat!(
            r#"{{"app": "links", "app_image": "{live}", "artifact_id": "{artifact}", "#,
            r#""backup_dir": "/tmp/day2-links-backup-ab12cd_9", "configmap": "day2-links-instance", "#,
            r#""namespace": "app-links", "operator": "{operator}", "#,
            r#""pod_label": {{"key": "internal-tools.wonderly.io/service", "value": "background"}}, "#,
            r#""pvc": "data", "statefulset": "day2-links", "tooling_image": "{tooling}", "yes": true}}"#,
            "\n"
        ),
        live = image("links", "a"),
        artifact = LIVE_ARTIFACT,
        operator = APPLY_IDENTITY,
        tooling = image("day2-tooling", "2"),
    );
    assert_eq!(String::from_utf8(bytes)?, expected);
    let activate = request::value(
        Operation::Activate,
        &names(),
        &live(),
        &attempt,
        Some(&target()),
    )?;
    let activated = request::encode(Operation::Activate, &activate)?;
    request::check(Operation::MarkActivated, &activated)?;
    // The operator's own validation refuses what it would refuse at open.
    let mut same = activate.clone();
    same["target"]["app_image"] = json!(image("links", "a"));
    assert_eq!(
        format!(
            "{:#}",
            request::encode(Operation::Activate, &same).unwrap_err()
        ),
        "the target names the running image; nothing to activate"
    );
    let mut keeps = activate.clone();
    keeps["target"]["artifact_id"] = json!(LIVE_ARTIFACT);
    request::encode(Operation::Activate, &keeps)?;
    assert!(request::encode(Operation::MarkActivated, &keeps).is_err());
    Ok(())
}

#[test]
fn names_paths_and_request_ids_are_derived() -> Result<()> {
    assert_eq!(request::namespace("links"), "app-links");
    assert_eq!(request::workload("links"), "day2-links");
    assert_eq!(request::configmap("links"), "day2-links-instance");
    assert_eq!(request::cronjob("links"), "day2-links-backup");
    assert_eq!(request::pod("links"), "day2-links-0");
    assert_eq!(
        request::backup_bucket("exampleco-tools", "links"),
        "exampleco-tools-links-backups"
    );
    assert_eq!(
        request::request_id(COMMIT, &image("links", "e"))?,
        format!("deploy-{COMMIT}-{}", "e".repeat(16))
    );
    assert!(request::request_id("main", &image("links", "e")).is_err());
    assert!(request::request_id(COMMIT, &format!("{REGISTRY}/links/links:latest")).is_err());
    let attempt = attempt();
    assert_eq!(
        attempt.backup_dir(),
        std::path::Path::new("/tmp/day2-links-backup-ab12cd_9")
    );
    assert_eq!(
        attempt.target_instance(),
        std::path::Path::new("/tmp/day2-links-activation-ab12cd_9/desired-instance.json")
    );
    for bad in ["ab12cd9", "ab12cd_9x", "AB12CD_9", "ab12cd-9", "ab/2cd_9"] {
        assert!(Attempt::new("links", bad).is_err(), "{bad}");
    }
    for _ in 0..64 {
        assert!(request::suffix(&request::random_suffix()?));
    }
    // A saved request names exactly one attempt's paths.
    let activate = request::value(
        Operation::Activate,
        &names(),
        &live(),
        &attempt,
        Some(&target()),
    )?;
    assert_eq!(Attempt::of_request("links", &activate)?, attempt);
    for change in [
        json!({"backup_dir": "/var/tmp/day2-links-backup-ab12cd_9"}),
        json!({"backup_dir": "/tmp/day2-links-backup-ab12cd_9/../x"}),
        json!({"target": {"instance": "/tmp/day2-links-activation-zzzzzzzz/desired-instance.json"}}),
        json!({"target": {"instance": "/tmp/elsewhere/desired-instance.json"}}),
    ] {
        let mut changed = activate.clone();
        for (key, value) in change.as_object().unwrap() {
            if key == "target" {
                changed["target"]["instance"] = value["instance"].clone();
            } else {
                changed[key] = value.clone();
            }
        }
        assert!(Attempt::of_request("links", &changed).is_err(), "{change}");
    }
    Ok(())
}

#[test]
fn crc32c_and_base64_are_what_gcs_reports() {
    let crc = |bytes: &[u8]| {
        let mut crc = archive::Crc32c::new();
        crc.update(bytes);
        crc.finish()
    };
    assert_eq!(crc(b""), 0);
    assert_eq!(crc(b"123456789"), 0xE306_9283);
    let mut split = archive::Crc32c::new();
    split.update(b"1234");
    split.update(b"56789");
    assert_eq!(split.finish(), 0xE306_9283);
    assert_eq!(archive::base64(&0xE306_9283_u32.to_be_bytes()), "4waSgw==");
    assert_eq!(archive::base64(&0_u32.to_be_bytes()), "AAAAAA==");
    assert_eq!(archive::base64(b"f"), "Zg==");
    assert_eq!(archive::base64(b"fo"), "Zm8=");
    assert_eq!(archive::base64(b"foo"), "Zm9v");
    assert_eq!(archive::base64(b""), "");
}

/// A backup directory as two maintenance sessions leave it: a backup session's
/// verified copy and journal, then an activation's copy, preflight copy,
/// journal, an interrupted copy and a crashed journal write.
fn backup_tree(root: &std::path::Path) -> Result<std::path::PathBuf> {
    let directory = root.join("day2-links-backup-ab12cd_9");
    fs::create_dir(&directory)?;
    for (name, bytes) in [
        ("A1-20261123T120000Z/backup.json", &b"{}"[..]),
        ("A1-20261123T120000Z/links.sqlite", b"sqlite"),
        ("A1-20261123T120000Z/providers/google.sqlite", b"provider"),
        ("A1-20261123T120000Z/instance.json", b"{\"apps\":{}}"),
        ("A1-20261123T120000Z.session.json", b"{\"events\":[]}"),
        ("B2-20261123T121000Z/backup.json", b"{}"),
        ("B2-20261123T121000Z-preflight/backup.json", b"{}"),
        ("B2-20261123T121000Z.session.json", b"{\"events\":[1]}"),
        ("B2-20261123T121000Z.session.json.tmp", b"{\"ev"),
        ("C3-20261123T122000Z.INCOMPLETE/links.sqlite", b"part"),
        ("empty", b""),
    ] {
        let path = directory.join(name);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, bytes)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    }
    Ok(directory)
}

#[test]
fn archives_keep_the_controllers_paths_and_check_every_object() -> Result<()> {
    let root = tempfile::tempdir()?;
    let directory = backup_tree(root.path())?;
    let entries = archive::manifest(&directory)?;
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "A1-20261123T120000Z.session.json",
            "A1-20261123T120000Z/backup.json",
            "A1-20261123T120000Z/instance.json",
            "A1-20261123T120000Z/links.sqlite",
            "A1-20261123T120000Z/providers/google.sqlite",
            "B2-20261123T121000Z-preflight/backup.json",
            "B2-20261123T121000Z.session.json",
            "B2-20261123T121000Z.session.json.tmp",
            "B2-20261123T121000Z/backup.json",
            "C3-20261123T122000Z.INCOMPLETE/links.sqlite",
            "empty",
        ]
    );
    assert_eq!(
        entries.last().unwrap(),
        &Entry {
            name: "empty".into(),
            size: 0,
            crc32c: "AAAAAA==".into()
        }
    );
    let uuid = archive::uuid4([0xff; 16]);
    assert_eq!(uuid, "ffffffffffff4fffbfffffffffffffff");
    let prefix = archive::prefix("exampleco-tools-links-backups", COMMIT, &uuid)?;
    assert_eq!(
        prefix,
        format!("gs://exampleco-tools-links-backups/deployments/{COMMIT}/{uuid}/")
    );
    assert!(archive::prefix("exampleco-tools-links-backups", "main", &uuid).is_err());
    assert!(archive::prefix("exampleco-tools-links-backups", COMMIT, "short").is_err());
    let name = archive::directory_name(&directory)?;
    let expected = archive::expected(&prefix, archive::BEFORE, &name, &entries)?;
    assert_eq!(
        expected.keys().next().unwrap(),
        &format!(
            "deployments/{COMMIT}/{uuid}/before-activation/day2-links-backup-ab12cd_9/A1-20261123T120000Z.session.json"
        )
    );
    assert_eq!(
        archive::upload_args(&directory, &prefix, archive::BEFORE),
        [
            "storage".into(),
            "cp".into(),
            "--recursive".into(),
            "--no-clobber".into(),
            directory.clone().into_os_string(),
            format!("{prefix}before-activation/").into(),
        ]
    );
    assert_eq!(
        archive::list_args(&prefix, archive::AFTER),
        [
            "storage",
            "objects",
            "list",
            &format!("{prefix}after-activation/**"),
            "--format=json(name,size,crc32c_hash)"
        ]
        .map(std::ffi::OsString::from)
    );
    // The listing must name exactly the manifest, sizes as numbers or strings.
    let listing = |objects: &std::collections::BTreeMap<String, (u64, String)>| -> Vec<Value> {
        objects
            .iter()
            .map(|(name, (size, crc))| json!({"name": name, "size": size, "crc32c_hash": crc}))
            .collect()
    };
    let totals = archive::verify(&serde_json::to_vec(&listing(&expected))?, &expected)?;
    assert_eq!(totals.objects, 11);
    assert_eq!(
        totals.bytes,
        entries.iter().map(|entry| entry.size).sum::<u64>()
    );
    let mut stringly = listing(&expected);
    stringly[0]["size"] = json!(stringly[0]["size"].to_string());
    archive::verify(&serde_json::to_vec(&stringly)?, &expected)?;
    let refused = |items: Vec<Value>| {
        format!(
            "{:#}",
            archive::verify(&serde_json::to_vec(&items).unwrap(), &expected).unwrap_err()
        )
    };
    let mut missing = listing(&expected);
    let gone = missing.remove(3);
    assert_eq!(
        refused(missing),
        format!(
            "archive object {} is missing after the upload",
            gone["name"].as_str().unwrap()
        )
    );
    let mut changed = listing(&expected);
    changed[2]["crc32c_hash"] = json!("AAAAAA==");
    assert!(refused(changed).ends_with("differs from the local backup"));
    let mut resized = listing(&expected);
    resized[2]["size"] = json!(99);
    assert!(refused(resized).ends_with("differs from the local backup"));
    let mut extra = listing(&expected);
    extra.push(json!({"name": format!("deployments/{COMMIT}/{uuid}/before-activation/other"), "size": 1, "crc32c_hash": "AAAAAA=="}));
    assert!(refused(extra).ends_with("is not in the local backup"));
    let mut twice = listing(&expected);
    twice.push(twice[0].clone());
    assert!(refused(twice).ends_with("is listed twice"));
    assert!(archive::verify(b"{}", &expected).is_err());
    assert!(archive::verify(br#"[{"name": "x"}]"#, &expected).is_err());
    Ok(())
}

#[test]
fn archives_refuse_links_devices_and_unbounded_trees() -> Result<()> {
    let root = tempfile::tempdir()?;
    let directory = backup_tree(root.path())?;
    std::os::unix::fs::symlink("/etc/hostname", directory.join("link"))?;
    assert_eq!(
        format!("{:#}", archive::manifest(&directory).unwrap_err()),
        "the backup directory may hold only files and directories: link"
    );
    fs::remove_file(directory.join("link"))?;
    let socket = std::os::unix::net::UnixListener::bind(directory.join("socket"))?;
    assert_eq!(
        format!("{:#}", archive::manifest(&directory).unwrap_err()),
        "the backup directory may hold only files and directories: socket"
    );
    drop(socket);
    fs::remove_file(directory.join("socket"))?;
    std::os::unix::fs::symlink(&directory, root.path().join("linked"))?;
    assert!(archive::manifest(&root.path().join("linked")).is_err());
    let mut deep = directory.clone();
    for level in 0..=archive::MAX_DEPTH {
        deep = deep.join(format!("d{level}"));
    }
    fs::create_dir_all(&deep)?;
    fs::write(deep.join("f"), b"x")?;
    assert_eq!(
        format!("{:#}", archive::manifest(&directory).unwrap_err()),
        "the backup directory nests too deeply"
    );
    assert!(archive::nonempty(&directory)?);
    let empty = root.path().join("empty");
    fs::create_dir(&empty)?;
    assert!(!archive::nonempty(&empty)?);
    assert!(archive::nonempty(&root.path().join("absent")).is_err());
    Ok(())
}

/// A StatefulSet as kubectl prints it.
pub(crate) fn statefulset(
    image: &str,
    replicas: u64,
    stamp: Option<&str>,
    checkpoint: Option<(&str, &str)>,
) -> Value {
    let mut annotations = serde_json::Map::new();
    if let Some(stamp) = stamp {
        annotations.insert("day2.dev/activated-image".into(), json!(stamp));
    }
    if let Some((phase, digest)) = checkpoint {
        annotations.insert(
            "day2.dev/activation".into(),
            json!(
                json!({
                    "format": 1, "owner": "abcdef0123456789-20261123T120000Z",
                    "request_digest": digest, "target_instance_digest": format!("sha256:{}", "9".repeat(64)),
                    "controller_uid": "uid-1", "template_digest": format!("sha256:{}", "8".repeat(64)),
                    "source_instance_digest": format!("sha256:{}", "7".repeat(64)), "pvc_uid": "pvc-1",
                    "replicas": 1, "pod": "day2-maintenance-x", "pod_uid": null, "phase": phase,
                })
                .to_string()
            ),
        );
    }
    json!({
        "metadata": {"name": "day2-links", "generation": 4, "annotations": annotations},
        "spec": {"replicas": replicas, "template": {"spec": {"containers": [{"name": "day2", "image": image}]}}},
        "status": {"readyReplicas": replicas, "observedGeneration": 4,
            "currentRevision": "day2-links-1", "updateRevision": "day2-links-1"},
    })
}

fn observed(statefulset: Option<Value>, claim: Claim) -> Observed {
    Observed {
        workload: statefulset.map(|value| Workload::read(&value).unwrap()),
        claim,
    }
}

const DIGEST: &str = "sha256:5555555555555555555555555555555555555555555555555555555555555555";

#[test]
fn the_path_follows_the_live_workload() {
    let old = image("links", "a");
    let new = image("links", "e");
    let choose = |statefulset: Option<Value>, claim: Claim| {
        fence::choose(&observed(statefulset, claim), &new)
    };
    let path = |value: Value| choose(Some(value), Claim::Bound).unwrap();
    assert_eq!(path(statefulset(&old, 1, None, None)), Path::Fresh);
    // A stamp equal to the live image is inert; a completed checkpoint is evidence.
    assert_eq!(
        path(statefulset(&old, 1, Some(&old), Some(("restored", DIGEST)))),
        Path::Fresh
    );
    assert_eq!(
        path(statefulset(
            &old,
            0,
            Some(&new),
            Some(("activated", DIGEST))
        )),
        Path::Activated
    );
    assert_eq!(
        path(statefulset(&new, 1, None, Some(("activated", DIGEST)))),
        Path::Serving
    );
    assert_eq!(choose(None, Claim::Unbound).unwrap(), Path::Install);
    let refusal =
        |statefulset: Option<Value>, claim: Claim| choose(statefulset, claim).unwrap_err();
    let bound = refusal(None, Claim::Bound);
    assert_eq!(bound.class, Class::Failed);
    assert!(
        bound
            .message
            .starts_with("the app's state volume is bound but it has no workload")
    );
    assert_eq!(refusal(None, Claim::Absent).class, Class::Failed);
    for (phase, class) in [
        ("prepared", Class::Failed),
        ("stopped", Class::Failed),
        ("fenced", Class::Fenced),
        ("recovering", Class::Fenced),
    ] {
        let refused = refusal(
            Some(statefulset(&old, 0, None, Some((phase, DIGEST)))),
            Claim::Bound,
        );
        assert_eq!(refused.class, class, "{phase}");
        assert!(
            refused
                .message
                .starts_with("activation_recovery_required: "),
            "{phase}"
        );
    }
    // Activated for another image that was never rolled: forward only.
    let other = image("links", "f");
    let refused = refusal(Some(statefulset(&old, 0, Some(&other), None)), Claim::Bound);
    assert_eq!(refused.class, Class::Fenced);
    // A checkpoint this CLI cannot read is refused when the workload is read.
    let mut unknown = statefulset(&old, 1, None, Some(("fenced", DIGEST)));
    unknown["metadata"]["annotations"]["day2.dev/activation"] = json!("{\"format\": 2}");
    assert!(Workload::read(&unknown).is_err());
    let mut sidecar = statefulset(&old, 1, None, None);
    sidecar["spec"]["template"]["spec"]["containers"] =
        json!([{"name": "proxy", "image": "x"}, {"name": "day2", "image": old}]);
    assert_eq!(
        format!("{:#}", Workload::read(&sidecar).unwrap_err()),
        "the workload's first container is not day2"
    );
}

#[test]
fn claims_are_unbound_only_while_pending_without_a_volume() {
    assert_eq!(Claim::read(None), Claim::Absent);
    assert_eq!(
        Claim::read(Some(&json!({"spec": {}, "status": {"phase": "Pending"}}))),
        Claim::Unbound
    );
    assert_eq!(
        Claim::read(Some(
            &json!({"spec": {"volumeName": ""}, "status": {"phase": "Pending"}})
        )),
        Claim::Unbound
    );
    for pvc in [
        json!({"spec": {"volumeName": "pv-1"}, "status": {"phase": "Bound"}}),
        json!({"spec": {"volumeName": "pv-1"}, "status": {"phase": "Pending"}}),
        json!({"spec": {}, "status": {"phase": "Lost"}}),
        json!({}),
    ] {
        assert_eq!(Claim::read(Some(&pvc)), Claim::Bound, "{pvc}");
    }
}

#[test]
fn the_deadline_budget_is_the_sum_of_every_remaining_step() -> Result<()> {
    use budget::*;
    assert_eq!(APPLY, 1680);
    assert_eq!(ROLLOUT, 660);
    assert_eq!(READBACK, 240);
    let roll = APPLY + ROLLOUT + READBACK + CLASSIFY;
    assert_eq!(
        fence::remaining(Path::Fresh),
        BACKUP + MAINTAIN_GRACE + 2 * ARCHIVE + ACTIVATE + MAINTAIN_GRACE + roll
    );
    assert_eq!(fence::remaining(Path::Fresh), 8460);
    for path in [Path::Activated, Path::Serving, Path::Install] {
        assert_eq!(fence::remaining(path), roll);
    }
    let now = 1_800_000_000;
    fence::within(now, None, Path::Fresh)?;
    fence::within(now, Some(now + 8460), Path::Fresh)?;
    assert_eq!(
        format!(
            "{:#}",
            fence::within(now, Some(now + 8459), Path::Fresh).unwrap_err()
        ),
        "deploy_deadline: the fresh path needs up to 8460 s, but the job's deadline is 8459 s away; nothing was \
         stopped, retry with more time"
    );
    fence::within(now, Some(now + 2640), Path::Serving)?;
    assert!(fence::within(now, Some(now - 1), Path::Install).is_err());
    Ok(())
}

#[test]
fn a_failure_is_classified_from_the_workload_read_after_it() {
    let old = image("links", "a");
    let new = image("links", "e");
    let after = |value: Option<Value>| observed(value, Claim::Bound);
    let base = Failure {
        stage: Stage::Backup,
        retryable: false,
        path: Some(Path::Fresh),
        mutated: true,
        activated: false,
        verified: false,
        original: Some(&old),
        target: &new,
        after: None,
    };
    let class = |failure: &Failure<'_>| fence::classify(failure);
    // Before anything stops: retryable reads are exit 7, the rest 6.
    for stage in [
        Stage::Prepare,
        Stage::Operator,
        Stage::Credentials,
        Stage::Observe,
        Stage::Target,
        Stage::Deadline,
    ] {
        let unchanged = Failure {
            stage,
            mutated: false,
            retryable: true,
            ..base.clone()
        };
        assert_eq!(class(&unchanged).0, Class::Unavailable);
        let refused = Failure {
            retryable: false,
            ..unchanged
        };
        assert_eq!(class(&refused).0, Class::Failed);
    }
    // A run that changed nothing on an already-activated app is still past the fence.
    let activated = Failure {
        stage: Stage::Deadline,
        mutated: false,
        path: Some(Path::Activated),
        ..base.clone()
    };
    assert_eq!(class(&activated).0, Class::Fenced);
    // An unreadable workload after a change counts as fenced.
    assert_eq!(class(&base).0, Class::Fenced);
    let restored = after(Some(statefulset(&old, 1, None, Some(("restored", DIGEST)))));
    assert_eq!(
        class(&Failure {
            after: Some(&restored),
            ..base.clone()
        }),
        (Class::Failed, "the app was restored on its image")
    );
    let stopped = after(Some(statefulset(&old, 0, None, None)));
    let (stopped_class, message) = class(&Failure {
        after: Some(&stopped),
        ..base.clone()
    });
    assert_eq!(stopped_class, Class::Failed);
    assert!(message.starts_with("activation_recovery_required: "));
    for (phase, expected) in [
        ("prepared", Class::Failed),
        ("stopped", Class::Failed),
        ("fenced", Class::Fenced),
        ("recovering", Class::Fenced),
    ] {
        let workload = after(Some(statefulset(&old, 0, None, Some((phase, DIGEST)))));
        let failure = Failure {
            stage: Stage::Activate,
            after: Some(&workload),
            ..base.clone()
        };
        assert_eq!(class(&failure).0, expected, "{phase}");
    }
    // Activated in this run: everything after is forward only.
    let stamped = after(Some(statefulset(
        &old,
        0,
        Some(&new),
        Some(("activated", DIGEST)),
    )));
    for stage in [
        Stage::Apply,
        Stage::Rollout,
        Stage::Readback,
        Stage::ArchiveAfter,
    ] {
        let failure = Failure {
            stage,
            activated: true,
            after: Some(&stamped),
            ..base.clone()
        };
        assert_eq!(class(&failure).0, Class::Fenced, "{stage:?}");
    }
    // A stamp for the target that was not rolled is fenced even without the flag.
    let failure = Failure {
        stage: Stage::Activate,
        after: Some(&stamped),
        ..base.clone()
    };
    assert_eq!(class(&failure).0, Class::Fenced);
    // Only a failed final archive after a verified readback leaves exit 6.
    let serving = after(Some(statefulset(
        &new,
        1,
        None,
        Some(("activated", DIGEST)),
    )));
    let archived = Failure {
        stage: Stage::ArchiveAfter,
        activated: true,
        verified: true,
        after: Some(&serving),
        ..base.clone()
    };
    assert_eq!(
        class(&archived),
        (
            Class::Failed,
            "the app serves the target, but its evidence was not archived"
        )
    );
    // Serving the target already: a failed apply or readback is forward only.
    let failure = Failure {
        stage: Stage::Readback,
        path: Some(Path::Serving),
        after: Some(&serving),
        ..base.clone()
    };
    assert_eq!(class(&failure).0, Class::Fenced);
    // A first install that fails leaves nothing that was serving.
    let none = after(None);
    let install = Failure {
        stage: Stage::Apply,
        path: Some(Path::Install),
        original: None,
        after: Some(&none),
        ..base.clone()
    };
    assert_eq!(class(&install).0, Class::Failed);
    let half = after(Some(statefulset(&new, 1, None, None)));
    assert_eq!(
        class(&Failure {
            after: Some(&half),
            ..install.clone()
        })
        .0,
        Class::Failed
    );
    // A workload that vanished, or runs something else, is fenced.
    assert_eq!(
        class(&Failure {
            after: Some(&none),
            ..base.clone()
        })
        .0,
        Class::Fenced
    );
    let other = after(Some(statefulset(&image("links", "f"), 1, None, None)));
    assert_eq!(
        class(&Failure {
            after: Some(&other),
            ..base.clone()
        })
        .0,
        Class::Fenced
    );
}

#[test]
fn checkpoints_read_with_the_operators_format() -> Result<()> {
    let workload = Workload::read(&statefulset(
        &image("links", "a"),
        0,
        None,
        Some(("fenced", DIGEST)),
    ))?;
    let checkpoint = workload.checkpoint.unwrap();
    assert_eq!(checkpoint.phase, Phase::Fenced);
    assert_eq!(checkpoint.request_digest, DIGEST);
    assert!(checkpoint.active());
    Ok(())
}
