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
    for byte in 0..=255_u8 {
        assert!(request::suffix(&request::suffix_from([byte; 16])));
    }
    assert_eq!(request::suffix_from([0; 16]), "aaaaaaaa");
    assert_eq!(request::suffix_from([36; 16]), "________");
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
        "deploy_deadline: the fresh path needs up to 8460 s, but the job's deadline is 8459 s away; retry with \
         more time"
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

// ---------------------------------------------------------------------------
// The session, against a fake cluster, bucket and operator. The fake operator
// walks the maintenance session's journal steps and changes the fake workload
// as the real session would, so a failure can be injected at any step.

use super::{Effects, FENCED, Session, tools as deploy};
use crate::instance_candidate::record;
use crate::instance_source::tests::{BUCKET, Fake, PLATFORM};
use day2::sdk_release::{
    BlobIdentity, Distribution, Evidence, Image, OPERATOR_FILES, PROFILE, Release, TARGET,
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    path::{Path as FsPath, PathBuf},
    rc::Rc,
};

const GOLDEN_RECEIPT: &str = include_str!("../../../../cli/fixtures/deploy-receipt.json");

/// A qualified release whose operator files are synthetic bytes (each its own
/// name), as the candidate tests publish one.
struct Published {
    release: Release,
    manifest: Vec<u8>,
    distribution: Vec<u8>,
    native: Vec<u8>,
    strict: Vec<u8>,
}

fn published() -> Published {
    let digest = |label: &str| day2::digest(label.as_bytes());
    let blob = |label: &str| BlobIdentity::of(label.as_bytes());
    let operator = blob("operator archive");
    let distribution = Distribution {
        format: 1,
        target: TARGET.into(),
        inputs: digest("inputs"),
        workflow_sources: digest("workflows"),
        toolchain: digest("toolchain"),
        worker: blob("!<arch>\nworker"),
        operator: operator.clone(),
        operator_files: OPERATOR_FILES
            .iter()
            .map(|name| ((*name).to_owned(), blob(name)))
            .collect(),
    };
    let runtime = digest("runtime config");
    let tooling = digest("tooling config");
    let raw_distribution = serde_json::to_vec_pretty(&distribution).unwrap();
    let native = json!({
        "format": 1, "status": "passed", "scope": PROFILE, "source_revision": PLATFORM,
        "runtime_image": runtime, "tooling_image": tooling,
        "workflow": distribution.workflow_sources, "toolchain": distribution.toolchain,
        "platform": digest("platform"), "platform_inventory": digest("inventory"),
        "artifact": digest("fixture app"), "environment": {"architecture": "x86_64"},
        "tooling_distribution": {"distribution": day2::digest(&raw_distribution),
            "operator": operator, "worker": distribution.worker},
    });
    let raw_native = serde_json::to_vec(&native).unwrap();
    let mut strict = json!({"status": "strict-admission-passed", "qualification": false,
        "qualification_digest": day2::digest(&raw_native)});
    for field in [
        "runtime_image",
        "tooling_image",
        "platform",
        "platform_inventory",
        "artifact",
    ] {
        strict[field] = native[field].clone();
    }
    let raw_strict = serde_json::to_vec(&strict).unwrap();
    let release = Release {
        version: 1,
        platform_commit: PLATFORM.into(),
        profile: PROFILE.into(),
        target: TARGET.into(),
        runtime: Image {
            image: format!("{REGISTRY}/links/day2-runtime@{runtime}"),
            config: runtime,
        },
        tooling: Image {
            image: format!("{REGISTRY}/links/day2-tooling@{tooling}"),
            config: tooling,
        },
        distribution: BlobIdentity::of(&raw_distribution),
        operator,
        evidence: Evidence {
            native: BlobIdentity::of(&raw_native),
            strict: BlobIdentity::of(&raw_strict),
        },
    };
    Published {
        manifest: release.encode().unwrap(),
        release,
        distribution: raw_distribution,
        native: raw_native,
        strict: raw_strict,
    }
}

/// A checked candidate record for `links` at `COMMIT`, as the deploy
/// controller stores one, for the release `reference` and its native evidence.
fn candidate_record(reference: &BlobIdentity, native: &str, image: &str, artifact: &str) -> Value {
    let verification = json!({"cases": 4, "seed": 42, "version": 1});
    let binding = json!({
        "app": "links",
        "ci_artifact": {"digest": format!("sha256:{}", "3".repeat(64)), "job": "roc", "version": 1,
            "workflow": "roc.yml"},
        "directory": ".",
        "image_repository": format!("{REGISTRY}/links/links"),
        "qualified_release": {"bytes": reference.bytes, "digest": reference.digest},
        "repository": "tools/links-app",
        "runtime_image": format!("{REGISTRY}/links/day2-runtime@sha256:{}", "1".repeat(64)),
        "source": {"branch": "main", "forge": "gitea", "repository": "tools/links-app",
            "repository_id": 7, "server": "https://git.example.com"},
        "tooling_image": image_of("day2-tooling", "2"),
        "verification": verification,
    });
    let inputs = format!("sha256:{}", "cd".repeat(32));
    json!({
        "artifact_id": artifact,
        "binding": binding,
        "build_log": record::log_uri(BUCKET, "links", &record::binding_digest(&binding).unwrap(), COMMIT),
        "checked_commit": COMMIT,
        "ci_artifact": {"attempt": 1, "job": 2, "receipt": {
            "archive": {"bytes": 100, "digest": format!("sha256:{}", "4".repeat(64))},
            "artifact_id": artifact,
            "artifact_name": format!("day2-checked-app-{COMMIT}-{}", "5".repeat(32)),
            "examples": 1, "generated": 2, "repository": "tools/links-app",
            "sdk_release": {"bytes": reference.bytes, "digest": reference.digest},
            "source_commit": COMMIT, "source_inputs": inputs, "upload_id": 9,
            "verification": verification, "version": 1}, "run": 1, "version": 1},
        "image": image,
        "security_requirements": {"artifact": format!("sha256:{artifact}"),
            "containment": {"evidence": {"receipt_digest": native}, "kind": "linux_qualified_v1"},
            "version": 1},
        "source_commit": COMMIT,
        "source_inputs": inputs,
        "version": 1,
    })
}

fn image_of(name: &str, fill: &str) -> String {
    image(name, fill)
}

/// How the fake operator ends a run that fails at a journal step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    /// The session errs and its Drop cleans up (exit 1).
    Exit,
    /// SIGINT from the deploy: the session cleans up.
    Interrupt,
    /// The deploy's deadline: SIGINT, then the session cleans up.
    Deadline,
    /// Killed outright: no cleanup at all.
    Killed,
}

/// The maintenance session's journal steps, as `ops/Maintain.roc` orders them.
fn journal(operation: Operation) -> &'static [&'static str] {
    match operation {
        Operation::Backup => &[
            "open",
            "artifacts",
            "stop",
            "measure",
            "pod",
            "operation-claimed",
            "backup",
            "backup-copied",
            "finish",
        ],
        Operation::Activate => &[
            "open",
            "artifacts",
            "preparation-intent",
            "measure",
            "pod",
            "operation-claimed",
            "stop",
            "scratch",
            "backup",
            "backup-copied",
            "rehearsal-copy",
            "migration-plan",
            "target-admitted",
            "confirmed",
            "fence",
            "migration-applied",
            "authority-inspect",
            "authority-activated",
            "live-store-admitted",
            "mark-activated",
            "finish",
        ],
        Operation::MarkActivated => &[
            "open",
            "artifacts",
            "preparation-intent",
            "stop",
            "measure",
            "pod",
            "operation-claimed",
            "authority-inspect",
            "mark-activated",
            "finish",
        ],
    }
}

#[derive(Default)]
struct ClusterWorld {
    statefulset: Option<Value>,
    configmap: Option<Value>,
    pod: Option<Value>,
    cronjob: Option<Value>,
    pvc: Option<Value>,
    /// Objects in the backup bucket: name -> (size, crc32c).
    objects: BTreeMap<String, (u64, String)>,
    calls: Vec<String>,
    /// Verbs that fail: `credentials`, `get <kind>`, `rollout`, `upload <phase>`, `list <phase>`.
    failing: Vec<String>,
    /// The operation, journal step and ending a run fails at.
    fail_at: Option<(Operation, &'static str, Ending)>,
    /// Each operator run: its operation and request.
    runs: Vec<(Operation, Value)>,
    /// The database's active artifact, which mark-activated reads.
    active_artifact: String,
    now: u64,
    suffixes: Vec<String>,
    config: Option<deploy::Config>,
}

#[derive(Clone, Default)]
struct FakeTools(Rc<RefCell<ClusterWorld>>);

fn checkpoint_value(phase: &str, request: &str, target: &str) -> String {
    json!({
        "format": 1, "owner": "abcdef0123456789-20261123T120000Z",
        "request_digest": request, "target_instance_digest": target,
        "controller_uid": "uid-1", "template_digest": format!("sha256:{}", "8".repeat(64)),
        "source_instance_digest": format!("sha256:{}", "7".repeat(64)), "pvc_uid": "pvc-1",
        "replicas": 1, "pod": "day2-maintenance-x", "pod_uid": null, "phase": phase,
    })
    .to_string()
}

impl ClusterWorld {
    fn annotate(&mut self, key: &str, value: Option<String>) {
        let annotations = &mut self.statefulset.as_mut().unwrap()["metadata"]["annotations"];
        match value {
            Some(value) => annotations[key] = json!(value),
            None => {
                annotations.as_object_mut().unwrap().remove(key);
            }
        }
    }

    fn replicas(&mut self, count: u64) {
        let statefulset = self.statefulset.as_mut().unwrap();
        statefulset["spec"]["replicas"] = json!(count);
        statefulset["status"]["readyReplicas"] = json!(count);
    }

    fn phase(&self) -> Option<String> {
        self.statefulset.as_ref().and_then(|statefulset| {
            statefulset["metadata"]["annotations"]["day2.dev/activation"]
                .as_str()
                .map(|raw| {
                    serde_json::from_str::<Value>(raw).unwrap()["phase"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
        })
    }

    fn set_phase(&mut self, phase: &str, request: &str, target: &str) {
        self.annotate(
            "day2.dev/activation",
            Some(checkpoint_value(phase, request, target)),
        );
    }

    /// One fake maintenance session: each journal step's effect on the fake
    /// workload and the private backup directory, a failure where asked, and
    /// the cleanup the real session's Drop does (or none, when killed).
    fn maintain(&mut self, operation: Operation, path: &FsPath) -> deploy::Ran {
        let bytes = fs::read(path).unwrap();
        request::check(operation, &bytes).unwrap();
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        self.runs.push((operation, request.clone()));
        let backup = PathBuf::from(request["backup_dir"].as_str().unwrap());
        let stamp = format!(
            "{:016x}-20261123T12{:02}00Z",
            self.runs.len(),
            self.runs.len()
        );
        let request_digest = day2::digest(&bytes);
        let target_digest = request["target"]["instance"]
            .as_str()
            .map(|instance| day2::digest(&fs::read(instance).unwrap()))
            .unwrap_or_default();
        let original = self.statefulset.as_ref().unwrap()["spec"]["replicas"]
            .as_u64()
            .unwrap();
        let mut done = Vec::new();
        let mut fenced = matches!(self.phase().as_deref(), Some("fenced"));
        let failure = self.fail_at.filter(|(failing, _, _)| *failing == operation);
        for step in journal(operation) {
            if failure.is_some_and(|(_, at, _)| at == *step) {
                break;
            }
            done.push(*step);
            fs::write(
                backup.join(format!("{stamp}.session.json")),
                json!({"format": 2, "steps": done}).to_string(),
            )
            .unwrap();
            let target = request["target"]["app_image"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            match (*step, operation) {
                ("preparation-intent", _) if !fenced => {
                    self.set_phase("prepared", &request_digest, &target_digest)
                }
                ("stop", _) => {
                    self.replicas(0);
                    if operation != Operation::Backup && !fenced {
                        self.set_phase("stopped", &request_digest, &target_digest);
                    }
                }
                ("backup-copied", _) => {
                    let copy = backup.join(&stamp);
                    fs::create_dir_all(copy.join("providers")).unwrap();
                    fs::write(copy.join("backup.json"), b"{}").unwrap();
                    fs::write(copy.join("links.sqlite"), stamp.as_bytes()).unwrap();
                    fs::write(copy.join("providers/google.sqlite"), b"provider").unwrap();
                }
                ("fence", _) => {
                    fenced = true;
                    self.set_phase("fenced", &request_digest, &target_digest);
                }
                ("migration-applied", _) => {
                    self.active_artifact = request["target"]["artifact_id"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                }
                ("mark-activated", Operation::MarkActivated)
                    if self.active_artifact
                        != request["target"]["artifact_id"].as_str().unwrap() =>
                {
                    // The database proves nothing about the target: refused,
                    // nothing marked.
                    return self.cleanup(fenced, original, Some(1));
                }
                ("mark-activated", _) => {
                    self.annotate("day2.dev/activated-image", Some(target));
                    self.set_phase("activated", &request_digest, &target_digest);
                }
                ("finish", Operation::Backup) => {
                    self.replicas(original);
                }
                _ => {}
            }
        }
        match failure {
            None => deploy::Ran {
                code: Some(0),
                stdout: format!(
                    "progress\n{}\n",
                    json!({"operation": operation.name(), "journal": backup.join(format!("{stamp}.session.json"))})
                )
                .into_bytes(),
                ..deploy::Ran::default()
            },
            Some((_, _, Ending::Killed)) => deploy::Ran {
                code: None,
                killed: true,
                ..deploy::Ran::default()
            },
            Some((_, _, ending)) => {
                let mut ran = self.cleanup(fenced, original, Some(1));
                ran.stopped = match ending {
                    Ending::Interrupt => Some("interrupt"),
                    Ending::Deadline => Some("deadline"),
                    _ => None,
                };
                ran
            }
        }
    }

    /// The session's Drop: before the fence the app is restored on its image;
    /// after it the old image is never restarted.
    fn cleanup(&mut self, fenced: bool, original: u64, code: Option<i32>) -> deploy::Ran {
        if !fenced {
            self.replicas(original);
            if self
                .phase()
                .is_some_and(|phase| phase == "prepared" || phase == "stopped")
            {
                let annotation = self.statefulset.as_ref().unwrap()["metadata"]["annotations"]
                    ["day2.dev/activation"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let mut checkpoint: Value = serde_json::from_str(&annotation).unwrap();
                checkpoint["phase"] = json!("restored");
                self.annotate("day2.dev/activation", Some(checkpoint.to_string()));
            }
        }
        deploy::Ran {
            code,
            ..deploy::Ran::default()
        }
    }

    fn fail(&self, verb: &str) -> Result<()> {
        if self.failing.iter().any(|failing| failing == verb) {
            anyhow::bail!("{verb} failed (exit 1)");
        }
        Ok(())
    }
}

impl deploy::Tools for FakeTools {
    fn configure(&mut self, config: deploy::Config) {
        self.0.borrow_mut().config = Some(config);
    }

    fn credentials(&mut self) -> Result<()> {
        let mut world = self.0.borrow_mut();
        world.calls.push("credentials".into());
        world.fail("credentials")?;
        let path = world.config.as_ref().unwrap().kubeconfig.clone();
        fs::write(path, b"apiVersion: v1\n")?;
        Ok(())
    }

    fn get(&mut self, namespace: &str, kind: deploy::Kind, name: &str) -> Result<Option<Value>> {
        let mut world = self.0.borrow_mut();
        assert_eq!(namespace, "app-links");
        let verb = format!("get {}", kind.resource());
        world.calls.push(format!("{verb} {name}"));
        world.fail(&verb)?;
        Ok(match kind {
            deploy::Kind::StatefulSet => world.statefulset.clone(),
            deploy::Kind::ConfigMap => world.configmap.clone(),
            deploy::Kind::Pod => world.pod.clone(),
            deploy::Kind::CronJob => world.cronjob.clone(),
            deploy::Kind::Claim => world.pvc.clone(),
        })
    }

    fn rollout(&mut self, namespace: &str, workload: &str) -> Result<()> {
        let mut world = self.0.borrow_mut();
        assert_eq!((namespace, workload), ("app-links", "day2-links"));
        world.calls.push("rollout".into());
        world.fail("rollout")
    }

    fn upload(&mut self, directory: &FsPath, prefix: &str, phase: &str) -> Result<()> {
        let mut world = self.0.borrow_mut();
        world.calls.push(format!("upload {phase}"));
        world.fail(&format!("upload {phase}"))?;
        let path = prefix
            .strip_prefix("gs://")
            .unwrap()
            .split_once('/')
            .unwrap()
            .1;
        let name = archive::directory_name(directory)?;
        for entry in archive::manifest(directory)? {
            let object = format!("{path}{phase}/{name}/{}", entry.name);
            // Retention: an existing object is never replaced (--no-clobber skips it).
            world
                .objects
                .entry(object)
                .or_insert((entry.size, entry.crc32c));
        }
        Ok(())
    }

    fn list(&mut self, prefix: &str, phase: &str) -> Result<Vec<u8>> {
        let mut world = self.0.borrow_mut();
        world.calls.push(format!("list {phase}"));
        world.fail(&format!("list {phase}"))?;
        let path = format!(
            "{}{phase}/",
            prefix
                .strip_prefix("gs://")
                .unwrap()
                .split_once('/')
                .unwrap()
                .1
        );
        let items: Vec<Value> = world
            .objects
            .iter()
            .filter(|(name, _)| name.starts_with(&path))
            .map(|(name, (size, crc))| json!({"name": name, "size": size, "crc32c_hash": crc}))
            .collect();
        Ok(serde_json::to_vec(&items)?)
    }

    fn maintain(
        &mut self,
        operator: &FsPath,
        operation: Operation,
        request: &FsPath,
        deadline: std::time::Duration,
    ) -> Result<deploy::Ran> {
        assert!(
            operator.ends_with("operator/cli/day2"),
            "{}",
            operator.display()
        );
        assert_eq!(
            deadline.as_secs(),
            match operation {
                Operation::Backup => budget::BACKUP,
                Operation::Activate => budget::ACTIVATE,
                Operation::MarkActivated => unreachable!("mark-activated runs only on a resume"),
            }
        );
        let mut world = self.0.borrow_mut();
        world.calls.push(format!("maintain {}", operation.name()));
        Ok(world.maintain(operation, request))
    }

    fn now(&mut self) -> Result<u64> {
        Ok(self.0.borrow().now)
    }

    fn random(&mut self) -> Result<[u8; 16]> {
        use ring::rand::SecureRandom;
        let mut bytes = [0_u8; 16];
        ring::rand::SystemRandom::new().fill(&mut bytes).unwrap();
        self.0
            .borrow_mut()
            .suffixes
            .push(request::suffix_from(bytes));
        Ok(bytes)
    }
}

const OLD_ARTIFACT: &str = LIVE_ARTIFACT;

/// The instance, the release, the candidate and a fake cluster running `old`.
struct World {
    directory: tempfile::TempDir,
    fake: Fake,
    cluster: FakeTools,
    published: Published,
    target: String,
    artifact: String,
    runs: RefCell<u32>,
}

impl Drop for World {
    fn drop(&mut self) {
        // Writable again so the temporary directory can be removed, and the
        // attempts' fixed /tmp directories removed with it.
        fn writable(path: &FsPath) {
            if let Ok(metadata) = fs::symlink_metadata(path)
                && metadata.is_dir()
            {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        writable(&entry.path());
                    }
                }
            }
        }
        writable(self.directory.path());
        for suffix in &self.cluster.0.borrow().suffixes {
            for kind in ["backup", "activation"] {
                let _ = fs::remove_dir_all(format!("/tmp/day2-links-{kind}-{suffix}"));
            }
        }
    }
}

/// The workload's objects for `image` and `artifact`, ready at one replica.
fn serving(world: &mut ClusterWorld, image_name: &str, artifact: &str, instance: Option<&str>) {
    let instance = instance.map(str::to_owned).unwrap_or_else(|| {
        json!({"apps": {"links": {"artifact": format!("artifacts/{artifact}")}}}).to_string()
    });
    let generation = world
        .statefulset
        .as_ref()
        .and_then(|statefulset| statefulset["metadata"]["generation"].as_u64())
        .unwrap_or(0)
        + 1;
    let annotations = world
        .statefulset
        .as_ref()
        .map(|statefulset| statefulset["metadata"]["annotations"].clone())
        .unwrap_or_else(|| json!({}));
    let revision = format!("day2-links-{generation}");
    world.statefulset = Some(json!({
        "metadata": {"name": "day2-links", "generation": generation, "annotations": annotations},
        "spec": {"replicas": 1, "template": {"spec": {"containers": [{"name": "day2", "image": image_name}]}}},
        "status": {"readyReplicas": 1, "observedGeneration": generation,
            "currentRevision": revision, "updateRevision": revision},
    }));
    world.configmap = Some(json!({"data": {"instance.json": instance}}));
    let digest = image_name.rsplit_once('@').unwrap().1;
    world.pod = Some(json!({
        "metadata": {"name": "day2-links-0", "labels": {"controller-revision-hash": revision}},
        "status": {"containerStatuses": [{"name": "day2", "ready": true,
            "imageID": format!("docker-pullable://{REGISTRY}/links/links@{digest}")}]},
    }));
    world.cronjob = Some(
        json!({"spec": {"jobTemplate": {"spec": {"template": {"spec": {
        "containers": [{"name": "backup", "image": image_name}],
        "volumes": [{"name": "instance", "configMap": {"name": "day2-links-instance"}}]}}}}}}),
    );
    world.pvc = Some(json!({"spec": {"volumeName": "pv-1"}, "status": {"phase": "Bound"}}));
}

/// The rendered target the day2-app root would publish for the candidate.
fn desired(artifact: &str) -> String {
    json!({"installation": "exampleco", "apps": {"links": {"artifact": format!("artifacts/{artifact}"),
        "rendered_authority": {"admins": ["ada@example.com", APPLY_IDENTITY]}}}})
    .to_string()
}

/// A change to the fake cluster.
type Tamper = Rc<dyn Fn(&mut ClusterWorld)>;

/// How a run's day2-app root behaves (the slice 4a stages the recipe calls).
#[derive(Clone)]
struct Roots {
    /// The day2-app deploy apply succeeds, and the workload rolls.
    applies: bool,
    /// The rendered target's instance.json.
    target: Option<String>,
    /// What else changes in the cluster once the apply rolled the workload.
    tamper: Option<Tamper>,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            applies: true,
            target: None,
            tamper: None,
        }
    }
}

/// A run's outcome: the receipt or the classified error, and its steps.
struct Outcome {
    result: Result<Value, String>,
    steps: Vec<String>,
    output: PathBuf,
}

impl Outcome {
    /// The exit code the CLI maps the host's error to.
    fn exit(&self) -> i32 {
        match &self.result {
            Ok(_) => 0,
            Err(error) if error.starts_with(crate::instance_source::RETRYABLE) => 7,
            Err(error) if error.starts_with(FENCED) => 8,
            Err(_) => 6,
        }
    }

    fn error(&self) -> &str {
        self.result.as_ref().err().map(String::as_str).unwrap_or("")
    }
}

impl World {
    fn new() -> Self {
        Self::with(&image("links", "e"), TARGET_ARTIFACT)
    }

    fn with(target: &str, artifact: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let published = published();
        let fake = Fake::default();
        for blob in [
            &published.manifest,
            &published.distribution,
            &published.native,
            &published.strict,
        ] {
            let identity = BlobIdentity::of(blob);
            fake.0.borrow_mut().objects.insert(
                format!(
                    "gs://{BUCKET}/{}/{}",
                    crate::instance_release::OBJECTS,
                    &identity.digest[7..]
                ),
                blob.clone(),
            );
        }
        // The job image bakes the release's operator into the cache.
        let operator = directory.path().join(format!(
            "cache/{}.operator",
            &published.release.operator.digest[7..]
        ));
        for name in OPERATOR_FILES {
            let path = operator.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, name.as_bytes()).unwrap();
        }
        for name in ["instance", "platform"] {
            fs::create_dir(directory.path().join(name)).unwrap();
        }
        let reference = BlobIdentity::of(&published.manifest);
        let candidate = candidate_record(
            &reference,
            &published.release.evidence.native.digest,
            target,
            artifact,
        );
        fs::write(
            directory.path().join("candidate.json"),
            record::encode(&candidate).unwrap(),
        )
        .unwrap();
        let cluster = FakeTools::default();
        {
            let mut world = cluster.0.borrow_mut();
            serving(&mut world, &image("links", "a"), OLD_ARTIFACT, None);
            world.active_artifact = OLD_ARTIFACT.into();
            world.now = 1_800_000_000;
        }
        Self {
            directory,
            fake,
            cluster,
            published,
            target: target.to_owned(),
            artifact: artifact.to_owned(),
            runs: RefCell::new(0),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn request(&self, output: &FsPath, deadline: Option<u64>) -> Value {
        json!({
            "instance": {
                "project": "exampleco-tools", "zone": "us-central1-a", "cluster": "day2",
                "registry": REGISTRY, "bucket": BUCKET, "org": "tools",
                "apply_identity": APPLY_IDENTITY,
                "apps": [{"id": "links", "sdk": BlobIdentity::of(&self.published.manifest).digest,
                    "verification": 4}],
            },
            "directory": self.path("instance"),
            "platform": self.path("platform"),
            "app_id": "links",
            "candidate": self.path("candidate.json"),
            "output": output,
            "deadline": deadline,
        })
    }

    fn effects(&self) -> Effects {
        Effects {
            tools: Box::new(self.cluster.clone()),
            release: Box::new(self.fake.clone()),
            cache: Some(self.path("cache")),
        }
    }

    fn session(&self, request: &Value) -> Result<(Session, PathBuf)> {
        let raw = self.path("request.json");
        fs::write(&raw, request.to_string())?;
        let output = PathBuf::from(request["output"].as_str().unwrap());
        Ok((Session::prepare(&raw, self.effects())?, output))
    }

    fn cluster(&self) -> std::cell::RefMut<'_, ClusterWorld> {
        self.cluster.0.borrow_mut()
    }

    /// One deploy, in InstanceDeploy.roc's order, with `roots` standing in for
    /// the day2-app root's stages.
    fn deploy_with(&self, roots: &Roots, deadline: Option<u64>) -> Outcome {
        let run = {
            let mut runs = self.runs.borrow_mut();
            *runs += 1;
            *runs
        };
        let output = self.path(&format!("deploy-{run}"));
        let (mut session, output) = match self.session(&self.request(&output, deadline)) {
            Ok(session) => session,
            Err(error) => {
                return Outcome {
                    result: Err(format!("{error:#}")),
                    steps: vec!["prepare".into()],
                    output,
                };
            }
        };
        let mut steps = vec!["prepare".to_owned()];
        let mut step = |name: &str, detail: Value| -> Result<Value> {
            steps.push(name.to_owned());
            session.step(name, &detail)
        };
        let ran = (|| -> Result<Value> {
            step("operator", Value::Null)?;
            step("credentials", Value::Null)?;
            let path = step("observe", Value::Null)?["path"]
                .as_str()
                .unwrap()
                .to_owned();
            if path == "fresh" {
                let target = roots
                    .target
                    .clone()
                    .unwrap_or_else(|| desired(&self.artifact));
                let file = output.join("roots-target.json");
                fs::write(&file, &target)?;
                let identity = BlobIdentity::of(target.as_bytes());
                step(
                    "target",
                    json!({"path": file, "digest": identity.digest, "bytes": identity.bytes}),
                )?;
                for name in ["deadline", "backup", "archive-before", "activate"] {
                    step(name, Value::Null)?;
                }
            } else {
                step("deadline", Value::Null)?;
            }
            step("apply", Value::Null)?;
            if roots.applies {
                let mut world = self.cluster();
                let instance = world
                    .runs
                    .iter()
                    .rev()
                    .find_map(|(operation, request)| {
                        (*operation == Operation::Activate).then(|| {
                            fs::read_to_string(request["target"]["instance"].as_str().unwrap())
                                .unwrap()
                        })
                    })
                    .unwrap_or_else(|| desired(&self.artifact));
                // The direct apply rolls the workload and consumes the stamp.
                if world.statefulset.is_some() {
                    world.annotate("day2.dev/activated-image", None);
                }
                serving(&mut world, &self.target, &self.artifact, Some(&instance));
                if let Some(tamper) = &roots.tamper {
                    tamper(&mut world);
                }
            }
            step("applied", json!({"ok": roots.applies}))?;
            step("rollout", Value::Null)?;
            step("readback", Value::Null)
        })();
        let error = ran.as_ref().err().map(|error| format!("{error:#}"));
        let _ = step("archive-after", Value::Null);
        let result =
            step("finish", json!({ "error": error })).map_err(|error| format!("{error:#}"));
        drop(step);
        Outcome {
            result,
            steps,
            output,
        }
    }

    fn deploy(&self) -> Outcome {
        self.deploy_with(&Roots::default(), None)
    }

    /// The archived object names under `phase`, relative to the run's prefix.
    fn archived(&self, phase: &str) -> Vec<String> {
        self.cluster()
            .objects
            .keys()
            .filter_map(|name| {
                name.split_once(&format!("/{phase}/"))
                    .map(|(_, rest)| rest.to_owned())
            })
            .collect()
    }

    fn phase(&self) -> Option<String> {
        self.cluster().phase()
    }

    fn workload(&self) -> Value {
        self.cluster().statefulset.clone().unwrap()
    }
}

fn fresh_steps() -> Vec<String> {
    [
        "prepare",
        "operator",
        "credentials",
        "observe",
        "target",
        "deadline",
        "backup",
        "archive-before",
        "activate",
        "apply",
        "applied",
        "rollout",
        "readback",
        "archive-after",
        "finish",
    ]
    .map(str::to_owned)
    .to_vec()
}

#[test]
fn f0_a_fresh_deploy_backs_up_archives_activates_and_reads_back() -> Result<()> {
    let world = World::new();
    let outcome = world.deploy();
    let receipt = outcome.result.clone().unwrap();
    assert_eq!(outcome.steps, fresh_steps());
    assert_eq!(receipt["path"], "fresh");
    assert_eq!(receipt["image"], world.target);
    assert_eq!(
        receipt["request_id"],
        format!("deploy-{COMMIT}-{}", "e".repeat(16))
    );
    // Backup, then activate, each from the private operator copy.
    let runs: Vec<Operation> = world
        .cluster()
        .runs
        .iter()
        .map(|(operation, _)| *operation)
        .collect();
    assert_eq!(runs, [Operation::Backup, Operation::Activate]);
    let (_, activate) = world.cluster().runs[1].clone();
    let attempt = Attempt::of_request("links", &activate)?;
    assert_eq!(activate["operator"], APPLY_IDENTITY);
    assert_eq!(activate["yes"], true);
    assert_eq!(activate["app_image"], image("links", "a"));
    assert_eq!(activate["artifact_id"], OLD_ARTIFACT);
    assert_eq!(activate["target"]["app_image"], world.target);
    // The activation's request digest is the saved request file's.
    let saved = fs::read(outcome.output.join("maintain-activate.json"))?;
    assert_eq!(
        receipt["activation"]["request_digest"],
        day2::digest(&saved)
    );
    assert_eq!(
        receipt["activation"]["target_instance_digest"],
        day2::digest(desired(TARGET_ARTIFACT).as_bytes())
    );
    // Both phases archived, the backup session's files before activation and
    // everything the attempt left after it, under one prefix.
    let directory = attempt.backup_dir();
    let name = directory.file_name().unwrap().to_str().unwrap();
    let before = world.archived("before-activation");
    let after = world.archived("after-activation");
    assert!(
        before
            .iter()
            .all(|object| object.starts_with(&format!("{name}/")))
    );
    assert_eq!(before.len(), 4);
    assert_eq!(after.len(), 8);
    assert!(before.iter().all(|object| after.contains(object)));
    let uri = receipt["archive"]["uri"].as_str().unwrap();
    assert!(uri.starts_with(&format!(
        "gs://exampleco-tools-links-backups/deployments/{COMMIT}/"
    )));
    assert_eq!(receipt["archive"]["before"]["objects"], 4);
    assert_eq!(receipt["archive"]["after"]["objects"], 8);
    // The private directories, the readback and the receipt file.
    for path in [&directory, &attempt.activation_dir(), &outcome.output] {
        assert_eq!(
            fs::metadata(path)?.permissions().mode() & 0o777,
            0o700,
            "{}",
            path.display()
        );
    }
    assert_eq!(
        receipt["readback"]["instance_digest"],
        day2::digest(desired(TARGET_ARTIFACT).as_bytes())
    );
    let written: Value = serde_json::from_slice(&fs::read(outcome.output.join("receipt.json"))?)?;
    assert_eq!(written, receipt);
    assert_eq!(world.phase().as_deref(), Some("activated"));
    // The operator ran from the private copy, checked on its copied bytes.
    let copy = outcome.output.join("operator/cli");
    assert_eq!(fs::metadata(&copy)?.permissions().mode() & 0o777, 0o500);
    assert_eq!(fs::read(copy.join("day2"))?, b"cli/day2");
    assert_eq!(
        fs::metadata(copy.join("day2"))?.permissions().mode() & 0o777,
        0o555
    );
    assert_eq!(
        fs::metadata(copy.join("day2-workflows.json"))?
            .permissions()
            .mode()
            & 0o777,
        0o444
    );
    assert_eq!(
        receipt["operator"]["release"],
        BlobIdentity::of(&world.published.manifest).digest
    );
    // The environment the tools got: the session's kubeconfig, no DAY2_ variable.
    let config = world.cluster().config.clone().unwrap();
    assert_eq!(config.kubeconfig, outcome.output.join("kube/config"));
    assert!(
        config
            .env
            .iter()
            .all(|(name, _)| !name.to_string_lossy().starts_with("DAY2_"))
    );
    // The receipt has the golden shape.
    let golden: Value = serde_json::from_str(GOLDEN_RECEIPT)?;
    let keys = |value: &Value| {
        value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(keys(&receipt), keys(&golden));
    let decoded: super::Receipt = serde_json::from_value(golden)?;
    assert_eq!(decoded.mode, "deploy");
    Ok(())
}

#[test]
fn f8_a_rerun_after_success_only_applies_and_reads_back() -> Result<()> {
    let world = World::new();
    assert_eq!(world.deploy().exit(), 0);
    let calls = world.cluster().calls.len();
    let again = world.deploy();
    let receipt = again.result.clone().unwrap();
    assert_eq!(receipt["path"], "serving");
    assert_eq!(
        again.steps,
        [
            "prepare",
            "operator",
            "credentials",
            "observe",
            "deadline",
            "apply",
            "applied",
            "rollout",
            "readback",
            "archive-after",
            "finish"
        ]
    );
    assert!(receipt["archive"].is_null() && receipt["activation"].is_null());
    let calls: Vec<String> = world.cluster().calls[calls..].to_vec();
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("maintain") || call.starts_with("upload"))
    );
    Ok(())
}

#[test]
fn f7_a_new_image_of_the_same_artifact_is_activated_too() -> Result<()> {
    let world = World::with(&image("links", "f"), OLD_ARTIFACT);
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 0, "{}", outcome.error());
    assert_eq!(outcome.result.unwrap()["path"], "fresh");
    let (_, activate) = world.cluster().runs[1].clone();
    assert_eq!(activate["artifact_id"], activate["target"]["artifact_id"]);
    Ok(())
}

#[test]
fn f1_a_backup_stopped_at_any_step_restores_the_app_and_a_rerun_deploys() -> Result<()> {
    for step in journal(Operation::Backup) {
        for ending in [Ending::Exit, Ending::Interrupt, Ending::Deadline] {
            let world = World::new();
            world.cluster().fail_at = Some((Operation::Backup, step, ending));
            let outcome = world.deploy();
            assert_eq!(outcome.exit(), 6, "{step} {ending:?}: {}", outcome.error());
            assert!(
                outcome
                    .error()
                    .contains("the app was restored on its image"),
                "{}",
                outcome.error()
            );
            assert_eq!(world.workload()["spec"]["replicas"], 1);
            assert!(world.archived("before-activation").is_empty());
            // Whatever the session left (its journal, a partial copy) is archived after.
            if *step != "open" {
                assert!(!world.archived("after-activation").is_empty(), "{step}");
                assert!(
                    outcome
                        .error()
                        .contains("; evidence: gs://exampleco-tools-links-backups/")
                );
            }
            world.cluster().fail_at = None;
            let rerun = world.deploy();
            assert_eq!(rerun.exit(), 0, "{step}: {}", rerun.error());
        }
    }
    Ok(())
}

#[test]
fn f2_an_activation_stopped_before_the_fence_restores_the_app_and_a_rerun_deploys() -> Result<()> {
    let steps = journal(Operation::Activate);
    let fence = steps.iter().position(|step| *step == "fence").unwrap();
    for step in &steps[..=fence] {
        for ending in [Ending::Exit, Ending::Interrupt, Ending::Deadline] {
            let world = World::new();
            world.cluster().fail_at = Some((Operation::Activate, step, ending));
            let outcome = world.deploy();
            assert_eq!(outcome.exit(), 6, "{step} {ending:?}: {}", outcome.error());
            assert!(
                outcome
                    .error()
                    .contains("the app was restored on its image"),
                "{step}"
            );
            assert_eq!(world.workload()["spec"]["replicas"], 1);
            assert!(
                matches!(world.phase().as_deref(), None | Some("restored")),
                "{step}"
            );
            assert!(!world.archived("before-activation").is_empty());
            world.cluster().fail_at = None;
            let rerun = world.deploy();
            assert_eq!(rerun.exit(), 0, "{step}: {}", rerun.error());
            assert_eq!(rerun.result.unwrap()["path"], "fresh");
        }
    }
    Ok(())
}

#[test]
fn f3_an_activation_stopped_after_the_fence_never_restarts_the_old_image() -> Result<()> {
    let steps = journal(Operation::Activate);
    let fence = steps.iter().position(|step| *step == "fence").unwrap();
    let mark = steps
        .iter()
        .position(|step| *step == "mark-activated")
        .unwrap();
    for step in &steps[fence + 1..=mark] {
        for ending in [Ending::Exit, Ending::Interrupt, Ending::Deadline] {
            let world = World::new();
            world.cluster().fail_at = Some((Operation::Activate, step, ending));
            let outcome = world.deploy();
            assert_eq!(outcome.exit(), 8, "{step} {ending:?}: {}", outcome.error());
            assert!(
                outcome
                    .error()
                    .starts_with("fenced: day2 platform maintain activate")
            );
            assert!(outcome.error().contains("never restarts on its old image"));
            assert_eq!(world.workload()["spec"]["replicas"], 0);
            assert_eq!(world.phase().as_deref(), Some("fenced"));
            assert!(!world.archived("after-activation").is_empty());
            // Without a saved request a rerun refuses rather than touch it.
            world.cluster().fail_at = None;
            let rerun = world.deploy();
            assert_eq!(rerun.exit(), 8, "{step}: {}", rerun.error());
            assert!(rerun.error().contains("activation_recovery_required"));
            assert_eq!(world.cluster().runs.len(), 2);
        }
    }
    Ok(())
}

#[test]
fn f3_an_activation_that_marked_but_did_not_finish_rolls_forward_on_rerun() -> Result<()> {
    let world = World::new();
    world.cluster().fail_at = Some((Operation::Activate, "finish", Ending::Exit));
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 8, "{}", outcome.error());
    assert!(
        outcome
            .error()
            .contains("activated for the target but not rolled")
    );
    world.cluster().fail_at = None;
    let rerun = world.deploy();
    assert_eq!(rerun.exit(), 0, "{}", rerun.error());
    assert_eq!(rerun.result.unwrap()["path"], "activated");
    Ok(())
}

#[test]
fn f4_a_failed_apply_after_activation_is_fenced_and_a_rerun_rolls_forward() -> Result<()> {
    let world = World::new();
    let outcome = world.deploy_with(
        &Roots {
            applies: false,
            ..Roots::default()
        },
        None,
    );
    assert_eq!(outcome.exit(), 8, "{}", outcome.error());
    assert!(outcome.error().starts_with(
        "fenced: the day2-app apply did not apply this candidate; its roots receipt says why; the app's store runs the target"
    ));
    assert_eq!(
        world.workload()["metadata"]["annotations"]["day2.dev/activated-image"],
        world.target
    );
    let rerun = world.deploy();
    assert_eq!(rerun.exit(), 0, "{}", rerun.error());
    assert_eq!(rerun.result.unwrap()["path"], "activated");
    Ok(())
}

#[test]
fn f5_a_failed_rollout_is_fenced_and_a_rerun_reads_back() -> Result<()> {
    let world = World::new();
    world.cluster().failing = vec!["rollout".into()];
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 8, "{}", outcome.error());
    assert!(outcome.error().starts_with("fenced: rollout failed"));
    world.cluster().failing.clear();
    let rerun = world.deploy();
    assert_eq!(rerun.exit(), 0, "{}", rerun.error());
    assert_eq!(rerun.result.unwrap()["path"], "serving");
    Ok(())
}

#[test]
fn f9_a_busy_operation_lock_refuses_before_the_stop() -> Result<()> {
    let world = World::new();
    world.cluster().fail_at = Some((Operation::Backup, "operation-claimed", Ending::Exit));
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 6);
    assert_eq!(world.workload()["spec"]["replicas"], 1);
    assert_eq!(world.cluster().runs.len(), 1);
    Ok(())
}

#[test]
fn f10_a_killed_activation_before_the_fence_needs_recovery() -> Result<()> {
    let world = World::new();
    world.cluster().fail_at = Some((Operation::Activate, "scratch", Ending::Killed));
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 6, "{}", outcome.error());
    assert!(
        outcome
            .error()
            .contains("left processes running and was killed; activation_recovery_required")
    );
    assert_eq!(world.phase().as_deref(), Some("stopped"));
    world.cluster().fail_at = None;
    let rerun = world.deploy();
    assert_eq!(rerun.exit(), 6);
    assert!(
        rerun
            .error()
            .starts_with("activation_recovery_required: an earlier activation stopped before")
    );
    // Killed after the fence: forward only.
    let world = World::new();
    world.cluster().fail_at = Some((Operation::Activate, "authority-inspect", Ending::Killed));
    assert_eq!(world.deploy().exit(), 8);
    Ok(())
}

#[test]
fn the_deadline_refuses_before_anything_stops() -> Result<()> {
    let world = World::new();
    let now = world.cluster().now;
    let outcome = world.deploy_with(
        &Roots::default(),
        Some(now + fence::remaining(Path::Fresh) - 1),
    );
    assert_eq!(outcome.exit(), 7, "{}", outcome.error());
    assert!(
        outcome
            .error()
            .starts_with("retryable: deploy_deadline: the fresh path needs up to 8460 s")
    );
    assert!(outcome.error().ends_with("nothing was stopped"));
    assert!(world.cluster().runs.is_empty());
    assert_eq!(world.workload()["spec"]["replicas"], 1);
    let outcome = world.deploy_with(&Roots::default(), Some(now + fence::remaining(Path::Fresh)));
    assert_eq!(outcome.exit(), 0, "{}", outcome.error());
    // A shorter path needs less.
    let outcome = world.deploy_with(
        &Roots::default(),
        Some(now + fence::remaining(Path::Serving)),
    );
    assert_eq!(outcome.exit(), 0, "{}", outcome.error());
    Ok(())
}

#[test]
fn transient_reads_before_anything_stops_are_retryable() -> Result<()> {
    for verb in ["credentials", "get statefulset", "get configmap"] {
        let world = World::new();
        world.cluster().failing = vec![verb.into()];
        let outcome = world.deploy();
        assert_eq!(outcome.exit(), 7, "{verb}: {}", outcome.error());
        assert!(world.cluster().runs.is_empty());
    }
    // A read after the app changed is not.
    let world = World::new();
    world.cluster().failing = vec!["get pod".into()];
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 8, "{}", outcome.error());
    Ok(())
}

#[test]
fn every_readback_check_names_itself() -> Result<()> {
    let instance = |artifact: &str| {
        Some(json!({"data": {"instance.json": json!({"apps": {"links": {
            "artifact": format!("artifacts/{artifact}")}}}).to_string()}}))
    };
    let checks: Vec<(&str, Tamper)> = vec![
        (
            "readback replicas",
            Rc::new(|w: &mut ClusterWorld| {
                w.statefulset.as_mut().unwrap()["status"]["readyReplicas"] = json!(0)
            }),
        ),
        (
            "readback generation",
            Rc::new(|w: &mut ClusterWorld| {
                w.statefulset.as_mut().unwrap()["status"]["observedGeneration"] = json!(0)
            }),
        ),
        (
            "readback revision",
            Rc::new(|w: &mut ClusterWorld| {
                w.statefulset.as_mut().unwrap()["status"]["currentRevision"] = json!("old")
            }),
        ),
        (
            "readback image",
            Rc::new(|w: &mut ClusterWorld| {
                w.statefulset.as_mut().unwrap()["spec"]["template"]["spec"]["containers"][0]["image"] =
                    json!(image("links", "f"))
            }),
        ),
        (
            "readback stamp",
            Rc::new(|w: &mut ClusterWorld| {
                w.annotate("day2.dev/activated-image", Some(image("links", "f")))
            }),
        ),
        (
            "readback checkpoint",
            Rc::new(|w: &mut ClusterWorld| w.set_phase("fenced", DIGEST, DIGEST)),
        ),
        (
            "readback pod deletion",
            Rc::new(|w: &mut ClusterWorld| {
                w.pod.as_mut().unwrap()["metadata"]["deletionTimestamp"] =
                    json!("2026-11-23T12:00:00Z")
            }),
        ),
        (
            "readback pod revision",
            Rc::new(|w: &mut ClusterWorld| {
                w.pod.as_mut().unwrap()["metadata"]["labels"]["controller-revision-hash"] =
                    json!("old")
            }),
        ),
        (
            "readback pod image",
            Rc::new(|w: &mut ClusterWorld| {
                w.pod.as_mut().unwrap()["status"]["containerStatuses"][0]["ready"] = json!(false)
            }),
        ),
        (
            "readback artifact",
            Rc::new(move |w: &mut ClusterWorld| w.configmap = instance(OLD_ARTIFACT)),
        ),
        (
            "readback instance",
            Rc::new(move |w: &mut ClusterWorld| w.configmap = instance(TARGET_ARTIFACT)),
        ),
        (
            "readback backup job",
            Rc::new(|w: &mut ClusterWorld| {
                w.cronjob.as_mut().unwrap()["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"]
                    [0]["image"] = json!(image("links", "a"))
            }),
        ),
    ];
    for (name, tamper) in checks {
        let world = World::new();
        let outcome = world.deploy_with(
            &Roots {
                tamper: Some(tamper),
                ..Roots::default()
            },
            None,
        );
        assert_eq!(outcome.exit(), 8, "{name}: {}", outcome.error());
        assert!(
            outcome.error().starts_with(&format!("fenced: {name}: ")),
            "{name}: {}",
            outcome.error()
        );
    }
    Ok(())
}

#[test]
fn a_failed_final_archive_after_a_verified_deploy_is_exit_6() -> Result<()> {
    let world = World::new();
    world.cluster().failing = vec!["list after-activation".into()];
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 6, "{}", outcome.error());
    assert!(
        outcome
            .error()
            .starts_with("the final archive failed: list after-activation failed")
    );
    assert!(
        outcome
            .error()
            .contains("the app serves the target, but its evidence was not archived")
    );
    Ok(())
}

#[test]
fn an_archive_that_does_not_match_the_manifest_stops_before_activation() -> Result<()> {
    let world = World::new();
    world.cluster().failing = vec!["upload before-activation".into()];
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 6, "{}", outcome.error());
    assert!(
        outcome
            .error()
            .starts_with("upload before-activation failed")
    );
    assert_eq!(world.cluster().runs.len(), 1);
    assert_eq!(world.workload()["spec"]["replicas"], 1);
    Ok(())
}

#[test]
fn a_first_install_needs_a_never_bound_claim() -> Result<()> {
    let world = World::new();
    {
        let mut cluster = world.cluster();
        cluster.statefulset = None;
        cluster.pod = None;
        cluster.configmap = None;
        cluster.cronjob = None;
        cluster.pvc = Some(json!({"spec": {}, "status": {"phase": "Pending"}}));
    }
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 0, "{}", outcome.error());
    let receipt = outcome.result.unwrap();
    assert_eq!(receipt["path"], "install");
    assert!(world.cluster().runs.is_empty());
    for pvc in [
        None,
        Some(json!({"spec": {"volumeName": "pv-1"}, "status": {"phase": "Bound"}})),
    ] {
        let world = World::new();
        {
            let mut cluster = world.cluster();
            cluster.statefulset = None;
            cluster.pvc = pvc.clone();
        }
        let outcome = world.deploy();
        assert_eq!(outcome.exit(), 6, "{}", outcome.error());
        assert!(world.cluster().runs.is_empty());
    }
    Ok(())
}

#[test]
fn an_active_or_foreign_checkpoint_is_refused_before_anything_changes() -> Result<()> {
    for (phase, exit) in [
        ("prepared", 6),
        ("stopped", 6),
        ("fenced", 8),
        ("recovering", 8),
    ] {
        let world = World::new();
        {
            let mut cluster = world.cluster();
            cluster.replicas(0);
            cluster.set_phase(phase, DIGEST, DIGEST);
        }
        let outcome = world.deploy();
        assert_eq!(outcome.exit(), exit, "{phase}: {}", outcome.error());
        assert!(world.cluster().runs.is_empty());
        assert!(
            !world
                .cluster()
                .calls
                .iter()
                .any(|call| call.starts_with("upload"))
        );
    }
    // A checkpoint in a format this CLI cannot read may be past the fence.
    let world = World::new();
    world
        .cluster()
        .annotate("day2.dev/activation", Some("{\"format\": 9}".into()));
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 8, "{}", outcome.error());
    Ok(())
}

#[test]
fn the_session_runs_only_the_steps_its_path_allows() -> Result<()> {
    let world = World::new();
    let output = world.path("ordered");
    let (mut session, _) = world.session(&world.request(&output, None))?;
    let refused = |session: &mut Session, name: &str| {
        format!("{:#}", session.step(name, &Value::Null).unwrap_err())
    };
    assert_eq!(
        refused(&mut session, "backup"),
        "instance deploy runs operator next, not backup"
    );
    session.step("operator", &Value::Null)?;
    session.step("credentials", &Value::Null)?;
    assert_eq!(
        session.step("observe", &Value::Null)?,
        json!({"path": "fresh"})
    );
    assert_eq!(
        refused(&mut session, "apply"),
        "instance deploy runs target next, not apply"
    );
    // The rendered target must be the candidate's, with the reported digest.
    let file = world.path("target.json");
    fs::write(&file, desired(OLD_ARTIFACT))?;
    let identity = BlobIdentity::of(desired(OLD_ARTIFACT).as_bytes());
    let detail = json!({"path": file, "digest": identity.digest, "bytes": identity.bytes});
    assert_eq!(
        format!("{:#}", session.step("target", &detail).unwrap_err()),
        "the rendered target does not bind links to the candidate's artifact"
    );
    let detail = json!({"path": file, "digest": day2::digest(b"other"), "bytes": identity.bytes});
    assert_eq!(
        format!("{:#}", session.step("target", &detail).unwrap_err()),
        "the rendered target changed"
    );
    // The final archive and finish end the session; nothing runs after them.
    session.step("archive-after", &Value::Null)?;
    assert_eq!(
        refused(&mut session, "target"),
        "only finish follows the final archive"
    );
    let finished = session
        .step("finish", &json!({"error": "stopped"}))
        .unwrap_err();
    assert_eq!(format!("{finished:#}"), "stopped; nothing was stopped");
    assert_eq!(
        refused(&mut session, "finish"),
        "the deploy session has finished"
    );
    Ok(())
}

#[test]
fn requests_candidates_and_output_directories_are_checked_first() -> Result<()> {
    let world = World::new();
    let output = world.path("checked");
    let refused = |request: Value| match world.session(&request) {
        Ok(_) => panic!("accepted"),
        Err(error) => format!("{error:#}"),
    };
    let request = world.request(&output, None);
    let mut other = request.clone();
    other["app_id"] = json!("notes");
    assert_eq!(refused(other), "the app notes is not in day2.json");
    let mut bucket = request.clone();
    bucket["instance"]["bucket"] = json!("elsewhere");
    assert_eq!(
        refused(bucket),
        "the instance's bucket and registry must be its project's"
    );
    let mut identity = request.clone();
    identity["instance"]["apply_identity"] = json!("ada@example.com");
    assert!(refused(identity).starts_with("the apply identity must be"));
    let mut inside = request.clone();
    inside["output"] = json!(world.path("instance/out"));
    assert_eq!(
        refused(inside),
        "the output directory must be outside the instance and the platform checkout"
    );
    let mut extra = request.clone();
    extra["extra"] = json!(1);
    assert!(world.session(&extra).is_err());
    fs::create_dir(&output)?;
    assert!(
        refused(request.clone()).starts_with("instance deploy requires a new output directory")
    );
    fs::remove_dir(&output)?;
    // The candidate is checked as candidate check checks it.
    let mut candidate: Value = serde_json::from_slice(&fs::read(world.path("candidate.json"))?)?;
    candidate["binding"]["app"] = json!("notes");
    fs::write(world.path("candidate.json"), record::encode(&candidate)?)?;
    assert_eq!(refused(request), "release belongs to another app");
    assert!(
        fs::symlink_metadata(&output).is_err(),
        "nothing is created for a refused request"
    );
    Ok(())
}

#[test]
fn the_operator_must_be_the_candidates_qualified_bytes() -> Result<()> {
    let world = World::new();
    let operator = world.path(&format!(
        "cache/{}.operator/cli/day2-host",
        &world.published.release.operator.digest[7..]
    ));
    fs::write(&operator, b"changed")?;
    let outcome = world.deploy();
    assert_eq!(outcome.exit(), 6, "{}", outcome.error());
    assert!(
        outcome
            .error()
            .starts_with("cached operator executable changed"),
        "{}",
        outcome.error()
    );
    assert!(world.cluster().calls.is_empty());
    // A candidate qualified by another release's evidence is refused too.
    let world = World::new();
    let mut candidate: Value = serde_json::from_slice(&fs::read(world.path("candidate.json"))?)?;
    candidate["security_requirements"]["containment"]["evidence"]["receipt_digest"] = json!(DIGEST);
    fs::write(world.path("candidate.json"), record::encode(&candidate)?)?;
    let outcome = world.deploy();
    assert_eq!(
        outcome.error(),
        "candidate uses another platform qualification; nothing was stopped"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The native adapters, against stub executables.

use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant};

/// An executable stub in `directory`, a POSIX shell script.
fn stub(directory: &FsPath, name: &str, body: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn operator_command(program: &FsPath) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    command.args(["platform", "maintain", "backup", "/private/request.json"]);
    command
}

#[test]
fn the_operator_runs_to_its_receipt_or_its_failure() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let log = directory.path().join("args");
    let program = stub(
        directory.path(),
        "day2",
        &format!(
            "printf '%s\\n' \"$@\" > '{}'\necho '== progress' >&2\nprintf 'noise\\n{{\"operation\": \"backup\", \"journal\": \"/x\"}}\\n'\n",
            log.display()
        ),
    );
    let flag = AtomicBool::new(false);
    let ran = deploy::supervise_operator(
        operator_command(&program),
        Duration::from_secs(30),
        Duration::from_secs(5),
        &flag,
    )?;
    assert_eq!((ran.code, ran.stopped, ran.killed), (Some(0), None, false));
    assert_eq!(deploy::finished(&ran, Operation::Backup)?["journal"], "/x");
    assert_eq!(
        fs::read_to_string(&log)?,
        "platform\nmaintain\nbackup\n/private/request.json\n"
    );
    assert_eq!(
        format!(
            "{:#}",
            deploy::finished(&ran, Operation::Activate).unwrap_err()
        ),
        "day2 platform maintain activate reported another operation"
    );
    let failing = stub(
        directory.path(),
        "failing",
        "echo 'Error: refused' >&2\nexit 3\n",
    );
    let ran = deploy::supervise_operator(
        operator_command(&failing),
        Duration::from_secs(30),
        Duration::from_secs(5),
        &flag,
    )?;
    assert_eq!(ran.code, Some(3));
    assert_eq!(
        format!(
            "{:#}",
            deploy::finished(&ran, Operation::Backup).unwrap_err()
        ),
        "day2 platform maintain backup failed (exit 3)"
    );
    let silent = stub(directory.path(), "silent", "exit 0\n");
    let ran = deploy::supervise_operator(
        operator_command(&silent),
        Duration::from_secs(30),
        Duration::from_secs(5),
        &flag,
    )?;
    assert_eq!(
        format!(
            "{:#}",
            deploy::finished(&ran, Operation::Backup).unwrap_err()
        ),
        "the operator printed no receipt"
    );
    let loud = stub(
        directory.path(),
        "loud",
        "head -c 1048577 /dev/zero | tr '\\0' a\n",
    );
    let error = deploy::supervise_operator(
        operator_command(&loud),
        Duration::from_secs(30),
        Duration::from_secs(5),
        &flag,
    )
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "the operator's output exceeds its bound"
    );
    Ok(())
}

#[test]
fn the_operator_gets_sigint_at_its_deadline_and_its_group_its_grace() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("cleaned");
    // The session cleans up on SIGINT and exits.
    let cleaning = stub(
        directory.path(),
        "cleaning",
        &format!(
            "trap 'echo cleaned > \"{}\"; exit 1' INT\nwhile :; do sleep 0.1; done\n",
            marker.display()
        ),
    );
    let flag = AtomicBool::new(false);
    let started = Instant::now();
    // The deadline leaves the stub time to install its trap, even under load.
    let ran = deploy::supervise_operator(
        operator_command(&cleaning),
        Duration::from_secs(3),
        Duration::from_secs(10),
        &flag,
    )?;
    assert_eq!(
        (ran.stopped, ran.killed, ran.code),
        (Some("deadline"), false, Some(1)),
        "{ran:?}"
    );
    assert!(marker.exists());
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(
        format!(
            "{:#}",
            deploy::finished(&ran, Operation::Backup).unwrap_err()
        ),
        "day2 platform maintain backup stopped at its deadline"
    );
    // A session that ignores SIGINT is killed with its group after the grace.
    let stubborn = stub(
        directory.path(),
        "stubborn",
        "trap '' INT\nwhile :; do sleep 0.1; done\n",
    );
    let ran = deploy::supervise_operator(
        operator_command(&stubborn),
        Duration::from_secs(3),
        Duration::from_secs(1),
        &flag,
    )?;
    assert!(ran.killed && ran.stopped == Some("deadline"), "{ran:?}");
    // An interrupt of this process reaches the session as SIGINT at once.
    fs::remove_file(&marker)?;
    let interrupted = Arc::new(AtomicBool::new(false));
    let raise = interrupted.clone();
    let raiser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        raise.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let ran = deploy::supervise_operator(
        operator_command(&cleaning),
        Duration::from_secs(60),
        Duration::from_secs(10),
        &interrupted,
    )?;
    raiser.join().unwrap();
    assert_eq!(ran.stopped, Some("interrupt"));
    assert!(marker.exists());
    assert_eq!(
        format!(
            "{:#}",
            deploy::finished(&ran, Operation::Activate).unwrap_err()
        ),
        "day2 platform maintain activate was interrupted"
    );
    Ok(())
}

#[test]
fn the_run_ends_only_when_the_operators_group_is_empty() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("host-finished");
    // The CLI exits at once while its host keeps cleaning up in its group.
    let host = stub(
        directory.path(),
        "host",
        &format!(
            "( sleep 2; echo done > \"{}\" ) &\nprintf '{{\"operation\": \"backup\"}}\\n'\nexit 0\n",
            marker.display()
        ),
    );
    let flag = AtomicBool::new(false);
    let ran = deploy::supervise_operator(
        operator_command(&host),
        Duration::from_secs(30),
        Duration::from_secs(20),
        &flag,
    )?;
    assert!(marker.exists(), "the run waited for the group");
    assert_eq!((ran.code, ran.killed), (Some(0), false));
    // A group member that outlives the grace is killed.
    let lingering = stub(
        directory.path(),
        "lingering",
        "( trap '' INT; sleep 30 ) &\nexit 0\n",
    );
    let started = Instant::now();
    let ran = deploy::supervise_operator(
        operator_command(&lingering),
        Duration::from_secs(30),
        Duration::from_secs(1),
        &flag,
    )?;
    assert!(ran.killed);
    assert!(started.elapsed() < Duration::from_secs(10));
    Ok(())
}

#[test]
fn tools_get_only_the_allowlisted_environment() {
    let ambient = |name: &str| -> Option<std::ffi::OsString> {
        match name {
            "PATH" => Some("/usr/bin:/bin".into()),
            "HOME" => Some("/home/ci".into()),
            "GOOGLE_APPLICATION_CREDENTIALS" => Some("/run/creds.json".into()),
            "DAY2_PRECOMPILED_TOOLING" | "GITEA_TOKEN" | "KUBECONFIG" | "CI_MODE" => {
                Some("leak".into())
            }
            _ => None,
        }
    };
    let env = deploy::environment(
        &ambient,
        FsPath::new("/work/deploy/kube/config"),
        "exampleco-tools",
    );
    let pairs: Vec<(String, String)> = env
        .iter()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect();
    assert_eq!(
        pairs,
        [
            ("CLOUDSDK_CORE_PROJECT", "exampleco-tools"),
            ("GOOGLE_APPLICATION_CREDENTIALS", "/run/creds.json"),
            ("HOME", "/home/ci"),
            ("KUBECONFIG", "/work/deploy/kube/config"),
            ("LANG", "C"),
            ("PATH", "/usr/bin:/bin"),
            ("TMPDIR", "/tmp"),
            ("USE_GKE_GCLOUD_AUTH_PLUGIN", "True"),
        ]
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
    );
}

#[test]
fn kubectl_and_gcloud_run_exactly_their_closed_verbs() -> Result<()> {
    use deploy::Tools as _;
    let directory = tempfile::tempdir()?;
    let log = directory.path().join("calls");
    let body = format!(
        r#"for arg in "$@"; do printf '%s\n' "$arg" >> '{log}'; done
printf -- '--env %s\n' "$(env | cut -d= -f1 | sort | tr '\n' ' ')" >> '{log}'
printf -- '--end--\n' >> '{log}'
case "$*" in
  *get-credentials*) printf 'kind: Config\n' > "$KUBECONFIG";;
  *"get statefulset day2-links"*) printf '{{"kind": "StatefulSet"}}';;
  *"get pod"*) echo 'Error from server (Forbidden)' >&2; exit 1;;
  *"objects list"*) printf '[]';;
esac
exit 0
"#,
        log = log.display()
    );
    let kubectl = stub(directory.path(), "kubectl", &body);
    let gcloud = stub(directory.path(), "gcloud", &body);
    let kubeconfig = directory.path().join("config");
    let mut native = deploy::Native::new(Arc::new(AtomicBool::new(false)));
    native.kubectl = Some(kubectl);
    native.gcloud = Some(gcloud);
    native.configure(deploy::Config {
        env: deploy::environment(
            &|name| std::env::var_os(name),
            &kubeconfig,
            "exampleco-tools",
        ),
        kubeconfig: kubeconfig.clone(),
        project: "exampleco-tools".into(),
        zone: "us-central1-a".into(),
        cluster: "day2".into(),
    });
    native.credentials()?;
    assert_eq!(fs::read_to_string(&kubeconfig)?, "kind: Config\n");
    assert_eq!(
        native.get("app-links", deploy::Kind::StatefulSet, "day2-links")?,
        Some(json!({"kind": "StatefulSet"}))
    );
    assert_eq!(native.get("app-links", deploy::Kind::Claim, "data")?, None);
    assert_eq!(
        format!(
            "{:#}",
            native
                .get("app-links", deploy::Kind::Pod, "day2-links-0")
                .unwrap_err()
        ),
        "read pod day2-links-0 failed (exit 1)"
    );
    native.rollout("app-links", "day2-links")?;
    let prefix = format!(
        "gs://exampleco-tools-links-backups/deployments/{COMMIT}/{}/",
        "a".repeat(32)
    );
    native.upload(
        FsPath::new("/tmp/day2-links-backup-ab12cd_9"),
        &prefix,
        archive::BEFORE,
    )?;
    assert_eq!(native.list(&prefix, archive::BEFORE)?, b"[]");
    let calls: Vec<Vec<String>> = fs::read_to_string(&log)?
        .split("--end--\n")
        .filter(|call| !call.is_empty())
        .map(|call| call.lines().map(str::to_owned).collect())
        .collect();
    let args: Vec<Vec<String>> = calls
        .iter()
        .map(|call| {
            call.iter()
                .filter(|line| !line.starts_with("--env "))
                .cloned()
                .collect()
        })
        .collect();
    let strings = |values: &[&str]| {
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        args,
        [
            strings(&[
                "container",
                "clusters",
                "get-credentials",
                "day2",
                "--zone",
                "us-central1-a",
                "--project",
                "exampleco-tools"
            ]),
            strings(&[
                "--namespace",
                "app-links",
                "get",
                "statefulset",
                "day2-links",
                "--ignore-not-found",
                "--output=json"
            ]),
            strings(&[
                "--namespace",
                "app-links",
                "get",
                "persistentvolumeclaim",
                "data",
                "--ignore-not-found",
                "--output=json"
            ]),
            strings(&[
                "--namespace",
                "app-links",
                "get",
                "pod",
                "day2-links-0",
                "--ignore-not-found",
                "--output=json"
            ]),
            strings(&[
                "--namespace",
                "app-links",
                "rollout",
                "status",
                "statefulset/day2-links",
                "--timeout=600s"
            ]),
            strings(&[
                "storage",
                "cp",
                "--recursive",
                "--no-clobber",
                "/tmp/day2-links-backup-ab12cd_9",
                &format!("{prefix}before-activation/")
            ]),
            strings(&[
                "storage",
                "objects",
                "list",
                &format!("{prefix}before-activation/**"),
                "--format=json(name,size,crc32c_hash)"
            ]),
        ]
    );
    // Every tool saw only the allowlisted environment.
    let allowed: Vec<&str> = deploy::PASSED
        .iter()
        .copied()
        .chain([
            "KUBECONFIG",
            "USE_GKE_GCLOUD_AUTH_PLUGIN",
            "CLOUDSDK_CORE_PROJECT",
            "LANG",
            "TMPDIR",
            "PWD",
            "SHLVL",
            "_",
            "OLDPWD",
        ])
        .collect();
    for call in &calls {
        let names = call.iter().find(|line| line.starts_with("--env ")).unwrap();
        for name in names["--env ".len()..].split_whitespace() {
            assert!(allowed.contains(&name), "{name} leaked into a tool");
        }
    }
    Ok(())
}
