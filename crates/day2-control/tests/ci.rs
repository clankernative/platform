use anyhow::Result;
use day2_control::{
    BindingRef, BuildPlan, Digest, GitOid, Name,
    ci::Receiver,
    contracts::BuildProfile,
    journal::Journal,
    source::{CheckBinding, GithubBinding, SecretRef},
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

fn name(value: &str) -> Name {
    Name::try_from(value.to_owned()).unwrap()
}

fn receiver() -> Result<Receiver> {
    Receiver::new(
        7,
        GithubBinding {
            owner: "exampleco".into(),
            repository: "reports-app".into(),
            repository_id: 9,
            subdirectory: None,
            credential: None,
            checks: Some(CheckBinding {
                app_id: 11,
                credential: SecretRef::try_from("checks".to_owned())?,
            }),
        },
        BuildPlan {
            version: 1,
            company: name("installation"),
            app: name("reports"),
            request: name("template"),
            commit: GitOid::try_from("a".repeat(40))?,
            profile: BuildProfile {
                source: BindingRef::pin(name("source"), &json!({"repository":9}))?,
                builder: BindingRef::pin(name("builder"), &"pinned")?,
                durability: BindingRef::pin(name("durability"), &"pinned")?,
                platform: Digest::new(b"platform"),
                recipe: day2_control::build::recipe_digest(),
            },
        },
        vec![42; 32],
    )
}

fn signature(bytes: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&[42; 32]).unwrap();
    mac.update(bytes);
    format!("sha256={:x}", mac.finalize().into_bytes())
}

fn event() -> Value {
    json!({"installation":{"id":7},"repository":{"id":9,"name":"reports-app","owner":{"login":"exampleco"}},"ref":"refs/heads/main","after":"b".repeat(40),"deleted":false})
}

#[test]
fn authenticates_before_routing_and_pins_exact_sha_with_durable_delivery_deduplication()
-> Result<()> {
    let receiver = receiver()?;
    let body = serde_json::to_vec(&event())?;
    assert!(
        receiver
            .plan("delivery-1", "push", "sha256=00", &body)
            .is_err()
    );
    let plan = receiver
        .plan("delivery-1", "push", &signature(&body), &body)?
        .unwrap();
    assert_eq!(plan.commit.as_str(), "b".repeat(40));
    assert_eq!(plan.app.as_str(), "reports");
    let scratch = tempfile::tempdir()?;
    let path = scratch.path().join("journal.sqlite");
    let first = Journal::open(&path)?.accept_as(&plan, "github-app:7")?;
    let duplicate = Journal::open(&path)?.accept_as(&plan, "github-app:7")?;
    assert_eq!(first.id, duplicate.id);
    let mut changed = event();
    changed["after"] = "c".repeat(40).into();
    let changed = serde_json::to_vec(&changed)?;
    let conflict = receiver
        .plan("delivery-1", "push", &signature(&changed), &changed)?
        .unwrap();
    assert!(
        Journal::open(&path)?
            .accept_as(&conflict, "github-app:7")
            .is_err()
    );
    let rerun = receiver
        .plan("delivery-2", "push", &signature(&body), &body)?
        .unwrap();
    assert_ne!(plan.execution_id()?, rerun.execution_id()?);
    for key in ["installation", "repository"] {
        let mut payload = event();
        payload[key]["id"] = 999.into();
        let bytes = serde_json::to_vec(&payload)?;
        assert!(
            receiver
                .plan("delivery-3", "push", &signature(&bytes), &bytes)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn handles_pr_updates_merge_queue_and_own_check_reruns_without_app_workflows() -> Result<()> {
    let receiver = receiver()?;
    for (event_name, details) in [
        (
            "pull_request",
            json!({"action":"synchronize","pull_request":{"head":{"sha":"d".repeat(40),"repo":{"id":9}},"base":{"repo":{"id":9}}}}),
        ),
        (
            "merge_group",
            json!({"action":"checks_requested","merge_group":{"head_sha":"d".repeat(40)}}),
        ),
        (
            "check_run",
            json!({"action":"rerequested","check_run":{"name":"day2 / verification","app":{"id":11},"head_sha":"d".repeat(40)}}),
        ),
    ] {
        let mut payload = event();
        payload
            .as_object_mut()
            .unwrap()
            .extend(details.as_object().unwrap().clone());
        let bytes = serde_json::to_vec(&payload)?;
        assert_eq!(
            receiver
                .plan("event-1", event_name, &signature(&bytes), &bytes)?
                .unwrap()
                .commit
                .as_str(),
            "d".repeat(40)
        );
    }
    let mut payload = event();
    payload["deleted"] = true.into();
    let bytes = serde_json::to_vec(&payload)?;
    assert!(
        receiver
            .plan("deleted-1", "push", &signature(&bytes), &bytes)?
            .is_none()
    );
    Ok(())
}
