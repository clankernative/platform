use super::*;
use crate::security_epoch::{preparation_image::tests as image_fixture, tests as epoch_fixture};
use serde_json::json;

fn fixture() -> (PersistentDiskSelection, InitialBootstrapPolicy, Vec<Value>) {
    let (_directory, runtime) = image_fixture::runtime();
    let store = epoch_fixture::selection();
    let mut policy = image_fixture::policy(&runtime, &store);
    let object = |name: &str, uid: &str| KubernetesObjectSelection {
        name: name.into(),
        uid: uid.into(),
    };
    let selected = PersistentDiskSelection {
        claim: object("data", "claim-uid"),
        volume: object("pvc-claim-uid", "volume-uid"),
        zone: "zone-one".to_owned().try_into().unwrap(),
        disk: "disk-one".to_owned().try_into().unwrap(),
        disk_id: "781".into(),
        node: object("node-one", "node-uid"),
        instance: "instance-one".to_owned().try_into().unwrap(),
        instance_id: "982".into(),
    };
    policy.fresh_storage.provider_volume_uid = selected.disk_id.clone();
    policy.fresh_storage.mount_binding = selected.digest().unwrap();
    let metadata = |value: &KubernetesObjectSelection| json!({"name":value.name,"uid":value.uid});
    let mut claim_metadata = metadata(&selected.claim);
    claim_metadata["namespace"] = json!(policy.app.namespace.name);
    let disk_source = format!(
        "https://www.googleapis.com/compute/v1/{}",
        selected.disk_path(&policy)
    );
    let instance_source = format!(
        "https://www.googleapis.com/compute/v1/{}",
        selected.instance_path(&policy)
    );
    let replies = vec![
        json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":claim_metadata,
            "spec":{"volumeName":selected.volume.name,"volumeMode":"Filesystem","accessModes":["ReadWriteOnce"]},
            "status":{"phase":"Bound","accessModes":["ReadWriteOnce"]}}),
        json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":metadata(&selected.volume),
            "spec":{"claimRef":{"apiVersion":"v1","kind":"PersistentVolumeClaim","name":selected.claim.name,
                "uid":selected.claim.uid,"namespace":policy.app.namespace.name},"volumeMode":"Filesystem","accessModes":["ReadWriteOnce"],
                "csi":{"driver":"pd.csi.storage.gke.io","fsType":"ext4","volumeHandle":selected.disk_path(&policy)}},
            "status":{"phase":"Bound"}}),
        json!({"apiVersion":"v1","kind":"Node","metadata":metadata(&selected.node),
            "spec":{"providerID":format!("gce://{}/{}/{}",policy.cluster.project.as_str(),selected.zone.as_str(),selected.instance.as_str())},
            "status":{"nodeInfo":{"bootID":"original-boot"}}}),
        json!({"id":selected.disk_id,"name":selected.disk.as_str(),"selfLink":disk_source,
            "zone":format!("https://www.googleapis.com/compute/v1/projects/{}/zones/{}",policy.cluster.project.as_str(),selected.zone.as_str()),
            "type":format!("https://www.googleapis.com/compute/v1/projects/{}/zones/{}/diskTypes/pd-balanced",policy.cluster.project.as_str(),selected.zone.as_str()),
            "status":"READY","users":[instance_source]}),
        json!({"id":selected.instance_id,"name":selected.instance.as_str(),"selfLink":instance_source,"status":"RUNNING",
            "disks":[{"source":disk_source,"type":"PERSISTENT","mode":"READ_WRITE","boot":false,"deviceName":"attached-device"}]}),
    ];
    (selected, policy, replies)
}

fn check(
    selected: &PersistentDiskSelection,
    policy: &InitialBootstrapPolicy,
    replies: &[Value],
) -> Result<String> {
    selected.claim(policy, &replies[0])?;
    selected.volume(policy, &replies[1])?;
    selected.node(policy, "original-boot", &replies[2])?;
    selected.disk(policy, &replies[3])?;
    selected.instance(policy, &replies[4])
}

#[test]
fn physical_disk_selection_requires_complete_uid_and_attachment_joins() {
    let (selected, policy, replies) = fixture();
    assert_eq!(
        check(&selected, &policy, &replies).unwrap(),
        "attached-device"
    );
    let encoded = serde_json::to_vec(&selected).unwrap();
    let decoded: PersistentDiskSelection = crate::json::decode(&encoded).unwrap();
    assert!(decoded == selected);
    for (index, pointer, value) in [
        (0, "/metadata/uid", json!("recreated-claim")),
        (0, "/metadata/namespace", json!("foreign")),
        (0, "/spec/volumeName", json!("foreign-volume")),
        (0, "/spec/accessModes", json!(["ReadWriteMany"])),
        (1, "/metadata/uid", json!("recreated-volume")),
        (
            1,
            "/metadata/deletionTimestamp",
            json!("2026-10-19T00:00:00Z"),
        ),
        (1, "/spec/claimRef/uid", json!("foreign-claim")),
        (
            1,
            "/spec/csi/volumeHandle",
            json!("projects/foreign/zones/zone-one/disks/disk-one"),
        ),
        (1, "/spec/csi/driver", json!("foreign.csi")),
        (1, "/spec/csi/fsType", json!("xfs")),
        (1, "/spec/csi/readOnly", json!(true)),
        (2, "/metadata/uid", json!("recreated-node")),
        (2, "/status/nodeInfo/bootID", json!("later-boot")),
        (
            2,
            "/spec/providerID",
            json!("gce://foreign/zone-one/instance-one"),
        ),
        (3, "/id", json!("782")),
        (3, "/status", json!("RESTORING")),
        (3, "/users", json!([])),
        (3, "/users", json!(["one", "two"])),
        (4, "/id", json!("983")),
        (4, "/status", json!("STOPPING")),
        (4, "/disks/0/mode", json!("READ_ONLY")),
        (4, "/disks/0/boot", json!(true)),
        (4, "/disks/0/type", json!("SCRATCH")),
        (4, "/disks/0/deviceName", json!("../forwarded")),
    ] {
        let mut changed = replies.clone();
        // Inserting optional API fields is deliberate; JSON-pointer mutation
        // of an absent field would silently skip the negative oracle.
        if pointer.ends_with("deletionTimestamp") {
            changed[index]["metadata"]["deletionTimestamp"] = value;
        } else if pointer.ends_with("readOnly") {
            changed[index]["spec"]["csi"]["readOnly"] = value;
        } else {
            *changed[index].pointer_mut(pointer).unwrap() = value;
        }
        assert!(
            check(&selected, &policy, &changed).is_err(),
            "admitted {index}:{pointer}"
        );
    }
    let mut duplicate = replies.clone();
    let extra = duplicate[4]["disks"][0].clone();
    duplicate[4]["disks"].as_array_mut().unwrap().push(extra);
    assert!(check(&selected, &policy, &duplicate).is_err());
}

#[test]
fn profile_is_bound_to_policy_and_cannot_substitute_a_recreated_disk() {
    let (selected, policy, replies) = fixture();
    for id in ["0", "0781", "-1", "18446744073709551616", "another-disk"] {
        let mut wrong = selected.clone();
        wrong.disk_id = id.into();
        let mut changed = policy.clone();
        changed.fresh_storage.provider_volume_uid = id.into();
        changed.fresh_storage.mount_binding = wrong.digest().unwrap();
        assert!(wrong.validate(&changed).is_err());
    }
    let mut changed = selected.clone();
    changed.disk_id = "782".into();
    assert!(check(&changed, &policy, &replies).is_err());
    let mut changed = policy.clone();
    changed.fresh_storage.mount_binding = Digest::new(b"other profile");
    assert!(check(&selected, &changed, &replies).is_err());
}
