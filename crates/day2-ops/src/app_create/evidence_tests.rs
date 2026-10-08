use super::{
    SourceFile, bundle,
    core::{Node, Snapshot},
    simulation::{Memory, SeededEntropy, bundle_fixture},
    state_machine,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

#[test]
fn no_fs_bundle_admission_preserves_the_closed_native_guards() -> Result<()> {
    for mutation in 0..25 {
        let mut reader = bundle_fixture();
        let mut manifest: Value = serde_json::from_slice(&reader.0["manifest.json"])?;
        match mutation {
            0 => manifest["schemaVersion"] = 2.into(),
            1 => manifest["target"] = "wrong-target".into(),
            2 => manifest["provider"] = "wrong-provider".into(),
            3 => manifest["assemblyProtocol"] = 1.into(),
            4 => manifest["bindingAbi"] = 1.into(),
            5 => manifest["templateEngine"] = "wrong-engine".into(),
            6 => manifest["toolVersion"] = "".into(),
            7 => manifest["sourceRevision"] = "short".into(),
            8 => manifest["executable"]["path"] = "bin/wrong".into(),
            9 => manifest["executable"]["bytes"] = (64 * 1024 * 1024 + 1).into(),
            10 => manifest["package"]["name"] = "wrong-package".into(),
            11 => manifest["package"]["version"] = "".into(),
            12 => manifest["entries"] = json!([]),
            13 => manifest["legal"] = json!([]),
            14 => manifest["legal"][0]["path"] = "../LICENSE".into(),
            15 => manifest["legal"][0]["bytes"] = 0.into(),
            16 => manifest["legal"][0]["digest"] = super::sha(b"wrong").into(),
            17 => {
                reader.0.insert("provider-pin.json".into(), b"{}".to_vec());
            }
            18 => {
                reader
                    .0
                    .insert("bin/clanker-ui".into(), b"tampered".to_vec());
            }
            19 => manifest["entries"][0]["path"] = "../outside".into(),
            20 => manifest["entries"][0]["path"] = "a/".repeat(10).into(),
            21 => manifest["entries"][0]["bytes"] = 1_048_577.into(),
            22 => manifest["entries"][0]["digest"] = super::sha(b"wrong").into(),
            23 => manifest["package"]["digest"] = super::sha(b"wrong").into(),
            24 => manifest["unknown"] = true.into(),
            _ => unreachable!(),
        }
        let bytes = serde_json::to_vec(&manifest)?;
        reader.0.insert("manifest.json".into(), bytes.clone());
        ensure!(
            bundle::capture(&reader, &super::sha(&bytes), "linux-x86_64").is_err(),
            "bundle mutation {mutation} accepted"
        );
    }
    let reader = bundle_fixture();
    ensure!(
        bundle::capture(&reader, &super::sha(b"wrong approval"), "linux-x86_64").is_err(),
        "approval mismatch accepted"
    );
    let capture = bundle::capture(
        &reader,
        &super::sha(&reader.0["manifest.json"]),
        "linux-x86_64",
    )?;
    ensure!(
        capture.executable == reader.0["bin/clanker-ui"],
        "captured executable differs"
    );
    ensure!(
        capture.files[".ui-dependencies/legal/LICENSE"] == reader.0["legal/LICENSE"],
        "legal capture differs"
    );
    Ok(())
}

#[test]
fn bounded_evidence_rejects_links_special_depth_member_count_and_total_bytes() -> Result<()> {
    for node in [Node::Link, Node::Special, Node::File(vec![0; 1_048_577])] {
        ensure!(
            Snapshot(BTreeMap::from([("member".into(), node)]))
                .digest()
                .is_err(),
            "unsafe member accepted"
        );
    }
    ensure!(
        Snapshot(BTreeMap::from([(
            "a/".repeat(10) + "deep",
            Node::File(vec![])
        )]))
        .digest()
        .is_err(),
        "depth accepted"
    );
    for ancestor in [
        None,
        Some(Node::File(vec![])),
        Some(Node::Link),
        Some(Node::Special),
    ] {
        let mut evidence = Snapshot(BTreeMap::from([(
            "parent/child".into(),
            Node::File(vec![]),
        )]));
        if let Some(node) = ancestor {
            evidence.0.insert("parent".into(), node);
        }
        ensure!(evidence.digest().is_err(), "inconsistent ancestor accepted");
    }
    Snapshot(BTreeMap::from([
        ("parent".into(), Node::Directory),
        ("parent/child".into(), Node::File(vec![])),
    ]))
    .digest()?;
    let mut evidence = Snapshot::default();
    for n in 0..8192 {
        evidence.0.insert(format!("file-{n}"), Node::File(vec![]));
    }
    evidence.digest()?;
    evidence.0.insert("overflow".into(), Node::Directory);
    ensure!(evidence.digest().is_err(), "entry budget accepted");
    let mut evidence = Snapshot::default();
    for n in 0..64 {
        evidence
            .0
            .insert(format!("file-{n}"), Node::File(vec![0; 1_048_576]));
    }
    evidence.digest()?;
    evidence.0.insert("overflow".into(), Node::File(vec![0]));
    ensure!(evidence.digest().is_err(), "aggregate byte budget accepted");
    Ok(())
}

#[test]
fn wrong_source_namespace_and_admission_failure_close_publication() -> Result<()> {
    let entropy = SeededEntropy::new(130);
    let mut creation = Memory::begin(&state_machine::options())?;
    creation.write_files(vec![SourceFile {
        path: "App.roc".into(),
        content: "App :: [].{ definition = { namespace: \"other\" } }\n".into(),
    }])?;
    ensure!(
        creation
            .identity("starters", "Models.StarterRecord", &entropy)
            .is_err(),
        "wrong source namespace accepted"
    );
    ensure!(
        creation.publish(Path::new("/artifact")).is_err(),
        "failed identity published"
    );
    ensure!(creation.port.publications == 0, "publication on failure");
    // Adapter evidence (not a mocked publish response) must stay valid right up
    // to the same shared publication guard's re-admission boundary.
    let mut creation = Memory::begin(&state_machine::options())?;
    creation.write_files(state_machine::sources())?;
    creation.identity("starters", "Models.StarterRecord", &entropy)?;
    creation.check_build_source(Path::new("/captured-source"))?;
    ensure!(
        creation.built(Path::new("/not-admitted")).is_err(),
        "unadmitted artifact accepted"
    );
    ensure!(
        creation.port.publications == 0 && creation.port.published.is_none(),
        "unadmitted artifact published"
    );
    Ok(())
}

#[test]
fn empty_directory_capture_tamper_is_not_silently_ignored() -> Result<()> {
    let mut creation = Memory::begin(&state_machine::options())?;
    creation.write_files(state_machine::sources())?;
    creation.identity("starters", "Models.StarterRecord", &SeededEntropy::new(130))?;
    creation.port.tree.0.insert("extra".into(), Node::Directory);
    ensure!(
        creation
            .check_build_source(Path::new("/captured-source"))
            .is_err(),
        "empty directory tamper accepted"
    );
    ensure!(
        creation.port.publications == 0,
        "directory tamper published"
    );
    Ok(())
}
