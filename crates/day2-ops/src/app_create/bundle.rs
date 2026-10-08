//! Closed approved bundle admission, shared by native reads and evidence replay.
use super::{Manifest, relative, sha};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) trait Reader {
    /// Return all regular member bytes or fail, never truncate at the bound.
    fn read(&self, path: &str, budget: u64) -> Result<Vec<u8>>;
}

pub(crate) struct Capture {
    pub files: BTreeMap<String, Vec<u8>>,
    pub executable: Vec<u8>,
    pub pin: Vec<u8>,
}

pub(crate) fn capture(reader: &impl Reader, approval: &str, target: &str) -> Result<Capture> {
    ensure!(
        ["linux-x86_64", "macos-aarch64"].contains(&target),
        "installed bundle host unsupported"
    );
    let mut files = BTreeMap::new();
    let manifest_bytes = reader.read("manifest.json", 1_048_576)?;
    ensure!(
        sha(&manifest_bytes) == approval,
        "approved bundle manifest digest mismatch"
    );
    let manifest: Manifest = day2::json::decode(&manifest_bytes)?;
    ensure!(
        manifest.schema_version == 1
            && manifest.target == target
            && manifest.provider == "clanker-ui.native"
            && manifest.assembly_protocol == 2
            && manifest.binding_abi == 2
            && manifest.template_engine == "minijinja-2.12.0"
            && !manifest.tool_version.is_empty()
            && manifest.source_revision.len() == 40
            && manifest.executable.path == "bin/clanker-ui"
            && manifest.executable.bytes <= 64 * 1024 * 1024
            && manifest.package.name == "@clanker/vanilla"
            && !manifest.package.version.is_empty()
            && !manifest.entries.is_empty()
            && manifest.entries.len() <= 4096,
        "unsupported installed bundle manifest"
    );
    // Legal bytes are a closed, separately captured release input, never
    // catalog resources or app-authored executable authority.
    ensure!(
        manifest.legal.len() == 2,
        "unsupported bundle legal closure"
    );
    for (entry, path) in manifest
        .legal
        .iter()
        .zip(["legal/LICENSE", "legal/NOTICES.txt"])
    {
        ensure!(
            entry.path == path && entry.bytes > 0 && entry.bytes <= 1_048_576,
            "unsafe bundle legal member or budget"
        );
        let bytes = reader.read(path, 1_048_576)?;
        ensure!(
            bytes.len() == entry.bytes && sha(&bytes) == entry.digest,
            "bundle legal member mismatch"
        );
        files.insert(format!(".ui-dependencies/{path}"), bytes);
    }
    let installed_pin: Value = day2::json::decode(&reader.read("provider-pin.json", 1_048_576)?)?;
    ensure!(
        installed_pin
            == json!({
                "schemaVersion":1,"provider":manifest.provider,"assemblyProtocol":2,"bindingAbi":2,
                "targets":{target:{"executable":"bin/clanker-ui","digest":manifest.executable.digest}}
            }),
        "installed provider pin must name only the reviewed manifest executable"
    );
    let executable = reader.read(&manifest.executable.path, 64 * 1024 * 1024)?;
    ensure!(
        executable.len() == manifest.executable.bytes
            && sha(&executable) == manifest.executable.digest,
        "bundle executable mismatch"
    );
    let pin = serde_json::to_vec(&json!({
        "schemaVersion":1,"provider":manifest.provider,"assemblyProtocol":2,"bindingAbi":2,
        "targets":{target:{"executable":"adapter","digest":manifest.executable.digest}}
    }))?;
    let mut sorted = manifest.entries.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut hash = Sha256::new();
    let mut names = BTreeSet::new();
    let mut total = 0usize;
    let mut inputs = Vec::new();
    for entry in sorted {
        ensure!(
            relative(&entry.path)
                && names.insert(entry.path.to_ascii_lowercase())
                && entry.bytes <= 1_048_576,
            "unsafe/colliding bundle member"
        );
        total = total
            .checked_add(entry.bytes)
            .context("bundle byte overflow")?;
        ensure!(total <= 32 * 1024 * 1024, "bundle byte budget");
        let bytes = reader.read(&format!("package/{}", entry.path), 1_048_576)?;
        ensure!(
            bytes.len() == entry.bytes && sha(&bytes) == entry.digest,
            "bundle package member mismatch"
        );
        files.insert(format!(".ui-dependencies/vanilla/{}", entry.path), bytes);
        hash.update(entry.path.as_bytes());
        hash.update([0]);
        hash.update(entry.bytes.to_string().as_bytes());
        hash.update([0]);
        hash.update(entry.digest.as_bytes());
        hash.update(b"\n");
        inputs.push(json!({"path":entry.path,"bytes":entry.bytes,"digest":entry.digest}));
    }
    ensure!(
        format!("sha256:{:x}", hash.finalize()) == manifest.package.digest,
        "bundle package manifest mismatch"
    );
    files.insert(
            "ui/ui.lock.json".into(),
            serde_json::to_vec_pretty(&json!({
                "schemaVersion":1,"provider":manifest.provider,
                "package":{"name":manifest.package.name,"version":manifest.package.version,
                    "path":"../.ui-dependencies/vanilla","digest":manifest.package.digest,"inputs":inputs}
            }))?,
        );
    Ok(Capture {
        files,
        executable,
        pin,
    })
}
