//! Deterministic no-filesystem adapter. It replaces evidence/atomic operations,
//! never the production phase, namespace, source or artifact admission guards.
use super::{
    Options, bundle,
    core::{Admission, Creation, Node, Ports, Snapshot},
    relative, sha,
};
use anyhow::{Context, Result, ensure};
use day2::host_inputs::Entropy;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

pub(crate) struct SeededEntropy {
    state: Mutex<u64>,
    pub fail: bool,
}

impl SeededEntropy {
    pub fn new(seed: u64) -> Self {
        Self {
            state: Mutex::new(seed),
            fail: false,
        }
    }
}

impl Entropy for SeededEntropy {
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        ensure!(!self.fail, "injected entropy failure");
        let mut state = self.state.lock().unwrap();
        for byte in bytes {
            *state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (*state >> 56) as u8;
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct Memory {
    pub tree: Snapshot,
    pub admitted: BTreeMap<PathBuf, Admission>,
    pub occupied: bool,
    pub published: Option<Snapshot>,
    pub publications: usize,
    pub fail_admission: bool,
}

impl Memory {
    pub fn begin(options: &Options) -> Result<Creation<Self>> {
        super::core::validate_options(options)?;
        let mut port = Self::default();
        if options.ui == "clanker" {
            let reader = bundle_fixture();
            let capture = bundle::capture(&reader, &options.bundle_sha256, "linux-x86_64")?;
            port.write(&capture.files)?;
        }
        Creation::new(
            options.name.clone(),
            PathBuf::from("/captured-source"),
            port,
        )
    }

    pub fn verified(&mut self, artifact: &Path, namespace: &str) {
        self.admitted.insert(
            artifact.into(),
            Admission {
                artifact: artifact.into(),
                identity: sha(b"verified fixture artifact"),
                namespace: namespace.into(),
            },
        );
    }
}

impl Ports for Memory {
    fn snapshot(&self) -> Result<Snapshot> {
        Ok(self.tree.clone())
    }

    fn resolve_source(&self, source: &Path) -> Result<PathBuf> {
        Ok(source.into())
    }

    fn write(&mut self, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        for (path, bytes) in files {
            ensure!(
                relative(path) && !self.tree.0.contains_key(path),
                "no-clobber memory write"
            );
            // Include directories in evidence, just like native enumeration.
            let mut prefix = String::new();
            let parts: Vec<_> = path.split('/').collect();
            for part in &parts[..parts.len() - 1] {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(part);
                if let Some(node) = self.tree.0.get(&prefix) {
                    ensure!(
                        matches!(node, Node::Directory),
                        "non-directory memory ancestor"
                    );
                } else {
                    self.tree.0.insert(prefix.clone(), Node::Directory);
                }
            }
            self.tree.0.insert(path.clone(), Node::File(bytes.clone()));
        }
        Ok(())
    }

    fn admit(&self, artifact: &Path) -> Result<Admission> {
        ensure!(!self.fail_admission, "injected admission failure");
        self.admitted
            .get(artifact)
            .cloned()
            .context("ordinary admission required")
    }

    fn publish(&mut self, artifact: &Path) -> Result<Value> {
        ensure!(!self.occupied, "destination collision");
        self.occupied = true;
        self.publications += 1;
        self.published = Some(self.tree.clone());
        Ok(json!({"source":"fresh-app","artifact":artifact}))
    }
}

pub(crate) struct Bundle(pub BTreeMap<String, Vec<u8>>);

impl bundle::Reader for Bundle {
    fn read(&self, path: &str, budget: u64) -> Result<Vec<u8>> {
        ensure!(relative(path), "unsafe captured path");
        let bytes = self.0.get(path).context("missing regular bundle member")?;
        ensure!(bytes.len() as u64 <= budget, "bundle member byte budget");
        Ok(bytes.clone())
    }
}

pub(crate) fn bundle_fixture() -> Bundle {
    let executable = b"capture-only fixture, never executed";
    let package = b"opaque fixture package bytes";
    let legal = [
        b"opaque fixture project legal bytes".as_slice(),
        b"opaque fixture third-party legal bytes".as_slice(),
    ];
    let mut hash = Sha256::new();
    hash.update(format!("ui-package.json\0{}\0{}\n", package.len(), sha(package)).as_bytes());
    let manifest = json!({
        "schemaVersion":1,"target":"linux-x86_64","toolVersion":"0.1.0","sourceRevision":"a".repeat(40),
        "provider":"clanker-ui.native","assemblyProtocol":2,"bindingAbi":2,"templateEngine":"minijinja-2.12.0",
        "executable":{"path":"bin/clanker-ui","bytes":executable.len(),"digest":sha(executable)},
        "package":{"name":"@clanker/vanilla","version":"0.7.0","digest":format!("sha256:{:x}",hash.finalize())},
        "entries":[{"path":"ui-package.json","bytes":package.len(),"digest":sha(package)}],
        "legal":[{"path":"legal/LICENSE","bytes":legal[0].len(),"digest":sha(legal[0])},
            {"path":"legal/NOTICES.txt","bytes":legal[1].len(),"digest":sha(legal[1])}]
    });
    Bundle(BTreeMap::from([
        ("manifest.json".into(), serde_json::to_vec(&manifest).unwrap()),
        ("provider-pin.json".into(), serde_json::to_vec(&json!({
            "schemaVersion":1,"provider":"clanker-ui.native","assemblyProtocol":2,"bindingAbi":2,
            "targets":{"linux-x86_64":{"executable":"bin/clanker-ui","digest":sha(executable)}}
        })).unwrap()),
        ("bin/clanker-ui".into(), executable.to_vec()),
        ("package/ui-package.json".into(), package.to_vec()),
        ("legal/LICENSE".into(), legal[0].to_vec()),
        ("legal/NOTICES.txt".into(), legal[1].to_vec()),
    ]))
}
