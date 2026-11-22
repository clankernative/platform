//! A qualified SDK release: the manifest an instance approves by digest, the
//! tooling distribution it names and the native and strict evidence that
//! qualified both. This is the one copy of the schema and its checks. xtask
//! produces distributions and joins releases with it; `day2 instance release`
//! publishes and fetches them with it.
//!
//! The approved manifest digest is the trust input. These integrity checks bind
//! the bytes to one another; they never grant qualification authority to an app
//! or to a local cache.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fs, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

/// The only release profile: one exclusive SQLite runtime per app. Rolling
/// releases (`linux_sqlite_rwo_v1`) are unused and refused.
pub const PROFILE: &str = "linux_sqlite_single_v1";
pub const TARGET: &str = "linux-x86_64";
pub const MANIFEST_LIMIT: u64 = 65_536;
pub const DISTRIBUTION_LIMIT: u64 = 65_536;
pub const EVIDENCE_LIMIT: u64 = 1_048_576;
/// The operator archive, the worker and each operator file.
pub const FILE_LIMIT: u64 = 256 << 20;
/// All operator files together, once extracted.
pub const EXPANSION_LIMIT: u64 = 768 << 20;

/// Exactly the files an operator package carries: the native CLI, its host and
/// workflow runner, and their notices.
pub const OPERATOR_FILES: [&str; 7] = [
    "cli/day2",
    "cli/day2-host",
    "cli/day2-workflows",
    "cli/day2-workflows.json",
    "licenses/LICENSE",
    "licenses/THIRD-PARTY-NOTICES.txt",
    "licenses/dependency-inventory.json",
];

/// An extracted operator file's mode: CLI executables are 0555, everything else 0444.
pub fn operator_mode(name: &str) -> u32 {
    if name.starts_with("cli/") && !name.ends_with(".json") {
        0o555
    } else {
        0o444
    }
}

/// Bytes named by content: a sha256 digest and an exact length.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobIdentity {
    pub digest: String,
    pub bytes: u64,
}

impl BlobIdentity {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            digest: crate::digest(bytes),
            bytes: bytes.len() as u64,
        }
    }

    /// A sha256 digest and a length of 1 to `limit` bytes; returns the digest's hex.
    pub fn check(&self, limit: u64) -> Result<&str> {
        let hex = day2_assets::hash_part(&self.digest).context("invalid qualified release blob")?;
        ensure!(
            self.bytes > 0 && self.bytes <= limit,
            "invalid qualified release blob"
        );
        Ok(hex)
    }
}

/// A digest-pinned image and the image ID its builder reported, which may be a
/// config, a runnable manifest or an OCI index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub image: String,
    pub config: String,
}

impl Image {
    /// Any digest-pinned repository with a sha256 image ID.
    pub fn validate(&self) -> Result<()> {
        let (repository, digest) = self
            .image
            .rsplit_once('@')
            .context("immutable SDK image required")?;
        let (registry, name) = repository
            .split_once('/')
            .context("SDK image registry required")?;
        ensure!(
            self.image.len() <= 512
                && !registry.is_empty()
                && registry
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:".contains(&b))
                && name
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-/".contains(&b)),
            "invalid SDK image repository"
        );
        day2_assets::hash_part(digest)?;
        day2_assets::hash_part(&self.config)?;
        Ok(())
    }

    /// Exactly `<registry>/<repository>/<name>@sha256:<hex>`, where `registry` is
    /// the instance's Artifact Registry root, `<region>-docker.pkg.dev/<project>`:
    /// one repository and one image name of lowercase letters, digits and hyphens.
    pub fn pinned_under(&self, registry: &str) -> bool {
        let segment = |value: &str| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        let Some((path, digest)) = self
            .image
            .strip_prefix(registry)
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|rest| rest.split_once('@'))
        else {
            return false;
        };
        let Some((repository, name)) = path.split_once('/') else {
            return false;
        };
        !registry.is_empty()
            && !registry.ends_with('/')
            && segment(repository)
            && segment(name)
            && day2_assets::hash_part(digest).is_ok()
            && day2_assets::hash_part(&self.config).is_ok()
    }
}

/// The release's native qualification and its strict-admission supplement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub native: BlobIdentity,
    pub strict: BlobIdentity,
}

/// The release manifest an instance approves by its digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub version: u32,
    pub platform_commit: String,
    pub profile: String,
    pub target: String,
    pub runtime: Image,
    pub tooling: Image,
    pub distribution: BlobIdentity,
    pub operator: BlobIdentity,
    pub evidence: Evidence,
}

impl Release {
    /// Decode and validate a manifest. Duplicate and unknown fields are refused.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Value = crate::json::decode(bytes)?;
        ensure!(
            value.is_object() && value["profile"] == PROFILE,
            "unsupported qualified release profile: only {PROFILE} releases are supported"
        );
        let release: Self =
            serde_json::from_value(value).context("invalid qualified release fields")?;
        release.validate()?;
        Ok(release)
    }

    /// Version 1 of the one supported profile and target, at an exact platform
    /// commit, with digest-pinned images and blobs within their byte budgets.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.profile == PROFILE && self.target == TARGET,
            "unsupported qualified release profile"
        );
        ensure!(
            self.platform_commit.len() == 40
                && self
                    .platform_commit
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "exact platform commit required"
        );
        self.runtime.validate()?;
        self.tooling.validate()?;
        self.distribution.check(DISTRIBUTION_LIMIT)?;
        self.operator.check(FILE_LIMIT)?;
        self.evidence.native.check(EVIDENCE_LIMIT)?;
        self.evidence.strict.check(EVIDENCE_LIMIT)?;
        Ok(())
    }

    /// Both images are pinned in the instance's own Artifact Registry, `<region>-docker.pkg.dev/<project>`.
    pub fn pinned_under(&self, registry: &str) -> Result<()> {
        ensure!(
            self.runtime.pinned_under(registry) && self.tooling.pinned_under(registry),
            "invalid qualified image identity: images must be pinned under {registry}/"
        );
        Ok(())
    }

    /// The published manifest bytes: keys sorted, two-space indentation, ASCII
    /// only and a final newline, byte for byte as the instance's Python
    /// publisher wrote them (`json.dumps(release, sort_keys=True, indent=2)`).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = crate::python_json::dumps(
            &serde_json::to_value(self)?,
            crate::python_json::Layout::Indented,
        )?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// The operator-only CLI distribution and the native build inputs it came from.
/// Field order is the order xtask writes it in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Distribution {
    pub format: u32,
    pub target: String,
    pub inputs: String,
    pub workflow_sources: String,
    pub toolchain: String,
    pub worker: BlobIdentity,
    pub operator: BlobIdentity,
    pub operator_files: BTreeMap<String, BlobIdentity>,
}

impl Distribution {
    /// Belongs to `release` (its target and operator archive), names its inputs
    /// by digest and carries exactly the fixed operator files within budget.
    pub fn bind(&self, release: &Release) -> Result<()> {
        ensure!(
            self.format == 1 && self.target == release.target && self.operator == release.operator,
            "tooling distribution belongs to another release"
        );
        for digest in [&self.inputs, &self.workflow_sources, &self.toolchain] {
            day2_assets::hash_part(digest).context("invalid tooling input digest")?;
        }
        self.worker.check(FILE_LIMIT)?;
        ensure!(
            self.operator_files.len() == OPERATOR_FILES.len()
                && OPERATOR_FILES
                    .iter()
                    .all(|name| self.operator_files.contains_key(*name)),
            "operator package must contain exactly the fixed native CLI and notice files"
        );
        let mut expanded = 0u64;
        for file in self.operator_files.values() {
            file.check(FILE_LIMIT)?;
            expanded += file.bytes;
        }
        ensure!(
            expanded <= EXPANSION_LIMIT,
            "operator package expansion budget"
        );
        Ok(())
    }
}

/// The native qualification ran this platform commit's tooling and runtime
/// images, workflows, toolchain and distribution on x86_64, and the strict
/// supplement names that exact qualification receipt and its identities.
pub fn bind_evidence(
    release: &Release,
    distribution: &Distribution,
    native: &Value,
    strict: &Value,
) -> Result<()> {
    let built = &native["tooling_distribution"];
    ensure!(
        native["format"] == 1
            && native["status"] == "passed"
            && native["source_revision"] == release.platform_commit
            && native["scope"] == PROFILE
            && native["runtime_image"] == release.runtime.config
            && native["tooling_image"] == release.tooling.config
            && native["workflow"] == distribution.workflow_sources
            && native["toolchain"] == distribution.toolchain
            && native["environment"]["architecture"] == "x86_64"
            && built["distribution"] == release.distribution.digest
            && built["operator"] == serde_json::to_value(&release.operator)?
            && built["worker"] == serde_json::to_value(&distribution.worker)?,
        "native qualification does not bind this tooling/runtime distribution"
    );
    ensure!(
        strict["status"] == "strict-admission-passed"
            && strict["qualification"] == false
            && strict["qualification_digest"] == release.evidence.native.digest
            && [
                "runtime_image",
                "tooling_image",
                "platform",
                "platform_inventory",
                "artifact",
            ]
            .iter()
            .all(|field| strict[*field] == native[*field]),
        "strict-admission supplement does not bind this native qualification"
    );
    Ok(())
}

/// Read a regular file (never through a link) whose bytes are exactly `expected`.
pub fn verify(path: &Path, expected: &BlobIdentity, limit: u64) -> Result<Vec<u8>> {
    day2_assets::hash_part(&expected.digest)?;
    ensure!(
        expected.bytes > 0 && expected.bytes <= limit,
        "tooling output byte budget"
    );
    let bytes = day2_assets::read_regular(path, limit)?;
    ensure!(
        bytes.len() as u64 == expected.bytes && crate::digest(&bytes) == expected.digest,
        "precompiled tooling output changed: {}",
        path.display()
    );
    Ok(bytes)
}

/// The identity of a regular file of 1 to `limit` bytes, hashed as it streams
/// and opened without following a link.
pub fn identity(path: &Path, limit: u64) -> Result<BlobIdentity> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("release file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() > 0 && metadata.len() <= limit,
        "release output must be a bounded regular file: {}",
        path.display()
    );
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        ensure!(size <= limit, "release output exceeds byte budget");
        context.update(&buffer[..read]);
    }
    Ok(BlobIdentity {
        digest: format!("sha256:{}", crate::hex(context.finish().as_ref())),
        bytes: size,
    })
}

/// Hold an exclusive flock on a cache key's lock file, created 0600 and never
/// opened through a link. The instance's earlier Python consumer took the same
/// locks, so the two exclude one another on a shared cache.
pub fn lock(path: &Path) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .with_context(|| format!("release cache lock {}", path.display()))?;
    file.lock()?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const GOLDEN: &[u8] = include_bytes!("../fixtures/sdk-release/manifest-cc689326.json");
    const GOLDEN_DIGEST: &str =
        "sha256:cc689326c54b7a9cba772211381d9e7442a3e4d7137a3ede128593d6e0e76432";
    const DISTRIBUTION: &[u8] =
        include_bytes!("../fixtures/sdk-release/distribution-8d35dccb.json");
    const REGISTRY: &str = "us-central1-docker.pkg.dev/wonderly-internal-tools";

    /// A synthetic release whose evidence binds it, with only the receipt fields
    /// the checks read. It qualifies nothing.
    pub(crate) fn fixture() -> (Release, Distribution, Value, Value) {
        let digest = |label: &str| crate::digest(label.as_bytes());
        let native_blob = |label: &str| BlobIdentity::of(label.as_bytes());
        let operator = native_blob("operator archive");
        let distribution = Distribution {
            format: 1,
            target: TARGET.into(),
            inputs: digest("inputs"),
            workflow_sources: digest("workflows"),
            toolchain: digest("toolchain"),
            worker: native_blob("!<arch>\nworker"),
            operator: operator.clone(),
            operator_files: OPERATOR_FILES
                .iter()
                .map(|name| ((*name).to_owned(), native_blob(name)))
                .collect(),
        };
        let runtime = digest("runtime config");
        let tooling = digest("tooling config");
        let mut native = json!({
            "format": 1, "status": "passed", "scope": PROFILE, "source_revision": "a".repeat(40),
            "runtime_image": runtime, "tooling_image": tooling,
            "workflow": distribution.workflow_sources, "toolchain": distribution.toolchain,
            "platform": digest("platform"), "platform_inventory": digest("inventory"),
            "artifact": digest("fixture app"), "environment": {"architecture": "x86_64"},
        });
        let raw_distribution = serde_json::to_vec_pretty(&distribution).unwrap();
        native["tooling_distribution"] = json!({
            "distribution": crate::digest(&raw_distribution),
            "operator": operator, "worker": distribution.worker,
        });
        let raw_native = serde_json::to_vec(&native).unwrap();
        let mut strict = json!({
            "status": "strict-admission-passed", "qualification": false,
            "qualification_digest": crate::digest(&raw_native),
        });
        for field in [
            "runtime_image",
            "tooling_image",
            "platform",
            "platform_inventory",
            "artifact",
        ] {
            strict[field] = native[field].clone();
        }
        let release = Release {
            version: 1,
            platform_commit: "a".repeat(40),
            profile: PROFILE.into(),
            target: TARGET.into(),
            runtime: Image {
                image: format!("{REGISTRY}/platform/day2-runtime@{runtime}"),
                config: runtime,
            },
            tooling: Image {
                image: format!("{REGISTRY}/platform/day2-tooling@{tooling}"),
                config: tooling,
            },
            distribution: BlobIdentity::of(&raw_distribution),
            operator,
            evidence: Evidence {
                native: BlobIdentity::of(&raw_native),
                strict: BlobIdentity::of(&serde_json::to_vec(&strict).unwrap()),
            },
        };
        (release, distribution, native, strict)
    }

    fn accepted(release: &Release) -> Result<()> {
        release.validate()?;
        release.pinned_under(REGISTRY)
    }

    #[test]
    fn the_published_manifest_reencodes_byte_for_byte() -> Result<()> {
        assert_eq!(crate::digest(GOLDEN), GOLDEN_DIGEST);
        let release = Release::decode(GOLDEN)?;
        release.pinned_under(REGISTRY)?;
        assert_eq!(
            release.platform_commit,
            "93aba94790df7ad80d6a45103788e3604ad06b7e"
        );
        let encoded = release.encode()?;
        assert_eq!(encoded, GOLDEN);
        assert_eq!(crate::digest(&encoded), GOLDEN_DIGEST);
        // The published distribution is the one the manifest names, and binds it.
        assert_eq!(BlobIdentity::of(DISTRIBUTION), release.distribution);
        let distribution: Distribution = crate::json::decode(DISTRIBUTION)?;
        distribution.bind(&release)?;
        // xtask writes a distribution in field order with two-space indentation.
        assert_eq!(serde_json::to_vec_pretty(&distribution)?, DISTRIBUTION);
        Ok(())
    }

    #[test]
    fn a_single_release_requires_native_and_strict_and_refuses_rolling() -> Result<()> {
        let (release, distribution, native, strict) = fixture();
        accepted(&release)?;
        distribution.bind(&release)?;
        bind_evidence(&release, &distribution, &native, &strict)?;
        let mut value = serde_json::to_value(&release)?;
        value["profile"] = json!("linux_sqlite_rwo_v1");
        assert!(Release::decode(&serde_json::to_vec(&value)?).is_err());
        value["profile"] = json!(PROFILE);
        value["evidence"]["rolling"] = json!(release.evidence.native);
        assert!(Release::decode(&serde_json::to_vec(&value)?).is_err());
        value["evidence"] = json!({"native": release.evidence.native});
        assert!(Release::decode(&serde_json::to_vec(&value)?).is_err());
        Ok(())
    }

    #[test]
    fn unknown_duplicate_unpinned_and_unsupported_manifests_are_refused() -> Result<()> {
        let (release, ..) = fixture();
        let raw = serde_json::to_value(&release)?;
        assert!(Release::decode(&serde_json::to_vec(&raw)?).is_ok());
        let refused = |field: &str, value: Value| {
            let mut changed = raw.clone();
            changed[field] = value;
            Release::decode(&serde_json::to_vec(&changed).unwrap())
                .and_then(|release| release.pinned_under(REGISTRY))
                .is_err()
        };
        for (field, value) in [
            ("version", json!(true)),
            ("version", json!(2)),
            ("version", json!(1.0)),
            ("profile", json!("native_enrollment_v1")),
            ("platform_commit", json!("main")),
            ("platform_commit", json!("A".repeat(40))),
            ("target", json!("linux-aarch64")),
            ("extra", json!(1)),
            (
                "distribution",
                json!({"digest": release.distribution.digest, "bytes": 65_537}),
            ),
            (
                "distribution",
                json!({"digest": release.distribution.digest, "bytes": 0}),
            ),
            (
                "distribution",
                json!({"digest": release.distribution.digest, "bytes": true}),
            ),
            (
                "distribution",
                json!({"digest": "sha256:short", "bytes": 1}),
            ),
            (
                "operator",
                json!({"digest": release.operator.digest, "bytes": (256u64 << 20) + 1}),
            ),
            (
                "operator",
                json!({"digest": release.operator.digest, "bytes": 1, "extra": 1}),
            ),
        ] {
            assert!(refused(field, value.clone()), "{field} {value}");
        }
        let native = json!({"digest": release.evidence.native.digest, "bytes": 1_048_577});
        assert!(refused(
            "evidence",
            json!({"native": native, "strict": release.evidence.strict})
        ));
        for image in [
            format!("{REGISTRY}/platform/day2-runtime:latest"),
            format!(
                "{REGISTRY}/platform/nested/day2-runtime@{}",
                release.runtime.config
            ),
            format!(
                "{REGISTRY}/Platform/day2-runtime@{}",
                release.runtime.config
            ),
            format!("{REGISTRY}/day2-runtime@{}", release.runtime.config),
            format!(
                "other-docker.pkg.dev/project/platform/day2-runtime@{}",
                release.runtime.config
            ),
        ] {
            assert!(
                refused(
                    "runtime",
                    json!({"image": image, "config": release.runtime.config})
                ),
                "{image}"
            );
        }
        // The tooling image is held to the same registry as the runtime image.
        for image in [
            format!(
                "other-docker.pkg.dev/project/platform/day2-tooling@{}",
                release.tooling.config
            ),
            format!(
                "{REGISTRY}-other/platform/day2-tooling@{}",
                release.tooling.config
            ),
        ] {
            assert!(
                refused(
                    "tooling",
                    json!({"image": image, "config": release.tooling.config})
                ),
                "{image}"
            );
        }
        assert!(refused(
            "tooling",
            json!({"image": release.tooling.image, "config": "sha256:short"})
        ));
        assert!(refused(
            "tooling",
            json!({"image": release.tooling.image, "config": release.tooling.config, "x": 1})
        ));
        assert!(Release::decode(br#"{"version":1,"version":1}"#).is_err());
        assert!(Release::decode(b"[]").is_err());
        Ok(())
    }

    #[test]
    fn a_distribution_binds_one_release_and_exactly_the_fixed_files() -> Result<()> {
        let (release, distribution, ..) = fixture();
        distribution.bind(&release)?;
        let refused = |change: &dyn Fn(&mut Distribution)| {
            let mut changed = distribution.clone();
            change(&mut changed);
            changed.bind(&release).is_err()
        };
        assert!(refused(&|d| d.format = 2));
        assert!(refused(&|d| d.target = "linux-aarch64".into()));
        assert!(refused(
            &|d| d.operator = BlobIdentity::of(b"another archive")
        ));
        assert!(refused(&|d| d.inputs = "main".into()));
        assert!(refused(&|d| d.workflow_sources = "sha256:short".into()));
        assert!(refused(&|d| d.toolchain = String::new()));
        assert!(refused(&|d| d.worker.bytes = (256 << 20) + 1));
        assert!(refused(&|d| d.worker.digest = "md5:x".into()));
        assert!(refused(&|d| {
            d.operator_files
                .insert("cli/arbitrary-hook".into(), BlobIdentity::of(b"hook"));
        }));
        assert!(refused(&|d| {
            d.operator_files.remove("licenses/LICENSE");
        }));
        assert!(refused(&|d| {
            let file = d.operator_files.remove("cli/day2").unwrap();
            d.operator_files.insert("cli/day3".into(), file);
        }));
        assert!(refused(&|d| d
            .operator_files
            .get_mut("cli/day2")
            .unwrap()
            .bytes = 0));
        // Each file fits, but together they expand past the budget.
        assert!(refused(&|d| {
            for file in d.operator_files.values_mut() {
                file.bytes = 200 << 20;
            }
        }));
        let mut value = serde_json::to_value(&distribution)?;
        value["extra"] = json!(1);
        assert!(serde_json::from_value::<Distribution>(value).is_err());
        Ok(())
    }

    #[test]
    fn evidence_cannot_be_reused_for_another_release_runtime_or_campaign() -> Result<()> {
        let (release, distribution, native, strict) = fixture();
        bind_evidence(&release, &distribution, &native, &strict)?;
        let other = crate::digest(b"another release");
        for (field, value) in [
            ("format", json!(2)),
            ("format", json!(true)),
            ("status", json!("failed")),
            ("source_revision", json!("b".repeat(40))),
            ("scope", json!("linux_sqlite_rwo_v1")),
            ("runtime_image", json!(other)),
            ("tooling_image", json!(other)),
            ("workflow", json!(other)),
            ("toolchain", json!(other)),
            ("environment", json!({"architecture": "aarch64"})),
            ("environment", json!(null)),
            ("tooling_distribution", json!(null)),
        ] {
            let mut changed = native.clone();
            changed[field] = value.clone();
            assert!(
                bind_evidence(&release, &distribution, &changed, &strict).is_err(),
                "native {field} {value}"
            );
        }
        for (field, value) in [
            ("distribution", json!(other)),
            ("operator", json!(BlobIdentity::of(b"other"))),
            ("worker", json!(BlobIdentity::of(b"other"))),
        ] {
            let mut changed = native.clone();
            changed["tooling_distribution"][field] = value;
            assert!(
                bind_evidence(&release, &distribution, &changed, &strict).is_err(),
                "tooling_distribution {field}"
            );
        }
        for (field, value) in [
            ("status", json!("passed")),
            ("qualification", json!(true)),
            ("qualification", json!(null)),
            (
                "qualification_digest",
                json!(crate::digest(b"other receipt")),
            ),
            ("runtime_image", json!(other)),
            ("tooling_image", json!(other)),
            ("platform", json!(other)),
            ("platform_inventory", json!(other)),
            ("artifact", json!(other)),
        ] {
            let mut changed = strict.clone();
            changed[field] = value.clone();
            assert!(
                bind_evidence(&release, &distribution, &native, &changed).is_err(),
                "strict {field} {value}"
            );
        }
        Ok(())
    }

    #[test]
    fn identity_streams_only_bounded_regular_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("blob");
        fs::write(&path, b"qualified bytes")?;
        assert_eq!(identity(&path, 64)?, BlobIdentity::of(b"qualified bytes"));
        assert!(identity(&path, 4).is_err());
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(identity(&link, 64).is_err());
        fs::write(&path, b"")?;
        assert!(identity(&path, 64).is_err());
        assert!(identity(directory.path(), 64).is_err());
        assert!(identity(&directory.path().join("missing"), 64).is_err());
        Ok(())
    }
}
