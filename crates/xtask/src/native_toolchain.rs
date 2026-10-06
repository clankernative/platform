//! Fixed native targets only. The instance and app cannot select a compiler or
//! linker search path; Linux system inputs come from the reviewed build image.
use super::*;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// The historical macOS backport's semantic base. No official pin selects it.
const SEMANTIC_VERSION: &str = "nightly-2026-09-05-b195f5b";
/// The official release every native target compiles applications with. One
/// release for all targets, so an artifact's language semantics do not depend on
/// the machine that built it.
const OFFICIAL_VERSION: &str = "nightly-2026-09-12-220fd47";
const DERIVED_VERSION: &str = "nightly-2026-09-05-b195f5b-day2-glue11254";
const UPSTREAM_MAC_SHA256: &str =
    "47dba6e951a246c08aa51926c52566922276db2401b6ffb015150905598da01b";
const PATCH_PATH: &str = "tools/roc-compiler/glue-layouts.patch";
// Only this reviewed, portable backport may retain the September 5 semantic
// identity. Updating a JSON digest alone cannot authorize another compiler patch.
const REVIEWED_GLUE_PATCH_SHA256: &str =
    "9d33559435a7d4acae54adda099cc91b644c0255bdfeab1621542196e775de72";
const PROVENANCE_PATH: &str = "tools/roc-compiler/build-provenance.json";
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;

fn hash_field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    let hash = value[field].as_str().context("missing compiler digest")?;
    ensure!(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid compiler digest: {field}"
    );
    Ok(hash)
}

fn verify_file(path: &Path, expected: &str, budget: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= budget,
        "compiler input must be a bounded regular file: {}",
        path.display()
    );
    let bytes = fs::read(path)?;
    ensure!(bytes.len() as u64 <= budget, "compiler input byte budget");
    ensure!(
        digest(&bytes) == format!("sha256:{expected}"),
        "compiler input digest mismatch: {}",
        path.display()
    );
    Ok(())
}

fn real_directory(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "compiler input directory must not be a symlink: {}",
        path.display()
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    MacArm64,
    LinuxArm64,
    LinuxX64,
}

impl Target {
    fn detect(os: &str, arch: &str, environment: &str) -> Result<Self> {
        match (os, arch, environment) {
            ("macos", "aarch64", _) => Ok(Self::MacArm64),
            ("linux", "aarch64", "gnu") => Ok(Self::LinuxArm64),
            ("linux", "x86_64", "gnu") => Ok(Self::LinuxX64),
            _ => bail!("unsupported native toolchain: {arch}-{os}-{environment}"),
        }
    }

    fn current() -> Result<Self> {
        Self::detect(
            std::env::consts::OS,
            std::env::consts::ARCH,
            if cfg!(target_env = "gnu") { "gnu" } else { "" },
        )
    }

    pub fn pin_path(self) -> &'static str {
        match self {
            Self::MacArm64 => "toolchain.json",
            Self::LinuxArm64 => "toolchains/linux-aarch64.json",
            Self::LinuxX64 => "toolchains/linux-x86_64.json",
        }
    }

    fn rust_target(self) -> &'static str {
        match self {
            Self::MacArm64 => "aarch64-apple-darwin",
            Self::LinuxArm64 => "aarch64-unknown-linux-gnu",
            Self::LinuxX64 => "x86_64-unknown-linux-gnu",
        }
    }

    pub fn roc_target(self) -> &'static str {
        match self {
            Self::MacArm64 => "arm64mac",
            Self::LinuxArm64 => "arm64glibc",
            Self::LinuxX64 => "x64glibc",
        }
    }

    fn official_version(self) -> &'static str {
        OFFICIAL_VERSION
    }

    /// The glibc multiarch directory the build image's linker inputs live in,
    /// and the ELF machine number they must carry.
    fn linux_abi(self) -> Option<(&'static str, &'static str, u16)> {
        match self {
            Self::LinuxArm64 => Some(("/usr/lib/aarch64-linux-gnu", "ld-linux-aarch64.so.1", 183)),
            Self::LinuxX64 => Some(("/usr/lib/x86_64-linux-gnu", "ld-linux-x86-64.so.2", 62)),
            Self::MacArm64 => None,
        }
    }
}

pub struct Pin {
    pub target: Target,
    pub value: Value,
}

impl Pin {
    fn parse(target: Target, bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(bytes)?;
        ensure!(
            value["host_target"] == target.rust_target(),
            "compiler pin target mismatch"
        );
        let derived = value.get("compiler_patch").is_some();
        if derived {
            ensure!(
                target == Target::MacArm64
                    && value["roc_version"] == DERIVED_VERSION
                    && value["roc_semantic_version"] == SEMANTIC_VERSION
                    && value["roc_upstream_binary_sha256"] == UPSTREAM_MAC_SHA256
                    && value["roc_binary_sha256"] != value["roc_upstream_binary_sha256"],
                "unsupported derived compiler identity"
            );
            let patch = &value["compiler_patch"];
            ensure!(
                patch["kind"] == "glue-layouts-v1"
                    && patch["path"] == PATCH_PATH
                    && patch["sha256"] == REVIEWED_GLUE_PATCH_SHA256
                    && patch["provenance_path"] == PROVENANCE_PATH,
                "unsupported compiler patch"
            );
            hash_field(patch, "sha256")?;
            hash_field(patch, "provenance_sha256")?;
        } else {
            ensure!(
                value["roc_version"] == target.official_version()
                    && value.get("roc_semantic_version").is_none()
                    && value.get("roc_upstream_binary_sha256").is_none(),
                "unsupported compiler release or semantic override"
            );
            // Each official pin names the exact upstream bytes GitHub publishes
            // for this release, so editing a digest in the JSON cannot select
            // another compiler.
            if let Some((binary, archive)) = match target {
                Target::MacArm64 => None,
                Target::LinuxArm64 => Some((
                    "93d5397a18d52ff3e4357c886ce9ed9c434f9d1ed5b4bf3506adb8c3b102def5",
                    "51ae658f7dfaf16713d7610b6a421769e3c9f94740d222f7ea2a17e8dbb731ca",
                )),
                Target::LinuxX64 => Some((
                    "c0033dc4ec3b95624bdb26f672c98c3ddb2e581869781389b09e7d2861a01a22",
                    "c2ba90f59bedf0b3617c085f5aec7854cf5fe8127a7cdca6d0509c3525a73b78",
                )),
            } {
                ensure!(
                    value["roc_binary_sha256"] == binary
                        && value["roc_archive_sha256"] == archive
                        && value["roc_source_archive_sha256"]
                            == "d25cbd3f9cf012a08d734daf1c6d917b9d997e3943376103943109be01570b4d",
                    "official compiler must retain reviewed upstream inputs"
                );
            }
            if target == Target::MacArm64 {
                ensure!(
                    value["roc_binary_sha256"]
                        == "b4f197fde4836ab8ae19f8d427d38d721ade9bd43323ca793c7411a9f11d1cc6"
                        && value["roc_archive_sha256"]
                            == "fd302798ddb15356744384761a2c23b318880e96c052aad6966cfb34e226af8f"
                        && value["roc_source_archive_sha256"]
                            == "d25cbd3f9cf012a08d734daf1c6d917b9d997e3943376103943109be01570b4d"
                        && value["libsystem_sha256"]
                            == "4f96f1402e1950b1764ac6accd0d2b9c1ca197b7783caae5e838fd0a4b474028",
                    "official compiler must retain reviewed upstream inputs"
                );
            }
        }
        for field in ["roc_binary_sha256", "roc_archive_sha256"] {
            hash_field(&value, field)?;
        }
        if derived {
            ensure!(
                value["roc_archive_sha256"]
                    == "a9f206071511b9f659bdb70cc520a0825d9c8024bc40b922b8148ce886b67d77"
                    && value["roc_source_archive_sha256"]
                        == "45de9ca1b48741ecf610aac1c6849a6d873a4cbc2a93cb0efdd0425d216c2cb6"
                    && value["libsystem_sha256"]
                        == "4f96f1402e1950b1764ac6accd0d2b9c1ca197b7783caae5e838fd0a4b474028",
                "derived compiler must retain reviewed upstream inputs"
            );
        }
        let archive = value["roc_archive"]
            .as_str()
            .context("missing compiler archive")?;
        let suffix = match target {
            Target::MacArm64 => "macos_apple_silicon",
            Target::LinuxArm64 => "linux_arm64",
            Target::LinuxX64 => "linux_x86_64",
        };
        let version = if derived {
            SEMANTIC_VERSION
        } else {
            target.official_version()
        };
        let release = version
            .strip_prefix("nightly-")
            .context("official nightly version")?;
        ensure!(
            archive
                == format!(
                    "https://github.com/roc-lang/nightlies/releases/download/{version}/roc_nightly-{suffix}-{release}.tar.gz"
                ),
            "compiler archive does not match native target"
        );
        Ok(Self { target, value })
    }

    pub fn verified_compiler(&self, root: &Path) -> Result<PathBuf> {
        self.verify_derivation(root)?;
        let directory = root.join("../.toolchains");
        real_directory(&directory)?;
        self.verify_directory(&directory)?;
        directory
            .join("roc")
            .canonicalize()
            .context("compiler path")
    }

    fn verify_directory(&self, directory: &Path) -> Result<()> {
        self.verify_directory_hash(directory, hash_field(&self.value, "roc_binary_sha256")?)
    }

    fn verify_directory_hash(&self, directory: &Path, binary_hash: &str) -> Result<()> {
        real_directory(directory)?;
        verify_file(&directory.join("roc"), binary_hash, MAX_BINARY_BYTES)?;
        if self.target == Target::MacArm64 {
            for component in ["darwin", "darwin/usr", "darwin/usr/lib"] {
                real_directory(&directory.join(component))?;
            }
            verify_file(
                &directory.join("darwin/usr/lib/libSystem.tbd"),
                hash_field(&self.value, "libsystem_sha256")?,
                16 * 1024 * 1024,
            )?;
        }
        Ok(())
    }

    fn derived(&self) -> bool {
        self.value.get("compiler_patch").is_some()
    }

    /// ABI generators follow the reviewed compiler, independently of the host
    /// formatter. Both sources remain in the artifact's platform fingerprint.
    pub fn rust_glue_path(&self) -> &'static str {
        if self.derived() {
            "vendor/RustGlueSep5.roc"
        } else {
            "vendor/RustGlue.roc"
        }
    }

    fn upstream_hash(&self) -> Result<&str> {
        hash_field(&self.value, "roc_upstream_binary_sha256")
    }

    fn verify_derivation(&self, root: &Path) -> Result<()> {
        if !self.derived() {
            return Ok(());
        }
        for directory in ["tools", "tools/roc-compiler"] {
            real_directory(&root.join(directory))?;
        }
        let patch = &self.value["compiler_patch"];
        ensure!(
            patch["sha256"] == REVIEWED_GLUE_PATCH_SHA256,
            "compiler semantic identity requires the exact reviewed glue patch"
        );
        verify_file(
            &root.join(PATCH_PATH),
            hash_field(patch, "sha256")?,
            512 * 1024,
        )?;
        verify_file(
            &root.join(PROVENANCE_PATH),
            hash_field(patch, "provenance_sha256")?,
            64 * 1024,
        )?;
        let provenance: Value = serde_json::from_slice(&fs::read(root.join(PROVENANCE_PATH))?)?;
        for field in [
            "roc_version",
            "roc_binary_sha256",
            "roc_upstream_binary_sha256",
            "roc_source_archive_sha256",
        ] {
            ensure!(
                provenance[field] == self.value[field],
                "compiler provenance identity mismatch: {field}"
            );
        }
        ensure!(
            provenance["patch_sha256"] == patch["sha256"],
            "compiler provenance patch mismatch"
        );
        Ok(())
    }

    pub fn semantic_version(&self, root: &Path) -> Result<&'static str> {
        self.verify_derivation(root)?;
        Ok(if self.derived() {
            SEMANTIC_VERSION
        } else {
            self.target.official_version()
        })
    }
}

pub fn load(root: &Path) -> Result<Pin> {
    let target = Target::current()?;
    let path = root.join(target.pin_path());
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 16_384,
        "compiler pin must be a bounded regular file"
    );
    Pin::parse(target, &fs::read(path)?)
}

pub fn bootstrap(root: &Path) -> Result<()> {
    install(root, None)
}

pub fn install(root: &Path, candidate: Option<&Path>) -> Result<()> {
    let pin = load(root)?;
    install_pin(root, &pin, candidate)
}

fn install_pin(root: &Path, pin: &Pin, candidate: Option<&Path>) -> Result<()> {
    pin.verify_derivation(root)?;
    if let Some(candidate) = candidate {
        verify_file(
            candidate,
            hash_field(&pin.value, "roc_binary_sha256")?,
            MAX_BINARY_BYTES,
        )?;
        verify_executable_target(pin.target, candidate)?;
    }
    let directory = root.join("../.toolchains");
    if fs::symlink_metadata(&directory)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        if pin.derived() {
            ensure!(
                candidate.is_some(),
                "reviewed derived compiler required: run xtask bootstrap-compiler REVIEWED_BINARY"
            );
        }
        let temporary = tempfile::tempdir_in(root.parent().context("workspace parent")?)?;
        let archive = temporary.path().join("roc.tar.gz");
        run(
            root,
            Command::new("/usr/bin/curl")
                .args([
                    "--fail",
                    "--location",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "--max-time",
                    "180",
                    "--max-filesize",
                    "268435456",
                    "--output",
                ])
                .arg(&archive)
                .arg(pin.value["roc_archive"].as_str().context("archive URL")?),
        )?;
        verify_file(
            &archive,
            hash_field(&pin.value, "roc_archive_sha256")?,
            MAX_BINARY_BYTES,
        )?;
        let extracted = temporary.path().join("extracted");
        fs::create_dir(&extracted)?;
        run(
            root,
            Command::new("/usr/bin/tar")
                .arg("-xzf")
                .arg(&archive)
                .arg("-C")
                .arg(&extracted)
                .arg("--strip-components=1"),
        )?;
        if pin.derived() {
            pin.verify_directory_hash(&extracted, pin.upstream_hash()?)?;
            replace_upstream(pin, &extracted, candidate.context("reviewed compiler")?)?;
        } else {
            pin.verify_directory(&extracted)?;
        }
        ensure!(
            !directory.exists(),
            "toolchain directory appeared during bootstrap"
        );
        fs::rename(extracted, &directory)?;
        fs::File::open(directory.parent().context("compiler parent")?)?.sync_all()?;
    } else if pin.derived() && pin.verify_directory(&directory).is_err() {
        real_directory(&directory)?;
        pin.verify_directory_hash(&directory, pin.upstream_hash()?)?;
        replace_upstream(
            pin,
            &directory,
            candidate.context(
                "reviewed derived compiler required: run xtask bootstrap-compiler REVIEWED_BINARY",
            )?,
        )?;
    }
    pin.verified_compiler(root)?;
    println!(
        "Verified pinned Roc compiler: {} ({})",
        pin.value["roc_version"],
        pin.target.rust_target()
    );
    Ok(())
}

fn replace_upstream(pin: &Pin, directory: &Path, candidate: &Path) -> Result<()> {
    let expected = hash_field(&pin.value, "roc_binary_sha256")?;
    verify_file(candidate, expected, MAX_BINARY_BYTES)?;
    verify_executable_target(pin.target, candidate)?;
    pin.verify_directory_hash(directory, pin.upstream_hash()?)?;
    let staged = tempfile::NamedTempFile::new_in(directory)?;
    fs::copy(candidate, staged.path())?;
    verify_file(staged.path(), expected, MAX_BINARY_BYTES)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    staged.as_file().sync_all()?;
    // The workspace task lock serializes installers. Recheck the sole accepted
    // predecessor immediately before the atomic file replacement.
    pin.verify_directory_hash(directory, pin.upstream_hash()?)?;
    staged.persist(directory.join("roc"))?;
    fs::File::open(directory)?.sync_all()?;
    pin.verify_directory(directory)
}

/// Linker inputs every glibc target stages beside the host archive, plus the
/// target's own dynamic loader.
const LINUX_INPUTS: &[&str] = &[
    "Scrt1.o",
    "crti.o",
    "crtn.o",
    "libc.so.6",
    "libm.so.6",
    "libgcc_s.so.1",
];

fn validate_linux_elf(target: Target, bytes: &[u8]) -> Result<()> {
    let (_, _, machine) = target.linux_abi().context("not a Linux target")?;
    ensure!(
        bytes.len() >= 64
            && &bytes[..4] == b"\x7fELF"
            && bytes[4] == 2
            && bytes[5] == 1
            && u16::from_le_bytes([bytes[18], bytes[19]]) == machine,
        "native linker input must be little-endian ELF64 for {}",
        target.rust_target()
    );
    Ok(())
}

pub fn verify_executable_target(target: Target, executable: &Path) -> Result<()> {
    let bytes = fs::read(executable)?;
    match target {
        Target::LinuxArm64 | Target::LinuxX64 => validate_linux_elf(target, &bytes),
        Target::MacArm64 => {
            ensure!(
                bytes.len() >= 32
                    && bytes[..4] == [0xcf, 0xfa, 0xed, 0xfe]
                    && bytes[4..8] == [0x0c, 0, 0, 1],
                "native executable must be arm64 Mach-O"
            );
            Ok(())
        }
    }
}

pub fn stage_link_inputs(
    target: Target,
    stage: &Path,
    archive: &Path,
) -> Result<BTreeMap<String, String>> {
    let directory = stage.join("sdk/targets").join(target.roc_target());
    fs::create_dir_all(&directory)?;
    let mut hashes = BTreeMap::new();
    let host = fs::read(archive)?;
    ensure!(
        host.starts_with(b"!<arch>\n"),
        "native host is not a static archive"
    );
    fs::write(directory.join("libhost.a"), &host)?;
    hashes.insert(
        format!("native/{}/libhost.a", target.roc_target()),
        digest(&host),
    );
    if let Some((library, loader, _)) = target.linux_abi() {
        for name in LINUX_INPUTS.iter().copied().chain([loader]) {
            let path = format!("{library}/{name}");
            let canonical = Path::new(&path)
                .canonicalize()
                .with_context(|| format!("build image missing native linker input: {path}"))?;
            ensure!(
                canonical.starts_with(library) && fs::metadata(&canonical)?.is_file(),
                "native linker input outside reviewed system library directory"
            );
            let bytes = fs::read(&canonical)?;
            validate_linux_elf(target, &bytes)?;
            fs::write(directory.join(name), &bytes)?;
            hashes.insert(
                format!("native/{}/{name}", target.roc_target()),
                digest(&bytes),
            );
        }
    }
    Ok(hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_mac_upgrade_has_its_actual_semantic_identity_and_exact_upstream_bytes() {
        let bytes = include_bytes!("../../../toolchain.json");
        let pin = Pin::parse(Target::MacArm64, bytes).unwrap();
        assert!(!pin.derived());
        assert_eq!(pin.rust_glue_path(), "vendor/RustGlue.roc");
        assert_eq!(
            pin.semantic_version(Path::new("unused")).unwrap(),
            OFFICIAL_VERSION
        );
        let linux = Pin::parse(
            Target::LinuxArm64,
            include_bytes!("../../../toolchains/linux-aarch64.json"),
        )
        .unwrap();
        assert_eq!(
            linux.semantic_version(Path::new("unused")).unwrap(),
            OFFICIAL_VERSION
        );
        assert_eq!(linux.rust_glue_path(), "vendor/RustGlue.roc");
        let x64 = Pin::parse(
            Target::LinuxX64,
            include_bytes!("../../../toolchains/linux-x86_64.json"),
        )
        .unwrap();
        assert_eq!(
            x64.semantic_version(Path::new("unused")).unwrap(),
            OFFICIAL_VERSION
        );
        assert_eq!(x64.rust_glue_path(), "vendor/RustGlue.roc");
        let legacy = Pin::parse(
            Target::MacArm64,
            &serde_json::to_vec(&derived_pin_value()).unwrap(),
        )
        .unwrap();
        assert_eq!(legacy.rust_glue_path(), "vendor/RustGlueSep5.roc");
        for field in [
            "roc_binary_sha256",
            "roc_archive_sha256",
            "roc_source_archive_sha256",
            "libsystem_sha256",
        ] {
            let mut invalid = pin.value.clone();
            invalid[field] = "1".repeat(64).into();
            assert!(
                Pin::parse(Target::MacArm64, &serde_json::to_vec(&invalid).unwrap()).is_err(),
                "accepted altered {field}"
            );
        }
        let mut disguised = pin.value.clone();
        disguised["roc_semantic_version"] = SEMANTIC_VERSION.into();
        assert!(Pin::parse(Target::MacArm64, &serde_json::to_vec(&disguised).unwrap()).is_err());
    }

    fn derived_pin_value() -> Value {
        let mut value: Value =
            serde_json::from_slice(include_bytes!("../../../toolchain.json")).unwrap();
        value["roc_version"] = DERIVED_VERSION.into();
        value["roc_semantic_version"] = SEMANTIC_VERSION.into();
        value["roc_upstream_binary_sha256"] = UPSTREAM_MAC_SHA256.into();
        value["roc_archive"] = "https://github.com/roc-lang/nightlies/releases/download/nightly-2026-09-05-b195f5b/roc_nightly-macos_apple_silicon-2026-09-05-b195f5b.tar.gz".into();
        value["roc_archive_sha256"] =
            "a9f206071511b9f659bdb70cc520a0825d9c8024bc40b922b8148ce886b67d77".into();
        value["roc_source_archive_sha256"] =
            "45de9ca1b48741ecf610aac1c6849a6d873a4cbc2a93cb0efdd0425d216c2cb6".into();
        value["roc_binary_sha256"] = "1".repeat(64).into();
        value["compiler_patch"] = serde_json::json!({
            "kind": "glue-layouts-v1",
            "path": PATCH_PATH,
            "sha256": REVIEWED_GLUE_PATCH_SHA256,
            "provenance_path": PROVENANCE_PATH,
            "provenance_sha256": "3".repeat(64),
        });
        value
    }

    fn fixture_provenance(root: &Path, pin: &mut Pin) {
        fs::create_dir_all(root.join("tools/roc-compiler")).unwrap();
        let patch = include_bytes!("../../../tools/roc-compiler/glue-layouts.patch");
        fs::write(root.join(PATCH_PATH), patch).unwrap();
        pin.value["compiler_patch"]["sha256"] = digest(patch)[7..].into();
        let provenance = serde_json::json!({
            "roc_version": pin.value["roc_version"],
            "roc_binary_sha256": pin.value["roc_binary_sha256"],
            "roc_upstream_binary_sha256": pin.value["roc_upstream_binary_sha256"],
            "roc_source_archive_sha256": pin.value["roc_source_archive_sha256"],
            "patch_sha256": pin.value["compiler_patch"]["sha256"],
        });
        let bytes = serde_json::to_vec(&provenance).unwrap();
        fs::write(root.join(PROVENANCE_PATH), &bytes).unwrap();
        pin.value["compiler_patch"]["provenance_sha256"] = digest(&bytes)[7..].into();
    }

    fn installation_fixture() -> (tempfile::TempDir, PathBuf, Pin, PathBuf) {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().join("platform");
        let directory = workspace.path().join(".toolchains");
        fs::create_dir_all(directory.join("darwin/usr/lib")).unwrap();
        let mut pin = Pin::parse(
            Target::MacArm64,
            &serde_json::to_vec(&derived_pin_value()).unwrap(),
        )
        .unwrap();
        // Substitute small byte fixtures after parser tests independently prove
        // production pins accept only the exact reviewed upstream identities.
        let upstream = b"reviewed upstream compiler";
        fs::write(directory.join("roc"), upstream).unwrap();
        pin.value["roc_upstream_binary_sha256"] = digest(upstream)[7..].into();
        let stub = b"reviewed linker stub";
        fs::write(directory.join("darwin/usr/lib/libSystem.tbd"), stub).unwrap();
        pin.value["libsystem_sha256"] = digest(stub)[7..].into();
        let mut executable = [0_u8; 32];
        executable[..8].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1]);
        let candidate = workspace.path().join("candidate");
        fs::write(&candidate, executable).unwrap();
        pin.value["roc_binary_sha256"] = digest(&executable)[7..].into();
        fixture_provenance(&root, &mut pin);
        (workspace, root, pin, candidate)
    }

    #[test]
    fn derived_semantic_override_requires_the_reviewed_identity_and_base_inputs() {
        let value = derived_pin_value();
        Pin::parse(Target::MacArm64, &serde_json::to_vec(&value).unwrap()).unwrap();
        for (field, replacement) in [
            ("roc_version", "nightly-2026-09-10-a670e34"),
            ("roc_semantic_version", "arbitrary-checker"),
            ("roc_upstream_binary_sha256", &"4".repeat(64)),
            ("roc_archive_sha256", &"4".repeat(64)),
            ("roc_source_archive_sha256", &"4".repeat(64)),
            ("libsystem_sha256", &"4".repeat(64)),
            ("roc_binary_sha256", UPSTREAM_MAC_SHA256),
        ] {
            let mut invalid = value.clone();
            invalid[field] = replacement.into();
            assert!(
                Pin::parse(Target::MacArm64, &serde_json::to_vec(&invalid).unwrap()).is_err(),
                "accepted invalid {field}"
            );
        }
        for (field, replacement) in [
            ("kind", "checker-rewrite"),
            ("path", "../../other.patch"),
            ("provenance_path", "other.json"),
            ("sha256", "malformed"),
            ("sha256", &"2".repeat(64)),
            ("provenance_sha256", "malformed"),
        ] {
            let mut invalid = value.clone();
            invalid["compiler_patch"][field] = replacement.into();
            assert!(Pin::parse(Target::MacArm64, &serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        for field in [
            "compiler_patch",
            "roc_semantic_version",
            "roc_upstream_binary_sha256",
        ] {
            let mut invalid = value.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(Pin::parse(Target::MacArm64, &serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut linux = value;
        linux["host_target"] = "aarch64-unknown-linux-gnu".into();
        assert!(Pin::parse(Target::LinuxArm64, &serde_json::to_vec(&linux).unwrap()).is_err());

        let mut disguised = derived_pin_value();
        disguised["roc_version"] = SEMANTIC_VERSION.into();
        disguised.as_object_mut().unwrap().remove("compiler_patch");
        assert!(Pin::parse(Target::MacArm64, &serde_json::to_vec(&disguised).unwrap()).is_err());
    }

    #[test]
    fn derived_install_is_explicit_atomic_and_idempotent() {
        let (_workspace, root, pin, candidate) = installation_fixture();
        let installed = root.join("../.toolchains/roc");
        let original = fs::read(&installed).unwrap();
        assert!(install_pin(&root, &pin, None).is_err());
        assert_eq!(fs::read(&installed).unwrap(), original);
        install_pin(&root, &pin, Some(&candidate)).unwrap();
        assert_eq!(fs::read(&installed).unwrap(), fs::read(&candidate).unwrap());
        install_pin(&root, &pin, None).unwrap();
        assert_eq!(pin.semantic_version(&root).unwrap(), SEMANTIC_VERSION);
        fs::write(&candidate, b"unreviewed replacement").unwrap();
        assert!(install_pin(&root, &pin, Some(&candidate)).is_err());
        assert_ne!(fs::read(&installed).unwrap(), fs::read(&candidate).unwrap());
    }

    #[test]
    fn derived_install_never_replaces_unrelated_bytes_or_damaged_linker_inputs() {
        let (_workspace, root, pin, candidate) = installation_fixture();
        let installed = root.join("../.toolchains/roc");
        let original = fs::read(&installed).unwrap();
        fs::write(&installed, b"unrelated compiler").unwrap();
        assert!(install_pin(&root, &pin, Some(&candidate)).is_err());
        assert_eq!(fs::read(&installed).unwrap(), b"unrelated compiler");
        fs::write(&installed, &original).unwrap();
        fs::write(
            root.join("../.toolchains/darwin/usr/lib/libSystem.tbd"),
            b"altered",
        )
        .unwrap();
        assert!(install_pin(&root, &pin, Some(&candidate)).is_err());
        assert_eq!(fs::read(&installed).unwrap(), original);
    }

    #[test]
    fn reviewed_digest_does_not_replace_native_target_validation() {
        let (_workspace, root, mut pin, candidate) = installation_fixture();
        let installed = root.join("../.toolchains/roc");
        let original = fs::read(&installed).unwrap();
        let other_target = [0_u8; 32];
        fs::write(&candidate, other_target).unwrap();
        pin.value["roc_binary_sha256"] = digest(&other_target)[7..].into();
        fixture_provenance(&root, &mut pin);
        assert!(install_pin(&root, &pin, Some(&candidate)).is_err());
        assert_eq!(fs::read(&installed).unwrap(), original);
    }

    #[test]
    fn semantic_override_requires_intact_and_consistent_patch_provenance() {
        let (_workspace, root, mut pin, _candidate) = installation_fixture();
        assert_eq!(pin.semantic_version(&root).unwrap(), SEMANTIC_VERSION);
        fs::write(root.join(PATCH_PATH), b"changed checker code").unwrap();
        assert!(pin.semantic_version(&root).is_err());
        pin.value["compiler_patch"]["sha256"] = digest(b"changed checker code")[7..].into();
        assert!(pin.semantic_version(&root).is_err());
        fixture_provenance(&root, &mut pin);
        let mut provenance: Value =
            serde_json::from_slice(&fs::read(root.join(PROVENANCE_PATH)).unwrap()).unwrap();
        provenance["roc_binary_sha256"] = "9".repeat(64).into();
        let bytes = serde_json::to_vec(&provenance).unwrap();
        fs::write(root.join(PROVENANCE_PATH), &bytes).unwrap();
        pin.value["compiler_patch"]["provenance_sha256"] = digest(&bytes)[7..].into();
        assert!(pin.semantic_version(&root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn derived_installer_rejects_symlinked_candidates_and_linker_inputs() {
        let (workspace, root, pin, candidate) = installation_fixture();
        let alias = workspace.path().join("candidate-alias");
        std::os::unix::fs::symlink(&candidate, &alias).unwrap();
        assert!(install_pin(&root, &pin, Some(&alias)).is_err());
        let stub = root.join("../.toolchains/darwin/usr/lib/libSystem.tbd");
        let moved = workspace.path().join("stub");
        fs::rename(&stub, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &stub).unwrap();
        assert!(install_pin(&root, &pin, Some(&candidate)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn derived_installer_rejects_symlinked_input_directories() {
        for relative in [
            "../.toolchains",
            "../.toolchains/darwin/usr",
            "tools/roc-compiler",
        ] {
            let (workspace, root, pin, candidate) = installation_fixture();
            let directory = root.join(relative);
            let moved = workspace.path().join("redirected-input");
            fs::rename(&directory, &moved).unwrap();
            std::os::unix::fs::symlink(&moved, &directory).unwrap();
            assert!(
                install_pin(&root, &pin, Some(&candidate)).is_err(),
                "accepted symlinked {relative}"
            );
        }
    }

    #[test]
    fn only_reviewed_native_targets_are_supported() {
        assert_eq!(
            Target::detect("linux", "aarch64", "gnu").unwrap(),
            Target::LinuxArm64
        );
        assert_eq!(
            Target::detect("linux", "x86_64", "gnu").unwrap(),
            Target::LinuxX64
        );
        for (os, arch, abi) in [
            ("linux", "x86_64", "musl"),
            ("macos", "x86_64", ""),
            ("linux", "aarch64", "musl"),
            ("windows", "aarch64", "msvc"),
        ] {
            assert!(Target::detect(os, arch, abi).is_err());
        }
    }

    #[test]
    fn pins_bind_archive_and_compiler_to_the_native_target() {
        let arm = include_bytes!("../../../toolchains/linux-aarch64.json");
        let x64 = include_bytes!("../../../toolchains/linux-x86_64.json");
        Pin::parse(Target::LinuxArm64, arm).unwrap();
        Pin::parse(Target::LinuxX64, x64).unwrap();
        assert!(Pin::parse(Target::MacArm64, arm).is_err());
        assert!(Pin::parse(Target::LinuxX64, arm).is_err());
        assert!(Pin::parse(Target::LinuxArm64, x64).is_err());
        for (target, bytes) in [(Target::LinuxArm64, &arm[..]), (Target::LinuxX64, &x64[..])] {
            let pin: Value = serde_json::from_slice(bytes).unwrap();
            for field in [
                "roc_binary_sha256",
                "roc_archive_sha256",
                "roc_source_archive_sha256",
            ] {
                let mut value = pin.clone();
                value[field] = Value::String("1".repeat(64));
                assert!(
                    Pin::parse(target, &serde_json::to_vec(&value).unwrap()).is_err(),
                    "accepted altered {field}"
                );
            }
            let mut value = pin.clone();
            value["roc_binary_sha256"] = Value::String("A".repeat(64));
            assert!(Pin::parse(target, &serde_json::to_vec(&value).unwrap()).is_err());
            let mut value = pin;
            value["roc_version"] = SEMANTIC_VERSION.into();
            assert!(Pin::parse(target, &serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn linker_scripts_and_wrong_architectures_are_not_link_inputs() {
        for target in [Target::LinuxArm64, Target::LinuxX64] {
            assert!(validate_linux_elf(target, b"GROUP (/tmp/evil.so)").is_err());
        }
        let mut elf = [0_u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18] = 183;
        validate_linux_elf(Target::LinuxArm64, &elf).unwrap();
        assert!(validate_linux_elf(Target::LinuxX64, &elf).is_err());
        elf[18] = 62;
        validate_linux_elf(Target::LinuxX64, &elf).unwrap();
        assert!(validate_linux_elf(Target::LinuxArm64, &elf).is_err());
        assert!(validate_linux_elf(Target::MacArm64, &elf).is_err());
    }

    #[test]
    fn bootstrap_never_replaces_an_existing_wrong_host_compiler() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().join("platform");
        let target = Target::current().unwrap();
        let pin = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(target.pin_path());
        fs::create_dir_all(root.join("toolchains")).unwrap();
        fs::copy(pin, root.join(target.pin_path())).unwrap();
        let directory = workspace.path().join(".toolchains");
        fs::create_dir(&directory).unwrap();
        let existing = directory.join("roc");
        fs::write(&existing, b"compiler for another host").unwrap();
        assert!(bootstrap(&root).is_err());
        assert_eq!(fs::read(&existing).unwrap(), b"compiler for another host");
    }

    #[cfg(unix)]
    #[test]
    fn compiler_symlinks_are_not_accepted_even_with_matching_bytes() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().join("platform");
        fs::create_dir(&root).unwrap();
        let directory = workspace.path().join(".toolchains");
        fs::create_dir(&directory).unwrap();
        let candidate = workspace.path().join("other-compiler");
        fs::write(&candidate, b"compiler").unwrap();
        std::os::unix::fs::symlink(&candidate, directory.join("roc")).unwrap();
        let mut pin = Pin::parse(
            Target::LinuxArm64,
            include_bytes!("../../../toolchains/linux-aarch64.json"),
        )
        .unwrap();
        pin.value["roc_binary_sha256"] = Value::String(digest(b"compiler")[7..].to_owned());
        assert!(pin.verified_compiler(&root).is_err());
    }
}
