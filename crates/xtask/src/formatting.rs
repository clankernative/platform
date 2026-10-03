//! A separately pinned native formatter for authored Roc sources. Application
//! compilation and admission use the pinned compiler, which may carry the
//! independently reviewed reflection backport with unchanged language semantics.

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Write,
    Check,
}

#[derive(Deserialize)]
struct CompilerPin {
    roc_version: String,
    roc_binary_sha256: String,
    patch_sha256: String,
}

const PIN_PATH: &str = "tools/roc-formatter/toolchain.json";
const PATCH_PATH: &str = "tools/roc-formatter/associated-method-spacing.patch";
const BINARY_PATH: &str = "../.toolchains/roc-fmt-day2";

pub fn run(root: &Path, mode: Mode) -> Result<usize> {
    run_selected(root, mode)
}

pub fn reports(root: &Path, mode: Mode) -> Result<usize> {
    run_selected(root, mode)
}

fn run_selected(root: &Path, mode: Mode) -> Result<usize> {
    ensure!(
        fs::symlink_metadata(root)?.file_type().is_dir(),
        "formatter platform root must be a real directory"
    );
    let root = root.canonicalize()?;
    let compiler = checked_compiler(&root)?;
    let sources = sources(&root)?;
    ensure!(!sources.is_empty(), "no authored Roc sources selected");
    // Admit the entire file set before any writes. Pass files, not directories,
    // so native recursive discovery cannot include excluded build outputs.
    for source in &sources {
        super::run(&root, &mut command(&root, &compiler, source, mode))
            .with_context(|| format!("Roc formatter {mode:?} failed for {}", source.display()))?;
    }
    Ok(sources.len())
}

fn checked_compiler(root: &Path) -> Result<PathBuf> {
    let path = root.join(PIN_PATH);
    ensure!(
        fs::symlink_metadata(&path)?.file_type().is_file(),
        "Roc formatter pin must be a regular file"
    );
    // Bootstrap verifies the additional source/build provenance. Execution reads
    // only these required identity fields; serde intentionally permits the rest.
    let pin: CompilerPin = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        !pin.roc_version.is_empty()
            && pin.roc_version.len() <= 128
            && pin
                .roc_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)),
        "invalid Roc formatter version pin"
    );
    for (name, digest) in [
        ("compiler", &pin.roc_binary_sha256),
        ("patch", &pin.patch_sha256),
    ] {
        ensure!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid Roc formatter {name} pin"
        );
    }
    let patch = root.join(PATCH_PATH);
    ensure!(
        fs::symlink_metadata(&patch)?.file_type().is_file(),
        "Roc formatter patch must be a regular file"
    );
    ensure!(
        day2::digest(&fs::read(patch)?) == format!("sha256:{}", pin.patch_sha256),
        "Roc formatter patch digest mismatch"
    );
    let compiler = root.join(BINARY_PATH);
    ensure!(
        fs::symlink_metadata(&compiler)
            .context("reviewed Roc formatter unavailable; run xtask bootstrap-formatter REVIEWED_BINARY (see tools/roc-formatter/README.md)")?
            .file_type().is_file(),
        "Roc formatter compiler must be a regular file"
    );
    ensure!(
        day2::digest(&fs::read(&compiler)?) == format!("sha256:{}", pin.roc_binary_sha256),
        "Roc formatter compiler digest mismatch"
    );
    compiler
        .canonicalize()
        .context("Roc formatter compiler path")
}

fn command(root: &Path, compiler: &Path, source: &Path, mode: Mode) -> Command {
    let mut command = Command::new(compiler);
    command
        .current_dir(root)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .arg("fmt");
    if mode == Mode::Check {
        command.arg("--check");
    }
    command.arg(source);
    command
}

fn sources(root: &Path) -> Result<Vec<PathBuf>> {
    ensure!(
        fs::symlink_metadata(root.join("examples"))?
            .file_type()
            .is_dir(),
        "Roc example source parent must be a real directory"
    );
    let mut files = Vec::new();
    let mut entries = 0;
    let roots = [
        root.join("sdk"),
        root.join("tools"),
        root.join("fixtures"),
        root.join("cli"),
        root.join("ops"),
        root.join("infra"),
        root.join("examples/reports"),
        root.join("examples/app-ownership"),
        root.join("examples/notifications"),
    ];
    for source in roots {
        collect(&source, 0, &mut entries, &mut files)
            .with_context(|| format!("collect Roc formatter sources from {}", source.display()))?;
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn excluded_directory(name: &std::ffi::OsStr) -> bool {
    [
        ".git",
        ".cache",
        ".state",
        "artifacts",
        "target",
        "vendor",
        "generated",
        "node_modules",
    ]
    .iter()
    .any(|excluded| name == *excluded)
}

fn collect(
    directory: &Path,
    depth: usize,
    entries: &mut usize,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    ensure!(depth <= 32, "Roc formatter source depth budget");
    ensure!(
        fs::symlink_metadata(directory)?.file_type().is_dir(),
        "Roc formatter source must be a real directory"
    );
    let mut children = Vec::new();
    for child in fs::read_dir(directory)? {
        *entries += 1;
        ensure!(*entries <= 16_384, "Roc formatter source entry budget");
        children.push(child?);
    }
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let kind = child.file_type()?;
        ensure!(
            kind.is_dir() || kind.is_file(),
            "Roc formatter rejects symlinks and special files: {}",
            child.path().display()
        );
        if kind.is_dir() {
            if !excluded_directory(&child.file_name()) {
                collect(&child.path(), depth + 1, entries, files)?;
            }
        } else if child.path().extension().is_some_and(|value| value == "roc") {
            ensure!(
                child.metadata()?.len() <= 2_000_000 && files.len() < 4_096,
                "Roc formatter source file budget"
            );
            files.push(child.path());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> Result<tempfile::TempDir> {
        let directory = tempfile::tempdir()?;
        for path in [
            "platform/sdk",
            "platform/tools",
            "platform/fixtures",
            "platform/cli",
            "platform/ops",
            "platform/infra",
            "platform/examples/reports",
            "platform/examples/app-ownership",
            "platform/examples/notifications",
        ] {
            fs::create_dir_all(directory.path().join(path))?;
        }
        Ok(directory)
    }

    fn file(directory: &Path, path: &str) -> Result<()> {
        let path = directory.join(path);
        fs::create_dir_all(path.parent().context("fixture parent")?)?;
        fs::write(path, "Value :: [].{}\n")?;
        Ok(())
    }

    fn formatter(root: &Path) -> Result<serde_json::Value> {
        fs::create_dir_all(root.join("../.toolchains"))?;
        fs::create_dir_all(root.join("tools/roc-formatter"))?;
        fs::write(root.join(BINARY_PATH), "not an executable")?;
        fs::write(root.join(PATCH_PATH), "reviewed native formatter patch")?;
        let sha = |path: &str| -> Result<String> {
            Ok(day2::digest(&fs::read(root.join(path))?)
                .strip_prefix("sha256:")
                .context("digest")?
                .to_owned())
        };
        let pin = serde_json::json!({
            "roc_version": "nightly-2026-09-05-b195f5b",
            "roc_binary_sha256": sha(BINARY_PATH)?,
            "patch_sha256": sha(PATCH_PATH)?,
            "zig_version": "0.16.0",
            "build_args": ["roc"],
        });
        fs::write(root.join(PIN_PATH), serde_json::to_vec(&pin)?)?;
        Ok(pin)
    }

    #[test]
    fn selects_authored_sources_and_probes_in_stable_order_without_outputs() -> Result<()> {
        let workspace = workspace()?;
        let selected = [
            "platform/examples/app-ownership/App.roc",
            "platform/examples/notifications/App.roc",
            "platform/examples/reports/commands/analyze/AnalyzeReport.roc",
            "platform/examples/reports/storage/Models.roc",
            "platform/fixtures/command-target-adversaries/commands/submit/SubmitReport.roc",
            "platform/fixtures/row-authority-web-conformance/pages/Routes.roc",
            "platform/sdk/data/pagination/Cursor.roc",
            "platform/tools/SchemaGlue.roc",
        ];
        for path in selected.into_iter().rev() {
            file(workspace.path(), path)?;
        }
        for path in [
            "platform/sdk/README.md",
            "platform/vendor/RustGlue.roc",
            "platform/artifacts/app/App.roc",
            "platform/examples/reports/ui/pages/directory.html",
            "platform/examples/reports/.git/hooks/Ignored.roc",
            "platform/examples/reports/generated/Inputs.roc",
            "platform/examples/reports/artifacts/Worker.roc",
            "platform/examples/reports/target/Generated.roc",
            "platform/examples/reports/vendor/Dependency.roc",
            "platform/examples/reports/.state/Trace.roc",
            "platform/examples/reports/node_modules/Dependency.roc",
        ] {
            file(workspace.path(), path)?;
        }
        let actual = sources(&workspace.path().join("platform"))?;
        let expected = selected.map(|path| workspace.path().join(path));
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn required_workspace_roots_cannot_be_silently_omitted() -> Result<()> {
        let workspace = workspace()?;
        fs::remove_dir(workspace.path().join("platform/examples/reports"))?;
        assert!(sources(&workspace.path().join("platform")).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_application_parent() -> Result<()> {
        use std::os::unix::fs::symlink;
        let workspace = workspace()?;
        fs::rename(
            workspace.path().join("platform/examples"),
            workspace.path().join("elsewhere"),
        )?;
        symlink("../elsewhere", workspace.path().join("platform/examples"))?;
        assert!(sources(&workspace.path().join("platform")).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_source_symlinks_special_files_and_symlinked_roots() -> Result<()> {
        use std::os::unix::{fs::symlink, net::UnixListener};
        let workspace = workspace()?;
        let root = workspace.path().join("platform");
        let link = root.join("sdk/Linked.roc");
        symlink("../examples/reports/storage/Models.roc", &link)?;
        assert!(sources(&root).is_err());
        fs::remove_file(&link)?;
        let socket = root.join("sdk/socket");
        let listener = UnixListener::bind(&socket)?;
        assert!(sources(&root).is_err());
        drop(listener);
        fs::remove_file(socket)?;
        fs::remove_dir(workspace.path().join("platform/examples/reports"))?;
        symlink(
            "../fixtures",
            workspace.path().join("platform/examples/reports"),
        )?;
        assert!(sources(&root).is_err());
        Ok(())
    }

    #[test]
    fn checks_the_compiler_pin_before_any_formatter_execution() -> Result<()> {
        let workspace = workspace()?;
        let root = workspace.path().join("platform");
        let pin = formatter(&root)?;
        let compiler = root.join(BINARY_PATH);
        assert_eq!(checked_compiler(&root)?, compiler.canonicalize()?);
        let mut incorrect = pin.clone();
        incorrect["roc_binary_sha256"] = "0".repeat(64).into();
        fs::write(root.join(PIN_PATH), serde_json::to_vec(&incorrect)?)?;
        assert!(
            run(&root, Mode::Write)
                .unwrap_err()
                .to_string()
                .contains("compiler digest mismatch")
        );
        fs::write(root.join(PIN_PATH), serde_json::to_vec(&pin)?)?;
        assert_eq!(checked_compiler(&root)?, compiler.canonicalize()?);
        Ok(())
    }

    #[test]
    fn rejects_invalid_required_pins_and_modified_patch_before_execution() -> Result<()> {
        let workspace = workspace()?;
        let root = workspace.path().join("platform");
        let pin = formatter(&root)?;
        file(workspace.path(), "platform/sdk/Unchanged.roc")?;
        let source = root.join("sdk/Unchanged.roc");
        let original = fs::read(&source)?;
        for field in ["roc_version", "roc_binary_sha256", "patch_sha256"] {
            let mut missing = pin.clone();
            missing.as_object_mut().context("pin object")?.remove(field);
            fs::write(root.join(PIN_PATH), serde_json::to_vec(&missing)?)?;
            assert!(checked_compiler(&root).is_err(), "missing {field}");
        }
        for field in ["roc_binary_sha256", "patch_sha256"] {
            for invalid in ["f".repeat(63), "A".repeat(64), "g".repeat(64)] {
                let mut invalid_pin = pin.clone();
                invalid_pin[field] = invalid.into();
                fs::write(root.join(PIN_PATH), serde_json::to_vec(&invalid_pin)?)?;
                assert!(
                    run(&root, Mode::Write)
                        .unwrap_err()
                        .to_string()
                        .contains("invalid Roc formatter"),
                    "invalid {field}"
                );
            }
        }
        for invalid in ["", "nightly\n", "nightly/version"] {
            let mut invalid_pin = pin.clone();
            invalid_pin["roc_version"] = invalid.into();
            fs::write(root.join(PIN_PATH), serde_json::to_vec(&invalid_pin)?)?;
            assert!(checked_compiler(&root).is_err());
        }
        fs::write(root.join(PIN_PATH), serde_json::to_vec(&pin)?)?;
        fs::write(root.join(PATCH_PATH), "unreviewed change")?;
        assert!(
            run(&root, Mode::Write)
                .unwrap_err()
                .to_string()
                .contains("patch digest mismatch")
        );
        assert_eq!(fs::read(source)?, original);
        Ok(())
    }

    #[test]
    fn missing_patched_formatter_never_falls_back_to_semantic_compiler() -> Result<()> {
        let workspace = workspace()?;
        let root = workspace.path().join("platform");
        formatter(&root)?;
        fs::rename(root.join(BINARY_PATH), root.join("../.toolchains/roc"))?;
        assert!(checked_compiler(&root).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_formatter_pin_patch_and_binary() -> Result<()> {
        use std::os::unix::fs::symlink;
        let workspace = workspace()?;
        let root = workspace.path().join("platform");
        formatter(&root)?;
        for path in [PIN_PATH, PATCH_PATH, BINARY_PATH] {
            let path = root.join(path);
            let backup = path.with_extension("original");
            fs::rename(&path, &backup)?;
            symlink(&backup, &path)?;
            assert!(
                checked_compiler(&root)
                    .unwrap_err()
                    .to_string()
                    .contains("must be a regular file")
            );
            fs::remove_file(&path)?;
            fs::rename(backup, path)?;
        }
        assert!(checked_compiler(&root).is_ok());
        Ok(())
    }

    #[test]
    #[ignore = "requires bootstrap-formatter"]
    fn formatter_native_spacing_width_check_idempotence_and_parse_failure() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let compiler = checked_compiler(&root)?;
        let temporary = tempfile::tempdir()?;
        let fixtures = [
            (
                "Wide.roc",
                concat!(
                    "CommandDef(input, output, input_fields, output_fields) :: { ",
                    "input_witness : (input -> input), output_witness : (output -> output), ",
                    "handler : (Context, input -> Tx(output)), ",
                    "contract : Contract(input, output, input_fields, output_fields), ",
                    "execution : Execution(input), verification : Verification(input, output) }.{}\n",
                ),
                concat!(
                    "CommandDef(input, output, input_fields, output_fields) :: {\n",
                    "\tinput_witness : (input -> input),\n",
                    "\toutput_witness : (output -> output),\n",
                    "\thandler : (Context, input -> Tx(output)),\n",
                    "\tcontract : Contract(input, output, input_fields, output_fields),\n",
                    "\texecution : Execution(input),\n",
                    "\tverification : Verification(input, output),\n",
                    "}.{}\n",
                ),
            ),
            (
                "Typed.roc",
                concat!(
                    "Typed :: [].{\n",
                    "\tfirst : U64 -> U64\n",
                    "\tfirst = |value| value\n",
                    "\tsecond : U64 -> U64\n",
                    "\tsecond = |value| value\n",
                    "}\n",
                ),
                concat!(
                    "Typed :: [].{\n",
                    "\tfirst : U64 -> U64\n",
                    "\tfirst = |value| value\n",
                    "\n",
                    "\tsecond : U64 -> U64\n",
                    "\tsecond = |value| value\n",
                    "}\n",
                ),
            ),
            (
                "Commented.roc",
                concat!(
                    "Commented :: [].{\n",
                    "\tfirst = || 1\n",
                    "\t# Keep this comment with the second helper.\n",
                    "\tsecond = || 2\n",
                    "}\n",
                ),
                concat!(
                    "Commented :: [].{\n",
                    "\tfirst = || 1\n",
                    "\n",
                    "\t# Keep this comment with the second helper.\n",
                    "\tsecond = || 2\n",
                    "}\n",
                ),
            ),
        ];
        for (name, original, expected) in fixtures {
            let source = temporary.path().join(name);
            fs::write(&source, original)?;
            assert!(
                super::super::run(&root, &mut command(&root, &compiler, &source, Mode::Check))
                    .is_err(),
                "compact definitions or overlong code must fail --check: {name}"
            );
            assert_eq!(fs::read(&source)?, original.as_bytes(), "{name}");
            super::super::run(&root, &mut command(&root, &compiler, &source, Mode::Write))?;
            assert_eq!(fs::read_to_string(&source)?, expected, "{name}");
            super::super::run(&root, &mut command(&root, &compiler, &source, Mode::Check))?;
            super::super::run(&root, &mut command(&root, &compiler, &source, Mode::Write))?;
            assert_eq!(fs::read_to_string(&source)?, expected, "{name}");
        }

        let pin: CompilerPin = serde_json::from_slice(&fs::read(root.join(PIN_PATH))?)?;
        let header = format!("package [Typed] {{ roc: \"{}\" }}\n", pin.roc_version);
        let source = temporary.path().join("main.roc");
        fs::write(&source, &header)?;
        for mode in [Mode::Check, Mode::Write, Mode::Check] {
            super::super::run(&root, &mut command(&root, &compiler, &source, mode))?;
            assert_eq!(fs::read_to_string(&source)?, header);
        }

        let malformed = "Broken :: [].{\n\tfirst = |value| {\n";
        let source = temporary.path().join("Broken.roc");
        fs::write(&source, malformed)?;
        for mode in [Mode::Check, Mode::Write] {
            assert!(
                super::super::run(&root, &mut command(&root, &compiler, &source, mode)).is_err()
            );
            assert_eq!(fs::read_to_string(&source)?, malformed);
        }
        Ok(())
    }

    #[test]
    fn check_mode_passes_native_check_flag_without_formatting_directories() {
        let root = Path::new("/workspace/platform");
        let compiler = Path::new("/workspace/.toolchains/roc-fmt-day2");
        let source = root.join("sdk/data/Tx.roc");
        for (mode, flags) in [
            (Mode::Check, vec!["fmt", "--check"]),
            (Mode::Write, vec!["fmt"]),
        ] {
            let command = command(root, compiler, &source, mode);
            let expected: Vec<std::ffi::OsString> = flags
                .into_iter()
                .map(Into::into)
                .chain(std::iter::once(source.clone().into_os_string()))
                .collect();
            assert_eq!(command.get_program(), compiler);
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                expected
                    .iter()
                    .map(|value| value.as_os_str())
                    .collect::<Vec<_>>()
            );
        }
    }
}
