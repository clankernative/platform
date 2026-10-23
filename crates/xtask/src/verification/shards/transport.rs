//! File allowlists for the current run's prepared compiler outputs. No compiler
//! scratch, runtime result or private build spool belongs in these hand-offs.
use super::{BINARIES, BUILD_CACHE, PREPARED, Prepared};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

const OUTPUT: &str = "/tmp/day2-verification-transport";
const GROUPS: [&str; 3] = ["workspace-day2", "workspace-control", "workspace-other"];
const MAX_FILES: usize = 100_000;

#[derive(Default, Serialize)]
struct Files {
    entries: BTreeSet<PathBuf>,
    bytes: u64,
}

impl Files {
    fn add(&mut self, root: &Path, relative: &Path, depth: usize) -> Result<()> {
        ensure!(
            depth <= 32
                && !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|part| matches!(part, Component::Normal(_))),
            "transport path must stay within the workspace"
        );
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            (metadata.is_file() || metadata.is_dir()) && path.canonicalize()? == path,
            "transport allows only regular files and directories without symlink ancestors"
        );
        if !self.entries.insert(relative.into()) {
            return Ok(());
        }
        ensure!(
            self.entries.len() <= MAX_FILES,
            "transport file inventory exhausted"
        );
        if metadata.is_file() {
            self.bytes = self
                .bytes
                .checked_add(metadata.len())
                .context("transport byte overflow")?;
        } else {
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                self.add(root, &relative.join(entry.file_name()), depth + 1)?;
            }
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        for path in &self.entries {
            let path = path.to_str().context("UTF-8 transport path required")?;
            ensure!(!path.as_bytes().contains(&0), "NUL transport path");
            output.extend_from_slice(path.as_bytes());
            output.push(0);
        }
        Ok(output)
    }
}

fn grouped_outputs(prepared: &Prepared, group: &str) -> Result<BTreeSet<PathBuf>> {
    ensure!(GROUPS.contains(&group), "unknown binary transport group");
    Ok(prepared
        .binaries
        .iter()
        .chain(&prepared.programs)
        .filter(|binary| super::selected(&binary.package, group))
        .map(|binary| binary.executable.clone())
        .collect())
}

fn add_outputs(root: &Path, files: &mut Files, outputs: &BTreeSet<PathBuf>) -> Result<()> {
    for output in outputs {
        files.add(root, output, 0)?;
    }
    Ok(())
}

fn add_auxiliaries(root: &Path, files: &mut Files, prepared: &Prepared) -> Result<()> {
    for auxiliary in &prepared.auxiliaries {
        files.add(root, &auxiliary.executable, 0)?;
        files.add(
            root,
            &Path::new(crate::bazel::TESTS).join(&auxiliary.target),
            0,
        )?;
    }
    Ok(())
}

fn add_fixtures(root: &Path, files: &mut Files, prepared: &Prepared) -> Result<()> {
    for path in super::fixtures(root, prepared)?.values() {
        files.add(root, path.strip_prefix(root)?, 0)?;
    }
    Ok(())
}

pub(in crate::verification) fn plan(root: &Path, snapshot: &str, phase: &str) -> Result<()> {
    let part = match phase {
        "inputs" | "tests" => phase,
        "runtime" => "all",
        _ => anyhow::bail!("unknown preparation transport phase"),
    };
    let prepared: Prepared =
        day2::json::decode(&fs::read(root.join(super::preparation_path(part)?))?)?;
    ensure!(
        prepared.identity == super::identity(root, snapshot)?,
        "transport belongs to another checkout, run or attempt"
    );
    super::validate_preparation(&prepared, part)?;
    super::admit_outputs(root, &prepared, None)?;
    let mut groups = BTreeMap::<String, Files>::new();
    if phase == "runtime" {
        let mut common = Files::default();
        for path in [
            PREPARED,
            BINARIES,
            BUILD_CACHE,
            "artifacts/ci-preparation-inputs.json",
            "artifacts/ci-preparation-tests.json",
            "build-out/bin/day2-workflows",
            "build-out/bin/day2-workflows.json",
        ] {
            common.add(root, Path::new(path), 0)?;
        }
        add_fixtures(root, &mut common, &prepared)?;
        add_auxiliaries(root, &mut common, &prepared)?;
        groups.insert("common".into(), common);
        for group in GROUPS {
            let mut files = Files::default();
            add_outputs(root, &mut files, &grouped_outputs(&prepared, group)?)?;
            ensure!(
                !files.entries.is_empty(),
                "nonempty compiler transport partition required"
            );
            groups.insert(group.into(), files);
        }
    } else {
        let mut files = Files::default();
        files.add(root, Path::new(super::preparation_path(part)?), 0)?;
        if phase == "inputs" {
            add_fixtures(root, &mut files, &prepared)?;
            files.add(root, Path::new("build-out/bin/day2-workflows"), 0)?;
            files.add(root, Path::new("build-out/bin/day2-workflows.json"), 0)?;
        } else {
            for path in [BINARIES, BUILD_CACHE] {
                files.add(root, Path::new(path), 0)?;
            }
            for group in GROUPS {
                add_outputs(root, &mut files, &grouped_outputs(&prepared, group)?)?;
            }
            add_auxiliaries(root, &mut files, &prepared)?;
        }
        groups.insert(phase.into(), files);
    }
    // GNU tar consumes these fixed-phase NUL lists with --no-recursion. Every
    // directory entry is explicit, including the fixture's admitted modes.
    fs::create_dir(OUTPUT)?;
    for (name, files) in &groups {
        fs::write(
            Path::new(OUTPUT).join(format!("{name}.list0")),
            files.list()?,
        )?;
    }
    fs::write(
        Path::new(OUTPUT).join("plan.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "phase": phase,
            "identity": prepared.identity,
            "prepared_digest": day2::digest(&serde_json::to_vec(&prepared)?),
            "groups": groups,
            "compiler_scratch_included": false,
            "runtime_outcomes_cached": false,
        }))?,
    )?;
    println!(
        "Prepared explicit {phase} transport file lists; compiler scratch and runtime spools excluded"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_partitions_are_disjoint_exhaustive_and_keep_support_programs() -> Result<()> {
        let mut prepared = super::super::tests::sample_part("inputs")?;
        for (package, target) in [
            ("day2", "day2"),
            ("day2-control", "controller"),
            ("xtask", "xtask"),
        ] {
            let binary = super::super::Binary {
                package: package.into(),
                target: target.into(),
                kind: vec!["bin".into()],
                directory: format!("crates/{package}").into(),
                executable: format!("build-out/tests/{target}").into(),
                digest: "unused".into(),
                permissions: 0o755,
            };
            let mut program = binary.clone();
            program.executable = format!("build-out/bin/{target}").into();
            prepared.binaries.push(binary);
            prepared.programs.push(program);
        }
        let mut union = BTreeSet::new();
        for group in GROUPS {
            let outputs = grouped_outputs(&prepared, group)?;
            assert_eq!(outputs.len(), 2);
            assert!(union.is_disjoint(&outputs));
            union.extend(outputs);
        }
        assert_eq!(
            union,
            prepared
                .binaries
                .iter()
                .chain(&prepared.programs)
                .map(|b| b.executable.clone())
                .collect()
        );
        assert!(super::super::expected_binaries(&prepared, "simulation").is_empty());
        assert_eq!(
            super::super::expected_binaries(&prepared, "parallel-runtime").len(),
            3
        );
        assert!(grouped_outputs(&prepared, "unknown").is_err());
        Ok(())
    }

    #[test]
    fn file_list_refuses_symlinks_escapes_and_preserves_exact_directories() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        fs::create_dir(root.join("fixture"))?;
        fs::write(root.join("fixture/input"), b"fixture bytes")?;
        let mut files = Files::default();
        files.add(&root, Path::new("fixture"), 0)?;
        assert_eq!(files.bytes, 13);
        assert_eq!(files.list()?, b"fixture\0fixture/input\0");
        assert!(files.add(&root, Path::new("../outside"), 0).is_err());
        std::os::unix::fs::symlink(root.join("fixture"), root.join("alias"))?;
        assert!(files.add(&root, Path::new("alias/input"), 0).is_err());
        Ok(())
    }

    #[test]
    fn shard_admission_requires_selected_bytes_and_final_admission_requires_every_output()
    -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let scratch = tempfile::tempdir()?;
        let root = scratch.path().canonicalize()?;
        fs::create_dir_all(root.join("build-out/tests"))?;
        let selected = root.join("build-out/tests/day2");
        fs::write(&selected, b"selected executable")?;
        fs::set_permissions(&selected, fs::Permissions::from_mode(0o755))?;
        let mut prepared = super::super::tests::sample_part("inputs")?;
        for package in ["day2", "day2-control"] {
            prepared.binaries.push(super::super::Binary {
                package: package.into(),
                target: package.into(),
                kind: vec!["lib".into()],
                directory: format!("crates/{package}").into(),
                executable: format!("build-out/tests/{package}").into(),
                digest: day2::digest(b"selected executable"),
                permissions: 0o755,
            });
        }
        super::super::admit_outputs(&root, &prepared, Some("workspace-day2"))?;
        assert!(super::super::admit_outputs(&root, &prepared, None).is_err());
        assert!(super::super::admit_outputs(&root, &prepared, Some("parallel-runtime")).is_err());
        assert!(super::super::admit_outputs(&root, &prepared, Some("unknown")).is_err());
        fs::set_permissions(&selected, fs::Permissions::from_mode(0o644))?;
        assert!(super::super::admit_outputs(&root, &prepared, Some("workspace-day2")).is_err());
        fs::set_permissions(&selected, fs::Permissions::from_mode(0o755))?;
        fs::write(&selected, b"changed executable")?;
        assert!(super::super::admit_outputs(&root, &prepared, Some("workspace-day2")).is_err());
        fs::remove_file(&selected)?;
        assert!(super::super::admit_outputs(&root, &prepared, Some("workspace-day2")).is_err());
        Ok(())
    }
}
