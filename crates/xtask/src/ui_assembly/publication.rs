//! Private capture/publication effects. No host paths, clocks or entropy enter admission.
use super::{MAX_FILE, MAX_FILES, MAX_TOTAL, MAX_UI_FILE, safe_rel};
use anyhow::{Context, Result, anyhow, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

const MAX_PATH_BYTES: usize = 4096;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct UiSnapshot {
    pub files: BTreeMap<String, Vec<u8>>,
    pub directories: BTreeSet<String>,
}

impl UiSnapshot {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.files.len() + self.directories.len() <= MAX_FILES,
            "captured UI source count exceeded"
        );
        let mut total = 0usize;
        for path in self.files.keys().chain(self.directories.iter()) {
            ensure!(
                path.len() <= MAX_PATH_BYTES
                    && !path.contains('\\')
                    && path.split('/').all(|part| !part.is_empty()
                        && part.len() <= 255
                        && part != "."
                        && part != "..")
                    && Path::new(path)
                        .components()
                        .all(|c| matches!(c, Component::Normal(_))),
                "invalid captured UI path"
            );
            for ancestor in path.match_indices('/').map(|(offset, _)| &path[..offset]) {
                ensure!(
                    self.directories.contains(ancestor),
                    "incomplete captured UI directory"
                );
            }
            ensure!(
                !(self.files.contains_key(path) && self.directories.contains(path)),
                "captured UI file/directory collision"
            );
        }
        for bytes in self.files.values() {
            ensure!(bytes.len() <= MAX_UI_FILE, "captured UI file exceeds limit");
            total = total
                .checked_add(bytes.len())
                .context("captured UI byte overflow")?;
            ensure!(total <= MAX_TOTAL, "captured UI byte budget exceeded");
        }
        Ok(())
    }

    pub fn input(&self, relative: &str) -> Result<&[u8]> {
        ensure!(safe_rel(relative), "unsafe input path: {relative}");
        let bytes = self
            .files
            .get(relative)
            .context("incomplete captured UI input")?;
        ensure!(
            bytes.len() <= MAX_FILE,
            "invalid/oversized input: {relative}"
        );
        Ok(bytes)
    }

    pub fn check_output(&self, relative: &str) -> Result<()> {
        ensure!(
            safe_rel(relative)
                && relative.len() <= MAX_PATH_BYTES
                && relative.split('/').all(|part| part.len() <= 255),
            "unsafe output path: {relative}"
        );
        ensure!(
            !self.directories.contains(relative),
            "output target is not a regular file"
        );
        for ancestor in relative
            .match_indices('/')
            .map(|(offset, _)| &relative[..offset])
        {
            ensure!(
                !self.files.contains_key(ancestor),
                "output parent is not a directory"
            );
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct PublicationPlan {
    pub writes: BTreeMap<String, Vec<u8>>,
    pub removes: BTreeSet<String>,
}

impl PublicationPlan {
    pub fn revalidate(&self, expected: &UiSnapshot, current: &UiSnapshot) -> Result<()> {
        current.validate()?;
        ensure!(current == expected, "UI source changed before publication");
        for relative in self.writes.keys() {
            current.check_output(relative)?;
        }
        for relative in &self.removes {
            current.input(relative)?;
            ensure!(
                !self.writes.contains_key(relative),
                "consumed input collides with output"
            );
        }
        Ok(())
    }
}

pub(super) trait UiPublication {
    /// Complete bounded UI tree, including directories; errors never become an empty capture.
    fn capture(&mut self) -> Result<UiSnapshot>;

    /// Stage first, revalidate the complete expected capture, then publish admitted bytes.
    /// Hash publication is owned by the caller and happens only on success.
    fn publish(&mut self, expected: &UiSnapshot, plan: &PublicationPlan) -> Result<()>;
}

pub(super) struct FilePublication<'a> {
    pub captured: &'a Path,
}

/// Charge the original global entry budget while streaming, BEFORE collecting/sorting.
pub(super) fn ordered_entries(directory: &Path, count: &mut usize) -> Result<Vec<fs::DirEntry>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        *count += 1;
        ensure!(*count <= MAX_FILES, "captured UI source count exceeded");
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

impl UiPublication for FilePublication<'_> {
    fn capture(&mut self) -> Result<UiSnapshot> {
        let ui = self.captured.join("ui");
        let meta = fs::symlink_metadata(&ui).context("captured UI directory missing")?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "invalid captured UI root"
        );
        let mut snapshot = UiSnapshot::default();
        let mut stack = vec![(ui, String::new())];
        let mut count = 0usize;
        let mut total = 0usize;
        while let Some((directory, prefix)) = stack.pop() {
            // Reverse push order makes the directory stack deterministic too.
            let mut directories = Vec::new();
            for entry in ordered_entries(&directory, &mut count)? {
                let kind = entry.file_type()?;
                ensure!(!kind.is_symlink(), "captured UI symlink forbidden");
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow!("non-UTF8 UI source path"))?;
                let relative = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                ensure!(
                    relative.len() <= MAX_PATH_BYTES,
                    "captured UI path byte budget exceeded"
                );
                if kind.is_dir() {
                    snapshot.directories.insert(relative.clone());
                    directories.push((entry.path(), relative));
                } else {
                    ensure!(kind.is_file(), "special captured UI source forbidden");
                    let bytes = day2::assets::read_regular(&entry.path(), MAX_UI_FILE as u64)?;
                    ensure!(bytes.len() <= MAX_UI_FILE, "captured UI file exceeds limit");
                    total = total
                        .checked_add(bytes.len())
                        .context("captured UI byte overflow")?;
                    ensure!(total <= MAX_TOTAL, "captured UI byte budget exceeded");
                    snapshot.files.insert(relative, bytes);
                }
            }
            stack.extend(directories.into_iter().rev());
        }
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn publish(&mut self, expected: &UiSnapshot, plan: &PublicationPlan) -> Result<()> {
        use std::io::Write;
        // OS randomness is an opaque adapter-owned handle, never decision input.
        let staging = tempfile::Builder::new()
            .prefix(".ui-stage-")
            .tempdir_in(self.captured)?;
        let mut staged = BTreeMap::new();
        for (relative, bytes) in &plan.writes {
            expected.check_output(relative)?;
            if expected.files.get(relative) == Some(bytes) {
                continue;
            }
            let mut file = tempfile::NamedTempFile::new_in(staging.path())?;
            file.write_all(bytes)?;
            staged.insert(relative, file);
        }
        plan.revalidate(expected, &self.capture()?)?;
        let ui = self.captured.join("ui");
        // As before, this is publication into a private build capture, not a
        // crash-atomic multi-file store or protection against hostile parent races.
        for (relative, file) in staged {
            let target = ui.join(relative);
            fs::create_dir_all(target.parent().context("invalid output parent")?)?;
            if expected.files.contains_key(relative) {
                file.persist(&target).map_err(|error| error.error)?;
            } else {
                file.persist_noclobber(&target)
                    .map_err(|error| error.error)?;
            }
        }
        for relative in &plan.removes {
            fs::remove_file(ui.join(relative))?;
        }
        Ok(())
    }
}
