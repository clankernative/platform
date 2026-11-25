//! Which lanes a change selects, by comparing two source trees' file digests.
//! The platform's own rules decide: a path the build captures, or refuses, is a
//! native input because [`day2::app_capture::classify`] says so; every Roc
//! source selects native, whose formatter reads them all; extension sources
//! select the extension check; JavaScript selects the JavaScript checks.
//! Mode changes, symlinks and special files take the native lane anywhere;
//! additions and removals do wherever the build walks.
use anyhow::{Result, ensure};
use day2::app_capture::{self, Capture, Kind, ROOT};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

/// Entries one tree may hold, as a forge source archive may.
pub const ENTRY_LIMIT: usize = 8192;
/// File bytes one tree may hold.
pub const BYTE_LIMIT: u64 = 128 << 20;
/// Path components below the tree's root.
pub const DEPTH_LIMIT: usize = 64;
/// Reasons a result lists; the count of changed paths is always complete.
pub const REASON_LIMIT: usize = 256;

/// One entry of a source tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Directory,
    File { executable: bool, digest: String },
    Symlink { target: Vec<u8> },
    Special,
}

impl Entry {
    fn kind(&self) -> Kind {
        match self {
            Self::Directory => Kind::Directory,
            Self::File { .. } => Kind::File,
            Self::Symlink { .. } => Kind::Symlink,
            Self::Special => Kind::Special,
        }
    }
}

/// Every entry of a tree by its `/`-separated path below the root.
/// Version-control metadata (`.git`) is never read.
pub type Tree = BTreeMap<String, Entry>;

/// Read a tree without following symlinks.
pub fn read_tree(root: &Path) -> Result<Tree> {
    ensure!(
        fs::symlink_metadata(root)?.file_type().is_dir(),
        "a source tree must be a real directory: {}",
        root.display()
    );
    let mut tree = Tree::new();
    let mut bytes = 0;
    walk(root, "", 0, &mut tree, &mut bytes)?;
    Ok(tree)
}

fn walk(
    directory: &Path,
    prefix: &str,
    depth: usize,
    tree: &mut Tree,
    bytes: &mut u64,
) -> Result<()> {
    ensure!(depth < DEPTH_LIMIT, "source tree nesting budget exceeded");
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("source tree names must be UTF-8"))?;
        if name == ".git" {
            continue;
        }
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        ensure!(
            tree.len() < ENTRY_LIMIT,
            "source tree entry budget exceeded"
        );
        let metadata = fs::symlink_metadata(entry.path())?;
        let value = match Kind::of(metadata.file_type()) {
            Kind::Directory => {
                walk(&entry.path(), &path, depth + 1, tree, bytes)?;
                Entry::Directory
            }
            Kind::File => {
                use std::os::unix::fs::PermissionsExt;
                *bytes += metadata.len();
                ensure!(*bytes <= BYTE_LIMIT, "source tree byte budget exceeded");
                Entry::File {
                    executable: metadata.permissions().mode() & 0o111 != 0,
                    digest: day2::digest(&fs::read(entry.path())?),
                }
            }
            Kind::Symlink => {
                use std::os::unix::ffi::OsStrExt;
                Entry::Symlink {
                    target: fs::read_link(entry.path())?.as_os_str().as_bytes().to_vec(),
                }
            }
            Kind::Special => Entry::Special,
        };
        tree.insert(path, value);
    }
    Ok(())
}

/// The selected lanes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Lanes {
    pub native: bool,
    pub extension: bool,
    pub javascript: bool,
}

impl Lanes {
    pub const ALL: Self = Self {
        native: true,
        extension: true,
        javascript: true,
    };

    /// The selected lanes' names, in a fixed order.
    pub fn names(self) -> Vec<&'static str> {
        [
            (self.native, "native"),
            (self.extension, "extension"),
            (self.javascript, "javascript"),
        ]
        .into_iter()
        .filter_map(|(selected, name)| selected.then_some(name))
        .collect()
    }
}

/// Why one changed path selects its lanes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    pub path: String,
    pub change: String,
    pub lanes: Vec<String>,
    pub rules: Vec<String>,
}

/// The routing decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Route {
    pub lanes: Lanes,
    /// Whether a base tree was compared; without one every lane runs.
    pub base: bool,
    pub changed: usize,
    pub reasons: Vec<Reason>,
}

/// Route the change from `base` to `head`, a pull-request gate optimisation:
/// without a base, or when nothing differs, every lane runs.
pub fn route(head: &Tree, base: Option<&Tree>) -> Route {
    let Some(base) = base else {
        return Route {
            lanes: Lanes::ALL,
            base: false,
            changed: 0,
            reasons: Vec::new(),
        };
    };
    let mut lanes = Lanes::default();
    let mut changed = 0;
    let mut reasons = Vec::new();
    let paths: std::collections::BTreeSet<&String> = head.keys().chain(base.keys()).collect();
    for path in paths {
        let (before, after) = (base.get(path), head.get(path));
        if before == after
            || (before == Some(&Entry::Directory) && after.is_none())
            || (after == Some(&Entry::Directory) && before.is_none())
        {
            // A directory alone carries no content; its files are compared.
            continue;
        }
        changed += 1;
        let change = match (before, after) {
            (None, _) => "added",
            (_, None) => "deleted",
            (Some(a), Some(b)) if a.kind() != b.kind() => "kind",
            (Some(Entry::File { executable: a, .. }), Some(Entry::File { executable: b, .. }))
                if a != b =>
            {
                "mode"
            }
            _ => "modified",
        };
        let selected = select(path, change, before, after, head, base);
        lanes.native |= selected.0.native;
        lanes.extension |= selected.0.extension;
        lanes.javascript |= selected.0.javascript;
        if reasons.len() < REASON_LIMIT {
            reasons.push(Reason {
                path: path.clone(),
                change: change.to_owned(),
                lanes: selected.0.names().into_iter().map(str::to_owned).collect(),
                rules: selected.1.into_iter().map(str::to_owned).collect(),
            });
        }
    }
    // Identical trees prove nothing about the head: every lane runs, as an
    // empty diff did.
    Route {
        lanes: if changed == 0 { Lanes::ALL } else { lanes },
        base: true,
        changed,
        reasons,
    }
}

/// The lanes one changed path selects, and the rules that selected them.
fn select(
    path: &str,
    change: &'static str,
    before: Option<&Entry>,
    after: Option<&Entry>,
    head: &Tree,
    base: &Tree,
) -> (Lanes, Vec<&'static str>) {
    let mut lanes = Lanes::default();
    let mut rules = Vec::new();
    let mut native = |rule| {
        lanes.native = true;
        rules.push(rule);
    };
    let kinds = [before, after].into_iter().flatten().map(Entry::kind);
    if kinds
        .clone()
        .any(|kind| matches!(kind, Kind::Symlink | Kind::Special))
    {
        native("symlink or special file");
    }
    if change == "kind" || change == "mode" {
        native("kind or mode change");
    }
    if path.ends_with(".roc") {
        native("Roc source");
    }
    if let Some(relative) = path.strip_prefix(&format!("{ROOT}/")) {
        let kind = after.or(before).map_or(Kind::File, Entry::kind);
        match captured(relative, kind) {
            Captured::Input => native("build input"),
            Captured::Refused => native("refused by the build"),
            Captured::Skipped { inside } => {
                // The build reads every entry name of a directory it walks, so
                // adding or removing one there can change the build. A skipped
                // directory present in both trees is never walked.
                let walked = inside.is_none_or(|directory| {
                    !(head.get(&directory) == Some(&Entry::Directory)
                        && base.get(&directory) == Some(&Entry::Directory))
                });
                if (change == "added" || change == "deleted") && walked {
                    native("entry added or removed where the build walks");
                }
            }
        }
        if relative.starts_with(".chrome-extension/") {
            lanes.extension = true;
            rules.push("extension source");
        }
    } else if path == ROOT {
        native("app root changed kind");
    }
    if day2::app_javascript::selected(path) {
        lanes.javascript = true;
        rules.push("JavaScript");
    }
    (lanes, rules)
}

/// What the build does with a path below the app root.
#[derive(Debug, PartialEq, Eq)]
enum Captured {
    Input,
    Refused,
    /// The build never reads it. `inside` is the skipped directory it lies in,
    /// if it is not itself the skipped entry.
    Skipped {
        inside: Option<String>,
    },
}

fn captured(relative: &str, kind: Kind) -> Captured {
    let parts: Vec<&str> = relative.split('/').collect();
    let mut prefix = ROOT.to_owned();
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        let entry_kind = if last { kind } else { Kind::Directory };
        match app_capture::classify(&prefix, part, entry_kind) {
            Err(_) => return Captured::Refused,
            Ok(Capture::Skipped) => {
                return Captured::Skipped {
                    inside: (!last).then(|| format!("{prefix}/{part}")),
                };
            }
            Ok(Capture::File { .. }) => return Captured::Input,
            Ok(Capture::Directory) if last => return Captured::Input,
            Ok(Capture::Directory) => prefix = format!("{prefix}/{part}"),
        }
    }
    Captured::Input
}
