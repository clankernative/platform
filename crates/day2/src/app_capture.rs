//! The build's capture rules for an app source tree: which entries the build
//! copies into its staged sources and hashes as the artifact's inputs, which it
//! never reads, and which it refuses. xtask's snapshot captures by [`classify`];
//! CI routing asks it whether a changed path is a build input. Both use these
//! rules, so they cannot disagree.
use anyhow::{Result, bail, ensure};
use std::fs;

/// The key prefix of a captured app's root directory, and the directory an app
/// keeps in its repository.
pub const ROOT: &str = "app";

/// The kind of a source entry, as `symlink_metadata` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Directory,
    File,
    Symlink,
    Special,
}

impl Kind {
    pub fn of(file_type: fs::FileType) -> Self {
        if file_type.is_symlink() {
            Self::Symlink
        } else if file_type.is_dir() {
            Self::Directory
        } else if file_type.is_file() {
            Self::File
        } else {
            Self::Special
        }
    }
}

/// What the build does with one directory entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capture {
    /// Never read: version-control metadata, prose, design data and extension
    /// tooling. Nothing below a skipped directory is read either.
    Skipped,
    /// Walked: each of its entries is classified in turn.
    Directory,
    /// Copied and hashed. Resources are UI, asset and published-download files;
    /// every other captured file is Roc source or the identity registry.
    File { resource: bool },
}

/// Modules the build generates or the SDK owns. An app that authors one is refused.
const GENERATED: [&str; 23] = [
    "main.roc",
    "schema-platform.roc",
    "app-platform.roc",
    "AppIdentity.roc",
    "SchemaSource.roc",
    "Selectors.roc",
    "Domains.roc",
    "Errors.roc",
    "Catalog.roc",
    "Data.roc",
    "Inputs.roc",
    "Outputs.roc",
    "Assets.roc",
    "Templates.roc",
    "Commands.roc",
    "Reads.roc",
    "AppContract.roc",
    "ImportedContracts.roc",
    "Credentials.roc",
    "Connections.roc",
    "SecurityActions.roc",
    "ProductReturns.roc",
    "Registry.roc",
];

/// The rule for the entry `name` of the captured directory `prefix` (`app` for
/// the app root, `app/ui`, ...). An error is an entry the build refuses.
pub fn classify(prefix: &str, name: &str, kind: Kind) -> Result<Capture> {
    // Version-control metadata is never app input: an app that lives in its
    // own repository carries it beside its sources. `.clanker` holds design
    // tool data (Studio fake-data scenes and canvas layout) committed with
    // the app; it is never compiled, served or admitted. Only the app root
    // may carry it. `.chrome-extension` is separate browser-extension source
    // and release tooling; only its explicitly published public-downloads/
    // outputs enter the app artifact. Signing keys must live outside the app.
    // UI build dependencies belong to the Platform distribution.
    if [".git", ".gitignore", ".gitattributes"].contains(&name)
        || (prefix == ROOT && [".clanker", ".chrome-extension"].contains(&name))
    {
        return Ok(Capture::Skipped);
    }
    ensure!(kind != Kind::Symlink, "source symlinks forbidden");
    if prefix == ROOT && ["assets", "ui", "public-downloads"].contains(&name) {
        ensure!(kind == Kind::Directory, "{name} must be a directory");
    }
    if kind == Kind::Directory {
        return Ok(Capture::Directory);
    }
    ensure!(kind == Kind::File, "special source file forbidden");
    let resource = prefix.starts_with("app/ui/")
        || prefix.starts_with("app/assets/")
        || prefix == "app/ui"
        || prefix == "app/assets"
        || prefix == "app/public-downloads";
    if name.ends_with(".md") && !resource {
        return Ok(Capture::Skipped);
    }
    let key = format!("{prefix}/{name}");
    ensure!(
        name.ends_with(".roc")
            || resource
            || (prefix == ROOT && name == crate::identity::REGISTRY_FILE),
        "app-owned non-Roc input: {key}"
    );
    if !resource && (crate::admission::reserved_module(name) || GENERATED.contains(&name)) {
        bail!("app-owned generated platform input forbidden: {name}");
    }
    Ok(Capture::File { resource })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_names_what_the_build_reads_skips_and_refuses() {
        let file = Kind::File;
        assert_eq!(
            classify(ROOT, "App.roc", file).unwrap(),
            Capture::File { resource: false }
        );
        assert_eq!(
            classify("app/ui/pages", "home.html", file).unwrap(),
            Capture::File { resource: true }
        );
        assert_eq!(
            classify("app/ui", "NOTES.md", file).unwrap(),
            Capture::File { resource: true }
        );
        assert_eq!(
            classify("app/domain", "README.md", file).unwrap(),
            Capture::Skipped
        );
        assert_eq!(
            classify(ROOT, ".chrome-extension", Kind::Directory).unwrap(),
            Capture::Skipped
        );
        assert_eq!(
            classify("app/domain", ".chrome-extension", Kind::Directory).unwrap(),
            Capture::Directory
        );
        assert!(classify("app/domain", "tool.mjs", file).is_err());
        assert!(classify("app/public-downloads/nested", "x.crx", file).is_err());
        assert!(classify(ROOT, "ui", file).is_err());
        assert!(classify(ROOT, "Linked.roc", Kind::Symlink).is_err());
        assert!(classify(ROOT, "Data.roc", file).is_err());
    }
}
