//! `day2 ci check`: an app repository's CI over local source trees, with no
//! forge, network or git. The CLI renders the request (the head tree, an
//! optional base tree, the instance's verification case count and a new output
//! directory); CiCheck.roc chooses the step order; this adapter validates the
//! request, routes the change, runs the JavaScript checks, packs the checked
//! artifact and writes the receipt, refusing any step out of order or outside
//! its lane. The host records the build and the extension check it ran for the
//! session, so the receipt never trusts a recipe's account of them.
//!
//! The app lives in `app/` of its repository. The seed is fixed. Forge
//! identity (repository, commit, run) is not known here and is not recorded.
//!
//! Routing against a base tree is only a pull-request gate optimisation: it
//! may skip lanes the change cannot affect, so a routed run that skipped a lane
//! never writes an artifact. A push run passes no base: every lane runs and,
//! with a qualified SDK's tooling, the artifact and its receipt are written.
//! Identical trees run every lane, as an empty diff did. Without the SDK's
//! precompiled tooling distribution there is no SDK identity to record, so
//! every check still runs but no artifact or receipt is written.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

mod artifact;
mod route;
#[cfg(test)]
mod tests;

pub use artifact::{File, files, pack, source_inputs};
pub use route::{Entry, Lanes, Reason, Route, Tree, read_tree, route};

/// Every app CI campaign's seed.
pub const SEED: u64 = 42;
/// The checks a completed native campaign reports, publish_artifact.CHECKS.
pub const CHECKS: [&str; 5] = [
    "command-trace-replay",
    "duplicate-delivery",
    "empty-state-properties",
    "properties-after-each-command-and-completion",
    "schema-invalid-input-rejection",
];
/// The JavaScript findings a result lists; the count is always complete.
pub const FINDING_LIMIT: usize = 256;
const REQUEST_LIMIT: u64 = 65_536;
/// Each JavaScript file the checks read.
const SOURCE_LIMIT: u64 = 4 << 20;
/// Each fixed platform tool the checks run: the formatter and the linter.
const TOOL_DEADLINE: Duration = Duration::from_secs(900);

/// What the CLI hands the host.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub head: PathBuf,
    pub base: Option<PathBuf>,
    pub cases: u64,
    pub output: PathBuf,
}

impl Request {
    fn read(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.len() <= REQUEST_LIMIT,
            "invalid CI check request file"
        );
        let request: Self = day2::json::decode(&fs::read(path)?)?;
        let head = real_directory(&request.head, "the head tree")?;
        let app = real_directory(&head.join(day2::app_capture::ROOT), "the head tree's app/")?;
        ensure!(
            fs::symlink_metadata(app.join("App.roc")).is_ok_and(|entry| entry.is_file()),
            "the head tree's app/ needs App.roc"
        );
        let base = match &request.base {
            Some(base) => Some(real_directory(base, "the base tree")?),
            None => None,
        };
        ensure!(
            (4..=100).contains(&request.cases),
            "verification cases must be 4 to 100"
        );
        let output = std::path::absolute(&request.output)?;
        ensure!(
            fs::symlink_metadata(&output).is_err(),
            "ci check requires a new output directory: {}",
            output.display()
        );
        ensure!(
            output.parent().is_some_and(Path::is_dir),
            "the new output directory's parent must exist: {}",
            output.display()
        );
        Ok(Self {
            head,
            base,
            cases: request.cases,
            output,
        })
    }
}

fn real_directory(path: &Path, role: &str) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    ensure!(
        fs::symlink_metadata(&path).is_ok_and(|entry| entry.file_type().is_dir()),
        "{role} must be a real directory: {}",
        path.display()
    );
    Ok(path)
}

/// The build the host ran for the session.
struct Built {
    receipt: day2::development::BuildReceipt,
    cases: u64,
}

/// The checked artifact written to the output directory.
struct Packed {
    artifact_id: String,
    archive: day2::sdk_release::BlobIdentity,
    examples: usize,
    generated: usize,
}

/// What became of the artifact: the report's `artifact` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Artifact {
    /// No native lane ran, so nothing was built.
    NotBuilt,
    /// Built and checked, but a routed run skipped a lane: only a run in which
    /// every lane ran writes an artifact.
    Routed,
    /// Built and checked, but this tooling has no SDK identity to record.
    NoSdkIdentity,
    /// `app.tar.gz` and `receipt.json` are in the output directory.
    Written,
}

impl Artifact {
    fn name(self) -> &'static str {
        match self {
            Self::NotBuilt => "not_built",
            Self::Routed => "routed",
            Self::NoSdkIdentity => "no_sdk_identity",
            Self::Written => "written",
        }
    }
}

pub struct Session {
    request: Request,
    platform: PathBuf,
    /// The tooling's SDK identity, read once when the session starts.
    sdk: Option<day2::sdk_release::BlobIdentity>,
    head: Tree,
    route: Option<Route>,
    done: BTreeSet<&'static str>,
    javascript: Option<u64>,
    format: Option<u64>,
    extension: Option<bool>,
    built: Option<Built>,
    packed: Option<Packed>,
    artifact: Artifact,
}

impl Session {
    /// Validate the request, read the tooling's SDK identity and the head tree.
    pub fn prepare(path: &Path, platform: &Path) -> Result<Self> {
        Self::with_sdk(path, platform, sdk_distribution(platform)?)
    }

    fn with_sdk(
        path: &Path,
        platform: &Path,
        sdk: Option<day2::sdk_release::BlobIdentity>,
    ) -> Result<Self> {
        let request = Request::read(path)?;
        let head = read_tree(&request.head)?;
        Ok(Self {
            request,
            platform: platform.to_path_buf(),
            sdk,
            head,
            route: None,
            done: BTreeSet::new(),
            javascript: None,
            format: None,
            extension: None,
            built: None,
            packed: None,
            artifact: Artifact::NotBuilt,
        })
    }

    /// The app root the recipe checks and builds.
    pub fn app(&self) -> PathBuf {
        self.request.head.join(day2::app_capture::ROOT)
    }

    fn lanes(&self) -> Result<Lanes> {
        Ok(self.route.as_ref().context("route the change first")?.lanes)
    }

    pub fn step(&mut self, name: &str) -> Result<Value> {
        let step = match name {
            "route" => "route",
            "javascript" => "javascript",
            "format" => "format",
            "artifact" => "artifact",
            "result" => "result",
            _ => bail!("unknown CI check step: {name}"),
        };
        ensure!(self.done.insert(step), "CI check step repeated: {name}");
        if step != "route" {
            ensure!(self.route.is_some(), "route the change first");
        }
        match step {
            "route" => self.route(),
            "javascript" => self.javascript(),
            "format" => self.format(),
            "artifact" => self.artifact(),
            _ => self.result(),
        }
    }

    fn route(&mut self) -> Result<Value> {
        let base = match &self.request.base {
            Some(base) => Some(read_tree(base)?),
            None => None,
        };
        let route = route(&self.head, base.as_ref());
        let lanes = route.lanes;
        self.route = Some(route);
        Ok(json!({
            "root": self.app(),
            "seed": SEED,
            "cases": self.request.cases,
            "native": lanes.native,
            "extension": lanes.extension,
            "javascript": lanes.javascript,
        }))
    }

    /// Syntax and formatting of every regular JavaScript file in the head tree,
    /// then the SDK's pinned oxlint with the platform's one configuration over
    /// every file that parsed. All findings are reported together.
    fn javascript(&mut self) -> Result<Value> {
        ensure!(
            self.lanes()?.javascript,
            "the change selects no JavaScript checks"
        );
        let minified: Vec<&str> = self
            .head
            .keys()
            .filter(|path| {
                day2::app_javascript::selected(path) && day2::app_javascript::minified(path)
            })
            .map(String::as_str)
            .collect();
        ensure!(
            minified.is_empty(),
            "the platform lints only JavaScript source it can check, and its linter never \
             reads a name containing .min., -min. or _min.; commit the source instead: {}",
            minified.join(", ")
        );
        let mut findings: Vec<(String, u64, String, String)> = Vec::new();
        let mut parsed = Vec::new();
        let mut checked = 0;
        for (path, entry) in &self.head {
            if !day2::app_javascript::selected(path) || *entry == Entry::Directory {
                continue;
            }
            ensure!(
                matches!(entry, Entry::File { .. }),
                "expected regular JavaScript source: {path}"
            );
            let file = self.request.head.join(path);
            ensure!(
                fs::metadata(&file)?.len() <= SOURCE_LIMIT,
                "JavaScript source budget exceeded: {path}"
            );
            checked += 1;
            let found = day2::app_javascript::check(path, &fs::read(&file)?);
            if !found.iter().any(|finding| finding.rule == "syntax") {
                parsed.push(path.clone());
            }
            for finding in found {
                findings.push((
                    path.clone(),
                    finding.line as u64,
                    finding.rule.to_owned(),
                    finding.message,
                ));
            }
        }
        findings.extend(self.lint(&parsed)?);
        if !findings.is_empty() {
            findings.sort();
            let listed = findings
                .iter()
                .take(FINDING_LIMIT)
                .map(|(path, line, rule, message)| format!("{path}:{line}: {message} ({rule})"))
                .collect::<Vec<_>>()
                .join("; ");
            // One line: the CLI prints a failure without control characters.
            bail!(
                "{} JavaScript finding(s) in {checked} file(s): {listed}",
                findings.len()
            );
        }
        self.javascript = Some(checked);
        Ok(json!({ "files": checked }))
    }

    /// The pinned oxlint over `files`, through the distribution's own
    /// `cli/xtask ci-javascript-lint`, which verifies the installed binary.
    fn lint(&self, files: &[String]) -> Result<Vec<(String, u64, String, String)>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Linted {
            files: usize,
            findings: Vec<Finding>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Finding {
            path: String,
            line: u64,
            rule: String,
            message: String,
        }
        if files.is_empty() {
            return Ok(Vec::new());
        }
        let directory = operations(&self.platform, "ci-lint-")?;
        let list = directory.path().join("files.json");
        fs::write(&list, serde_json::to_vec(files)?)?;
        let result = directory.path().join("lint.json");
        let mut command = Command::new(self.platform.join("cli/xtask"));
        command
            .arg("ci-javascript-lint")
            .arg(&self.request.head)
            .arg(&list)
            .arg(&result);
        let directory = run_tool(&mut command, &self.platform, directory, "lint.log")?;
        let linted: Linted = day2::json::decode(&day2_assets::read_regular(&result, 32 << 20)?)?;
        drop(directory);
        ensure!(linted.files == files.len(), "invalid lint result");
        Ok(linted
            .findings
            .into_iter()
            .map(|finding| (finding.path, finding.line, finding.rule, finding.message))
            .collect())
    }

    /// `roc fmt --check` on every regular `.roc` file, with the SDK's reviewed formatter.
    fn format(&mut self) -> Result<Value> {
        ensure!(self.lanes()?.native, "the change selects no native checks");
        let directory = operations(&self.platform, "ci-format-")?;
        let result = directory.path().join("format.json");
        let mut command = Command::new(self.platform.join("cli/xtask"));
        command
            .arg("ci-roc-format")
            .arg(&self.request.head)
            .arg(&result);
        let directory = run_tool(&mut command, &self.platform, directory, "format.log")?;
        let decoded: Value = day2::json::decode(&fs::read(&result)?)?;
        drop(directory);
        let files = decoded["files"]
            .as_u64()
            .filter(|files| *files > 0)
            .context("invalid formatter result")?;
        self.format = Some(files);
        Ok(json!({ "files": files }))
    }

    /// The host ran `platform extension verify` on `source`.
    pub fn extension_verified(&mut self, source: &Path, result: &Value) -> Result<()> {
        ensure!(
            std::path::absolute(source)? == self.app(),
            "CI checks only the head tree's app"
        );
        self.extension = Some(
            result["declared"]
                .as_bool()
                .context("invalid extension verification")?,
        );
        Ok(())
    }

    /// The host is about to build `source`: only the head tree's app, once,
    /// tested, with the fixed seed and the request's cases.
    pub fn building(&self, source: &Path, seed: &str, cases: u64, tests: bool) -> Result<()> {
        ensure!(self.lanes()?.native, "the change selects no native build");
        ensure!(self.built.is_none(), "CI builds the app once");
        ensure!(
            std::path::absolute(source)? == self.app()
                && seed == SEED.to_string()
                && cases == self.request.cases
                && tests,
            "CI builds the head tree's app with its tests, seed {SEED} and the instance's cases"
        );
        Ok(())
    }

    /// The host built the app.
    pub fn built(&mut self, receipt: day2::development::BuildReceipt) {
        self.built = Some(Built {
            receipt,
            cases: self.request.cases,
        });
    }

    /// Bind the build's selected artifact, then pack it as publish_artifact.pack
    /// did, but only when every lane ran and the tooling has an SDK identity.
    fn artifact(&mut self) -> Result<Value> {
        let lanes = self.lanes()?;
        ensure!(lanes.native, "the change selects no native build");
        let built = self.built.as_ref().context("build the app first")?;
        let verification = &built.receipt.verification;
        let current: Value =
            day2::json::decode(&fs::read(self.platform.join("artifacts/current.json"))?)?;
        let id = verification
            .artifact
            .strip_prefix("sha256:")
            .context("invalid checked artifact")?;
        ensure!(
            current["artifact"].as_str() == Some(verification.artifact.as_str())
                && built.receipt.artifact == self.platform.join("artifacts").join(id),
            "native check does not bind the selected artifact"
        );
        let checks: BTreeSet<&str> = verification.checks.iter().map(String::as_str).collect();
        ensure!(
            checks == CHECKS.into_iter().collect()
                && verification.seed == SEED.to_string()
                && verification.generated > 0,
            "native check does not bind this artifact/profile"
        );
        self.artifact = if lanes != Lanes::ALL {
            Artifact::Routed
        } else if self.sdk.is_none() {
            Artifact::NoSdkIdentity
        } else {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&self.request.output)?;
            let archive = pack(&built.receipt.artifact, id, &self.request.output)?;
            self.packed = Some(Packed {
                artifact_id: id.to_owned(),
                archive,
                examples: verification.examples,
                generated: verification.generated,
            });
            Artifact::Written
        };
        Ok(json!({ "artifact": self.artifact.name() }))
    }

    /// Every selected lane ran; write the receipt when an artifact was packed.
    fn result(&mut self) -> Result<Value> {
        let route = self.route.as_ref().context("route the change first")?;
        let lanes = route.lanes;
        ensure!(
            (!lanes.javascript || self.javascript.is_some())
                && (!lanes.native
                    || (self.format.is_some() && self.artifact != Artifact::NotBuilt))
                && (!(lanes.native || lanes.extension) || self.extension.is_some()),
            "a selected CI lane did not run"
        );
        let source_inputs = source_inputs(&self.app())?;
        let names: Vec<String> = lanes.names().into_iter().map(str::to_owned).collect();
        let receipt = match (&self.packed, &self.built, &self.sdk) {
            (Some(packed), Some(built), Some(sdk)) if self.artifact == Artifact::Written => {
                let receipt = Receipt {
                    version: 1,
                    source_inputs: source_inputs.clone(),
                    artifact_id: packed.artifact_id.clone(),
                    sdk_distribution: sdk.clone(),
                    verification: Verification {
                        version: 1,
                        seed: SEED,
                        cases: built.cases,
                    },
                    archive: packed.archive.clone(),
                    examples: packed.examples as u64,
                    generated: packed.generated as u64,
                    lanes: names.clone(),
                };
                receipt.write(&self.request.output)?;
                Some(receipt)
            }
            _ => None,
        };
        let report = Report {
            format: 1,
            lanes: names,
            base: route.base,
            changed: route.changed as u64,
            reasons: route.reasons.clone(),
            javascript_files: self.javascript,
            roc_files: self.format,
            extension_declared: self.extension,
            source_inputs,
            artifact: self.artifact.name().to_owned(),
            output: receipt.as_ref().map(|_| self.request.output.clone()),
            receipt,
        };
        Ok(serde_json::to_value(report)?)
    }
}

/// What `day2 ci check` prints: the lanes the change selected and why, what
/// each lane checked, the app's source inputs, what became of the artifact
/// (`not_built`, `routed`, `no_sdk_identity` or `written`) and, once written,
/// the output directory and its receipt. cli/fixtures/ci-check-report.json
/// pins the shape for the host and the CLI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub format: u32,
    pub lanes: Vec<String>,
    pub base: bool,
    pub changed: u64,
    pub reasons: Vec<Reason>,
    pub javascript_files: Option<u64>,
    pub roc_files: Option<u64>,
    pub extension_declared: Option<bool>,
    pub source_inputs: String,
    pub artifact: String,
    pub output: Option<PathBuf>,
    pub receipt: Option<Receipt>,
}

/// `receipt.json` beside `app.tar.gz`: what the deploy side binds a checked
/// artifact to. Forge identity is added where the forge is known.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: u32,
    pub source_inputs: String,
    pub artifact_id: String,
    pub sdk_distribution: day2::sdk_release::BlobIdentity,
    pub verification: Verification,
    pub archive: day2::sdk_release::BlobIdentity,
    pub examples: u64,
    pub generated: u64,
    pub lanes: Vec<String>,
}

/// The campaign the build ran as its required verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub version: u32,
    pub seed: u64,
    pub cases: u64,
}

impl Receipt {
    /// Key-sorted, as `json.dumps(receipt, sort_keys=True)` wrote it, and a newline.
    fn write(&self, output: &Path) -> Result<()> {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut bytes = day2::python_json::dumps(
            &serde_json::to_value(self)?,
            day2::python_json::Layout::Default,
        )?;
        bytes.push(b'\n');
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(output.join("receipt.json"))?
            .write_all(&bytes)?;
        Ok(())
    }
}

/// Run a fixed platform tool under the process supervisor, its log in
/// `directory`. A failure keeps the directory and carries the log's last 4 KiB
/// on one line, since CI keeps only this message; a success hands the
/// directory back, to be removed once its result is read.
fn run_tool(
    command: &mut Command,
    platform: &Path,
    directory: tempfile::TempDir,
    log: &str,
) -> Result<tempfile::TempDir> {
    let log = directory.path().join(log);
    if let Err(error) = crate::process::run(command, platform, &log, TOOL_DEADLINE) {
        // The error names the log, so it outlives this run.
        let _kept = directory.keep();
        let tail = fs::read(&log).unwrap_or_default();
        let tail = String::from_utf8_lossy(&tail[tail.len().saturating_sub(4096)..]);
        let tail: Vec<&str> = tail
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
            .collect();
        bail!("{error:#}: {}", tail.join(" | "));
    }
    Ok(directory)
}

/// A private directory for one tool's log and result, removed when dropped.
fn operations(platform: &Path, prefix: &str) -> Result<tempfile::TempDir> {
    fs::create_dir_all(platform.join("artifacts/operations"))?;
    Ok(tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(platform.join("artifacts/operations"))?)
}

/// The SDK identity this tooling knows: its precompiled tooling distribution,
/// which a qualified release manifest names as its `distribution`. A source
/// checkout has none.
fn sdk_distribution(platform: &Path) -> Result<Option<day2::sdk_release::BlobIdentity>> {
    let path = platform.join("build-out/tooling/distribution.json");
    match std::env::var("DAY2_PRECOMPILED_TOOLING") {
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Ok(value) if value == "1" => {}
        _ => bail!("DAY2_PRECOMPILED_TOOLING must be 1 or unset"),
    }
    let bytes = day2_assets::read_regular(&path, day2::sdk_release::DISTRIBUTION_LIMIT)?;
    let distribution: day2::sdk_release::Distribution = day2::json::decode(&bytes)?;
    ensure!(
        distribution.workflow_sources == day2::automation::source_digest()
            && distribution.toolchain == day2::automation::toolchain_digest(),
        "the tooling distribution belongs to another SDK"
    );
    Ok(Some(day2::sdk_release::BlobIdentity::of(&bytes)))
}
