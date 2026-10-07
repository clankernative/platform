//! Optional provider-neutral UI assembly capability.
//!
//! The host owns locked capture, admission and staging. Providers own expansion.
//! Execution requires an operator-trusted executable pin; an app lock grants no authority.
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

mod port;
use port::{AssemblyFailure, ProcessAssembler, UiAssembler};

const MAX_FILE: usize = 1_048_576;
const MAX_FILES: usize = 512;
const MAX_INPUTS: usize = 4096;
const MAX_UI_FILE: usize = 8 * 1024 * 1024;
const MAX_TOTAL: usize = 32 * 1024 * 1024;
const MAX_STDOUT: usize = 32 * 1024 * 1024;
const MAX_STDERR: usize = 1024 * 1024;
const PACKAGE_KEY: &str = "ui/package";
const LOCK: &str = "ui/ui.lock.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Lock {
    schema_version: u32,
    provider: String,
    package: LockedPackage,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LockedPackage {
    name: String,
    version: String,
    path: String,
    digest: String,
    inputs: Vec<Input>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pin {
    schema_version: u32,
    provider: String,
    assembly_protocol: u32,
    binding_abi: u32,
    targets: BTreeMap<String, TargetPin>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssemblyRequest {
    schema_version: u32,
    assembly_protocol: u32,
    provider: String,
    target: AssemblyTarget,
    package: LockedPackage,
    ui: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssemblyTarget {
    binding_abi: u32,
    template_engine: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetPin {
    executable: String,
    digest: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    ok: bool,
    command: String,
    data: Bundle,
    diagnostics: Vec<serde_json::Value>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bundle {
    schema_version: u32,
    runtime_abi: u32,
    template_engine: String,
    package_digest: String,
    templates: BTreeMap<String, String>,
    resources: Vec<Resource>,
    inputs: Vec<Input>,
    consumed_inputs: Vec<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Resource {
    path: String,
    source: Option<String>,
    content: Option<String>,
    digest: String,
    bytes: usize,
    kind: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    path: String,
    digest: String,
    bytes: usize,
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn safe_rel(s: &str) -> bool {
    !s.is_empty()
        && !s.contains('\\')
        && Path::new(s)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && s.split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
}
fn checked(root: &Path, rel: &str) -> Result<Vec<u8>> {
    ensure!(safe_rel(rel), "unsafe input path: {rel}");
    let mut p = root.to_path_buf();
    for (i, part) in rel.split('/').enumerate() {
        p.push(part);
        let m = fs::symlink_metadata(&p).with_context(|| format!("inspect {}", p.display()))?;
        ensure!(
            !m.file_type().is_symlink(),
            "symlink input forbidden: {}",
            p.display()
        );
        if i + 1 < rel.split('/').count() {
            ensure!(m.is_dir(), "invalid input parent: {}", p.display());
        }
    }
    let m = fs::symlink_metadata(&p)?;
    ensure!(
        m.is_file() && m.len() <= MAX_FILE as u64,
        "invalid/oversized input: {}",
        p.display()
    );
    let b = day2::assets::read_regular(&p, MAX_FILE as u64)?;
    ensure!(
        b.len() <= MAX_FILE,
        "input grew beyond file limit: {}",
        p.display()
    );
    Ok(b)
}
fn parse_lock(path: &Path) -> Result<Lock> {
    let m = fs::symlink_metadata(path).context("read captured UI lock")?;
    ensure!(
        m.is_file() && !m.file_type().is_symlink() && m.len() <= MAX_FILE as u64,
        "invalid captured UI lock"
    );
    let lock: Lock = serde_json::from_slice(&day2::assets::read_regular(path, MAX_FILE as u64)?)?;
    ensure!(
        lock.schema_version == 1
            && !lock.provider.is_empty()
            && lock.provider.len() <= 128
            && lock
                .provider
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
            && !lock.package.name.trim().is_empty()
            && !lock.package.version.trim().is_empty(),
        "unsupported UI lock"
    );
    ensure!(
        safe_lock_path(&lock.package.path),
        "invalid package lock path"
    );
    ensure!(
        valid_digest(&lock.package.digest),
        "invalid package digest in lock"
    );
    ensure!(
        manifest_digest(&lock.package.inputs)? == lock.package.digest,
        "locked input manifest digest mismatch"
    );
    Ok(lock)
}
fn safe_lock_path(s: &str) -> bool {
    if s.contains('\\') || s.is_empty() {
        return false;
    }
    let parts = s.split('/').collect::<Vec<_>>();
    let parents = parts.iter().take_while(|p| **p == "..").count();
    (1..=2).contains(&parents)
        && parents < parts.len()
        && parts[parents..].iter().all(|p| {
            !p.is_empty()
                && *p != "."
                && *p != ".."
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
}
fn valid_digest(s: &str) -> bool {
    s.len() == 71
        && s.starts_with("sha256:")
        && s[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn package_root(app: &Path, lock: &Lock) -> Result<PathBuf> {
    let app = app.canonicalize().context("canonicalize app source")?;
    let parent = app.parent().context("app has no parent")?;
    let ui_root = app.join("ui");
    let ui_meta = fs::symlink_metadata(&ui_root).context("inspect app UI root")?;
    ensure!(
        ui_meta.is_dir() && !ui_meta.file_type().is_symlink(),
        "app UI root must be a real directory"
    );
    let lexical = ui_root.join(&lock.package.path);
    let root = lexical
        .canonicalize()
        .context("canonicalize locked package")?;
    ensure!(
        root.starts_with(parent) && root != parent,
        "locked package escapes app sibling boundary"
    );
    let m = fs::symlink_metadata(&root)?;
    ensure!(
        m.is_dir() && !m.file_type().is_symlink(),
        "invalid package root"
    );
    // Reject symlinks in every traversed lexical package path component.
    let mut cursor = ui_root;
    for part in Path::new(&lock.package.path).components() {
        match part {
            Component::ParentDir => {
                cursor.pop();
            }
            Component::Normal(n) => cursor.push(n),
            _ => bail!("invalid package path"),
        }
        let meta = fs::symlink_metadata(&cursor)?;
        ensure!(
            !meta.file_type().is_symlink(),
            "package path ancestor symlink forbidden"
        );
    }
    Ok(root)
}

/// A manifest is a content-addressed input closure, not a provider package schema.
fn manifest_digest(inputs: &[Input]) -> Result<String> {
    ensure!(
        !inputs.is_empty() && inputs.len() <= MAX_INPUTS,
        "locked input count budget"
    );
    let mut sorted = inputs.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut names = BTreeSet::new();
    let mut total = 0usize;
    let mut digest = Sha256::new();
    for input in sorted {
        ensure!(
            safe_rel(&input.path)
                && input.path.len() <= 512
                && input.path.split('/').count() <= 8
                && input.bytes <= MAX_FILE
                && valid_digest(&input.digest),
            "invalid locked input"
        );
        ensure!(
            names.insert(input.path.to_ascii_lowercase()),
            "duplicate/case-colliding locked input"
        );
        total = total
            .checked_add(input.bytes)
            .context("locked byte count overflow")?;
        ensure!(total <= MAX_TOTAL, "locked package byte budget");
        digest.update(input.path.as_bytes());
        digest.update([0]);
        digest.update(input.bytes.to_string().as_bytes());
        digest.update([0]);
        digest.update(input.digest.as_bytes());
        digest.update(b"\n");
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn package_inputs(root: &Path, package: &LockedPackage) -> Result<BTreeMap<String, Vec<u8>>> {
    ensure!(
        manifest_digest(&package.inputs)? == package.digest,
        "locked input manifest mismatch"
    );
    package
        .inputs
        .iter()
        .map(|input| {
            let bytes = checked(root, &input.path)?;
            ensure!(
                bytes.len() == input.bytes && sha(&bytes) == input.digest,
                "locked input changed: {}",
                input.path
            );
            Ok((input.path.clone(), bytes))
        })
        .collect()
}

fn capture_package(inputs: &BTreeMap<String, Vec<u8>>, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    for (path, bytes) in inputs {
        let output = target.join(path);
        fs::create_dir_all(output.parent().context("locked input parent")?)?;
        fs::write(output, bytes)?;
    }
    Ok(())
}
fn target_key() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("macos-aarch64"),
        ("macos", "x86_64") => Ok("macos-x86_64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        _ => bail!("unsupported UI adapter host target"),
    }
}
fn pin_digest(pin: &Pin, path: &Path) -> Result<(Vec<u8>, String)> {
    ensure!(
        pin.schema_version == 1 && pin.assembly_protocol == 2 && pin.binding_abi == 2,
        "unsupported UI adapter pin protocol/runtime ABI"
    );
    let target = pin
        .targets
        .get(target_key()?)
        .context("UI adapter pin has no target executable")?;
    ensure!(
        valid_digest(&target.digest),
        "invalid UI adapter executable digest"
    );
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= MAX_FILE as u64 * 64,
        "invalid UI adapter executable"
    );
    let bytes = day2::assets::read_regular(path, MAX_FILE as u64 * 64)?;
    ensure!(
        sha(&bytes) == target.digest,
        "UI adapter executable digest mismatch"
    );
    Ok((bytes, target.digest.clone()))
}

fn lock_present(captured: &Path) -> Result<bool> {
    match fs::symlink_metadata(captured.join(LOCK)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Production entry point; opt-in and intentionally unavailable without a valid local pin.
pub fn expand(
    app_source: &Path,
    captured: &Path,
    hashes: &mut BTreeMap<String, String>,
) -> Result<()> {
    if !lock_present(captured)? {
        return Ok(());
    }
    let pin = std::env::var_os("DAY2_UI_PROVIDER_PIN_JSON").context(
        "UI assembly is opt-in: set DAY2_UI_PROVIDER_PIN_JSON to an operator-trusted executable pin",
    )?;
    expand_with_pin(app_source, captured, hashes, Path::new(&pin))
}

/// Testable explicit-pin variant; production callers must use `expand` above.
pub fn expand_with_pin(
    app_source: &Path,
    captured: &Path,
    hashes: &mut BTreeMap<String, String>,
    pin_path: &Path,
) -> Result<()> {
    let lock_path = captured.join(LOCK);
    if !lock_present(captured)? {
        // Ordinary apps are unchanged. Their existing HTML/template admission
        // rejects unsupported tags; this port must not inspect unrelated JS/images.
        return Ok(());
    }
    let lock = parse_lock(&lock_path)?;
    let root = package_root(app_source, &lock)?;
    let actual_inputs = package_inputs(&root, &lock.package)?;
    let pin_meta = fs::symlink_metadata(pin_path).context("inspect explicit UI adapter pin")?;
    ensure!(
        pin_meta.is_file()
            && !pin_meta.file_type().is_symlink()
            && pin_meta.len() <= MAX_FILE as u64,
        "invalid/oversized UI adapter pin"
    );
    let pin_bytes = day2::assets::read_regular(pin_path, MAX_FILE as u64)
        .context("read explicit UI adapter pin")?;
    ensure!(
        pin_bytes.len() <= MAX_FILE,
        "UI adapter pin grew beyond limit"
    );
    let pin: Pin = serde_json::from_slice(&pin_bytes).context("parse strict UI adapter pin")?;
    ensure!(
        pin.provider == lock.provider,
        "UI provider pin identity mismatch"
    );
    let target = pin
        .targets
        .get(target_key()?)
        .context("UI adapter pin has no target executable")?;
    let declared_exe = PathBuf::from(&target.executable);
    ensure!(
        !target.executable.is_empty(),
        "empty UI adapter executable path"
    );
    let exe_path = if declared_exe.is_absolute() {
        declared_exe
    } else {
        pin_path
            .parent()
            .context("adapter pin has no parent directory")?
            .join(declared_exe)
    };
    let (exe, exe_digest) = pin_digest(&pin, &exe_path)?;
    let temp = tempfile::Builder::new()
        .prefix("day2-ui-adapter-")
        .tempdir()
        .context("create private adapter directory")?;
    let private_exe = temp.path().join("adapter");
    fs::write(&private_exe, exe)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private_exe, fs::Permissions::from_mode(0o700))?;
    }
    let private_ui = temp.path().join("ui");
    copy_tree_checked(&captured.join("ui"), &private_ui)?;
    let private_package = temp.path().join("package");
    capture_package(&actual_inputs, &private_package)?;
    let mut request_package = lock.package.clone();
    request_package.path = private_package
        .to_str()
        .context("private package path is not UTF-8")?
        .into();
    let request = AssemblyRequest {
        schema_version: 1,
        assembly_protocol: 2,
        provider: lock.provider.clone(),
        target: AssemblyTarget {
            binding_abi: 2,
            template_engine: "minijinja-2.12.0".into(),
        },
        package: request_package,
        ui: private_ui
            .to_str()
            .context("private UI path is not UTF-8")?
            .into(),
    };
    let adapter = ProcessAssembler {
        executable: &private_exe,
        timeout: Duration::from_secs(60),
    };
    assemble_and_stage(&adapter, &request, &lock, &actual_inputs, captured, hashes)?;
    hashes.insert("ui-provider/executable".into(), exe_digest);
    Ok(())
}

/// Application boundary shared by production and deterministic port simulations.
/// Simulation replaces the external provider only; admission/staging is real.
fn assemble_and_stage(
    adapter: &dyn UiAssembler,
    request: &AssemblyRequest,
    lock: &Lock,
    actual_inputs: &BTreeMap<String, Vec<u8>>,
    captured: &Path,
    hashes: &mut BTreeMap<String, String>,
) -> Result<()> {
    let env = adapter.assemble(request)?;
    ensure!(
        env.schema_version == 1
            && env.ok
            && env.command == "assemble"
            && env.diagnostics.is_empty(),
        "invalid UI assembly outcome"
    );
    validate_bundle(&env.data, lock, actual_inputs, captured, hashes)?;
    apply_bundle(&env.data, actual_inputs, captured)?;
    hashes.insert(PACKAGE_KEY.into(), lock.package.digest.clone());
    for input in &env.data.inputs {
        if input.path.starts_with("ui/") {
            hashes.insert(
                format!("ui-source/app/{}", input.path),
                input.digest.clone(),
            );
        }
    }
    for t in env.data.templates.keys() {
        hashes.insert(format!("app/ui/{t}"), sha(env.data.templates[t].as_bytes()));
    }
    for r in &env.data.resources {
        hashes.insert(format!("app/{}", r.path), r.digest.clone());
    }
    Ok(())
}

fn copy_tree_checked(source: &Path, target: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(source).context("captured UI directory missing")?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "invalid captured UI root"
    );
    fs::create_dir(target)?;
    let mut stack = vec![(source.to_path_buf(), target.to_path_buf())];
    let mut count = 0usize;
    let mut total = 0usize;
    while let Some((src, dst)) = stack.pop() {
        for e in fs::read_dir(src)? {
            let e = e?;
            let ty = e.file_type()?;
            ensure!(!ty.is_symlink(), "captured UI symlink forbidden");
            count += 1;
            ensure!(count <= MAX_FILES, "captured UI file budget exceeded");
            let out = dst.join(e.file_name());
            if ty.is_dir() {
                fs::create_dir(&out)?;
                stack.push((e.path(), out));
            } else {
                ensure!(ty.is_file(), "special UI input forbidden");
                let meta = fs::symlink_metadata(e.path())?;
                ensure!(
                    meta.is_file() && meta.len() <= MAX_UI_FILE as u64,
                    "captured UI file exceeds limit"
                );
                let b = day2::assets::read_regular(&e.path(), MAX_UI_FILE as u64)?;
                ensure!(b.len() <= MAX_UI_FILE, "captured UI file grew beyond limit");
                total += b.len();
                ensure!(total <= MAX_TOTAL, "captured UI byte budget exceeded");
                fs::write(out, b)?;
            }
        }
    }
    Ok(())
}
fn run_adapter_with_timeout(
    exe: &Path,
    request: &Path,
    ui: &Path,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut cmd = Command::new(exe);
    cmd.arg("assemble")
        .arg("--request")
        .arg(request)
        .current_dir(ui)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("start pinned UI adapter")?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out_thread = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stdout.take((MAX_STDOUT + 1) as u64).read_to_end(&mut b);
        b
    });
    let err_thread = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stderr.take((MAX_STDERR + 1) as u64).read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let mut status = None;
    loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        // A provider descendant may keep inherited pipes open after the direct child exits.
        // The same deadline must cover output draining; joining early would bypass it.
        if let Some(status) = status
            && out_thread.is_finished()
            && err_thread.is_finished()
        {
            let out = out_thread
                .join()
                .map_err(|_| anyhow!("adapter stdout reader failed"))?;
            let err = err_thread
                .join()
                .map_err(|_| anyhow!("adapter stderr reader failed"))?;
            if out.len() > MAX_STDOUT || err.len() > MAX_STDERR {
                return Err(
                    AssemblyFailure::InvalidResponse("output budget exceeded".into()).into(),
                );
            }
            if !status.success() {
                return Err(AssemblyFailure::ProviderRejected(adapter_failure(&out, &err)).into());
            }
            return Ok(out);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            // Never block on inherited pipes at this point. Their readers retain bounded
            // buffers; operator-approved provider execution is not hostile-code containment.
            return Err(AssemblyFailure::Timeout.into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}
/// The adapter reports structured diagnostics on stdout; stderr is often empty.
fn adapter_failure(out: &[u8], err: &[u8]) -> String {
    let mut parts: Vec<String> = serde_json::from_slice::<serde_json::Value>(out)
        .ok()
        .and_then(|v| v["diagnostics"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .take(20)
        .map(|d| {
            format!(
                "{} {}",
                d["code"].as_str().unwrap_or(""),
                d["message"].as_str().unwrap_or("")
            )
            .trim()
            .to_string()
        })
        .filter(|line| !line.is_empty())
        .collect();
    let stderr = String::from_utf8_lossy(err).trim().to_string();
    if !stderr.is_empty() {
        parts.push(stderr);
    }
    if parts.is_empty() {
        "no diagnostics".into()
    } else {
        parts.join("; ")
    }
}

fn validate_bundle(
    b: &Bundle,
    lock: &Lock,
    package: &BTreeMap<String, Vec<u8>>,
    captured: &Path,
    captured_hashes: &BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        b.schema_version == 1
            && b.runtime_abi == 2
            && b.template_engine == "minijinja-2.12.0"
            && b.package_digest == lock.package.digest,
        "UI adapter package digest/schema/runtime ABI/template engine mismatch"
    );
    let mut inputmap = BTreeMap::new();
    let mut total = 0usize;
    ensure!(b.inputs.len() <= MAX_INPUTS, "input count exceeded");
    for i in &b.inputs {
        ensure!(
            i.bytes <= MAX_FILE && valid_digest(&i.digest) && safe_rel(&i.path),
            "invalid bundle input"
        );
        ensure!(
            inputmap.insert(i.path.clone(), i).is_none(),
            "duplicate bundle input"
        );
        let bytes = if let Some(p) = i.path.strip_prefix("package/") {
            package
                .get(p)
                .cloned()
                .context("input is not a locked package source")?
        } else if let Some(p) = i.path.strip_prefix("ui/") {
            checked(&captured.join("ui"), p)?
        } else {
            bail!("unsupported bundle input source")
        };
        ensure!(
            bytes.len() == i.bytes && sha(&bytes) == i.digest,
            "bundle input bytes/digest mismatch: {}",
            i.path
        );
        total += bytes.len();
        ensure!(total <= MAX_TOTAL, "bundle input byte budget exceeded");
    }
    for path in package.keys() {
        ensure!(
            inputmap.contains_key(&format!("package/{path}")),
            "adapter omitted a locked package input: {path}"
        );
    }
    let template_names = b.templates.keys().cloned().collect::<BTreeSet<_>>();
    let mut output_names = BTreeSet::new();
    for path in b
        .templates
        .keys()
        .map(|path| format!("ui/{path}"))
        .chain(b.resources.iter().map(|resource| resource.path.clone()))
    {
        ensure!(
            path.to_ascii_lowercase() != LOCK,
            "UI lock is not a provider output"
        );
        ensure!(
            output_names.insert(path.to_ascii_lowercase()),
            "case-colliding UI outputs"
        );
    }
    for path in &output_names {
        for ancestor in path.match_indices('/').map(|(offset, _)| &path[..offset]) {
            ensure!(
                !output_names.contains(ancestor),
                "overlapping UI output paths"
            );
        }
    }
    ensure!(b.templates.len() <= MAX_FILES, "invalid template set");
    let expanded_bytes = b
        .templates
        .values()
        .try_fold(0usize, |total, html| total.checked_add(html.len()))
        .context("expanded template byte count overflow")?;
    ensure!(
        expanded_bytes <= MAX_TOTAL,
        "expanded template byte budget exceeded"
    );
    for (p, html) in &b.templates {
        ensure!(
            safe_rel(p)
                && (p.starts_with("pages/") || p.starts_with("components/"))
                && p.ends_with(".html")
                && html.len() <= MAX_FILE,
            "invalid expanded template"
        );
        ensure!(
            inputmap.contains_key(&format!("ui/{p}")),
            "template source was not captured: {p}"
        );
        // These are symbolic templates, not rendered HTML. Ordinary Native
        // template/type/form admission follows staging; rendered-HTML checks
        // cannot run here without rejecting valid route/asset expressions.
    }
    let mut outs = BTreeSet::new();
    ensure!(b.resources.len() <= MAX_FILES, "resource count exceeded");
    let mut resource_total = 0usize;
    for r in &b.resources {
        ensure!(
            safe_rel(&r.path)
                && r.path.starts_with("ui/")
                && r.bytes <= MAX_FILE
                && valid_digest(&r.digest),
            "invalid resource"
        );
        ensure!(
            ["stylesheet", "module", "font", "metadata"].contains(&r.kind.as_str()),
            "unknown resource kind"
        );
        ensure!(
            r.source.is_some() != r.content.is_some(),
            "resource needs exactly one source/content"
        );
        let bytes = if let Some(src) = &r.source {
            let k = format!("package/{src}");
            ensure!(safe_rel(src), "unsafe resource source");
            ensure!(
                inputmap.contains_key(&k),
                "resource source absent from bundle inputs"
            );
            package
                .get(src)
                .cloned()
                .context("resource source outside verified package")?
        } else {
            r.content.as_ref().unwrap().as_bytes().to_vec()
        };
        ensure!(
            bytes.len() == r.bytes && sha(&bytes) == r.digest,
            "resource digest/length mismatch: {}",
            r.path
        );
        ensure!(outs.insert(r.path.clone()), "duplicate resource path");
        resource_total = resource_total.saturating_add(bytes.len());
        ensure!(resource_total <= MAX_TOTAL, "resource byte budget exceeded");
    }
    for a in &outs {
        for c in &outs {
            if a != c {
                ensure!(
                    !a.starts_with(&format!("{c}/")) && !c.starts_with(&format!("{a}/")),
                    "overlapping resource paths"
                );
            }
        }
    }
    for template in &template_names {
        let path = format!("ui/{template}");
        for resource in &outs {
            ensure!(
                path != *resource
                    && !path.starts_with(&format!("{resource}/"))
                    && !resource.starts_with(&format!("{path}/")),
                "template/resource output collision: {path} / {resource}"
            );
        }
    }
    let mut consumed = BTreeSet::new();
    for p in &b.consumed_inputs {
        ensure!(
            p.starts_with("ui/")
                && p.to_ascii_lowercase() != LOCK
                && inputmap.contains_key(p)
                && consumed.insert(p.clone()),
            "invalid/duplicate consumed input"
        );
    }
    // Every template and claimed adapter UI input must match the original host
    // snapshot. Unused app resources are left to normal resource admission.
    let mut stack = vec![(captured.join("ui"), String::new())];
    let mut scanned = 0usize;
    while let Some((dir, prefix)) = stack.pop() {
        for e in fs::read_dir(&dir)? {
            let e = e?;
            let ty = e.file_type()?;
            ensure!(!ty.is_symlink(), "captured UI symlink forbidden");
            scanned += 1;
            ensure!(scanned <= MAX_FILES, "captured UI source count exceeded");
            let name = e
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("non-UTF8 UI source path"))?;
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if ty.is_dir() {
                stack.push((e.path(), rel));
                continue;
            }
            ensure!(ty.is_file(), "special captured UI source forbidden");
            if rel == "ui.lock.json" {
                continue;
            }
            if (rel.starts_with("pages/") || rel.starts_with("components/"))
                && rel.ends_with(".html")
            {
                ensure!(
                    template_names.contains(&rel),
                    "CLI omitted captured template {rel}"
                );
            }
            let key = format!("ui/{rel}");
            let Some(input) = inputmap.get(&key) else {
                // Unused app JS/images remain captured host inputs, not adapter
                // inputs. The CLI cannot overwrite them through this omission.
                continue;
            };
            let source = checked(&captured.join("ui"), &rel)?;
            ensure!(
                source.len() == input.bytes && sha(&source) == input.digest,
                "UI source changed after capture: {key}"
            );
            let original = captured_hashes.get(&format!("app/{key}"));
            ensure!(
                original.is_some_and(|d| d == &input.digest),
                "captured source hash differs from snapshot manifest: {key}"
            );
        }
    }
    Ok(())
}
fn check_output_path(root: &Path, relative: &str) -> Result<()> {
    ensure!(safe_rel(relative), "unsafe output path: {relative}");
    let parts = relative.split('/').collect::<Vec<_>>();
    let mut path = root.to_path_buf();
    for (index, part) in parts.iter().enumerate() {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                ensure!(
                    !meta.file_type().is_symlink(),
                    "output ancestor symlink forbidden: {}",
                    path.display()
                );
                if index + 1 < parts.len() {
                    ensure!(
                        meta.is_dir(),
                        "output parent is not a directory: {}",
                        path.display()
                    );
                } else {
                    ensure!(
                        meta.is_file(),
                        "output target is not a regular file: {}",
                        path.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn apply_bundle(b: &Bundle, package: &BTreeMap<String, Vec<u8>>, captured: &Path) -> Result<()> {
    let ui = captured.join("ui");
    let mut writes = BTreeMap::<String, Vec<u8>>::new();
    for (p, html) in &b.templates {
        writes.insert(format!("ui/{p}"), html.as_bytes().to_vec());
    }
    for r in &b.resources {
        let bytes = if let Some(content) = &r.content {
            content.as_bytes().to_vec()
        } else {
            package
                .get(r.source.as_deref().unwrap())
                .context("missing verified resource snapshot")?
                .clone()
        };
        writes.insert(r.path.clone(), bytes);
    }
    // Validate every target/collision before the first mutation.
    for (path, bytes) in &writes {
        let rel = path.strip_prefix("ui/").context("output outside ui")?;
        check_output_path(&ui, rel)?;
        if fs::symlink_metadata(ui.join(rel)).is_ok() {
            let existing = checked(&ui, rel)?;
            if b.templates.contains_key(rel) {
                let input_path = format!("ui/{rel}");
                let input = b
                    .inputs
                    .iter()
                    .find(|i| i.path == input_path)
                    .context("template overwrite is not a captured input")?;
                ensure!(
                    sha(&existing) == input.digest,
                    "captured template changed before overwrite: {rel}"
                );
            } else if path == "ui/app.css" {
                let input = b
                    .inputs
                    .iter()
                    .find(|i| i.path == "ui/app.css")
                    .context("app.css overwrite is not a captured input")?;
                ensure!(
                    sha(&existing) == input.digest,
                    "captured app.css changed before overwrite"
                );
            } else {
                ensure!(&existing == bytes, "managed resource collision: {path}");
            }
        }
    }
    for p in &b.consumed_inputs {
        let rel = p.strip_prefix("ui/").unwrap();
        let source = checked(&ui, rel)?;
        let input = b.inputs.iter().find(|i| i.path == *p).unwrap();
        ensure!(sha(&source) == input.digest, "consumed input changed: {p}");
        ensure!(
            !writes.contains_key(p),
            "consumed input collides with output: {p}"
        );
    }
    for (path, bytes) in writes {
        let rel = path.strip_prefix("ui/").unwrap();
        let target = ui.join(rel);
        if target.exists() {
            let existing = checked(&ui, rel)?;
            if existing == bytes {
                continue;
            }
        }
        let parent = target.parent().context("invalid output parent")?;
        fs::create_dir_all(parent)?;
        fs::write(target, bytes)?;
    }
    for p in &b.consumed_inputs {
        let rel = p.strip_prefix("ui/").unwrap();
        fs::remove_file(ui.join(rel))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "ui_assembly/tests.rs"]
mod isolatedtests;

#[cfg(test)]
#[path = "ui_assembly/manifest_tests.rs"]
mod manifest_tests;

#[cfg(test)]
#[path = "ui_assembly/port_tests.rs"]
mod port_tests;

#[cfg(test)]
#[path = "ui_assembly/external_tests.rs"]
mod external_tests;
