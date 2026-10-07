//! Transport for private Roc operational workflows. This module does not choose
//! recipes or interpret shell commands. The caller supplies a closed capability
//! dispatcher; each native operation retains its own admission and atomicity.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

const MAX_MESSAGE: u64 = 16 * 1024 * 1024;
const MAX_EFFECTS: usize = 4096;

// Explicitly catalog the private package, as we do for the public SDK. Changes
// invalidate both the executable cache and centralized CI recipe identity.
pub const SOURCES: &[(&str, &[u8])] = &[
    ("ops/Runner.roc", include_bytes!("../../../ops/Runner.roc")),
    ("ops/main.roc", include_bytes!("../../../ops/main.roc")),
    (
        "ops/Workflow.roc",
        include_bytes!("../../../ops/Workflow.roc"),
    ),
    (
        "ops/Capability.roc",
        include_bytes!("../../../ops/Capability.roc"),
    ),
    ("ops/Build.roc", include_bytes!("../../../ops/Build.roc")),
    (
        "ops/AppCreate.roc",
        include_bytes!("../../../ops/AppCreate.roc"),
    ),
    (
        "ops/Delegation.roc",
        include_bytes!("../../../ops/Delegation.roc"),
    ),
    ("ops/Check.roc", include_bytes!("../../../ops/Check.roc")),
    (
        "ops/LocalDev.roc",
        include_bytes!("../../../ops/LocalDev.roc"),
    ),
    ("ops/Backup.roc", include_bytes!("../../../ops/Backup.roc")),
    (
        "ops/Maintain.roc",
        include_bytes!("../../../ops/Maintain.roc"),
    ),
    (
        "ops/Authority.roc",
        include_bytes!("../../../ops/Authority.roc"),
    ),
    ("ops/Infra.roc", include_bytes!("../../../ops/Infra.roc")),
    (
        "ops/Provision.roc",
        include_bytes!("../../../ops/Provision.roc"),
    ),
    ("ops/Ci.roc", include_bytes!("../../../ops/Ci.roc")),
    ("ops/Verify.roc", include_bytes!("../../../ops/Verify.roc")),
    ("ops/Linux.roc", include_bytes!("../../../ops/Linux.roc")),
    (
        "ops/Simulation.roc",
        include_bytes!("../../../ops/Simulation.roc"),
    ),
    (
        "ops/ProviderConformance.roc",
        include_bytes!("../../../ops/ProviderConformance.roc"),
    ),
    (
        "ops/OAuthRegistration.roc",
        include_bytes!("../../../ops/OAuthRegistration.roc"),
    ),
    (
        "ops/Release.roc",
        include_bytes!("../../../ops/Release.roc"),
    ),
    (
        "ops/GkeRelease.roc",
        include_bytes!("../../../ops/GkeRelease.roc"),
    ),
    (
        "ops/SecretRetirement.roc",
        include_bytes!("../../../ops/SecretRetirement.roc"),
    ),
    ("infra/main.roc", include_bytes!("../../../infra/main.roc")),
    (
        "infra/Stack.roc",
        include_bytes!("../../../infra/Stack.roc"),
    ),
];

pub fn source_digest() -> String {
    crate::digest(
        &SOURCES
            .iter()
            .flat_map(|(name, bytes)| [name.as_bytes(), b"\0", *bytes, b"\0"].concat())
            .collect::<Vec<_>>(),
    )
}

/// A workflow built with another compiler must not satisfy the executable cache.
pub fn toolchain_digest() -> String {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    let pin = include_bytes!("../../../toolchains/linux-aarch64.json").as_slice();
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let pin = include_bytes!("../../../toolchains/linux-x86_64.json").as_slice();
    #[cfg(not(target_os = "linux"))]
    let pin = include_bytes!("../../../toolchain.json").as_slice();
    crate::digest(pin)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Distribution {
    pub sources: String,
    pub toolchain: String,
    pub executable: String,
}

pub fn checked_runner(executable: &Path) -> Result<PathBuf> {
    let pin: Distribution = crate::json::decode(&fs::read(executable.with_extension("json"))?)?;
    ensure!(
        pin.sources == source_digest(),
        "Roc workflow sources changed; run xtask workflows"
    );
    ensure!(
        pin.toolchain == toolchain_digest(),
        "Roc workflow compiler changed; run xtask workflows"
    );
    ensure!(
        pin.executable == crate::digest(&fs::read(executable)?),
        "Roc workflow executable changed"
    );
    executable.canonicalize().context("workflow executable")
}

pub fn runner() -> Result<PathBuf> {
    checked_runner(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/day2-workflows"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: u32,
    pub action: String,
    pub input: String,
}

impl Request {
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        ensure!(
            self.protocol == 1 && self.input.len() <= MAX_MESSAGE as usize,
            "workflow protocol or input budget"
        );
        crate::json::decode(self.input.as_bytes())
    }
}

struct Supervised(Child);

impl Drop for Supervised {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn run(
    executable: &Path,
    arguments: &[&str],
    mut effect: impl FnMut(Request) -> Result<Value>,
) -> Result<Value> {
    supervise(executable, arguments, &mut effect, false)
}

/// Interactive operator sessions retain bounded messages and computation, but
/// may wait for edits and shutdown for the lifetime of a development session.
pub fn run_interactive(
    executable: &Path,
    arguments: &[&str],
    mut effect: impl FnMut(Request) -> Result<Value>,
) -> Result<Value> {
    supervise(executable, arguments, &mut effect, true)
}

fn supervise(
    executable: &Path,
    arguments: &[&str],
    effect: &mut impl FnMut(Request) -> Result<Value>,
    interactive: bool,
) -> Result<Value> {
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = Supervised(command.spawn().context("start Roc workflow")?);
    let mut input = child.0.stdin.take().context("workflow stdin")?;
    let output = child.0.stdout.take().context("workflow stdout")?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(output);
        loop {
            let mut bytes = Vec::new();
            let result = reader
                .by_ref()
                .take(MAX_MESSAGE + 1)
                .read_until(b'\n', &mut bytes);
            let done = !result.as_ref().is_ok_and(|count| *count != 0)
                || bytes.len() > MAX_MESSAGE as usize;
            if sender.send((result, bytes)).is_err() || done {
                break;
            }
        }
    });
    let mut effects = 0_usize;
    loop {
        ensure!(
            interactive || effects < MAX_EFFECTS,
            "Roc workflow effect budget exceeded"
        );
        effects = effects.saturating_add(1);
        // Native effects enforce their own deadlines. Roc gets ten seconds of
        // computation between effects; output cannot grow without backpressure.
        let (read, bytes) = receiver
            .recv_timeout(Duration::from_secs(10))
            .context("Roc workflow stalled")?;
        ensure!(
            read? > 0 && bytes.len() <= MAX_MESSAGE as usize,
            "workflow closed or exceeded message budget"
        );
        let request: Request = crate::json::decode(&bytes)?;
        ensure!(request.protocol == 1, "unknown workflow protocol");
        match request.action.as_str() {
            "complete" | "failed" => {
                let started = Instant::now();
                let status = loop {
                    if let Some(status) = child.0.try_wait()? {
                        break status;
                    }
                    ensure!(
                        started.elapsed() < Duration::from_secs(2),
                        "workflow did not exit"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                };
                ensure!(status.success(), "workflow process failed");
                ensure!(request.action == "complete", "{}", request.input);
                return crate::json::decode(request.input.as_bytes());
            }
            _ => {
                let response = match effect(request) {
                    Ok(value) => {
                        json!({"protocol":1,"ok":true,"result":value.to_string(),"error":""})
                    }
                    Err(error) => {
                        json!({"protocol":1,"ok":false,"result":"","error":format!("{error:#}")})
                    }
                };
                let response = serde_json::to_vec(&response)?;
                ensure!(
                    response.len() <= MAX_MESSAGE as usize,
                    "native response exceeds workflow budget"
                );
                input.write_all(&response)?;
                input.write_all(b"\n")?;
                input.flush()?;
            }
        }
    }
}
