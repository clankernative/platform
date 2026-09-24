//! Real CLI/watch smoke test. Run after `xtask cli`, outside xtask's build lock:
//! cargo test --locked -p day2-ops --test local_dev_cli -- --ignored
use anyhow::{Context, Result, ensure};
use reqwest::{StatusCode, blocking::Client, redirect::Policy};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

struct Dev {
    root: Option<tempfile::TempDir>,
    source: PathBuf,
    state: PathBuf,
    cli: PathBuf,
    sequence: usize,
    running: bool,
    success: bool,
}

impl Dev {
    fn new() -> Result<Self> {
        let platform = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let cli = platform.join("cli/day2");
        ensure!(cli.is_file(), "build the CLI with xtask cli first");
        let root = tempfile::Builder::new()
            .prefix("d2cli-")
            .tempdir_in("/tmp")?;
        let source = root.path().join("reports");
        copy_source(&platform.join("examples/reports"), &source)?;
        Ok(Self {
            state: root.path().join("state"),
            root: Some(root),
            source,
            cli,
            sequence: 0,
            running: false,
            success: false,
        })
    }

    fn command(&mut self, args: &[&str]) -> Result<String> {
        self.sequence += 1;
        let log = self
            .root
            .as_ref()
            .context("test directory")?
            .path()
            .join(format!("command-{}.log", self.sequence));
        day2_ops::process::run(
            Command::new(&self.cli)
                .args(["platform", "local-dev", "--directory"])
                .arg(&self.state)
                .args(args),
            &self.source,
            &log,
            Duration::from_secs(660),
        )?;
        Ok(fs::read_to_string(log)?)
    }

    fn status_command(&mut self, args: &[&str]) -> Result<Value> {
        let output = self.command(args)?;
        output
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str(line).ok())
            .context("CLI JSON result")
    }

    fn events(&self) -> Result<Vec<Value>> {
        // The final record may still be in the writer's buffer.
        Ok(fs::read_to_string(self.state.join("events.jsonl"))?
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect())
    }

    fn await_event(&self, offset: usize, event: &str) -> Result<()> {
        let start = Instant::now();
        loop {
            if self
                .events()?
                .iter()
                .skip(offset)
                .any(|record| record["event"] == event)
            {
                return Ok(());
            }
            ensure!(
                start.elapsed() < Duration::from_secs(300),
                "timed out waiting for {event}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn stop(&mut self) -> Result<()> {
        let result = self.status_command(&["--stop"])?;
        ensure!(
            result["stopping"] == true || result["stopped"] == true,
            "session did not stop"
        );
        self.running = false;
        assert_eq!(self.status_command(&["--status"])?["running"], false);
        Ok(())
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        if self.running
            && let Err(error) = self.stop()
        {
            // Keep state available for native --stop if the test was interrupted.
            if let Some(root) = self.root.take() {
                eprintln!(
                    "local-dev cleanup failed ({error:#}); state retained in {}",
                    root.keep().display()
                );
            }
        }
        if !self.success
            && let Some(root) = self.root.take()
        {
            eprintln!(
                "local-dev test evidence retained in {}",
                root.keep().display()
            );
        }
    }
}

fn copy_source(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let kind = entry.file_type()?;
        let output = target.join(entry.file_name());
        if kind.is_dir() {
            copy_source(&entry.path(), &output)?;
        } else {
            ensure!(kind.is_file(), "regular app input required");
            fs::copy(entry.path(), output)?;
        }
    }
    Ok(())
}

fn sign_in(status: &Value) -> Result<Client> {
    let origin = status["origin"].as_str().context("origin")?;
    let login = reqwest::Url::parse(status["login_url"].as_str().context("login URL")?)?;
    let client = Client::builder()
        .no_proxy()
        .cookie_store(true)
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    assert_eq!(client.get(login.clone()).send()?.status(), StatusCode::OK);
    let response = client
        .post(format!("{origin}/login"))
        .header("Origin", origin)
        .form(&login.query_pairs().collect::<Vec<_>>())
        .send()?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    Ok(client)
}

fn page(client: &Client, origin: &str) -> Result<String> {
    let response = client.get(format!("{origin}/")).send()?;
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.text()?;
    assert!(html.contains("Weekly report") && html.contains("Release notes"));
    assert!(html.contains("2 on this page"));
    Ok(html)
}

#[test]
#[ignore = "requires xtask cli and exclusive access to the platform build lock"]
fn cli_watches_source_keeps_http_on_errors_and_preserves_login_data_and_port() -> Result<()> {
    let mut dev = Dev::new()?;
    dev.running = true;
    let first = dev.status_command(&[
        "--example",
        "demo",
        "--actor",
        "local@example.test",
        "--detach",
    ])?;
    assert_eq!(first["state"], "ready");
    assert_eq!(first["watch"], true);
    let client = sign_in(&first)?;
    let origin = first["origin"].as_str().context("origin")?;
    assert!(page(&client, origin)?.contains("Document reports"));
    let instance = Path::new(first["instance"].as_str().context("instance")?);
    let original_rows = day2::store::Runtime::load(instance, "app")?.inspect()?;
    let offset = dev.events()?.len();
    let app = dev.source.join("App.roc");
    let valid = fs::read(&app)?;
    fs::write(&app, b"invalid syntax = ->\n")?;
    dev.await_event(offset, "rebuild-failed")?;
    assert!(page(&client, origin)?.contains("Document reports"));
    assert_eq!(
        dev.status_command(&["--status"])?["instance"],
        first["instance"]
    );
    let offset = dev.events()?.len();
    let template = dev.source.join("ui/pages/directory.html");
    let html = fs::read_to_string(&template)?;
    ensure!(
        html.contains("Document reports"),
        "Reports heading changed; update smoke assertion"
    );
    fs::write(
        &template,
        html.replace("Document reports", "Reports after local rebuild"),
    )?;
    fs::write(&app, valid)?;
    dev.await_event(offset, "ready")?;
    let rebuilt = dev.status_command(&["--status"])?;
    assert_eq!(rebuilt["port"], first["port"]);
    assert_ne!(rebuilt["artifact"], first["artifact"]);
    assert_ne!(rebuilt["instance"], first["instance"]);
    assert!(page(&client, origin)?.contains("Reports after local rebuild"));
    assert_eq!(
        day2::store::Runtime::load(
            Path::new(rebuilt["instance"].as_str().context("instance")?),
            "app"
        )?
        .inspect()?,
        original_rows
    );
    let logs = dev.command(&["--logs"])?;
    assert!(logs.contains("rebuild-failed") && logs.contains("migration-checked"));
    dev.stop()?;
    assert!(client.get(format!("{origin}/")).send().is_err());
    dev.running = true;
    let restarted = dev.status_command(&["--detach"])?;
    assert_eq!(restarted["actor"], first["actor"]);
    assert_eq!(restarted["port"], first["port"]);
    assert!(page(&client, origin)?.contains("Reports after local rebuild"));
    assert_eq!(
        day2::store::Runtime::load(
            Path::new(restarted["instance"].as_str().context("instance")?),
            "app"
        )?
        .inspect()?,
        original_rows
    );
    dev.stop()?;
    dev.success = true;
    Ok(())
}
