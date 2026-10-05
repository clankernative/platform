//! Dedicated GKE shell entrypoint. All identity, clients and bounds are selected
//! by the instance; arguments cannot choose credentials, callbacks or readiness.
use anyhow::{Result, ensure};
use std::{path::PathBuf, time::Duration};

fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(arguments.len() == 1, "usage: day2-security-shell INSTANCE");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let result = runtime.block_on(day2::deployment::serve_security_shell(&PathBuf::from(
        &arguments[0],
    )));
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

fn main() {
    if run().is_err() {
        // Startup and provider errors can contain private configuration. The
        // shell exposes a bounded refusal, never a provider error description.
        eprintln!("day2-security-shell refused or stopped");
        std::process::exit(1);
    }
}
