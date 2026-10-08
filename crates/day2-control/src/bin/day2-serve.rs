//! Container entrypoint.
//!
//! Two forms, and which one an installation may use is decided by its instance,
//! not by the argument: `--edge` serves behind the installation's identity
//! provider and requires one to be declared; `--development-auth` prints a
//! one-use sign-in link and is refused when one is.

use anyhow::{Context, Result, ensure};
use std::{num::NonZeroU16, path::PathBuf, time::Duration};

fn run() -> Result<()> {
    let mut arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let app_calls = if arguments.len() == 5 && arguments[3] == "--app-calls" {
        let path = PathBuf::from(arguments.pop().context("app call configuration")?);
        arguments.pop();
        Some(path)
    } else {
        None
    };
    let usage = "usage: day2-serve INSTANCE APP --edge\n       day2-serve INSTANCE APP --development-auth ACTOR --published-port PORT";
    ensure!(arguments.len() >= 3, "{usage}");
    let instance = PathBuf::from(&arguments[0]);
    let app = arguments[1].to_str().context("app must be UTF-8")?;
    let actor;
    let access = if arguments.len() == 3 && arguments[2] == "--edge" {
        day2::deployment::Access::Edge
    } else {
        ensure!(app_calls.is_none(), "app calls require edge authentication");
        ensure!(
            arguments.len() == 6
                && arguments[2] == "--development-auth"
                && arguments[4] == "--published-port",
            "{usage}"
        );
        actor = arguments[3].to_str().context("actor must be UTF-8")?;
        ensure!(
            !actor.is_empty() && actor.len() <= 256,
            "invalid development actor"
        );
        let published_port: NonZeroU16 = arguments[5]
            .to_str()
            .context("port must be UTF-8")?
            .parse()?;
        day2::deployment::Access::Development {
            actor,
            published_port,
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let result = runtime.block_on(day2::deployment::serve_with(
        &instance,
        app,
        access,
        move |runtime| match app_calls {
            Some(path) => day2_control::app_host::configure(runtime, &path),
            None => Ok(runtime),
        },
    ));
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

fn main() {
    if let Err(error) = run() {
        eprintln!("day2-serve refused or stopped: {error:#}");
        std::process::exit(1);
    }
}
