//! Container entrypoint.
//!
//! Two forms, and which one an installation may use is decided by its instance,
//! not by the argument: `--edge` serves behind the installation's identity
//! provider and requires one to be declared; `--development-auth` prints a
//! one-use sign-in link and is refused when one is.

use anyhow::{Context, Result, ensure};
use std::{num::NonZeroU16, path::PathBuf, time::Duration};

enum ServiceExit {
    Stopped,
    NativeRefused(Result<day2::deployment::NativeTerminalHold>),
}

fn run() -> Result<ServiceExit> {
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
    // Capture stop receipts before Tokio's old driver disappears. The hold
    // itself cannot begin until every actual native owner thread has joined.
    let terminal = result
        .as_ref()
        .err()
        .map(|_| day2::deployment::NativeTerminalHold::prepare());
    runtime.shutdown_timeout(Duration::from_secs(1));
    let native_ran = day2::deployment::close_native_http_executors()?;
    service_exit(result, native_ran, terminal)
}

fn service_exit(
    result: Result<()>,
    native_ran: bool,
    terminal: Option<Result<day2::deployment::NativeTerminalHold>>,
) -> Result<ServiceExit> {
    match result {
        Ok(()) => Ok(ServiceExit::Stopped),
        Err(error) if native_ran => {
            drop(error);
            Ok(ServiceExit::NativeRefused(
                terminal.context("native terminal listeners were not prepared")?,
            ))
        }
        Err(error) => Err(error),
    }
}

fn main() {
    match run() {
        Ok(ServiceExit::Stopped) => {}
        Ok(ServiceExit::NativeRefused(terminal)) => {
            // Inner native diagnostics already retain their allowlisted facts.
            // Neither provider errors nor private paths enter this log/hold.
            eprintln!("day2-serve refused or stopped; terminal hold at most 300 seconds");
            if terminal.and_then(|hold| hold.wait()).is_err() {
                eprintln!("day2-serve terminal stop unavailable");
            }
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("day2-serve refused or stopped: {error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Debug)]
    struct PrivateFailure(Arc<AtomicBool>);
    impl std::fmt::Display for PrivateFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("private fixture error")
        }
    }
    impl std::error::Error for PrivateFailure {}
    impl Drop for PrivateFailure {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn only_closed_native_execution_selects_hold_and_drops_private_failure_first() {
        assert!(matches!(
            service_exit(Ok(()), true, None).unwrap(),
            ServiceExit::Stopped
        ));
        assert!(service_exit(Err(anyhow::anyhow!("ordinary failure")), false, None).is_err());
        assert!(service_exit(Err(anyhow::anyhow!("native failure")), true, None).is_err());
        let dropped = Arc::new(AtomicBool::new(false));
        let result = service_exit(
            Err(anyhow::Error::new(PrivateFailure(dropped.clone()))),
            true,
            Some(Err(anyhow::anyhow!("fixture stop unavailable"))),
        )
        .unwrap();
        assert!(dropped.load(Ordering::Acquire));
        let ServiceExit::NativeRefused(hold) = result else {
            panic!("wrong disposition")
        };
        assert!(hold.is_err());
    }
}
