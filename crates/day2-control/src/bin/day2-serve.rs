//! Container entrypoint.
//!
//! Public serving mode is decided by the instance: `--edge` serves behind its identity
//! provider and requires one to be declared; `--development-auth` prints a
//! one-use sign-in link and is refused when one is. Runtime-pair modes instead
//! require their exact durable executor admission and expose no app listener.

use anyhow::{Context, Result, ensure};
use std::{num::NonZeroU16, path::PathBuf, time::Duration};

enum ServiceExit {
    Stopped,
    NativeRefused(Result<day2::deployment::NativeTerminalHold>),
}

fn pair_executor_exit(result: Result<()>) -> Result<ServiceExit> {
    // Executor failures may include app-owned diagnostics. Replay evidence has
    // its own protected destination; process logs retain only this fixed label.
    result
        .map(|()| ServiceExit::Stopped)
        .map_err(|_| anyhow::anyhow!("runtime_pair_executor_refused"))
}

fn run_pair_executor(arguments: &[std::ffi::OsString]) -> Result<()> {
    let instance = PathBuf::from(&arguments[0]);
    let app = arguments[1].to_str().context("app must be UTF-8")?;
    let selection = day2::runtime_pair::Selection::load(&PathBuf::from(&arguments[3]))?;
    if arguments[2] == "--runtime-source-executor" {
        let budget: usize = arguments[4]
            .to_str()
            .context("source budget must be UTF-8")?
            .parse()?;
        let outcomes = day2::runtime_pair::source_drain(&instance, app, &selection, budget)?;
        println!("{}", serde_json::json!({"settled":outcomes.len()}));
        return Ok(());
    }
    let evidence = PathBuf::from(&arguments[4]);
    if arguments[2] == "--runtime-candidate-check" {
        let candidate = day2::runtime_pair::Candidate::open(&instance, app, selection)?;
        println!("{}", serde_json::to_string(&candidate.check(&evidence)?)?);
    } else {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let result = runtime.block_on(day2::runtime_pair::supervise(
            &instance, app, selection, &evidence,
        ));
        runtime.shutdown_timeout(Duration::from_secs(1));
        result?;
    }
    Ok(())
}

fn run() -> Result<ServiceExit> {
    let mut arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() == 5
        && matches!(
            arguments[2].to_str(),
            Some("--runtime-candidate" | "--runtime-candidate-check" | "--runtime-source-executor")
        )
    {
        return pair_executor_exit(run_pair_executor(&arguments));
    }
    let app_calls = if arguments.len() == 5 && arguments[3] == "--app-calls" {
        let path = PathBuf::from(arguments.pop().context("app call configuration")?);
        arguments.pop();
        Some(path)
    } else {
        None
    };
    let usage = "usage: day2-serve INSTANCE APP --edge\n       day2-serve INSTANCE APP --development-auth ACTOR --published-port PORT\n       day2-serve INSTANCE APP --runtime-candidate SELECTION EVIDENCE_DIRECTORY\n       day2-serve INSTANCE APP --runtime-candidate-check SELECTION EVIDENCE_DIRECTORY\n       day2-serve INSTANCE APP --runtime-source-executor SELECTION BUDGET";
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
    fn pair_executor_failure_drops_private_details_before_logging() {
        assert!(matches!(
            pair_executor_exit(Ok(())).unwrap(),
            ServiceExit::Stopped
        ));
        let dropped = Arc::new(AtomicBool::new(false));
        let error = pair_executor_exit(Err(anyhow::Error::new(PrivateFailure(dropped.clone()))))
            .err()
            .expect("failed executor accepted");
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(format!("{error:#}"), "runtime_pair_executor_refused");
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
