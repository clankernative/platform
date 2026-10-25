//! Fixed ownerless terminal wait for the existing container entrypoints.
//! Prepare stop listeners before readiness-runtime teardown, then wait only
//! after all real executors/resources have unwound and their threads joined.
//! No enrollment, provider call, original, retry or clock renewal lives here.

use anyhow::{Result, ensure};
use std::{future::Future, time::Duration};

const HOLD: Duration = Duration::from_secs(300);

pub struct NativeTerminalHold {
    runtime: tokio::runtime::Runtime,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
}

impl NativeTerminalHold {
    /// Signal receipts contain no native authority. Capture them before the
    /// old Tokio runtime disappears: Tokio's installed handlers persist after
    /// that runtime, and a plain park would otherwise swallow operator stop.
    pub fn prepare() -> Result<Self> {
        #[cfg(unix)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let (terminate, interrupt) = {
                let _entered = runtime.enter();
                (
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
                )
            };
            Ok(Self {
                runtime,
                terminate,
                interrupt,
            })
        }
        #[cfg(not(unix))]
        anyhow::bail!("native terminal hold requires Unix signals")
    }

    /// One fixed five-minute wait, after executor cleanup. Operator shutdown
    /// must finish before this bound; it is not once-across-restarts protection
    /// during a control-plane outage and supplies no hard OS scheduling bound.
    pub fn wait(self) -> Result<()> {
        #[cfg(unix)]
        {
            let Self {
                runtime,
                mut terminate,
                mut interrupt,
            } = self;
            runtime.block_on(wait_bounded(async {
                let received = tokio::select! {
                    received = terminate.recv() => received,
                    received = interrupt.recv() => received,
                };
                ensure!(received.is_some(), "native terminal stop listener closed");
                Ok(())
            }))
        }
        #[cfg(not(unix))]
        anyhow::bail!("native terminal hold requires Unix signals")
    }
}

async fn wait_bounded(stop: impl Future<Output = Result<()>>) -> Result<()> {
    match tokio::time::timeout(HOLD, stop).await {
        Ok(result) => result,
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn wait_has_one_fixed_deadline_without_a_retry_or_reset() {
        let held = tokio::spawn(wait_bounded(std::future::pending()));
        tokio::task::yield_now().await;
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(99)).await;
            tokio::task::yield_now().await;
            assert!(!held.is_finished());
        }
        tokio::time::advance(Duration::from_secs(3)).await;
        held.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn operator_stop_and_listener_failure_are_not_retried() {
        wait_bounded(async { Ok(()) }).await.unwrap();
        let error = wait_bounded(async { anyhow::bail!("closed fixture stop") })
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "closed fixture stop");
    }

    #[cfg(unix)]
    #[test]
    fn terminal_signal_child() -> Result<()> {
        if std::env::var_os("DAY2_TERMINAL_SIGNAL_CHILD").is_none() {
            return Ok(());
        }
        use std::io::Write;
        let old = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _old_signal = {
            let _entered = old.enter();
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?
        };
        let hold = NativeTerminalHold::prepare()?;
        println!("terminal signal ready");
        std::io::stdout().flush()?;
        let mut command = String::new();
        std::io::stdin().read_line(&mut command)?;
        ensure!(command == "continue\n", "fixture continuation");
        old.shutdown_timeout(Duration::from_secs(1));
        hold.wait()
    }

    #[cfg(unix)]
    #[test]
    fn operator_signals_survive_readiness_runtime_shutdown_before_hold() -> Result<()> {
        use std::io::{BufRead, Write};
        struct Child {
            child: std::process::Child,
            reaped: bool,
        }
        impl Drop for Child {
            fn drop(&mut self) {
                if !self.reaped {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                }
            }
        }
        for signal in [rustix::process::Signal::TERM, rustix::process::Signal::INT] {
            let mut child = Child {
                child: std::process::Command::new(std::env::current_exe()?)
                    .args([
                        "--exact",
                        "deployment::terminal::tests::terminal_signal_child",
                        "--nocapture",
                    ])
                    .env("DAY2_TERMINAL_SIGNAL_CHILD", "1")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()?,
                reaped: false,
            };
            let stdout = child.child.stdout.take().unwrap();
            let (ready, observed) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout).lines() {
                    if line.is_ok_and(|line| line.ends_with("terminal signal ready")) {
                        let _ = ready.send(());
                    }
                }
            });
            observed.recv_timeout(Duration::from_secs(3))?;
            // This exact Child has not been reaped, so its PID cannot be reused.
            let process = rustix::process::Pid::from_raw(child.child.id().try_into()?).unwrap();
            rustix::process::kill_process(process, signal)?;
            child.child.stdin.take().unwrap().write_all(b"continue\n")?;
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(status) = child.child.try_wait()? {
                    child.reaped = true;
                    ensure!(status.success(), "terminal signal child failed");
                    break;
                }
                ensure!(
                    std::time::Instant::now() < deadline,
                    "terminal signal child did not stop"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            reader.join().unwrap();
        }
        Ok(())
    }
}
