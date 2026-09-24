use anyhow::{Context, Result, bail, ensure};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_FRAME: usize = 1_048_576;

/// Exit state observed before the supervisor terminates a failed exchange.
/// This carries no worker output or application data and does not classify it.
#[derive(Debug)]
pub(crate) struct ExitEvidence {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl std::fmt::Display for ExitEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("isolated worker exchange failed")
    }
}

pub struct Worker {
    child: Child,
    requests: Option<SyncSender<Vec<u8>>>,
    responses: Option<Receiver<Result<Vec<u8>>>>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn start(path: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::start_with_trusted_launcher(path, &sibling("day2-sandbox")?)
        }
        #[cfg(target_os = "macos")]
        {
            Self::start_macos(path)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        bail!("worker sandbox unsupported on this operating system");
    }

    /// The launcher path is supplied by trusted host installation/tests, never app input.
    #[cfg(target_os = "linux")]
    pub fn start_with_trusted_launcher(path: &Path, launcher: &Path) -> Result<Self> {
        let mut command = Command::new(
            launcher
                .canonicalize()
                .context("trusted worker launcher missing")?,
        );
        command
            .arg(path.canonicalize()?)
            .arg(std::process::id().to_string());
        Self::spawn(command)
    }

    #[cfg(target_os = "macos")]
    fn start_macos(path: &Path) -> Result<Self> {
        let path = path.canonicalize()?;
        let executable = path.to_str().context("non UTF-8 path")?;
        ensure!(
            !executable.contains(['"', '\\']),
            "unsupported sandbox path"
        );
        let profile = format!(
            r#"(version 1)(deny default)
            (allow process-exec (literal "{executable}"))
            (allow file-read*)
            (deny file-read-data (require-all (vnode-type REGULAR-FILE)
                (require-not (literal "{executable}"))
                (require-not (subpath "/usr/lib"))
                (require-not (subpath "/System"))))
            (allow sysctl-read)
            (allow mach-lookup (global-name "com.apple.system.logger"))
            (allow file-write-data (literal "/dev/null"))"#
        );
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.args(["-p", &profile, executable]);
        Self::spawn(command)
    }

    fn spawn(mut command: Command) -> Result<Self> {
        let mut child = command
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn isolated Roc worker")?;
        let mut stdin = child.stdin.take().context("worker stdin")?;
        let stdout = child.stdout.take().context("worker stdout")?;
        let (sender, responses) = mpsc::sync_channel(1);
        let (requests, incoming) = mpsc::sync_channel::<Vec<u8>>(1);
        let writer = thread::Builder::new()
            .name("day2-worker-input".into())
            .spawn(move || {
                while let Ok(frame) = incoming.recv() {
                    if stdin
                        .write_all(&frame)
                        .and_then(|_| stdin.write_all(b"\n"))
                        .and_then(|_| stdin.flush())
                        .is_err()
                    {
                        break;
                    }
                }
            });
        let writer = match writer {
            Ok(writer) => writer,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("start worker input thread");
            }
        };
        let reader = thread::Builder::new()
            .name("day2-worker-output".into())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let result = read_frame(&mut reader);
                    let failed = result.is_err();
                    if sender.send(result).is_err() || failed {
                        break;
                    }
                }
            });
        let reader = match reader {
            Ok(reader) => reader,
            Err(error) => {
                drop(requests);
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer.join();
                return Err(error).context("start worker output thread");
            }
        };
        Ok(Self {
            child,
            requests: Some(requests),
            responses: Some(responses),
            reader: Some(reader),
            writer: Some(writer),
        })
    }
    pub fn exchange(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let result = self.exchange_frame(input);
        match result {
            Ok(frame) => Ok(frame),
            Err(error) => {
                let status = self.child.try_wait().ok().flatten();
                #[cfg(unix)]
                let signal = {
                    use std::os::unix::process::ExitStatusExt;
                    status.as_ref().and_then(|status| status.signal())
                };
                #[cfg(not(unix))]
                let signal = None;
                let evidence = ExitEvidence {
                    code: status.as_ref().and_then(|status| status.code()),
                    signal,
                };
                self.terminate();
                Err(error.context(evidence))
            }
        }
    }

    fn exchange_frame(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            input.len() < MAX_FRAME && !input.contains(&b'\n'),
            "invalid worker frame"
        );
        self.requests
            .as_ref()
            .context("closed worker")?
            .try_send(input.to_vec())
            .context("worker request backlog")?;
        self.responses
            .as_ref()
            .context("closed worker")?
            .recv_timeout(Duration::from_secs(3))
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => crate::error::Failure::WorkerTimeout,
                mpsc::RecvTimeoutError::Disconnected => crate::error::Failure::WorkerCrashed,
            })?
    }

    fn terminate(&mut self) {
        self.requests.take();
        self.responses.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

#[cfg(target_os = "linux")]
fn sibling(name: &str) -> Result<PathBuf> {
    let supervisor = std::env::current_exe()?.canonicalize()?;
    Ok(supervisor
        .parent()
        .context("supervisor installation directory")?
        .join(name))
}

/// Mandatory Linux startup qualification using the same launcher and a host-only probe.
pub fn qualify_sandbox() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut worker = Worker::start(&sibling("day2-sandbox-probe")?)?;
        ensure!(
            worker.exchange(b"qualify")? == day2_sandbox::QUALIFIED,
            "Linux worker sandbox qualification failed"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    bail!("Linux worker qualification requires Linux");
}

fn read_frame(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    loop {
        let data = reader.fill_buf()?;
        if data.is_empty() {
            return Err(anyhow::Error::new(crate::error::Failure::WorkerCrashed)
                .context("worker exited before response"));
        }
        let count = data
            .iter()
            .position(|b| *b == b'\n')
            .map_or(data.len(), |i| i + 1);
        ensure!(
            frame.len() + count <= MAX_FRAME,
            "oversized worker response"
        );
        frame.extend_from_slice(&data[..count]);
        reader.consume(count);
        if frame.last() == Some(&b'\n') {
            frame.pop();
            return Ok(frame);
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_FRAME, read_frame};
    use std::io::Cursor;

    #[test]
    fn frames_preserve_exact_payload_and_buffered_next_response() {
        let mut bytes = Cursor::new(b"first\n\nlast\n");
        assert_eq!(read_frame(&mut bytes).unwrap(), b"first");
        assert_eq!(read_frame(&mut bytes).unwrap(), b"");
        assert_eq!(read_frame(&mut bytes).unwrap(), b"last");
        assert!(read_frame(&mut bytes).is_err());
    }

    #[test]
    fn eof_and_size_limit_fail_without_accepting_partial_frames() {
        assert!(read_frame(&mut Cursor::new(b"partial")).is_err());
        let mut maximum = vec![b'x'; MAX_FRAME - 1];
        maximum.push(b'\n');
        assert_eq!(
            read_frame(&mut Cursor::new(&maximum)).unwrap().len(),
            MAX_FRAME - 1
        );
        maximum.insert(0, b'x');
        assert!(read_frame(&mut Cursor::new(maximum)).is_err());
    }
}
