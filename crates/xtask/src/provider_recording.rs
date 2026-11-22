//! One explicit operator recording. The user runs this outside an agent tool.
//! Secrets are read only from a no-echo controlling terminal, never from argv,
//! environment or a file. The Roc recipe owns network step order.
use super::*;
use day2::{
    automation::Request,
    provider_recording::{Provider, Session as Native},
};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::termios::{
    LocalModes, OptionalActions, QueueSelector, SpecialCodeIndex, Termios, tcflush, tcgetattr,
    tcsetattr,
};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

struct Echo<'a> {
    terminal: &'a File,
    restore: Termios,
    restored: bool,
}

impl Echo<'_> {
    fn restore(mut self) -> Result<()> {
        let flushed = tcflush(self.terminal, QueueSelector::IFlush);
        tcsetattr(self.terminal, OptionalActions::Now, &self.restore)
            .map_err(|_| anyhow::anyhow!("recording_terminal_restore_failed: run stty sane"))?;
        self.restored = true;
        flushed.map_err(|_| anyhow::anyhow!("recording_terminal_restore_failed: run stty sane"))?;
        Ok(())
    }
}

impl Drop for Echo<'_> {
    fn drop(&mut self) {
        if self.restored {
            return;
        }
        let flushed = tcflush(self.terminal, QueueSelector::IFlush);
        if tcsetattr(self.terminal, OptionalActions::Now, &self.restore).is_err()
            || flushed.is_err()
        {
            let mut terminal = self.terminal;
            let _ = terminal.write_all(b"\nrecording_terminal_restore_failed: run stty sane\n");
        }
    }
}

fn prompt(terminal: &File, label: &'static str, hidden: bool) -> Result<String> {
    prompt_with_budget(terminal, label, hidden, Duration::from_secs(180))
}

fn prompt_with_budget(
    terminal: &File,
    label: &'static str,
    hidden: bool,
    budget: Duration,
) -> Result<String> {
    let started = Instant::now();
    let mut io = terminal;
    let guard = if hidden {
        let restore =
            tcgetattr(terminal).map_err(|_| anyhow::anyhow!("recording_terminal_mode"))?;
        let mut modes = restore.clone();
        // Typed Ctrl-C/Ctrl-D are cancellation bytes while echo is disabled,
        // rather than a default signal that would bypass the restoration guard.
        modes
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON | LocalModes::ISIG);
        modes.special_codes[SpecialCodeIndex::VMIN] = 1;
        modes.special_codes[SpecialCodeIndex::VTIME] = 0;
        tcsetattr(terminal, OptionalActions::Now, &modes)
            .map_err(|_| anyhow::anyhow!("recording_terminal_mode"))?;
        Some(Echo {
            terminal,
            restore,
            restored: false,
        })
    } else {
        None
    };
    io.write_all(label.as_bytes())
        .map_err(|_| anyhow::anyhow!("recording_terminal_write"))?;
    io.flush()
        .map_err(|_| anyhow::anyhow!("recording_terminal_write"))?;
    let mut bytes = Vec::new();
    let result = (|| {
        for _ in 0..16_385 {
            let remaining = budget
                .checked_sub(started.elapsed())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| anyhow::anyhow!("recording_input_timeout"))?;
            let timeout = Timespec {
                tv_sec: remaining.as_secs().try_into()?,
                tv_nsec: remaining.subsec_nanos().into(),
            };
            let mut fds = [PollFd::new(terminal, PollFlags::IN)];
            let count = rustix::event::poll(&mut fds, Some(&timeout))
                .map_err(|_| anyhow::anyhow!("recording_terminal_poll"))?;
            ensure!(
                count == 1 && fds[0].revents() == PollFlags::IN && started.elapsed() < budget,
                "recording_input_timeout_or_closed"
            );
            let mut byte = [0];
            io.read_exact(&mut byte)
                .map_err(|_| anyhow::anyhow!("recording_terminal_read"))?;
            if byte[0] == b'\n' {
                return Ok(());
            }
            ensure!(!byte[0].is_ascii_control(), "recording_input_cancelled");
            bytes.push(byte[0]);
        }
        anyhow::bail!("recording_input_bound")
    })();
    if let Some(guard) = guard {
        guard.restore()?;
    }
    if hidden {
        io.write_all(b"\n")
            .map_err(|_| anyhow::anyhow!("recording_terminal_write"))?;
    }
    result?;
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("recording_input_encoding"))
}

fn inputs(provider: Provider) -> Result<Native> {
    let terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open("/dev/tty")
        .map_err(|_| anyhow::anyhow!("recording_requires_user_terminal"))?;
    match provider {
        Provider::Carta => {
            let client = prompt(
                &terminal,
                "Carta PLAYGROUND client ID (not production): ",
                false,
            )?;
            let issuer = prompt(&terminal, "Carta PLAYGROUND numeric issuer ID: ", false)?;
            let secret = prompt(&terminal, "Carta PLAYGROUND client secret (hidden): ", true)?;
            Ok(Native::carta(client, issuer, secret)?)
        }
        Provider::OpenAi => {
            let consent = prompt(
                &terminal,
                "One paid gpt-6-luna request, max 64 output tokens, estimated under $0.001. Type APPROVE: ",
                false,
            )?;
            ensure!(consent == "APPROVE", "recording_spend_not_approved");
            let project = prompt(&terminal, "OpenAI project ID (proj_...): ", false)?;
            let key = prompt(
                &terminal,
                "OpenAI API key for that project (hidden): ",
                true,
            )?;
            Ok(Native::openai(project, key)?)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Start,
    Token,
    Stakeholders,
    Grants,
    OpenAi,
    Publish,
    Complete,
    Failed,
}

struct Session {
    provider: Provider,
    directory: PathBuf,
    native: Option<Native>,
    phase: Phase,
}

impl Session {
    fn effect(&mut self, request: Request) -> Result<Value> {
        let actual = self.phase;
        self.phase = Phase::Failed;
        let result = (|| {
            ensure!(
                request.protocol == 1 && request.decode::<Value>()? == json!({}),
                "recording_request_invalid"
            );
            let expected = match request.action.as_str() {
                "provider-recording-open" => Phase::Start,
                "provider-recording-token" => Phase::Token,
                "provider-recording-stakeholders" => Phase::Stakeholders,
                "provider-recording-grants" => Phase::Grants,
                "provider-recording-openai" => Phase::OpenAi,
                "provider-recording-publish" => Phase::Publish,
                _ => anyhow::bail!("recording_action_invalid"),
            };
            ensure!(actual == expected, "recording_step_out_of_order");
            match expected {
                Phase::Start => {
                    qualification_evidence::create_directory(&self.directory)?;
                    self.native = Some(inputs(self.provider)?);
                    self.phase = match self.provider {
                        Provider::Carta => Phase::Token,
                        Provider::OpenAi => Phase::OpenAi,
                    };
                }
                Phase::Token => {
                    self.native
                        .as_mut()
                        .context("recording_not_open")?
                        .token()?;
                    self.phase = Phase::Stakeholders;
                }
                Phase::Stakeholders => {
                    self.native
                        .as_mut()
                        .context("recording_not_open")?
                        .stakeholders()?;
                    self.phase = Phase::Grants;
                }
                Phase::Grants => {
                    self.native
                        .as_mut()
                        .context("recording_not_open")?
                        .grants()?;
                    self.phase = Phase::Publish;
                }
                Phase::OpenAi => {
                    self.native
                        .as_mut()
                        .context("recording_not_open")?
                        .openai_response()?;
                    self.phase = Phase::Publish;
                }
                Phase::Publish => {
                    let bundle = self.native.take().context("recording_not_open")?.finish()?;
                    publish_ordered(
                        bundle.recordings().iter().map(|r| (r.name(), r.bytes())),
                        bundle.provenance(),
                        |name, bytes| {
                            qualification_evidence::publish(&self.directory, name, bytes)
                                .map(|_| ())
                        },
                    )?;
                    self.phase = Phase::Complete;
                }
                _ => anyhow::bail!("recording_phase_invalid"),
            }
            Ok(json!({}))
        })();
        if result.is_err() {
            self.native = None;
            self.phase = Phase::Failed;
        }
        result
    }
}

fn publish_ordered<'a>(
    recordings: impl Iterator<Item = (&'static str, &'a [u8])>,
    provenance: &[u8],
    mut publish: impl FnMut(&str, &[u8]) -> Result<()>,
) -> Result<()> {
    for (name, bytes) in recordings {
        publish(name, bytes)?;
    }
    // A late sync/close error can leave this name visible. Its presence alone
    // never proves success: require actual command success and hash readback.
    publish("PROVENANCE.json", provenance)
}

pub fn execute(root: &Path, provider: Provider, directory: &Path) -> Result<()> {
    // Compile/check the source-bound runner before a secret is requested.
    let runner = workflows::build(root)?;
    let mut session = Session {
        provider,
        directory: directory.into(),
        native: None,
        phase: Phase::Start,
    };
    day2::automation::run(&runner, &["provider-recording", provider.name()], |r| {
        session.effect(r)
    })?;
    ensure!(
        session.phase == Phase::Complete,
        "provider_recording_incomplete"
    );
    println!("redacted recording complete: {}", directory.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn late_manifest_failure_is_not_success_even_with_valid_visible_data() -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("safe");
        qualification_evidence::create_directory(&directory)?;
        let body = b"{\"synthetic\":true}";
        let manifest = serde_json::to_vec(
            &json!({"files":[{"name":"synthetic.json","sha256":digest(body)}]}),
        )?;
        let mut order = Vec::new();
        let result = publish_ordered(
            [("synthetic.json", body.as_slice())].into_iter(),
            &manifest,
            |name, bytes| {
                order.push(name.to_owned());
                qualification_evidence::publish(&directory, name, bytes)?;
                if name == "PROVENANCE.json" {
                    anyhow::bail!("synthetic late sync failure");
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(order, ["synthetic.json", "PROVENANCE.json"]);
        assert_eq!(fs::read(directory.join("PROVENANCE.json"))?, manifest);
        assert_eq!(fs::read(directory.join("synthetic.json"))?, body);
        let other = root.path().join("refused");
        qualification_evidence::create_directory(&other)?;
        let result = publish_ordered(
            [("synthetic.json", body.as_slice())].into_iter(),
            &manifest,
            |name, _bytes| {
                ensure!(name != "synthetic.json", "synthetic early write failure");
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!other.join("PROVENANCE.json").exists());
        Ok(())
    }

    fn terminal_pair() -> Result<(File, File)> {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
        let master = File::from(
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).context("synthetic openpt")?,
        );
        grantpt(&master).context("synthetic grantpt")?;
        unlockpt(&master).context("synthetic unlockpt")?;
        let name = ptsname(&master, Vec::new()).context("synthetic ptsname")?;
        let slave = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(std::ffi::OsStr::from_bytes(name.to_bytes()))
            .context("synthetic slave open")?;
        rustix::fs::fcntl_setfl(
            &master,
            rustix::fs::fcntl_getfl(&master).context("synthetic master flags")?
                | rustix::fs::OFlags::NONBLOCK,
        )
        .context("synthetic nonblocking master")?;
        Ok((master, slave))
    }

    fn settings(file: &File) -> String {
        let value = tcgetattr(file).unwrap();
        // Darwin reports this kernel queue-state bit after changing canonical
        // mode. Every configured bit and control character is still compared;
        // the separate poll asserts that no secret input actually remains.
        #[cfg(target_os = "macos")]
        let value = {
            let mut value = value;
            value.local_modes.remove(LocalModes::PENDIN);
            value
        };
        format!("{value:?}")
    }

    fn label(master: &mut File) -> Result<()> {
        let started = Instant::now();
        let mut label = [0; 8];
        for byte in &mut label {
            let remaining = Duration::from_secs(3)
                .checked_sub(started.elapsed())
                .context("synthetic label timeout")?;
            let mut poll = [PollFd::new(&*master, PollFlags::IN)];
            ensure!(
                rustix::event::poll(
                    &mut poll,
                    Some(&Timespec {
                        tv_sec: remaining.as_secs().try_into()?,
                        tv_nsec: remaining.subsec_nanos().into()
                    })
                )? == 1,
                "synthetic label absent"
            );
            master.read_exact(std::slice::from_mut(byte))?;
        }
        ensure!(&label == b"hidden: ", "synthetic label mismatch");
        Ok(())
    }

    fn start_prompt(worker: File) -> std::sync::mpsc::Receiver<Result<String>> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = prompt_with_budget(&worker, "hidden: ", true, Duration::from_secs(2));
            let _ = sender.send(result);
        });
        receiver
    }

    fn input(master: &mut File, bytes: &[u8]) -> Result<()> {
        let started = Instant::now();
        let mut remaining_bytes = bytes;
        while !remaining_bytes.is_empty() {
            let remaining = Duration::from_secs(3)
                .checked_sub(started.elapsed())
                .context("synthetic input timeout")?;
            let mut poll = [PollFd::new(&*master, PollFlags::OUT)];
            ensure!(
                rustix::event::poll(
                    &mut poll,
                    Some(&Timespec {
                        tv_sec: remaining.as_secs().try_into()?,
                        tv_nsec: remaining.subsec_nanos().into()
                    })
                )? == 1,
                "synthetic input blocked"
            );
            match master.write(remaining_bytes) {
                Ok(0) => anyhow::bail!("synthetic input closed"),
                Ok(count) => remaining_bytes = &remaining_bytes[count..],
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    #[test]
    fn synthetic_tty_secret_is_not_echoed_and_settings_are_restored() -> Result<()> {
        let (mut master, slave) = terminal_pair()?;
        let before = settings(&slave);
        let worker = slave.try_clone()?;
        let run = start_prompt(worker);
        label(&mut master)?;
        input(&mut master, b"synthetic-secret\nsynthetic-tail\n")?;
        assert_eq!(
            run.recv_timeout(Duration::from_secs(4))??,
            "synthetic-secret"
        );
        assert_eq!(settings(&slave), before);
        let mut pending = [PollFd::new(&slave, PollFlags::IN)];
        assert_eq!(
            rustix::event::poll(
                &mut pending,
                Some(&Timespec {
                    tv_sec: 0,
                    tv_nsec: 0
                })
            )?,
            0
        );
        let mut poll = [PollFd::new(&master, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        if rustix::event::poll(&mut poll, Some(&timeout))? != 0 {
            let mut output = [0; 128];
            let count = master.read(&mut output)?;
            assert!(
                !output[..count]
                    .windows(b"synthetic-secret".len())
                    .any(|s| s == b"synthetic-secret")
            );
            assert!(
                !output[..count]
                    .windows(b"synthetic-tail".len())
                    .any(|s| s == b"synthetic-tail")
            );
        }
        Ok(())
    }

    #[test]
    fn synthetic_tty_cancel_timeout_bounds_and_unwind_restore() -> Result<()> {
        for input in [
            b"\x03synthetic-secret\n".to_vec(),
            b"\x04synthetic-secret\n".to_vec(),
            [vec![b'x'; 16_385], b"synthetic-tail\n".to_vec()].concat(),
        ] {
            let (mut master, slave) = terminal_pair()?;
            let before = settings(&slave);
            let worker = slave.try_clone()?;
            let run = start_prompt(worker);
            label(&mut master)?;
            self::input(&mut master, &input)?;
            assert!(run.recv_timeout(Duration::from_secs(4))?.is_err());
            assert_eq!(settings(&slave), before);
            let mut poll = [PollFd::new(&slave, PollFlags::IN)];
            assert_eq!(
                rustix::event::poll(
                    &mut poll,
                    Some(&Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                )?,
                0,
                "cancelled input is not left for the shell"
            );
        }
        let (_master, slave) = terminal_pair()?;
        let before = settings(&slave);
        assert!(prompt_with_budget(&slave, "", true, Duration::from_millis(10)).is_err());
        assert_eq!(settings(&slave), before);
        let result = std::panic::catch_unwind(|| {
            let restore = tcgetattr(&slave).unwrap();
            let mut changed = restore.clone();
            changed.local_modes.remove(LocalModes::ECHO);
            tcsetattr(&slave, OptionalActions::Now, &changed).unwrap();
            let _guard = Echo {
                terminal: &slave,
                restore,
                restored: false,
            };
            panic!("synthetic unwind");
        });
        assert!(result.is_err());
        assert_eq!(settings(&slave), before);
        Ok(())
    }

    #[test]
    fn malformed_or_out_of_order_recipe_never_opens_input_or_publishes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("recording");
        for request in [
            Request {
                protocol: 1,
                action: "provider-recording-publish".into(),
                input: "{}".into(),
            },
            Request {
                protocol: 2,
                action: "provider-recording-open".into(),
                input: "{}".into(),
            },
            Request {
                protocol: 1,
                action: "provider-recording-open".into(),
                input: r#"{"unexpected":true}"#.into(),
            },
        ] {
            let mut session = Session {
                provider: Provider::Carta,
                directory: directory.clone(),
                native: None,
                phase: Phase::Start,
            };
            assert!(session.effect(request).is_err());
            assert!(session.phase == Phase::Failed);
            assert!(session.native.is_none());
            assert!(!directory.exists());
        }
        Ok(())
    }
}
