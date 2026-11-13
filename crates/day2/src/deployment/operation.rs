//! One native exclusion domain for scheduled snapshots and release operations.
//! A helper retains the lock between operator RPCs and lends the actual locked
//! file description to its children. A child therefore retains exclusion even
//! if the helper dies. Socket responses and environment strings grant no
//! business authority; callers still perform ordinary store/operator admission.
use anyhow::{Context, Result, bail, ensure};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{IoSlice, IoSliceMut, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::AsFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const SOCKET_ENV: &str = "DAY2_OPERATION_SOCKET";
const STATE_ENV: &str = "DAY2_OPERATION_STATE";
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Owned kernel exclusion, never an assertion that a snapshot is current or
/// that a runtime/authority transition is admitted. Never unlink its lock file.
pub struct OperationLease {
    file: File,
    path: PathBuf,
}

fn lock_file(state: &Path, app: &str) -> Result<(File, PathBuf)> {
    day2_contracts::names::identifier(app)?;
    ensure!(
        fs::symlink_metadata(state)?.is_dir(),
        "operation_state_directory_required"
    );
    let path = state.canonicalize()?.join(format!("{app}.operation.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)?;
    ensure!(
        file.metadata()?.is_file(),
        "operation_regular_lock_required"
    );
    Ok((file, path))
}

impl OperationLease {
    pub fn acquire(state: &Path, app: &str) -> Result<Self> {
        let (expected, path) = lock_file(state, app)?;
        let file = match (std::env::var_os(STATE_ENV), std::env::var_os(SOCKET_ENV)) {
            (Some(guard_state), Some(socket))
                if Path::new(&guard_state).canonicalize()? == state.canonicalize()? =>
            {
                let stream = UnixStream::connect(socket).context("operation_guard_unavailable")?;
                loan(&stream)?
            }
            (None, None) | (Some(_), Some(_)) => expected.try_clone()?,
            _ => bail!("incomplete_operation_guard_binding"),
        };
        let lease = Self { file, path };
        lease.check(state, app)?;
        // The loan shares the guard's open file description. A forged or stale
        // independent descriptor cannot acquire a lock held by another owner.
        lease
            .file
            .try_lock()
            .context("another_backup_or_release_owns_this_app")?;
        Ok(lease)
    }

    pub fn for_instance(instance: &Path, app: &str) -> Result<Self> {
        let instance = instance.canonicalize()?;
        let selection = crate::artifact::Instance::load(&instance)?;
        ensure!(
            selection.apps.contains_key(app),
            "operation_app_not_installed"
        );
        Self::acquire(
            &instance
                .parent()
                .context("instance directory")?
                .join(".state"),
            app,
        )
    }

    pub fn check(&self, state: &Path, app: &str) -> Result<()> {
        day2_contracts::names::identifier(app)?;
        let path = state.canonicalize()?.join(format!("{app}.operation.lock"));
        let current = fs::symlink_metadata(&path)?;
        let owned = self.file.metadata()?;
        ensure!(
            self.path == path
                && current.is_file()
                && current.dev() == owned.dev()
                && current.ino() == owned.ino(),
            "operation_lease_identity_changed"
        );
        Ok(())
    }
}

fn loan(stream: &UnixStream) -> Result<File> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    (&*stream).write_all(b"L")?;
    let mut byte = [0; 1];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    #[cfg(target_os = "linux")]
    let flags = RecvFlags::CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = RecvFlags::empty();
    let received = recvmsg(
        stream,
        &mut [IoSliceMut::new(&mut byte)],
        &mut ancillary,
        flags,
    )?;
    #[cfg(target_os = "linux")]
    let returned = received.flags & !rustix::net::ReturnFlags::CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let returned = received.flags;
    ensure!(byte != *b"B", "another_backup_or_release_owns_this_app");
    ensure!(
        received.bytes == 1 && byte == *b"L" && returned.is_empty(),
        "operation_guard_invalid_reply"
    );
    let mut files = Vec::new();
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(descriptors) => files.extend(descriptors),
            _ => bail!("operation_guard_unknown_ancillary"),
        }
    }
    ensure!(files.len() == 1, "operation_guard_one_descriptor_required");
    let file = File::from(files.pop().context("operation descriptor")?);
    rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::CLOEXEC)?;
    Ok(file)
}

fn lend(stream: &UnixStream, lease: &OperationLease) -> Result<()> {
    let descriptors = [lease.file.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    ensure!(
        ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)),
        "operation_descriptor_buffer"
    );
    ensure!(
        sendmsg(
            stream,
            &[IoSlice::new(b"L")],
            &mut ancillary,
            SendFlags::empty()
        )? == 1,
        "operation_descriptor_send"
    );
    Ok(())
}

/// Fixed helper supervision, not a workflow runner. Pings never claim the
/// lock, allowing a source-image offsite backup before a rolling release claims
/// exclusion. The first loan claims it nonblockingly; refusal leaves no lease.
pub fn guard(state: &Path, app: &str, socket: &Path, seconds: u64) -> Result<()> {
    ensure!(
        (1..=86_400).contains(&seconds),
        "operation_guard_deadline_bound"
    );
    let (file, path) = lock_file(state, app)?;
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    // PID 1 must handle TERM explicitly so ordinary Pod deletion can close the
    // helper promptly. No operation is detached or force-unlocked on shutdown.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let started = Instant::now();
    let mut claimed = false;
    let lease = OperationLease { file, path };
    while started.elapsed() < Duration::from_secs(seconds) {
        if runtime.block_on(async {
            tokio::select! {
                _ = terminate.recv() => true,
                _ = interrupt.recv() => true,
                _ = tokio::time::sleep(Duration::from_millis(25)) => false,
            }
        }) {
            break;
        }
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut command = [0; 1];
        if stream.read_exact(&mut command).is_err() {
            continue;
        }
        match command[0] {
            b'P' => {
                let _ = stream.write_all(b"P");
            }
            b'L' => {
                lease.check(state, app)?;
                if !claimed {
                    if lease.file.try_lock().is_err() {
                        let _ = stream.write_all(b"B");
                        continue;
                    }
                    claimed = true;
                }
                // A disconnected client does not release the retained owner.
                let _ = lend(&stream, &lease);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Readiness of the helper supervisor only; this never claims exclusion or
/// opens a database. The operator explicitly requests a loan before stopping.
pub fn ping(socket: &Path) -> Result<()> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(b"P")?;
    let mut reply = [0; 1];
    stream.read_exact(&mut reply)?;
    ensure!(reply == *b"P", "operation_guard_ping_refused");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_excludes_even_a_draining_server_and_blocks_new_serving() -> Result<()> {
        let state = tempfile::tempdir()?;
        let serving = super::super::serving_lock(state.path(), "reports", true)?;
        assert!(super::super::migration_exclusion(state.path(), "reports").is_err());
        drop(serving);
        let migration = super::super::migration_exclusion(state.path(), "reports")?;
        assert!(super::super::serving_lock(state.path(), "reports", true).is_err());
        assert!(OperationLease::acquire(state.path(), "reports").is_err());
        drop(migration);
        drop(super::super::serving_lock(state.path(), "reports", true)?);
        Ok(())
    }

    #[test]
    fn guard_child() -> Result<()> {
        let Some(state) = std::env::var_os("DAY2_TEST_OPERATION_CHILD_STATE") else {
            return Ok(());
        };
        let socket =
            std::env::var_os("DAY2_TEST_OPERATION_CHILD_SOCKET").context("child socket")?;
        guard(Path::new(&state), "reports", Path::new(&socket), 60)
    }

    #[test]
    fn a_real_guard_death_cannot_release_a_borrowing_childs_exclusion() -> Result<()> {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let state = tempfile::tempdir()?;
        let socket = state.path().join("op.sock");
        let mut child = Child(
            std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "deployment::operation::tests::guard_child"])
                .env("DAY2_TEST_OPERATION_CHILD_STATE", state.path())
                .env("DAY2_TEST_OPERATION_CHILD_SOCKET", &socket)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?,
        );
        let started = Instant::now();
        while ping(&socket).is_err() {
            ensure!(
                started.elapsed() < Duration::from_secs(5),
                "guard child did not start"
            );
            ensure!(child.0.try_wait()?.is_none(), "guard child exited early");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Readiness itself does not reserve the operation domain.
        drop(OperationLease::acquire(state.path(), "reports")?);
        let borrower = OperationLease {
            file: loan(&UnixStream::connect(&socket)?)?,
            path: state.path().canonicalize()?.join("reports.operation.lock"),
        };
        assert!(rustix::io::fcntl_getfd(&borrower.file)?.contains(rustix::io::FdFlags::CLOEXEC));
        child.0.kill()?;
        child.0.wait()?;
        assert!(OperationLease::acquire(state.path(), "reports").is_err());
        borrower.check(state.path(), "reports")?;
        drop(borrower);
        drop(OperationLease::acquire(state.path(), "reports")?);
        Ok(())
    }

    #[test]
    fn exclusion_is_per_app_and_releases_only_after_the_last_native_owner() -> Result<()> {
        let state = tempfile::tempdir()?;
        let first = OperationLease::acquire(state.path(), "reports")?;
        assert!(OperationLease::acquire(state.path(), "reports").is_err());
        let another_root = tempfile::tempdir()?;
        let _foreign = OperationLease::acquire(another_root.path(), "reports")?;
        assert!(first.check(another_root.path(), "reports").is_err());
        let other = OperationLease::acquire(state.path(), "other")?;
        let (sender, receiver) = UnixStream::pair()?;
        let worker = std::thread::spawn(move || -> Result<()> {
            let mut request = [0; 1];
            (&sender).read_exact(&mut request)?;
            ensure!(request == *b"L", "loan request");
            lend(&sender, &first)
        });
        let lent = OperationLease {
            file: loan(&receiver)?,
            path: state.path().canonicalize()?.join("reports.operation.lock"),
        };
        worker.join().unwrap()?; // The supervisor's own file is now closed.
        lent.check(state.path(), "reports")?;
        assert!(lent.check(state.path(), "other").is_err());
        assert!(OperationLease::acquire(state.path(), "reports").is_err());
        drop(lent);
        let _again = OperationLease::acquire(state.path(), "reports")?;
        drop(other);
        Ok(())
    }

    #[test]
    fn replaced_lock_symlink_and_malformed_loan_refuse() -> Result<()> {
        let state = tempfile::tempdir()?;
        let lease = OperationLease::acquire(state.path(), "reports")?;
        let lock = state.path().join("reports.operation.lock");
        fs::rename(&lock, state.path().join("retained.lock"))?;
        fs::write(&lock, [])?;
        assert!(lease.check(state.path(), "reports").is_err());
        fs::remove_file(&lock)?;
        std::os::unix::fs::symlink("retained.lock", &lock)?;
        assert!(OperationLease::acquire(state.path(), "reports").is_err());
        assert!(OperationLease::acquire(state.path(), "../escape").is_err());
        let (mut sender, receiver) = UnixStream::pair()?;
        let worker = std::thread::spawn(move || {
            let mut request = [0; 1];
            sender.read_exact(&mut request).unwrap();
            sender.write_all(b"L").unwrap(); // An assertion is not a locked FD.
        });
        assert!(loan(&receiver).is_err());
        worker.join().unwrap();
        Ok(())
    }
}
