//! The one fixed initial-holder endpoint and per-message sender handles. No
//! caller path, descriptor adoption, weaker credentials or renewed clock.

use super::{Channel, configure, wait};
use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    EnrolledRoleStage, NativeRole,
    process::MessageProcess,
    protocol::MAX_PACKET,
    storage_peer_wire::{Message, StageStatement},
    storage_socket_directory::StorageSocketDirectory,
};
use anyhow::{Result, ensure};
use rustix::{
    event::{PollFd, PollFlags},
    fs::{Mode, OFlags},
    io::Errno,
    net::{self, AddressFamily, RecvPidfdError, SendFlags, SocketFlags, SocketType},
};
use std::{fs::File, io::IoSliceMut, marker::PhantomData, rc::Rc};

const PATH: &str = "/run/day2-native-enrollment/storage/peer.sock";

impl Channel {
    /// Readiness DATA on the SAME retained descriptor. No packet is consumed,
    /// role stage issued or clock/holder authority created while idle.
    pub(in crate::security_epoch::native_enrollment) fn storage_pending(&mut self) -> Result<bool> {
        let result = (|| {
            ensure!(!self.refused, "storage_peer_channel_refused");
            let mut fds = [PollFd::new(&self.socket, PollFlags::IN | PollFlags::RDHUP)];
            rustix::event::poll(
                &mut fds,
                Some(&rustix::time::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )?;
            let flags = fds[0].revents();
            ensure!(
                !flags.intersects(
                    PollFlags::HUP | PollFlags::RDHUP | PollFlags::ERR | PollFlags::NVAL
                ),
                "storage_peer_idle_channel_closed"
            );
            Ok(flags.contains(PollFlags::IN))
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn connect_storage(
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let result = (|| {
            stage.check_storage_acquisition(acquisition)?;
            ensure!(
                rustix::process::geteuid().as_raw() == 10001,
                "storage_peer_filesystem_uid"
            );
            let socket = net::socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )?;
            configure(&socket)?;
            net::connect(&socket, &net::SocketAddrUnix::new(PATH)?)?;
            stage.check_storage_acquisition(acquisition)?;
            Ok(Self {
                socket: File::from(socket),
                refused: false,
                local: PhantomData,
            })
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn check_storage_open(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "storage_peer_channel_refused");
            stage.check_storage_acquisition(acquisition)?;
            require_connected(&self.socket, acquisition)?;
            stage.check_storage_acquisition(acquisition)
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn send_storage(
        &mut self,
        message: &Message,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "storage_peer_channel_refused");
            self.check_storage_open(stage, acquisition)?;
            let bytes = serde_json::to_vec(message)?;
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                "storage_peer_packet_bound"
            );
            loop {
                self.check_storage_open(stage, acquisition)?;
                match net::send(
                    &self.socket,
                    &bytes,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                ) {
                    Ok(count) => {
                        ensure!(count == bytes.len(), "storage_peer_partial_packet");
                        break;
                    }
                    Err(Errno::AGAIN) => wait(&self.socket, PollFlags::OUT, acquisition)?,
                    Err(Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            self.check_storage_open(stage, acquisition)
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn receive_storage(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<(Message, StorageSender)> {
        let result = (|| {
            ensure!(!self.refused, "storage_peer_channel_refused");
            self.check_storage_open(stage, acquisition)?;
            let expected_code = stage.storage_peer_code()?;
            let mut bytes = [0_u8; MAX_PACKET];
            let received = loop {
                self.check_storage_open(stage, acquisition)?;
                match net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)]) {
                    Ok(received) => break received,
                    Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                        wait(&self.socket, PollFlags::IN, acquisition)?
                    }
                    Err(RecvPidfdError::Io(Errno::INTR)) => continue,
                    Err(error) => return Err(error.into()),
                }
            };
            let message = crate::security_epoch::native_enrollment::storage_peer_wire::decode(
                &bytes[..received.bytes],
            )?;
            let process = match stage.storage_peer_role()? {
                NativeRole::AppHost => StorageSender::App(Box::new(MessageProcess::receive(
                    received,
                    &expected_code,
                    acquisition,
                )?)),
                NativeRole::EpochController => {
                    StorageSender::Controller(ControllerReceipt::receive(received, acquisition)?)
                }
                NativeRole::SecurityShell => anyhow::bail!("storage_peer_shell_role_refused"),
            };
            self.check_storage_open(stage, acquisition)?;
            Ok((message, process))
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }
}

pub(in crate::security_epoch::native_enrollment) struct StorageListener {
    socket: File,
    root: File,
    directory: StorageSocketDirectory,
    local: PhantomData<Rc<()>>,
}

impl StorageListener {
    /// Zero-timeout readiness on this retained descriptor. No role, clock,
    /// packet, peer authentication, file or P3 permission is obtained here.
    pub(in crate::security_epoch::native_enrollment) fn pending(&self) -> Result<bool> {
        storage_listener_pending(&self.socket)
    }

    pub(in crate::security_epoch::native_enrollment) fn bind(
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let result = (|| {
            stage.check_storage_acquisition(acquisition)?;
            ensure!(
                rustix::process::geteuid().as_raw() == 10001,
                "storage_peer_filesystem_uid"
            );
            let root = File::from(rustix::fs::open(
                "/run/day2-native-enrollment",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let directory = StorageSocketDirectory::observe(&root)?;
            stage.check_storage_acquisition(acquisition)?;
            let socket = net::socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )?;
            configure(&socket)?;
            // No unlink/adoption: an existing endpoint permanently refuses this
            // attempt. A failed/unknown exchange cannot restart its creator.
            net::bind(&socket, &net::SocketAddrUnix::new(PATH)?)?;
            std::fs::set_permissions(PATH, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
            net::listen(&socket, 1)?;
            directory.check(&root)?;
            stage.check_storage_acquisition(acquisition)?;
            Ok(Self {
                socket: File::from(socket),
                root,
                directory,
                local: PhantomData,
            })
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn accept(
        &self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Channel> {
        let result = (|| {
            require_listener_cloexec(&self.socket)?;
            self.directory.check(&self.root)?;
            stage.check_storage_acquisition(acquisition)?;
            wait(&self.socket, PollFlags::IN, acquisition)?;
            stage.check_storage_acquisition(acquisition)?;
            let socket =
                net::accept_with(&self.socket, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)?;
            configure(&socket)?;
            require_listener_cloexec(&self.socket)?;
            self.directory.check(&self.root)?;
            stage.check_storage_acquisition(acquisition)?;
            Ok(Channel {
                socket: File::from(socket),
                refused: false,
                local: PhantomData,
            })
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }
}

fn require_listener_cloexec(socket: &File) -> Result<()> {
    ensure!(
        rustix::io::fcntl_getfd(socket)?.contains(rustix::io::FdFlags::CLOEXEC),
        "storage_peer_listener_cloexec_lost"
    );
    Ok(())
}

fn storage_listener_pending(socket: &File) -> Result<bool> {
    require_listener_cloexec(socket)?;
    let mut fds = [PollFd::new(socket, PollFlags::IN | PollFlags::RDHUP)];
    rustix::event::poll(
        &mut fds,
        Some(&rustix::time::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )?;
    let flags = fds[0].revents();
    ensure!(
        !flags.intersects(PollFlags::HUP | PollFlags::RDHUP | PollFlags::ERR | PollFlags::NVAL),
        "storage_peer_listener_closed"
    );
    Ok(flags.contains(PollFlags::IN))
}

#[cfg(test)]
mod idle_tests {
    use super::*;

    #[test]
    fn idle_listener_probe_is_data_only_and_refuses_buffered_hup_and_lost_cloexec() -> Result<()> {
        // Lower socket DATA controls, not construction of a native listener,
        // role, prepared file, holder or P3 owner.
        let (left, right) = net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        let left = File::from(left);
        assert!(!storage_listener_pending(&left)?);
        net::send(&right, b"queued-data", SendFlags::NOSIGNAL)?;
        assert!(storage_listener_pending(&left)?);
        drop(right);
        assert!(storage_listener_pending(&left).is_err());
        let (open, _peer) = net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        let open = File::from(open);
        rustix::io::fcntl_setfd(&open, rustix::io::FdFlags::empty())?;
        assert!(storage_listener_pending(&open).is_err());
        Ok(())
    }
}

/// Distinct provenance: Controller can inspect the unprivileged App process.
/// App retains a kernel Controller handle and the actual issuer's attestation;
/// it does not independently read privileged executable/namespace objects.
pub(in crate::security_epoch::native_enrollment) enum StorageSender {
    App(Box<MessageProcess>),
    Controller(ControllerReceipt),
}

pub(in crate::security_epoch::native_enrollment) struct ControllerReceipt {
    pidfd: File,
    kernel_process: u32,
    statement: Option<day2_capabilities::Digest>,
    local_process: u32,
    thread: std::thread::ThreadId,
    valid: bool,
    local: PhantomData<Rc<()>>,
}

impl ControllerReceipt {
    // Only the closed receiver above can construct this with its ORIGINAL
    // SCM_PIDFD. No caller PID, certificate or reopened FD constructor exists.
    fn receive(
        packet: net::ReceivedPidfdPacket,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let kernel_process = match packet.credentials.process {
            net::KernelPidVisibility::Visible(pid) => pid.get(),
            net::KernelPidVisibility::NotVisible => {
                anyhow::bail!("storage_peer_controller_pid_not_visible")
            }
        };
        let pidfd = File::from(packet.process);
        crate::security_epoch::native_enrollment::process::live(&pidfd, acquisition)?;
        Ok(Self {
            pidfd,
            kernel_process,
            statement: None,
            local_process: std::process::id(),
            thread: std::thread::current().id(),
            valid: true,
            local: PhantomData,
        })
    }

    pub(in crate::security_epoch::native_enrollment) fn bind(
        &mut self,
        statement: &StageStatement,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check_received(acquisition)?;
            stage.check_storage_controller_statement(
                statement,
                self.kernel_process,
                acquisition,
            )?;
            let digest = statement.digest()?;
            ensure!(
                self.statement.as_ref().is_none_or(|old| old == &digest),
                "storage_peer_controller_statement_changed"
            );
            self.statement = Some(digest);
            self.check(statement, stage, acquisition)
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }

    fn check_received(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        ensure!(
            self.valid
                && self.local_process == std::process::id()
                && self.thread == std::thread::current().id(),
            "storage_peer_controller_receipt_refused"
        );
        crate::security_epoch::native_enrollment::process::live(&self.pidfd, acquisition)
    }

    /// A retained original sender handle is identity/liveness continuity only;
    /// it does not make the old grant current. Fresh phases verify a newly
    /// signed role statement and nonce exchange separately.
    pub(in crate::security_epoch::native_enrollment) fn check_continuity(
        &mut self,
        statement: &StageStatement,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check_received(acquisition)?;
            stage.check_storage_acquisition(acquisition)?;
            let local = stage.storage_statement()?;
            ensure!(
                self.statement.as_ref() == Some(&statement.digest()?)
                    && statement.certificate == local.certificate
                    && statement.stage.data.policy == local.stage.data.policy
                    && statement.stage.data.role == NativeRole::EpochController
                    && local.stage.data.role == NativeRole::AppHost
                    && statement.stage.data.process.process == self.kernel_process,
                "storage_peer_original_controller_identity_changed"
            );
            self.check_received(acquisition)?;
            stage.check_storage_acquisition(acquisition)
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn check(
        &mut self,
        statement: &StageStatement,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check_received(acquisition)?;
            ensure!(
                self.statement.as_ref() == Some(&statement.digest()?),
                "storage_peer_controller_not_bound"
            );
            stage.check_storage_controller_statement(
                statement,
                self.kernel_process,
                acquisition,
            )?;
            self.check_received(acquisition)
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }
}

/// No successful buffered final reply survives peer close/exec. This is a
/// socket-liveness primitive, not an enrollment or storage-permission factory.
fn require_connected(socket: &File, acquisition: &mut NativeAcquisition) -> Result<()> {
    let result = (|| {
        loop {
            acquisition.remaining()?;
            ensure!(
                rustix::io::fcntl_getfd(socket)?.contains(rustix::io::FdFlags::CLOEXEC),
                "storage_peer_channel_cloexec_required"
            );
            let mut fds = [PollFd::new(socket, PollFlags::RDHUP)];
            let zero = rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            match rustix::event::poll(&mut fds, Some(&zero)) {
                Ok(_) => ensure!(
                    !fds[0].revents().intersects(
                        PollFlags::HUP | PollFlags::RDHUP | PollFlags::ERR | PollFlags::NVAL
                    ),
                    "storage_peer_channel_closed"
                ),
                Err(Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
            acquisition.remaining()?;
            return Ok(());
        }
    })();
    if result.is_err() {
        acquisition.refuse();
    }
    result
}

#[cfg(test)]
mod tests;
