//! Fixed protected-restore socket resources, not native peer admission.
//! The actual enrolled setup supplies every bounded operation. Idle polling
//! retains only descriptors and names, never a role, Current or original.

use super::{
    Actor, Channel, ControllerReceipt, Direction, Protocol, ServingSender, Transcript, Transport,
    configure, require_connected, require_idle_socket_profile,
};
use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    EnrolledRoleStage, NativeRole, SameEnrolledOwner,
    protected_restore::{
        AdmissionBody, AdmissionPacket, CommandData, MAX_ADMISSION_PACKET_BYTES,
        MAX_COMMAND_PACKET_BYTES, ProtectedRestoreMessage, UnverifiedCommandPacket,
        admission_enrollment,
    },
    serving_peer_wire::Statement,
    storage_socket_directory::StorageSocketDirectory,
};
use anyhow::{Result, ensure};
use rustix::{
    event::{PollFd, PollFlags},
    fs::{AtFlags, Mode, OFlags},
    io::Errno,
    net::{self, AddressFamily, RecvPidfdError, SendFlags, SocketFlags, SocketType},
};
use std::{
    fs::File,
    io::IoSliceMut,
    marker::PhantomData,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    rc::Rc,
};

const PATH: &str = "/run/day2-native-enrollment/storage/protected-restore.sock";

/// Raw listener resources only. Its sole factory requires an actual checked
/// Controller stage. This has no peer/packet/admission or descriptor getter.
pub(in crate::security_epoch::native_enrollment) struct ProtectedRestoreSocketListener {
    socket: File,
    name: File,
    root: File,
    directory: StorageSocketDirectory,
    named: (u64, u64),
    local: PhantomData<Rc<()>>,
}

/// Check-only ownership of this SAME connected socket and refusal root. It
/// cannot send, receive, wait, sign, export a descriptor or supply admission,
/// protocol/cursor authentication or a Current. A fixed action guard must
/// separately retain its genuine admitted peer and signed request binding.
pub(in crate::security_epoch::native_enrollment) struct ProtectedRestoreSocketObserver {
    socket: Rc<File>,
    refused: Rc<std::cell::Cell<bool>>,
    process: u32,
    thread: std::thread::ThreadId,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <ProtectedRestoreSocketObserver as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
};

impl ProtectedRestoreSocketObserver {
    pub(in crate::security_epoch::native_enrollment) fn require_channel(
        &self,
        channel: &Channel,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.refused.get()
                    && Rc::ptr_eq(&self.socket, &channel.socket)
                    && Rc::ptr_eq(&self.refused, &channel.refused),
                "protected_restore_output_socket_changed"
            );
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
            channel.refused.set(true);
        }
        result
    }
    /// SQL-safe retained resource checks only. require_connected uses a zero
    /// timeout and refuses close/error even with buffered readable bytes.
    /// It performs no packet/cursor work and calls no enrolled stage method.
    pub(in crate::security_epoch::native_enrollment) fn check(
        &mut self,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            ensure!(
                !self.refused.get(),
                "protected_restore_socket_observer_refused"
            );
            ensure!(
                self.process == std::process::id() && self.thread == std::thread::current().id(),
                "protected_restore_socket_observer_owner_changed"
            );
            acquisition.remaining()?;
            require_idle_socket_profile(&self.socket)?;
            ensure!(
                rustix::fs::fcntl_getfl(&self.socket)?.contains(OFlags::NONBLOCK)
                    && net::sockopt::socket_passcred(&self.socket)?
                    && net::sockopt::socket_passpidfd(&self.socket)?,
                "protected_restore_channel_profile"
            );
            require_connected(&self.socket, acquisition)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            acquisition.remaining().map(|_| ())
        }));
        if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(())) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => result,
            },
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse(&self) {
        self.refused.set(true);
    }
}

impl ProtectedRestoreSocketListener {
    pub(in crate::security_epoch::native_enrollment) fn bind(
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let requested: Result<Self> = (|| {
            stage.require_protected_restore_role(NativeRole::EpochController)?;
            stage.check_serving_acquisition(acquisition)?;
            ensure!(
                rustix::process::geteuid().as_raw() == 10001,
                "protected_restore_listener_uid"
            );
            let root = File::from(rustix::fs::open(
                "/run/day2-native-enrollment",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let directory = StorageSocketDirectory::observe(&root)?;
            stage.check_serving_acquisition(acquisition)?;
            let socket = net::socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )?;
            configure(&socket)?;
            stage.check_serving_acquisition(acquisition)?;
            // Never unlink or adopt an existing endpoint. A failed/unknown
            // setup permanently refuses the actual enrolled owner.
            net::bind(&socket, &net::SocketAddrUnix::new(PATH)?)?;
            stage.check_serving_acquisition(acquisition)?;
            let name = File::from(rustix::fs::open(
                PATH,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            stage.check_serving_acquisition(acquisition)?;
            set_private_socket_mode(&name, acquisition)?;
            stage.check_serving_acquisition(acquisition)?;
            net::listen(&socket, 1)?;
            stage.check_serving_acquisition(acquisition)?;
            let socket = File::from(socket);
            let named = named_socket()?;
            let held = name.metadata()?;
            ensure!(
                (held.dev(), held.ino()) == named,
                "protected_restore_listener_dentry_changed"
            );
            directory.check(&root)?;
            require_listener_profile(&socket)?;
            stage.check_serving_acquisition(acquisition)?;
            Ok(Self {
                socket,
                name,
                root,
                directory,
                named,
                local: PhantomData,
            })
        })();
        let checked = stage.check_serving_acquisition(acquisition);
        if requested.is_err() || checked.is_err() {
            stage.refuse_serving();
            acquisition.refuse();
        }
        let listener = requested?;
        checked?;
        Ok(listener)
    }

    fn check_name(&self) -> Result<()> {
        self.directory.check(&self.root)?;
        let held = self.name.metadata()?;
        ensure!(
            rustix::io::fcntl_getfd(&self.name)?.contains(rustix::io::FdFlags::CLOEXEC)
                && held.mode() & 0o170000 == 0o140000
                && held.uid() == 10001
                && held.mode() & 0o7777 == 0o600
                && (held.dev(), held.ino()) == self.named,
            "protected_restore_listener_dentry_changed"
        );
        ensure!(
            named_socket()? == self.named,
            "protected_restore_listener_path_changed"
        );
        Ok(())
    }

    /// Descriptor construction only. The actual caller must first spend the
    /// one-shot cold admission on this same stage, then authenticate all four
    /// protected messages before it may construct any admitted peer.
    pub(in crate::security_epoch::native_enrollment) fn accept(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Channel> {
        let requested =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Channel> {
                stage.require_protected_restore_role(NativeRole::EpochController)?;
                stage.protected_restore_statement()?;
                stage.check_serving_acquisition(acquisition)?;
                self.check_name()?;
                require_listener_profile(&self.socket)?;
                let socket =
                    net::accept_with(&self.socket, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)?;
                stage.check_serving_acquisition(acquisition)?;
                configure(&socket)?;
                let mut channel = Channel {
                    socket: Rc::new(File::from(socket)),
                    refused: Rc::new(std::cell::Cell::new(false)),
                    transcript: Some(Transcript::new(
                        Protocol::ProtectedRestoreAdmission,
                        Actor::Controller,
                    )),
                    unprivileged_sender: None,
                    local: PhantomData,
                };
                channel.check_protected_open(stage, acquisition)?;
                self.check_name()?;
                require_listener_profile(&self.socket)?;
                Ok(channel)
            }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.check_serving_acquisition(acquisition)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(channel)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(channel)
                }
            },
        }
    }

    /// Zero-time DATA readiness. No NativeAcquisition is created or retained;
    /// a successful poll cannot supply a peer or permit accepting a packet.
    pub(in crate::security_epoch::native_enrollment) fn pending(&self) -> Result<bool> {
        let requested: Result<bool> = (|| {
            self.check_name()?;
            require_listener_profile(&self.socket)?;
            let mut fds = [PollFd::new(&self.socket, PollFlags::IN | PollFlags::RDHUP)];
            rustix::event::poll(
                &mut fds,
                Some(&rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )?;
            let flags = fds[0].revents();
            ensure!(
                !flags.intersects(
                    PollFlags::HUP | PollFlags::RDHUP | PollFlags::ERR | PollFlags::NVAL
                ),
                "native_peer_idle_channel_closed"
            );
            Ok(flags.contains(PollFlags::IN))
        })();
        let checked = self
            .check_name()
            .and_then(|()| require_listener_profile(&self.socket));
        let ready = requested?;
        checked?;
        Ok(ready)
    }
}

impl Channel {
    /// Separate terminal grammar. The received SCM_PIDFD is retained and
    /// independently observed even when packet decoding/signature DATA fails.
    pub(in crate::security_epoch::native_enrollment) fn receive_protected_installed(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<(
        crate::security_epoch::native_enrollment::protected_restore::UnverifiedInstalledPacket,
        ControllerReceipt,
    )> {
        use crate::security_epoch::native_enrollment::protected_restore::{
            MAX_INSTALLED_PACKET_BYTES, UnverifiedInstalledPacket, select_guard_check,
        };
        let mut sender = None;
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<UnverifiedInstalledPacket> {
                stage.require_protected_restore_role(NativeRole::SecurityShell)?;
                self.check_protected_open(stage, acquisition)?;
                let mut bytes = [0_u8; MAX_INSTALLED_PACKET_BYTES];
                self.begin_packet(Direction::Receive, None, acquisition)?;
                let received = loop {
                    self.check_protected_open(stage, acquisition)?;
                    match net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)]) {
                        Ok(received) => break received,
                        Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                            self.transport(Transport::WouldBlock, PollFlags::IN, acquisition)?
                        }
                        Err(RecvPidfdError::Io(Errno::INTR)) => {
                            self.transport(Transport::Interrupted, PollFlags::IN, acquisition)?
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                let count = received.bytes;
                sender = Some(ControllerReceipt::receive(received, acquisition)?);
                let packet = UnverifiedInstalledPacket::decode(&bytes[..count])?;
                self.check_protected_open(stage, acquisition)?;
                self.packet_delivered(Some(packet.frame()), acquisition)?;
                Ok(packet)
            },
        ));
        let native = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_protected_open(stage, acquisition)
        }));
        let receipt =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match &mut sender {
                Some(receipt) => receipt.check_received(acquisition),
                None => Ok(()),
            }));
        let checked = select_guard_check(native, receipt);
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        let packet = match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result?,
        };
        match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result?,
        };
        Ok((
            packet,
            sender
                .take()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_controller_sender_required"))?,
        ))
    }
    /// Independent posts on the same real socket, carrier and native original.
    /// Selection happens only after all three have actually evaluated.
    fn check_protected_installed(
        &mut self,
        frame:&mut crate::security_epoch::native_enrollment::protected_restore::ProtectedRestoreOutputFrame,
        stage: &mut EnrolledRoleStage<'_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreInstalledOutputLoan<'_, '_, '_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        use crate::security_epoch::native_enrollment::protected_restore::select_guard_check;
        let native = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_protected_open(stage, acquisition)
        }));
        let socket = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            frame.check_socket(acquisition)
        }));
        let carrier = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            frame.check_loan(stage, loan)
        }));
        let checked = select_guard_check(select_guard_check(native, socket), carrier);
        if !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            frame.refuse();
            stage.refuse_serving();
            loan.refuse();
            acquisition.refuse();
        }
        match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result,
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn send_protected_installed(
        &mut self,
        frame:&mut crate::security_epoch::native_enrollment::protected_restore::ProtectedRestoreOutputFrame,
        stage: &mut EnrolledRoleStage<'_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreInstalledOutputLoan<'_, '_, '_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        use crate::security_epoch::native_enrollment::{
            ReceiverProgress,
            protected_restore::{InstalledSendStart, select_guard_check},
        };
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<ReceiverProgress> {
                let start = frame.begin_send()?;
                if matches!(start, InstalledSendStart::First) {
                    self.begin_packet(Direction::Send, Some(frame.packet_frame()), acquisition)?;
                }
                self.check_protected_installed(frame, stage, loan, acquisition)?;
                // No wait, native observation, callback or signing intervenes
                // between the last actual carrier check and this one syscall.
                let bytes = frame.bytes()?;
                match net::send(
                    &self.socket,
                    bytes,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                ) {
                    Ok(count) => {
                        ensure!(count == bytes.len(), "protected_restore_partial_packet");
                        Ok(ReceiverProgress::Delivered)
                    }
                    Err(Errno::AGAIN) => Ok(ReceiverProgress::WouldBlock),
                    Err(Errno::INTR) => Ok(ReceiverProgress::Interrupted),
                    Err(error) => Err(error.into()),
                }
            },
        ));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_protected_installed(frame, stage, loan, acquisition)
        }));
        let checked = select_guard_check(Ok(Ok(())), checked);
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            frame.refuse();
            stage.refuse_serving();
            loan.refuse();
            acquisition.refuse();
        }
        let progress = match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result?,
        };
        match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result?,
        };
        let recorded = (|| {
            match progress {
                ReceiverProgress::Delivered => {
                    self.packet_delivered(Some(frame.packet_frame()), acquisition)?
                }
                ReceiverProgress::WouldBlock => {
                    self.transcript
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("native_handshake_transcript_required"))?
                        .transport(Transport::WouldBlock, Self::observation(acquisition))?;
                }
                ReceiverProgress::Interrupted => {
                    self.transcript
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("native_handshake_transcript_required"))?
                        .transport(Transport::Interrupted, Self::observation(acquisition))?;
                }
                _ => anyhow::bail!("protected_restore_installed_send_progress"),
            }
            frame.after_send(progress)?;
            Ok(progress)
        })();
        if recorded.is_err() {
            self.refuse();
            frame.refuse();
            stage.refuse_serving();
            loan.refuse();
            acquisition.refuse();
        }
        recorded
    }

    pub(in crate::security_epoch::native_enrollment) fn poll_protected_installed(
        &mut self,
        frame:&mut crate::security_epoch::native_enrollment::protected_restore::ProtectedRestoreOutputFrame,
        stage: &mut EnrolledRoleStage<'_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreInstalledOutputLoan<'_, '_, '_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        use crate::security_epoch::native_enrollment::ReceiverProgress;
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<ReceiverProgress> {
                frame.require_poll()?;
                self.check_protected_installed(frame, stage, loan, acquisition)?;
                let timeout = rustix::event::Timespec::try_from(acquisition.remaining()?)?;
                let mut fds = [PollFd::new(&self.socket, PollFlags::OUT | PollFlags::RDHUP)];
                match rustix::event::poll(&mut fds, Some(&timeout)) {
                    Ok(1) if fds[0].revents() == PollFlags::OUT => Ok(ReceiverProgress::Advanced),
                    Err(Errno::INTR) => Ok(ReceiverProgress::Interrupted),
                    Err(error) => Err(error.into()),
                    _ => anyhow::bail!("protected_restore_installed_poll_refused"),
                }
            },
        ));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_protected_installed(frame, stage, loan, acquisition)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            frame.refuse();
            stage.refuse_serving();
            loan.refuse();
            acquisition.refuse();
        }
        let progress = match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result?,
        };
        match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result?,
        };
        let recorded = (|| {
            let transport = match progress {
                ReceiverProgress::Advanced => Transport::Ready,
                ReceiverProgress::Interrupted => Transport::Interrupted,
                _ => anyhow::bail!("protected_restore_installed_poll_progress"),
            };
            self.transcript
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("native_handshake_transcript_required"))?
                .transport(transport, Self::observation(acquisition))?;
            frame.after_poll(progress)?;
            Ok(progress)
        })();
        if recorded.is_err() {
            self.refuse();
            frame.refuse();
            stage.refuse_serving();
            loan.refuse();
            acquisition.refuse();
        }
        recorded
    }

    /// The fixed protected caller obtains only an observer of the actual
    /// retained channel, not a caller-selected FD or a checked permission.
    pub(in crate::security_epoch::native_enrollment) fn protected_restore_observer(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<ProtectedRestoreSocketObserver> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_protected_open(stage, acquisition)?;
            let mut observer = ProtectedRestoreSocketObserver {
                socket: Rc::clone(&self.socket),
                refused: Rc::clone(&self.refused),
                process: std::process::id(),
                thread: std::thread::current().id(),
            };
            observer.check(acquisition)?;
            Ok(observer)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.check_serving_acquisition(acquisition)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(observer)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(observer)
                }
            },
        }
    }

    /// Call only after the actual received sender, signature, common clock
    /// and cursor have been authenticated. The child is already narrowed to
    /// that authenticated ceiling. Persist it into the SAME saved stage first,
    /// then meet the historical DATA cursor; neither view may be widened.
    pub(in crate::security_epoch::native_enrollment) fn meet_protected_received(
        &mut self,
        same: &mut SameEnrolledOwner,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            self.check_protected_open(stage, acquisition)?;
            same.meet_current_read_view(stage, acquisition)?;
            self.transcript
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("native_handshake_transcript_required"))?
                .narrow_protected_received(Self::observation(acquisition))?;
            self.check_protected_open(stage, acquisition)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_protected_open(stage, acquisition)
        }));
        if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(())) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => result,
            },
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn connect_protected_restore(
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let requested =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Self> {
                stage.require_protected_restore_role(NativeRole::SecurityShell)?;
                stage.protected_restore_statement()?;
                stage.check_serving_acquisition(acquisition)?;
                ensure!(
                    rustix::process::geteuid().as_raw() == 10001,
                    "protected_restore_listener_uid"
                );
                let named = named_socket()?;
                let socket = net::socket_with(
                    AddressFamily::UNIX,
                    SocketType::SEQPACKET,
                    SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                    None,
                )?;
                configure(&socket)?;
                stage.check_serving_acquisition(acquisition)?;
                net::connect(&socket, &net::SocketAddrUnix::new(PATH)?)?;
                stage.check_serving_acquisition(acquisition)?;
                ensure!(
                    named_socket()? == named,
                    "protected_restore_listener_path_changed"
                );
                let mut channel = Self {
                    socket: Rc::new(File::from(socket)),
                    refused: Rc::new(std::cell::Cell::new(false)),
                    transcript: Some(Transcript::new(
                        Protocol::ProtectedRestoreAdmission,
                        Actor::Shell,
                    )),
                    unprivileged_sender: None,
                    local: PhantomData,
                };
                channel.check_protected_open(stage, acquisition)?;
                Ok(channel)
            }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.check_serving_acquisition(acquisition)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(channel)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(channel)
                }
            },
        }
    }

    // Negative observation of this actual protected channel, stage and saved
    // acquisition. Initial admission lends no descriptor or serving purpose.
    pub(in crate::security_epoch::native_enrollment) fn check_protected_open(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let checked = (|| {
            ensure!(!self.refused.get(), "protected_restore_channel_refused");
            stage.protected_restore_statement()?;
            stage.check_serving_acquisition(acquisition)?;
            require_idle_socket_profile(&self.socket)?;
            ensure!(
                rustix::fs::fcntl_getfl(&self.socket)?.contains(OFlags::NONBLOCK)
                    && net::sockopt::socket_passcred(&self.socket)?
                    && net::sockopt::socket_passpidfd(&self.socket)?,
                "protected_restore_channel_profile"
            );
            require_connected(&self.socket, acquisition)?;
            stage.check_serving_acquisition(acquisition)
        })();
        if checked.is_err() {
            self.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        checked
    }

    pub(in crate::security_epoch::native_enrollment) fn send_protected_admission(
        &mut self,
        body: AdmissionBody,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            self.check_protected_open(stage, acquisition)?;
            let local = stage.protected_restore_statement()?;
            let frame = body.frame();
            let signature =
                stage.sign_protected_restore_message(&ProtectedRestoreMessage::admission(&body))?;
            let bytes = AdmissionPacket::encode(admission_enrollment(&local)?, body, signature)?;
            self.begin_packet(Direction::Send, Some(frame), acquisition)?;
            loop {
                self.check_protected_open(stage, acquisition)?;
                match net::send(
                    &self.socket,
                    &bytes,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                ) {
                    Ok(count) => {
                        ensure!(count == bytes.len(), "protected_restore_partial_packet");
                        break;
                    }
                    Err(Errno::AGAIN) => {
                        self.transport(Transport::WouldBlock, PollFlags::OUT, acquisition)?
                    }
                    Err(Errno::INTR) => {
                        self.transport(Transport::Interrupted, PollFlags::OUT, acquisition)?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            self.check_protected_open(stage, acquisition)?;
            self.packet_delivered(Some(frame), acquisition)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_protected_open(stage, acquisition)
        }));
        if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(())) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => result,
            },
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn receive_protected_admission(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<(AdmissionPacket, ServingSender)> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<(AdmissionPacket, ServingSender)> {
                self.check_protected_open(stage, acquisition)?;
                let expected_code = stage.serving_peer_code()?;
                let mut bytes = [0_u8; MAX_ADMISSION_PACKET_BYTES];
                self.begin_packet(Direction::Receive, None, acquisition)?;
                let received = loop {
                    self.check_protected_open(stage, acquisition)?;
                    match net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)]) {
                        Ok(received) => break received,
                        Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                            self.transport(Transport::WouldBlock, PollFlags::IN, acquisition)?
                        }
                        Err(RecvPidfdError::Io(Errno::INTR)) => {
                            self.transport(Transport::Interrupted, PollFlags::IN, acquisition)?
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                let packet = AdmissionPacket::decode(&bytes[..received.bytes])?;
                let sender = match stage.serving_peer_role()? {
                    NativeRole::SecurityShell => ServingSender::Shell(Box::new(
                        self.receive_unprivileged_sender(received, &expected_code, acquisition)?,
                    )),
                    NativeRole::EpochController => ServingSender::Controller(
                        ControllerReceipt::receive(received, acquisition)?,
                    ),
                    NativeRole::AppHost => anyhow::bail!("protected_restore_sender_app_refused"),
                };
                self.check_protected_open(stage, acquisition)?;
                self.packet_delivered(Some(packet.body.frame()), acquisition)?;
                Ok((packet, sender))
            },
        ));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_protected_open(stage, acquisition)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(packet)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(packet)
                }
            },
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn send_protected_command(
        &mut self,
        data: CommandData,
        admitted: &Statement,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            self.check_protected_open(stage, acquisition)?;
            let frame = data.frame();
            let signature = stage.sign_protected_restore_message(
                &ProtectedRestoreMessage::command(&data, admitted),
            )?;
            let bytes = UnverifiedCommandPacket::encode(data, signature)?;
            self.begin_packet(Direction::Send, Some(frame), acquisition)?;
            loop {
                self.check_protected_open(stage, acquisition)?;
                match net::send(
                    &self.socket,
                    &bytes,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                ) {
                    Ok(count) => {
                        ensure!(count == bytes.len(), "protected_restore_partial_packet");
                        break;
                    }
                    Err(Errno::AGAIN) => {
                        self.transport(Transport::WouldBlock, PollFlags::OUT, acquisition)?
                    }
                    Err(Errno::INTR) => {
                        self.transport(Transport::Interrupted, PollFlags::OUT, acquisition)?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            self.check_protected_open(stage, acquisition)?;
            self.packet_delivered(Some(frame), acquisition)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_protected_open(stage, acquisition)
        }));
        if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(())) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => result,
            },
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn receive_protected_command(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<(UnverifiedCommandPacket, ServingSender)> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<(UnverifiedCommandPacket, ServingSender)> {
                self.check_protected_open(stage, acquisition)?;
                let expected_code = stage.serving_peer_code()?;
                let mut bytes = [0_u8; MAX_COMMAND_PACKET_BYTES];
                self.begin_packet(Direction::Receive, None, acquisition)?;
                let received = loop {
                    self.check_protected_open(stage, acquisition)?;
                    match net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)]) {
                        Ok(received) => break received,
                        Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                            self.transport(Transport::WouldBlock, PollFlags::IN, acquisition)?
                        }
                        Err(RecvPidfdError::Io(Errno::INTR)) => {
                            self.transport(Transport::Interrupted, PollFlags::IN, acquisition)?
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                let packet = UnverifiedCommandPacket::decode(&bytes[..received.bytes])?;
                let sender = match stage.serving_peer_role()? {
                    NativeRole::SecurityShell => ServingSender::Shell(Box::new(
                        self.receive_unprivileged_sender(received, &expected_code, acquisition)?,
                    )),
                    NativeRole::EpochController => ServingSender::Controller(
                        ControllerReceipt::receive(received, acquisition)?,
                    ),
                    NativeRole::AppHost => anyhow::bail!("protected_restore_sender_app_refused"),
                };
                self.check_protected_open(stage, acquisition)?;
                self.packet_delivered(Some(packet.frame()), acquisition)?;
                Ok((packet, sender))
            },
        ));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_protected_open(stage, acquisition)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(packet)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(packet)
                }
            },
        }
    }
}

fn require_listener_profile(socket: &File) -> Result<()> {
    require_idle_socket_profile(socket)?;
    ensure!(
        rustix::fs::fcntl_getfl(socket)?.contains(OFlags::NONBLOCK)
            && net::sockopt::socket_acceptconn(socket)?
            && net::sockopt::socket_passcred(socket)?
            && net::sockopt::socket_passpidfd(socket)?,
        "protected_restore_listener_profile"
    );
    Ok(())
}

/// Metadata on this retained socket dentry only. The actual bind factory owns
/// the enrolled stage; this helper cannot return a listener, peer or authority.
pub(super) fn set_private_socket_mode(
    name: &File,
    acquisition: &mut NativeAcquisition,
) -> Result<()> {
    let requested: Result<()> = (|| {
        acquisition.remaining()?;
        let before = name.metadata()?;
        ensure!(
            before.mode() & 0o170000 == 0o140000
                && before.uid() == rustix::process::geteuid().as_raw()
                && rustix::io::fcntl_getfd(name)?.contains(rustix::io::FdFlags::CLOEXEC),
            "protected_restore_listener_dentry_shape"
        );
        // The numeric name selects THIS still-owned O_PATH descriptor in
        // the held proc-fd directory, not an untrusted socket-path symlink.
        // There is no alternate path or retry if this fixed operation refuses.
        let proc_fds = File::from(rustix::fs::open(
            "/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        acquisition.remaining()?;
        rustix::fs::chmodat(
            &proc_fds,
            name.as_raw_fd().to_string(),
            Mode::RUSR | Mode::WUSR,
            AtFlags::empty(),
        )?;
        acquisition.remaining()?;
        let after = name.metadata()?;
        ensure!(
            (before.dev(), before.ino(), before.uid()) == (after.dev(), after.ino(), after.uid())
                && after.mode() & 0o170000 == 0o140000
                && after.mode() & 0o7777 == 0o600,
            "protected_restore_listener_dentry_changed"
        );
        Ok(())
    })();
    let checked = acquisition.remaining();
    if requested.is_err() || checked.is_err() {
        acquisition.refuse();
    }
    requested?;
    checked?;
    Ok(())
}

fn named_socket() -> Result<(u64, u64)> {
    let named = std::fs::symlink_metadata(PATH)?;
    ensure!(
        named.mode() & 0o170000 == 0o140000
            && named.uid() == 10001
            && named.mode() & 0o7777 == 0o600,
        "protected_restore_listener_named_shape"
    );
    Ok((named.dev(), named.ino()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[derive(Debug)]
    enum ObserverFixtureRefusal {
        SocketPair,
        CredentialsOrPidfd,
    }

    impl std::fmt::Display for ObserverFixtureRefusal {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(match self {
                Self::SocketPair => "protected_socket_fixture_pair_setup_refused",
                Self::CredentialsOrPidfd => {
                    "protected_socket_fixture_credentials_or_pidfd_setup_refused"
                }
            })
        }
    }

    impl std::error::Error for ObserverFixtureRefusal {}

    fn observed_pair() -> Result<(ProtectedRestoreSocketObserver, rustix::fd::OwnedFd)> {
        // Actual connected kernel resources only, with no enrolled stage,
        // native admission, request, peer or permission. Setup failure is a
        // typed test error, never a silently successful conformance case.
        let (socket, peer) = net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|_| ObserverFixtureRefusal::SocketPair)?;
        configure(&socket).map_err(|_| ObserverFixtureRefusal::CredentialsOrPidfd)?;
        Ok((
            ProtectedRestoreSocketObserver {
                socket: Rc::new(File::from(socket)),
                refused: Rc::new(std::cell::Cell::new(false)),
                process: std::process::id(),
                thread: std::thread::current().id(),
            },
            peer,
        ))
    }

    #[test]
    fn actual_socket_observer_refuses_buffered_bytes_after_peer_death_and_never_repairs()
    -> Result<()> {
        let (mut observer, peer) = observed_pair()?;
        observer.check(&mut clock())?;
        net::send(
            &peer,
            b"untrusted queued DATA",
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )?;
        drop(peer);
        let mut original = clock();
        assert!(observer.check(&mut original).is_err());
        assert!(observer.refused.get());
        assert!(original.remaining().is_err());
        assert!(observer.check(&mut clock()).is_err());
        Ok(())
    }

    #[test]
    fn actual_socket_observer_keeps_the_same_refusal_root_and_rejects_flag_repair() -> Result<()> {
        let (mut observer, _peer) = observed_pair()?;
        let root = Rc::clone(&observer.refused);
        observer.check(&mut clock())?;
        rustix::io::fcntl_setfd(&observer.socket, rustix::io::FdFlags::empty())?;
        assert!(observer.check(&mut clock()).is_err());
        assert!(root.get());
        rustix::io::fcntl_setfd(&observer.socket, rustix::io::FdFlags::CLOEXEC)?;
        assert!(observer.check(&mut clock()).is_err());
        let (mut other, _other_peer) = observed_pair()?;
        other.check(&mut clock())?;
        root.set(true);
        assert!(!other.refused.get());
        other.check(&mut clock())?;
        Ok(())
    }

    #[test]
    fn actual_socket_observer_rejects_foreign_creator_before_any_rescue() -> Result<()> {
        let (mut observer, _peer) = observed_pair()?;
        observer.process = 0;
        let mut original = clock();
        assert!(observer.check(&mut original).is_err());
        assert!(original.remaining().is_err());
        observer.process = std::process::id();
        assert!(observer.check(&mut clock()).is_err());
        Ok(())
    }

    fn clock() -> NativeAcquisition {
        // A clock fixture for a raw filesystem operation only, not an enrolled
        // role, listener, native stage or accepting peer.
        NativeAcquisition::fixture(
            day2_capabilities::Digest::new(b"socket-dentry-data-fixture"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        )
    }

    fn socket(path: &std::path::Path) -> Result<(File, File)> {
        let socket = net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        net::bind(&socket, &net::SocketAddrUnix::new(path)?)?;
        let name = File::from(rustix::fs::open(
            path,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        Ok((File::from(socket), name))
    }

    #[test]
    fn mode_operation_uses_the_actual_pinned_socket_even_after_path_replacement() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("raw-data.sock");
        let (_socket, name) = socket(&path)?;
        std::fs::remove_file(&path)?;
        std::fs::write(&path, b"foreign ordinary file")?;
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
        set_private_socket_mode(&name, &mut clock())?;
        assert_eq!(name.metadata()?.mode() & 0o7777, 0o600);
        assert_eq!(std::fs::symlink_metadata(&path)?.mode() & 0o7777, 0o644);
        assert_eq!(std::fs::read(&path)?, b"foreign ordinary file");
        Ok(())
    }

    #[test]
    fn symlink_and_regular_file_dentries_refuse_before_mode_change_and_stay_refused() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("ordinary");
        std::fs::write(&path, b"private raw fixture")?;
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
        let link = directory.path().join("alias");
        std::os::unix::fs::symlink(&path, &link)?;
        let (_socket, valid) = socket(&directory.path().join("valid.sock"))?;
        let valid_mode = valid.metadata()?.mode();
        for candidate in [&path, &link] {
            let name = File::from(rustix::fs::open(
                candidate,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let mut original = clock();
            assert!(set_private_socket_mode(&name, &mut original).is_err());
            assert!(original.remaining().is_err());
            assert!(set_private_socket_mode(&name, &mut original).is_err());
            // Replacing the bad input with an actual socket does not rescue
            // this spent observation, nor change that other socket's mode.
            assert!(set_private_socket_mode(&valid, &mut original).is_err());
            assert_eq!(valid.metadata()?.mode(), valid_mode);
            assert_eq!(std::fs::metadata(&path)?.mode() & 0o7777, 0o644);
        }
        Ok(())
    }
}
