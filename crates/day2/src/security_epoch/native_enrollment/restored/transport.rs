//! Fixed restore-only channel. No ordinary role/grant, received-FD adoption,
//! caller path or clock accessor constructs a restored process or peer.
use super::{
    AdmittedRestoreProcess, AppInstalledHandoff, AppPreparedHandoff, DecisionReceiveAttempt,
    ReceivedRestorePacket, RestoreTransport, RestoredAppPeer, RestoredControllerReceipt,
    RoleReceiveAttempt,
};
use crate::security_epoch::native_enrollment::handshake::{Direction, Observation, Transport};
use crate::security_epoch::native_enrollment::storage_peer_wire::{Message, StageStatement};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    NativeRole,
    channel::{configure, wait},
    handshake::{Actor, Protocol, Transcript, TransportDecision},
    process,
    protocol::{self, MAX_PACKET},
    restore_peer_wire::{self as wire, RestoreBody},
    storage_peer_wire::Body,
};
use crate::security_epoch::{
    native_clock::NativeAcquisition, native_enrollment::EnrolledRoleStage,
};
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::ensure;
#[cfg(target_os = "linux")]
use day2_capabilities::Digest;
use rustix::event::PollFlags;
#[cfg(target_os = "linux")]
use rustix::{
    event::PollFd,
    io::Errno,
    net::{self, RecvPidfdError},
};
#[cfg(target_os = "linux")]
use std::{fs::File, io::IoSliceMut, marker::PhantomData};

const PATH: &str = "/run/day2-native-enrollment/storage/restore.sock";

impl RestoredControllerReceipt {
    fn received(packet: ReceivedRestorePacket, app: &mut AdmittedRestoreProcess) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (packet, app);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            app.check()?;
            let requested: Result<_> = (|| {
                let packet = packet.packet;
                let sender = match packet.credentials.process {
                    net::KernelPidVisibility::Visible(pid) => pid.get(),
                    net::KernelPidVisibility::NotVisible => {
                        anyhow::bail!("restore_peer_controller_not_visible")
                    }
                };
                let pidfd = File::from(packet.process);
                process::live(&pidfd, &mut app.receiver.original)?;
                Ok(Self {
                    pidfd,
                    sender,
                    statement: None,
                    process: std::process::id(),
                    thread: std::thread::current().id(),
                    refused: false,
                    local_only: PhantomData,
                })
            })();
            let checked = app.check();
            if requested.is_err() || checked.is_err() {
                app.receiver.refuse();
            }
            let receipt = requested?;
            checked?;
            Ok(receipt)
        }
    }

    pub(super) fn live(&mut self, app: &mut AdmittedRestoreProcess) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, app);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            ensure!(
                !self.refused
                    && self.process == std::process::id()
                    && self.thread == std::thread::current().id(),
                "restore_peer_receipt_refused"
            );
            process::live(&self.pidfd, &mut app.receiver.original)
        }
    }

    pub(super) fn bind(
        &mut self,
        message: &Message,
        statement: &StageStatement,
        app: &mut AdmittedRestoreProcess,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, message, statement, app);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            app.check()?;
            let requested: Result<()> = (|| {
                self.live(app)?;
                let local = app.statement_data()?;
                local.require_controller(statement)?;
                ensure!(
                    statement.stage.data.process.process == self.sender,
                    "restore_peer_controller_sender_changed"
                );
                // The actual sender handle, fresh issuer authorization and key
                // possession are mandatory; historical request DATA is not a grant.
                message.verify(statement)?;
                super::super::runtime::require_common(
                    &statement.stage.data.process,
                    &app.receiver
                        .current
                        .try_borrow()
                        .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                        .data,
                )?;
                let now = app.receiver.original.sample()?.elapsed;
                local.validate_controller_data(
                    &app.receiver.policy,
                    statement,
                    self.sender,
                    now,
                )?;
                let digest = statement.digest()?;
                ensure!(
                    self.statement.as_ref().is_none_or(|old| old == &digest),
                    "restore_peer_controller_rebound"
                );
                self.statement = Some(digest);
                // Meet only a ceiling authenticated after the common clock join.
                // This narrows the same actual App view and never revives a grant.
                let ceiling = statement
                    .original
                    .deadline_ns
                    .min(app.authorization.statement.effective_deadline_ns);
                app.receiver.narrow_authenticated_ceiling(ceiling)?;
                self.live(app)
            })();
            let checked = app.check();
            if requested.is_err() || checked.is_err() {
                self.refused = true;
                app.receiver.refuse();
            }
            requested?;
            checked
        }
    }

    fn check(
        &mut self,
        statement: &StageStatement,
        app: &mut AdmittedRestoreProcess,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, statement, app);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            app.check()?;
            let requested = (|| {
                ensure!(
                    self.statement.as_ref() == Some(&statement.digest()?),
                    "restore_peer_controller_not_bound"
                );
                self.live(app)
            })();
            let checked = app.check();
            if requested.is_err() || checked.is_err() {
                self.refused = true;
                app.receiver.refuse();
            }
            requested?;
            checked
        }
    }
}

impl RestoreTransport {
    fn observation(
        original: &crate::security_epoch::native_clock::NativeAcquisition,
    ) -> Observation {
        let (domain, origin, deadline, now) = original.historical_interval_observation();
        Observation {
            domain,
            origin,
            deadline,
            now,
        }
    }

    fn refuse(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.refused.set(true);
            self.transcript.refuse();
        }
    }

    fn begin_packet(
        &mut self,
        direction: Direction,
        frame: Option<super::super::handshake::Frame>,
        original: &crate::security_epoch::native_clock::NativeAcquisition,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, direction, frame, original);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            if direction == Direction::Send {
                self.transcript
                    .select_frame(frame.ok_or_else(|| anyhow::anyhow!("restore_peer_frame"))?)?;
            }
            self.transcript
                .begin(direction, Self::observation(original))
        }
    }

    fn packet_delivered(
        &mut self,
        frame: Option<super::super::handshake::Frame>,
        original: &crate::security_epoch::native_clock::NativeAcquisition,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, frame, original);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.transcript.delivered(
                frame.ok_or_else(|| anyhow::anyhow!("restore_peer_frame"))?,
                Self::observation(original),
            )
        }
    }

    fn transport(
        &mut self,
        transport: Transport,
        events: PollFlags,
        original: &mut crate::security_epoch::native_clock::NativeAcquisition,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, transport, events, original);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            if self
                .transcript
                .transport(transport, Self::observation(original))?
                == TransportDecision::Wait
            {
                wait(&self.socket, events, original)?;
                self.transcript
                    .transport(Transport::Ready, Self::observation(original))?;
            }
            Ok(())
        }
    }
    fn connect_restore(app: &mut AdmittedRestoreProcess) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (app,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            app.check()?;
            let requested: Result<_> = (|| {
                ensure!(
                    rustix::process::geteuid().as_raw() == 10001,
                    "restore_peer_filesystem_uid"
                );
                let socket = net::socket_with(
                    net::AddressFamily::UNIX,
                    net::SocketType::SEQPACKET,
                    net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                    None,
                )?;
                configure(&socket)?;
                net::connect(&socket, &net::SocketAddrUnix::new(PATH)?)?;
                Ok(Self {
                    socket: std::rc::Rc::new(File::from(socket)),
                    refused: std::rc::Rc::new(std::cell::Cell::new(false)),
                    transcript: Transcript::new(Protocol::RestoredStorage, Actor::App),
                    operation: super::RestoreTransportOperation::Restoring,
                    local_only: PhantomData,
                })
            })();
            let checked = app.check();
            if requested.is_err() || checked.is_err() {
                app.receiver.refuse();
            }
            let mut channel = requested?;
            checked?;
            channel.check_restore_open(app)?;
            Ok(channel)
        }
    }

    fn check_restore_open(&mut self, app: &mut AdmittedRestoreProcess) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, app);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            if self.operation != super::RestoreTransportOperation::Restoring {
                self.refuse();
                app.receiver.refuse();
                anyhow::bail!("restore_peer_operational_socket_transferred");
            }
            app.check()?;
            let requested: Result<()> = (|| {
                ensure!(!self.refused.get(), "restore_peer_channel_refused");
                ensure!(
                    rustix::io::fcntl_getfd(&self.socket)?.contains(rustix::io::FdFlags::CLOEXEC),
                    "restore_peer_channel_not_cloexec"
                );
                loop {
                    let mut poll = [PollFd::new(&self.socket, PollFlags::RDHUP)];
                    match rustix::event::poll(
                        &mut poll,
                        Some(&rustix::time::Timespec {
                            tv_sec: 0,
                            tv_nsec: 0,
                        }),
                    ) {
                        Ok(_) => {
                            ensure!(
                                !poll[0].revents().intersects(
                                    PollFlags::HUP
                                        | PollFlags::RDHUP
                                        | PollFlags::ERR
                                        | PollFlags::NVAL
                                ),
                                "restore_peer_channel_closed"
                            );
                            break;
                        }
                        Err(Errno::INTR) => {
                            app.check()?;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Ok(())
            })();
            let checked = app.check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
                app.receiver.refuse();
            }
            requested?;
            checked
        }
    }

    pub(super) fn send_restore(
        &mut self,
        message: &Message,
        app: &mut AdmittedRestoreProcess,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, message, app);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check_restore_open(app)?;
            let requested: Result<()> = (|| {
                ensure!(
                    matches!(&message.body, Body::Restore { payload } if payload.sender_role() == NativeRole::AppHost),
                    "restore_peer_app_phase_required"
                );
                let bytes = serde_json::to_vec(message)?;
                ensure!(
                    !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                    "restore_peer_packet_bound"
                );
                self.begin_packet(
                    Direction::Send,
                    Some(message.body.frame()),
                    &app.receiver.original,
                )?;
                loop {
                    self.check_restore_open(app)?;
                    match net::send(
                        &self.socket,
                        &bytes,
                        net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
                    ) {
                        Ok(count) => {
                            ensure!(count == bytes.len(), "restore_peer_partial_packet");
                            break;
                        }
                        Err(Errno::AGAIN) => self.transport(
                            Transport::WouldBlock,
                            PollFlags::OUT,
                            &mut app.receiver.original,
                        )?,
                        Err(Errno::INTR) => self.transport(
                            Transport::Interrupted,
                            PollFlags::OUT,
                            &mut app.receiver.original,
                        )?,
                        Err(error) => return Err(error.into()),
                    }
                }
                self.packet_delivered(Some(message.body.frame()), &app.receiver.original)
            })();
            let checked = self.check_restore_open(app);
            if requested.is_err() || checked.is_err() {
                self.refuse();
                app.receiver.refuse();
            }
            requested?;
            checked
        }
    }

    pub(super) fn receive_restore(
        &mut self,
        app: &mut AdmittedRestoreProcess,
    ) -> Result<(Message, RestoredControllerReceipt)> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, app);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check_restore_open(app)?;
            let requested: Result<_> = (|| {
                let mut bytes = [0u8; MAX_PACKET];
                self.begin_packet(Direction::Receive, None, &app.receiver.original)?;
                let received = loop {
                    self.check_restore_open(app)?;
                    match net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)]) {
                        Ok(packet) => break packet,
                        Err(RecvPidfdError::Io(Errno::AGAIN)) => self.transport(
                            Transport::WouldBlock,
                            PollFlags::IN,
                            &mut app.receiver.original,
                        )?,
                        Err(RecvPidfdError::Io(Errno::INTR)) => self.transport(
                            Transport::Interrupted,
                            PollFlags::IN,
                            &mut app.receiver.original,
                        )?,
                        Err(error) => return Err(error.into()),
                    }
                };
                let message = super::super::storage_peer_wire::decode(&bytes[..received.bytes])?;
                ensure!(
                    matches!(&message.body, Body::Restore { payload } if payload.sender_role() == NativeRole::EpochController),
                    "restore_peer_controller_phase_required"
                );
                let receipt = RestoredControllerReceipt::received(
                    ReceivedRestorePacket {
                        packet: received,
                        local_only: PhantomData,
                    },
                    app,
                )?;
                self.packet_delivered(Some(message.body.frame()), &app.receiver.original)?;
                Ok((message, receipt))
            })();
            let checked = self.check_restore_open(app);
            if requested.is_err() || checked.is_err() {
                self.refuse();
                app.receiver.refuse();
            }
            let value = requested?;
            checked?;
            Ok(value)
        }
    }
}

impl RoleReceiveAttempt<'_> {
    /// One fixed packet from the already-held Controller socket. The actual
    /// first keeper and both originals remain under the lexical negative owner.
    pub(super) fn receive_role_packet(&mut self) -> Result<Message> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            self.local_check()?;
            let requested = (|| {
                ensure!(
                    self.transcript.is_none() && self.receipt.is_none(),
                    "restore_role_receive_reentered"
                );
                let observation = self.observation()?;
                let transcript = {
                    let peer = &mut self.keeper.input.owner.captured.peer;
                    peer.channel
                        .transcript
                        .derive_restored_role(observation.clone())?
                };
                self.transcript = Some(transcript);
                self.transcript
                    .as_mut()
                    .context("restore_role_receive_transcript_missing")?
                    .begin(Direction::Receive, observation)?;
                let mut bytes = [0u8; MAX_PACKET];
                let packet = loop {
                    self.local_check()?;
                    let received = {
                        let peer = &self.keeper.input.owner.captured.peer;
                        net::recv_pidfd_packet(
                            &peer.channel.socket,
                            &mut [IoSliceMut::new(&mut bytes)],
                        )
                    };
                    let checked = self.local_check();
                    match received {
                        Ok(packet) => {
                            checked?;
                            break packet;
                        }
                        Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                            checked?;
                            self.wait_role_readable()?;
                        }
                        Err(RecvPidfdError::Io(Errno::INTR)) => {
                            checked?;
                            let observation = self.observation()?;
                            self.transcript
                                .as_mut()
                                .context("restore_role_receive_transcript_missing")?
                                .transport(Transport::Interrupted, observation)?;
                        }
                        Err(error) => {
                            let _ = checked;
                            return Err(error.into());
                        }
                    }
                };
                let count = packet.bytes;
                let receipt = {
                    let peer = &mut self.keeper.input.owner.captured.peer;
                    RestoredControllerReceipt::received(
                        ReceivedRestorePacket {
                            packet,
                            local_only: PhantomData,
                        },
                        &mut peer.process,
                    )?
                };
                // Retain the actual original pidfd before interpreting any
                // message; all later errors still run the actual liveness post.
                self.receipt = Some(receipt);
                self.local_check()?;
                super::super::storage_peer_wire::decode(&bytes[..count])
            })();
            let checked = self.local_check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            let message = requested?;
            checked?;
            Ok(message)
        }
    }

    fn wait_role_readable(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let observation = self.observation()?;
            self.transcript
                .as_mut()
                .context("restore_role_receive_transcript_missing")?
                .transport(Transport::WouldBlock, observation)?;
            loop {
                let transport = self.poll_role_once()?;
                let observation = self.observation()?;
                let decision = self
                    .transcript
                    .as_mut()
                    .context("restore_role_receive_transcript_missing")?
                    .transport(transport, observation)?;
                if decision == TransportDecision::Retry {
                    return Ok(());
                }
            }
        }
    }

    fn poll_role_once(&mut self) -> Result<Transport> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let requested = (|| {
                self.local_check()?;
                let observation = self.observation()?;
                let remaining = observation
                    .deadline
                    .checked_sub(observation.now)
                    .context("restore_role_receive_expired")?;
                let timeout = rustix::event::Timespec::try_from(remaining)?;
                let peer = &self.keeper.input.owner.captured.peer;
                let mut fds = [PollFd::new(
                    &peer.channel.socket,
                    PollFlags::IN | PollFlags::RDHUP,
                )];
                match rustix::event::poll(&mut fds, Some(&timeout)) {
                    Ok(1) => {
                        let flags = fds[0].revents();
                        ensure!(
                            flags.contains(PollFlags::IN)
                                && !flags.intersects(
                                    PollFlags::HUP
                                        | PollFlags::RDHUP
                                        | PollFlags::ERR
                                        | PollFlags::NVAL
                                ),
                            "restore_role_receive_poll_events"
                        );
                        Ok(Transport::Ready)
                    }
                    Ok(_) => anyhow::bail!("restore_role_receive_poll_timeout_or_count"),
                    Err(Errno::INTR) => Ok(Transport::Interrupted),
                    Err(error) => Err(error.into()),
                }
            })();
            let checked = self.local_check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            let transport = requested?;
            checked?;
            Ok(transport)
        }
    }
}

impl DecisionReceiveAttempt<'_> {
    /// One fixed packet from the already-held Controller socket. The actual
    /// first keeper and both originals remain under the lexical negative owner.
    pub(super) fn receive_decision_packet(&mut self) -> Result<Message> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            self.local_check()?;
            let requested = (|| {
                ensure!(
                    self.transcript.is_none() && self.receipt.is_none(),
                    "restore_decision_receive_reentered"
                );
                let observation = self.observation()?;
                let transcript = self
                    .owner
                    .role_transcript
                    .derive_restored_decision(observation.clone())?;
                self.transcript = Some(transcript);
                self.transcript
                    .as_mut()
                    .context("restore_decision_receive_transcript_missing")?
                    .begin(Direction::Receive, observation)?;
                let mut bytes = [0u8; MAX_PACKET];
                let packet = loop {
                    self.local_check()?;
                    let received = {
                        let peer = &self.owner.keeper.input.owner.captured.peer;
                        net::recv_pidfd_packet(
                            &peer.channel.socket,
                            &mut [IoSliceMut::new(&mut bytes)],
                        )
                    };
                    let checked = self.local_check();
                    match received {
                        Ok(packet) => {
                            checked?;
                            break packet;
                        }
                        Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                            checked?;
                            self.wait_decision_readable()?;
                        }
                        Err(RecvPidfdError::Io(Errno::INTR)) => {
                            checked?;
                            let observation = self.observation()?;
                            self.transcript
                                .as_mut()
                                .context("restore_decision_receive_transcript_missing")?
                                .transport(Transport::Interrupted, observation)?;
                        }
                        Err(error) => {
                            let _ = checked;
                            return Err(error.into());
                        }
                    }
                };
                let count = packet.bytes;
                let receipt = {
                    let peer = &mut self.owner.keeper.input.owner.captured.peer;
                    RestoredControllerReceipt::received(
                        ReceivedRestorePacket {
                            packet,
                            local_only: PhantomData,
                        },
                        &mut peer.process,
                    )?
                };
                // Retain the actual original pidfd before interpreting any
                // message; all later errors still run the actual liveness post.
                self.receipt = Some(receipt);
                self.local_check()?;
                super::super::storage_peer_wire::decode(&bytes[..count])
            })();
            let checked = self.local_check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            let message = requested?;
            checked?;
            Ok(message)
        }
    }

    fn wait_decision_readable(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let observation = self.observation()?;
            self.transcript
                .as_mut()
                .context("restore_decision_receive_transcript_missing")?
                .transport(Transport::WouldBlock, observation)?;
            loop {
                let transport = self.poll_decision_once()?;
                let observation = self.observation()?;
                let decision = self
                    .transcript
                    .as_mut()
                    .context("restore_decision_receive_transcript_missing")?
                    .transport(transport, observation)?;
                if decision == TransportDecision::Retry {
                    return Ok(());
                }
            }
        }
    }

    fn poll_decision_once(&mut self) -> Result<Transport> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let requested = (|| {
                self.local_check()?;
                let observation = self.observation()?;
                let remaining = observation
                    .deadline
                    .checked_sub(observation.now)
                    .context("restore_decision_receive_expired")?;
                let timeout = rustix::event::Timespec::try_from(remaining)?;
                let peer = &self.owner.keeper.input.owner.captured.peer;
                let mut fds = [PollFd::new(
                    &peer.channel.socket,
                    PollFlags::IN | PollFlags::RDHUP,
                )];
                match rustix::event::poll(&mut fds, Some(&timeout)) {
                    Ok(1) => {
                        let flags = fds[0].revents();
                        ensure!(
                            flags.contains(PollFlags::IN)
                                && !flags.intersects(
                                    PollFlags::HUP
                                        | PollFlags::RDHUP
                                        | PollFlags::ERR
                                        | PollFlags::NVAL
                                ),
                            "restore_decision_receive_poll_events"
                        );
                        Ok(Transport::Ready)
                    }
                    Ok(_) => anyhow::bail!("restore_decision_receive_poll_timeout_or_count"),
                    Err(Errno::INTR) => Ok(Transport::Interrupted),
                    Err(error) => Err(error.into()),
                }
            })();
            let checked = self.local_check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            let transport = requested?;
            checked?;
            Ok(transport)
        }
    }
}

impl AdmittedRestoreProcess {
    /// Fixed App-side Ready/Hello/Offer exchange. Its result owns the actual
    /// selected sender receipts but has no file, P3, SQL or writer permission.
    pub(in crate::security_epoch::native_enrollment) fn connect_restore(
        mut self,
    ) -> Result<RestoredAppPeer> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&mut self,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<_> = (|| {
                let mut channel = RestoreTransport::connect_restore(&mut self)?;
                let (ready, mut ready_receipt) = channel.receive_restore(&mut self)?;
                let authorized = &self.authorization.statement.data;
                let selection = wire::Selection {
                    operation: authorized.operation.clone(),
                    approval_request: authorized.approval.clone(),
                    intent: authorized.intent.clone(),
                    full_archive: authorized.full_archive.clone(),
                    target: authorized.target.clone(),
                };
                let Body::Restore { payload } = &ready.body else {
                    anyhow::bail!("restore_peer_expected_ready");
                };
                let (controller, controller_nonce) = payload.ready(&selection)?;
                ready_receipt.bind(&ready, controller, &mut self)?;
                let controller = controller.clone();
                let controller_nonce = controller_nonce.clone();
                let local = self.statement_data()?;
                self.check()?;
                let nonce = protocol::nonce("restore-app-peer");
                let checked = self.check();
                let nonce = nonce?;
                checked?;
                let body = Body::Restore {
                    payload: RestoreBody::Hello {
                        app: Box::new(local.clone()),
                        nonce: nonce.clone(),
                        controller_nonce: controller_nonce.clone(),
                        selection: selection.clone(),
                    },
                };
                let sender = local.digest()?;
                self.check()?;
                let signature = self
                    .receiver
                    .key
                    .sign("restored-storage-message", &(&sender, &body));
                let checked = self.check();
                let signature = signature?;
                checked?;
                channel.send_restore(
                    &Message {
                        sender,
                        body,
                        signature,
                    },
                    &mut self,
                )?;
                ready_receipt.check(&controller, &mut self)?;
                let (offer, mut offer_receipt) = channel.receive_restore(&mut self)?;
                offer_receipt.bind(&offer, &controller, &mut self)?;
                let Body::Restore { payload } = &offer.body else {
                    anyhow::bail!("restore_peer_expected_offer");
                };
                let (exchange, projection) =
                    payload.offer(&selection, &local, &controller, &nonce, &controller_nonce)?;
                ensure!(
                    projection.report == self.authorization.statement.data.report,
                    "restore_peer_authorized_report_changed"
                );
                ready_receipt.check(&controller, &mut self)?;
                offer_receipt.check(&controller, &mut self)?;
                channel.check_restore_open(&mut self)?;
                Ok((
                    channel,
                    controller,
                    ready_receipt,
                    offer_receipt,
                    local,
                    projection.clone(),
                    exchange.clone(),
                ))
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.receiver.refuse();
            }
            let (channel, controller, first, second, local, projection, exchange) = requested?;
            checked?;
            Ok(RestoredAppPeer {
                process: self,
                channel,
                controller,
                receipts: vec![first, second],
                local,
                projection,
                exchange,
                refused: false,
                local_only: PhantomData,
            })
        }
    }
}

impl RestoredAppPeer {
    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.process.check()?;
            let requested: Result<()> = (|| {
                ensure!(
                    !self.refused && (2..=5).contains(&self.receipts.len()),
                    "restore_peer_owner_refused"
                );
                for receipt in &mut self.receipts {
                    receipt.check(&self.controller, &mut self.process)?;
                }
                self.channel.check_restore_open(&mut self.process)
            })();
            let checked = self.process.check();
            if requested.is_err() || checked.is_err() {
                self.refused = true;
                self.process.receiver.refuse();
            }
            requested?;
            checked
        }
    }
}

impl AppPreparedHandoff {
    pub(super) fn send_prepared_ack(&mut self) -> Result<()> {
        let requested: Result<()> = (|| {
            self.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                ensure!(
                    !self.ack_delivered && !self.accepted && self.receipt.is_none(),
                    "restore_prepared_ack_order"
                );
                let message = self
                    .acknowledgement
                    .as_ref()
                    .context("restore_prepared_ack_missing")?;
                let bytes = serde_json::to_vec(message)?;
                ensure!(
                    !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                    "restore_prepared_ack_packet_bound"
                );
                let frame = message.body.frame();
                let observation = self.observation()?;
                let transcript = self
                    .transcript
                    .as_mut()
                    .context("restore_prepared_handoff_history_missing")?;
                ensure!(
                    transcript.next() == Some((Direction::Send, frame)),
                    "restore_prepared_ack_frame_changed"
                );
                transcript.begin(Direction::Send, observation)?;
                loop {
                    self.check()?;
                    let sent = {
                        let actual = self
                            .input
                            .as_ref()
                            .context("restore_prepared_handoff_input_missing")?
                            .pending
                            .input
                            .as_ref()
                            .context("restore_prepared_input_missing")?;
                        net::send(
                            &actual
                                .received
                                .keeper
                                .input
                                .owner
                                .captured
                                .peer
                                .channel
                                .socket,
                            &bytes,
                            net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
                        )
                    };
                    let checked = self.check();
                    match sent {
                        Ok(count) => {
                            checked?;
                            ensure!(count == bytes.len(), "restore_prepared_ack_partial_packet");
                            break;
                        }
                        Err(Errno::AGAIN) => {
                            checked?;
                            self.wait_prepared(Direction::Send)?;
                        }
                        Err(Errno::INTR) => {
                            checked?;
                            let observation = self.observation()?;
                            self.transcript
                                .as_mut()
                                .context("restore_prepared_handoff_history_missing")?
                                .transport(Transport::Interrupted, observation)?;
                        }
                        Err(error) => {
                            let _ = checked;
                            return Err(error.into());
                        }
                    }
                }
                let observation = self.observation()?;
                self.transcript
                    .as_mut()
                    .context("restore_prepared_handoff_history_missing")?
                    .delivered(frame, observation)?;
                self.ack_delivered = true;
                Ok(())
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(super) fn receive_prepared_acceptance(&mut self) -> Result<Message> {
        let requested: Result<Message> = (|| {
            self.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                ensure!(
                    self.ack_delivered && !self.accepted && self.receipt.is_none(),
                    "restore_prepared_acceptance_receive_order"
                );
                let observation = self.observation()?;
                self.transcript
                    .as_mut()
                    .context("restore_prepared_handoff_history_missing")?
                    .begin(Direction::Receive, observation)?;
                let mut bytes = [0u8; MAX_PACKET];
                let packet = loop {
                    self.check()?;
                    let received = {
                        let actual = self
                            .input
                            .as_ref()
                            .context("restore_prepared_handoff_input_missing")?
                            .pending
                            .input
                            .as_ref()
                            .context("restore_prepared_input_missing")?;
                        net::recv_pidfd_packet(
                            &actual
                                .received
                                .keeper
                                .input
                                .owner
                                .captured
                                .peer
                                .channel
                                .socket,
                            &mut [IoSliceMut::new(&mut bytes)],
                        )
                    };
                    let checked = self.check();
                    match received {
                        Ok(packet) => {
                            checked?;
                            break packet;
                        }
                        Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                            checked?;
                            self.wait_prepared(Direction::Receive)?;
                        }
                        Err(RecvPidfdError::Io(Errno::INTR)) => {
                            checked?;
                            let observation = self.observation()?;
                            self.transcript
                                .as_mut()
                                .context("restore_prepared_handoff_history_missing")?
                                .transport(Transport::Interrupted, observation)?;
                        }
                        Err(error) => {
                            let _ = checked;
                            return Err(error.into());
                        }
                    }
                };
                let count = packet.bytes;
                let receipt = {
                    let actual = self
                        .input
                        .as_mut()
                        .context("restore_prepared_handoff_input_missing")?
                        .pending
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    RestoredControllerReceipt::received(
                        ReceivedRestorePacket {
                            packet,
                            local_only: PhantomData,
                        },
                        &mut actual.received.keeper.input.owner.captured.peer.process,
                    )?
                };
                // Keep the actual SCM receipt before decoding any claimed DATA.
                self.receipt = Some(receipt);
                self.check()?;
                super::super::storage_peer_wire::decode(&bytes[..count])
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let message = requested?;
        checked?;
        Ok(message)
    }

    fn wait_prepared(&mut self, direction: Direction) -> Result<()> {
        let requested: Result<()> = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = direction;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                let observation = self.observation()?;
                self.transcript
                    .as_mut()
                    .context("restore_prepared_handoff_history_missing")?
                    .transport(Transport::WouldBlock, observation)?;
                loop {
                    self.check()?;
                    let polled: Result<Transport> = (|| {
                        let observation = self.observation()?;
                        let remaining = observation
                            .deadline
                            .checked_sub(observation.now)
                            .context("restore_prepared_handoff_expired")?;
                        let timeout = rustix::event::Timespec::try_from(remaining)?;
                        let expected = if direction == Direction::Send {
                            PollFlags::OUT
                        } else {
                            PollFlags::IN
                        };
                        let actual = self
                            .input
                            .as_ref()
                            .context("restore_prepared_handoff_input_missing")?
                            .pending
                            .input
                            .as_ref()
                            .context("restore_prepared_input_missing")?;
                        let mut fds = [PollFd::new(
                            &actual
                                .received
                                .keeper
                                .input
                                .owner
                                .captured
                                .peer
                                .channel
                                .socket,
                            expected | PollFlags::RDHUP,
                        )];
                        match rustix::event::poll(&mut fds, Some(&timeout)) {
                            Ok(1) => {
                                let flags = fds[0].revents();
                                ensure!(
                                    flags.contains(expected)
                                        && !flags.intersects(
                                            PollFlags::HUP
                                                | PollFlags::RDHUP
                                                | PollFlags::ERR
                                                | PollFlags::NVAL
                                        ),
                                    "restore_prepared_handoff_poll_events"
                                );
                                Ok(Transport::Ready)
                            }
                            Ok(_) => {
                                anyhow::bail!("restore_prepared_handoff_poll_timeout_or_count")
                            }
                            Err(Errno::INTR) => Ok(Transport::Interrupted),
                            Err(error) => Err(error.into()),
                        }
                    })();
                    let checked = self.check();
                    let transport = polled?;
                    checked?;
                    let observation = self.observation()?;
                    let decision = self
                        .transcript
                        .as_mut()
                        .context("restore_prepared_handoff_history_missing")?
                        .transport(transport, observation)?;
                    if decision == TransportDecision::Retry {
                        return Ok(());
                    }
                }
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }
}

impl RestoredControllerReceipt {
    pub(in crate::security_epoch::native_enrollment) fn check_current_anchor(
        &mut self,
        statement: &StageStatement,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = statement;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                ensure!(
                    !self.refused
                        && self.process == std::process::id()
                        && self.thread == std::thread::current().id(),
                    "restore_peer_receipt_refused"
                );
                stage.storage()?.check_storage_acquisition(acquisition)?;
                let local = stage.storage()?.storage_statement()?;
                ensure!(
                    self.statement.as_ref() == Some(&statement.digest()?)
                        && statement.certificate == local.certificate
                        && statement.stage.data.policy == local.stage.data.policy
                        && statement.stage.data.role == NativeRole::EpochController
                        && local.stage.data.role == NativeRole::AppHost
                        && statement.stage.data.process.process == self.sender,
                    "restore_original_controller_identity_changed"
                );
                process::live(&self.pidfd, acquisition)
            }
        })();
        // Always evaluate the fresh local post, including after a native error.
        let checked = stage
            .storage()
            .and_then(|mut storage| storage.check_storage_acquisition(acquisition));
        if requested.is_err() || checked.is_err() {
            #[cfg(target_os = "linux")]
            {
                self.refused = true;
            }
            acquisition.refuse();
        }
        requested?;
        checked
    }
}

impl RestoreTransport {
    pub(super) fn check_current_anchor(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                ensure!(!self.refused.get(), "restore_peer_channel_refused");
                stage.storage()?.check_storage_acquisition(acquisition)?;
                super::super::channel::require_connected(&self.socket, acquisition)
            }
        })();
        let checked = stage
            .storage()
            .and_then(|mut storage| storage.check_storage_acquisition(acquisition));
        if requested.is_err() || checked.is_err() {
            self.refuse();
            acquisition.refuse();
        }
        requested?;
        checked
    }
}

impl AppInstalledHandoff<'_, '_, '_> {
    pub(super) fn send_installed_ack(&mut self) -> Result<()> {
        let requested: Result<()> = (|| {
            self.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                ensure!(
                    !self.ack_delivered && !self.accepted && self.receipt.is_none(),
                    "restore_installed_ack_order"
                );
                let message = self
                    .acknowledgement
                    .as_ref()
                    .context("restore_installed_ack_missing")?;
                let bytes = serde_json::to_vec(message)?;
                ensure!(
                    !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                    "restore_installed_ack_packet_bound"
                );
                let frame = message.body.frame();
                let observation = self.observation()?;
                let transcript = self
                    .transcript
                    .as_mut()
                    .context("restore_installed_handoff_history_missing")?;
                ensure!(
                    transcript.next() == Some((Direction::Send, frame)),
                    "restore_installed_ack_frame_changed"
                );
                transcript.begin(Direction::Send, observation)?;
                loop {
                    self.check()?;
                    let sent = {
                        let actual = self
                            .owner
                            .pending
                            .input
                            .as_ref()
                            .context("restore_installed_handoff_input_missing")?
                            .pending
                            .input
                            .as_ref()
                            .context("restore_installed_input_missing")?;
                        net::send(
                            &actual
                                .received
                                .keeper
                                .input
                                .owner
                                .captured
                                .peer
                                .channel
                                .socket,
                            &bytes,
                            net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
                        )
                    };
                    let checked = self.check();
                    match sent {
                        Ok(count) => {
                            checked?;
                            ensure!(count == bytes.len(), "restore_installed_ack_partial_packet");
                            break;
                        }
                        Err(Errno::AGAIN) => {
                            checked?;
                            self.wait_installed(Direction::Send)?;
                        }
                        Err(Errno::INTR) => {
                            checked?;
                            let observation = self.observation()?;
                            self.transcript
                                .as_mut()
                                .context("restore_installed_handoff_history_missing")?
                                .transport(Transport::Interrupted, observation)?;
                        }
                        Err(error) => {
                            let _ = checked;
                            return Err(error.into());
                        }
                    }
                }
                let observation = self.observation()?;
                self.transcript
                    .as_mut()
                    .context("restore_installed_handoff_history_missing")?
                    .delivered(frame, observation)?;
                self.ack_delivered = true;
                Ok(())
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(super) fn receive_installed_acceptance(&mut self) -> Result<Message> {
        let requested: Result<Message> = (|| {
            self.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                ensure!(
                    self.ack_delivered && !self.accepted && self.receipt.is_none(),
                    "restore_installed_acceptance_receive_order"
                );
                let observation = self.observation()?;
                self.transcript
                    .as_mut()
                    .context("restore_installed_handoff_history_missing")?
                    .begin(Direction::Receive, observation)?;
                let mut bytes = [0u8; MAX_PACKET];
                let packet = loop {
                    self.check()?;
                    let received = {
                        let actual = self
                            .owner
                            .pending
                            .input
                            .as_ref()
                            .context("restore_installed_handoff_input_missing")?
                            .pending
                            .input
                            .as_ref()
                            .context("restore_installed_input_missing")?;
                        net::recv_pidfd_packet(
                            &actual
                                .received
                                .keeper
                                .input
                                .owner
                                .captured
                                .peer
                                .channel
                                .socket,
                            &mut [IoSliceMut::new(&mut bytes)],
                        )
                    };
                    let checked = self.check();
                    match received {
                        Ok(packet) => {
                            checked?;
                            break packet;
                        }
                        Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                            checked?;
                            self.wait_installed(Direction::Receive)?;
                        }
                        Err(RecvPidfdError::Io(Errno::INTR)) => {
                            checked?;
                            let observation = self.observation()?;
                            self.transcript
                                .as_mut()
                                .context("restore_installed_handoff_history_missing")?
                                .transport(Transport::Interrupted, observation)?;
                        }
                        Err(error) => {
                            let _ = checked;
                            return Err(error.into());
                        }
                    }
                };
                let count = packet.bytes;
                let receipt = {
                    let actual = self
                        .owner
                        .pending
                        .input
                        .as_mut()
                        .context("restore_installed_handoff_input_missing")?
                        .pending
                        .input
                        .as_mut()
                        .context("restore_installed_input_missing")?;
                    RestoredControllerReceipt::received(
                        ReceivedRestorePacket {
                            packet,
                            local_only: PhantomData,
                        },
                        &mut actual.received.keeper.input.owner.captured.peer.process,
                    )?
                };
                // Keep the actual SCM receipt before decoding any claimed DATA.
                self.receipt = Some(receipt);
                self.check()?;
                super::super::storage_peer_wire::decode(&bytes[..count])
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let message = requested?;
        checked?;
        Ok(message)
    }

    fn wait_installed(&mut self, direction: Direction) -> Result<()> {
        let requested: Result<()> = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = direction;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                let observation = self.observation()?;
                self.transcript
                    .as_mut()
                    .context("restore_installed_handoff_history_missing")?
                    .transport(Transport::WouldBlock, observation)?;
                loop {
                    self.check()?;
                    let polled: Result<Transport> = (|| {
                        let observation = self.observation()?;
                        let remaining = observation
                            .deadline
                            .checked_sub(observation.now)
                            .context("restore_installed_handoff_expired")?;
                        let timeout = rustix::event::Timespec::try_from(remaining)?;
                        let expected = if direction == Direction::Send {
                            PollFlags::OUT
                        } else {
                            PollFlags::IN
                        };
                        let actual = self
                            .owner
                            .pending
                            .input
                            .as_ref()
                            .context("restore_installed_handoff_input_missing")?
                            .pending
                            .input
                            .as_ref()
                            .context("restore_installed_input_missing")?;
                        let mut fds = [PollFd::new(
                            &actual
                                .received
                                .keeper
                                .input
                                .owner
                                .captured
                                .peer
                                .channel
                                .socket,
                            expected | PollFlags::RDHUP,
                        )];
                        match rustix::event::poll(&mut fds, Some(&timeout)) {
                            Ok(1) => {
                                let flags = fds[0].revents();
                                ensure!(
                                    flags.contains(expected)
                                        && !flags.intersects(
                                            PollFlags::HUP
                                                | PollFlags::RDHUP
                                                | PollFlags::ERR
                                                | PollFlags::NVAL
                                        ),
                                    "restore_installed_handoff_poll_events"
                                );
                                Ok(Transport::Ready)
                            }
                            Ok(_) => {
                                anyhow::bail!("restore_installed_handoff_poll_timeout_or_count")
                            }
                            Err(Errno::INTR) => Ok(Transport::Interrupted),
                            Err(error) => Err(error.into()),
                        }
                    })();
                    let checked = self.check();
                    let transport = polled?;
                    checked?;
                    let observation = self.observation()?;
                    let decision = self
                        .transcript
                        .as_mut()
                        .context("restore_installed_handoff_history_missing")?
                        .transport(transport, observation)?;
                    if decision == TransportDecision::Retry {
                        return Ok(());
                    }
                }
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }
}
