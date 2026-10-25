//! One bounded sequence-packet exchange. No FD adoption or raw ancillary API is
//! exposed to a caller. The private birth owner is the only socketpair creator.

use super::handshake::{
    Actor, Direction, Frame, Observation, Protocol, Transcript, Transport, TransportDecision,
};
use super::issuer_costs::HashCosts;
use super::peer_idle::{IdleRequest, PeerChannel};
use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    process::MessageProcess,
    protocol::{self, MAX_PACKET, Packet},
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use rustix::{
    event::{PollFd, PollFlags},
    fd::OwnedFd,
    io::Errno,
    net::{self, AddressFamily, RecvPidfdError, SendFlags, SocketFlags, SocketType},
};
use std::{fs::File, io::IoSliceMut, marker::PhantomData, rc::Rc};

mod serving;
mod storage;
pub(super) use serving::{ServingListener, ServingSender};
pub(super) use storage::{StorageListener, StorageSender};

pub(super) struct Channel {
    socket: File,
    refused: bool,
    // None only for the private issuer birth socket and kernel DATA fixtures.
    // Every production enrollment/storage/serving channel installs a transcript.
    transcript: Option<Transcript>,
    local: PhantomData<Rc<()>>,
}

impl Channel {
    fn observation(acquisition: &NativeAcquisition) -> Observation {
        let (domain, origin, deadline, now) = acquisition.historical_interval_observation();
        Observation {
            domain,
            origin,
            deadline,
            now,
        }
    }

    fn begin_packet(
        &mut self,
        direction: Direction,
        frame: Option<Frame>,
        acquisition: &NativeAcquisition,
    ) -> Result<()> {
        if let Some(transcript) = &mut self.transcript {
            if direction == Direction::Send && transcript.next().map(|(_, next)| next) != frame {
                transcript.refuse();
                anyhow::bail!("native_handshake_send_order");
            }
            transcript.begin(direction, Self::observation(acquisition))?;
        }
        Ok(())
    }

    fn packet_delivered(
        &mut self,
        frame: Option<Frame>,
        acquisition: &NativeAcquisition,
    ) -> Result<()> {
        if let Some(transcript) = &mut self.transcript {
            let frame = frame.ok_or_else(|| anyhow::anyhow!("native_handshake_packet_kind"))?;
            transcript.delivered(frame, Self::observation(acquisition))?;
        }
        Ok(())
    }

    fn transport(
        &mut self,
        transport: Transport,
        events: PollFlags,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let decision = match &mut self.transcript {
            Some(transcript) => transcript.transport(transport, Self::observation(acquisition))?,
            None => match transport {
                Transport::WouldBlock => TransportDecision::Wait,
                Transport::Interrupted | Transport::Ready => TransportDecision::Retry,
                Transport::Failed => anyhow::bail!("native_handshake_transport"),
            },
        };
        if decision == TransportDecision::Wait {
            wait(&self.socket, events, acquisition)?;
            if let Some(transcript) = &mut self.transcript {
                transcript.transport(Transport::Ready, Self::observation(acquisition))?;
            }
        }
        Ok(())
    }

    fn refuse(&mut self) {
        self.refused = true;
        if let Some(transcript) = &mut self.transcript {
            transcript.refuse();
        }
    }

    /// Observe the purpose already checked against the caller's actual signed
    /// stage and acquisition. This selects only a DATA transcript class; no
    /// NativeAcquisition is created, widened or reconstructed here.
    pub(in crate::security_epoch::native_enrollment) fn begin_current_handshake(
        &mut self,
        sequence: u64,
        purpose: super::protocol::StagePurpose,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "native_handshake_channel_refused");
            self.transcript
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("native_handshake_transcript_required"))?
                .begin_current(sequence, purpose)
        })();
        if result.is_err() {
            self.refuse();
            acquisition.refuse();
        }
        result
    }

    /// A single nonblocking wakeup on this retained socket. It carries only
    /// untrusted sequence DATA, never an old stage or an action permission.
    /// Any uncertain/partial send is terminal; no retry or replacement occurs.
    pub(super) fn notify_idle(
        &mut self,
        channel: PeerChannel,
        initial: &Digest,
        sequence: u64,
    ) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "native_enrollment_channel_refused");
            let bytes = IdleRequest::encode(channel, initial, sequence)?;
            idle_open(&self.socket)?;
            ensure!(
                net::send(
                    &self.socket,
                    &bytes,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL
                )? == bytes.len(),
                "native_peer_idle_partial_packet"
            );
            idle_open(&self.socket)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Receive untrusted wakeup DATA under the caller's real original bounded
    /// acquisition. Kernel ancillary validation still runs. Its descriptor is
    /// deliberately dropped, never attributed to a signer or used as authority;
    /// the subsequent signed Hello retains its own actual sender separately.
    pub(super) fn receive_idle(
        &mut self,
        channel: PeerChannel,
        initial: &Digest,
        sequence: u64,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "native_enrollment_channel_refused");
            let mut bytes = [0; super::peer_idle::MAX_BYTES];
            loop {
                acquisition.remaining()?;
                idle_open(&self.socket)?;
                match net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)]) {
                    Ok(packet) => {
                        IdleRequest::require(&bytes[..packet.bytes], channel, initial, sequence)?;
                        drop(packet);
                        break;
                    }
                    Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                        wait(&self.socket, PollFlags::IN, acquisition)?
                    }
                    Err(RecvPidfdError::Io(Errno::INTR)) => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            idle_open(&self.socket)?;
            acquisition.remaining()?;
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
            acquisition.refuse();
        }
        result
    }

    pub(super) fn connect(acquisition: &mut NativeAcquisition) -> Result<Self> {
        acquisition.remaining()?;
        let socket = net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        configure(&socket)?;
        net::connect(
            &socket,
            &net::SocketAddrUnix::new("/run/day2-native-enrollment/issuer.sock")?,
        )?;
        acquisition.remaining()?;
        Ok(Self {
            socket: File::from(socket),
            refused: false,
            transcript: Some(Transcript::new(Protocol::Enrollment, Actor::Client)),
            local: PhantomData,
        })
    }

    pub(super) fn pair(acquisition: &mut NativeAcquisition) -> Result<(Self, OwnedFd)> {
        acquisition.remaining()?;
        let (parent, child) = net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        for fd in [&parent, &child] {
            configure(fd)?;
        }
        acquisition.remaining()?;
        Ok((
            Self {
                socket: File::from(parent),
                refused: false,
                transcript: None,
                local: PhantomData,
            },
            child,
        ))
    }

    /// Called only by the fixed issuer entrypoint on its inherited startup
    /// socket. Shape/options are checked again; this alone is no enrollment.
    pub(super) fn startup(acquisition: &mut NativeAcquisition) -> Result<Self> {
        acquisition.remaining()?;
        let fd = rustix::io::fcntl_dupfd_cloexec(rustix::stdio::stdin(), 0)?;
        ensure!(
            net::sockopt::socket_type(&fd)? == SocketType::SEQPACKET
                && net::sockopt::socket_domain(&fd)? == AddressFamily::UNIX,
            "native_enrollment_startup_socket"
        );
        configure(&fd)?;
        acquisition.remaining()?;
        Ok(Self {
            socket: File::from(fd),
            refused: false,
            transcript: None,
            local: PhantomData,
        })
    }

    pub(super) fn send(
        &mut self,
        packet: &Packet,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "native_enrollment_channel_refused");
            let bytes = serde_json::to_vec(packet)?;
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                "native_enrollment_packet_bound"
            );
            self.begin_packet(Direction::Send, packet.frame(), acquisition)?;
            loop {
                acquisition.remaining()?;
                match net::send(
                    &self.socket,
                    &bytes,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                ) {
                    Ok(count) => {
                        ensure!(count == bytes.len(), "native_enrollment_partial_packet");
                        break;
                    }
                    Err(Errno::AGAIN) => {
                        self.transport(Transport::WouldBlock, PollFlags::OUT, acquisition)?;
                    }
                    Err(Errno::INTR) => {
                        self.transport(Transport::Interrupted, PollFlags::OUT, acquisition)?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            acquisition.remaining()?;
            self.packet_delivered(packet.frame(), acquisition)?;
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
            acquisition.refuse();
        }
        result
    }

    pub(super) fn receive(
        &mut self,
        expected_code: &Digest,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<(Packet, MessageProcess)> {
        self.receive_selected(ExpectedCode::Exact(expected_code), acquisition, costs)
    }

    pub(super) fn receive_role(
        &mut self,
        policy: &super::policy::EnrollmentPolicy,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<(Packet, MessageProcess)> {
        self.receive_selected(ExpectedCode::Role(policy), acquisition, costs)
    }

    fn receive_selected(
        &mut self,
        selection: ExpectedCode<'_>,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<(Packet, MessageProcess)> {
        let result = (|| {
            let (packet, received) = self.receive_kernel(acquisition)?;
            let expected_code = match selection {
                ExpectedCode::Exact(code) => code,
                ExpectedCode::Role(policy) => {
                    let Packet::StageHello { role, .. } = &packet else {
                        anyhow::bail!("native_enrollment_role_order")
                    };
                    policy.code(*role)
                }
            };
            let process = MessageProcess::receive(received, expected_code, acquisition, costs)?;
            acquisition.remaining()?;
            self.packet_delivered(packet.frame(), acquisition)?;
            Ok((packet, process))
        })();
        if result.is_err() {
            self.refuse();
            acquisition.refuse();
        }
        result
    }

    pub(super) fn receive_issuer(
        &mut self,
        acquisition: &mut NativeAcquisition,
    ) -> Result<(Packet, super::issuer_peer::IssuerReceipt)> {
        let result = (|| {
            let (packet, received) = {
                let _profile = crate::security_epoch::self_check_profile::enter(
                    crate::security_epoch::self_check_profile::Category::IssuerTransport,
                );
                self.receive_kernel(acquisition)?
            };
            let receipt = super::issuer_peer::IssuerReceipt::receive(received, acquisition)?;
            self.packet_delivered(packet.frame(), acquisition)?;
            Ok((packet, receipt))
        })();
        if result.is_err() {
            self.refuse();
            acquisition.refuse();
        }
        result
    }

    fn receive_kernel(
        &mut self,
        acquisition: &mut NativeAcquisition,
    ) -> Result<(Packet, net::ReceivedPidfdPacket)> {
        let result = (|| {
            ensure!(!self.refused, "native_enrollment_channel_refused");
            let mut bytes = [0_u8; MAX_PACKET];
            acquisition.remaining()?;
            self.begin_packet(Direction::Receive, None, acquisition)?;
            let received = loop {
                acquisition.remaining()?;
                match net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)]) {
                    Ok(packet) => break packet,
                    Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                        self.transport(Transport::WouldBlock, PollFlags::IN, acquisition)?;
                    }
                    Err(RecvPidfdError::Io(Errno::INTR)) => {
                        self.transport(Transport::Interrupted, PollFlags::IN, acquisition)?
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            let packet = protocol::decode(&bytes[..received.bytes])?;
            acquisition.remaining()?;
            Ok((packet, received))
        })();
        if result.is_err() {
            self.refuse();
            acquisition.refuse();
        }
        result
    }
}

fn idle_open(socket: &File) -> Result<()> {
    ensure!(
        rustix::io::fcntl_getfd(socket)?.contains(rustix::io::FdFlags::CLOEXEC)
            && net::sockopt::socket_type(socket)? == SocketType::SEQPACKET
            && net::sockopt::socket_domain(socket)? == AddressFamily::UNIX,
        "native_peer_idle_socket_profile"
    );
    let mut fds = [PollFd::new(socket, PollFlags::RDHUP)];
    let zero = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    rustix::event::poll(&mut fds, Some(&zero))?;
    ensure!(
        !fds[0]
            .revents()
            .intersects(PollFlags::HUP | PollFlags::RDHUP | PollFlags::ERR | PollFlags::NVAL),
        "native_peer_idle_channel_closed"
    );
    Ok(())
}

enum ExpectedCode<'a> {
    Exact(&'a Digest),
    Role(&'a super::policy::EnrollmentPolicy),
}

pub(super) struct Listener {
    socket: File,
}

impl Listener {
    pub(super) fn create(acquisition: &mut NativeAcquisition) -> Result<(Self, OwnedFd)> {
        acquisition.remaining()?;
        let socket = net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        configure(&socket)?;
        net::bind(
            &socket,
            &net::SocketAddrUnix::new("/run/day2-native-enrollment/issuer.sock")?,
        )?;
        std::fs::set_permissions(
            "/run/day2-native-enrollment/issuer.sock",
            std::os::unix::fs::PermissionsExt::from_mode(0o666),
        )?;
        net::listen(&socket, 128)?;
        acquisition.remaining()?;
        let child = socket.try_clone()?;
        Ok((
            Self {
                socket: File::from(socket),
            },
            child,
        ))
    }

    pub(super) fn startup(acquisition: &mut NativeAcquisition) -> Result<Self> {
        acquisition.remaining()?;
        let socket = rustix::io::fcntl_dupfd_cloexec(rustix::stdio::stdout(), 0)?;
        ensure!(
            net::sockopt::socket_type(&socket)? == SocketType::SEQPACKET
                && net::sockopt::socket_domain(&socket)? == AddressFamily::UNIX
                && net::sockopt::socket_acceptconn(&socket)?,
            "native_enrollment_listener_profile"
        );
        configure(&socket)?;
        acquisition.remaining()?;
        Ok(Self {
            socket: File::from(socket),
        })
    }

    /// Waiting for a new request grants no authority. Its original acquisition
    /// starts before accept, nonce creation and all request observations.
    pub(super) fn next(&self) -> Result<(Channel, NativeAcquisition)> {
        loop {
            let mut fds = [PollFd::new(&self.socket, PollFlags::IN)];
            match rustix::event::poll(&mut fds, None) {
                Ok(_) => ensure!(
                    fds[0].revents() == PollFlags::IN,
                    "native_enrollment_listener_closed"
                ),
                Err(Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
            let mut acquisition = NativeAcquisition::begin(5)?;
            let socket =
                net::accept_with(&self.socket, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)?;
            configure(&socket)?;
            acquisition.remaining()?;
            return Ok((
                Channel {
                    socket: File::from(socket),
                    refused: false,
                    transcript: Some(Transcript::new(Protocol::Enrollment, Actor::Issuer)),
                    local: PhantomData,
                },
                acquisition,
            ));
        }
    }
}

use std::os::fd::AsFd;

fn configure(fd: &impl AsFd) -> Result<()> {
    net::sockopt::set_socket_passcred(fd, true)?;
    // Probe the real kernel. No kernel-version assumption or weaker fallback.
    net::sockopt::set_socket_passpidfd(fd, true)?;
    Ok(())
}

fn wait(fd: &File, events: PollFlags, acquisition: &mut NativeAcquisition) -> Result<()> {
    use super::handshake::{PollObservation, poll_decision};
    loop {
        let timeout = rustix::event::Timespec::try_from(acquisition.remaining()?)?;
        let mut fds = [PollFd::new(fd, events)];
        let observed = {
            let _profile = crate::security_epoch::self_check_profile::packet_wait();
            rustix::event::poll(&mut fds, Some(&timeout))
        };
        let observation = match observed {
            Ok(0) => PollObservation::Timeout,
            Ok(1) if fds[0].revents() == events => PollObservation::Ready,
            Ok(_) => PollObservation::UnexpectedEvents,
            Err(Errno::INTR) => PollObservation::Interrupted,
            Err(error) => return Err(error.into()),
        };
        match poll_decision(observation)? {
            TransportDecision::Wait => continue,
            TransportDecision::Retry => break,
        }
    }
    acquisition.remaining()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn idle_channels(acquisition: &mut NativeAcquisition) -> (Channel, Channel) {
        // Socket DATA controls only: no enrolled role, file or serving owner.
        let (left, right) = Channel::pair(acquisition).unwrap();
        (
            left,
            Channel {
                socket: File::from(right),
                refused: false,
                transcript: None,
                local: PhantomData,
            },
        )
    }

    #[test]
    fn actual_idle_notification_round_trips_without_becoming_an_authenticated_message() {
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let (mut left, mut right) = idle_channels(&mut acquisition);
        let initial = Digest::new(b"retained peer data");
        left.notify_idle(PeerChannel::Storage, &initial, 1).unwrap();
        right
            .receive_idle(PeerChannel::Storage, &initial, 1, &mut acquisition)
            .unwrap();
        let bytes = IdleRequest::encode(PeerChannel::Storage, &initial, 1).unwrap();
        assert!(super::super::storage_peer_wire::decode(&bytes).is_err());
        assert!(super::super::serving_peer_wire::decode(&bytes).is_err());
    }

    #[test]
    fn consumed_foreign_idle_sequence_permanently_refuses_the_actual_channel() {
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let (mut left, mut right) = idle_channels(&mut acquisition);
        let initial = Digest::new(b"retained peer data");
        left.notify_idle(PeerChannel::Serving, &initial, 1).unwrap();
        assert!(
            right
                .receive_idle(PeerChannel::Serving, &initial, 2, &mut acquisition)
                .is_err()
        );
        let mut later = NativeAcquisition::begin(5).unwrap();
        assert!(
            right
                .receive_idle(PeerChannel::Serving, &initial, 1, &mut later)
                .is_err()
        );
        assert!(later.remaining().is_err());
    }

    #[test]
    fn buffered_idle_notification_cannot_survive_peer_close_or_a_fresh_clock() {
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let (mut left, mut right) = idle_channels(&mut acquisition);
        let initial = Digest::new(b"retained peer data");
        left.notify_idle(PeerChannel::Storage, &initial, 1).unwrap();
        drop(left);
        assert!(
            right
                .receive_idle(PeerChannel::Storage, &initial, 1, &mut acquisition)
                .is_err()
        );
        let mut later = NativeAcquisition::begin(5).unwrap();
        assert!(
            right
                .receive_idle(PeerChannel::Storage, &initial, 1, &mut later)
                .is_err()
        );
        assert!(later.remaining().is_err());
    }

    #[test]
    fn a_failed_idle_send_cannot_notify_again() {
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let (mut left, right) = idle_channels(&mut acquisition);
        drop(right);
        let initial = Digest::new(b"retained peer data");
        assert!(left.notify_idle(PeerChannel::Storage, &initial, 1).is_err());
        assert!(left.notify_idle(PeerChannel::Storage, &initial, 2).is_err());
        assert!(left.refused);
    }

    struct ChildOwner(std::process::Child);

    impl Drop for ChildOwner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "subprocess helper invoked by retained_process_handle_follows_actual_sender_not_connection_creator"]
    fn packet_child() {
        assert!(std::env::var_os("DAY2_NATIVE_ENROLLMENT_TEST_CHILD").is_some());
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let mut channel = Channel::startup(&mut acquisition).unwrap();
        channel
            .send(
                &Packet::BirthChallenge {
                    policy: Digest::new(b"test-only"),
                    nonce: Digest::new(b"native-packet"),
                },
                &mut acquisition,
            )
            .unwrap();
        loop {
            std::thread::park();
        }
    }

    #[test]
    fn retained_process_handle_follows_actual_sender_not_connection_creator() {
        let code = Digest::new(&std::fs::read("/proc/self/exe").unwrap());
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let (mut channel, child_socket) = Channel::pair(&mut acquisition).unwrap();
        let connection_creator = nix::sys::socket::getsockopt(
            &channel.socket,
            nix::sys::socket::sockopt::PeerCredentials,
        )
        .unwrap()
        .pid();
        assert_eq!(connection_creator as u32, std::process::id());
        let mut child = ChildOwner(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "security_epoch::native_enrollment::channel::tests::packet_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("DAY2_NATIVE_ENROLLMENT_TEST_CHILD", "1")
                .stdin(Stdio::from(child_socket))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let (packet, mut process) = channel
            .receive(&code, &mut acquisition, &HashCosts::disabled())
            .unwrap();
        assert!(matches!(packet, Packet::BirthChallenge { .. }));
        assert_eq!(process.data().process, child.0.id());
        assert_ne!(process.data().process, connection_creator as u32);
        process
            .check_identity(&mut acquisition, &HashCosts::disabled())
            .unwrap();
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(
            process
                .check_identity(&mut acquisition, &HashCosts::disabled())
                .is_err()
        );
        let mut later = NativeAcquisition::begin(5).unwrap();
        assert!(
            process
                .check_identity(&mut later, &HashCosts::disabled())
                .is_err()
        );
    }

    #[test]
    fn queued_startup_packet_with_closed_peer_refuses_wait_while_sender_is_live() {
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let (channel, sender) = Channel::pair(&mut acquisition).unwrap();
        let packet = Packet::BirthChallenge {
            policy: Digest::new(b"test-only"),
            nonce: Digest::new(b"native-startup"),
        };
        net::send(
            &sender,
            &serde_json::to_vec(&packet).unwrap(),
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )
        .unwrap();
        // Closing the socket is distinct from the sender process exiting.
        // The startup owner must retain its endpoint after publishing a grant.
        drop(sender);
        let error = wait(&channel.socket, PollFlags::IN, &mut acquisition).unwrap_err();
        assert_eq!(
            error.to_string(),
            "native_enrollment_socket_unexpected_events"
        );
        let self_pidfd = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        crate::security_epoch::native_enrollment::process::live(
            &File::from(self_pidfd),
            &mut acquisition,
        )
        .unwrap();
    }

    #[test]
    fn no_packet_reports_poll_timeout_and_a_later_clock_cannot_revive_the_channel() {
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let (mut channel, _sender) = Channel::pair(&mut acquisition).unwrap();
        let code = Digest::new(b"no packet must reach executable admission");
        let Err(error) = channel.receive(&code, &mut acquisition, &HashCosts::disabled()) else {
            panic!("a quiet socket must not supply a packet")
        };
        assert_eq!(error.to_string(), "native_enrollment_socket_poll_timeout");
        let mut later = NativeAcquisition::begin(5).unwrap();
        let Err(error) = channel.receive(&code, &mut later, &HashCosts::disabled()) else {
            panic!("a later clock must not revive the refused channel")
        };
        assert_eq!(error.to_string(), "native_enrollment_channel_refused");
    }

    #[test]
    fn truncation_consumes_the_packet_and_permanently_refuses_the_channel() {
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let (mut channel, sender) = Channel::pair(&mut acquisition).unwrap();
        net::send(
            &sender,
            &vec![b'x'; MAX_PACKET + 1],
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert!(
            channel
                .receive(
                    &Digest::new(b"not-a-code-proof"),
                    &mut acquisition,
                    &HashCosts::disabled()
                )
                .is_err()
        );
        let mut later = NativeAcquisition::begin(5).unwrap();
        let error = channel
            .receive(
                &Digest::new(b"anything"),
                &mut later,
                &HashCosts::disabled(),
            )
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("channel_refused"));
        assert!(later.remaining().is_err());
    }
}
