//! One bounded sequence-packet exchange. No FD adoption or raw ancillary API is
//! exposed to a caller. The private birth owner is the only socketpair creator.

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

pub(super) struct Channel {
    socket: File,
    refused: bool,
    local: PhantomData<Rc<()>>,
}

impl Channel {
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
                    Err(Errno::AGAIN) => wait(&self.socket, PollFlags::OUT, acquisition)?,
                    Err(Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            acquisition.remaining()?;
            Ok(())
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }

    pub(super) fn receive(
        &mut self,
        expected_code: &Digest,
        acquisition: &mut NativeAcquisition,
    ) -> Result<(Packet, MessageProcess)> {
        self.receive_selected(ExpectedCode::Exact(expected_code), acquisition)
    }

    pub(super) fn receive_role(
        &mut self,
        policy: &super::policy::EnrollmentPolicy,
        acquisition: &mut NativeAcquisition,
    ) -> Result<(Packet, MessageProcess)> {
        self.receive_selected(ExpectedCode::Role(policy), acquisition)
    }

    fn receive_selected(
        &mut self,
        selection: ExpectedCode<'_>,
        acquisition: &mut NativeAcquisition,
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
            let process = MessageProcess::receive(received, expected_code, acquisition)?;
            acquisition.remaining()?;
            Ok((packet, process))
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }

    pub(super) fn receive_issuer(
        &mut self,
        acquisition: &mut NativeAcquisition,
    ) -> Result<(Packet, super::issuer_peer::IssuerReceipt)> {
        let result = (|| {
            let (packet, received) = self.receive_kernel(acquisition)?;
            let receipt = super::issuer_peer::IssuerReceipt::receive(received, acquisition)?;
            Ok((packet, receipt))
        })();
        if result.is_err() {
            self.refused = true;
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
            let received = loop {
                acquisition.remaining()?;
                match net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)]) {
                    Ok(packet) => break packet,
                    Err(RecvPidfdError::Io(Errno::AGAIN)) => {
                        wait(&self.socket, PollFlags::IN, acquisition)?
                    }
                    Err(RecvPidfdError::Io(Errno::INTR)) => continue,
                    Err(error) => return Err(error.into()),
                }
            };
            let packet = protocol::decode(&bytes[..received.bytes])?;
            acquisition.remaining()?;
            Ok((packet, received))
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }
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
    loop {
        let timeout = rustix::event::Timespec::try_from(acquisition.remaining()?)?;
        let mut fds = [PollFd::new(fd, events)];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(count) => {
                ensure!(
                    count == 1 && fds[0].revents() == events,
                    "native_enrollment_socket_closed_or_timeout"
                );
                break;
            }
            Err(Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    acquisition.remaining()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

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
        let (packet, mut process) = channel.receive(&code, &mut acquisition).unwrap();
        assert!(matches!(packet, Packet::BirthChallenge { .. }));
        assert_eq!(process.data().process, child.0.id());
        assert_ne!(process.data().process, connection_creator as u32);
        process.check_identity(&mut acquisition).unwrap();
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(process.check_identity(&mut acquisition).is_err());
        let mut later = NativeAcquisition::begin(5).unwrap();
        assert!(process.check_identity(&mut later).is_err());
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
            "native_enrollment_socket_closed_or_timeout"
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
                .receive(&Digest::new(b"not-a-code-proof"), &mut acquisition)
                .is_err()
        );
        let mut later = NativeAcquisition::begin(5).unwrap();
        let error = channel
            .receive(&Digest::new(b"anything"), &mut later)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("channel_refused"));
        assert!(later.remaining().is_err());
    }
}
