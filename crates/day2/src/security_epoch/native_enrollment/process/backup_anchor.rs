//! Actual forwarded socket/process anchors, not backup permission or a role.
//! The issuer must separately authenticate the Controller, current workload,
//! protected scheduled creation, intent/nonces and original before admission.
use crate::security_epoch::{
    namespace_protocol,
    native_clock::NativeAcquisition,
    native_enrollment::{
        issuer_costs::{Costs, HashCosts, Subject},
        policy::EnrollmentPolicy,
        process::{MessageProcess, live},
        protocol::ProcessData,
        scheduled_runtime::{self, ScheduledRuntimeData},
    },
    native_namespace as ns,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use rustix::{
    fd::{AsFd, AsRawFd},
    fs::{Mode, OFlags},
    net::{
        AddressFamily, KernelPidVisibility, ReceivedPidfdRights, ReceivedPidfdRightsPacket,
        SocketType,
    },
};
use std::{fs::File, num::NonZeroU32, rc::Rc};

/// The ORIGINAL message sender and actual accepted connection, not a peer
/// reconstructed from SO_PEERCRED, a PID or a signed observation. No handle
/// getter, process role or request/source permission is exposed.
pub(in crate::security_epoch::native_enrollment) struct ScheduledJobSender {
    process: MessageProcess,
    connector: MessageProcess,
    socket: Rc<File>,
    proc: File,
    cookie: u64,
    refused: bool,
}

impl ScheduledJobSender {
    /// Fixed observer Bind only. Forward the ORIGINAL message PIDFD and SAME
    /// accepted socket as exactly two rights; never expose either descriptor.
    /// The issuer validates this pair and does not read the Submit stream.
    pub(in crate::security_epoch::native_enrollment) fn send_observation_bind(
        &mut self,
        issuer: &File,
        packet: &crate::security_epoch::native_enrollment::protocol::Packet,
        original: &mut NativeAcquisition,
    ) -> Result<()> {
        use crate::security_epoch::native_enrollment::protocol::{MAX_PACKET, Packet};
        use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
        let requested = (|| {
            self.check(original)?;
            ensure!(
                matches!(packet, Packet::BackupObserveBind { .. }),
                "backup_observer_bind_purpose"
            );
            let bytes = serde_json::to_vec(packet)?;
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                "backup_observer_bind_bound"
            );
            let rights = [self.process.pidfd.as_fd(), self.socket.as_fd()];
            loop {
                original.remaining()?;
                // Rebuild unsent ancillary storage on AGAIN/INTR; a successful
                // or partial send is never repeated or treated as unapplied.
                let mut space =
                    [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
                let mut ancillary = SendAncillaryBuffer::new(&mut space);
                ensure!(
                    ancillary.push(SendAncillaryMessage::ScmRights(&rights)),
                    "backup_observer_rights_bound"
                );
                match rustix::net::sendmsg(
                    issuer,
                    &[std::io::IoSlice::new(&bytes)],
                    &mut ancillary,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                ) {
                    Ok(count) => {
                        ensure!(count == bytes.len(), "backup_observer_partial_bind");
                        break;
                    }
                    Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                        crate::security_epoch::native_enrollment::channel::wait(
                            issuer,
                            rustix::event::PollFlags::OUT,
                            original,
                        )?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        })();
        let checked = self.check(original);
        if requested.is_err() || checked.is_err() {
            self.refused = true;
            original.refuse();
        }
        requested?;
        checked
    }

    /// Public commitment of this actual retained packet sender only, not a
    /// process/descriptor getter or permission. Both native checks are real.
    pub(in crate::security_epoch::native_enrollment) fn commitment_data(
        &mut self,
        original: &mut NativeAcquisition,
    ) -> Result<Digest> {
        let requested = (|| {
            self.check(original)?;
            Digest::of(&("day2-scheduled-backup-process-v1", &self.process.data))
        })();
        let checked = self.check(original);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            original.refuse();
        }
        let commitment = requested?;
        checked?;
        Ok(commitment)
    }

    /// The Hello and final Submit must be actual messages from the SAME actor
    /// on the SAME accepted connection. Neither numeric PID nor equal DATA can
    /// replace these retained kernel anchors. Both independent posts always run.
    pub(in crate::security_epoch::native_enrollment) fn check_same_submit_actor(
        &mut self,
        other: &mut Self,
        original: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            self.check(original)?;
            other.check(original)?;
            ensure!(
                Rc::ptr_eq(&self.socket, &other.socket) && self.cookie == other.cookie,
                "backup_submit_connection_changed"
            );
            MessageProcess::check_same_actor(
                &mut [
                    &mut self.process,
                    &mut self.connector,
                    &mut other.process,
                    &mut other.connector,
                ],
                original,
                &HashCosts::disabled(),
            )
        }));
        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check(original)));
        let second =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| other.check(original)));
        if !matches!(&requested, Ok(Ok(())))
            || !matches!(&first, Ok(Ok(())))
            || !matches!(&second, Ok(Ok(())))
        {
            self.refuse();
            other.refuse();
            original.refuse();
        }
        // All checks above are evaluated before the first primary is returned.
        match requested {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(result) => result?,
        }
        match first {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(result) => result?,
        }
        match second {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(result) => result,
        }
    }

    /// Compare supplied historical DATA with the real retained message actor.
    /// This returns no actor/descriptor or native authority to the caller.
    pub(in crate::security_epoch::native_enrollment) fn require_process_data(
        &mut self,
        expected: &ProcessData,
        original: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = (|| {
            self.check(original)?;
            ensure!(
                *expected == self.process.data,
                "backup_observer_job_changed"
            );
            Ok(())
        })();
        let checked = self.check(original);
        if requested.is_err() || checked.is_err() {
            self.refused = true;
            original.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch::native_enrollment) fn receive(
        received: rustix::net::ReceivedPidfdPacket,
        socket: Rc<File>,
        expected_code: &Digest,
        original: &mut NativeAcquisition,
    ) -> Result<Self> {
        let requested = (|| {
            ensure!(
                received.credentials.user == 10001 && received.credentials.group == 10001,
                "backup_submit_sender_user"
            );
            socket_profile(&socket, original)?;
            let proc = require_proc_view(original)?;
            let costs = HashCosts::disabled();
            // This consumes THIS packet's actual SCM_PIDFD. NotVisible is
            // refused by MessageProcess; there is no host-PID translation.
            let mut process = MessageProcess::receive(received, expected_code, original, &costs)?;
            let credentials =
                nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::PeerCredentials)?;
            let pid = NonZeroU32::new(u32::try_from(credentials.pid())?)
                .context("backup_submit_connector_not_visible")?;
            ensure!(
                pid.get() == process.data.process
                    && credentials.uid() == 10001
                    && credentials.gid() == 10001,
                "backup_submit_connector_changed"
            );
            let connector_fd = File::from(nix::sys::socket::getsockopt(
                &socket,
                nix::sys::socket::sockopt::PeerPidfd,
            )?);
            require_pidfd(&proc, &process.pidfd, pid, original)?;
            require_pidfd(&proc, &connector_fd, pid, original)?;
            let mut connector = process.retain_message_anchor(original, &costs)?;
            connector.pidfd = connector_fd;
            MessageProcess::check_same_actor(
                &mut [&mut process, &mut connector],
                original,
                &costs,
            )?;
            let cookie = rustix::net::sockopt::socket_cookie(&socket)?;
            ensure!(cookie != 0, "backup_submit_socket_cookie");
            let mut sender = Self {
                process,
                connector,
                socket,
                proc,
                cookie,
                refused: false,
            };
            sender.check(original)?;
            Ok(sender)
        })();
        if requested.is_err() {
            original.refuse();
        }
        requested
    }

    pub(in crate::security_epoch::native_enrollment) fn check(
        &mut self,
        original: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(!self.refused, "backup_submit_sender_refused");
            socket_profile(&self.socket, original)?;
            require_process_views(&self.proc, &self.process, &self.connector, original)?;
            let credentials = nix::sys::socket::getsockopt(
                &self.socket,
                nix::sys::socket::sockopt::PeerCredentials,
            )?;
            let pid = NonZeroU32::new(u32::try_from(credentials.pid())?)
                .context("backup_submit_connector_not_visible")?;
            ensure!(
                pid.get() == self.process.data.process
                    && credentials.uid() == 10001
                    && credentials.gid() == 10001
                    && rustix::net::sockopt::socket_cookie(&self.socket)? == self.cookie,
                "backup_submit_connector_changed"
            );
            require_pidfd(&self.proc, &self.process.pidfd, pid, original)?;
            require_pidfd(&self.proc, &self.connector.pidfd, pid, original)?;
            MessageProcess::check_same_actor(
                &mut [&mut self.process, &mut self.connector],
                original,
                &HashCosts::disabled(),
            )?;
            require_process_views(&self.proc, &self.process, &self.connector, original)?;
            original.remaining()?;
            Ok(())
        })();
        if requested.is_err() {
            self.refused = true;
            original.refuse();
        }
        requested
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse(&mut self) {
        self.refused = true;
    }
}

/// Both handles are actual received/connected resources. No DATA constructor,
/// descriptor getter, role, source grant or signing capability is exposed.
pub(in crate::security_epoch::native_enrollment) struct ForwardedJobAnchors {
    forwarder: MessageProcess,
    process: MessageProcess,
    connector: MessageProcess,
    socket: File,
    proc: File,
    cookie: u64,
    user: u32,
    group: u32,
    refused: bool,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <ForwardedJobAnchors as Ambiguous<_>>::check;
            let _ = <ScheduledJobSender as Ambiguous<_>>::check;
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
    assert_not_impl!(AsRawFd);
    assert_not_impl!(std::convert::AsRef<File>);
    assert_not_impl!(rustix::fd::AsFd);
    assert_not_impl!(std::os::fd::IntoRawFd);
    assert_not_impl!(std::borrow::Borrow<File>);
    assert_not_impl!(std::ops::Deref);
};

impl ForwardedJobAnchors {
    pub(in crate::security_epoch::native_enrollment) fn receive(
        received: ReceivedPidfdRightsPacket,
        admitted_forwarder: &mut MessageProcess,
        expected_job_code: &Digest,
        original: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<Self> {
        let result = (|| {
            // THIS packet's original kernel PIDFD must still be the retained
            // forwarder. Rights never replace or impersonate its sender proof.
            let forwarder = MessageProcess::receive_admitted(
                received.packet,
                admitted_forwarder,
                original,
                costs,
            )?;
            let ReceivedPidfdRights::Two([process, socket]) = received.rights else {
                anyhow::bail!("backup_forwarded_rights_count")
            };
            let socket = File::from(socket);
            socket_profile(&socket, original)?;
            let credentials =
                nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::PeerCredentials)?;
            let pid = NonZeroU32::new(u32::try_from(credentials.pid())?)
                .context("backup_forwarded_pid_not_visible")?;
            let connector =
                nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::PeerPidfd)?;
            let process = File::from(process);
            let connector = File::from(connector);
            let proc = require_proc_view(original)?;
            // PIDFD inode equality is NOT a portable same-process proof.
            // Join actual live kernel PIDFD metadata to the socket's actual
            // peer in THIS namespace, before a proc/executable observation.
            require_pidfd(&proc, &process, pid, original)?;
            require_pidfd(&proc, &connector, pid, original)?;
            let mut process = MessageProcess::observe(
                process.into(),
                KernelPidVisibility::Visible(pid),
                expected_job_code,
                original,
                costs,
            )?;
            let mut retained = process.retain_message_anchor(original, costs)?;
            retained.pidfd = connector;
            MessageProcess::check_same_actor(&mut [&mut process, &mut retained], original, costs)?;
            require_process_views(&proc, &process, &retained, original)?;
            let cookie = rustix::net::sockopt::socket_cookie(&socket)?;
            ensure!(cookie != 0, "backup_forwarded_socket_cookie");
            let mut anchors = Self {
                forwarder,
                process,
                connector: retained,
                socket,
                proc,
                cookie,
                user: credentials.uid(),
                group: credentials.gid(),
                refused: false,
            };
            anchors.check(original, costs)?;
            Ok(anchors)
        })();
        if result.is_err() {
            original.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn check(
        &mut self,
        original: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "backup_forwarded_peer_refused");
            self.forwarder.check_identity(original, costs)?;
            socket_profile(&self.socket, original)?;
            require_process_views(&self.proc, &self.process, &self.connector, original)?;
            let credentials = nix::sys::socket::getsockopt(
                &self.socket,
                nix::sys::socket::sockopt::PeerCredentials,
            )?;
            let pid = NonZeroU32::new(self.process.data.process)
                .context("backup_forwarded_pid_not_visible")?;
            ensure!(
                u32::try_from(credentials.pid())? == pid.get()
                    && credentials.uid() == self.user
                    && credentials.gid() == self.group
                    && rustix::net::sockopt::socket_cookie(&self.socket)? == self.cookie,
                "backup_forwarded_socket_changed"
            );
            require_pidfd(&self.proc, &self.process.pidfd, pid, original)?;
            require_pidfd(&self.proc, &self.connector.pidfd, pid, original)?;
            MessageProcess::check_same_actor(
                &mut [&mut self.process, &mut self.connector],
                original,
                costs,
            )?;
            require_process_views(&self.proc, &self.process, &self.connector, original)?;
            self.forwarder.check_identity(original, costs)?;
            original.remaining()?;
            Ok(())
        })();
        if result.is_err() {
            self.refused = true;
            original.refuse();
        }
        result
    }

    /// Comparison DATA only. The actual resources above remain private and
    /// must be rechecked by the fixed observer under its existing original.
    pub(in crate::security_epoch::native_enrollment) fn process_data(&self) -> &ProcessData {
        self.process.data()
    }

    /// The observer gets a short borrow of the SAME resource, never a new
    /// process owner from signed/decoded DATA or a public descriptor getter.
    pub(in crate::security_epoch::native_enrollment) fn observe_runtime(
        &mut self,
        policy: &EnrollmentPolicy,
        intent: &[u8],
        original: &mut NativeAcquisition,
        costs: &Costs,
    ) -> Result<ScheduledRuntimeData> {
        let requested = (|| {
            self.check(original, &costs.hashes(Subject::Requester))?;
            scheduled_runtime::current(policy, &mut self.process, intent, original, costs)
        })();
        let checked = self.check(original, &costs.hashes(Subject::Requester));
        if requested.is_err() || checked.is_err() {
            self.refused = true;
            original.refuse();
        }
        let value = requested?;
        checked?;
        Ok(value)
    }
}

// SO_PEERCRED PID values are translated into the receiver's PID namespace;
// fdinfo and numeric process paths use the proc mount's PID namespace. Prove
// those views match before either join. Never compensate by translating or
// guessing an ancestor PID. All paths below are fixed kernel proc entries.
fn require_proc_view(original: &mut NativeAcquisition) -> Result<File> {
    let root = ns::open_root(original)?;
    require_proc_root_view(&root, original)?;
    Ok(root)
}

fn require_proc_root_view(root: &File, original: &mut NativeAcquisition) -> Result<()> {
    let own = File::from(rustix::fs::openat(
        root,
        "self",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    ns::require_proc(&own)?;
    // The real process leader in that view must also be the receiver's PID.
    let mut stat = ns::open_proc(&own, "stat", original)?;
    let mut status = ns::open_proc(&own, "status", original)?;
    namespace_protocol::require_same_proc_pid_view_data(
        &ns::read_proc(&mut stat, 16_384, original)?,
        &ns::read_proc(&mut status, 65_536, original)?,
        std::process::id(),
    )?;
    original.remaining()?;
    Ok(())
}

fn socket_profile(socket: &File, original: &mut NativeAcquisition) -> Result<()> {
    original.remaining()?;
    ensure!(
        rustix::net::sockopt::socket_type(socket)? == SocketType::SEQPACKET
            && rustix::net::sockopt::socket_domain(socket)? == AddressFamily::UNIX
            && rustix::io::fcntl_getfd(socket)?.contains(rustix::io::FdFlags::CLOEXEC)
            && rustix::fs::fcntl_getfl(socket)?.contains(OFlags::NONBLOCK),
        "backup_forwarded_socket_profile"
    );
    let mut poll = [rustix::event::PollFd::new(
        socket,
        rustix::event::PollFlags::RDHUP,
    )];
    let zero = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    rustix::event::poll(&mut poll, Some(&zero))?;
    ensure!(
        !poll[0].revents().intersects(
            rustix::event::PollFlags::RDHUP
                | rustix::event::PollFlags::HUP
                | rustix::event::PollFlags::ERR
                | rustix::event::PollFlags::NVAL
        ),
        "backup_forwarded_socket_closed"
    );
    original.remaining()?;
    Ok(())
}

fn require_process_views(
    root: &File,
    a: &MessageProcess,
    b: &MessageProcess,
    original: &mut NativeAcquisition,
) -> Result<()> {
    let fresh = ns::open_root(original)?;
    let identity = ns::proc_identity(root)?;
    ensure!(
        identity == ns::proc_identity(&fresh)?
            && identity == ns::proc_identity(&a.proc)?
            && identity == ns::proc_identity(&b.proc)?,
        "backup_forwarded_proc_view_changed"
    );
    require_proc_root_view(root, original)?;
    original.remaining()?;
    Ok(())
}

fn require_pidfd(
    root: &File,
    file: &File,
    expected: NonZeroU32,
    original: &mut NativeAcquisition,
) -> Result<()> {
    live(file, original)?;
    ensure!(
        rustix::io::fcntl_getfd(file)?.contains(rustix::io::FdFlags::CLOEXEC),
        "backup_forwarded_pidfd_cloexec"
    );
    require_proc_root_view(root, original)?;
    // The fixed kernel thread-self link selects OUR actual descriptor table,
    // even if a proc mount has a different numeric PID view. A numeric local
    // PID lookup could instead inspect another process's same-numbered FDs.
    let process = ns::open_task(root, original)?;
    let directory = File::from(rustix::fs::openat(
        &process,
        "fdinfo",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    ns::require_proc(&directory)?;
    // The sole filename is derived from this actual retained descriptor, not
    // an incoming PID/path. Descriptor0 is intentionally valid.
    let mut info = File::from(rustix::fs::openat(
        &directory,
        file.as_raw_fd().to_string(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    ns::require_proc(&info)?;
    ensure!(info.metadata()?.is_file(), "backup_forwarded_fdinfo_file");
    let bytes = ns::read_proc(&mut info, 4096, original)?;
    ensure!(
        pidfd_pid_data(&bytes)? == expected,
        "backup_forwarded_pidfd_actor_changed"
    );
    live(file, original)
}

// Only a join of actual kernel resources may use this number. Parsed DATA
// alone neither opens a process nor constructs a MessageProcess or role.
fn pidfd_pid_data(bytes: &[u8]) -> Result<NonZeroU32> {
    ensure!(bytes.len() <= 4096, "backup_forwarded_fdinfo_bound");
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("backup_forwarded_fdinfo_encoding"))?;
    let mut value = None;
    for line in text.lines() {
        if let Some(pid) = line.strip_prefix("Pid:") {
            ensure!(value.is_none(), "backup_forwarded_fdinfo_duplicate");
            let pid = pid.trim();
            ensure!(
                !pid.is_empty()
                    && pid.len() <= 10
                    && pid.bytes().all(|b| b.is_ascii_digit())
                    && (pid == "0" || !pid.starts_with('0')),
                "backup_forwarded_fdinfo_pid"
            );
            let parsed = pid
                .parse::<u32>()
                .map_err(|_| anyhow::anyhow!("backup_forwarded_fdinfo_pid"))?;
            ensure!(parsed <= i32::MAX as u32, "backup_forwarded_fdinfo_pid");
            value = NonZeroU32::new(parsed);
            ensure!(value.is_some(), "backup_forwarded_fdinfo_pid_not_visible");
        }
    }
    value.context("backup_forwarded_fdinfo_missing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fd::{AsFd, OwnedFd};
    use rustix::net::{self, SendFlags, SocketFlags};
    use std::{
        io::{IoSlice, IoSliceMut},
        mem::MaybeUninit,
    };

    fn pair() -> Result<(OwnedFd, OwnedFd)> {
        Ok(net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?)
    }

    fn receiver(socket: &OwnedFd) -> Result<()> {
        net::sockopt::set_socket_passcred(socket, true)?;
        net::sockopt::set_socket_passpidfd(socket, true)?;
        Ok(())
    }

    fn self_packet() -> Result<net::ReceivedPidfdPacket> {
        let (recv, send) = pair()?;
        receiver(&recv)?;
        net::send(
            &send,
            b"mechanical fixture DATA",
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )?;
        let mut bytes = [0; 64];
        Ok(net::recv_pidfd_packet(
            &recv,
            &mut [IoSliceMut::new(&mut bytes)],
        )?)
    }

    fn received(process: &File, socket: &File) -> Result<net::ReceivedPidfdRightsPacket> {
        let (recv, send) = pair()?;
        receiver(&recv)?;
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = net::SendAncillaryBuffer::new(&mut space);
        let rights = [process.as_fd(), socket.as_fd()];
        ensure!(
            ancillary.push(net::SendAncillaryMessage::ScmRights(&rights)),
            "fixture_ancillary_capacity"
        );
        net::sendmsg(
            &send,
            &[IoSlice::new(b"mechanical fixture DATA")],
            &mut ancillary,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )?;
        let mut bytes = [0; 64];
        Ok(net::recv_pidfd_rights_packet(
            &recv,
            &mut [IoSliceMut::new(&mut bytes)],
            net::PidfdRightsCount::Two,
        )?)
    }

    fn admitted(original: &mut NativeAcquisition) -> Result<(Digest, MessageProcess)> {
        let code = Digest::new(&std::fs::read("/proc/self/exe")?);
        let peer =
            MessageProcess::receive(self_packet()?, &code, original, &HashCosts::disabled())?;
        Ok((code, peer))
    }

    fn anchors(original: &mut NativeAcquisition) -> Result<(ForwardedJobAnchors, OwnedFd)> {
        let (code, mut controller) = admitted(original)?;
        let process = File::from(self_packet()?.process);
        let (socket, peer) = pair()?;
        let socket = File::from(socket);
        Ok((
            ForwardedJobAnchors::receive(
                received(&process, &socket)?,
                &mut controller,
                &code,
                original,
                &HashCosts::disabled(),
            )?,
            peer,
        ))
    }

    struct ChildOwner(std::process::Child);

    impl Drop for ChildOwner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "actual foreign process for kernel-only backup-anchor controls"]
    fn foreign_sender_child() -> Result<()> {
        ensure!(
            std::env::var_os("DAY2_BACKUP_ANCHOR_CHILD").is_some(),
            "fixture_child_only"
        );
        net::send(
            rustix::stdio::stdin(),
            b"foreign actual kernel process",
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )?;
        loop {
            std::thread::park();
        }
    }

    fn foreign_packet() -> Result<(ChildOwner, net::ReceivedPidfdPacket)> {
        let (recv, send) = pair()?;
        receiver(&recv)?;
        let child=ChildOwner(std::process::Command::new(std::env::current_exe()?)
            .args(["--exact","security_epoch::native_enrollment::process::backup_anchor::tests::foreign_sender_child","--ignored","--nocapture"])
            .env("DAY2_BACKUP_ANCHOR_CHILD","1")
            .stdin(std::process::Stdio::from(send)).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::inherit()).spawn()?);
        let mut poll = [rustix::event::PollFd::new(
            &recv,
            rustix::event::PollFlags::IN,
        )];
        let bound = rustix::event::Timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        ensure!(
            rustix::event::poll(&mut poll, Some(&bound))? == 1
                && poll[0].revents().contains(rustix::event::PollFlags::IN),
            "fixture_foreign_sender_not_received"
        );
        let mut bytes = [0; 64];
        Ok((
            child,
            net::recv_pidfd_packet(&recv, &mut [IoSliceMut::new(&mut bytes)])?,
        ))
    }

    #[test]
    fn unrelated_live_pidfd_or_actual_foreign_forwarder_cannot_borrow_the_same_socket() -> Result<()>
    {
        for replace_forwarder in [false, true] {
            let mut original = NativeAcquisition::begin(5)?;
            let (code, mut controller) = admitted(&mut original)?;
            let (_child, foreign) = foreign_packet()?;
            let process = File::from(foreign.process.try_clone()?);
            let (socket, _peer) = pair()?;
            let socket = File::from(socket);
            let mut message = received(&process, &socket)?;
            if replace_forwarder {
                message.packet = foreign;
            }
            let error = ForwardedJobAnchors::receive(
                message,
                &mut controller,
                &code,
                &mut original,
                &HashCosts::disabled(),
            )
            .err()
            .context("fixture_foreign_pair_accepted")?;
            assert_eq!(
                error.to_string(),
                if replace_forwarder {
                    "native_enrollment_packet_actor_changed"
                } else {
                    "backup_forwarded_pidfd_actor_changed"
                }
            );
            assert!(original.remaining().is_err());
        }
        Ok(())
    }

    #[test]
    fn actual_received_process_and_socket_are_retained_and_substitution_is_permanent() -> Result<()>
    {
        let mut original = NativeAcquisition::begin(5)?;
        let (mut owner, _peer) = anchors(&mut original)?;
        owner.check(&mut original, &HashCosts::disabled())?;
        assert_eq!(owner.process_data().process, std::process::id());
        let old = owner.socket.try_clone()?;
        let (replacement, _replacement_peer) = pair()?;
        owner.socket = File::from(replacement);
        assert_eq!(
            owner
                .check(&mut original, &HashCosts::disabled())
                .unwrap_err()
                .to_string(),
            "backup_forwarded_socket_changed"
        );
        owner.socket = old;
        let mut fresh = NativeAcquisition::begin(5)?;
        assert_eq!(
            owner
                .check(&mut fresh, &HashCosts::disabled())
                .unwrap_err()
                .to_string(),
            "backup_forwarded_peer_refused"
        );
        assert!(original.remaining().is_err());
        assert!(fresh.remaining().is_err());
        Ok(())
    }

    #[test]
    fn non_pidfd_and_wrong_socket_profiles_refuse_the_actual_original() -> Result<()> {
        for wrong_process in [false, true] {
            let mut original = NativeAcquisition::begin(5)?;
            let (code, mut controller) = admitted(&mut original)?;
            let temporary = tempfile::tempfile()?;
            let process = if wrong_process {
                temporary
            } else {
                File::from(self_packet()?.process)
            };
            let (socket, _peer) = if wrong_process {
                pair()?
            } else {
                net::socketpair(
                    AddressFamily::UNIX,
                    SocketType::STREAM,
                    SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                    None,
                )?
            };
            assert!(
                ForwardedJobAnchors::receive(
                    received(&process, &File::from(socket))?,
                    &mut controller,
                    &code,
                    &mut original,
                    &HashCosts::disabled()
                )
                .is_err()
            );
            assert!(original.remaining().is_err());
        }
        Ok(())
    }

    #[test]
    fn substituted_proc_view_and_closed_peer_never_recover_with_restored_fields() -> Result<()> {
        for replace_proc in [false, true] {
            let mut original = NativeAcquisition::begin(5)?;
            let (mut owner, peer) = anchors(&mut original)?;
            let old = owner.proc.try_clone()?;
            if replace_proc {
                owner.proc = File::open(tempfile::tempdir()?.path())?;
            } else {
                drop(peer);
            }
            assert!(owner.check(&mut original, &HashCosts::disabled()).is_err());
            owner.proc = old;
            let mut fresh = NativeAcquisition::begin(5)?;
            assert_eq!(
                owner
                    .check(&mut fresh, &HashCosts::disabled())
                    .unwrap_err()
                    .to_string(),
                "backup_forwarded_peer_refused"
            );
            assert!(original.remaining().is_err());
        }
        Ok(())
    }

    #[test]
    fn pidfd_number_is_only_bounded_kernel_join_data_with_no_alias_or_owner_factory() {
        assert_eq!(
            pidfd_pid_data(b"pos:\t0\nflags:\t02000002\nPid:\t17\nNSpid:\t17\n")
                .unwrap()
                .get(),
            17
        );
        for bytes in [
            b"Pid:\t0\n".as_slice(),
            b"Pid:\t-1\n",
            b"Pid:\t+17\n",
            b"Pid:\t017\n",
            b"Pid:\t2147483648\n",
            b"Pid:\t17\nPid:\t17\n",
            b"pos:\t17\n",
            b"Pid:\t\xff\n",
        ] {
            assert!(pidfd_pid_data(bytes).is_err());
        }
        assert!(pidfd_pid_data(&vec![b' '; 4097]).is_err());
    }
}
