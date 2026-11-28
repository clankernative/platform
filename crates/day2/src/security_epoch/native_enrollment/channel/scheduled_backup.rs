//! Dedicated scheduled-backup socket resources, never requester admission.
//! The Job mounts only this fixed child, not storage or enrollment sockets.
//! A connected socket or matching pathname grants no source permission.

use super::{Channel, Direction, configure, idle_open, require_idle_socket_profile, wait};
use crate::security_epoch::{
    native_clock::NativeAcquisition,
    native_enrollment::{
        EnrolledRoleStage, SameEnrolledOwner,
        issuer_peer::IssuerReceipt,
        owner::BackupSubmitOriginal,
        process::backup_anchor::ScheduledJobSender,
        protocol::{BackupObserverIdentityData, SignedBackupObservation},
        storage_socket_directory::ScheduledBackupSocketDirectory,
    },
};
use anyhow::{Result, ensure};
use rustix::{
    event::PollFlags,
    fs::{Mode, OFlags},
    net::{self, AddressFamily, RecvPidfdError, SocketFlags, SocketType},
};
use std::{cell::Cell, fs::File, io::IoSliceMut, os::unix::fs::MetadataExt, rc::Rc};

const PATH: &str = "/run/day2-native-enrollment/scheduled-backup/request.sock";
const MAX_SUBMIT: usize = crate::security_epoch::scheduled_backup::requester::MAX_SUBMIT_BYTES;

/// Owns the actual fixed dentry and directory across listener and connections.
/// Sharing these resource checks cannot construct a role, original or grant.
struct ScheduledBackupSocketName {
    name: File,
    root: File,
    directory: ScheduledBackupSocketDirectory,
    identity: (u64, u64),
    process: u32,
    thread: std::thread::ThreadId,
    refused: Cell<bool>,
    local: std::marker::PhantomData<Rc<()>>,
}

pub(in crate::security_epoch::native_enrollment) struct ScheduledBackupSocketListener {
    socket: File,
    name: Rc<ScheduledBackupSocketName>,
}

/// An accepted resource only. No packet authentication, process or request
/// permission is inferred from accept, SO_PEERCRED, path or file ownership.
pub(in crate::security_epoch::native_enrollment) struct ScheduledBackupConnection {
    socket: Rc<File>,
    name: Rc<ScheduledBackupSocketName>,
    refused: Cell<bool>,
}

/// One actual Submit, still NOT an admitted request. Its immutable comparison
/// bytes and original identity remain joined to the actual retained sender and
/// connection; there is no DATA/native-owner or renewed-original constructor.
pub(in crate::security_epoch::native_enrollment) struct CapturedScheduledBackupSubmit {
    connection: ScheduledBackupConnection,
    sender: ScheduledJobSender,
    intent: Vec<u8>,
    original: BackupSubmitOriginal,
    refused: bool,
}

/// Consumed, completed one-shot issuer exchange. The peer may close normally;
/// no method can send, receive, reconnect or infer the issuer's later posts.
pub(in crate::security_epoch::native_enrollment) struct CompletedBackupObservationChannel {
    channel: Channel,
    original: BackupSubmitOriginal,
}

/// Real completed comparison, never CREATE/request/source admission. No DATA
/// can construct this actual Submit/issuer-process/Controller continuity owner.
pub(in crate::security_epoch::native_enrollment) struct ObservedScheduledBackupSubmit {
    submit: CapturedScheduledBackupSubmit,
    channel: CompletedBackupObservationChannel,
    nonce_peer: IssuerReceipt,
    grant_peer: IssuerReceipt,
    same: SameEnrolledOwner,
    identity: BackupObserverIdentityData,
    observation: SignedBackupObservation,
    request: day2_capabilities::Digest,
    challenge: day2_capabilities::Digest,
    refused: bool,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
    }
    macro_rules! opaque {
        ($owner:ty) => {
            assert_not_impl!($owner, Clone);
            assert_not_impl!($owner, Copy);
            assert_not_impl!($owner, Default);
            assert_not_impl!($owner, std::fmt::Debug);
            assert_not_impl!($owner, Send);
            assert_not_impl!($owner, Sync);
            assert_not_impl!($owner, serde::Serialize);
            assert_not_impl!($owner, serde::Deserialize<'static>);
            assert_not_impl!($owner, rustix::fd::AsFd);
            assert_not_impl!($owner, std::os::fd::AsRawFd);
            assert_not_impl!($owner, std::ops::Deref);
        };
    }
    opaque!(ScheduledBackupSocketName);
    opaque!(ScheduledBackupSocketListener);
    opaque!(ScheduledBackupConnection);
    opaque!(CapturedScheduledBackupSubmit);
    opaque!(CompletedBackupObservationChannel);
    opaque!(ObservedScheduledBackupSubmit);
};

impl ScheduledBackupSocketName {
    fn check(&self) -> Result<()> {
        let requested = (|| {
            ensure!(
                !self.refused.get()
                    && self.process == std::process::id()
                    && self.thread == std::thread::current().id(),
                "scheduled_backup_socket_owner_changed"
            );
            self.directory.check(&self.root)?;
            let held = self.name.metadata()?;
            require_socket_name(&held)?;
            ensure!(
                rustix::io::fcntl_getfd(&self.name)?.contains(rustix::io::FdFlags::CLOEXEC)
                    && (held.dev(), held.ino()) == self.identity,
                "scheduled_backup_socket_held_changed"
            );
            let named = std::fs::symlink_metadata(PATH)?;
            require_socket_name(&named)?;
            ensure!(
                (named.dev(), named.ino()) == self.identity,
                "scheduled_backup_socket_name_changed"
            );
            Ok(())
        })();
        if requested.is_err() {
            self.refused.set(true);
        }
        requested
    }
}

impl ScheduledBackupSocketListener {
    pub(in crate::security_epoch::native_enrollment) fn bind(
        stage: &mut EnrolledRoleStage<'_>,
        original: &mut NativeAcquisition,
    ) -> Result<Self> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // The actual checked Controller and enabled policy select this
            // fixed resource. The policy DATA is not an admitted requester.
            stage.storage()?.scheduled_backup_root_selection()?;
            stage.check_serving_acquisition(original)?;
            ensure!(
                rustix::process::geteuid().as_raw() == 10001,
                "scheduled_backup_socket_uid"
            );
            let root = File::from(rustix::fs::open(
                "/run/day2-native-enrollment",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?);
            let directory = ScheduledBackupSocketDirectory::observe(&root)?;
            stage.check_serving_acquisition(original)?;
            let socket = net::socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )?;
            configure(&socket)?;
            // There is deliberately no unlink, adoption or retry on EEXIST.
            net::bind(&socket, &net::SocketAddrUnix::new(PATH)?)?;
            stage.check_serving_acquisition(original)?;
            let name = File::from(rustix::fs::open(
                PATH,
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?);
            // Static retained-dentry chmod helper only; no restore packet,
            // membership, listener or authentication factory is reused.
            super::protected_restore::set_private_socket_mode(&name, original)?;
            net::listen(&socket, 16)?;
            let held = name.metadata()?;
            let resource = Rc::new(ScheduledBackupSocketName {
                name,
                root,
                directory,
                identity: (held.dev(), held.ino()),
                process: std::process::id(),
                thread: std::thread::current().id(),
                refused: Cell::new(false),
                local: std::marker::PhantomData,
            });
            let listener = Self {
                socket: File::from(socket),
                name: resource,
            };
            listener.check()?;
            Ok(listener)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.check_serving_acquisition(original)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            stage.refuse_serving();
            original.refuse();
        }
        finish_checked(requested, checked)
    }

    fn check(&self) -> Result<()> {
        let requested = (|| {
            self.name.check()?;
            require_idle_socket_profile(&self.socket)?;
            ensure!(
                net::sockopt::socket_acceptconn(&self.socket)?
                    && net::sockopt::socket_passcred(&self.socket)?
                    && net::sockopt::socket_passpidfd(&self.socket)?
                    && rustix::fs::fcntl_getfl(&self.socket)?.contains(OFlags::NONBLOCK),
                "scheduled_backup_listener_profile"
            );
            Ok(())
        })();
        if requested.is_err() {
            self.name.refused.set(true);
        }
        requested
    }

    /// No wait or native original is retained by this resource. The eventual
    /// Submit driver must capture its genuine original before decode/auth.
    pub(in crate::security_epoch::native_enrollment) fn accept(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        original: &mut NativeAcquisition,
    ) -> Result<ScheduledBackupConnection> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.storage()?.scheduled_backup_root_selection()?;
            stage.check_serving_acquisition(original)?;
            self.check()?;
            let socket =
                net::accept_with(&self.socket, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)?;
            configure(&socket)?;
            let connection = ScheduledBackupConnection {
                socket: Rc::new(File::from(socket)),
                name: Rc::clone(&self.name),
                refused: Cell::new(false),
            };
            connection.check_resources()?;
            self.check()?;
            Ok(connection)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.check_serving_acquisition(original)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.name.refused.set(true);
            stage.refuse_serving();
            original.refuse();
        }
        finish_checked(requested, checked)
    }
}

impl ScheduledBackupConnection {
    /// Consumes this actual connection before the first fallible receive.
    /// The outer fixed Submit action must already own its genuine original;
    /// this method never starts, renews, returns or reconstructs a clock.
    pub(in crate::security_epoch::native_enrollment) fn receive_submit(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        original: &mut NativeAcquisition,
    ) -> Result<CapturedScheduledBackupSubmit> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let captured = BackupSubmitOriginal::capture(original)?;
            let selected = stage.storage()?.scheduled_backup_root_selection()?;
            stage.check_serving_acquisition(original)?;
            self.check_resources()?;
            let mut bytes = [0_u8; MAX_SUBMIT];
            let received = loop {
                original.remaining()?;
                match net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)]) {
                    Ok(packet) => break packet,
                    Err(RecvPidfdError::Io(rustix::io::Errno::AGAIN)) => {
                        wait(&self.socket, PollFlags::IN, original)?
                    }
                    Err(RecvPidfdError::Io(rustix::io::Errno::INTR)) => {
                        original.remaining()?;
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            let count = received.bytes;
            let sender = ScheduledJobSender::receive(
                received,
                Rc::clone(&self.socket),
                &selected.executable,
                original,
            )?;
            let intent = crate::security_epoch::scheduled_backup::requester::decode_submit_data(
                &bytes[..count],
            )?;
            let mut submit = CapturedScheduledBackupSubmit {
                connection: self,
                sender,
                intent,
                original: captured,
                refused: false,
            };
            submit.check(original)?;
            Ok(submit)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.check_serving_acquisition(original)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            stage.refuse_serving();
            original.refuse();
        }
        finish_checked(requested, checked)
    }

    fn check_resources(&self) -> Result<()> {
        let requested = (|| {
            ensure!(!self.refused.get(), "scheduled_backup_connection_refused");
            self.name.check()?;
            require_idle_socket_profile(&self.socket)?;
            ensure!(
                net::sockopt::socket_passcred(&self.socket)?
                    && net::sockopt::socket_passpidfd(&self.socket)?
                    && rustix::fs::fcntl_getfl(&self.socket)?.contains(OFlags::NONBLOCK),
                "scheduled_backup_connection_profile"
            );
            idle_open(&self.socket)
        })();
        if requested.is_err() {
            self.refused.set(true);
        }
        requested
    }
}

impl CapturedScheduledBackupSubmit {
    /// Consumes the actual Submit through the one fixed issuer exchange. The
    /// actual same Controller stage/original and both kernel receipts survive.
    pub(in crate::security_epoch::native_enrollment) fn observe_issuer(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
        original: &mut NativeAcquisition,
    ) -> Result<ObservedScheduledBackupSubmit> {
        use crate::security_epoch::native_enrollment::protocol::{self, Packet};
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<ObservedScheduledBackupSubmit> {
                self.check(original)?;
                let mut same = stage.capture_same_owner()?;
                same.meet_current_read_view(stage, original)?;
                let identity = stage.storage()?.backup_observer_identity_data(original)?;
                let intent = self.intent_data(original)?;
                let policy = identity.policy.digest()?;
                let request = protocol::nonce("scheduled-backup-observe-request")?;
                let mut channel = Channel::connect(original)?;
                channel.send(
                    &Packet::BackupObserveHello {
                        policy,
                        public_key: identity.public_key.clone(),
                        request: request.clone(),
                        intent: String::from_utf8(intent.clone())?,
                    },
                    original,
                )?;
                let (packet, mut nonce_peer) = channel.receive_issuer(original)?;
                let Packet::BackupObserveNonce {
                    request: echoed,
                    challenge,
                } = packet
                else {
                    anyhow::bail!("native_backup_observation_order")
                };
                ensure!(echoed == request, "native_backup_observation_request");
                nonce_peer.bind(&identity.certificate, &identity.policy, original)?;
                same.meet_current_read_view(stage, original)?;
                self.check(original)?;
                let signature = stage.storage()?.sign_backup_observer_bind(
                    &identity,
                    &intent,
                    (&request, &challenge),
                    original,
                )?;
                channel.send_backup_observe_bind(
                    &mut self,
                    &Packet::BackupObserveBind {
                        request: request.clone(),
                        challenge: challenge.clone(),
                        signature,
                    },
                    original,
                )?;
                let (packet, mut grant_peer) = channel.receive_issuer(original)?;
                let Packet::BackupObserveGrant { observation } = packet else {
                    anyhow::bail!("native_backup_observation_order")
                };
                grant_peer.bind(&identity.certificate, &identity.policy, original)?;
                ensure!(
                    observation.data.request == request && observation.data.challenge == challenge,
                    "native_backup_observation_nonce_changed"
                );
                let channel = channel.complete_backup_observation(original)?;
                let mut observed = ObservedScheduledBackupSubmit {
                    submit: self,
                    channel,
                    nonce_peer,
                    grant_peer,
                    same,
                    identity,
                    observation: *observation,
                    request,
                    challenge,
                    refused: false,
                };
                observed.check(stage, original)?;
                Ok(observed)
            },
        ));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.check_serving_acquisition(original)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            stage.refuse_serving();
            original.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(observed)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(observed)
                }
            },
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn check(
        &mut self,
        original: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(!self.refused, "backup_submit_refused");
            self.original.check(original)?;
            self.connection.check_resources()?;
            self.sender.check(original)?;
            self.original.check_intent(original, &self.intent)?;
            original.remaining()?;
            Ok(())
        })();
        if requested.is_err() {
            self.refused = true;
            self.original.refuse();
            self.sender.refuse();
            self.connection.refused.set(true);
            original.refuse();
        }
        requested
    }

    /// These are the already-submitted public comparison bytes, not private
    /// snapshot DATA, a role, source owner or descriptor. Copy only after the
    /// same actual Submit checks; it cannot reconstruct this resource.
    pub(in crate::security_epoch::native_enrollment) fn intent_data(
        &mut self,
        original: &mut NativeAcquisition,
    ) -> Result<Vec<u8>> {
        self.check(original)?;
        Ok(self.intent.clone())
    }

    pub(in crate::security_epoch::native_enrollment) fn require_job_data(
        &mut self,
        expected: &crate::security_epoch::native_enrollment::protocol::ProcessData,
        original: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = (|| {
            self.check(original)?;
            self.sender.require_process_data(expected, original)
        })();
        let checked = self.check(original);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            original.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse(&mut self) {
        self.refused = true;
        self.original.refuse();
        self.sender.refuse();
        self.connection.refused.set(true);
    }
}

impl Channel {
    pub(in crate::security_epoch::native_enrollment) fn complete_backup_observation(
        mut self,
        original: &mut NativeAcquisition,
    ) -> Result<CompletedBackupObservationChannel> {
        let mut guard = BackupSubmitOriginal::capture(original)?;
        let requested = (|| {
            ensure!(!self.refused.get(), "backup_observer_channel_refused");
            self.transcript
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("backup_observer_cursor_missing"))?
                .require_completed_backup_observation_data(Self::observation(original))?;
            guard.check(original)?;
            Ok(())
        })();
        if requested.is_err() {
            self.refuse();
            guard.refuse();
            original.refuse();
        }
        requested?;
        let mut completed = CompletedBackupObservationChannel {
            channel: self,
            original: guard,
        };
        completed.check(original)?;
        Ok(completed)
    }

    /// The sole two-rights sender is purpose-closed to this actual Submit and
    /// issuer Bind cursor. No arbitrary descriptor/ancillary API is exposed.
    pub(in crate::security_epoch::native_enrollment) fn send_backup_observe_bind(
        &mut self,
        submit: &mut CapturedScheduledBackupSubmit,
        packet: &crate::security_epoch::native_enrollment::protocol::Packet,
        original: &mut NativeAcquisition,
    ) -> Result<()> {
        use crate::security_epoch::native_enrollment::protocol::Packet;
        let requested = (|| {
            ensure!(
                !self.refused.get() && matches!(packet, Packet::BackupObserveBind { .. }),
                "backup_observer_bind_purpose"
            );
            submit.check(original)?;
            self.begin_packet(Direction::Send, packet.frame(), original)?;
            submit
                .sender
                .send_observation_bind(&self.socket, packet, original)?;
            self.packet_delivered(packet.frame(), original)?;
            Ok(())
        })();
        let checked = submit.check(original);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            submit.refuse();
            original.refuse();
        }
        requested?;
        checked
    }
}

impl CompletedBackupObservationChannel {
    pub(in crate::security_epoch::native_enrollment) fn check(
        &mut self,
        original: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = (|| {
            self.original.check(original)?;
            ensure!(
                !self.channel.refused.get(),
                "backup_observer_channel_refused"
            );
            require_idle_socket_profile(&self.channel.socket)?;
            ensure!(
                net::sockopt::socket_passcred(&self.channel.socket)?
                    && net::sockopt::socket_passpidfd(&self.channel.socket)?
                    && rustix::fs::fcntl_getfl(&self.channel.socket)?.contains(OFlags::NONBLOCK),
                "backup_observer_channel_profile"
            );
            self.channel
                .transcript
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("backup_observer_cursor_missing"))?
                .require_completed_backup_observation_data(Channel::observation(original))?;
            original.remaining()?;
            Ok(())
        })();
        if requested.is_err() {
            self.refuse();
            original.refuse();
        }
        requested
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse(&mut self) {
        self.original.refuse();
        self.channel.refuse();
    }
}

impl Drop for CompletedBackupObservationChannel {
    fn drop(&mut self) {
        self.refuse();
    }
}

impl ObservedScheduledBackupSubmit {
    pub(in crate::security_epoch::native_enrollment) fn check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        original: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            ensure!(!self.refused, "backup_observation_refused");
            self.same.meet_current_read_view(stage, original)?;
            self.submit.check(original)?;
            let identity = stage.storage()?.backup_observer_identity_data(original)?;
            ensure!(
                identity == self.identity,
                "backup_observer_controller_changed"
            );
            self.nonce_peer
                .bind(&identity.certificate, &identity.policy, original)?;
            self.grant_peer
                .bind(&identity.certificate, &identity.policy, original)?;
            self.nonce_peer.check_live(original)?;
            self.grant_peer.check_live(original)?;
            let intent = self.submit.intent_data(original)?;
            self.observation.verify_data(
                &identity.policy,
                &identity.certificate,
                (&identity.controller, &identity.public_key),
                &intent,
                (&self.request, &self.challenge),
                original.sample()?.elapsed,
            )?;
            self.submit
                .require_job_data(&self.observation.data.job, original)?;
            self.channel.check(original)?;
            Ok(())
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.check_serving_acquisition(original)
        }));
        if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
            original.refuse();
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

    fn refuse(&mut self) {
        self.refused = true;
        self.submit.refuse();
        self.channel.refuse();
    }
}

impl Drop for ObservedScheduledBackupSubmit {
    fn drop(&mut self) {
        self.refuse();
    }
}

fn require_socket_name(metadata: &std::fs::Metadata) -> Result<()> {
    ensure!(
        metadata.mode() & 0o170000 == 0o140000
            && metadata.uid() == 10001
            && metadata.gid() == 10001
            && metadata.mode() & 0o7777 == 0o600,
        "scheduled_backup_socket_shape"
    );
    Ok(())
}

// Both independent results have already been evaluated. Preserve the first
// real error/panic; a post failure never turns setup into a usable resource.
fn finish_checked<T>(
    requested: std::thread::Result<Result<T>>,
    checked: std::thread::Result<Result<()>>,
) -> Result<T> {
    match requested {
        Err(payload) => std::panic::resume_unwind(payload),
        Ok(Err(error)) => Err(error),
        Ok(Ok(value)) => match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => {
                result?;
                Ok(value)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::finish_checked;
    use std::sync::Arc;

    #[derive(Debug)]
    struct Cause(Arc<()>);

    impl std::fmt::Display for Cause {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("foreign display must not run")
        }
    }

    impl std::error::Error for Cause {}

    #[test]
    fn actual_resource_completion_preserves_first_error_and_post_refusal() {
        for first_fails in [false, true] {
            for post_fails in [false, true] {
                let first = Arc::new(());
                let post = Arc::new(());
                let requested = if first_fails {
                    Err(anyhow::Error::new(Cause(Arc::clone(&first))))
                } else {
                    Ok(7)
                };
                let checked = if post_fails {
                    Err(anyhow::Error::new(Cause(Arc::clone(&post))))
                } else {
                    Ok(())
                };
                let result = finish_checked(Ok(requested), Ok(checked));
                if first_fails || post_fails {
                    let error = result.err().unwrap();
                    let actual = error.downcast_ref::<Cause>().unwrap();
                    assert!(Arc::ptr_eq(
                        &actual.0,
                        if first_fails { &first } else { &post }
                    ));
                } else {
                    assert_eq!(result.unwrap(), 7);
                }
            }
        }
    }

    #[test]
    fn actual_resource_completion_keeps_first_panic_and_never_returns_on_post_panic() {
        let first = std::panic::catch_unwind(|| panic!("first"));
        let post = std::panic::catch_unwind(|| panic!("post"));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            finish_checked::<()>(first, post)
        }));
        assert_eq!(result.unwrap_err().downcast_ref::<&str>(), Some(&"first"));
        let post = std::panic::catch_unwind(|| panic!("post"));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            finish_checked(Ok(Ok(7)), post)
        }));
        assert_eq!(result.unwrap_err().downcast_ref::<&str>(), Some(&"post"));
    }
}
