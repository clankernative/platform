//! Fixed Shell courier. A known native reply is still DATA; the actual bound
//! HTTP request retains its opaque peer restriction through final transport.

use super::{
    ProtectedRestoreActionGuard, ProtectedRestoreGuardPeer, ProtectedRestorePending,
    ProtectedRestoreReply, ProtectedRestoreRequest, ProtectedRestoreShell,
    ProtectedRestoreShellReplyGuard, ProtectedRestoreShellTerminalGuard,
};
use crate::security_epoch::native_enrollment::EnrolledRoleStage;
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::NativeConsumerOrigin;
use anyhow::Result;

impl ProtectedRestoreActionGuard {
    fn from_shell_reply(guard: ProtectedRestoreShellReplyGuard) -> Self {
        Self {
            peer: ProtectedRestoreGuardPeer::ShellReply(Box::new(guard)),
        }
    }
}

fn check_shell(
    shell: &mut ProtectedRestoreShell,
    pending: Option<&mut ProtectedRestorePending>,
    bound: Option<&crate::security_epoch::native_enrollment::serving_peer_wire::Statement>,
    stage: &mut EnrolledRoleStage<'_>,
    acquisition: &mut crate::security_epoch::native_clock::NativeAcquisition,
) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pending, bound);
        shell.refuse();
        stage.refuse_serving();
        acquisition.refuse();
        anyhow::bail!(super::UNAVAILABLE);
    }
    #[cfg(target_os = "linux")]
    {
        use super::{ServingSender, select_guard_check};
        use crate::security_epoch::native_enrollment::NativeRole;
        use anyhow::ensure;
        let mut checked =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                ensure!(!shell.refused.get(), "protected_restore_shell_refused");
                shell._same.check(stage)?;
                stage.require_protected_restore_role(NativeRole::SecurityShell)?;
                let local = stage.protected_restore_statement()?;
                ensure!(
                    local.same_enrollment(&shell._local_statement),
                    "protected_restore_local_enrollment_changed"
                );
                ensure!(
                    shell._sender.len() == 2,
                    "protected_restore_admission_sender_count"
                );
                shell
                    .channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                    .check_protected_open(stage, acquisition)
            }));
        for sender in &mut shell._sender {
            let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || -> Result<()> {
                    match sender {
                        ServingSender::Controller(receipt) => {
                            receipt.check_continuity(&shell._remote_statement, stage, acquisition)
                        }
                        ServingSender::Shell(process) => {
                            process.check_identity(acquisition,&crate::security_epoch::native_enrollment::issuer_costs::HashCosts::disabled())?;
                            anyhow::bail!("protected_restore_controller_sender_required")
                        }
                    }
                },
            ));
            checked = select_guard_check(checked, observed);
        }
        if let Some(sender) = pending {
            let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || -> Result<()> {
                    match &mut sender.sender {
                        ServingSender::Controller(receipt) => {
                            receipt.check_received(acquisition)?;
                            if let Some(statement) = bound {
                                receipt.check_continuity(statement, stage, acquisition)?;
                            }
                            Ok(())
                        }
                        ServingSender::Shell(process) => {
                            process.check_identity(acquisition,&crate::security_epoch::native_enrollment::issuer_costs::HashCosts::disabled())?;
                            anyhow::bail!("protected_restore_controller_sender_required")
                        }
                    }
                },
            ));
            checked = select_guard_check(checked, observed);
        }
        let local = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.check_serving_acquisition(acquisition)
        }));
        let checked = select_guard_check(checked, local);
        if !matches!(&checked, Ok(Ok(()))) {
            shell.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result,
        }
    }
}

pub(super) fn request(
    shell: &mut ProtectedRestoreShell,
    stage: &mut EnrolledRoleStage<'_>,
    request: ProtectedRestoreRequest,
) -> Result<ProtectedRestoreReply> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = request;
        shell.refuse();
        stage.refuse_serving();
        anyhow::bail!(super::UNAVAILABLE);
    }
    #[cfg(target_os = "linux")]
    {
        use super::{ServingSender, admission, wire};
        use crate::security_epoch::native_enrollment::protocol::StagePurpose;
        use anyhow::ensure;
        use std::{rc::Rc, time::Duration};
        // This fixed negative supplier also rejects an already guarded frame
        // BEFORE any second packet could be sent under that HTTP original.
        let mut original = Some(NativeConsumerOrigin::protected_restore_shell_reply(stage)?);
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        let mut sender = None;
        let mut bound = None;
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<_> {
            let expected = request.reply_purpose()?;
            check_shell(
                shell,
                sender.as_mut(),
                bound.as_ref(),
                stage,
                &mut acquisition,
            )?;
            let sequence = shell
                ._sequence
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("protected_restore_sequence_exhausted"))?;
            shell
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .begin_current_handshake(sequence, StagePurpose::CurrentRole, &mut acquisition)?;
            let local = stage.protected_restore_statement()?;
            let data = wire::Data::request(
                shell._connection.clone(),
                admission::enrollment(&shell._local_statement)?,
                sequence,
                local.original,
                request,
            )?;
            shell
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .send_protected_command(data, &shell._local_statement, stage, &mut acquisition)?;
            check_shell(
                shell,
                sender.as_mut(),
                bound.as_ref(),
                stage,
                &mut acquisition,
            )?;
            let (packet, received) = shell
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .receive_protected_command(stage, &mut acquisition)?;
            sender = Some(ProtectedRestorePending {
                sender: received,
                _local: std::marker::PhantomData,
            });
            check_shell(
                shell,
                sender.as_mut(),
                bound.as_ref(),
                stage,
                &mut acquisition,
            )?;
            let data = packet.verify_data(&shell._remote_statement.stage.data.public_key)?;
            data.require_binding(
                &shell._connection,
                &admission::enrollment(&shell._remote_statement)?,
                sequence,
                wire::Direction::Reply,
            )?;
            let remote = data.original().clone();
            remote.require_request_continuity(&shell.last_remote)?;
            remote.validate_request(acquisition.sample()?.elapsed, StagePurpose::CurrentRole)?;
            let mut statement = shell._remote_statement.clone();
            statement.original = remote.clone();
            stage.check_admitted_serving_statement(
                &statement,
                &shell._remote_statement,
                &mut acquisition,
            )?;
            match (sender.as_mut(), shell._sender.first_mut()) {
                (
                    Some(ProtectedRestorePending {
                        sender: ServingSender::Controller(receipt),
                        ..
                    }),
                    Some(ServingSender::Controller(admitted)),
                ) => receipt.bind_admitted(
                    &statement,
                    admitted,
                    &shell._remote_statement,
                    stage,
                    &mut acquisition,
                )?,
                _ => anyhow::bail!("protected_restore_controller_sender_required"),
            }
            bound = Some(statement.clone());
            acquisition = acquisition.narrow(5, Duration::from_nanos(remote.deadline_ns))?;
            shell
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .meet_protected_received(&mut shell._same, stage, &mut acquisition)?;
            check_shell(
                shell,
                sender.as_mut(),
                bound.as_ref(),
                stage,
                &mut acquisition,
            )?;
            let reply = data.into_reply()?;
            reply.require_purpose(expected)?;
            let socket = shell
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .protected_restore_observer(stage, &mut acquisition)?;
            let same = stage.capture_same_owner()?;
            let receipt = match sender.take() {
                Some(ProtectedRestorePending {
                    sender: ServingSender::Controller(receipt),
                    ..
                }) => receipt,
                _ => anyhow::bail!("protected_restore_controller_sender_required"),
            };
            let guard =
                ProtectedRestoreActionGuard::from_shell_reply(ProtectedRestoreShellReplyGuard {
                    same,
                    original: original.take().ok_or_else(|| {
                        anyhow::anyhow!("protected_restore_shell_original_missing")
                    })?,
                    root: Rc::clone(&shell.refused),
                    connection: shell._connection.clone(),
                    sequence,
                    remote: statement,
                    socket,
                    receipt,
                });
            guard.attach_to_request(stage)?;
            shell._sequence = sequence;
            shell.last_remote = remote;
            ensure!(!shell.refused.get(), "protected_restore_shell_refused");
            Ok(reply)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_shell(
                shell,
                sender.as_mut(),
                bound.as_ref(),
                stage,
                &mut acquisition,
            )
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            if let Some(original) = &original {
                original.refuse();
            }
            shell.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(reply)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(reply)
                }
            },
        }
    }
}

impl ProtectedRestoreActionGuard {
    fn from_shell_terminal(guard: ProtectedRestoreShellTerminalGuard) -> Self {
        Self {
            peer: ProtectedRestoreGuardPeer::ShellTerminal(Box::new(guard)),
        }
    }
}

impl ProtectedRestoreShellTerminalGuard {
    pub(super) fn check(
        &mut self,
        owner: &crate::security_epoch::native_enrollment::EnrolledProcessRoleOwner,
        purpose: crate::security_epoch::native_enrollment::protocol::StagePurpose,
        acquisition: &mut crate::security_epoch::native_clock::NativeAcquisition,
    ) -> Result<()> {
        use super::select_guard_check;
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            anyhow::ensure!(
                !self.shell.refused.get()
                    && self.sequence > 0
                    && self.connection == self.shell._connection
                    && self.sequence == self.shell._sequence,
                "protected_restore_terminal_courier_changed"
            );
            anyhow::ensure!(purpose==crate::security_epoch::native_enrollment::protocol::StagePurpose::CurrentRole,"protected_restore_terminal_purpose");
            self.original.require_acquisition(acquisition)?;
            #[cfg(target_os = "linux")]
            {
                anyhow::ensure!(
                    self.shell._sender.len() == 2,
                    "protected_restore_admission_sender_count"
                );
                let channel = self
                    .shell
                    .channel
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?;
                self.socket.require_channel(channel)?;
                self.same
                    .require_protected_restore_shell_owner(owner, &self.remote)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = owner;
                anyhow::bail!(super::UNAVAILABLE)
            }
        }));
        #[cfg(target_os = "linux")]
        let socket = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.socket.check(acquisition)
        }));
        #[cfg(not(target_os = "linux"))]
        let socket = Ok(Err(anyhow::anyhow!(super::UNAVAILABLE)));
        #[cfg(target_os = "linux")]
        let receipt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.receipt
                .check_protected_restore_bound(&self.remote, acquisition)
        }));
        #[cfg(not(target_os = "linux"))]
        let receipt = Ok(Err(anyhow::anyhow!(super::UNAVAILABLE)));
        let checked = select_guard_check(select_guard_check(requested, socket), receipt);
        #[cfg(target_os = "linux")]
        let checked = {
            let mut checked = checked;
            for sender in &mut self.shell._sender {
                let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || -> Result<()> {
                        match sender {
                            super::ServingSender::Controller(receipt) => receipt
                                .check_protected_restore_bound(
                                    &self.shell._remote_statement,
                                    acquisition,
                                ),
                            super::ServingSender::Shell(process) => {
                                process.check_identity(acquisition,&crate::security_epoch::native_enrollment::issuer_costs::HashCosts::disabled())?;
                                anyhow::bail!("protected_restore_controller_sender_required")
                            }
                        }
                    },
                ));
                checked = select_guard_check(checked, observed);
            }
            checked
        };
        let clock = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            acquisition.remaining().map(|_| ())
        }));
        let checked = select_guard_check(checked, clock);
        if !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            acquisition.refuse();
        }
        match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result,
        }
    }

    pub(super) fn require_binding(
        &mut self,
        root: &std::rc::Rc<std::cell::Cell<bool>>,
        original: &crate::security_epoch::native_enrollment::NativeConsumerOrigin,
        connection: &day2_capabilities::Digest,
        sequence: u64,
    ) -> Result<()> {
        let requested = (|| {
            anyhow::ensure!(
                !self.shell.refused.get()
                    && std::rc::Rc::ptr_eq(&self.shell.refused, root)
                    && self.connection == *connection
                    && self.sequence == sequence
                    && sequence > 0,
                "protected_restore_terminal_binding_changed"
            );
            self.original.require_same(original)
        })();
        if requested.is_err() {
            self.refuse();
            root.set(true);
            original.refuse();
        }
        requested
    }

    pub(super) fn refuse(&mut self) {
        // Memory only. In particular, do not drop the actual courier/channel
        // from a SQL-safe frame check. Its owner retains it until settlement.
        self.shell.refused.set(true);
        self.original.refuse();
        #[cfg(target_os = "linux")]
        self.socket.refuse();
    }
}

pub(super) fn authenticate(
    shell: Box<ProtectedRestoreShell>,
    stage: &mut EnrolledRoleStage<'_>,
    id: &day2_capabilities::Digest,
    assertion: &[u8],
) -> Result<super::RestoreInstalledOutputData> {
    #[cfg(not(target_os = "linux"))]
    {
        let mut shell = shell;
        let _ = (id, assertion);
        shell.refuse();
        stage.refuse_serving();
        anyhow::bail!(super::UNAVAILABLE);
    }
    #[cfg(target_os = "linux")]
    {
        use super::{admission, select_guard_check, wire};
        use crate::security_epoch::native_enrollment::protocol::StagePurpose;
        use std::time::Duration;
        let mut shell = Some(shell);
        let mut original = Some(NativeConsumerOrigin::protected_restore_shell_reply(stage)?);
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        let mut sender = None;
        let mut bound = None;
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<_> {
            let active = shell
                .as_deref_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_terminal_courier_missing"))?;
            check_shell(active, None, None, stage, &mut acquisition)?;
            let sequence = active
                ._sequence
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("protected_restore_sequence_exhausted"))?;
            active
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .begin_current_handshake(sequence, StagePurpose::CurrentRole, &mut acquisition)?;
            let local = stage.protected_restore_statement()?;
            let data = wire::Data::request(
                active._connection.clone(),
                admission::enrollment(&active._local_statement)?,
                sequence,
                local.original,
                ProtectedRestoreRequest::Authenticate {
                    id: id.clone(),
                    assertion: assertion.to_vec(),
                },
            )?;
            let commitment = data.commitment()?;
            active
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .send_protected_command(data, &active._local_statement, stage, &mut acquisition)?;
            check_shell(active, None, None, stage, &mut acquisition)?;
            let (packet, receipt) = active
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .receive_protected_installed(stage, &mut acquisition)?;
            sender = Some(receipt);
            let data = packet.verify_data(&active._remote_statement.stage.data.public_key)?;
            data.require_binding(
                &active._connection,
                &admission::enrollment(&active._remote_statement)?,
                sequence,
                &commitment,
            )?;
            let remote = data.original().clone();
            remote.require_request_continuity(&active.last_remote)?;
            // Historical signed interval only: the Controller retires it after
            // its final send/post. Do not positively sample that retired grant.
            let mut statement = active._remote_statement.clone();
            statement.original = remote.clone();
            let receipt = sender
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_controller_sender_required"))?;
            let admitted = match active._sender.first_mut() {
                Some(super::ServingSender::Controller(receipt)) => receipt,
                _ => anyhow::bail!("protected_restore_controller_sender_required"),
            };
            receipt.bind_admitted(
                &statement,
                admitted,
                &active._remote_statement,
                stage,
                &mut acquisition,
            )?;
            bound = Some(statement.clone());
            acquisition = acquisition.narrow(5, Duration::from_nanos(remote.deadline_ns))?;
            active
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .meet_protected_received(&mut active._same, stage, &mut acquisition)?;
            let socket = active
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .protected_restore_observer(stage, &mut acquisition)?;
            let same = stage.capture_same_owner()?;
            let output = data.into_output();
            let connection = active._connection.clone();
            active._sequence = sequence;
            active.last_remote = remote;
            let guard = ProtectedRestoreActionGuard::from_shell_terminal(
                ProtectedRestoreShellTerminalGuard {
                    same,
                    original: original.take().ok_or_else(|| {
                        anyhow::anyhow!("protected_restore_shell_original_missing")
                    })?,
                    shell: shell.take().ok_or_else(|| {
                        anyhow::anyhow!("protected_restore_terminal_courier_missing")
                    })?,
                    connection,
                    sequence,
                    remote: statement,
                    socket,
                    receipt: sender.take().ok_or_else(|| {
                        anyhow::anyhow!("protected_restore_controller_sender_required")
                    })?,
                },
            );
            guard.attach_to_request(stage)?;
            Ok(output)
        }));
        let native = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
        let peer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            let existing = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match shell.as_deref_mut() {
                    Some(active) => check_shell(active, None, None, stage, &mut acquisition),
                    None => Ok(()),
                }
            }));
            let pending =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match &mut sender {
                    Some(receipt) => match &bound {
                        Some(statement) => {
                            receipt.check_protected_restore_bound(statement, &mut acquisition)
                        }
                        None => receipt.check_received(&mut acquisition),
                    },
                    None => Ok(()),
                }));
            match select_guard_check(existing, pending) {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => result,
            }
        }));
        let checked = select_guard_check(native, peer);
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            if let Some(active) = shell.as_deref_mut() {
                active.refuse();
            }
            if let Some(original) = &original {
                original.refuse();
            }
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(output)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(output)
                }
            },
        }
    }
}
