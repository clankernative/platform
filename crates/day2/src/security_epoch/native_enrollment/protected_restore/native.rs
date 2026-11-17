//! Initial protected admission using the actual local stage and every
//! message's original kernel sender. The retained result is connection
//! identity, not a Current or an unexpired permission across human idle.

use super::{ProtectedRestoreListener, ProtectedRestorePeer, ProtectedRestoreShell};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::protected_restore::admission::{
    Body, ConnectionData,
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    channel::{Channel, ServingSender},
    issuer_costs::HashCosts,
    protocol,
    serving_peer_wire::Statement,
};
use crate::security_epoch::{
    native_clock::NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, SameEnrolledOwner},
};
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::ensure;
#[cfg(target_os = "linux")]
use day2_capabilities::Digest;
#[cfg(target_os = "linux")]
use std::{cell::Cell, time::Duration};
use std::{marker::PhantomData, rc::Rc};

/// Owns every successfully returned raw receiver handle before any fallible
/// statement/signature validation. Raw decode failures refuse before a peer
/// exists. This cannot be constructed from parsed statement DATA.
struct AdmissionAttempt {
    #[cfg(target_os = "linux")]
    channel: Option<Channel>,
    #[cfg(target_os = "linux")]
    senders: Vec<ServingSender>,
    #[cfg(target_os = "linux")]
    remote: Option<Statement>,
    _local: PhantomData<Rc<()>>,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <AdmissionAttempt as Ambiguous<_>>::check;
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

impl AdmissionAttempt {
    fn check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            stage.refuse_serving();
            acquisition.refuse();
            anyhow::bail!(super::UNAVAILABLE);
        }
        #[cfg(target_os = "linux")]
        {
            // Evaluate every actual retained sender and the final local post even
            // when an earlier observation failed. Keep the first result selected.
            let mut checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match self
                .channel
                .as_mut()
            {
                Some(channel) => channel.check_protected_open(stage, acquisition),
                None => stage.check_serving_acquisition(acquisition),
            }));
            for sender in &mut self.senders {
                let observed =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                        match sender {
                            ServingSender::Shell(process) => {
                                process.check_identity(acquisition, &HashCosts::disabled())?;
                                if let Some(remote) = &self.remote {
                                    stage.check_serving_shell_statement(
                                        remote,
                                        process.data(),
                                        acquisition,
                                    )?;
                                }
                            }
                            ServingSender::Controller(receipt) => {
                                receipt.check_received(acquisition)?;
                                if let Some(remote) = &self.remote {
                                    receipt.bind(remote, stage, acquisition)?;
                                }
                            }
                        }
                        Ok(())
                    }));
                checked = first_observation(checked, observed);
            }
            let local = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                stage.check_serving_acquisition(acquisition)
            }));
            match first_observation(checked, local) {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => result,
            }
        }
    }

    /// Called only after the fixed caller verified the actual native sender,
    /// signature, common clock and this exact connection/receive step. The
    /// narrowed child is joined into the SAME saved parent before progressing.
    fn meet_received(
        &mut self,
        _same: &mut SameEnrolledOwner,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            stage.refuse_serving();
            acquisition.refuse();
            anyhow::bail!(super::UNAVAILABLE);
        }
        #[cfg(target_os = "linux")]
        {
            let remote = self
                .remote
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_admission_statement_missing"))?;
            *acquisition =
                acquisition.narrow(5, Duration::from_nanos(remote.original.deadline_ns))?;
            self.channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .meet_protected_received(_same, stage, acquisition)
        }
    }

    fn refuse(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.channel = None;
        }
    }
}

/// Both observations have already run. Selecting the first failure or panic
/// cannot skip the later native checks, or turn either result into permission.
#[cfg(target_os = "linux")]
fn first_observation(
    first: std::thread::Result<Result<()>>,
    next: std::thread::Result<Result<()>>,
) -> std::thread::Result<Result<()>> {
    match first {
        Ok(Ok(())) => next,
        failed => failed,
    }
}

/// The outer fixed accept already spent its one cold issuer attempt. This
/// consumes the only listening resource into an accepted channel and retains
/// all per-message handles through the independent admission post.
pub(super) fn accept(
    listener: &mut ProtectedRestoreListener,
    stage: &mut EnrolledRoleStage<'_>,
) -> Result<ProtectedRestorePeer> {
    #[cfg(not(target_os = "linux"))]
    {
        listener.refuse();
        stage.refuse_serving();
        anyhow::bail!(super::UNAVAILABLE);
    }
    #[cfg(target_os = "linux")]
    {
        let mut listener = listener
            .listener
            .take()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_listener_closed"))?;
        let mut same = stage.capture_same_owner()?;
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        let mut attempt = AdmissionAttempt {
            channel: None,
            senders: Vec::new(),
            remote: None,
            _local: PhantomData,
        };
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<(Statement, Digest)> {
                attempt.channel = Some(listener.accept(stage, &mut acquisition)?);
                let local = stage.protected_restore_statement()?;
                let nonce = protocol::nonce("protected-restore-controller")?;
                attempt.check(stage, &mut acquisition)?;
                attempt
                    .channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                    .send_protected_admission(
                        Body::ControllerHello {
                            controller: Box::new(local.clone()),
                            nonce: nonce.clone(),
                        },
                        stage,
                        &mut acquisition,
                    )?;
                attempt.check(stage, &mut acquisition)?;

                let (proof, sender) = attempt
                    .channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                    .receive_protected_admission(stage, &mut acquisition)?;
                attempt.senders.push(sender);
                let (remote, connection) = match &proof.body {
                    Body::ShellProof { shell, connection } => {
                        (shell.as_ref().clone(), connection.clone())
                    }
                    _ => anyhow::bail!("protected_restore_admission_proof_order"),
                };
                attempt.remote = Some(remote.clone());
                // Full initial native validation includes actual kernel process/code,
                // issuer/runtime selection and common BOOTTIME before any scalar cap.
                attempt.check(stage, &mut acquisition)?;
                proof.verify_data(&remote)?;
                connection.require_initial(&remote, &local, &nonce)?;
                proof.require_proof(&remote, &connection)?;
                attempt.meet_received(&mut same, stage, &mut acquisition)?;

                attempt.check(stage, &mut acquisition)?;
                attempt
                    .channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                    .send_protected_admission(
                        Body::ControllerAccept {
                            connection: connection.clone(),
                        },
                        stage,
                        &mut acquisition,
                    )?;
                attempt.check(stage, &mut acquisition)?;
                let (confirm, sender) = attempt
                    .channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                    .receive_protected_admission(stage, &mut acquisition)?;
                attempt.senders.push(sender);
                attempt.check(stage, &mut acquisition)?;
                confirm.verify_data(&remote)?;
                confirm.require_confirm(&connection)?;
                attempt.meet_received(&mut same, stage, &mut acquisition)?;
                Ok((local, connection.digest()?))
            },
        ));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            attempt.check(stage, &mut acquisition)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            attempt.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        let (local, connection) = match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(value)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    value
                }
            },
        };
        ensure!(
            attempt.senders.len() == 2,
            "protected_restore_admission_sender_count"
        );
        let remote = attempt
            .remote
            .take()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_admission_statement_missing"))?;
        Ok(ProtectedRestorePeer {
            _same: same,
            channel: attempt.channel.take(),
            _sender: attempt.senders,
            _local_statement: local,
            last_remote: remote.original.clone(),
            _remote_statement: remote,
            _connection: connection,
            _sequence: 0,
            refused: Rc::new(Cell::new(false)),
            _local: PhantomData,
        })
    }
}

/// The actual Shell HTTP request lends its stage. This cannot start a new
/// original, use a supplied PID/key or retain that Current across human idle.
pub(super) fn connect(stage: &mut EnrolledRoleStage<'_>) -> Result<ProtectedRestoreShell> {
    #[cfg(not(target_os = "linux"))]
    {
        stage.refuse_serving();
        anyhow::bail!(super::UNAVAILABLE);
    }
    #[cfg(target_os = "linux")]
    {
        let mut same = stage.capture_same_owner()?;
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        let mut attempt = AdmissionAttempt {
            channel: None,
            senders: Vec::new(),
            remote: None,
            _local: PhantomData,
        };
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<(Statement, Digest)> {
                attempt.channel =
                    Some(Channel::connect_protected_restore(stage, &mut acquisition)?);
                let (hello, sender) = attempt
                    .channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                    .receive_protected_admission(stage, &mut acquisition)?;
                attempt.senders.push(sender);
                let (remote, controller_nonce) = match &hello.body {
                    Body::ControllerHello { controller, nonce } => {
                        (controller.as_ref().clone(), nonce.clone())
                    }
                    _ => anyhow::bail!("protected_restore_admission_hello_order"),
                };
                attempt.remote = Some(remote.clone());
                attempt.check(stage, &mut acquisition)?;
                hello.verify_data(&remote)?;
                hello.require_hello(&remote, &controller_nonce)?;
                attempt.meet_received(&mut same, stage, &mut acquisition)?;

                // Capture the FIRST Shell statement after the authenticated common cap
                // has reached the saved HTTP request. Later reductions cannot replace
                // this initial enrollment/connection commitment.
                let local = stage.protected_restore_statement()?;
                let nonce = protocol::nonce("protected-restore-shell")?;
                let connection = ConnectionData::bind(&local, &remote, nonce, controller_nonce)?;
                attempt.check(stage, &mut acquisition)?;
                attempt
                    .channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                    .send_protected_admission(
                        Body::ShellProof {
                            shell: Box::new(local.clone()),
                            connection: connection.clone(),
                        },
                        stage,
                        &mut acquisition,
                    )?;
                attempt.check(stage, &mut acquisition)?;
                let (accept, sender) = attempt
                    .channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                    .receive_protected_admission(stage, &mut acquisition)?;
                attempt.senders.push(sender);
                attempt.check(stage, &mut acquisition)?;
                accept.verify_data(&remote)?;
                accept.require_accept(&connection)?;
                attempt.meet_received(&mut same, stage, &mut acquisition)?;

                attempt.check(stage, &mut acquisition)?;
                attempt
                    .channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                    .send_protected_admission(
                        Body::ShellConfirm {
                            connection: connection.clone(),
                        },
                        stage,
                        &mut acquisition,
                    )?;
                Ok((local, connection.digest()?))
            },
        ));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            attempt.check(stage, &mut acquisition)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            attempt.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        let (local, connection) = match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(value)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    value
                }
            },
        };
        ensure!(
            attempt.senders.len() == 2,
            "protected_restore_admission_sender_count"
        );
        let remote = attempt
            .remote
            .take()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_admission_statement_missing"))?;
        Ok(ProtectedRestoreShell {
            _same: same,
            channel: attempt.channel.take(),
            _sender: attempt.senders,
            _local_statement: local,
            last_remote: remote.original.clone(),
            _remote_statement: remote,
            _connection: connection,
            _sequence: 0,
            refused: Rc::new(Cell::new(false)),
            _local: PhantomData,
        })
    }
}
