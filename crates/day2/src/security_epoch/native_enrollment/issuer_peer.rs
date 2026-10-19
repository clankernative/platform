//! An actual message handle joined to the root-enrolled issuer. Clients do not
//! need ptrace access to the privileged issuer's executable/namespace objects.
//! Those observations belong to its trusted provisioner and current grant code.
//! A certificate alone never constructs this handle or an enrolled role owner.

use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    policy::EnrollmentPolicy, process, protocol::IssuerCertificate,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use rustix::net::{KernelPidVisibility, ReceivedPidfdPacket};
use std::{fs::File, marker::PhantomData, rc::Rc, thread::ThreadId};

pub(super) struct IssuerReceipt {
    pidfd: File,
    kernel_process: u32,
    certificate: Option<Digest>,
    local_process: u32,
    thread: ThreadId,
    refused: bool,
    local: PhantomData<Rc<()>>,
}

// This private native handle is checked in production builds too. A conditional
// convenience impl must not make its ownership transferable or serializable.
const _: () = {
    macro_rules! absent {
        ($trait:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $trait> Ambiguous<u8> for T {}
            let _ = <IssuerReceipt as Ambiguous<_>>::check;
        }};
    }
    absent!(Clone);
    absent!(Send);
    absent!(Sync);
    absent!(serde::Serialize);
    absent!(serde::Deserialize<'static>);
};

impl IssuerReceipt {
    /// Only the private packet receiver calls this with its original owned
    /// SCM_PIDFD. Neither a caller PID nor a reopened descriptor is accepted.
    pub(super) fn receive(
        packet: ReceivedPidfdPacket,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let kernel_process = match packet.credentials.process {
            KernelPidVisibility::Visible(pid) => pid.get(),
            KernelPidVisibility::NotVisible => {
                acquisition.refuse();
                anyhow::bail!("native_enrollment_issuer_pid_not_visible")
            }
        };
        let pidfd = File::from(packet.process);
        process::live(&pidfd, acquisition)?;
        Ok(Self {
            pidfd,
            kernel_process,
            certificate: None,
            local_process: std::process::id(),
            thread: std::thread::current().id(),
            refused: false,
            local: PhantomData,
        })
    }

    /// Partial provenance only: the owning exchange must additionally verify
    /// the fresh request/challenge signature, exact self/role/runtime binding,
    /// common namespace domain and both original deadlines before admission.
    pub(super) fn bind(
        &mut self,
        certificate: &IssuerCertificate,
        policy: &EnrollmentPolicy,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check_local()?;
            process::live(&self.pidfd, acquisition)?;
            certificate.verify(policy)?;
            ensure!(
                self.kernel_process == certificate.data.process.process,
                "native_enrollment_issuer_sender_changed"
            );
            let digest = certificate.digest()?;
            ensure!(
                self.certificate.as_ref().is_none_or(|old| old == &digest),
                "native_enrollment_issuer_generation_changed"
            );
            self.certificate = Some(digest);
            process::live(&self.pidfd, acquisition)
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }

    pub(super) fn check_live(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        let result = (|| {
            self.check_local()?;
            ensure!(
                self.certificate.is_some(),
                "native_enrollment_issuer_not_bound"
            );
            process::live(&self.pidfd, acquisition)
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }

    fn check_local(&self) -> Result<()> {
        ensure!(
            !self.refused
                && self.local_process == std::process::id()
                && self.thread == std::thread::current().id(),
            "native_enrollment_issuer_receipt_owner_changed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
