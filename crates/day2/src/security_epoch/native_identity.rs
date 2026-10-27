//! Actual self-process executable observation under the original acquisition
//! interval. This does not bind a process to a Pod or qualify a runtime profile.
//! Authentication and first-holder/file producers remain separate prerequisites.

use super::native_clock::NativeAcquisition;
use super::native_enrollment::issuer_costs::HashCosts;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{marker::PhantomData, rc::Rc};

/// Owns the originally observed executable descriptor on Linux. Historical
/// process IDs or code digests cannot reconstruct this owning observation.
pub(crate) struct NativeProcessObservation {
    process: u32,
    code: Digest,
    acquisition: Digest,
    #[cfg(target_os = "linux")]
    executable: std::fs::File,
    #[cfg(target_os = "linux")]
    identity: (u64, u64, u64, i64, i64),
    valid: bool,
    local: PhantomData<Rc<()>>,
}

impl NativeProcessObservation {
    pub(super) fn acquire(
        expected_executable: &Digest,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<Self> {
        let result = (|| {
            #[cfg(target_os = "linux")]
            {
                use ring::digest::{Context, SHA256};
                use std::{fs::File, io::Read};
                let origin = acquisition.identity_domain()?;
                let process = std::process::id();
                let mut executable = File::open("/proc/self/exe")?;
                let identity = file_identity(&executable)?;
                ensure!(
                    identity.2 > 0 && identity.2 <= 512 * 1024 * 1024,
                    "epoch_native_executable_bound"
                );
                let mut work = crate::security_epoch::admission_work::begin(
                    crate::security_epoch::admission_work::Work::ExecutableSha256,
                );
                let code: Result<Digest> = costs.hash(|read_bytes| {
                    let _profile = super::self_check_profile::enter(
                        super::self_check_profile::Category::SelfExecutableBytes,
                    );
                    let mut hash = Context::new(&SHA256);
                    let mut buffer = [0_u8; 65_536];
                    let mut size = 0_u64;
                    loop {
                        acquisition.remaining()?;
                        let count = executable.read(&mut buffer)?;
                        work.bytes(
                            crate::security_epoch::admission_work::Bytes::ShaRead,
                            count as u64,
                        );
                        if count == 0 {
                            break;
                        }
                        size = size
                            .checked_add(count as u64)
                            .ok_or_else(|| anyhow::anyhow!("epoch_native_executable_bound"))?;
                        *read_bytes = size;
                        ensure!(size <= identity.2, "epoch_native_executable_changed");
                        hash.update(&buffer[..count]);
                    }
                    ensure!(
                        size == identity.2 && file_identity(&executable)? == identity,
                        "epoch_native_executable_changed"
                    );
                    format!("sha256:{}", crate::hex(hash.finish().as_ref())).try_into()
                });
                work.finish(code.is_ok());
                let code = code?;
                ensure!(
                    code == *expected_executable,
                    "epoch_native_executable_pin_mismatch"
                );
                acquisition.remaining()?;
                let mut observed = Self {
                    process,
                    code,
                    acquisition: origin,
                    executable,
                    identity,
                    valid: true,
                    local: PhantomData,
                };
                observed.check(acquisition)?;
                Ok(observed)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (expected_executable, costs);
                anyhow::bail!("epoch_native_process_platform_unsupported")
            }
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(super) fn code(&self) -> &Digest {
        &self.code
    }

    pub(super) fn check(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "epoch_native_process_observation_refused");
            #[cfg(target_os = "linux")]
            {
                ensure!(
                    acquisition.identity_domain()? == self.acquisition,
                    "epoch_native_acquisition_changed"
                );
                ensure!(
                    std::process::id() == self.process,
                    "epoch_native_process_changed"
                );
                ensure!(
                    file_identity(&self.executable)? == self.identity,
                    "epoch_native_executable_changed"
                );
                let current = std::fs::File::open("/proc/self/exe")?;
                ensure!(
                    file_identity(&current)? == self.identity,
                    "epoch_native_executable_replaced"
                );
                acquisition.remaining()?;
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("epoch_native_process_platform_unsupported")
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }
}

#[cfg(target_os = "linux")]
fn file_identity(file: &std::fs::File) -> Result<(u64, u64, u64, i64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "epoch_native_executable_not_regular");
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_process_observation_refuses_the_whole_acquisition() {
        let mut acquisition = NativeAcquisition::fixture(
            Digest::new(b"clock"),
            std::process::id(),
            std::time::Duration::from_secs(100),
            std::time::Duration::from_secs(5),
        );
        assert!(
            NativeProcessObservation::acquire(
                &Digest::new(b"code"),
                &mut acquisition,
                &HashCosts::disabled()
            )
            .is_err()
        );
        assert!(acquisition.remaining().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_admitted_self_handles_check_two_fresh_requests_without_another_scan() {
        let code = Digest::new(&std::fs::read("/proc/self/exe").unwrap());
        let mut admission = NativeAcquisition::begin(5).unwrap();
        let mut process =
            NativeProcessObservation::acquire(&code, &mut admission, &HashCosts::disabled())
                .unwrap();
        let mut namespace =
            super::super::NativeNamespaceObservation::acquire(&mut admission).unwrap();
        let admitted_identity = admission.identity_domain().unwrap();
        let mut connection = admission.into_connection_clock().unwrap();
        let mut previous_domain = None;
        for _ in 0..2 {
            let mut request = connection.begin_current().unwrap();
            let domain = request.sample().unwrap().domain;
            assert!(
                previous_domain
                    .as_ref()
                    .is_none_or(|prior| prior != &domain)
            );
            assert_eq!(request.identity_domain().unwrap(), admitted_identity);
            let (checked, profile) = super::super::self_check_profile::sample_current(|| {
                process.check(&mut request)?;
                namespace.check(&mut request)?;
                request.remaining().map(|_| ())
            });
            checked.unwrap();
            assert_eq!(profile.unwrap().profile.rows[9].0, Some(0));
            previous_domain = Some(domain);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_retained_self_anchors_refuse_an_unrelated_live_acquisition() {
        let code = Digest::new(&std::fs::read("/proc/self/exe").unwrap());
        for check_namespace in [false, true] {
            let mut admission = NativeAcquisition::begin(5).unwrap();
            let mut process =
                NativeProcessObservation::acquire(&code, &mut admission, &HashCosts::disabled())
                    .unwrap();
            let mut namespace =
                super::super::NativeNamespaceObservation::acquire(&mut admission).unwrap();
            let mut connection = admission.into_connection_clock().unwrap();
            let mut request = connection.begin_current().unwrap();
            let mut foreign = NativeAcquisition::begin(5).unwrap();
            let refused = if check_namespace {
                namespace.check(&mut foreign)
            } else {
                process.check(&mut foreign)
            };
            assert!(refused.is_err());
            assert!(foreign.remaining().is_err());
            let restored = if check_namespace {
                namespace.check(&mut request)
            } else {
                process.check(&mut request)
            };
            assert!(restored.is_err());
            assert!(request.remaining().is_err());
            assert!(connection.begin_current().is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_observer_retains_actual_self_executable_and_refuses_wrong_pin() {
        let code = Digest::new(&std::fs::read("/proc/self/exe").unwrap());
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let (observed, profile) = super::super::self_check_profile::sample_current(|| {
            NativeProcessObservation::acquire(&code, &mut acquisition, &HashCosts::disabled())
        });
        let mut observed = observed.unwrap();
        assert_eq!(profile.unwrap().profile.rows[9].0, Some(1));
        assert_eq!(observed.code(), &code);
        observed.check(&mut acquisition).unwrap();
        let mut wrong = NativeAcquisition::begin(5).unwrap();
        let (refused, profile) = super::super::self_check_profile::sample_current(|| {
            NativeProcessObservation::acquire(
                &Digest::new(b"other-code"),
                &mut wrong,
                &HashCosts::disabled(),
            )
        });
        assert!(refused.is_err());
        assert_eq!(profile.unwrap().profile.rows[9].0, Some(1));
        assert!(wrong.remaining().is_err());
    }
}
