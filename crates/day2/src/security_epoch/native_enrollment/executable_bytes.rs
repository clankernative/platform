//! Full selected-byte admission, followed by actual retained-handle checks.
//! A private stamp joins held/current/final-path FDs. It grants no permission
//! and proves no immutable contents; ongoing integrity belongs to the trusted
//! enrolled services/node under the selected connection contract.

use super::issuer_costs::HashCosts;
use crate::security_epoch::native_clock::NativeAcquisition;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
};

#[derive(PartialEq, Eq)]
pub(super) struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn identity(file: &File) -> Result<Stamp> {
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.len() > 0 && m.len() <= 512 * 1024 * 1024,
        "native_enrollment_executable_bound"
    );
    Ok(Stamp {
        device: m.dev(),
        inode: m.ino(),
        length: m.len(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}

pub(super) fn hash(
    file: &mut File,
    acquisition: &mut NativeAcquisition,
    costs: &HashCosts,
) -> Result<Digest> {
    let _profile = crate::security_epoch::self_check_profile::enter(
        crate::security_epoch::self_check_profile::Category::ExecutableBytes,
    );
    costs.hash(|read_bytes| {
        acquisition.remaining()?;
        let before = identity(file)?;
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buffer = [0_u8; 65_536];
        let mut total = 0_u64;
        loop {
            acquisition.remaining()?;
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total += count as u64;
            *read_bytes = total;
            ensure!(
                total <= before.length,
                "native_enrollment_executable_changed"
            );
            hasher.update(&buffer[..count]);
        }
        ensure!(
            total == before.length && identity(file)? == before,
            "native_enrollment_executable_changed"
        );
        acquisition.remaining()?;
        format!("sha256:{}", crate::hex(hasher.finish().as_ref())).try_into()
    })
}

/// Admit one actual executable by reading all selected bytes, joining EVERY
/// retained descriptor before and after it. Only a genuine new process capture
/// calls this; later checks retain these actual descriptors and their stamp.
pub(super) fn admit(
    held: &[&File],
    current: &mut File,
    selected: &Digest,
    acquisition: &mut NativeAcquisition,
    costs: &HashCosts,
) -> Result<Stamp> {
    let result = (|| {
        acquisition.remaining()?;
        ensure!(
            (1..=5).contains(&held.len()),
            "native_enrollment_executable_owner_bound"
        );
        let before = identity(current)?;
        for file in held {
            ensure!(
                identity(file)? == before,
                "native_enrollment_executable_replaced"
            );
        }
        ensure!(
            hash(current, acquisition, costs)? == *selected,
            "native_enrollment_code_mismatch"
        );
        for file in held.iter().copied().chain([&*current]) {
            ensure!(
                identity(file)? == before,
                "native_enrollment_executable_changed"
            );
        }
        acquisition.remaining()?;
        Ok(before)
    })();
    if result.is_err() {
        acquisition.refuse();
    }
    result
}

/// Join actual held/current/final procfs executable descriptors to their original
/// admitted stamp, without another content read. The caller retains the actual
/// actor and original clock. Metadata is not an immutable content version or a
/// substitute for fresh authority; drift invisible to it is a trusted assumption.
pub(super) fn check_handles(
    held: &[&File],
    current: &File,
    final_path: &File,
    before: &Stamp,
    acquisition: &mut NativeAcquisition,
) -> Result<()> {
    let result = (|| {
        acquisition.remaining()?;
        ensure!(
            (1..=5).contains(&held.len()),
            "native_enrollment_executable_owner_bound"
        );
        for file in held.iter().copied().chain([current, final_path]) {
            ensure!(
                identity(file)? == *before,
                "native_enrollment_executable_changed"
            );
        }
        acquisition.remaining()?;
        Ok(())
    })();
    if result.is_err() {
        acquisition.refuse();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::native_enrollment::issuer_costs::{Outcome, Recorder, Subject};
    use std::{
        fs::{self, FileTimes},
        time::Duration,
    };

    fn acquisition(limit: Duration) -> NativeAcquisition {
        NativeAcquisition::fixture(
            Digest::new(b"byte-check-only"),
            std::process::id(),
            Duration::ZERO,
            limit,
        )
    }

    fn admit(
        held: &File,
        current: &mut File,
        selected: &Digest,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Stamp> {
        super::admit(
            &[held],
            current,
            selected,
            acquisition,
            &HashCosts::disabled(),
        )
    }

    fn check_handles(
        held: &File,
        current: &File,
        final_path: &File,
        before: &Stamp,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        super::check_handles(&[held], current, final_path, before, acquisition)
    }

    #[test]
    fn distinct_admissions_each_read_the_selected_bytes() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        let bytes = vec![23; 65_536 + 17];
        fs::write(&p, &bytes)?;
        let held = (0..5)
            .map(|_| File::open(&p))
            .collect::<std::io::Result<Vec<_>>>()?;
        let held = held.iter().collect::<Vec<_>>();
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        let mut output = Vec::new();
        {
            let mut recorder = Recorder::new(&mut output);
            let costs = recorder.connection();
            let hashes = costs.hashes(Subject::Requester);
            for _ in 0..2 {
                let stamp =
                    super::admit(&held, &mut current, &Digest::new(&bytes), &mut a, &hashes)?;
                assert_eq!(current.stream_position()?, bytes.len() as u64);
                super::check_handles(&held, &current, &File::open(&p)?, &stamp, &mut a)?;
            }
            recorder.emit(&costs, Outcome::Completed)?;
        }
        let output = String::from_utf8(output)?;
        let record: serde_json::Value =
            serde_json::from_str(output.strip_prefix("day2-native-issuer-cost ").unwrap())?;
        let rows = record["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], "hash_requester");
        assert_eq!(rows[0][1][0], 2);
        assert_eq!(rows[0][1][1], 2 * bytes.len());
        Ok(())
    }

    #[test]
    fn admitted_handle_checks_leave_every_executable_cursor_unchanged() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("selected");
        let bytes = vec![23; 65_536 + 17];
        fs::write(&path, &bytes)?;
        let mut held = File::open(&path)?;
        let mut current = File::open(&path)?;
        let mut original = acquisition(Duration::from_secs(5));
        let admitted = admit(&held, &mut current, &Digest::new(&bytes), &mut original)?;
        held.seek(SeekFrom::Start(2))?;
        current.seek(SeekFrom::Start(7))?;
        let mut final_path = File::open(&path)?;
        for _ in 0..2 {
            check_handles(&held, &current, &final_path, &admitted, &mut original)?;
            assert_eq!(held.stream_position()?, 2);
            assert_eq!(current.stream_position()?, 7);
            assert_eq!(final_path.stream_position()?, 0);
        }
        original.remaining()?;
        Ok(())
    }

    fn actual_process_capture_and_check_shape(source: &str) -> bool {
        use syn::visit::Visit;

        #[derive(Default)]
        struct Calls {
            admits: usize,
            handle_checks: usize,
            final_checks: usize,
        }

        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func {
                    let segments = path.path.segments.iter().collect::<Vec<_>>();
                    if segments.len() == 2 && segments[0].ident == "executable_bytes" {
                        self.admits += usize::from(segments[1].ident == "admit");
                        self.handle_checks += usize::from(segments[1].ident == "check_handles");
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }

            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                self.final_checks += usize::from(call.method == "check_identity");
                syn::visit::visit_expr_method_call(self, call);
            }
        }

        let source = syn::parse_file(source).unwrap();
        let mut capture = None;
        let mut check = None;
        for item in source.items {
            let syn::Item::Impl(implementation) = item else {
                continue;
            };
            if !matches!(&*implementation.self_ty, syn::Type::Path(path) if path.path.is_ident("MessageProcess"))
            {
                continue;
            }
            for item in implementation.items {
                let syn::ImplItem::Fn(function) = item else {
                    continue;
                };
                let mut calls = Calls::default();
                calls.visit_block(&function.block);
                if function.sig.ident == "observe" {
                    assert!(capture.replace(calls).is_none());
                } else if function.sig.ident == "check_same_actor" {
                    assert!(check.replace(calls).is_none());
                }
            }
        }
        matches!(
            capture,
            Some(Calls {
                admits: 1,
                handle_checks: 0,
                final_checks: 1
            })
        ) && matches!(
            check,
            Some(Calls {
                admits: 0,
                handle_checks: 2,
                final_checks: 0
            })
        )
    }

    #[test]
    fn actual_process_capture_admits_once_and_retained_checks_only_join_handles() {
        assert!(actual_process_capture_and_check_shape(include_str!(
            "process.rs"
        )));
    }

    #[test]
    fn actual_process_guard_rejects_skipped_admission_or_restored_full_checks() {
        let source = include_str!("process.rs");
        for (before, after) in [
            (
                "executable_bytes::admit(",
                "executable_bytes::metadata_only(",
            ),
            (
                "executable_bytes::check_handles(",
                "executable_bytes::admit(",
            ),
            (
                "executable_bytes::check_handles(",
                "executable_bytes::metadata_only(",
            ),
            (
                "owner.check_identity(acquisition, costs)?",
                "owner.skip_final_check(acquisition, costs)?",
            ),
        ] {
            let mutated = source.replacen(before, after, 1);
            assert_ne!(mutated, source);
            assert!(!actual_process_capture_and_check_shape(&mutated));
        }
    }

    #[test]
    fn every_retained_descriptor_must_join_before_and_after_the_read() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        let q = d.path().join("other");
        fs::write(&p, b"selected")?;
        fs::write(&q, b"selected")?;
        let held = (0..5)
            .map(|_| File::open(&p))
            .collect::<std::io::Result<Vec<_>>>()?;
        let other = File::open(&q)?;
        for index in 0..5 {
            let mut current = File::open(&p)?;
            let mut owners = held.iter().collect::<Vec<_>>();
            owners[index] = &other;
            let mut a = acquisition(Duration::from_secs(5));
            assert!(
                super::admit(
                    &owners,
                    &mut current,
                    &Digest::new(b"selected"),
                    &mut a,
                    &HashCosts::disabled(),
                )
                .is_err()
            );
            assert!(a.remaining().is_err());

            let mut a = acquisition(Duration::from_secs(5));
            let stamp = admit(&held[0], &mut current, &Digest::new(b"selected"), &mut a)?;
            assert!(
                super::check_handles(&owners, &current, &File::open(&p)?, &stamp, &mut a).is_err()
            );
            assert!(a.remaining().is_err());
        }
        Ok(())
    }

    #[test]
    fn complete_fresh_bytes_and_all_three_descriptors_must_match() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        let bytes = vec![23; 65_536 + 17];
        fs::write(&p, &bytes)?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        let stamp = admit(&held, &mut current, &Digest::new(&bytes), &mut a)?;
        assert_eq!(current.stream_position()?, bytes.len() as u64);
        check_handles(&held, &current, &File::open(&p)?, &stamp, &mut a)?;
        a.remaining()?;
        Ok(())
    }

    #[test]
    fn identical_bytes_in_a_different_inode_are_not_the_retained_executable() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("held");
        let q = d.path().join("other");
        fs::write(&p, b"selected")?;
        fs::write(&q, b"selected")?;
        let held = File::open(&p)?;
        let mut current = File::open(&q)?;
        let mut a = acquisition(Duration::from_secs(5));
        assert!(admit(&held, &mut current, &Digest::new(b"selected"), &mut a).is_err());
        let mut restored = File::open(&p)?;
        assert!(admit(&held, &mut restored, &Digest::new(b"selected"), &mut a).is_err());
        Ok(())
    }

    #[test]
    fn a_new_admission_rejects_same_length_wrong_bytes() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        fs::write(&p, b"selected")?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        admit(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        fs::write(&p, b"changed!")?;
        assert!(admit(&held, &mut current, &Digest::new(b"selected"), &mut a).is_err());
        Ok(())
    }

    #[test]
    fn distinct_ctime_after_mtime_restore_does_not_settle_the_byte_check() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        fs::write(&p, b"selected")?;
        let modified = fs::metadata(&p)?.modified()?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        let stamp = admit(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        // The assertion is conditional on an OBSERVED distinct stamp, not on
        // every rapid write advancing ctime. Coarse timestamp resolution is
        // allowed; bound fixture preparation without skipping the oracle.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            fs::write(&p, b"changed!")?;
            File::options()
                .write(true)
                .open(&p)?
                .set_times(FileTimes::new().set_modified(modified))?;
            if identity(&current)?.changed != stamp.changed {
                break;
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "fixture requires an observed distinguishable ctime"
            );
            std::thread::yield_now();
        }
        assert_eq!(fs::metadata(&p)?.modified()?, modified);
        assert!(check_handles(&held, &current, &File::open(&p)?, &stamp, &mut a).is_err());
        assert!(a.remaining().is_err());
        Ok(())
    }

    #[test]
    fn final_path_replacement_is_rejected_even_when_earlier_fds_and_bytes_match() -> Result<()> {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir()?;
        let p = d.path().join("exe");
        let q = d.path().join("new");
        let original = d.path().join("original");
        fs::write(&original, b"selected")?;
        fs::write(&q, b"selected")?;
        symlink(&original, &p)?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        let stamp = admit(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        fs::remove_file(&p)?;
        symlink(&q, &p)?;
        assert!(identity(&held)? == stamp && identity(&current)? == stamp);
        assert!(check_handles(&held, &current, &File::open(&p)?, &stamp, &mut a).is_err());
        Ok(())
    }

    #[test]
    fn expired_budget_cannot_finish_an_existing_byte_check() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        fs::write(&p, b"selected")?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        let stamp = admit(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        let mut expired = acquisition(Duration::ZERO);
        assert!(check_handles(&held, &current, &File::open(&p)?, &stamp, &mut expired).is_err());
        assert!(expired.remaining().is_err());
        Ok(())
    }
}
