//! Fresh selected bytes for one process check, never a cached executable grant.
//! A stamp joins held/current/final-path FDs; it is DATA, not immutability or an
//! atomic snapshot. Code-replacing actors remain in the qualified native TCB.

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

/// Hash one freshly opened descriptor once, joining EVERY retained descriptor
/// before and after it. The caller joins these to the same actual live actor.
/// Each invocation rereads all bytes; no cross-check/stage cache.
pub(super) fn begin_check(
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
            "native_enrollment_executable_changed"
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

/// The caller reopens the actual procfs executable path after its other native
/// checks. ctime strengthens mutation detection but is not a content version.
pub(super) fn finish_check(
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

    fn begin_check(
        held: &File,
        current: &mut File,
        selected: &Digest,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Stamp> {
        super::begin_check(
            &[held],
            current,
            selected,
            acquisition,
            &HashCosts::disabled(),
        )
    }

    fn finish_check(
        held: &File,
        current: &File,
        final_path: &File,
        before: &Stamp,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        super::finish_check(&[held], current, final_path, before, acquisition)
    }

    #[test]
    fn multiple_retained_descriptors_share_one_fresh_read_without_a_cache() -> Result<()> {
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
                    super::begin_check(&held, &mut current, &Digest::new(&bytes), &mut a, &hashes)?;
                assert_eq!(current.stream_position()?, bytes.len() as u64);
                super::finish_check(&held, &current, &File::open(&p)?, &stamp, &mut a)?;
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
                super::begin_check(
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
            let stamp = begin_check(&held[0], &mut current, &Digest::new(b"selected"), &mut a)?;
            assert!(
                super::finish_check(&owners, &current, &File::open(&p)?, &stamp, &mut a).is_err()
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
        let stamp = begin_check(&held, &mut current, &Digest::new(&bytes), &mut a)?;
        assert_eq!(current.stream_position()?, bytes.len() as u64);
        finish_check(&held, &current, &File::open(&p)?, &stamp, &mut a)?;
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
        assert!(begin_check(&held, &mut current, &Digest::new(b"selected"), &mut a).is_err());
        let mut restored = File::open(&p)?;
        assert!(begin_check(&held, &mut restored, &Digest::new(b"selected"), &mut a).is_err());
        Ok(())
    }

    #[test]
    fn same_length_wrong_bytes_are_rehashed_on_every_check() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        fs::write(&p, b"selected")?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        begin_check(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        fs::write(&p, b"changed!")?;
        assert!(begin_check(&held, &mut current, &Digest::new(b"selected"), &mut a).is_err());
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
        let stamp = begin_check(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
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
        assert!(finish_check(&held, &current, &File::open(&p)?, &stamp, &mut a).is_err());
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
        let stamp = begin_check(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        fs::remove_file(&p)?;
        symlink(&q, &p)?;
        assert!(identity(&held)? == stamp && identity(&current)? == stamp);
        assert!(finish_check(&held, &current, &File::open(&p)?, &stamp, &mut a).is_err());
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
        let stamp = begin_check(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        let mut expired = acquisition(Duration::ZERO);
        assert!(finish_check(&held, &current, &File::open(&p)?, &stamp, &mut expired).is_err());
        assert!(expired.remaining().is_err());
        Ok(())
    }
}
