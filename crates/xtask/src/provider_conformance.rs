//! Explicit live-probe CLI. Roc owns probe order; no ambient cloud identity is used.
use super::*;
use day2_control::provider_conformance::{FileToken, LiveProbe, Profile, Session};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    num::NonZeroU64,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_RESERVATION_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureIdentity {
    project_number: NonZeroU64,
    secret: String,
    run_marker: String,
    versions: [NonZeroU64; 2],
}

impl From<&Profile> for FixtureIdentity {
    fn from(profile: &Profile) -> Self {
        let mut versions = [profile.lost_ack_version, profile.late_version];
        versions.sort();
        Self {
            project_number: profile.project_number,
            secret: profile.secret.clone(),
            run_marker: profile.run_marker.clone(),
            versions,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    format: u32,
    fixture: FixtureIdentity,
    evidence: PathBuf,
}

fn directory(path: &Path, private: bool) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && (!private || metadata.permissions().mode() & 0o077 == 0),
        "non-symlink {}directory required: {}",
        if private { "private " } else { "" },
        path.display()
    );
    path.canonicalize().context("canonical directory identity")
}

fn reservation_path(registry: &Path, fixture: &FixtureIdentity) -> Result<PathBuf> {
    let digest = day2_control::Digest::of(&("day2-provider-conformance-fixture-v1", fixture))?;
    let filename = digest
        .as_str()
        .strip_prefix("sha256:")
        .context("fixture digest")?;
    Ok(registry.join(format!("{filename}.json")))
}

/// Workspace-local accident prevention, not a provider lock or another workflow
/// engine. A reservation survives expiry and uncertain dispatch until reviewed.
fn reserve_fixture(
    root: &Path,
    fixture: &FixtureIdentity,
    evidence: &Path,
    resume: bool,
) -> Result<()> {
    let root = directory(root, false)?;
    let artifacts = directory(&root.join("artifacts"), false)?;
    let registry = artifacts.join("provider-conformance-runs");
    if !resume {
        match fs::DirBuilder::new().mode(0o700).create(&registry) {
            Ok(()) => File::open(&artifacts)?.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("create private fixture registry"),
        }
    }
    let registry = directory(&registry, true)?;
    let evidence = directory(evidence, true)?;
    let path = reservation_path(&registry, fixture)?;
    if resume {
        let metadata =
            fs::symlink_metadata(&path).context("missing original fixture reservation")?;
        ensure!(
            metadata.is_file()
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.len() <= MAX_RESERVATION_BYTES,
            "private bounded non-symlink fixture reservation required"
        );
        let file = File::open(&path)?;
        let opened = file.metadata()?;
        ensure!(
            opened.dev() == metadata.dev() && opened.ino() == metadata.ino(),
            "fixture reservation changed while opening"
        );
        let mut bytes = Vec::new();
        file.take(MAX_RESERVATION_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_RESERVATION_BYTES as usize,
            "fixture reservation byte budget"
        );
        let reservation: Reservation = serde_json::from_slice(&bytes)?;
        ensure!(
            reservation.format == 1
                && reservation.fixture == *fixture
                && reservation.evidence == evidence,
            "fixture reservation differs; resume requires its original evidence directory"
        );
    } else {
        let reservation = Reservation {
            format: 1,
            fixture: fixture.clone(),
            evidence,
        };
        let bytes = serde_json::to_vec_pretty(&reservation)?;
        ensure!(
            bytes.len() <= MAX_RESERVATION_BYTES as usize,
            "fixture reservation byte budget"
        );
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)
            .context("fixture already reserved or unavailable; use resume with its original evidence directory")?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(registry)?.sync_all()?;
    }
    Ok(())
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn execute(
    root: &Path,
    profile: &Path,
    token: &Path,
    evidence: &Path,
    resume: bool,
) -> Result<()> {
    let profile = Profile::load(profile, now()?)?;
    let fixture = FixtureIdentity::from(&profile);
    let credentials = Arc::new(FileToken::load(token)?);
    let probe = LiveProbe::new(&profile, credentials)?;
    // Admission and private-directory checks happen before building or executing
    // the recipe. Constructing the client performs no provider calls.
    let mut session = Session::open(evidence, profile, probe, now()?, resume)?;
    // Reserve only after the private journal exists, but before compilation or
    // provider I/O. Failures retain both records; the next attempt must resume.
    reserve_fixture(root, &fixture, evidence, resume)?;
    let runner = workflows::build(root)?;
    let result = day2::automation::run(&runner, &["provider-conformance"], |request| {
        session.effect(&request, now()?)
    });
    println!("Provider observation journal: {}", evidence.display());
    result?;
    let report = session.report()?;
    ensure!(
        report["provider_qualified"] == false,
        "unexpected provider qualification claim"
    );
    println!("Configured provider observations complete; review missing/inconclusive checks.");
    println!("Review receipt.json for unproven guarantees and retained cleanup obligations.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Result<(tempfile::TempDir, FixtureIdentity, PathBuf)> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("artifacts"))?;
        let evidence = root.path().join("evidence");
        fs::DirBuilder::new().mode(0o700).create(&evidence)?;
        let fixture = FixtureIdentity {
            project_number: NonZeroU64::new(12345).unwrap(),
            secret: "day2-conformance-fixture".into(),
            run_marker: "fixture-run".into(),
            versions: [NonZeroU64::new(1).unwrap(), NonZeroU64::new(2).unwrap()],
        };
        Ok((root, fixture, evidence))
    }

    #[test]
    fn fixture_reservation_is_private_create_only_and_resumes_only_its_directory() -> Result<()> {
        let (root, fixture, evidence) = setup()?;
        assert!(reserve_fixture(root.path(), &fixture, &evidence, true).is_err());
        reserve_fixture(root.path(), &fixture, &evidence, false)?;
        reserve_fixture(root.path(), &fixture, &evidence, true)?;
        assert!(reserve_fixture(root.path(), &fixture, &evidence, false).is_err());
        let other = root.path().join("another-evidence");
        fs::DirBuilder::new().mode(0o700).create(&other)?;
        assert!(reserve_fixture(root.path(), &fixture, &other, false).is_err());
        assert!(reserve_fixture(root.path(), &fixture, &other, true).is_err());
        let registry = root.path().join("artifacts/provider-conformance-runs");
        assert_eq!(fs::metadata(&registry)?.permissions().mode() & 0o777, 0o700);
        let path = reservation_path(&registry, &fixture)?;
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        reserve_fixture(root.path(), &fixture, &evidence, true)?;
        Ok(())
    }

    #[test]
    fn fixture_identity_ignores_expiration_and_probe_version_order() -> Result<()> {
        let profile: Profile = serde_json::from_value(serde_json::json!({
            "format":1,"installation":"exampleco","environment":"sandbox",
            "project_number":12345,"secret":"day2-conformance-fixture","run_marker":"fixture-run",
            "aliases":["app_a","app_b"],"lost_ack_version":1,"late_version":2,
            "expires_at_unix":1000,"gke":null
        }))?;
        let expected = FixtureIdentity::from(&profile);
        let mut changed = profile.clone();
        changed.expires_at_unix = 2000;
        std::mem::swap(&mut changed.lost_ack_version, &mut changed.late_version);
        assert_eq!(FixtureIdentity::from(&changed), expected);
        changed.run_marker = "another-explicit-approval".into();
        assert_ne!(FixtureIdentity::from(&changed), expected);
        Ok(())
    }

    #[test]
    fn competing_fresh_directories_cannot_both_reserve_the_fixture() -> Result<()> {
        let (root, fixture, first) = setup()?;
        let second = root.path().join("competing-evidence");
        fs::DirBuilder::new().mode(0o700).create(&second)?;
        let barrier = std::sync::Barrier::new(2);
        let winners = std::thread::scope(|scope| {
            let handles: Vec<_> = [&first, &second]
                .into_iter()
                .map(|evidence| {
                    let (root, fixture, barrier) = (root.path(), &fixture, &barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        reserve_fixture(root, fixture, evidence, false).is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| usize::from(handle.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(winners, 1);
        let resumable = [&first, &second]
            .into_iter()
            .filter(|evidence| reserve_fixture(root.path(), &fixture, evidence, true).is_ok())
            .count();
        assert_eq!(resumable, 1);
        Ok(())
    }

    #[test]
    fn fixture_resume_rejects_unknown_schema_or_changed_identity() -> Result<()> {
        let (root, fixture, evidence) = setup()?;
        reserve_fixture(root.path(), &fixture, &evidence, false)?;
        let path = reservation_path(
            &root.path().join("artifacts/provider-conformance-runs"),
            &fixture,
        )?;
        let original: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        for (field, value) in [
            ("format", serde_json::json!(2)),
            ("unexpected", serde_json::json!(true)),
            ("evidence", serde_json::json!("/another-directory")),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            fs::write(&path, serde_json::to_vec(&changed)?)?;
            assert!(reserve_fixture(root.path(), &fixture, &evidence, true).is_err());
        }
        Ok(())
    }

    #[test]
    fn fixture_reservations_reject_symlinks_and_public_registry() -> Result<()> {
        use std::os::unix::fs::symlink;
        let (root, fixture, evidence) = setup()?;
        reserve_fixture(root.path(), &fixture, &evidence, false)?;
        let registry = root.path().join("artifacts/provider-conformance-runs");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o755))?;
        assert!(reserve_fixture(root.path(), &fixture, &evidence, true).is_err());
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o700))?;
        let linked_evidence = root.path().join("linked-evidence");
        symlink(&evidence, &linked_evidence)?;
        assert!(reserve_fixture(root.path(), &fixture, &linked_evidence, true).is_err());
        let path = reservation_path(&registry, &fixture)?;
        let original = registry.join("original.json");
        fs::rename(&path, &original)?;
        symlink(&original, &path)?;
        assert!(reserve_fixture(root.path(), &fixture, &evidence, true).is_err());
        assert!(reserve_fixture(root.path(), &fixture, &evidence, false).is_err());
        Ok(())
    }
}
