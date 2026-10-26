//! The operator-owned provisioner creates the selected issuer, startup channel,
//! nonce and listener itself and retains its actual Child. No CSR adoption.

use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::issuer_costs::{HashCosts, issuer_stderr};
use crate::security_epoch::native_enrollment::{
    channel::{Channel, Listener},
    policy::{EnrollmentPolicy, MAX_POLICY_BYTES},
    process::{MessageProcess, SelfSnapshot},
    protocol::{self, IssuerCertificate, IssuerData, KeyOwner, Packet},
    root_kms::RootKms,
    storage_socket_directory::StorageSocketDirectory,
};
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::{Child, Command, Stdio},
};

const POLICY: &str = "/etc/day2/native-enrollment.json";
const ISSUER: &str = "/usr/local/bin/day2-native-enrollment";

pub(super) fn load_policy(acquisition: &mut NativeAcquisition) -> Result<EnrollmentPolicy> {
    let (policy, _file) = admit_policy(acquisition)?;
    Ok(policy)
}

/// Full cold admission of the actual fixed policy file. No parsed policy or
/// caller-supplied descriptor can construct its retained native file owner.
pub(super) fn admit_policy(
    acquisition: &mut NativeAcquisition,
) -> Result<(EnrollmentPolicy, PolicyFileOwner)> {
    admit_policy_file(POLICY, acquisition)
}

pub(super) struct PolicyFileOwner {
    file: File,
    stamp: PolicyFileStamp,
    refused: bool,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[derive(PartialEq, Eq)]
struct PolicyFileStamp {
    device: u64,
    inode: u64,
    mount: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <PolicyFileOwner as Ambiguous<_>>::check;
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

fn open_policy_file(path: &'static str, acquisition: &mut NativeAcquisition) -> Result<File> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    acquisition.remaining()?;
    let file = File::from(rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    acquisition.remaining()?;
    Ok(file)
}

fn policy_file_stamp(file: &File, acquisition: &mut NativeAcquisition) -> Result<PolicyFileStamp> {
    use rustix::fs::{AtFlags, StatxFlags};
    acquisition.remaining()?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.len() > 0
            && metadata.len() <= MAX_POLICY_BYTES,
        "native_enrollment_operator_file"
    );
    let mask = StatxFlags::INO | StatxFlags::MNT_ID;
    let mounted = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, mask)?;
    ensure!(
        mounted.stx_mask & mask.bits() == mask.bits()
            && mounted.stx_ino == metadata.ino()
            && mounted.stx_ino != 0
            && mounted.stx_mnt_id != 0,
        "native_enrollment_operator_file_mount"
    );
    acquisition.remaining()?;
    Ok(PolicyFileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount: mounted.stx_mnt_id,
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        length: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

// Production selects only POLICY. Isolated Linux conformance tests use actual
// temporary root-owned files through this same lower adapter, never a role.
fn admit_policy_file(
    path: &'static str,
    acquisition: &mut NativeAcquisition,
) -> Result<(EnrollmentPolicy, PolicyFileOwner)> {
    let result = (|| {
        let _profile = crate::security_epoch::self_check_profile::enter(
            crate::security_epoch::self_check_profile::Category::Policy,
        );
        let mut file: File = open_policy_file(path, acquisition)?;
        let stamp = policy_file_stamp(&file, acquisition)?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        let mut buffer = zeroize::Zeroizing::new([0_u8; 8192]);
        loop {
            acquisition.remaining()?;
            let remaining = (MAX_POLICY_BYTES as usize + 1) - bytes.len();
            let capacity = remaining.min(buffer.len());
            let count = File::read(&mut file, &mut buffer[..capacity])?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
            ensure!(
                bytes.len() as u64 <= MAX_POLICY_BYTES,
                "native_enrollment_operator_file_bound"
            );
        }
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 == stamp.length,
            "native_enrollment_operator_file_changed"
        );
        let policy: EnrollmentPolicy = crate::json::decode(&bytes)?;
        policy.validate()?;
        let mut owner = PolicyFileOwner {
            file,
            stamp,
            refused: false,
            local: std::marker::PhantomData,
        };
        owner.check_file(path, acquisition)?;
        Ok((policy, owner))
    })();
    if result.is_err() {
        acquisition.refuse();
    }
    result
}

impl PolicyFileOwner {
    pub(super) fn check(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        self.check_file(POLICY, acquisition)
    }

    fn check_file(
        &mut self,
        path: &'static str,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "native_enrollment_operator_file_refused");
            let _profile = crate::security_epoch::self_check_profile::enter(
                crate::security_epoch::self_check_profile::Category::Policy,
            );
            acquisition.remaining()?;
            let named = open_policy_file(path, acquisition)?;
            let held = policy_file_stamp(&self.file, acquisition)?;
            let current = policy_file_stamp(&named, acquisition)?;
            ensure!(
                held == self.stamp && current == self.stamp,
                "native_enrollment_operator_file_changed"
            );
            acquisition.remaining()?;
            Ok(())
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }
}

struct IssuerBirthOwner {
    child: Child,
    peer: Option<MessageProcess>,
    // Keep the actual startup peer alive while the child admits the queued
    // grant. A buffered packet plus HUP must remain a refusal, even if the
    // sending provisioner itself is still alive.
    startup: Channel,
    _listener: Listener,
    socket_identity: (u64, u64),
    storage: StorageSocketDirectory,
}

impl Drop for IssuerBirthOwner {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let path = "/run/day2-native-enrollment/issuer.sock";
        if std::fs::symlink_metadata(path).is_ok_and(|m| (m.dev(), m.ino()) == self.socket_identity)
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub(super) struct Provisioner {
    directory: File,
    birth: IssuerBirthOwner,
}

pub(super) fn start() -> Result<Provisioner> {
    // Original origin precedes policy/key reads, executable checks and spawn.
    let mut acquisition =
        NativeAcquisition::begin(5).context("native_enrollment_original_clock")?;
    let policy = load_policy(&mut acquisition).context("native_enrollment_policy")?;
    let mut current = SelfSnapshot::acquire(
        &policy.provisioner_code,
        &mut acquisition,
        &HashCosts::disabled(),
    )
    .context("native_enrollment_provisioner_self")?;
    current
        .require_node_init(&mut acquisition)
        .context("native_enrollment_node_init")?;
    let root = RootSigner::Kms(RootKms::new().context("native_enrollment_root_client")?);
    match std::fs::create_dir("/run/day2-native-enrollment") {
        Ok(()) => std::fs::set_permissions(
            "/run/day2-native-enrollment",
            std::fs::Permissions::from_mode(0o755),
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("native_enrollment_socket_directory"),
    }
    let directory = File::from(rustix::fs::open(
        "/run/day2-native-enrollment",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let metadata = directory.metadata()?;
    ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o755,
        "native_enrollment_operator_directory"
    );
    acquisition.remaining()?;
    let storage = StorageSocketDirectory::prepare(&directory)
        .context("native_enrollment_storage_directory")?;
    acquisition.remaining()?;
    let (listener, listener_child) =
        Listener::create(&mut acquisition).context("native_enrollment_listener")?;
    let metadata = std::fs::symlink_metadata("/run/day2-native-enrollment/issuer.sock")?;
    let (channel, child_channel) =
        Channel::pair(&mut acquisition).context("native_enrollment_startup_channel")?;
    let child = Command::new(ISSUER)
        .arg("issuer")
        .env_clear()
        .stdin(Stdio::from(child_channel))
        .stdout(Stdio::from(listener_child))
        .stderr(issuer_stderr())
        .spawn()
        .context("native_enrollment_child_spawn")?;
    let mut birth = IssuerBirthOwner {
        child,
        peer: None,
        startup: channel,
        _listener: listener,
        socket_identity: (metadata.dev(), metadata.ino()),
        storage,
    };
    birth.peer = Some(
        grant_child(
            &mut birth.child,
            &mut birth.startup,
            &root,
            &mut current,
            &policy,
            &mut acquisition,
        )
        .context("native_enrollment_birth_grant")?,
    );
    Ok(Provisioner { directory, birth })
}

impl Provisioner {
    // Fresh checks never extend the completed original birth acquisition.
    pub(super) fn check(&mut self) -> Result<()> {
        ensure!(
            self.birth.child.try_wait()?.is_none(),
            "native_enrollment_issuer_stopped"
        );
        let mut check = NativeAcquisition::begin(5)?;
        self.birth.storage.check(&self.directory)?;
        check.remaining()?;
        self.birth
            .peer
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("native_enrollment_birth_missing"))?
            .check_identity(&mut check, &HashCosts::disabled())?;
        Ok(())
    }
}

enum RootSigner {
    Kms(RootKms),
    #[cfg(test)]
    Fixture(KeyOwner),
}

fn grant_child(
    child: &mut Child,
    channel: &mut Channel,
    root: &RootSigner,
    current: &mut SelfSnapshot,
    policy: &EnrollmentPolicy,
    acquisition: &mut NativeAcquisition,
) -> Result<MessageProcess> {
    let result = (|| {
        let nonce = protocol::nonce("issuer-birth")?;
        let policy_hash = policy.digest()?;
        channel.send(
            &Packet::BirthChallenge {
                policy: policy_hash.clone(),
                nonce: nonce.clone(),
            },
            acquisition,
        )?;
        let (packet, mut peer) =
            channel.receive(&policy.issuer_code, acquisition, &HashCosts::disabled())?;
        let Packet::BirthKey {
            nonce: echoed,
            public_key,
            signature,
        } = packet
        else {
            anyhow::bail!("native_enrollment_birth_order")
        };
        ensure!(
            echoed == nonce && peer.data().process == child.id() && child.try_wait()?.is_none(),
            "native_enrollment_birth_child"
        );
        super::runtime::require_common(&current.data, peer.data())?;
        protocol::verify(
            &public_key,
            "issuer-birth-key",
            &(&policy_hash, &nonce, &public_key),
            &signature,
        )?;
        let data = IssuerData {
            policy: policy_hash,
            root_version: policy.root.version.clone(),
            nonce,
            public_key,
            process: peer.data().clone(),
            provisioner: current.data.clone(),
        };
        current.check(acquisition)?;
        peer.check_identity(acquisition, &HashCosts::disabled())?;
        ensure!(
            child.try_wait()?.is_none(),
            "native_enrollment_birth_child_stopped"
        );
        let signature = match root {
            RootSigner::Kms(kms) => kms.issuer_birth(&policy.root, &data, acquisition)?,
            #[cfg(test)]
            RootSigner::Fixture(key) => key.sign("issuer-birth", &data)?,
        };
        current.check(acquisition)?;
        peer.check_identity(acquisition, &HashCosts::disabled())?;
        ensure!(
            child.try_wait()?.is_none(),
            "native_enrollment_birth_child_stopped"
        );
        let certificate = IssuerCertificate { signature, data };
        channel.send(&Packet::BirthGrant { certificate }, acquisition)?;
        Ok(peer)
    })();
    if result.is_err() {
        acquisition.refuse();
    }
    result
}

pub(super) struct IssuerOwner {
    pub policy: EnrollmentPolicy,
    pub key: KeyOwner,
    pub certificate: IssuerCertificate,
    pub parent: MessageProcess,
    pub listener: Listener,
}

impl IssuerOwner {
    pub(super) fn born() -> Result<Self> {
        let mut acquisition = NativeAcquisition::begin(5)?;
        let policy = load_policy(&mut acquisition)?;
        let mut current = SelfSnapshot::acquire(
            &policy.issuer_code,
            &mut acquisition,
            &HashCosts::disabled(),
        )?;
        current.require_node_init(&mut acquisition)?;
        let mut channel = Channel::startup(&mut acquisition)?;
        let listener = Listener::startup(&mut acquisition)?;
        let key = KeyOwner::generate()?;
        let (packet, mut parent) = channel.receive(
            &policy.provisioner_code,
            &mut acquisition,
            &HashCosts::disabled(),
        )?;
        let Packet::BirthChallenge {
            policy: selected,
            nonce,
        } = packet
        else {
            anyhow::bail!("native_enrollment_birth_order")
        };
        ensure!(
            selected == policy.digest()?
                && Some(parent.data().process)
                    == rustix::process::getppid().map(|pid| pid.as_raw_nonzero().get() as u32),
            "native_enrollment_birth_parent"
        );
        super::runtime::require_common(&current.data, parent.data())?;
        let public_key = key.public();
        let signature = key.sign("issuer-birth-key", &(&selected, &nonce, &public_key))?;
        channel.send(
            &Packet::BirthKey {
                nonce: nonce.clone(),
                public_key: public_key.clone(),
                signature,
            },
            &mut acquisition,
        )?;
        let (packet, mut grant_parent) = channel.receive(
            &policy.provisioner_code,
            &mut acquisition,
            &HashCosts::disabled(),
        )?;
        let Packet::BirthGrant { certificate } = packet else {
            anyhow::bail!("native_enrollment_birth_order")
        };
        certificate.verify(&policy)?;
        ensure!(
            certificate.data.nonce == nonce
                && certificate.data.public_key == public_key
                && certificate.data.process == current.data
                && &certificate.data.provisioner == parent.data()
                && parent.data() == grant_parent.data(),
            "native_enrollment_birth_binding"
        );
        current.check(&mut acquisition)?;
        parent.check_identity(&mut acquisition, &HashCosts::disabled())?;
        grant_parent.check_identity(&mut acquisition, &HashCosts::disabled())?;
        Ok(Self {
            policy,
            key,
            certificate,
            parent,
            listener,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_fixture() -> Result<(tempfile::TempDir, &'static str, EnrollmentPolicy, Vec<u8>)> {
        let directory = tempfile::tempdir()?;
        ensure!(
            std::fs::metadata(directory.path())?.uid() == 0,
            "native_policy_fixture_requires_linux_root"
        );
        let selected = directory.path().join("native-enrollment.json");
        let path = Box::leak(
            selected
                .to_str()
                .context("native_policy_fixture_path")?
                .to_owned()
                .into_boxed_str(),
        );
        let expected = super::super::tests::policy(&KeyOwner::generate()?);
        let bytes = serde_json::to_vec(&expected)?;
        std::fs::write(&selected, &bytes)?;
        std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o600))?;
        Ok((directory, path, expected, bytes))
    }

    #[test]
    fn admitted_policy_checks_actual_handles_without_reading_and_refuses_restoration() -> Result<()>
    {
        use std::io::{Seek, SeekFrom};
        // Actual Linux file/clock controls, not enrolled-role construction.
        // The canonical Linux workspace shard runs in its root container.
        for change in [
            "replacement",
            "held_fd",
            "mode",
            "symlink",
            "missing",
            "oversize",
            "semantic",
            "malformed",
        ] {
            let (directory, path, expected, bytes) = policy_fixture()?;
            let selected = std::path::Path::new(path);
            let saved = directory.path().join("saved-policy.json");
            let mut acquisition = NativeAcquisition::begin(5)?;
            let (actual, mut owner) = admit_policy_file(path, &mut acquisition)?;
            ensure!(actual == expected, "native_policy_fixture_selection");
            owner.file.seek(SeekFrom::Start(1))?;
            owner.check_file(path, &mut acquisition)?;
            owner.check_file(path, &mut acquisition)?;
            assert_eq!(owner.file.stream_position()?, 1);
            let mut original_fd = None;
            match change {
                "replacement" => {
                    std::fs::rename(selected, &saved)?;
                    std::fs::write(selected, &bytes)?;
                    std::fs::set_permissions(selected, std::fs::Permissions::from_mode(0o600))?;
                    assert_ne!(
                        std::fs::metadata(selected)?.ino(),
                        owner.file.metadata()?.ino()
                    );
                }
                "held_fd" => {
                    std::fs::write(&saved, &bytes)?;
                    original_fd = Some(std::mem::replace(&mut owner.file, File::open(&saved)?));
                }
                "mode" => {
                    std::fs::set_permissions(selected, std::fs::Permissions::from_mode(0o666))?
                }
                "symlink" => {
                    std::fs::rename(selected, &saved)?;
                    std::os::unix::fs::symlink(&saved, selected)?;
                }
                "missing" => std::fs::rename(selected, &saved)?,
                "oversize" => std::fs::write(selected, vec![b' '; MAX_POLICY_BYTES as usize + 1])?,
                "semantic" => {
                    let metadata = std::fs::metadata(selected)?;
                    let mut changed = expected.clone();
                    changed.runtime.node_name = "node-two".into();
                    let encoded = serde_json::to_vec(&changed)?;
                    assert_eq!(encoded.len(), bytes.len());
                    std::fs::write(selected, encoded)?;
                    File::open(selected)?
                        .set_times(std::fs::FileTimes::new().set_modified(metadata.modified()?))?;
                    assert_eq!(
                        std::fs::metadata(selected)?.modified()?,
                        metadata.modified()?
                    );
                }
                "malformed" => std::fs::write(selected, b"{")?,
                _ => unreachable!(),
            }
            let error = owner.check_file(path, &mut acquisition).unwrap_err();
            match change {
                "mode" | "oversize" => {
                    assert_eq!(error.to_string(), "native_enrollment_operator_file")
                }
                "symlink" => assert_eq!(
                    error.downcast_ref::<rustix::io::Errno>(),
                    Some(&rustix::io::Errno::LOOP)
                ),
                "missing" => assert_eq!(
                    error.downcast_ref::<rustix::io::Errno>(),
                    Some(&rustix::io::Errno::NOENT)
                ),
                _ => assert_eq!(error.to_string(), "native_enrollment_operator_file_changed"),
            }
            assert!(owner.refused);
            assert!(acquisition.remaining().is_err());
            if let Some(file) = original_fd {
                owner.file = file;
            }
            match std::fs::symlink_metadata(selected) {
                Ok(_) => std::fs::remove_file(selected)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            std::fs::write(selected, &bytes)?;
            std::fs::set_permissions(selected, std::fs::Permissions::from_mode(0o600))?;
            let mut later = NativeAcquisition::begin(5)?;
            let (restored, _) = admit_policy_file(path, &mut later)?;
            ensure!(
                restored == expected,
                "native_policy_fixture_restored_selection"
            );
            let error = owner.check_file(path, &mut later).unwrap_err();
            assert_eq!(error.to_string(), "native_enrollment_operator_file_refused");
            assert!(later.remaining().is_err());
        }
        Ok(())
    }

    #[test]
    fn cold_policy_file_still_requires_bounded_strict_and_valid_selected_data() -> Result<()> {
        for change in [
            "empty",
            "oversize",
            "malformed",
            "unknown",
            "duplicate",
            "invalid_key",
            "invalid_selection",
            "deep",
        ] {
            let (_directory, path, expected, _) = policy_fixture()?;
            let mut value = serde_json::to_value(&expected)?;
            let bytes = match change {
                "empty" => vec![],
                "oversize" => vec![b' '; MAX_POLICY_BYTES as usize + 1],
                "malformed" => b"{".to_vec(),
                "unknown" => {
                    value["unexpected"] = true.into();
                    serde_json::to_vec(&value)?
                }
                "duplicate" => b"{\"root\":null,\"root\":null}".to_vec(),
                "invalid_key" => {
                    value["root"]["public_key"] = "!".repeat(43).into();
                    serde_json::to_vec(&value)?
                }
                "invalid_selection" => {
                    value["runtime"]["node_name"] = "".into();
                    serde_json::to_vec(&value)?
                }
                "deep" => format!("{}0{}", "[".repeat(129), "]".repeat(129)).into_bytes(),
                _ => unreachable!(),
            };
            std::fs::write(path, bytes)?;
            let mut acquisition = NativeAcquisition::begin(5)?;
            assert!(
                admit_policy_file(path, &mut acquisition).is_err(),
                "case {change}"
            );
            assert!(acquisition.remaining().is_err(), "case {change}");
        }
        Ok(())
    }

    #[test]
    fn policy_named_remount_refuses_even_with_the_same_inode_and_after_restoration() -> Result<()> {
        // One isolated subprocess mount namespace; no host policy, database,
        // runtime role, selected node resource or other test mount is touched.
        let status = Command::new("unshare")
            .args(["--mount", "--propagation", "private"])
            .arg(std::env::current_exe()?)
            .args([
                "--exact",
                "security_epoch::native_enrollment::birth::tests::policy_remount_child",
                "--ignored",
                "--nocapture",
            ])
            .env("DAY2_NATIVE_POLICY_REMOUNT_CHILD", "1")
            .status()?;
        ensure!(status.success(), "native_policy_remount_child_refused");
        Ok(())
    }

    #[test]
    #[ignore = "isolated actual Linux mount-namespace child, invoked by the remount conformance control"]
    fn policy_remount_child() -> Result<()> {
        ensure!(
            std::env::var_os("DAY2_NATIVE_POLICY_REMOUNT_CHILD").is_some(),
            "native_policy_remount_child_only"
        );
        let (_directory, path, expected, _) = policy_fixture()?;
        let mut acquisition = NativeAcquisition::begin(5)?;
        let (_, mut owner) = admit_policy_file(path, &mut acquisition)?;
        ensure!(
            Command::new("mount")
                .args(["--bind", path, path])
                .status()?
                .success(),
            "native_policy_fixture_mount_refused"
        );
        struct Mounted(&'static str, bool);
        impl Drop for Mounted {
            fn drop(&mut self) {
                if self.1 {
                    let _ = Command::new("umount").arg(self.0).status();
                }
            }
        }
        let mut mounted = Mounted(path, true);
        let named = open_policy_file(path, &mut acquisition)?;
        let mut changed = policy_file_stamp(&named, &mut acquisition)?;
        assert_eq!(changed.inode, owner.stamp.inode);
        assert_ne!(changed.mount, owner.stamp.mount);
        changed.mount = owner.stamp.mount;
        assert!(
            changed == owner.stamp,
            "this control changes only the actual named mount identity"
        );
        // Release the inspection FD on the new bind mount before unmounting.
        // The admitted owner retains its original pre-mount descriptor.
        drop(named);
        let error = owner.check_file(path, &mut acquisition).unwrap_err();
        assert_eq!(error.to_string(), "native_enrollment_operator_file_changed");
        assert!(acquisition.remaining().is_err());
        ensure!(
            Command::new("umount").arg(path).status()?.success(),
            "native_policy_fixture_unmount_refused"
        );
        mounted.1 = false;
        let mut later = NativeAcquisition::begin(5)?;
        let (restored, _) = admit_policy_file(path, &mut later)?;
        ensure!(
            restored == expected,
            "native_policy_fixture_selection_changed"
        );
        let error = owner.check_file(path, &mut later).unwrap_err();
        assert_eq!(error.to_string(), "native_enrollment_operator_file_refused");
        assert!(later.remaining().is_err());
        Ok(())
    }

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "native subprocess helper invoked by retained_child_birth_requires_original_nonce_and_key_possession"]
    fn issuer_child() {
        let selected = std::env::var("DAY2_ENROLLMENT_BIRTH_TEST_POLICY").unwrap();
        let policy: EnrollmentPolicy = crate::json::decode(selected.as_bytes()).unwrap();
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let current = SelfSnapshot::acquire(
            &policy.issuer_code,
            &mut acquisition,
            &HashCosts::disabled(),
        )
        .unwrap();
        let mut channel = Channel::startup(&mut acquisition).unwrap();
        let (packet, parent) = channel
            .receive(
                &policy.provisioner_code,
                &mut acquisition,
                &HashCosts::disabled(),
            )
            .unwrap();
        let Packet::BirthChallenge {
            policy: digest,
            nonce,
        } = packet
        else {
            panic!("birth order")
        };
        assert_eq!(digest, policy.digest().unwrap());
        let key = KeyOwner::generate().unwrap();
        let public_key = key.public();
        let echoed = if std::env::var_os("DAY2_ENROLLMENT_WRONG_BIRTH_NONCE").is_some() {
            day2_capabilities::Digest::new(b"not-the-original")
        } else {
            nonce.clone()
        };
        let signature = key
            .sign("issuer-birth-key", &(&digest, &echoed, &public_key))
            .unwrap();
        channel
            .send(
                &Packet::BirthKey {
                    nonce: echoed,
                    public_key: public_key.clone(),
                    signature,
                },
                &mut acquisition,
            )
            .unwrap();
        if std::env::var_os("DAY2_ENROLLMENT_WRONG_BIRTH_NONCE").is_some() {
            loop {
                std::thread::park();
            }
        }
        let (packet, grant_parent) = channel
            .receive(
                &policy.provisioner_code,
                &mut acquisition,
                &HashCosts::disabled(),
            )
            .unwrap();
        let Packet::BirthGrant { certificate } = packet else {
            panic!("birth grant order")
        };
        certificate.verify(&policy).unwrap();
        assert_eq!(certificate.data.nonce, nonce);
        assert_eq!(certificate.data.public_key, public_key);
        assert_eq!(certificate.data.process, current.data);
        assert_eq!(&certificate.data.provisioner, parent.data());
        assert_eq!(parent.data(), grant_parent.data());
        channel
            .send(
                &Packet::BirthChallenge {
                    policy: digest,
                    nonce,
                },
                &mut acquisition,
            )
            .unwrap();
        loop {
            std::thread::park();
        }
    }

    #[test]
    fn retained_child_birth_requires_original_nonce_and_key_possession() {
        let code = day2_capabilities::Digest::new(&std::fs::read("/proc/self/exe").unwrap());
        for wrong_nonce in [false, true] {
            let mut acquisition = NativeAcquisition::begin(5).unwrap();
            let root = KeyOwner::generate().unwrap();
            let mut policy = crate::security_epoch::native_enrollment::tests::policy(&root);
            policy.provisioner_code = code.clone();
            policy.issuer_code = code.clone();
            let mut current =
                SelfSnapshot::acquire(&code, &mut acquisition, &HashCosts::disabled()).unwrap();
            let (mut channel, child_socket) = Channel::pair(&mut acquisition).unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "security_epoch::native_enrollment::birth::tests::issuer_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env(
                    "DAY2_ENROLLMENT_BIRTH_TEST_POLICY",
                    serde_json::to_string(&policy).unwrap(),
                )
                .stdin(Stdio::from(child_socket))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit());
            if wrong_nonce {
                command.env("DAY2_ENROLLMENT_WRONG_BIRTH_NONCE", "1");
            }
            let mut child = ChildGuard(command.spawn().unwrap());
            let result = grant_child(
                &mut child.0,
                &mut channel,
                &RootSigner::Fixture(root),
                &mut current,
                &policy,
                &mut acquisition,
            );
            if wrong_nonce {
                assert!(result.is_err());
                assert!(acquisition.remaining().is_err());
            } else {
                let mut peer = result.unwrap();
                assert_eq!(peer.data().process, child.0.id());
                let (reply, ack_peer) = channel
                    .receive(&code, &mut acquisition, &HashCosts::disabled())
                    .unwrap();
                assert!(matches!(reply, Packet::BirthChallenge { .. }));
                assert_eq!(peer.data(), ack_peer.data());
                peer.check_identity(&mut acquisition, &HashCosts::disabled())
                    .unwrap();
            }
        }
    }
}
