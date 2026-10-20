//! The operator-owned provisioner creates the selected issuer, startup channel,
//! nonce and listener itself and retains its actual Child. No CSR adoption.

use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    channel::{Channel, Listener},
    policy::EnrollmentPolicy,
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
    let bytes = selected_file(POLICY, 65_536, acquisition)?;
    let policy: EnrollmentPolicy = crate::json::decode(&bytes)?;
    policy.validate()?;
    acquisition.remaining()?;
    Ok(policy)
}

fn selected_file(
    path: &'static str,
    limit: u64,
    acquisition: &mut NativeAcquisition,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    acquisition.remaining()?;
    let file = File::from(rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.len() > 0
            && metadata.len() <= limit,
        "native_enrollment_operator_file"
    );
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= limit,
        "native_enrollment_operator_file_bound"
    );
    acquisition.remaining()?;
    Ok(bytes)
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
    let mut current = SelfSnapshot::acquire(&policy.provisioner_code, &mut acquisition)
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
        .stderr(Stdio::inherit())
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
            .check_identity(&mut check)?;
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
        let (packet, mut peer) = channel.receive(&policy.issuer_code, acquisition)?;
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
        peer.check_identity(acquisition)?;
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
        peer.check_identity(acquisition)?;
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
        let mut current = SelfSnapshot::acquire(&policy.issuer_code, &mut acquisition)?;
        current.require_node_init(&mut acquisition)?;
        let mut channel = Channel::startup(&mut acquisition)?;
        let listener = Listener::startup(&mut acquisition)?;
        let key = KeyOwner::generate()?;
        let (packet, mut parent) = channel.receive(&policy.provisioner_code, &mut acquisition)?;
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
        let (packet, mut grant_parent) =
            channel.receive(&policy.provisioner_code, &mut acquisition)?;
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
        parent.check_identity(&mut acquisition)?;
        grant_parent.check_identity(&mut acquisition)?;
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
        let current = SelfSnapshot::acquire(&policy.issuer_code, &mut acquisition).unwrap();
        let mut channel = Channel::startup(&mut acquisition).unwrap();
        let (packet, parent) = channel
            .receive(&policy.provisioner_code, &mut acquisition)
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
            .receive(&policy.provisioner_code, &mut acquisition)
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
            let mut current = SelfSnapshot::acquire(&code, &mut acquisition).unwrap();
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
                let (reply, ack_peer) = channel.receive(&code, &mut acquisition).unwrap();
                assert!(matches!(reply, Packet::BirthChallenge { .. }));
                assert_eq!(peer.data(), ack_peer.data());
                peer.check_identity(&mut acquisition).unwrap();
            }
        }
    }
}
