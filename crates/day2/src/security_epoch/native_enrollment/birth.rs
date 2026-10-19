//! The operator-owned provisioner creates the selected issuer, startup channel,
//! nonce and listener itself and retains its actual Child. No CSR adoption.

use crate::security_epoch::native_enrollment::{
    channel::{Channel, Listener},
    policy::EnrollmentPolicy,
    process::{MessageProcess, SelfSnapshot},
    protocol::{self, IssuerCertificate, IssuerData, KeyOwner, Packet},
};
use crate::security_epoch::native_clock::NativeAcquisition;
use anyhow::{Result, ensure};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::{Child, Command, Stdio},
};

const POLICY: &str = "/etc/day2/native-enrollment.json";
const ROOT_KEY: &str = "/run/secrets/day2-native-enrollment-root.pk8";
const ISSUER: &str = "/usr/local/bin/day2-native-enrollment";

pub(super) fn load_policy(acquisition: &mut NativeAcquisition) -> Result<EnrollmentPolicy> {
    let bytes = selected_file(POLICY, 65_536, false, acquisition)?;
    let policy: EnrollmentPolicy = crate::json::decode(&bytes)?;
    policy.validate()?;
    acquisition.remaining()?;
    Ok(policy)
}

fn selected_file(
    path: &'static str,
    limit: u64,
    secret: bool,
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
            && (!secret || metadata.mode() & 0o077 == 0)
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
    _listener: Listener,
    socket_identity: (u64, u64),
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

pub(super) fn run() -> Result<()> {
    // Original origin precedes policy/key reads, executable checks and spawn.
    let mut acquisition = NativeAcquisition::begin(5)?;
    let policy = load_policy(&mut acquisition)?;
    let mut current = SelfSnapshot::acquire(&policy.provisioner_code, &mut acquisition)?;
    current.require_node_init(&mut acquisition)?;
    let root = KeyOwner::from_pkcs8(&selected_file(ROOT_KEY, 4096, true, &mut acquisition)?)?;
    ensure!(
        root.public() == policy.root_public_key,
        "native_enrollment_root_key_selection"
    );
    match std::fs::create_dir("/run/day2-native-enrollment") {
        Ok(()) => std::fs::set_permissions(
            "/run/day2-native-enrollment",
            std::fs::Permissions::from_mode(0o755),
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
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
        metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "native_enrollment_operator_directory"
    );
    let (listener, listener_child) = Listener::create(&mut acquisition)?;
    let metadata = std::fs::symlink_metadata("/run/day2-native-enrollment/issuer.sock")?;
    let (mut channel, child_channel) = Channel::pair(&mut acquisition)?;
    let child = Command::new(ISSUER)
        .arg("issuer")
        .env_clear()
        .stdin(Stdio::from(child_channel))
        .stdout(Stdio::from(listener_child))
        .stderr(Stdio::null())
        .spawn()?;
    let mut birth = IssuerBirthOwner {
        child,
        peer: None,
        _listener: listener,
        socket_identity: (metadata.dev(), metadata.ino()),
    };
    let nonce = protocol::nonce("issuer-birth")?;
    let policy_hash = policy.digest()?;
    channel.send(
        &Packet::BirthChallenge {
            policy: policy_hash.clone(),
            nonce: nonce.clone(),
        },
        &mut acquisition,
    )?;
    let (packet, mut peer) = channel.receive(&policy.issuer_code, &mut acquisition)?;
    let Packet::BirthKey {
        nonce: echoed,
        public_key,
        signature,
    } = packet
    else {
        anyhow::bail!("native_enrollment_birth_order")
    };
    ensure!(
        echoed == nonce
            && peer.data().process == birth.child.id()
            && birth.child.try_wait()?.is_none(),
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
        root_version: policy.root_version.clone(),
        nonce,
        public_key,
        process: peer.data().clone(),
        provisioner: current.data.clone(),
    };
    let certificate = IssuerCertificate {
        signature: root.sign("issuer-birth", &data)?,
        data,
    };
    current.check(&mut acquisition)?;
    peer.check_identity(&mut acquisition)?;
    channel.send(&Packet::BirthGrant { certificate }, &mut acquisition)?;
    birth.peer = Some(peer);
    // Root stays alive and retains actual child ownership. There is no restart,
    // key export, saved-row re-enrollment or successful-reply retry path.
    loop {
        ensure!(
            birth.child.try_wait()?.is_none(),
            "native_enrollment_issuer_stopped"
        );
        let mut check = NativeAcquisition::begin(5)?;
        birth
            .peer
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("native_enrollment_birth_missing"))?
            .check_identity(&mut check)?;
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
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
