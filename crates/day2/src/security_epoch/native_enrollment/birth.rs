//! The operator-owned provisioner creates the selected issuer, startup channel,
//! nonce and listener itself and retains its actual Child. No CSR adoption.

use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::issuer_costs::{HashCosts, issuer_stderr};
use crate::security_epoch::native_enrollment::{
    channel::{Channel, Listener},
    policy::{EnrollmentPolicy, MAX_POLICY_BYTES, PolicyInterpretation},
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
    let bytes = selected_file(POLICY, MAX_POLICY_BYTES, acquisition)?;
    let policy: EnrollmentPolicy = crate::json::decode(&bytes)?;
    policy.validate()?;
    acquisition.remaining()?;
    Ok(policy)
}

pub(super) fn check_policy_interpretation(
    acquisition: &mut NativeAcquisition,
    interpretation: &mut PolicyInterpretation,
    expected: &EnrollmentPolicy,
) -> Result<()> {
    check_policy_file(POLICY, acquisition, interpretation, expected)
}

// The producer has only the fixed POLICY entry above. This private atomic
// loader also lets isolated root Linux tests exercise the exact same guards
// with their own temporary files, without changing the host's /etc policy.
fn check_policy_file(
    path: &'static str,
    acquisition: &mut NativeAcquisition,
    interpretation: &mut PolicyInterpretation,
    expected: &EnrollmentPolicy,
) -> Result<()> {
    let _profile = crate::security_epoch::self_check_profile::enter(
        crate::security_epoch::self_check_profile::Category::Policy,
    );
    // The same fresh NOFOLLOW/open, metadata, bounded read and clock checks
    // run even on an exact-byte hit. A failed read cannot use cached DATA.
    interpretation.observe(selected_file(path, MAX_POLICY_BYTES, acquisition), expected)?;
    acquisition.remaining()?;
    Ok(())
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

    #[test]
    #[ignore = "isolated root Linux cost fixture; no enrolled role or full Controller sample"]
    fn profile_guarded_policy_cold_and_exact_byte_reads() -> Result<()> {
        use crate::security_epoch::native_clock::boottime;

        let expected = super::super::tests::policy(&KeyOwner::generate()?);
        expected.validate()?;
        let encoded = serde_json::to_vec(&expected)?;
        for length in [encoded.len(), MAX_POLICY_BYTES as usize] {
            let directory = tempfile::tempdir()?;
            ensure!(
                std::fs::metadata(directory.path())?.uid() == 0,
                "native_policy_file_test_requires_root_owned_linux_fixture"
            );
            let selected = directory.path().join("copied-policy.json");
            let path: &'static str = Box::leak(
                selected
                    .to_str()
                    .context("native_policy_profile_path")?
                    .to_owned()
                    .into_boxed_str(),
            );
            // The larger case adds JSON whitespace, not more policy rules.
            let mut bytes = encoded.clone();
            bytes.resize(length, b' ');
            std::fs::write(&selected, &bytes)?;
            std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o600))?;
            let mut acquisition = NativeAcquisition::begin(5)?;
            let mut warm = PolicyInterpretation::new();
            check_policy_file(path, &mut acquisition, &mut warm, &expected)?;
            assert_eq!(warm.decodes_for_fixture(), 1);
            let mut rows = Vec::new();
            for cold in [true, false] {
                let mut total_ns = Some(0_u64);
                let mut decodes = 0;
                for _ in 0..8 {
                    let mut empty = PolicyInterpretation::new();
                    let interpretation = if cold { &mut empty } else { &mut warm };
                    let prior = interpretation.decodes_for_fixture();
                    let before = boottime().ok();
                    let result =
                        check_policy_file(path, &mut acquisition, interpretation, &expected);
                    let after = boottime().ok();
                    result?;
                    let elapsed = before
                        .zip(after)
                        .and_then(|(a, b)| b.checked_sub(a))
                        .and_then(|duration| u64::try_from(duration.as_nanos()).ok());
                    total_ns = total_ns.zip(elapsed).and_then(|(a, b)| a.checked_add(b));
                    decodes += interpretation.decodes_for_fixture() - prior;
                    // All measurements spend this SAME actual original clock.
                    acquisition.remaining()?;
                }
                assert_eq!(decodes, if cold { 8 } else { 0 });
                rows.push(serde_json::json!({
                    "interpretation": if cold { "cold" } else { "exact_byte_hit" },
                    "calls": 8,
                    "decodes_during_measurement": decodes,
                    "total_ns": total_ns,
                }));
            }
            acquisition.remaining()?;
            eprintln!(
                "day2-native-policy-profile-fixture {}",
                serde_json::json!({
                    "scope": "generated_policy_guarded_file_read_only",
                    "policy_bytes": length,
                    "padding_bytes": length - encoded.len(),
                    "rows": rows,
                })
            );
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires isolated root-owned Linux fixture; run this exact test explicitly"]
    fn policy_interpretation_rechecks_real_files_after_hits_and_refuses_restoration() -> Result<()>
    {
        use std::os::unix::fs::symlink;

        for change in [
            "mode",
            "symlink",
            "missing",
            "oversize",
            "semantic",
            "malformed",
        ] {
            let directory = tempfile::tempdir()?;
            ensure!(
                std::fs::metadata(directory.path())?.uid() == 0,
                "native_policy_file_test_requires_root_owned_linux_fixture"
            );
            let selected = directory.path().join("native-enrollment.json");
            let saved = directory.path().join("saved-policy.json");
            // selected_file already accepts static paths. Only this bounded
            // test leaks one temporary path string per case; no production
            // configuration, callback or path argument is exposed.
            let path: &'static str = Box::leak(
                selected
                    .to_str()
                    .context("native_policy_test_path")?
                    .to_owned()
                    .into_boxed_str(),
            );
            let expected = super::super::tests::policy(&KeyOwner::generate()?);
            expected.validate()?;
            let bytes = serde_json::to_vec(&expected)?;
            std::fs::write(&selected, &bytes)?;
            std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o600))?;

            // A real original clock and real successful file reads establish
            // both cold interpretation and an exact-byte hit. No native role
            // or file authority is manufactured by this test.
            let mut acquisition = NativeAcquisition::begin(5)?;
            let mut interpretation = PolicyInterpretation::new();
            check_policy_file(path, &mut acquisition, &mut interpretation, &expected)?;
            check_policy_file(path, &mut acquisition, &mut interpretation, &expected)?;

            match change {
                "mode" => {
                    std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o666))?;
                }
                "symlink" => {
                    std::fs::rename(&selected, &saved)?;
                    symlink(&saved, &selected)?;
                }
                "missing" => std::fs::rename(&selected, &saved)?,
                "oversize" => {
                    std::fs::write(&selected, vec![b' '; MAX_POLICY_BYTES as usize + 1])?;
                }
                "semantic" => {
                    let original = std::fs::metadata(&selected)?;
                    let mut changed = expected.clone();
                    changed.runtime.node_name = "node-two".into();
                    changed.validate()?;
                    let encoded = serde_json::to_vec(&changed)?;
                    ensure!(encoded.len() == bytes.len(), "native_policy_test_same_size");
                    std::fs::write(&selected, &encoded)?;
                    File::open(&selected)?
                        .set_times(std::fs::FileTimes::new().set_modified(original.modified()?))?;
                    let observed = std::fs::metadata(&selected)?;
                    ensure!(
                        observed.ino() == original.ino()
                            && observed.len() == original.len()
                            && observed.modified()? == original.modified()?,
                        "native_policy_test_preserved_metadata"
                    );
                }
                "malformed" => std::fs::write(&selected, b"{")?,
                _ => unreachable!(),
            }

            let error = check_policy_file(path, &mut acquisition, &mut interpretation, &expected)
                .unwrap_err();
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
                "semantic" => assert_eq!(
                    error.to_string(),
                    "native_enrollment_operator_selection_changed"
                ),
                "malformed" => assert!(error.to_string().contains("EOF")),
                _ => unreachable!(),
            }

            // Restore a genuinely valid regular file, prove the unchanged
            // native loader can read it, then require sticky interpretation
            // refusal on the same original clock. No fresh stage or retry.
            match std::fs::symlink_metadata(&selected) {
                Ok(_) => std::fs::remove_file(&selected)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            std::fs::write(&selected, &bytes)?;
            std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o600))?;
            assert_eq!(
                selected_file(path, MAX_POLICY_BYTES, &mut acquisition)?.as_slice(),
                bytes
            );
            let restored =
                check_policy_file(path, &mut acquisition, &mut interpretation, &expected)
                    .unwrap_err();
            assert_eq!(
                restored.to_string(),
                "native_enrollment_policy_interpretation_refused"
            );
            acquisition.remaining()?;
        }
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
