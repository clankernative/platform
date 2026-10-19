use super::*;
use crate::security_epoch::native_enrollment::{
    channel::Channel,
    process::SelfSnapshot,
    protocol::{self, IssuerData, KeyOwner, Packet},
};
use std::process::{Child, Command, Stdio};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn certificate(
    root: &KeyOwner,
    policy: &EnrollmentPolicy,
    data: super::super::protocol::ProcessData,
    nonce: Digest,
) -> IssuerCertificate {
    let data = IssuerData {
        policy: policy.digest().unwrap(),
        root_version: policy.root_version.clone(),
        nonce,
        public_key: KeyOwner::generate().unwrap().public(),
        process: data.clone(),
        provisioner: data,
    };
    IssuerCertificate {
        signature: root.sign("issuer-birth", &data).unwrap(),
        data,
    }
}

#[test]
fn actual_message_receipt_requires_root_binding_and_never_recovers_after_mismatch() {
    let code = Digest::new(&std::fs::read("/proc/self/exe").unwrap());
    let mut acquisition = NativeAcquisition::begin(5).unwrap();
    let root = KeyOwner::generate().unwrap();
    let mut policy = crate::security_epoch::native_enrollment::tests::policy(&root);
    policy.provisioner_code = code.clone();
    policy.issuer_code = code.clone();
    let current = SelfSnapshot::acquire(&code, &mut acquisition).unwrap();
    let certificate = certificate(
        &root,
        &policy,
        current.data,
        protocol::nonce("receipt-test").unwrap(),
    );
    let (mut channel, sender) = Channel::pair(&mut acquisition).unwrap();
    let bytes = serde_json::to_vec(&Packet::BirthGrant {
        certificate: certificate.clone(),
    })
    .unwrap();
    rustix::net::send(&sender, &bytes, rustix::net::SendFlags::DONTWAIT).unwrap();
    let (_, mut unbound) = channel.receive_issuer(&mut acquisition).unwrap();
    assert!(unbound.check_live(&mut acquisition).is_err());
    let mut later = NativeAcquisition::begin(5).unwrap();
    assert!(unbound.bind(&certificate, &policy, &mut later).is_err());
    let mut acquisition = NativeAcquisition::begin(5).unwrap();
    rustix::net::send(&sender, &bytes, rustix::net::SendFlags::DONTWAIT).unwrap();
    let (_, mut receipt) = channel.receive_issuer(&mut acquisition).unwrap();
    let mut wrong = certificate.clone();
    wrong.data.process.process += 1;
    wrong.signature = root.sign("issuer-birth", &wrong.data).unwrap();
    assert!(receipt.bind(&wrong, &policy, &mut acquisition).is_err());
    let mut later = NativeAcquisition::begin(5).unwrap();
    assert!(receipt.bind(&certificate, &policy, &mut later).is_err());
}

#[test]
#[ignore = "native subprocess helper invoked by unprivileged_client_receives_root_issuer_without_ptrace"]
fn unprivileged_client() {
    let mut acquisition = NativeAcquisition::begin(5).unwrap();
    assert_eq!(rustix::process::geteuid().as_raw(), 10001);
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    assert!(
        status
            .lines()
            .any(|line| line == "CapEff:\t0000000000000000")
    );
    let bytes = std::env::var("DAY2_ISSUER_RECEIPT_TEST_POLICY").unwrap();
    let policy: EnrollmentPolicy = crate::json::decode(bytes.as_bytes()).unwrap();
    let mut current = SelfSnapshot::acquire(&policy.issuer_code, &mut acquisition).unwrap();
    let request = protocol::nonce("cross-uid-issuer").unwrap();
    let mut channel = Channel::startup(&mut acquisition).unwrap();
    channel
        .send(
            &Packet::BirthChallenge {
                policy: policy.digest().unwrap(),
                nonce: request.clone(),
            },
            &mut acquisition,
        )
        .unwrap();
    let (packet, mut receipt) = channel.receive_issuer(&mut acquisition).unwrap();
    let Packet::BirthGrant { certificate } = packet else {
        panic!("receipt order")
    };
    assert_eq!(certificate.data.nonce, request);
    certificate.verify(&policy).unwrap();
    // Demonstrate why measuring the privileged issuer from the client would
    // require extra privilege. This receipt never performs that open.
    let error = std::fs::File::open(format!("/proc/{}/exe", certificate.data.process.process))
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    super::super::runtime::require_common(&current.data, &certificate.data.process).unwrap();
    receipt
        .bind(&certificate, &policy, &mut acquisition)
        .unwrap();
    receipt.check_live(&mut acquisition).unwrap();
    current.check(&mut acquisition).unwrap();
    channel
        .send(
            &Packet::BirthChallenge {
                policy: policy.digest().unwrap(),
                nonce: request,
            },
            &mut acquisition,
        )
        .unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
#[ignore = "requires isolated root-owned Linux fixture for cross-UID process launch; run exact test explicitly"]
fn unprivileged_client_receives_root_issuer_without_ptrace() {
    use std::os::unix::process::CommandExt;
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let code = Digest::new(&std::fs::read("/proc/self/exe").unwrap());
    let mut acquisition = NativeAcquisition::begin(5).unwrap();
    let root = KeyOwner::generate().unwrap();
    let mut policy = crate::security_epoch::native_enrollment::tests::policy(&root);
    policy.provisioner_code = code.clone();
    policy.issuer_code = code.clone();
    let current = SelfSnapshot::acquire(&code, &mut acquisition).unwrap();
    let (mut channel, child_socket) = Channel::pair(&mut acquisition).unwrap();
    let child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "security_epoch::native_enrollment::issuer_peer::tests::unprivileged_client",
                "--ignored",
                "--nocapture",
            ])
            .env(
                "DAY2_ISSUER_RECEIPT_TEST_POLICY",
                serde_json::to_string(&policy).unwrap(),
            )
            .uid(10001)
            .gid(10001)
            .stdin(Stdio::from(child_socket))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let (packet, received) = channel.receive_issuer(&mut acquisition).unwrap();
    assert_eq!(received.kernel_process, child.0.id());
    let Packet::BirthChallenge {
        policy: selected,
        nonce,
    } = packet
    else {
        panic!("receipt order")
    };
    assert_eq!(selected, policy.digest().unwrap());
    let certificate = certificate(&root, &policy, current.data, nonce.clone());
    channel
        .send(&Packet::BirthGrant { certificate }, &mut acquisition)
        .unwrap();
    let (packet, _) = channel.receive_issuer(&mut acquisition).unwrap();
    assert!(matches!(packet, Packet::BirthChallenge {nonce: value, ..} if value == nonce));
}
