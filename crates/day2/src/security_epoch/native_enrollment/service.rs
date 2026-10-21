use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    birth::IssuerOwner,
    channel::Channel,
    policy::decode_key,
    process::SelfSnapshot,
    protocol::{self, Packet, ProcessData, SignedStage, StageData},
    runtime::{self, RuntimeBinding},
};
use anyhow::{Result, ensure};
use std::collections::BTreeMap;

struct Enrollment {
    public_key: String,
    process: ProcessData,
    runtime: RuntimeBinding,
}

pub(super) fn run() -> Result<()> {
    let mut issuer = IssuerOwner::born()?;
    let mut enrolled = BTreeMap::new();
    loop {
        let (mut channel, mut acquisition) = issuer.listener.next()?;
        // Parent failure terminates the issuer generation. A malformed client
        // consumes and closes only its one connection/acquisition.
        issuer.parent.check_identity(&mut acquisition)?;
        let _ = serve(&mut issuer, &mut enrolled, &mut channel, &mut acquisition);
        let mut check = NativeAcquisition::begin(5)?;
        issuer.parent.check_identity(&mut check)?;
    }
}

fn serve(
    issuer: &mut IssuerOwner,
    enrolled: &mut BTreeMap<(u32, u64, super::NativeRole), Enrollment>,
    channel: &mut Channel,
    acquisition: &mut NativeAcquisition,
) -> Result<()> {
    ensure!(
        super::birth::load_policy(acquisition)? == issuer.policy,
        "native_enrollment_operator_selection_changed"
    );
    let mut current = SelfSnapshot::acquire(&issuer.policy.issuer_code, acquisition)?;
    current.require_node_init(acquisition)?;
    ensure!(
        current.data == issuer.certificate.data.process,
        "native_enrollment_issuer_identity_changed"
    );
    // Parse the closed role before selecting its executable pin. An initial
    // untrusted role header cannot create authority; actual receipt observes
    // kernel process handles and later joins the selected runtime role.
    let (packet, mut peer) = channel.receive_role(&issuer.policy, acquisition)?;
    let Packet::StageHello {
        policy,
        role,
        public_key,
        request,
    } = packet
    else {
        anyhow::bail!("native_enrollment_role_order")
    };
    ensure!(
        policy == issuer.policy.digest()?,
        "native_enrollment_policy_mismatch"
    );
    decode_key(&public_key)?;
    let identity = (peer.data().process, peer.data().start_ticks, role);
    if let Some(existing) = enrolled.get(&identity) {
        ensure!(
            existing.public_key == public_key && existing.process == *peer.data(),
            "native_enrollment_process_rekey_refused"
        );
    } else {
        ensure!(enrolled.len() < 1024, "native_enrollment_table_full");
    }
    runtime::require_common(peer.data(), &issuer.certificate.data.process)?;
    let challenge = protocol::nonce("role-bind")?;
    channel.send(
        &Packet::StageNonce {
            request: request.clone(),
            challenge: challenge.clone(),
        },
        acquisition,
    )?;
    let (packet, mut bound) = channel.receive(issuer.policy.code(role), acquisition)?;
    let Packet::StageBind {
        policy: selected,
        role: selected_role,
        public_key: selected_key,
        request: echoed,
        challenge: answered,
        signature,
    } = packet
    else {
        anyhow::bail!("native_enrollment_role_order")
    };
    ensure!(
        selected == policy
            && selected_role == role
            && selected_key == public_key
            && echoed == request
            && answered == challenge
            && peer.data() == bound.data(),
        "native_enrollment_role_binding"
    );
    protocol::verify(
        &public_key,
        "role-bind",
        &(&policy, role, &public_key, &request, &challenge),
        &signature,
    )?;
    let runtime = runtime::current(&issuer.policy, role, &mut peer, acquisition)?;
    if let Some(existing) = enrolled.get(&identity) {
        ensure!(
            existing.runtime == runtime,
            "native_enrollment_runtime_incarnation_changed"
        );
    }
    issuer.parent.check_identity(acquisition)?;
    issuer.certificate.verify(&issuer.policy)?;
    peer.check_identity(acquisition)?;
    bound.check_identity(acquisition)?;
    let (origin, deadline) = acquisition.interval_data()?;
    let data = StageData {
        issuer: issuer.certificate.digest()?,
        policy,
        role,
        public_key: public_key.clone(),
        challenge,
        request,
        process: peer.data().clone(),
        runtime: runtime.clone(),
        origin_ns: origin.as_nanos().try_into()?,
        deadline_ns: deadline.as_nanos().try_into()?,
    };
    let stage = SignedStage {
        signature: issuer.key.sign("role-stage", &data)?,
        data,
    };
    // Bind before the ambiguous send. Losing a reply never enables a new key
    // or reconstructs the lost native owner from a stored row.
    enrolled.entry(identity).or_insert_with(|| Enrollment {
        public_key,
        process: peer.data().clone(),
        runtime,
    });
    issuer.parent.check_identity(acquisition)?;
    current.check(acquisition)?;
    channel.send(
        &Packet::StageGrant {
            certificate: issuer.certificate.clone(),
            stage: Box::new(stage),
        },
        acquisition,
    )?;
    Ok(())
}
