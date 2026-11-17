//! Separate, bounded installed-output DATA. A valid signature does not create
//! a native peer, a live Controller original, a restore grant or delivery proof.
//! The dedicated receiver must retain actual handles and its local HTTP frame.

#[cfg(target_os = "linux")]
use super::ProtectedRestoreRequest;
use super::RestoreInstalledOutputData;
use super::{ProtectedRestoreInstalledIo, ProtectedRestoreTurn};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::channel::ProtectedRestoreSocketObserver;
use crate::security_epoch::native_enrollment::{
    handshake::{Frame, Protocol, Step},
    protocol::{self, StagePurpose},
    serving_peer_wire::Statement,
    storage_peer_wire::OriginalInterval,
};
use crate::security_epoch::{
    bootstrap::RestoreInstalledOutputLoan,
    native_enrollment::{EnrolledRoleStage, NativeConsumerOrigin, ReceiverProgress},
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, rc::Rc};

pub(in crate::security_epoch::native_enrollment) const DOMAIN: &str =
    "day2-protected-restore-installed-packet-v1";
pub(in crate::security_epoch::native_enrollment) const MAX_PACKET_BYTES: usize = 8192;

#[derive(Clone, Serialize, Deserialize)]
enum Format {
    #[serde(rename = "day2_protected_restore_installed_v1")]
    V1,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct ProtectedRestoreInstalledData {
    format: Format,
    connection: Digest,
    sender: Digest,
    sequence: u64,
    request: Digest,
    original: OriginalInterval,
    output: RestoreInstalledOutputData,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct Packet {
    data: ProtectedRestoreInstalledData,
    signature: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputPhase {
    Prepared,
    Signed,
    Sending,
    Waiting,
    Retry,
    Delivered,
    Refused,
}

/// Closed protocol decisions only. None of these values is authority to sign,
/// poll or send: the owning frame retains all real guards around each effect.
#[derive(Clone, Copy)]
enum OutputEvent {
    Signed,
    BeginSend,
    Sent,
    Blocked,
    SendInterrupted,
    Poll,
    Ready,
    PollInterrupted,
}

impl OutputPhase {
    fn refuse(&mut self) {
        *self = Self::Refused;
    }

    fn next(self, event: OutputEvent) -> Option<Self> {
        match (self, event) {
            (Self::Prepared, OutputEvent::Signed) => Some(Self::Signed),
            (Self::Signed | Self::Retry, OutputEvent::BeginSend) => Some(Self::Sending),
            (Self::Sending, OutputEvent::Sent) => Some(Self::Delivered),
            (Self::Sending, OutputEvent::Blocked) => Some(Self::Waiting),
            (Self::Sending, OutputEvent::SendInterrupted) => Some(Self::Retry),
            (Self::Waiting, OutputEvent::Poll | OutputEvent::PollInterrupted) => {
                Some(Self::Waiting)
            }
            (Self::Waiting, OutputEvent::Ready) => Some(Self::Retry),
            _ => None,
        }
    }
}

/// Dispatch DATA from this sealed frame, never an IO or authority permission.
pub(in crate::security_epoch::native_enrollment) enum InstalledSendStart {
    First,
    Retry,
}

/// Own the actual source socket and negative original with the fixed bounded
/// packet. Only the actual output loan can prepare/sign it. It cannot expose a
/// stage, file descriptor, clock or future grant, or settle the whole restore.
pub(in crate::security_epoch::native_enrollment) struct ProtectedRestoreOutputFrame {
    data: ProtectedRestoreInstalledData,
    original: NativeConsumerOrigin,
    #[cfg(target_os = "linux")]
    socket: ProtectedRestoreSocketObserver,
    bytes: Option<Vec<u8>>,
    phase: OutputPhase,
    _local: PhantomData<Rc<()>>,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <ProtectedRestoreOutputFrame as Ambiguous<_>>::check;
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

impl ProtectedRestoreOutputFrame {
    fn transition(&mut self, event: OutputEvent) -> Result<()> {
        match self.phase.next(event) {
            Some(next) => {
                self.phase = next;
                Ok(())
            }
            None => {
                self.refuse();
                anyhow::bail!("protected_restore_installed_phase_changed")
            }
        }
    }
    pub(super) fn prepare(
        turn: &mut ProtectedRestoreTurn<'_>,
        stage: &mut EnrolledRoleStage<'_>,
        loan: &mut RestoreInstalledOutputLoan<'_, '_, '_>,
    ) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            turn.refuse();
            stage.refuse_serving();
            loan.refuse();
            anyhow::bail!(super::UNAVAILABLE);
        }
        #[cfg(target_os = "linux")]
        {
            turn.require_received_guard(stage)?;
            ensure!(
                matches!(&turn.request, ProtectedRestoreRequest::Authenticate { .. }),
                "protected_restore_authenticate_required"
            );
            let output = {
                let mut storage = stage.storage()?;
                loan.check(&mut storage)?
            };
            let local = stage.protected_restore_statement()?;
            ensure!(
                local.same_enrollment(&turn.peer._local_statement),
                "protected_restore_installed_signer_changed"
            );
            let data = ProtectedRestoreInstalledData::new(
                turn.peer._connection.clone(),
                super::admission::enrollment(&turn.peer._local_statement)?,
                turn.peer._sequence,
                turn.request_commitment.clone(),
                local.original,
                output,
            )?;
            let mut acquisition = stage.narrow_io_acquisition(5)?;
            let socket = turn
                .peer
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .protected_restore_observer(stage, &mut acquisition)?;
            let original = NativeConsumerOrigin::received_protected_restore(stage)?;
            Ok(Self {
                data,
                original,
                socket,
                bytes: None,
                phase: OutputPhase::Prepared,
                _local: PhantomData,
            })
        }
    }

    fn require_phase(&mut self, expected: OutputPhase) -> Result<()> {
        if self.phase == expected {
            return Ok(());
        }
        self.refuse();
        anyhow::bail!("protected_restore_installed_phase_changed")
    }

    pub(super) fn sign(
        &mut self,
        turn: &mut ProtectedRestoreTurn<'_>,
        stage: &mut EnrolledRoleStage<'_>,
        loan: &mut RestoreInstalledOutputLoan<'_, '_, '_>,
    ) -> Result<()> {
        self.require_phase(OutputPhase::Prepared)?;
        let signature = super::super::owner::sign_protected_restore_installed(
            turn,
            stage,
            loan,
            &self.original,
            &self.data,
        )?;
        self.bytes = Some(Packet::encode(self.data.clone(), signature)?);
        self.transition(OutputEvent::Signed)?;
        Ok(())
    }

    pub(in crate::security_epoch::native_enrollment) fn begin_send(
        &mut self,
    ) -> Result<InstalledSendStart> {
        let start = match self.phase {
            OutputPhase::Signed => InstalledSendStart::First,
            OutputPhase::Retry => InstalledSendStart::Retry,
            _ => {
                self.refuse();
                anyhow::bail!("protected_restore_installed_not_sendable")
            }
        };
        self.transition(OutputEvent::BeginSend)?;
        Ok(start)
    }

    pub(in crate::security_epoch::native_enrollment) fn after_send(
        &mut self,
        progress: ReceiverProgress,
    ) -> Result<()> {
        self.require_phase(OutputPhase::Sending)?;
        let event = match progress {
            ReceiverProgress::Delivered => OutputEvent::Sent,
            ReceiverProgress::WouldBlock => OutputEvent::Blocked,
            ReceiverProgress::Interrupted => OutputEvent::SendInterrupted,
            _ => {
                self.refuse();
                anyhow::bail!("protected_restore_installed_send_progress")
            }
        };
        self.transition(event)
    }

    pub(in crate::security_epoch::native_enrollment) fn require_poll(&mut self) -> Result<()> {
        self.transition(OutputEvent::Poll)
    }

    pub(in crate::security_epoch::native_enrollment) fn after_poll(
        &mut self,
        progress: ReceiverProgress,
    ) -> Result<()> {
        self.require_phase(OutputPhase::Waiting)?;
        let event = match progress {
            ReceiverProgress::Advanced => OutputEvent::Ready,
            ReceiverProgress::Interrupted => OutputEvent::PollInterrupted,
            _ => {
                self.refuse();
                anyhow::bail!("protected_restore_installed_poll_progress")
            }
        };
        self.transition(event)
    }

    pub(in crate::security_epoch::native_enrollment) fn packet_frame(&self) -> Frame {
        self.data.frame()
    }

    pub(in crate::security_epoch::native_enrollment) fn bytes(&self) -> Result<&[u8]> {
        ensure!(
            self.phase == OutputPhase::Sending,
            "protected_restore_installed_not_sendable"
        );
        self.bytes
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_installed_signature_missing"))
    }

    pub(in crate::security_epoch::native_enrollment) fn check_loan(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        loan: &mut RestoreInstalledOutputLoan<'_, '_, '_>,
    ) -> Result<()> {
        let output = {
            let mut storage = stage.storage()?;
            loan.check(&mut storage)?
        };
        self.data.require_output(&output)?;
        super::super::owner::check_protected_restore_installed_original(
            stage,
            &self.original,
            &self.data,
        )
    }

    pub(in crate::security_epoch::native_enrollment) fn check_socket(
        &mut self,
        acquisition: &mut crate::security_epoch::native_clock::NativeAcquisition,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            self.refuse();
            acquisition.refuse();
            anyhow::bail!(super::UNAVAILABLE);
        }
        #[cfg(target_os = "linux")]
        {
            let checked = self.socket.check(acquisition);
            if checked.is_err() {
                self.refuse();
                acquisition.refuse();
            }
            checked
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse(&mut self) {
        self.phase.refuse();
        self.original.refuse();
        #[cfg(target_os = "linux")]
        self.socket.refuse();
    }
}

pub(super) fn step(
    turn: &mut ProtectedRestoreTurn<'_>,
    stage: &mut EnrolledRoleStage<'_>,
    loan: &mut RestoreInstalledOutputLoan<'_, '_, '_>,
    operation: ProtectedRestoreInstalledIo,
) -> Result<ReceiverProgress> {
    turn.require_received_guard(stage)?;
    if matches!(operation, ProtectedRestoreInstalledIo::Prepare) {
        ensure!(
            turn.output.is_none(),
            "protected_restore_installed_already_prepared"
        );
        turn.output = Some(ProtectedRestoreOutputFrame::prepare(turn, stage, loan)?);
        return Ok(ReceiverProgress::Advanced);
    }
    let mut frame = turn
        .output
        .take()
        .ok_or_else(|| anyhow::anyhow!("protected_restore_installed_not_prepared"))?;
    // Restore ownership before selecting any error or unwinding. The actual
    // turn retains the frame through its independent whole/native posts.
    let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<ReceiverProgress> {
            turn.require_installed_binding(&frame.data)?;
            match operation {
                ProtectedRestoreInstalledIo::Sign => {
                    frame.sign(turn, stage, loan)?;
                    Ok(ReceiverProgress::Advanced)
                }
                #[cfg(target_os = "linux")]
                ProtectedRestoreInstalledIo::Send | ProtectedRestoreInstalledIo::Poll => {
                    let mut acquisition = stage.narrow_io_acquisition(5)?;
                    let channel = turn
                        .peer
                        .channel
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?;
                    match operation {
                        ProtectedRestoreInstalledIo::Send => channel.send_protected_installed(
                            &mut frame,
                            stage,
                            loan,
                            &mut acquisition,
                        ),
                        ProtectedRestoreInstalledIo::Poll => channel.poll_protected_installed(
                            &mut frame,
                            stage,
                            loan,
                            &mut acquisition,
                        ),
                        _ => unreachable!(),
                    }
                }
                _ => anyhow::bail!(super::UNAVAILABLE),
            }
        },
    ));
    turn.output = Some(frame);
    match requested {
        Err(payload) => std::panic::resume_unwind(payload),
        Ok(result) => result,
    }
}

impl ProtectedRestoreInstalledData {
    pub(in crate::security_epoch::native_enrollment) fn original(&self) -> &OriginalInterval {
        &self.original
    }

    pub(in crate::security_epoch::native_enrollment) fn into_output(
        self,
    ) -> RestoreInstalledOutputData {
        self.output
    }
    /// Metadata construction only. The fixed signer separately requires the
    /// actual installed-output loan and current native owner at the key use.
    fn new(
        connection: Digest,
        sender: Digest,
        sequence: u64,
        request: Digest,
        original: OriginalInterval,
        output: RestoreInstalledOutputData,
    ) -> Result<Self> {
        let data = Self {
            format: Format::V1,
            connection,
            sender,
            sequence,
            request,
            original,
            output,
        };
        data.validate()?;
        Ok(data)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.sequence > 0
                && self.original.purpose == StagePurpose::CurrentRole
                && self.original.deadline_ns > self.original.origin_ns
                && u128::from(self.original.deadline_ns - self.original.origin_ns)
                    <= StagePurpose::CurrentRole.limit().as_nanos(),
            "protected_restore_installed_interval_shape"
        );
        ensure!(
            self.output.target.binding_generation > 0
                && self.output.target.security_epoch > 0
                && (1..=256).contains(&self.output.executor.email.len())
                && !self.output.executor.email.chars().any(char::is_control)
                && (1..=1024).contains(&self.output.executor.subject.len())
                && !self.output.executor.subject.chars().any(char::is_control),
            "protected_restore_installed_output_shape"
        );
        Ok(())
    }

    pub(in crate::security_epoch::native_enrollment) fn commitment(&self) -> Result<Digest> {
        Digest::of(&(DOMAIN, self))
    }

    pub(in crate::security_epoch::native_enrollment) fn frame(&self) -> Frame {
        Frame {
            protocol: Protocol::ProtectedRestoreCommand,
            step: Step::Complete,
            sequence: Some(self.sequence),
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn require_binding(
        &self,
        connection: &Digest,
        sender: &Digest,
        sequence: u64,
        request: &Digest,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            self.connection == *connection
                && self.sender == *sender
                && self.sequence == sequence
                && self.request == *request,
            "protected_restore_installed_binding_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch::native_enrollment) fn require_signer(
        &self,
        local: &Statement,
        admitted: &Statement,
    ) -> Result<()> {
        ensure!(
            local.stage.data.role == super::super::NativeRole::EpochController
                && local.same_enrollment(admitted),
            "protected_restore_installed_signer_changed"
        );
        self.require_binding(
            &self.connection,
            &super::admission::enrollment(admitted)?,
            self.sequence,
            &self.request,
        )?;
        self.require_original(&local.original)
    }

    pub(in crate::security_epoch::native_enrollment) fn require_original(
        &self,
        original: &OriginalInterval,
    ) -> Result<()> {
        ensure!(
            self.original == *original,
            "protected_restore_installed_original_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch::native_enrollment) fn require_output(
        &self,
        output: &RestoreInstalledOutputData,
    ) -> Result<()> {
        ensure!(
            self.output == *output,
            "protected_restore_installed_target_changed"
        );
        Ok(())
    }
}

impl Packet {
    pub(in crate::security_epoch::native_enrollment) fn encode(
        data: ProtectedRestoreInstalledData,
        signature: String,
    ) -> Result<Vec<u8>> {
        data.validate()?;
        super::wire::signature_shape(&signature)?;
        let bytes = serde_json::to_vec(&Self { data, signature })?;
        ensure!(
            bytes.len() <= MAX_PACKET_BYTES,
            "protected_restore_installed_packet_bound"
        );
        Ok(bytes)
    }

    pub(in crate::security_epoch::native_enrollment) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_PACKET_BYTES,
            "protected_restore_installed_packet_bound"
        );
        let value: serde_json::Value = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("protected_restore_installed_packet_encoding"))?;
        // Serde also accepts sequence-shaped structs; require this version's
        // concrete object form at every nested record before typed decoding.
        ensure!(
            value.is_object(),
            "protected_restore_installed_object_required"
        );
        for path in [
            "/data",
            "/data/original",
            "/data/output",
            "/data/output/target",
            "/data/output/target/scope",
            "/data/output/executor",
        ] {
            ensure!(
                value
                    .pointer(path)
                    .is_some_and(serde_json::Value::is_object),
                "protected_restore_installed_object_required"
            );
        }
        ensure!(
            value
                .pointer("/data/format")
                .is_some_and(serde_json::Value::is_string),
            "protected_restore_installed_version_required"
        );
        ensure!(
            value
                .pointer("/data/original/purpose")
                .is_some_and(serde_json::Value::is_string),
            "protected_restore_installed_purpose_required"
        );
        let packet: Self = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("protected_restore_installed_packet_encoding"))?;
        super::wire::signature_shape(&packet.signature)?;
        packet.data.validate()?;
        Ok(packet)
    }

    pub(in crate::security_epoch::native_enrollment) fn frame(&self) -> Frame {
        self.data.frame()
    }

    pub(in crate::security_epoch::native_enrollment) fn verify_data(
        self,
        key: &str,
    ) -> Result<ProtectedRestoreInstalledData> {
        protocol::verify(key, DOMAIN, &self.data.commitment()?, &self.signature)?;
        Ok(self.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::native_enrollment::protocol::KeyOwner;

    fn data() -> Result<ProtectedRestoreInstalledData> {
        let request = crate::security_epoch::restore_approval::fixture_request_data()?;
        ProtectedRestoreInstalledData::new(
            Digest::new(b"connection"),
            Digest::new(b"sender"),
            u64::MAX,
            Digest::new(b"exact signed Authenticate request"),
            OriginalInterval {
                purpose: StagePurpose::CurrentRole,
                domain: Digest::new(b"historical Controller interval DATA"),
                origin_ns: u64::MAX - 5_000_000_000,
                deadline_ns: u64::MAX,
            },
            RestoreInstalledOutputData {
                approval: request.commitment()?,
                operation: Digest::new(b"actual operation DATA"),
                full_archive: request.full_archive_digest,
                target: request.target,
                executor: request.executor,
                installed: Digest::new(b"installed report and cohort DATA"),
            },
        )
    }

    fn signed(data: ProtectedRestoreInstalledData, key: &KeyOwner) -> Result<Vec<u8>> {
        let signature = key.sign(DOMAIN, &data.commitment()?)?;
        Packet::encode(data, signature)
    }

    #[test]
    fn seeded_output_histories_match_independent_obligations_and_absorbing_uncertainty() {
        // Actual decision reducer, not an enrolled owner or positive loan.
        // The oracle derives obligations from the complete accepted history,
        // not a second state transition table.
        #[derive(Default)]
        struct History {
            events: Vec<usize>,
            poisoned: bool,
        }
        impl History {
            fn count(&self, event: usize) -> usize {
                self.events
                    .iter()
                    .filter(|actual| **actual == event)
                    .count()
            }
            fn outstanding(&self) -> usize {
                self.count(1) - self.count(2) - self.count(3) - self.count(4)
            }
            fn waiting(&self) -> usize {
                self.count(3) - self.count(6)
            }
            fn credit(&self) -> usize {
                self.count(0) + self.count(4) + self.count(6) - self.count(1)
            }
            fn admits(&self, event: usize) -> bool {
                if self.poisoned || self.count(2) > 0 {
                    return false;
                }
                match event {
                    0 => self.events.is_empty(),
                    1 => {
                        self.count(0) == 1
                            && self.outstanding() == 0
                            && self.waiting() == 0
                            && self.credit() == 1
                    }
                    2..=4 => self.outstanding() == 1,
                    5..=7 => self.waiting() == 1 && self.outstanding() == 0,
                    _ => false,
                }
            }
            fn agrees(&self, phase: OutputPhase) -> bool {
                if self.poisoned {
                    return phase == OutputPhase::Refused;
                }
                if self.count(2) == 1 {
                    return phase == OutputPhase::Delivered;
                }
                if self.outstanding() == 1 {
                    return phase == OutputPhase::Sending;
                }
                if self.waiting() == 1 {
                    return phase == OutputPhase::Waiting;
                }
                if self.count(0) == 0 {
                    return phase == OutputPhase::Prepared;
                }
                if self.count(1) == 0 {
                    phase == OutputPhase::Signed
                } else {
                    phase == OutputPhase::Retry
                }
            }
        }
        let events = [
            OutputEvent::Signed,
            OutputEvent::BeginSend,
            OutputEvent::Sent,
            OutputEvent::Blocked,
            OutputEvent::SendInterrupted,
            OutputEvent::Poll,
            OutputEvent::Ready,
            OutputEvent::PollInterrupted,
        ];
        let successful = [0, 1, 3, 5, 7, 5, 6, 1, 4, 1, 2];
        for seed in 0..256_u64 {
            let mut phase = OutputPhase::Prepared;
            let mut history = History::default();
            let mut schedule = seed + 1;
            for step in 0..64 {
                schedule ^= schedule << 13;
                schedule ^= schedule >> 7;
                schedule ^= schedule << 17;
                let event = if step < successful.len() && seed % 2 == 0 {
                    successful[step]
                } else {
                    (schedule % 13) as usize
                };
                if event >= 8 {
                    // Explicit negative obligations: actual frame refusal is
                    // absorbing for expiry, carrier/socket failure, ordinary
                    // Result error and unwinding. Kernel effects themselves
                    // remain covered by conformance and source wiring tests.
                    phase.refuse();
                    history.poisoned = true;
                } else {
                    let admitted = history.admits(event);
                    let actual = phase.next(events[event]);
                    assert_eq!(
                        actual.is_some(),
                        admitted,
                        "seed={seed},step={step},event={event}"
                    );
                    if admitted {
                        history.events.push(event);
                        phase = actual.unwrap();
                    } else {
                        history.poisoned = true;
                        phase.refuse();
                    }
                }
                assert!(
                    history.agrees(phase),
                    "seed={seed},step={step},event={event}"
                );
                assert!(history.count(2) <= 1);
                if history.poisoned {
                    for event in events {
                        assert!(phase.next(event).is_none());
                    }
                }
            }
            if seed % 2 == 0 {
                assert_eq!(history.count(2), 1);
            }
        }
    }

    #[test]
    fn terminal_packet_roundtrips_fixed_output_and_exact_request_without_granting_native_authority()
    -> Result<()> {
        let key = KeyOwner::generate()?;
        let expected = data()?;
        let original = serde_json::to_value(&expected)?;
        let packet = signed(expected.clone(), &key)?;
        let actual = Packet::decode(&packet)?.verify_data(&key.public())?;
        assert_eq!(serde_json::to_value(&actual)?, original);
        actual.require_binding(
            &expected.connection,
            &expected.sender,
            expected.sequence,
            &expected.request,
        )?;
        assert_eq!(
            actual.frame(),
            Frame {
                protocol: Protocol::ProtectedRestoreCommand,
                step: Step::Complete,
                sequence: Some(u64::MAX)
            }
        );
        assert!(super::super::wire::UnverifiedPacket::decode(&packet).is_err());
        Ok(())
    }

    #[test]
    fn terminal_packet_rejects_every_modified_binding_output_and_foreign_signature() -> Result<()> {
        let key = KeyOwner::generate()?;
        let foreign = KeyOwner::generate()?;
        let original = signed(data()?, &key)?;
        assert!(
            Packet::decode(&original)?
                .verify_data(&foreign.public())
                .is_err()
        );
        let value: serde_json::Value = serde_json::from_slice(&original)?;
        for path in [
            "/data/connection",
            "/data/sender",
            "/data/request",
            "/data/original/domain",
            "/data/output/approval",
            "/data/output/operation",
            "/data/output/full_archive",
            "/data/output/target/authority",
            "/data/output/target/selection",
            "/data/output/target/incarnation",
            "/data/output/target/artifact",
            "/data/output/target/schema",
            "/data/output/installed",
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(path).unwrap() =
                serde_json::json!(Digest::new(b"foreign well-shaped DATA"));
            assert!(
                Packet::decode(&serde_json::to_vec(&changed)?)?
                    .verify_data(&key.public())
                    .is_err(),
                "{path}"
            );
        }
        for path in [
            "/data/sequence",
            "/data/original/origin_ns",
            "/data/original/deadline_ns",
            "/data/output/target/security_epoch",
            "/data/output/target/binding_generation",
        ] {
            let mut changed = value.clone();
            let old = changed.pointer(path).unwrap().as_u64().unwrap();
            *changed.pointer_mut(path).unwrap() = serde_json::json!(old - 1);
            assert!(
                Packet::decode(&serde_json::to_vec(&changed)?)
                    .and_then(|p| p.verify_data(&key.public()))
                    .is_err(),
                "{path}"
            );
        }
        for (path, value) in [
            ("/data/output/target/scope/installation", "other-instance"),
            ("/data/output/target/scope/environment", "other-env"),
            ("/data/output/target/scope/app", "other-app"),
            ("/data/output/executor/email", "other@example.org"),
            ("/data/output/executor/subject", "other-subject"),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&original)?;
            *changed.pointer_mut(path).unwrap() = serde_json::json!(value);
            assert!(
                Packet::decode(&serde_json::to_vec(&changed)?)?
                    .verify_data(&key.public())
                    .is_err(),
                "{path}"
            );
        }
        Ok(())
    }

    #[test]
    fn valid_foreign_world_packets_and_constant_or_command_signatures_cannot_match_the_actual_exchange()
    -> Result<()> {
        let key = KeyOwner::generate()?;
        let expected = data()?;
        for field in 0..4 {
            let mut foreign = expected.clone();
            match field {
                0 => foreign.connection = Digest::new(b"other connection"),
                1 => foreign.sender = Digest::new(b"other sender"),
                2 => foreign.sequence -= 1,
                _ => foreign.request = Digest::new(b"other Authenticate"),
            }
            let decoded = Packet::decode(&signed(foreign, &key)?)?.verify_data(&key.public())?;
            assert!(
                decoded
                    .require_binding(
                        &expected.connection,
                        &expected.sender,
                        expected.sequence,
                        &expected.request
                    )
                    .is_err()
            );
        }
        for signature in [
            key.sign(DOMAIN, &Digest::new(b"constant"))?,
            key.sign(super::super::wire::SIGNING_DOMAIN, &expected.commitment()?)?,
        ] {
            assert!(
                Packet::decode(&Packet::encode(expected.clone(), signature)?)?
                    .verify_data(&key.public())
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn valid_resigned_foreign_output_and_original_cannot_match_the_actual_expected_data()
    -> Result<()> {
        let key = KeyOwner::generate()?;
        let expected = data()?;
        for field in 0..6 {
            let mut foreign = expected.clone();
            match field {
                0 => foreign.output.target.security_epoch += 1,
                1 => foreign.output.target.incarnation = Digest::new(b"other target"),
                2 => foreign.output.executor.subject = "other subject".into(),
                3 => foreign.output.installed = Digest::new(b"other installed report"),
                4 => foreign.output.approval = Digest::new(b"other approval"),
                _ => foreign.output.operation = Digest::new(b"other operation"),
            }
            let actual = Packet::decode(&signed(foreign, &key)?)?.verify_data(&key.public())?;
            assert!(actual.require_output(&expected.output).is_err(), "{field}");
        }
        for field in 0..3 {
            let mut foreign = expected.clone();
            match field {
                0 => foreign.original.domain = Digest::new(b"other original"),
                1 => foreign.original.origin_ns += 1,
                _ => foreign.original.deadline_ns -= 1,
            }
            let actual = Packet::decode(&signed(foreign, &key)?)?.verify_data(&key.public())?;
            assert!(
                actual.require_original(&expected.original).is_err(),
                "{field}"
            );
        }
        expected.require_output(&expected.output)?;
        expected.require_original(&expected.original)?;
        Ok(())
    }

    #[test]
    fn installed_signing_data_requires_the_actual_controller_role_and_first_enrollment()
    -> Result<()> {
        use crate::security_epoch::native_enrollment::NativeRole;
        let local = super::super::admission::fixture_statement_data(NativeRole::EpochController);
        let mut data = data()?;
        data.original = local.original.clone();
        data.sender = super::super::admission::enrollment(&local)?;
        data.require_signer(&local, &local)?;
        let foreign = super::super::admission::fixture_statement_data(NativeRole::EpochController);
        assert!(data.require_signer(&foreign, &local).is_err());
        let shell = super::super::admission::fixture_statement_data(NativeRole::SecurityShell);
        assert!(data.require_signer(&shell, &shell).is_err());
        let mut changed = local.clone();
        changed.original.deadline_ns -= 1;
        assert!(data.require_signer(&changed, &local).is_err());
        Ok(())
    }

    #[test]
    fn terminal_packet_refuses_noncanonical_nested_shapes_and_unknown_versions() -> Result<()> {
        let key = KeyOwner::generate()?;
        let original = signed(data()?, &key)?;
        let value: serde_json::Value = serde_json::from_slice(&original)?;
        for path in [
            "/data",
            "/data/original",
            "/data/output",
            "/data/output/target",
            "/data/output/target/scope",
            "/data/output/executor",
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(path).unwrap() = serde_json::json!([]);
            assert!(
                Packet::decode(&serde_json::to_vec(&changed)?).is_err(),
                "{path}"
            );
        }
        let mut extra = value.clone();
        extra["data"]["output"]["extra"] = serde_json::Value::Bool(true);
        assert!(Packet::decode(&serde_json::to_vec(&extra)?).is_err());
        let mut aliased = value.clone();
        aliased["data"]["original"]["purpose"] = serde_json::json!({"current_role":null});
        assert!(Packet::decode(&serde_json::to_vec(&aliased)?).is_err());
        let duplicated = format!(
            "{{\"data\":{},\"data\":{},\"signature\":{}}}",
            value["data"], value["data"], value["signature"]
        );
        assert!(Packet::decode(duplicated.as_bytes()).is_err());
        let mut version = value;
        version["data"]["format"] = serde_json::json!("other");
        assert!(Packet::decode(&serde_json::to_vec(&version)?).is_err());
        assert!(Packet::decode(&vec![b' '; MAX_PACKET_BYTES + 1]).is_err());
        Ok(())
    }

    #[test]
    fn terminal_output_with_full_identity_bounds_and_escaped_bytes_fits_the_fixed_native_packet()
    -> Result<()> {
        let key = KeyOwner::generate()?;
        let mut data = data()?;
        data.output.executor.email = format!("{}@x.org", "a".repeat(250));
        data.output.executor.subject = "\\".repeat(1024);
        data.output.target.scope.installation = day2_capabilities::Name::try_from("a".repeat(80))?;
        data.output.target.scope.environment = day2_capabilities::Name::try_from("b".repeat(80))?;
        data.output.target.scope.app = day2_capabilities::Name::try_from("c".repeat(80))?;
        let encoded = signed(data, &key)?;
        assert!(encoded.len() <= MAX_PACKET_BYTES);
        Packet::decode(&encoded)?.verify_data(&key.public())?;
        Ok(())
    }
}

#[cfg(test)]
mod source_controls {
    use quote::ToTokens;

    fn normalize_statement(statement: &syn::Stmt) -> String {
        fn statement_value(statement: &mut syn::Stmt) {
            match statement {
                syn::Stmt::Local(local) => {
                    if let Some(init) = &mut local.init {
                        expression(&mut init.expr);
                    }
                }
                syn::Stmt::Expr(value, _) => expression(value),
                _ => {}
            }
        }
        fn expression(value: &mut syn::Expr) {
            match value {
                syn::Expr::Call(call) => {
                    expression(&mut call.func);
                    for arg in &mut call.args {
                        expression(arg);
                    }
                    call.args.pop_punct();
                }
                syn::Expr::MethodCall(call) => {
                    expression(&mut call.receiver);
                    for arg in &mut call.args {
                        expression(arg);
                    }
                    call.args.pop_punct();
                }
                syn::Expr::Closure(closure) => {
                    expression(&mut closure.body);
                    if let syn::Expr::Block(block) = &*closure.body
                        && block.attrs.is_empty()
                        && block.label.is_none()
                        && let [syn::Stmt::Expr(inner, None)] = block.block.stmts.as_slice()
                    {
                        closure.body = Box::new(inner.clone());
                    }
                }
                syn::Expr::Block(block) => {
                    for stmt in &mut block.block.stmts {
                        statement_value(stmt);
                    }
                }
                syn::Expr::ForLoop(value) => {
                    expression(&mut value.expr);
                    for stmt in &mut value.body.stmts {
                        statement_value(stmt);
                    }
                }
                syn::Expr::Loop(value) => {
                    for stmt in &mut value.body.stmts {
                        statement_value(stmt);
                    }
                }
                syn::Expr::While(value) => {
                    expression(&mut value.cond);
                    for stmt in &mut value.body.stmts {
                        statement_value(stmt);
                    }
                }
                syn::Expr::Try(attempt) => expression(&mut attempt.expr),
                syn::Expr::Reference(reference) => expression(&mut reference.expr),
                syn::Expr::Paren(paren) => expression(&mut paren.expr),
                syn::Expr::Field(field) => expression(&mut field.base),
                syn::Expr::Assign(assign) => {
                    expression(&mut assign.left);
                    expression(&mut assign.right);
                }
                syn::Expr::Struct(value) => {
                    for field in &mut value.fields {
                        expression(&mut field.expr);
                    }
                }
                syn::Expr::Match(value) => {
                    expression(&mut value.expr);
                    for arm in &mut value.arms {
                        expression(&mut arm.body);
                    }
                }
                syn::Expr::If(value) => {
                    expression(&mut value.cond);
                    for stmt in &mut value.then_branch.stmts {
                        statement_value(stmt);
                    }
                    if let Some((_, other)) = &mut value.else_branch {
                        expression(other);
                    }
                }
                _ => {}
            }
        }
        let mut statement = statement.clone();
        statement_value(&mut statement);
        statement.to_token_stream().to_string()
    }

    fn text(node: &impl ToTokens) -> String {
        let tokens = node.to_token_stream();
        if let Ok(statement) = syn::parse2::<syn::Stmt>(tokens.clone()) {
            return normalize_statement(&statement);
        }
        if let Ok(expression) = syn::parse2::<syn::Expr>(tokens.clone()) {
            return normalize_statement(&syn::Stmt::Expr(expression, None));
        }
        tokens.to_string()
    }

    fn method(source: &str, owner: &str, name: &str) -> syn::Block {
        let file = syn::parse_file(source).unwrap();
        let mut found = Vec::new();
        for item in file.items {
            if let syn::Item::Impl(item) = item {
                if matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident==owner))
                {
                    for method in item.items {
                        if let syn::ImplItem::Fn(method) = method {
                            if method.sig.ident == name {
                                found.push(method.block);
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(found.len(), 1, "{owner}::{name}");
        found.pop().unwrap()
    }
    fn function(source: &str, name: &str) -> syn::Block {
        let mut found = syn::parse_file(source)
            .unwrap()
            .items
            .into_iter()
            .filter_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == name => Some(*item.block),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(found.len(), 1, "{name}");
        found.pop().unwrap()
    }
    fn expression(source: &str) -> String {
        text(&syn::parse_str::<syn::Expr>(source).unwrap())
    }
    fn statement(source: &str) -> String {
        text(&syn::parse_str::<syn::Stmt>(source).unwrap())
    }
    fn required(body: &syn::Block, parts: &[String]) -> bool {
        let source = text(body);
        parts.iter().all(|part| source.matches(part).count() == 1)
    }
    fn reject_deletions(body: &syn::Block, parts: &[String]) {
        for part in parts {
            assert_eq!(
                text(body).matches(part).count(),
                1,
                "actual unique guard: {part}"
            );
        }
        let source = text(body);
        for part in parts {
            assert_eq!(source.matches(part).count(), 1);
            let changed: syn::Block = syn::parse_str(&source.replacen(part, "", 1)).unwrap();
            assert!(!required(&changed, parts), "missing actual guard: {part}");
        }
    }

    #[test]
    fn normalization_reaches_the_actual_receipt_loop_without_erasing_its_guards() {
        let guard = method(
            include_str!("courier.rs"),
            "ProtectedRestoreShellTerminalGuard",
            "check",
        );
        let target = expression(
            "receipt.check_protected_restore_bound(&self.shell._remote_statement,acquisition)",
        );
        assert_eq!(text(&guard).matches(&target).count(), 1);
        let formatted:syn::Stmt=syn::parse_str("for sender in &mut self.shell._sender {receipt.check_protected_restore_bound(&self.shell._remote_statement,acquisition,)?;}").unwrap();
        let expected: syn::Stmt = syn::parse_quote!(for sender in &mut self.shell._sender {
            receipt.check_protected_restore_bound(&self.shell._remote_statement, acquisition)?;
        });
        assert_ne!(
            formatted.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        assert_eq!(text(&formatted), text(&expected));
        let foreign: syn::Stmt = syn::parse_quote!(for sender in &mut foreign._sender {
            receipt.check_protected_restore_bound(&self.shell._remote_statement, acquisition)?;
        });
        assert_ne!(text(&formatted), text(&foreign));
        let waits: syn::Stmt = syn::parse_quote!(for sender in &mut self.shell._sender {
            wait()?;
            receipt.check_protected_restore_bound(&self.shell._remote_statement, acquisition)?;
        });
        assert_ne!(text(&formatted), text(&waits));
    }

    #[test]
    fn fixed_terminal_signer_keeps_the_actual_carrier_check_immediately_before_key_use() {
        let body = function(
            include_str!("../owner/protected_restore.rs"),
            "sign_protected_restore_installed",
        );
        let linux: syn::Attribute = syn::parse_quote!(#[cfg(target_os="linux")]);
        let blocks = body
            .stmts
            .iter()
            .filter_map(|stmt| match stmt {
                syn::Stmt::Expr(syn::Expr::Block(block), _)
                    if block.attrs.iter().any(|attr| text(attr) == text(&linux)) =>
                {
                    Some(block.block.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(blocks.len(), 1);
        let body = blocks[0].clone();
        let source = text(&body);
        let tail: syn::Block = syn::parse_quote!({
            let output = {
                let mut storage = stage.storage()?;
                loan.check(&mut storage)?
            };
            data.require_output(&output)?;
            check_protected_restore_installed_original(stage, original, data)?;
            stage.owner.key.sign(crate::security_epoch::native_enrollment::protected_restore::INSTALLED_SIGNING_DOMAIN,&commitment)
        });
        let tail = text(&tail);
        let tail = tail.strip_prefix("{ ").unwrap().strip_suffix(" }").unwrap();
        assert_eq!(source.matches(tail).count(), 1);
        let parts = [
            statement("turn.require_received_guard(stage)?;"),
            statement("turn.require_installed_binding(data)?;"),
            statement("data.require_signer(&local,turn.admitted_statement()?)?;"),
            statement("loan.refuse();"),
            statement("original.refuse();"),
        ];
        reject_deletions(&body, &parts);
        let binder = function(
            include_str!("../owner/protected_restore.rs"),
            "check_protected_restore_installed_original",
        );
        let source = text(&binder);
        for forbidden in [
            ". check (",
            "require_purpose",
            "require_protected_restore_role",
            "storage (",
            "protected_restore_statement (",
            "begin_current",
            "NativeAcquisition ::",
        ] {
            assert!(
                !source.contains(forbidden),
                "last carrier/sign gap: {forbidden}"
            );
        }
        let parts = [
            statement("original.require_acquisition(stage.acquisition.as_mut())?;"),
            statement("data.require_original(&actual)?;"),
            expression("stage.acquisition.as_mut().remaining().map(|_|())"),
        ];
        // An expression cannot be deleted alone without making invalid Rust;
        // replace it with a valid constant-result counterexample instead.
        assert!(required(&binder, &parts));
        for (index, part) in parts.iter().enumerate() {
            let replacement = if index < 2 {
                statement("let _=();")
            } else {
                expression("Ok(())")
            };
            let changed: syn::Block =
                syn::parse_str(&source.replacen(part, &replacement, 1)).unwrap();
            assert!(!required(&changed, &parts));
        }
    }

    #[test]
    fn actual_terminal_courier_moves_the_whole_box_before_data_and_never_rechecks_a_retired_grant()
    {
        let body = function(include_str!("courier.rs"), "authenticate");
        let source = text(&body);
        let parts = [
            statement("let commitment=data.commitment()?;"),
            statement(
                "data.require_binding(&active._connection,&admission::enrollment(&active._remote_statement)?,sequence,&commitment)?;",
            ),
            statement(
                "receipt.bind_admitted(&statement,admitted,&active._remote_statement,stage,&mut acquisition)?;",
            ),
            statement("guard.attach_to_request(stage)?;"),
            expression(
                "shell.take().ok_or_else(||anyhow::anyhow!(\"protected_restore_terminal_courier_missing\"))?",
            ),
        ];
        assert!(required(&body, &parts));
        for part in &parts[..4] {
            let changed: syn::Block = syn::parse_str(&source.replacen(part, "", 1)).unwrap();
            assert!(!required(&changed, &parts));
        }
        assert!(source.find(&parts[4]).unwrap() < source.find(&parts[3]).unwrap());
        assert!(source.find(&parts[3]).unwrap() < source.find(&expression("Ok(output)")).unwrap());
        for forbidden in [
            "validate_request",
            "check_admitted_serving_statement",
            "begin_current_stage",
            "begin_current_request",
            "from_native",
            "restore_current",
        ] {
            assert!(!source.contains(forbidden), "{forbidden}");
        }
        let guard = method(
            include_str!("courier.rs"),
            "ProtectedRestoreShellTerminalGuard",
            "check",
        );
        let parts = [
            statement("self.original.require_acquisition(acquisition)?;"),
            statement("self.socket.require_channel(channel)?;"),
            expression("self.socket.check(acquisition)"),
            expression("self.receipt.check_protected_restore_bound(&self.remote,acquisition)"),
            expression(
                "receipt.check_protected_restore_bound(&self.shell._remote_statement,acquisition)",
            ),
        ];
        assert!(required(&guard, &parts));
        assert!(!text(&guard).contains("validate_request"));
        assert!(!text(&guard).contains("stage ."));
        let refused = method(
            include_str!("courier.rs"),
            "ProtectedRestoreShellTerminalGuard",
            "refuse",
        );
        assert!(!text(&refused).contains("self . shell . refuse ("));
        assert!(!text(&refused).contains("channel ="));
        assert!(text(&refused).contains(&statement("self.shell.refused.set(true);")));
    }

    #[test]
    fn frame_operations_require_the_actual_turn_channel_and_original_not_just_equal_packet_data() {
        let step = function(include_str!("terminal.rs"), "step");
        let parts = [
            statement("turn.require_received_guard(stage)?;"),
            statement("turn.require_installed_binding(&frame.data)?;"),
            statement(
                r#"let channel=turn.peer.channel.as_mut().ok_or_else(||anyhow::anyhow!("protected_restore_channel_closed"))?;"#,
            ),
        ];
        reject_deletions(&step, &parts);
        let source = text(&step);
        assert!(source.find(&parts[1]).unwrap() < source.find("match operation").unwrap());
        let foreign=source.replacen(&parts[2],&statement(r#"let channel=foreign.peer.channel.as_mut().ok_or_else(||anyhow::anyhow!("protected_restore_channel_closed"))?;"#),1);
        assert!(!required(&syn::parse_str(&foreign).unwrap(), &parts));
        let local=step.stmts.iter().find_map(|stmt|match stmt {syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="requested")=>Some(local),_=>None}).unwrap();
        let syn::Expr::Call(catch) = &*local.init.as_ref().unwrap().expr else {
            panic!("actual catch");
        };
        let syn::Expr::Call(safe) = &catch.args[0] else {
            panic!("actual unwind boundary");
        };
        let syn::Expr::Closure(closure) = &safe.args[0] else {
            panic!("actual closure");
        };
        let syn::Expr::Block(body) = &*closure.body else {
            panic!("actual executed body");
        };
        let prefix = |body: &syn::Block| {
            body.stmts.len() == 2
                && text(&body.stmts[0]) == parts[1]
                && matches!(&body.stmts[1], syn::Stmt::Expr(syn::Expr::Match(_), None))
        };
        assert!(prefix(&body.block));
        let mut moved = body.block.clone();
        moved.stmts.swap(0, 1);
        assert!(!prefix(&moved));
        let mut missing = body.block.clone();
        missing.stmts.remove(0);
        assert!(!prefix(&missing));
        let check = method(
            include_str!("terminal.rs"),
            "ProtectedRestoreOutputFrame",
            "check_loan",
        );
        let expected: syn::Block = syn::parse_quote!({
            let output = {
                let mut storage = stage.storage()?;
                loan.check(&mut storage)?
            };
            self.data.require_output(&output)?;
            super::super::owner::check_protected_restore_installed_original(
                stage,
                &self.original,
                &self.data,
            )
        });
        assert_eq!(text(&check), text(&expected));
        for index in 0..check.stmts.len() {
            let mut changed = check.clone();
            changed.stmts.remove(index);
            assert_ne!(text(&changed), text(&expected));
        }
        let pending = method(
            include_str!("courier.rs"),
            "ProtectedRestoreShellTerminalGuard",
            "check",
        );
        assert!(required(
            &pending,
            &[
                expression("self.receipt.check_protected_restore_bound(&self.remote,acquisition)"),
                expression(
                    "receipt.check_protected_restore_bound(&self.shell._remote_statement,acquisition)"
                )
            ]
        ));
    }

    #[test]
    fn installed_send_has_one_syscall_with_full_independent_posts_and_no_hidden_retry() {
        let body = method(
            include_str!("../channel/protected_restore.rs"),
            "Channel",
            "send_protected_installed",
        );
        let source = text(&body);
        assert_eq!(source.matches("net :: send").count(), 1);
        for forbidden in [
            "loop ",
            "while ",
            "wait (",
            "self . transport (",
            ". sign (",
        ] {
            assert!(!source.contains(forbidden), "{forbidden}");
        }
        assert_eq!(
            source
                .matches(&expression(
                    "self.check_protected_installed(frame,stage,loan,acquisition)"
                ))
                .count(),
            2
        );
        assert_eq!(source.matches(&statement("loan.refuse();")).count(), 2);
        let parts = [
            expression("self.packet_delivered(Some(frame.packet_frame()),acquisition)?"),
            statement("frame.after_send(progress)?;"),
        ];
        assert!(required(&body, &parts));
        let check = method(
            include_str!("../channel/protected_restore.rs"),
            "Channel",
            "check_protected_installed",
        );
        let parts = [
            expression("self.check_protected_open(stage,acquisition)"),
            expression("frame.check_socket(acquisition)"),
            expression("frame.check_loan(stage,loan)"),
        ];
        assert!(required(&check, &parts));
        assert!(text(&check).find(&parts[0]).unwrap() < text(&check).find(&parts[2]).unwrap());
        let receive = method(
            include_str!("../channel/protected_restore.rs"),
            "Channel",
            "receive_protected_installed",
        );
        let source = text(&receive);
        assert!(
            source
                .find(&statement(
                    "sender=Some(ControllerReceipt::receive(received,acquisition)?);"
                ))
                .unwrap()
                < source
                    .find(&expression(
                        "UnverifiedInstalledPacket::decode(&bytes[..count])?"
                    ))
                    .unwrap()
        );
        assert!(source.contains(&expression("receipt.check_received(acquisition)")));
        let step = function(include_str!("terminal.rs"), "step");
        let source = text(&step);
        assert!(
            source.find(&statement("turn.output=Some(frame);")).unwrap()
                < source.find("match requested").unwrap()
        );
    }
}
