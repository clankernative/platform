//! One bounded native receiver operation at a time, on the genuine prepared
//! issuer lifetime. The full restore context brackets each call. These actual
//! socket resources do not constitute a completed App exchange, P3 or writer.
use super::super::{RestoredCurrentPeerPort, RestoredPeerSource};
use super::{
    ActivatedRestoredAppRole, CompletedRestoreIssuer, DecisionHandoffAttempt, EnrolledRoleStage,
    EnrolledStorageStage, InstalledAcceptanceAttempt, InstalledConfirmationReceiveAttempt,
    InstalledRestoredAppConfirmation, PreparedAcceptanceAttempt, PreparedAcceptanceOperation,
    PreparedAcceptancePhase, PreparedConfirmationReceiveAttempt, PreparedRestoreAdmission,
    PreparedRestoredAppConfirmation, ReceiverRendezvous, RestoredControllerPortTransfer,
    RestoredWriterPeer, RoleHandoffAttempt,
};
use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::handshake::Observation;
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::storage_socket_directory::StorageSocketDirectory;
use crate::security_epoch::native_enrollment::{ReceiverAction, ReceiverProgress};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    handshake::{Actor, Direction, Frame, Protocol, Step, Transcript, Transport},
    issuer_costs::HashCosts,
    process::MessageProcess,
    protocol::{self, MAX_PACKET},
    restore_peer_wire::{self as wire, RestoreBody},
    storage_peer_wire::{Body, Message, StageStatement},
};
use crate::security_epoch::restore_staging::NativeStagedTarget;
use anyhow::{Result, ensure};
#[cfg(target_os = "linux")]
use rustix::{
    event::{PollFd, PollFlags},
    fs::{Mode, OFlags},
    io::Errno,
    net,
};
#[cfg(target_os = "linux")]
use std::io::IoSliceMut;
#[cfg(target_os = "linux")]
use std::{fs::File, os::unix::fs::PermissionsExt};
use std::{marker::PhantomData, rc::Rc};

#[cfg(any(target_os = "linux", test))]
fn require_retained_controller_binding(
    current: &super::super::storage_peer_wire::StageStatement,
    retained: &super::super::storage_peer_wire::StageStatement,
) -> Result<()> {
    use super::super::{NativeRole, protocol::StagePurpose};
    ensure!(
        current.certificate == retained.certificate
            && current.stage == retained.stage
            && retained.stage.data.role == NativeRole::EpochController
            && current.original.purpose == StagePurpose::CurrentRole
            && retained.original.purpose == StagePurpose::CurrentRole
            && current.original.domain == retained.original.domain
            && current.original.origin_ns == retained.original.origin_ns
            && current.original.deadline_ns <= retained.original.deadline_ns,
        "restore_receiver_retained_controller_changed"
    );
    Ok(())
}

const PATH: &str = "/run/day2-native-enrollment/storage/restore.sock";
const PRE_CAS_SENDERS: usize = 3; // actual Hello, Confirm and Accepted packets

// Transcript position DATA only. The genuine constructor additionally checks
// actual idle state, retained resources and fresh native/original authority.
fn writer_slot(transcript: &super::super::handshake::Transcript) -> bool {
    use super::super::handshake::{Direction, Frame, Protocol, Step};
    transcript.next()
        == Some((
            Direction::Send,
            Frame {
                protocol: Protocol::RestoredStorage,
                step: Step::Known,
                sequence: None,
            },
        ))
}

fn release_slot(transcript: &super::super::handshake::Transcript) -> bool {
    use super::super::handshake::{Direction, Frame, Protocol, Step};
    transcript.next()
        == Some((
            Direction::Send,
            Frame {
                protocol: Protocol::RestoredStorage,
                step: Step::Released,
                sequence: None,
            },
        ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    OpenRoot,
    ObserveDirectory,
    Socket,
    PassCredentials,
    PassPidfd,
    Bind,
    Permissions,
    Listen,
    Accept,
    AcceptedCredentials,
    AcceptedPidfd,
    NeedProjection,
    BoundProjection,
    SignReady,
    SendReady,
    ReceiveHello,
    SignOffer,
    SendOffer,
    ReceiveConfirm,
    NeedDurability,
    SignDurable,
    SendDurable,
    ReceiveAccepted,
    Accepted,
    SignActivated,
    SendActivated,
    ReceiveKeeperAck,
    KeeperAcknowledged,
    SignReleased,
    SendReleased,
    Released,
    Busy,
}

#[derive(Clone, Copy)]
enum ActivationOperation {
    Prepare,
    Sign,
    Send,
    Poll,
    ReceiveAck,
}

impl ActivationOperation {
    fn permits(self, phase: Phase, waiting: bool) -> bool {
        match self {
            Self::Prepare => phase == Phase::Accepted && !waiting,
            Self::Sign => phase == Phase::SignActivated && !waiting,
            Self::Send => phase == Phase::SendActivated && !waiting,
            Self::Poll => {
                matches!(phase, Phase::SendActivated | Phase::ReceiveKeeperAck) && waiting
            }
            Self::ReceiveAck => phase == Phase::ReceiveKeeperAck && !waiting,
        }
    }
}

#[derive(Clone, Copy)]
enum ReleaseOperation {
    Prepare,
    Sign,
    Send,
    Poll,
}

impl ReleaseOperation {
    fn permits(self, phase: Phase, waiting: bool) -> bool {
        match self {
            Self::Prepare => phase == Phase::KeeperAcknowledged && !waiting,
            Self::Sign => phase == Phase::SignReleased && !waiting,
            Self::Send => phase == Phase::SendReleased && !waiting,
            Self::Poll => phase == Phase::SendReleased && waiting,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoleHandoffPhase {
    Fresh,
    Busy,
    Sign,
    Send,
    Poll,
    Delivered,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoleHandoffOperation {
    Prepare,
    Sign,
    Send,
    Poll,
}

impl RoleHandoffPhase {
    fn after(self, operation: RoleHandoffOperation, progress: ReceiverProgress) -> Result<Self> {
        use ReceiverProgress as P;
        use RoleHandoffOperation as O;
        use RoleHandoffPhase as S;
        match (self, operation, progress) {
            (S::Fresh, O::Prepare, P::Advanced) => Ok(S::Sign),
            (S::Sign, O::Sign, P::Advanced) => Ok(S::Send),
            (S::Send, O::Send, P::Delivered) => Ok(S::Delivered),
            (S::Send, O::Send, P::WouldBlock) => Ok(S::Poll),
            (S::Send, O::Send, P::Interrupted) => Ok(S::Send),
            (S::Poll, O::Poll, P::Advanced) => Ok(S::Send),
            (S::Poll, O::Poll, P::Interrupted) => Ok(S::Poll),
            _ => anyhow::bail!("restore_role_handoff_transition"),
        }
    }
}

struct RoleHandoffState {
    phase: RoleHandoffPhase,
    #[cfg(target_os = "linux")]
    transcript: Option<Transcript>,
    #[cfg(target_os = "linux")]
    body: Option<Body>,
    #[cfg(target_os = "linux")]
    outgoing: Option<Message>,
    #[cfg(target_os = "linux")]
    delivered: Option<Frame>,
    #[cfg(target_os = "linux")]
    started: bool,
}

impl RoleHandoffState {
    fn new() -> Self {
        Self {
            phase: RoleHandoffPhase::Fresh,
            #[cfg(target_os = "linux")]
            transcript: None,
            #[cfg(target_os = "linux")]
            body: None,
            #[cfg(target_os = "linux")]
            outgoing: None,
            #[cfg(target_os = "linux")]
            delivered: None,
            #[cfg(target_os = "linux")]
            started: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Phase, ReceiverAction, ReceiverState};
    use syn::visit::Visit;

    fn method<'a>(file: &'a syn::File, name: &str) -> &'a syn::ImplItemFn {
        file.items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(implementation) = item else {
                    return None;
                };
                let syn::Type::Path(path) = &*implementation.self_ty else {
                    return None;
                };
                if !path.path.is_ident("ReceiverRendezvous") {
                    return None;
                }
                implementation.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                    _ => None,
                })
            })
            .unwrap()
    }

    fn binding(statement: &syn::Stmt, name: &str) -> bool {
        matches!(statement, syn::Stmt::Local(local)
            if matches!(&local.pat, syn::Pat::Ident(bound) if bound.ident == name)
                || matches!(&local.pat, syn::Pat::Type(typed)
                    if matches!(&*typed.pat,syn::Pat::Ident(bound) if bound.ident == name)))
    }

    fn propagation(statement: &syn::Stmt, name: &str) -> bool {
        matches!(statement, syn::Stmt::Expr(syn::Expr::Try(tried), Some(_))
            if matches!(&*tried.expr,syn::Expr::Path(path) if path.path.is_ident(name)))
    }

    fn self_call(expression: &syn::Expr, name: &str, arguments: &[&str]) -> bool {
        matches!(expression,syn::Expr::MethodCall(call)
            if call.method==name && call.args.len()==arguments.len()
                && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("self"))
                && call.args.iter().zip(arguments).all(|(argument,name)|
                    matches!(argument,syn::Expr::Path(path) if path.path.is_ident(name))))
    }

    #[derive(Default)]
    struct Calls {
        names: Vec<String>,
        renewed: bool,
    }

    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.names.push(call.method.to_string());
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                self.renewed |=
                    path.path.segments.last().is_some_and(|segment| {
                        segment.ident == "begin" || segment.ident == "narrow"
                    });
            }
            syn::visit::visit_expr_call(self, call);
        }
    }

    // Inspect the actual production envelope, including unconditional post
    // evaluation on operation Err and error precedence. These source controls
    // complement, and never replace, real Linux socket/SCM conformance.
    fn operation_envelope(method: &syn::ImplItemFn) -> bool {
        let statements = &method.block.stmts;
        let Some(requested) = statements
            .iter()
            .position(|statement| binding(statement, "requested"))
        else {
            return false;
        };
        let Some(checked) = statements
            .iter()
            .position(|statement| binding(statement, "checked"))
        else {
            return false;
        };
        let Some(propagated) = statements
            .iter()
            .position(|statement| propagation(statement, "checked"))
        else {
            return false;
        };
        let mut pre = Calls::default();
        pre.visit_stmt(&statements[0]);
        let mut post = Calls::default();
        post.visit_stmt(&statements[checked]);
        let mut prefix = Calls::default();
        for statement in &statements[..propagated] {
            prefix.visit_stmt(statement);
        }
        let requested_propagated = statements.iter().enumerate().any(|(index,statement)| {
            if index <= checked || index >= propagated { return false; }
            if propagation(statement,"requested") { return true; }
            matches!(statement,syn::Stmt::Local(local)
                if matches!(local.init.as_ref().map(|init| &*init.expr),Some(syn::Expr::Try(tried))
                    if matches!(&*tried.expr,syn::Expr::Path(path) if path.path.is_ident("requested"))))
        });
        let early_primary = statements[..checked]
            .iter()
            .any(|statement| propagation(statement, "requested"));
        let busy_before_request = statements[..requested].iter().any(|statement| {
            matches!(statement,syn::Stmt::Expr(syn::Expr::Assign(assignment),Some(_))
                if matches!(&*assignment.right,syn::Expr::Path(path)
                    if path.path.segments.last().is_some_and(|segment| segment.ident=="Busy"))
                    && matches!(&*assignment.left,syn::Expr::Field(phase)
                        if matches!(&phase.member,syn::Member::Named(name) if name=="phase")
                            && matches!(&*phase.base,syn::Expr::Field(receiver)
                                if matches!(&receiver.member,syn::Member::Named(name) if name=="receiver")
                                    && matches!(&*receiver.base,syn::Expr::Path(path) if path.path.is_ident("self")))))
        });
        pre.names == ["check"]
            && requested < checked
            && checked < propagated
            && post.names == ["check_inner"]
            && requested_propagated
            && !early_primary
            && busy_before_request
            && !prefix.names.iter().any(|name| name == "complete_packet")
            && !prefix.renewed
            && matches!(&statements[0],syn::Stmt::Expr(syn::Expr::Try(tried),Some(_))
                if self_call(&tried.expr,"check",&["storage","target"]))
            && matches!(&statements[checked],syn::Stmt::Local(local)
                if local.init.as_ref().is_some_and(|init|self_call(&init.expr,"check_inner",&["storage"])))
    }

    #[test]
    fn actual_receiver_operations_postcheck_before_error_propagation_or_delivery() {
        let file = syn::parse_file(include_str!("restore_receiver.rs")).unwrap();
        for name in ["try_send", "try_receive", "poll"] {
            let actual = method(&file, name);
            assert!(operation_envelope(actual), "{name}");
            let checked = actual
                .block
                .stmts
                .iter()
                .position(|statement| binding(statement, "checked"))
                .unwrap();
            let propagated = actual
                .block
                .stmts
                .iter()
                .position(|statement| propagation(statement, "checked"))
                .unwrap();
            let mut missing = actual.clone();
            missing.block.stmts[checked] = syn::parse_quote!(let checked: Result<()> = Ok(()););
            assert!(!operation_envelope(&missing), "missing actual post: {name}");
            let mut ignored_pre = actual.clone();
            ignored_pre.block.stmts[0] = syn::parse_quote!(let _ = self.check(storage,target););
            assert!(
                !operation_envelope(&ignored_pre),
                "discarded precheck: {name}"
            );
            let mut wrong_post = actual.clone();
            wrong_post.block.stmts[checked] =
                syn::parse_quote!(let checked=other.check_inner(storage););
            assert!(
                !operation_envelope(&wrong_post),
                "substituted post owner: {name}"
            );
            let mut early = actual.clone();
            early
                .block
                .stmts
                .insert(checked, syn::parse_quote!(requested?;));
            assert!(
                !operation_envelope(&early),
                "early primary propagation: {name}"
            );
            let mut discarded = actual.clone();
            discarded.block.stmts[propagated] = syn::parse_quote!(let _ = checked;);
            assert!(!operation_envelope(&discarded), "discarded post: {name}");
            let mut reversed = actual.clone();
            reversed.block.stmts.swap(propagated - 1, propagated);
            assert!(
                !operation_envelope(&reversed),
                "reversed primary error: {name}"
            );
            let mut delivered = actual.clone();
            delivered
                .block
                .stmts
                .insert(checked, syn::parse_quote!(self.complete_packet()?;));
            assert!(
                !operation_envelope(&delivered),
                "delivery before post: {name}"
            );
            let mut renewed = actual.clone();
            renewed.block.stmts.insert(
                1,
                syn::parse_quote!(let _replacement=NativeAcquisition::begin(5)?;),
            );
            assert!(!operation_envelope(&renewed), "new original: {name}");
        }
    }

    #[test]
    fn receiver_dispatch_stops_at_projection_durability_and_busy_without_a_peer() {
        let mut state = ReceiverState::new();
        for (phase, expected) in [
            (Phase::OpenRoot, ReceiverAction::Send),
            (Phase::Accept, ReceiverAction::Receive),
            (Phase::NeedProjection, ReceiverAction::NeedProjection),
            (Phase::BoundProjection, ReceiverAction::Send),
            (Phase::ReceiveHello, ReceiverAction::Receive),
            (Phase::ReceiveConfirm, ReceiverAction::Receive),
            (Phase::NeedDurability, ReceiverAction::NeedDurability),
            (Phase::SignDurable, ReceiverAction::Send),
            (Phase::SendDurable, ReceiverAction::Send),
            (Phase::ReceiveAccepted, ReceiverAction::Receive),
            (Phase::Accepted, ReceiverAction::Complete),
        ] {
            state.phase = phase;
            assert_eq!(state.action().unwrap(), expected);
            state.waiting = true;
            if matches!(
                phase,
                Phase::Accept
                    | Phase::ReceiveHello
                    | Phase::ReceiveConfirm
                    | Phase::SendDurable
                    | Phase::ReceiveAccepted
            ) {
                assert_eq!(state.action().unwrap(), ReceiverAction::Poll);
            } else {
                assert!(
                    state.action().is_err(),
                    "setup or durability is never a socket wait"
                );
            }
            state.waiting = false;
        }
        state.phase = Phase::Busy;
        assert!(state.action().is_err());
        state.waiting = true;
        assert!(
            state.action().is_err(),
            "readiness cannot repair interrupted operation"
        );
        state.phase = Phase::NeedDurability;
        state.refused.set(true);
        assert!(
            state.action().is_err(),
            "repairing phase cannot repair refusal"
        );
    }

    fn fixed_durability(method: &syn::ImplItemFn) -> bool {
        let statements = &method.block.stmts;
        if statements.len() != 9 {
            return false;
        }
        let mut calls = Calls::default();
        calls.visit_impl_item_fn(method);
        let actual_borrow = matches!(&statements[2],syn::Stmt::Local(local)
            if matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::Struct(value))
                if value.path.is_ident("ReceiverDurability") && value.fields.len()==2
                    && value.fields.iter().any(|field|
                        matches!(&field.member,syn::Member::Named(name) if name=="receiver")
                            && matches!(&field.expr,syn::Expr::Path(path) if path.path.is_ident("self")))
                    && value.fields.iter().any(|field|
                        matches!(&field.member,syn::Member::Named(name) if name=="completed")
                            && matches!(&field.expr,syn::Expr::Lit(value) if matches!(&value.lit,syn::Lit::Bool(value) if !value.value)))));
        let actual_effect = matches!(&statements[3],syn::Stmt::Local(local)
            if binding(&statements[3],"requested")
                && matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::MethodCall(call))
                    if call.method=="durable_target" && call.args.len()==2
                        && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("context"))
                        && matches!(&call.args[0],syn::Expr::Path(path) if path.path.is_ident("target"))
                        && matches!(&call.args[1],syn::Expr::Reference(reference)
                            if reference.mutability.is_some()
                                && matches!(&*reference.expr,syn::Expr::Path(path) if path.path.is_ident("loan")))));
        let completed_last = matches!(&statements[7],syn::Stmt::Expr(syn::Expr::Assign(assignment),Some(_))
            if matches!(&*assignment.left,syn::Expr::Field(field)
                if matches!(&*field.base,syn::Expr::Path(path) if path.path.is_ident("loan"))
                    && matches!(&field.member,syn::Member::Named(name) if name=="completed"))
                && matches!(&*assignment.right,syn::Expr::Lit(value)
                    if matches!(&value.lit,syn::Lit::Bool(value) if value.value)));
        actual_borrow
            && actual_effect
            && propagation(&statements[5], "requested")
            && completed_last
            && !calls.renewed
            && calls
                .names
                .iter()
                .filter(|name| name.as_str() == "durable_target")
                .count()
                == 1
    }

    #[test]
    fn actual_durability_lends_the_busy_receiver_and_disarms_only_after_the_real_parent_result() {
        let file = syn::parse_file(include_str!("restore_receiver.rs")).unwrap();
        let actual = method(&file, "complete_durability");
        assert!(fixed_durability(actual));
        let mut fake = actual.clone();
        fake.block.stmts[3] = syn::parse_quote!(let requested: Result<()> = Ok(()););
        assert!(!fixed_durability(&fake), "no DATA-only durability success");
        let mut discarded = actual.clone();
        discarded.block.stmts[5] = syn::parse_quote!(let _ = requested;);
        assert!(
            !fixed_durability(&discarded),
            "failed real sync cannot advance"
        );
        let mut early = actual.clone();
        early.block.stmts.swap(5, 7);
        assert!(
            !fixed_durability(&early),
            "Drop cannot be disarmed before real result"
        );
        let mut wrong_target = actual.clone();
        wrong_target.block.stmts[3] =
            syn::parse_quote!(let requested=context.durable_target(other,&mut loan););
        assert!(!fixed_durability(&wrong_target), "same actual target");
        let mut renewed = actual.clone();
        renewed.block.stmts.insert(
            1,
            syn::parse_quote!(let _replacement=NativeAcquisition::begin(5)?;),
        );
        assert!(!fixed_durability(&renewed), "no replacement original");
    }

    #[test]
    fn writer_transcript_slot_is_only_after_accepted_and_keeps_activation_ack_and_release_pending()
    -> anyhow::Result<()> {
        use crate::security_epoch::native_enrollment::handshake::{
            Actor, Observation, Protocol, Transcript, Transport,
        };
        use std::time::Duration;
        for actor in [Actor::Controller, Actor::App] {
            let mut transcript = Transcript::new(Protocol::RestoredStorage, actor);
            let mut received = 0;
            for position in 0..9 {
                assert_eq!(
                    super::writer_slot(&transcript),
                    actor == Actor::Controller && position == 6
                );
                if actor == Actor::Controller && position == 6 {
                    assert_eq!(received, super::PRE_CAS_SENDERS);
                }
                assert!(!transcript.complete());
                let (direction, frame) = transcript.next().unwrap();
                if direction
                    == crate::security_epoch::native_enrollment::handshake::Direction::Receive
                {
                    received += 1;
                }
                let observation = Observation {
                    domain: day2_capabilities::Digest::new(b"same-test-original"),
                    origin: Duration::from_secs(100),
                    deadline: Duration::from_secs(105),
                    now: Duration::from_millis(100_000 + position * 10),
                };
                transcript.select_frame(frame)?;
                transcript.begin(direction, observation.clone())?;
                transcript.transport(Transport::WouldBlock, observation.clone())?;
                transcript.transport(Transport::Interrupted, observation.clone())?;
                transcript.transport(Transport::Ready, observation.clone())?;
                transcript.delivered(frame, observation)?;
            }
            assert!(transcript.complete());
            assert!(
                !super::writer_slot(&transcript),
                "complete transcript is a later boundary"
            );
            transcript.refuse();
            assert!(!super::writer_slot(&transcript));
        }
        Ok(())
    }

    fn peer_birth(method: &syn::ImplItemFn) -> bool {
        let statements = &method.block.stmts;
        statements.len() == 5
            && matches!(&statements[0],syn::Stmt::Expr(syn::Expr::Try(tried),Some(_))
                if self_call(&tried.expr,"check",&["storage","target"]))
            && matches!(&statements[1],syn::Stmt::Local(local)
                if binding(&statements[1],"requested") && local.init.as_ref().is_some_and(|init|
                    self_call(&init.expr,"require_accepted_prefix",&[])))
            && propagation(&statements[3], "requested")
            && matches!(&statements[4],syn::Stmt::Expr(syn::Expr::Call(call),None)
                if matches!(&*call.func,syn::Expr::Path(path) if path.path.is_ident("Ok")) && call.args.len()==1
                    && matches!(&call.args[0],syn::Expr::Struct(value)
                        if value.path.is_ident("RestoredWriterPeer") && value.fields.len()==1
                            && matches!(&value.fields[0].member,syn::Member::Named(name) if name=="receiver")
                            && matches!(&value.fields[0].expr,syn::Expr::Path(path) if path.path.is_ident("self"))))
    }

    #[test]
    fn actual_peer_constructor_moves_the_whole_accepted_receiver_without_a_new_original() {
        let file = syn::parse_file(include_str!("restore_receiver.rs")).unwrap();
        let actual = method(&file, "into_peer");
        assert!(peer_birth(actual));
        let mut ignored_native = actual.clone();
        ignored_native.block.stmts[0] = syn::parse_quote!(let _=self.check(storage,target););
        assert!(!peer_birth(&ignored_native));
        let mut early = actual.clone();
        early.block.stmts[1] = syn::parse_quote!(let requested:Result<()>=Ok(()););
        assert!(!peer_birth(&early), "socket existence is not Accepted");
        let mut substitute = actual.clone();
        substitute.block.stmts[4] = syn::Stmt::Expr(
            syn::parse_quote!(Ok(RestoredWriterPeer { receiver: other })),
            None,
        );
        assert!(!peer_birth(&substitute));
        let mut renewed = actual.clone();
        renewed.block.stmts.insert(
            0,
            syn::parse_quote!(let _fresh=NativeAcquisition::begin(5)?;),
        );
        assert!(!peer_birth(&renewed));
    }

    fn peer_method<'a>(file: &'a syn::File, name: &str) -> &'a syn::ImplItemFn {
        file.items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(owner) = item else {
                    return None;
                };
                let syn::Type::Path(path) = &*owner.self_ty else {
                    return None;
                };
                if !path.path.is_ident("RestoredWriterPeer") {
                    return None;
                }
                owner.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                    _ => None,
                })
            })
            .unwrap()
    }

    fn activation_requested(method: &mut syn::ImplItemFn) -> &mut syn::Block {
        let local = method
            .block
            .stmts
            .iter_mut()
            .find_map(|statement| match statement {
                syn::Stmt::Local(local)
                    if binding(&syn::Stmt::Local(local.clone()), "requested") =>
                {
                    Some(local)
                }
                _ => None,
            })
            .unwrap();
        let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr else {
            panic!("actual requested call");
        };
        let syn::Expr::Paren(paren) = &mut *call.func else {
            panic!("actual closure parens");
        };
        let syn::Expr::Closure(closure) = &mut *paren.expr else {
            panic!("actual closure");
        };
        let syn::Expr::Block(body) = &mut *closure.body else {
            panic!("actual closure body");
        };
        &mut body.block
    }

    fn activation_envelope(method: &mut syn::ImplItemFn) -> bool {
        use syn::parse::Parser;
        let statements = &method.block.stmts;
        let Some(checked) = statements
            .iter()
            .position(|statement| binding(statement, "checked"))
        else {
            return false;
        };
        let Some(propagated) = statements
            .iter()
            .position(|statement| propagation(statement, "checked"))
        else {
            return false;
        };
        let actual_post = matches!(&statements[checked],syn::Stmt::Local(local)
            if local.init.as_ref().is_some_and(|init|self_call(&init.expr,"activation_guard",&["storage","loan"])));
        let actual_primary = matches!(statements.get(propagated.wrapping_sub(1)),Some(syn::Stmt::Local(local))
            if matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::Try(tried))
                if matches!(&*tried.expr,syn::Expr::Path(path) if path.path.is_ident("requested"))));
        let mut before = Calls::default();
        for statement in &statements[..propagated] {
            before.visit_stmt(statement);
        }
        if !actual_post
            || !actual_primary
            || checked >= propagated
            || before.renewed
            || before.names.iter().any(|name| name == "complete_packet")
        {
            return false;
        }
        let body = activation_requested(method);
        let Some(syn::Stmt::Macro(condition)) = body.stmts.first() else {
            return false;
        };
        if !condition.mac.path.is_ident("ensure") {
            return false;
        }
        let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
        let arguments = parser.parse2(condition.mac.tokens.clone()).unwrap();
        let permitted = matches!(arguments.first(),Some(syn::Expr::MethodCall(call))
            if call.method=="permits" && call.args.len()==2
                && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("operation"))
                && matches!(&call.args[0],syn::Expr::Path(path) if path.path.is_ident("phase"))
                && matches!(&call.args[1],syn::Expr::Path(path) if path.path.is_ident("waiting")));
        permitted
            && matches!(body.stmts.get(1),Some(syn::Stmt::Local(local))
            if matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::Try(tried))
                if self_call(&tried.expr,"activation_guard",&["storage","loan"])))
    }

    #[test]
    fn actual_activation_steps_keep_genuine_loan_posts_before_packet_delivery_and_no_clock_replacement()
     {
        let file = syn::parse_file(include_str!("restore_receiver.rs")).unwrap();
        let actual = peer_method(&file, "activation_operation");
        assert!(activation_envelope(&mut actual.clone()));
        let checked = actual
            .block
            .stmts
            .iter()
            .position(|statement| binding(statement, "checked"))
            .unwrap();
        let propagated = actual
            .block
            .stmts
            .iter()
            .position(|statement| propagation(statement, "checked"))
            .unwrap();
        let mut missing = actual.clone();
        missing.block.stmts[checked] = syn::parse_quote!(let checked:Result<()>=Ok(()););
        assert!(!activation_envelope(&mut missing));
        let mut other = actual.clone();
        other.block.stmts[checked] =
            syn::parse_quote!(let checked=self.activation_guard(storage,other_loan););
        assert!(!activation_envelope(&mut other));
        let mut ignored = actual.clone();
        ignored.block.stmts[propagated] = syn::parse_quote!(let _=checked;);
        assert!(!activation_envelope(&mut ignored));
        let mut delivered = actual.clone();
        delivered.block.stmts.insert(
            checked,
            syn::parse_quote!(self.receiver.complete_packet()?;),
        );
        assert!(!activation_envelope(&mut delivered));
        let mut unchecked = actual.clone();
        activation_requested(&mut unchecked).stmts[0] = syn::parse_quote!(ensure!(true,"skip"););
        assert!(!activation_envelope(&mut unchecked));
        let mut renewed = actual.clone();
        activation_requested(&mut renewed).stmts.insert(
            0,
            syn::parse_quote!(let _fresh=NativeAcquisition::begin(5)?;),
        );
        assert!(!activation_envelope(&mut renewed));
    }
}

pub(super) struct ReceiverState {
    phase: Phase,
    role: RoleHandoffState,
    decision: RoleHandoffState,
    waiting: bool,
    refused: Rc<std::cell::Cell<bool>>,
    #[cfg(target_os = "linux")]
    root: Option<File>,
    #[cfg(target_os = "linux")]
    directory: Option<StorageSocketDirectory>,
    #[cfg(target_os = "linux")]
    listener: Option<File>,
    #[cfg(target_os = "linux")]
    socket: Option<File>,
    // Physical/negative alias only after the sole operational File moved.
    #[cfg(target_os = "linux")]
    current_socket: Option<Rc<File>>,
    #[cfg(target_os = "linux")]
    projection: Option<crate::security_epoch::native_enrollment::RestoreFileProjectionData>,
    #[cfg(target_os = "linux")]
    transcript: Transcript,
    #[cfg(target_os = "linux")]
    started: bool,
    #[cfg(target_os = "linux")]
    controller: Option<StageStatement>,
    #[cfg(target_os = "linux")]
    nonce: Option<day2_capabilities::Digest>,
    #[cfg(target_os = "linux")]
    app: Option<wire::RestoreAppStatement>,
    #[cfg(target_os = "linux")]
    app_nonce: Option<day2_capabilities::Digest>,
    #[cfg(target_os = "linux")]
    exchange: Option<wire::Exchange>,
    #[cfg(target_os = "linux")]
    outgoing: Option<Message>,
    #[cfg(target_os = "linux")]
    delivered: Option<Frame>,
    #[cfg(target_os = "linux")]
    activation: Option<wire::Activation>,
    #[cfg(target_os = "linux")]
    keeper_ack: Option<super::super::storage_peer_wire::SqliteCohort>,
    #[cfg(target_os = "linux")]
    senders: Vec<MessageProcess>,
    local: PhantomData<Rc<()>>,
}

/// A lexical loan of the actual in-flight receiver. No readiness DATA,
/// descriptor, getter or caller-selected operation can construct this borrow.
/// Its sole constructor will be the fixed complete_durability operation.
pub(in crate::security_epoch) struct ReceiverDurability<'receiver> {
    receiver: &'receiver mut ReceiverRendezvous,
    completed: bool,
}

impl ReceiverDurability<'_> {
    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        target: &mut NativeStagedTarget<'_, '_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            ensure!(
                !self.completed && self.receiver.receiver.phase == Phase::Busy,
                "restore_receiver_durability_loan_closed"
            );
            self.receiver.check_inner(storage)
        })();
        if requested.is_err() {
            self.receiver.refuse();
            target.refuse();
        }
        requested
    }
}

impl Drop for ReceiverDurability<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.receiver.refuse();
        }
    }
}

impl ReceiverState {
    fn new() -> Self {
        Self {
            phase: Phase::OpenRoot,
            role: RoleHandoffState::new(),
            decision: RoleHandoffState::new(),
            waiting: false,
            refused: Rc::new(std::cell::Cell::new(false)),
            #[cfg(target_os = "linux")]
            root: None,
            #[cfg(target_os = "linux")]
            directory: None,
            #[cfg(target_os = "linux")]
            listener: None,
            #[cfg(target_os = "linux")]
            socket: None,
            #[cfg(target_os = "linux")]
            current_socket: None,
            #[cfg(target_os = "linux")]
            projection: None,
            #[cfg(target_os = "linux")]
            transcript: Transcript::new(Protocol::RestoredStorage, Actor::Controller),
            #[cfg(target_os = "linux")]
            started: false,
            #[cfg(target_os = "linux")]
            controller: None,
            #[cfg(target_os = "linux")]
            nonce: None,
            #[cfg(target_os = "linux")]
            app: None,
            #[cfg(target_os = "linux")]
            app_nonce: None,
            #[cfg(target_os = "linux")]
            exchange: None,
            #[cfg(target_os = "linux")]
            outgoing: None,
            #[cfg(target_os = "linux")]
            delivered: None,
            #[cfg(target_os = "linux")]
            activation: None,
            #[cfg(target_os = "linux")]
            keeper_ack: None,
            #[cfg(target_os = "linux")]
            senders: Vec::new(),
            local: PhantomData,
        }
    }

    fn action(&self) -> Result<ReceiverAction> {
        ensure!(
            !self.refused.get() && self.phase != Phase::Busy,
            "restore_receiver_refused_or_interrupted"
        );
        if self.waiting {
            ensure!(
                matches!(
                    self.phase,
                    Phase::Accept
                        | Phase::SendReady
                        | Phase::SendOffer
                        | Phase::SendDurable
                        | Phase::ReceiveHello
                        | Phase::ReceiveConfirm
                        | Phase::ReceiveAccepted
                        | Phase::SendActivated
                        | Phase::ReceiveKeeperAck
                        | Phase::SendReleased
                ),
                "restore_receiver_wait_order"
            );
            return Ok(ReceiverAction::Poll);
        }
        Ok(match self.phase {
            Phase::Accept
            | Phase::ReceiveHello
            | Phase::ReceiveConfirm
            | Phase::ReceiveAccepted
            | Phase::ReceiveKeeperAck => ReceiverAction::Receive,
            Phase::NeedProjection => ReceiverAction::NeedProjection,
            Phase::NeedDurability => ReceiverAction::NeedDurability,
            Phase::Accepted | Phase::KeeperAcknowledged | Phase::Released => {
                ReceiverAction::Complete
            }
            Phase::Busy => unreachable!(),
            _ => ReceiverAction::Send,
        })
    }
}

impl ReceiverRendezvous {
    /// Sign this receiver's retained Controller identity, after fresh actual
    /// checks. A narrower current deadline never changes the peer's admitted
    /// sender digest and never expands the real request's remaining budget.
    fn sign_restore_body(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        body: super::super::storage_peer_wire::Body,
    ) -> Result<super::super::storage_peer_wire::Message> {
        let requested = (|| {
            self.check_inner(storage)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = &body;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                storage.stage.require_current_role()?;
                let current = storage.storage_statement()?;
                let retained = self
                    .receiver
                    .controller
                    .as_ref()
                    .context("restore_receiver_controller_missing")?;
                require_retained_controller_binding(&current, retained)?;
                ensure!(
                    matches!(body, Body::Restore { .. })
                        && body.sender_role() == super::super::NativeRole::EpochController,
                    "restore_receiver_sign_body_role"
                );
                body.require_stage_purpose(storage.stage.purpose)?;
                let sender = retained.digest()?;
                storage.stage.check()?;
                let signature = storage
                    .stage
                    .owner
                    .key
                    .sign("initial-storage-message", &(&sender, &body))?;
                storage.stage.check()?;
                Ok(Message {
                    sender,
                    body,
                    signature,
                })
            }
        })();
        let checked = self.check_inner(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let message = requested?;
        checked?;
        Ok(message)
    }

    /// Only an actual completed issuer preparation constructs this socket
    /// lifetime. Initialization performs no endpoint IO and grants no P3.
    pub(in crate::security_epoch) fn begin(
        storage: &mut EnrolledStorageStage<'_, '_>,
        mut admission: PreparedRestoreAdmission,
        target: &mut NativeStagedTarget<'_, '_>,
    ) -> Result<Self> {
        let checked = admission.check(storage);
        if checked.is_err() {
            admission.refuse();
            target.refuse();
        }
        checked?;
        Ok(Self {
            admission,
            receiver: ReceiverState::new(),
            local: PhantomData,
        })
    }

    pub(in crate::security_epoch) fn next_action(&self) -> Result<ReceiverAction> {
        self.receiver.action()
    }

    /// Only this fixed operation creates the in-flight durability loan. The
    /// concrete full parent performs actual creator/directory/root fsync and
    /// image readback, with independent native and whole-parent tails on Err.
    pub(in crate::security_epoch) fn complete_durability(
        &mut self,
        target: &mut NativeStagedTarget<'_, '_>,
        context: &mut crate::security_epoch::bootstrap::RestoreWriterExchangeContext<
            '_,
            '_,
            '_,
            '_,
        >,
    ) -> Result<()> {
        if self.receiver.refused.get()
            || self.receiver.phase != Phase::NeedDurability
            || self.receiver.waiting
        {
            self.refuse();
            target.refuse();
            context.refuse();
            anyhow::bail!("restore_receiver_durability_order");
        }
        // Enter before any real effect. Only the lexical private tail can
        // disarm Drop; a caught unwind leaves receiver and parent refused.
        self.receiver.phase = Phase::Busy;
        let mut loan = ReceiverDurability {
            receiver: self,
            completed: false,
        };
        let requested = context.durable_target(target, &mut loan);
        if requested.is_err() {
            loan.receiver.refuse();
            target.refuse();
            context.refuse();
        }
        requested?;
        loan.receiver.receiver.phase = Phase::SignDurable;
        loan.completed = true;
        Ok(())
    }

    /// DATA assembled by the fixed whole-parent operation from the actual
    /// target and consumed ledger. Storing it does not supply P3 or advance a
    /// received App message; every signed issuer binding must remain exact.
    pub(in crate::security_epoch) fn bind_projection(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        projection: &crate::security_epoch::native_enrollment::RestoreFileProjectionData,
        target: &mut NativeStagedTarget<'_, '_>,
    ) -> Result<()> {
        self.check(storage, target)?;
        let requested: Result<()> = (|| {
            ensure!(
                self.receiver.phase == Phase::NeedProjection,
                "restore_receiver_projection_order"
            );
            self.receiver.phase = Phase::Busy;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = projection;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use crate::security_epoch::native_enrollment::restore_peer_wire::Selection;
                let data = &self.admission.preparation.data;
                let expected = Selection {
                    operation: data.operation.clone(),
                    approval_request: data.approval.clone(),
                    intent: data.intent.clone(),
                    full_archive: data.full_archive.clone(),
                    target: data.target.clone(),
                };
                projection.validate(&expected)?;
                ensure!(
                    projection.report == data.report
                        && projection.captured_records == data.records
                        && projection.ledger.grant == data.grant,
                    "restore_receiver_prepared_projection_changed"
                );
                ensure!(
                    self.receiver.projection.is_none(),
                    "restore_receiver_projection_repeated"
                );
                self.receiver.projection = Some(projection.clone());
                Ok(())
            }
        })();
        let checked = self.check_inner(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            target.refuse();
        }
        requested?;
        checked?;
        self.receiver.phase = Phase::BoundProjection;
        Ok(())
    }

    /// Exactly one fixed setup operation. No loop, wait, arbitrary endpoint,
    /// unlink, adoption, caller body or stage/clock accessor is available.
    pub(in crate::security_epoch) fn try_send(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        target: &mut NativeStagedTarget<'_, '_>,
    ) -> Result<ReceiverProgress> {
        self.check(storage, target)?;
        let phase = self.receiver.phase;
        if !matches!(self.next_action(), Ok(ReceiverAction::Send)) {
            self.refuse();
            target.refuse();
            anyhow::bail!("restore_receiver_send_order");
        }
        self.receiver.phase = Phase::Busy;
        let requested = match phase {
            Phase::BoundProjection => self
                .prepare_ready(storage)
                .map(|()| (Phase::SignReady, ReceiverProgress::Advanced, false)),
            Phase::SignReady | Phase::SignOffer | Phase::SignDurable => self
                .sign_packet(storage, phase)
                .map(|next| (next, ReceiverProgress::Advanced, false)),
            Phase::SendReady | Phase::SendOffer | Phase::SendDurable => self.send_packet(phase),
            _ => self
                .setup(phase)
                .map(|next| (next, ReceiverProgress::Advanced, false)),
        };
        let checked = self.check_inner(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            target.refuse();
        }
        let (next, progress, waiting) = requested?;
        checked?;
        if progress == ReceiverProgress::Delivered {
            let completed = self.complete_packet();
            if completed.is_err() {
                self.refuse();
                target.refuse();
            }
            completed?;
        }
        self.receiver.phase = next;
        self.receiver.waiting = waiting;
        Ok(progress)
    }

    /// One nonblocking accept or packet receive. Every delivered message
    /// retains its original kernel sender descriptor before authentication.
    pub(in crate::security_epoch) fn try_receive(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        target: &mut NativeStagedTarget<'_, '_>,
    ) -> Result<ReceiverProgress> {
        self.check(storage, target)?;
        if !matches!(self.next_action(), Ok(ReceiverAction::Receive)) {
            self.refuse();
            target.refuse();
            anyhow::bail!("restore_receiver_receive_order");
        }
        let phase = self.receiver.phase;
        self.receiver.phase = Phase::Busy;
        let requested = if phase == Phase::Accept {
            self.accept()
        } else {
            self.receive_packet(storage, phase)
        };
        let checked = self.check_inner(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            target.refuse();
        }
        let progress = requested?;
        checked?;
        if progress == ReceiverProgress::Delivered {
            let completed = self.complete_packet();
            if completed.is_err() {
                self.refuse();
                target.refuse();
            }
            completed?;
        }
        match progress {
            ReceiverProgress::Advanced if phase == Phase::Accept => {
                self.receiver.phase = Phase::AcceptedCredentials;
                self.receiver.waiting = false;
            }
            ReceiverProgress::WouldBlock => {
                self.receiver.phase = phase;
                self.receiver.waiting = true;
            }
            ReceiverProgress::Interrupted => {
                self.receiver.phase = phase;
                self.receiver.waiting = false;
            }
            ReceiverProgress::Delivered if phase == Phase::ReceiveHello => {
                self.receiver.phase = Phase::SignOffer;
                self.receiver.waiting = false;
            }
            ReceiverProgress::Delivered if phase == Phase::ReceiveConfirm => {
                self.receiver.phase = Phase::NeedDurability;
                self.receiver.waiting = false;
            }
            ReceiverProgress::Delivered if phase == Phase::ReceiveAccepted => {
                self.receiver.phase = Phase::Accepted;
                self.receiver.waiting = false;
            }
            _ => {
                self.refuse();
                target.refuse();
                anyhow::bail!("restore_receiver_progress_order");
            }
        }
        Ok(progress)
    }

    pub(in crate::security_epoch) fn poll(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        target: &mut NativeStagedTarget<'_, '_>,
    ) -> Result<ReceiverProgress> {
        self.check(storage, target)?;
        let phase = self.receiver.phase;
        if !matches!(self.next_action(), Ok(ReceiverAction::Poll)) {
            self.refuse();
            target.refuse();
            anyhow::bail!("restore_receiver_poll_order");
        }
        self.receiver.phase = Phase::Busy;
        let requested = self.poll_once(phase);
        let checked = self.check_inner(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            target.refuse();
        }
        let progress = requested?;
        checked?;
        self.receiver.phase = phase;
        self.receiver.waiting = progress == ReceiverProgress::Interrupted;
        Ok(progress)
    }

    /// Busy is negative on every public re-entry, including caught unwind.
    /// Only the private independent operation tail may observe it as busy.
    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        target: &mut NativeStagedTarget<'_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                !self.receiver.refused.get() && self.receiver.phase != Phase::Busy,
                "restore_receiver_refused_or_interrupted"
            );
            self.check_inner(storage)
        })();
        if requested.is_err() {
            self.refuse();
            target.refuse();
        }
        requested
    }

    fn check_inner(&mut self, storage: &mut EnrolledStorageStage<'_, '_>) -> Result<()> {
        let requested: Result<()> =
            (|| {
                ensure!(!self.receiver.refused.get(), "restore_receiver_refused");
                self.admission.check(storage)?;
                #[cfg(target_os = "linux")]
                {
                    if let Some(root) = &self.receiver.root
                        && let Some(directory) = &self.receiver.directory
                    {
                        directory.check(root)?;
                    }
                    for socket in [&self.receiver.listener, &self.receiver.socket]
                        .into_iter()
                        .flatten()
                    {
                        ensure!(
                            rustix::io::fcntl_getfd(socket)?.contains(rustix::io::FdFlags::CLOEXEC),
                            "restore_receiver_socket_not_cloexec"
                        );
                    }
                    for sender in &mut self.receiver.senders {
                        sender.check_identity(
                            &mut self.admission.preparation.original,
                            &HashCosts::disabled(),
                        )?;
                    }
                    if let Some(app) = &self.receiver.app {
                        let sender =
                            self.receiver.senders.first().ok_or_else(|| {
                                anyhow::anyhow!("restore_receiver_sender_missing")
                            })?;
                        super::super::runtime::require_common(
                            sender.data(),
                            &storage.stage.owner.self_data,
                        )?;
                        app.validate(
                            &storage.stage.owner.policy,
                            &self.admission.preparation.certificate,
                            sender.data(),
                            self.admission.preparation.original.sample()?.elapsed,
                        )?;
                        app.require_controller(self.receiver.controller.as_ref().ok_or_else(
                            || anyhow::anyhow!("restore_receiver_controller_missing"),
                        )?)?;
                    }
                }
                Ok(())
            })();
        let checked = self.admission.check(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    fn setup(&mut self, phase: Phase) -> Result<Phase> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, phase);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            Ok(match phase {
                Phase::OpenRoot => {
                    ensure!(
                        rustix::process::geteuid().as_raw() == 10001,
                        "restore_receiver_uid"
                    );
                    self.receiver.root = Some(File::from(rustix::fs::open(
                        "/run/day2-native-enrollment",
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?));
                    Phase::ObserveDirectory
                }
                Phase::ObserveDirectory => {
                    self.receiver.directory = Some(StorageSocketDirectory::observe(
                        self.receiver
                            .root
                            .as_ref()
                            .context("restore_receiver_root_missing")?,
                    )?);
                    Phase::Socket
                }
                Phase::Socket => {
                    self.receiver.listener = Some(File::from(net::socket_with(
                        net::AddressFamily::UNIX,
                        net::SocketType::SEQPACKET,
                        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                        None,
                    )?));
                    Phase::PassCredentials
                }
                Phase::PassCredentials => {
                    net::sockopt::set_socket_passcred(
                        self.receiver
                            .listener
                            .as_ref()
                            .context("restore_receiver_listener_missing")?,
                        true,
                    )?;
                    Phase::PassPidfd
                }
                Phase::PassPidfd => {
                    net::sockopt::set_socket_passpidfd(
                        self.receiver
                            .listener
                            .as_ref()
                            .context("restore_receiver_listener_missing")?,
                        true,
                    )?;
                    Phase::Bind
                }
                Phase::Bind => {
                    // No unlink or adoption. An existing endpoint refuses.
                    net::bind(
                        self.receiver
                            .listener
                            .as_ref()
                            .context("restore_receiver_listener_missing")?,
                        &net::SocketAddrUnix::new(PATH)?,
                    )?;
                    Phase::Permissions
                }
                Phase::Permissions => {
                    std::fs::set_permissions(PATH, std::fs::Permissions::from_mode(0o600))?;
                    Phase::Listen
                }
                Phase::Listen => {
                    net::listen(
                        self.receiver
                            .listener
                            .as_ref()
                            .context("restore_receiver_listener_missing")?,
                        1,
                    )?;
                    Phase::Accept
                }
                Phase::AcceptedCredentials => {
                    net::sockopt::set_socket_passcred(
                        self.receiver
                            .socket
                            .as_ref()
                            .context("restore_receiver_socket_missing")?,
                        true,
                    )?;
                    Phase::AcceptedPidfd
                }
                Phase::AcceptedPidfd => {
                    net::sockopt::set_socket_passpidfd(
                        self.receiver
                            .socket
                            .as_ref()
                            .context("restore_receiver_socket_missing")?,
                        true,
                    )?;
                    Phase::NeedProjection
                }
                _ => anyhow::bail!("restore_receiver_setup_order"),
            })
        }
    }

    fn accept(&mut self) -> Result<ReceiverProgress> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            match net::accept_with(
                self.receiver
                    .listener
                    .as_ref()
                    .context("restore_receiver_listener_missing")?,
                net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
            ) {
                Ok(socket) => {
                    self.receiver.socket = Some(File::from(socket));
                    Ok(ReceiverProgress::Advanced)
                }
                Err(Errno::AGAIN) => Ok(ReceiverProgress::WouldBlock),
                Err(Errno::INTR) => Ok(ReceiverProgress::Interrupted),
                Err(error) => Err(error.into()),
            }
        }
    }

    fn prepare_ready(&mut self, storage: &mut EnrolledStorageStage<'_, '_>) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = storage;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            ensure!(
                self.receiver.controller.is_none() && self.receiver.nonce.is_none(),
                "restore_receiver_ready_repeated"
            );
            let controller = storage.storage_statement()?;
            ensure!(
                controller.digest()? == self.admission.preparation.data.controller,
                "restore_receiver_prepared_controller_changed"
            );
            self.receiver.controller = Some(controller);
            self.receiver.nonce = Some(protocol::nonce("restore-controller-ready")?);
            Ok(())
        }
    }

    fn sign_packet(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        phase: Phase,
    ) -> Result<Phase> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (storage, phase);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            ensure!(
                self.receiver.outgoing.is_none(),
                "restore_receiver_outgoing_repeated"
            );
            let controller = self
                .receiver
                .controller
                .as_ref()
                .context("restore_receiver_controller_missing")?;
            let projection = self
                .receiver
                .projection
                .as_ref()
                .context("restore_receiver_projection_missing")?;
            let (payload, next) = match phase {
                Phase::SignReady => (
                    RestoreBody::Ready {
                        controller: Box::new(controller.clone()),
                        nonce: self
                            .receiver
                            .nonce
                            .as_ref()
                            .context("restore_receiver_nonce_missing")?
                            .clone(),
                        selection: projection.selection.clone(),
                    },
                    Phase::SendReady,
                ),
                Phase::SignOffer => {
                    let exchange = wire::Exchange {
                        app_stage: self
                            .receiver
                            .app
                            .as_ref()
                            .context("restore_receiver_app_missing")?
                            .digest()?,
                        controller_stage: controller.digest()?,
                        app_nonce: self
                            .receiver
                            .app_nonce
                            .as_ref()
                            .context("restore_receiver_app_nonce_missing")?
                            .clone(),
                        controller_nonce: self
                            .receiver
                            .nonce
                            .as_ref()
                            .context("restore_receiver_nonce_missing")?
                            .clone(),
                        projection: projection.digest()?,
                    };
                    ensure!(
                        self.receiver.exchange.is_none(),
                        "restore_receiver_exchange_repeated"
                    );
                    self.receiver.exchange = Some(exchange.clone());
                    (
                        RestoreBody::Offer {
                            controller: Box::new(controller.clone()),
                            exchange,
                            projection: Box::new(projection.clone()),
                        },
                        Phase::SendOffer,
                    )
                }
                Phase::SignDurable => (
                    RestoreBody::Durable {
                        exchange: self
                            .receiver
                            .exchange
                            .as_ref()
                            .context("restore_receiver_exchange_missing")?
                            .digest()?,
                        projection: projection.digest()?,
                    },
                    Phase::SendDurable,
                ),
                Phase::SignActivated => (
                    RestoreBody::Activated {
                        exchange: self
                            .receiver
                            .exchange
                            .as_ref()
                            .context("restore_receiver_exchange_missing")?
                            .digest()?,
                        activation: Box::new(
                            self.receiver
                                .activation
                                .as_ref()
                                .context("restore_receiver_activation_missing")?
                                .clone(),
                        ),
                    },
                    Phase::SendActivated,
                ),
                Phase::SignReleased => (
                    RestoreBody::Released {
                        exchange: self
                            .receiver
                            .exchange
                            .as_ref()
                            .context("restore_receiver_exchange_missing")?
                            .digest()?,
                        activation: day2_capabilities::Digest::of(
                            self.receiver
                                .activation
                                .as_ref()
                                .context("restore_receiver_activation_missing")?,
                        )?,
                    },
                    Phase::SendReleased,
                ),
                _ => anyhow::bail!("restore_receiver_sign_order"),
            };
            let expected_sender = controller.digest()?;
            let message = self.sign_restore_body(storage, Body::Restore { payload })?;
            ensure!(
                message.sender == expected_sender,
                "restore_receiver_signer_changed"
            );
            self.receiver.outgoing = Some(message);
            Ok(next)
        }
    }

    fn send_packet(&mut self, phase: Phase) -> Result<(Phase, ReceiverProgress, bool)> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = phase;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let message = self
                .receiver
                .outgoing
                .as_ref()
                .context("restore_receiver_outgoing_missing")?;
            let bytes = serde_json::to_vec(message)?;
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                "restore_receiver_packet_bound"
            );
            let frame = message.body.frame();
            if !self.receiver.started {
                self.receiver.transcript.select_frame(frame)?;
                let observation = self.observation()?;
                self.receiver
                    .transcript
                    .begin(Direction::Send, observation)?;
                self.receiver.started = true;
            }
            match net::send(
                self.receiver
                    .socket
                    .as_ref()
                    .context("restore_receiver_socket_missing")?,
                &bytes,
                net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
            ) {
                Ok(count) => {
                    ensure!(count == bytes.len(), "restore_receiver_partial_packet");
                    self.receiver.delivered = Some(frame);
                    let next = match phase {
                        Phase::SendReady => Phase::ReceiveHello,
                        Phase::SendOffer => Phase::ReceiveConfirm,
                        Phase::SendDurable => Phase::ReceiveAccepted,
                        Phase::SendActivated => Phase::ReceiveKeeperAck,
                        Phase::SendReleased => Phase::Released,
                        _ => anyhow::bail!("restore_receiver_send_packet_order"),
                    };
                    Ok((next, ReceiverProgress::Delivered, false))
                }
                Err(Errno::AGAIN) => {
                    let observation = self.observation()?;
                    self.receiver
                        .transcript
                        .transport(Transport::WouldBlock, observation)?;
                    Ok((phase, ReceiverProgress::WouldBlock, true))
                }
                Err(Errno::INTR) => {
                    let observation = self.observation()?;
                    self.receiver
                        .transcript
                        .transport(Transport::Interrupted, observation)?;
                    Ok((phase, ReceiverProgress::Interrupted, false))
                }
                Err(error) => Err(error.into()),
            }
        }
    }

    fn receive_packet(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        phase: Phase,
    ) -> Result<ReceiverProgress> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (storage, phase);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            if !self.receiver.started {
                let observation = self.observation()?;
                self.receiver
                    .transcript
                    .begin(Direction::Receive, observation)?;
                self.receiver.started = true;
            }
            let mut bytes = [0u8; MAX_PACKET];
            let packet = match net::recv_pidfd_packet(
                self.receiver
                    .socket
                    .as_ref()
                    .context("restore_receiver_socket_missing")?,
                &mut [IoSliceMut::new(&mut bytes)],
            ) {
                Ok(packet) => packet,
                Err(net::RecvPidfdError::Io(Errno::AGAIN)) => {
                    let observation = self.observation()?;
                    self.receiver
                        .transcript
                        .transport(Transport::WouldBlock, observation)?;
                    return Ok(ReceiverProgress::WouldBlock);
                }
                Err(net::RecvPidfdError::Io(Errno::INTR)) => {
                    let observation = self.observation()?;
                    self.receiver
                        .transcript
                        .transport(Transport::Interrupted, observation)?;
                    return Ok(ReceiverProgress::Interrupted);
                }
                Err(error) => return Err(error.into()),
            };
            let count = packet.bytes;
            let sender = if let Some(admitted) = self.receiver.senders.first_mut() {
                MessageProcess::receive_admitted(
                    packet,
                    admitted,
                    &mut self.admission.preparation.original,
                    &HashCosts::disabled(),
                )?
            } else {
                MessageProcess::receive(
                    packet,
                    storage
                        .stage
                        .owner
                        .policy
                        .code(super::super::NativeRole::AppHost),
                    &mut self.admission.preparation.original,
                    &HashCosts::disabled(),
                )?
            };
            // Retain even a subsequently rejected packet's original pidfd so
            // the independent operation tail still observes the actual actor.
            self.receiver.senders.push(sender);
            let sender = self
                .receiver
                .senders
                .last()
                .context("restore_receiver_sender_missing")?;
            let message = super::super::storage_peer_wire::decode(&bytes[..count])?;
            let Body::Restore { payload } = &message.body else {
                anyhow::bail!("restore_receiver_message_kind");
            };
            ensure!(
                payload.sender_role() == super::super::NativeRole::AppHost,
                "restore_receiver_sender_role"
            );
            let controller = self
                .receiver
                .controller
                .as_ref()
                .context("restore_receiver_controller_missing")?;
            let projection = self
                .receiver
                .projection
                .as_ref()
                .context("restore_receiver_projection_missing")?;
            // Interpret remote absolute time only AFTER the actual kernel
            // sender has joined the Controller's node, boot and clock domain.
            super::super::runtime::require_common(sender.data(), &storage.stage.owner.self_data)?;
            let now = self.admission.preparation.original.sample()?.elapsed;
            match phase {
                Phase::ReceiveHello => {
                    let (app, nonce) = payload.hello(
                        &projection.selection,
                        self.receiver
                            .nonce
                            .as_ref()
                            .context("restore_receiver_nonce_missing")?,
                    )?;
                    ensure!(
                        self.receiver.app.is_none()
                            && self.receiver.app_nonce.is_none()
                            && app.authorization
                                == *self
                                    .admission
                                    .preparation
                                    .signed
                                    .as_ref()
                                    .context("restore_receiver_authorization_missing")?,
                        "restore_receiver_app_authorization_changed"
                    );
                    app.validate(
                        &storage.stage.owner.policy,
                        &self.admission.preparation.certificate,
                        sender.data(),
                        now,
                    )?;
                    app.require_controller(controller)?;
                    message.verify_restored_app(app)?;
                    self.receiver.app = Some(app.clone());
                    self.receiver.app_nonce = Some(nonce.clone());
                }
                Phase::ReceiveConfirm | Phase::ReceiveAccepted => {
                    let app = self
                        .receiver
                        .app
                        .as_ref()
                        .context("restore_receiver_app_missing")?;
                    app.validate(
                        &storage.stage.owner.policy,
                        &self.admission.preparation.certificate,
                        sender.data(),
                        now,
                    )?;
                    app.require_controller(controller)?;
                    message.verify_restored_app(app)?;
                    let step = if phase == Phase::ReceiveConfirm {
                        Step::Confirm
                    } else {
                        Step::Accepted
                    };
                    payload.require_file_echo(
                        step,
                        &self
                            .receiver
                            .exchange
                            .as_ref()
                            .context("restore_receiver_exchange_missing")?
                            .digest()?,
                        &projection.digest()?,
                    )?;
                }
                Phase::ReceiveKeeperAck => {
                    let app = self
                        .receiver
                        .app
                        .as_ref()
                        .context("restore_receiver_app_missing")?;
                    app.validate(
                        &storage.stage.owner.policy,
                        &self.admission.preparation.certificate,
                        sender.data(),
                        now,
                    )?;
                    app.require_controller(controller)?;
                    message.verify_restored_app(app)?;
                    ensure!(
                        self.receiver.keeper_ack.is_none(),
                        "restore_receiver_keeper_ack_repeated"
                    );
                    let activation = self
                        .receiver
                        .activation
                        .as_ref()
                        .context("restore_receiver_activation_missing")?;
                    let cohort = payload.activation_ack(
                        &self
                            .receiver
                            .exchange
                            .as_ref()
                            .context("restore_receiver_exchange_missing")?
                            .digest()?,
                        &day2_capabilities::Digest::of(activation)?,
                    )?;
                    self.receiver.keeper_ack = Some(cohort.clone());
                }
                _ => anyhow::bail!("restore_receiver_packet_order"),
            }
            self.receiver.delivered = Some(message.body.frame());
            Ok(ReceiverProgress::Delivered)
        }
    }

    fn complete_packet(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let frame = self
                .receiver
                .delivered
                .take()
                .context("restore_receiver_delivery_missing")?;
            let observation = self.observation()?;
            self.receiver.transcript.delivered(frame, observation)?;
            self.receiver.started = false;
            self.receiver.outgoing = None;
            Ok(())
        }
    }

    fn observation(&self) -> Result<Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let (domain, origin, deadline, now) = self
                .admission
                .preparation
                .original
                .historical_interval_observation();
            Ok(Observation {
                domain,
                origin,
                deadline,
                now,
            })
        }
    }

    fn poll_once(&mut self, phase: Phase) -> Result<ReceiverProgress> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = phase;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let socket = if phase == Phase::Accept {
                self.receiver.listener.as_ref()
            } else {
                self.receiver.socket.as_ref()
            }
            .context("restore_receiver_poll_socket_missing")?;
            let events = if matches!(
                phase,
                Phase::SendReady
                    | Phase::SendOffer
                    | Phase::SendDurable
                    | Phase::SendActivated
                    | Phase::SendReleased
            ) {
                PollFlags::OUT
            } else {
                PollFlags::IN
            };
            let mut fds = [PollFd::new(socket, events | PollFlags::RDHUP)];
            let timeout = rustix::event::Timespec::try_from(
                self.admission.preparation.original.remaining()?,
            )?;
            match rustix::event::poll(&mut fds, Some(&timeout)) {
                Ok(1) => {
                    let flags = fds[0].revents();
                    ensure!(
                        flags.contains(events)
                            && !flags.intersects(
                                PollFlags::HUP
                                    | PollFlags::RDHUP
                                    | PollFlags::ERR
                                    | PollFlags::NVAL
                            ),
                        "restore_receiver_poll_events"
                    );
                    if phase != Phase::Accept {
                        let observation = self.observation()?;
                        self.receiver
                            .transcript
                            .transport(Transport::Ready, observation)?;
                    }
                    Ok(ReceiverProgress::Advanced)
                }
                Ok(_) => anyhow::bail!("restore_receiver_poll_timeout_or_count"),
                Err(Errno::INTR) => Ok(ReceiverProgress::Interrupted),
                Err(error) => Err(error.into()),
            }
        }
    }

    fn require_accepted_prefix(&self) -> Result<()> {
        ensure!(
            !self.receiver.refused.get()
                && self.receiver.phase == Phase::Accepted
                && !self.receiver.waiting,
            "restore_receiver_not_accepted"
        );
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            ensure!(
                !self.receiver.started
                    && self.receiver.outgoing.is_none()
                    && self.receiver.delivered.is_none()
                    && self.receiver.root.is_some()
                    && self.receiver.directory.is_some()
                    && self.receiver.listener.is_some()
                    && self.receiver.socket.is_some()
                    && self.receiver.app.is_some()
                    && self.receiver.controller.is_some()
                    && self.receiver.projection.is_some()
                    && self.receiver.nonce.is_some()
                    && self.receiver.app_nonce.is_some()
                    && self.receiver.exchange.is_some()
                    && self.receiver.senders.len() == PRE_CAS_SENDERS
                    && writer_slot(&self.receiver.transcript),
                "restore_receiver_accepted_prefix_changed"
            );
            Ok(())
        }
    }

    /// The real Accepted prefix follows completed durability. Keep the WHOLE
    /// rendezvous while the fixed outer Context checks its actual target and
    /// provider half before publishing the composite P3 candidate.
    pub(in crate::security_epoch) fn into_peer(
        mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        target: &mut NativeStagedTarget<'_, '_>,
    ) -> Result<RestoredWriterPeer> {
        self.check(storage, target)?;
        let requested = self.require_accepted_prefix();
        if requested.is_err() {
            self.refuse();
            target.refuse();
        }
        requested?;
        Ok(RestoredWriterPeer { receiver: self })
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.receiver.refused.set(true);
        self.receiver.role.phase = RoleHandoffPhase::Refused;
        self.receiver.decision.phase = RoleHandoffPhase::Refused;
        #[cfg(target_os = "linux")]
        {
            self.receiver.transcript.refuse();
            if let Some(role) = &mut self.receiver.role.transcript {
                role.refuse();
            }
            if let Some(decision) = &mut self.receiver.decision.transcript {
                decision.refuse();
            }
        }
        self.admission.refuse();
    }
}

impl DecisionHandoffAttempt<'_, '_, '_, '_> {
    fn perform(
        mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        operation: RoleHandoffOperation,
    ) -> Result<ReceiverProgress> {
        let phase = self.peer.receiver.receiver.decision.phase;
        // Spend the same actual attempt before checking, signing, send or wait.
        self.peer.receiver.receiver.decision.phase = RoleHandoffPhase::Busy;
        let requested = (|| {
            let expected = match operation {
                RoleHandoffOperation::Prepare => RoleHandoffPhase::Fresh,
                RoleHandoffOperation::Sign => RoleHandoffPhase::Sign,
                RoleHandoffOperation::Send => RoleHandoffPhase::Send,
                RoleHandoffOperation::Poll => RoleHandoffPhase::Poll,
            };
            ensure!(phase == expected, "restore_role_decision_order");
            self.peer.check_final_installation(storage, self.loan)?;
            self.issuer.check(storage, self.peer, self.loan)?;
            self.activation
                .check(storage, self.peer, self.issuer, self.loan)?;
            self.effect(storage, operation)
        })();
        // Evaluate the actual activation/completion/native post independently,
        // even when the socket or signing operation returned its primary error.
        let checked = self
            .activation
            .check(storage, self.peer, self.issuer, self.loan);
        if requested.is_err() || checked.is_err() {
            self.peer.refuse();
            self.issuer.refuse();
            self.activation.refuse();
            self.loan.refuse();
        }
        let progress = requested?;
        checked?;
        let next = phase.after(operation, progress)?;
        #[cfg(target_os = "linux")]
        if next == RoleHandoffPhase::Delivered {
            use anyhow::Context;
            let observation = self.observation()?;
            let state = &mut self.peer.receiver.receiver.decision;
            let frame = state
                .delivered
                .take()
                .context("restore_role_decision_delivery_missing")?;
            state
                .transcript
                .as_mut()
                .context("restore_role_decision_transcript_missing")?
                .delivered(frame, observation)?;
            state.outgoing = None;
            state.started = false;
        }
        self.peer.receiver.receiver.decision.phase = next;
        self.done = true;
        Ok(progress)
    }

    fn observation(&mut self) -> Result<Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let mut actual = self.peer.role_handoff_observation(self.issuer)?;
            self.activation.pending.original.remaining()?;
            let (domain, origin, deadline, now) = self
                .activation
                .pending
                .original
                .historical_interval_observation();
            ensure!(
                actual.domain == domain && actual.origin == origin,
                "restore_role_decision_original_changed"
            );
            let signed = self
                .activation
                .pending
                .signed
                .as_ref()
                .context("restore_role_decision_missing")?;
            actual.deadline = actual
                .deadline
                .min(deadline)
                .min(std::time::Duration::from_nanos(
                    signed.statement.effective_deadline_ns,
                ));
            actual.now = actual.now.max(now);
            ensure!(
                actual.now < actual.deadline,
                "restore_role_decision_expired"
            );
            Ok(actual)
        }
    }

    fn effect(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        operation: RoleHandoffOperation,
    ) -> Result<ReceiverProgress> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (storage, operation);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let observation = self.observation()?;
            match operation {
                RoleHandoffOperation::Prepare => {
                    self.peer.require_role_handoff_delivered()?;
                    let signed = self
                        .activation
                        .pending
                        .signed
                        .as_ref()
                        .context("restore_role_decision_missing")?
                        .clone();
                    let state = &mut self.peer.receiver.receiver;
                    ensure!(
                        state.decision.transcript.is_none()
                            && state.decision.body.is_none()
                            && state.decision.outgoing.is_none()
                            && state.decision.delivered.is_none()
                            && !state.decision.started,
                        "restore_role_decision_already_started"
                    );
                    state.decision.transcript = Some(
                        state
                            .role
                            .transcript
                            .as_mut()
                            .context("restore_role_history_missing")?
                            .derive_restored_decision(observation)?,
                    );
                    state.decision.body = Some(Body::Restore {
                        payload: RestoreBody::RoleDecision {
                            exchange: state
                                .exchange
                                .as_ref()
                                .context("restore_receiver_exchange_missing")?
                                .digest()?,
                            decision: Box::new(signed),
                        },
                    });
                    Ok(ReceiverProgress::Advanced)
                }
                RoleHandoffOperation::Sign => {
                    let body = self
                        .peer
                        .receiver
                        .receiver
                        .decision
                        .body
                        .take()
                        .context("restore_role_decision_body_missing")?;
                    let message = self.peer.receiver.sign_restore_body(storage, body)?;
                    let role = &mut self.peer.receiver.receiver.decision;
                    let frame = message.body.frame();
                    let transcript = role
                        .transcript
                        .as_mut()
                        .context("restore_role_decision_transcript_missing")?;
                    ensure!(
                        transcript.next() == Some((Direction::Send, frame)),
                        "restore_role_decision_frame_changed"
                    );
                    transcript.select_frame(frame)?;
                    role.outgoing = Some(message);
                    Ok(ReceiverProgress::Advanced)
                }
                RoleHandoffOperation::Send => {
                    let state = &mut self.peer.receiver.receiver;
                    let role = &mut state.decision;
                    let message = role
                        .outgoing
                        .as_ref()
                        .context("restore_role_decision_packet_missing")?;
                    let bytes = serde_json::to_vec(message)?;
                    ensure!(
                        !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                        "restore_role_decision_packet_bound"
                    );
                    let frame = message.body.frame();
                    let transcript = role
                        .transcript
                        .as_mut()
                        .context("restore_role_decision_transcript_missing")?;
                    if !role.started {
                        transcript.begin(Direction::Send, observation.clone())?;
                        role.started = true;
                    }
                    match net::send(
                        state
                            .socket
                            .as_ref()
                            .context("restore_receiver_socket_missing")?,
                        &bytes,
                        net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
                    ) {
                        Ok(count) => {
                            ensure!(count == bytes.len(), "restore_role_decision_partial_packet");
                            role.delivered = Some(frame);
                            Ok(ReceiverProgress::Delivered)
                        }
                        Err(Errno::AGAIN) => {
                            transcript.transport(Transport::WouldBlock, observation)?;
                            Ok(ReceiverProgress::WouldBlock)
                        }
                        Err(Errno::INTR) => {
                            transcript.transport(Transport::Interrupted, observation)?;
                            Ok(ReceiverProgress::Interrupted)
                        }
                        Err(error) => Err(error.into()),
                    }
                }
                RoleHandoffOperation::Poll => {
                    let state = &mut self.peer.receiver.receiver;
                    let socket = state
                        .socket
                        .as_ref()
                        .context("restore_receiver_socket_missing")?;
                    let mut fds = [PollFd::new(socket, PollFlags::OUT | PollFlags::RDHUP)];
                    let remaining = observation
                        .deadline
                        .checked_sub(observation.now)
                        .context("restore_role_decision_expired")?;
                    let timeout = rustix::event::Timespec::try_from(remaining)?;
                    match rustix::event::poll(&mut fds, Some(&timeout)) {
                        Ok(1) => {
                            let flags = fds[0].revents();
                            ensure!(
                                flags.contains(PollFlags::OUT)
                                    && !flags.intersects(
                                        PollFlags::HUP
                                            | PollFlags::RDHUP
                                            | PollFlags::ERR
                                            | PollFlags::NVAL
                                    ),
                                "restore_role_decision_poll_events"
                            );
                            let observation = self.observation()?;
                            self.peer
                                .receiver
                                .receiver
                                .decision
                                .transcript
                                .as_mut()
                                .context("restore_role_decision_transcript_missing")?
                                .transport(Transport::Ready, observation)?;
                            Ok(ReceiverProgress::Advanced)
                        }
                        Ok(_) => anyhow::bail!("restore_role_decision_poll_timeout_or_count"),
                        Err(Errno::INTR) => Ok(ReceiverProgress::Interrupted),
                        Err(error) => Err(error.into()),
                    }
                }
            }
        }
    }
}

impl RestoredWriterPeer {
    /// Spend the actual Installed socket and final cursor once. Both native
    /// historical owners remain borrowed for every later fresh Current phase.
    pub(in crate::security_epoch::native_enrollment) fn take_current_peer<'tail>(
        &'tail mut self,
        installed: &'tail mut InstalledRestoredAppConfirmation,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<RestoredCurrentPeerPort<'tail>> {
        let mut attempt = RestoredControllerPortTransfer {
            peer: Some(self),
            installed: Some(installed),
            stage,
            done: false,
        };
        let requested: Result<RestoredCurrentPeerPort<'tail>> = (|| {
            attempt.stage.require_current_role()?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                let mut original = attempt.stage.narrow_io_acquisition(5)?;
                let peer = attempt
                    .peer
                    .as_deref_mut()
                    .context("restore_current_peer_missing")?;
                let installed = attempt
                    .installed
                    .as_deref_mut()
                    .context("restore_current_installed_missing")?;
                let binding =
                    installed.current_transfer_binding(peer, attempt.stage, &mut original)?;
                installed
                    .transcript
                    .as_ref()
                    .context("restore_current_cursor_missing")?
                    .require_installed_current_data(Actor::Controller)?;
                let local = peer
                    .receiver
                    .receiver
                    .controller
                    .as_ref()
                    .context("restore_receiver_controller_missing")?
                    .clone();
                let Body::Restore {
                    payload: RestoreBody::AppInstalled { app: remote, .. },
                } = &installed.message.body
                else {
                    anyhow::bail!("restore_current_installed_packet_kind");
                };
                let remote = remote.as_ref().clone();
                let anchor = installed
                    .sender
                    .retain_message_anchor(&mut original, &HashCosts::disabled())?;
                let same = attempt.stage.capture_same_owner()?;
                let native_refusal = original.retained_refusal();
                let channel_refusal = Rc::clone(&peer.receiver.receiver.refused);
                // No operational slot is restored after an uncertain take.
                ensure!(
                    peer.receiver.receiver.current_socket.is_none(),
                    "restore_current_socket_already_spent"
                );
                let socket = Rc::new(
                    peer.receiver
                        .receiver
                        .socket
                        .take()
                        .context("restore_current_socket_already_spent")?,
                );
                peer.receiver.receiver.current_socket = Some(Rc::clone(&socket));
                let transcript = installed
                    .transcript
                    .take()
                    .context("restore_current_cursor_already_spent")?;
                let peer = attempt
                    .peer
                    .take()
                    .context("restore_current_peer_missing")?;
                let installed = attempt
                    .installed
                    .take()
                    .context("restore_current_installed_missing")?;
                Ok(RestoredCurrentPeerPort {
                    socket: Some(socket),
                    transcript: Some(transcript),
                    anchor: Some(super::super::RestoredPeerAnchor::App(Box::new(anchor))),
                    same: Some(same),
                    local,
                    remote,
                    binding,
                    native_refusal: Some(native_refusal),
                    original: Some(original),
                    channel_refusal,
                    tail: Some(super::super::RestoredPeerTail::Controller { peer, installed }),
                    completed: false,
                    local_only: PhantomData,
                })
            }
        })();
        let checked = attempt.stage.check();
        if requested.is_err() || checked.is_err() {
            attempt.stage.refuse_serving();
        }
        let port = requested?;
        checked?;
        attempt.done = true;
        Ok(port)
    }
}

impl InstalledRestoredAppConfirmation {
    /// Negative provenance of the actual moved socket/gate and exact old
    /// packet pair. This samples no old clock and creates no current grant.
    pub(in crate::security_epoch::native_enrollment) fn check_current_source(
        &mut self,
        peer: &mut RestoredWriterPeer,
        source: &RestoredPeerSource<'_>,
    ) -> Result<()> {
        let requested = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (&mut *self, source);
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                let state = &peer.receiver.receiver;
                ensure!(
                    !state.refused.get()
                        && !self.refused
                        && state.socket.is_none()
                        && self.transcript.is_none(),
                    "restore_current_source_refused_or_not_transferred"
                );
                let retained = state
                    .current_socket
                    .as_ref()
                    .context("restore_current_socket_anchor_missing")?;
                ensure!(
                    Rc::ptr_eq(retained, source.socket)
                        && Rc::ptr_eq(&state.refused, source.refusal),
                    "restore_current_source_native_identity_changed"
                );
                ensure!(
                    Some(source.local) == state.controller.as_ref(),
                    "restore_current_source_local_changed"
                );
                let Body::Restore {
                    payload: installed_body,
                } = &self.message.body
                else {
                    anyhow::bail!("restore_current_installed_packet_kind");
                };
                let RestoreBody::AppInstalled { app, .. } = installed_body else {
                    anyhow::bail!("restore_current_installed_packet_kind");
                };
                let Body::Restore { payload: accepted } = &self
                    .acceptance
                    .as_ref()
                    .context("restore_current_acceptance_missing")?
                    .body
                else {
                    anyhow::bail!("restore_current_acceptance_packet_kind");
                };
                ensure!(
                    app.as_ref() == source.remote
                        && &installed_body.current_connection_binding_data(accepted)?
                            == source.binding,
                    "restore_current_source_packet_binding_changed"
                );
                Ok(())
            }
        })();
        if requested.is_err() {
            peer.refuse();
            self.refuse();
        }
        requested
    }

    /// Historical native/physical tail under the actual NEW Current. This
    /// deliberately never calls check_inner or samples any retired original.
    /// The old operational socket/cursor may already be absent after transfer.
    fn current_transfer_binding(
        &mut self,
        peer: &mut RestoredWriterPeer,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<day2_capabilities::Digest> {
        let requested: Result<day2_capabilities::Digest> = (|| {
            stage.require_current_role()?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (&mut *self, &mut *acquisition);
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                ensure!(
                    !peer.receiver.receiver.refused.get()
                        && peer.receiver.receiver.phase == Phase::Released
                        && peer.receiver.receiver.role.phase == RoleHandoffPhase::Delivered
                        && peer.receiver.receiver.decision.phase == RoleHandoffPhase::Delivered
                        && !self.refused
                        && self.acceptance_phase == PreparedAcceptancePhase::Delivered,
                    "restore_current_historical_tail_refused"
                );
                peer.receiver.admission.preparation.same.check(stage)?;
                self.same.check(stage)?;
                peer.receiver
                    .admission
                    .preparation
                    .original
                    .require_same_retired_peer(&mut self.original, acquisition)?;
                let state = &mut peer.receiver.receiver;
                let local = stage.storage()?.storage_statement()?;
                let retained = state
                    .controller
                    .as_ref()
                    .context("restore_receiver_controller_missing")?;
                ensure!(
                    local.same_enrollment(retained),
                    "restore_current_controller_owner_changed"
                );
                local.original.require_later_request(&retained.original)?;
                state
                    .directory
                    .as_ref()
                    .context("restore_receiver_directory_missing")?
                    .check(
                        state
                            .root
                            .as_ref()
                            .context("restore_receiver_root_missing")?,
                    )?;
                let listener = state
                    .listener
                    .as_ref()
                    .context("restore_receiver_listener_missing")?;
                ensure!(
                    rustix::io::fcntl_getfd(listener)?.contains(rustix::io::FdFlags::CLOEXEC),
                    "restore_receiver_socket_not_cloexec"
                );
                ensure!(!state.senders.is_empty(), "restore_receiver_sender_missing");
                let mut senders = state.senders.iter_mut().collect::<Vec<_>>();
                senders.push(&mut self.sender);
                MessageProcess::check_same_actor(
                    &mut senders,
                    acquisition,
                    &HashCosts::disabled(),
                )?;
                drop(senders);
                super::super::runtime::require_common(self.sender.data(), &stage.owner.self_data)?;
                let app = state.app.as_ref().context("restore_receiver_app_missing")?;
                self.message.verify_restored_app(app)?;
                let Body::Restore { payload } = &self.message.body else {
                    anyhow::bail!("restore_current_installed_packet_kind");
                };
                let Body::Restore {
                    payload: acceptance,
                } = &self
                    .acceptance
                    .as_ref()
                    .context("restore_current_acceptance_missing")?
                    .body
                else {
                    anyhow::bail!("restore_current_acceptance_packet_kind");
                };
                let RestoreBody::AppInstalled {
                    exchange,
                    cohort,
                    app,
                    ..
                } = payload
                else {
                    anyhow::bail!("restore_current_installed_packet_kind");
                };
                ensure!(
                    *exchange
                        == state
                            .exchange
                            .as_ref()
                            .context("restore_receiver_exchange_missing")?
                            .digest()?
                        && Some(cohort) == state.keeper_ack.as_ref()
                        && &app.stage.data.process == self.sender.data(),
                    "restore_current_installed_receiver_changed"
                );
                payload.current_connection_binding_data(acceptance)
            }
        })();
        let checked = stage
            .storage()
            .and_then(|mut storage| storage.check_storage_acquisition(acquisition));
        if requested.is_err() || checked.is_err() {
            peer.refuse();
            self.refuse();
            acquisition.refuse();
            stage.refuse_serving();
        }
        let binding = requested?;
        checked?;
        Ok(binding)
    }

    pub(in crate::security_epoch::native_enrollment) fn check_current_tail(
        &mut self,
        peer: &mut RestoredWriterPeer,
        binding: &day2_capabilities::Digest,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested = self.current_transfer_binding(peer, stage, acquisition);
        #[cfg(target_os = "linux")]
        let checked = (|| {
            ensure!(
                peer.receiver.receiver.socket.is_none() && self.transcript.is_none(),
                "restore_current_old_operational_slot_remains"
            );
            if let Ok(actual) = &requested {
                ensure!(actual == binding, "restore_current_tail_binding_changed");
            }
            Ok(())
        })();
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = {
            let _ = binding;
            Err(anyhow::anyhow!("native_restore_platform_unsupported"))
        };
        let tail = stage
            .storage()
            .and_then(|mut storage| storage.check_storage_acquisition(acquisition));
        if requested.is_err() || checked.is_err() || tail.is_err() {
            peer.refuse();
            self.refuse();
            acquisition.refuse();
            stage.refuse_serving();
        }
        requested?;
        checked?;
        tail
    }
}

impl RestoredWriterPeer {
    pub(in crate::security_epoch) fn prepare_role_decision(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        DecisionHandoffAttempt {
            peer: self,
            issuer: completed,
            activation,
            loan,
            done: false,
        }
        .perform(storage, RoleHandoffOperation::Prepare)
        .map(|_| ())
    }

    pub(in crate::security_epoch) fn sign_role_decision(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        DecisionHandoffAttempt {
            peer: self,
            issuer: completed,
            activation,
            loan,
            done: false,
        }
        .perform(storage, RoleHandoffOperation::Sign)
        .map(|_| ())
    }

    pub(in crate::security_epoch) fn try_send_role_decision(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<ReceiverProgress> {
        DecisionHandoffAttempt {
            peer: self,
            issuer: completed,
            activation,
            loan,
            done: false,
        }
        .perform(storage, RoleHandoffOperation::Send)
    }

    pub(in crate::security_epoch) fn poll_role_decision(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<ReceiverProgress> {
        DecisionHandoffAttempt {
            peer: self,
            issuer: completed,
            activation,
            loan,
            done: false,
        }
        .perform(storage, RoleHandoffOperation::Poll)
    }

    /// Native delivery only. The sole G1 activation entry separately requires
    /// its actual Delivered state AFTER its full independent outer post.
    pub(super) fn require_role_handoff_delivered(&self) -> Result<()> {
        self.require_peer_phase()?;
        ensure!(
            self.receiver.receiver.role.phase == RoleHandoffPhase::Delivered,
            "restore_role_activation_requires_native_delivery"
        );
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("native_restore_platform_unsupported");
        #[cfg(target_os = "linux")]
        {
            ensure!(
                self.receiver
                    .receiver
                    .role
                    .transcript
                    .as_ref()
                    .is_some_and(|history| history.complete()),
                "restore_role_activation_transcript_incomplete"
            );
            Ok(())
        }
    }

    /// Distinct final role-handoff send. It neither widens the old Released
    /// peer checks nor constructs an ordinary App role or Runtime.
    pub(in crate::security_epoch) fn prepare_role_handoff(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        self.role_handoff_operation(storage, completed, loan, RoleHandoffOperation::Prepare)
            .map(|_| ())
    }

    pub(in crate::security_epoch) fn sign_role_handoff(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        self.role_handoff_operation(storage, completed, loan, RoleHandoffOperation::Sign)
            .map(|_| ())
    }

    pub(in crate::security_epoch) fn try_send_role_handoff(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<ReceiverProgress> {
        self.role_handoff_operation(storage, completed, loan, RoleHandoffOperation::Send)
    }

    pub(in crate::security_epoch) fn poll_role_handoff(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<ReceiverProgress> {
        self.role_handoff_operation(storage, completed, loan, RoleHandoffOperation::Poll)
    }

    fn role_handoff_operation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
        operation: RoleHandoffOperation,
    ) -> Result<ReceiverProgress> {
        let mut attempt = RoleHandoffAttempt {
            peer: self,
            issuer: completed,
            loan,
            done: false,
        };
        let phase = attempt.peer.receiver.receiver.role.phase;
        // Retire the actual attempt before checks, signing, send or wait. Drop
        // also refuses all three real owners on a caught unwind.
        attempt.peer.receiver.receiver.role.phase = RoleHandoffPhase::Busy;
        let requested = (|| {
            let expected = match operation {
                RoleHandoffOperation::Prepare => RoleHandoffPhase::Fresh,
                RoleHandoffOperation::Sign => RoleHandoffPhase::Sign,
                RoleHandoffOperation::Send => RoleHandoffPhase::Send,
                RoleHandoffOperation::Poll => RoleHandoffPhase::Poll,
            };
            ensure!(phase == expected, "restore_role_handoff_order");
            attempt
                .peer
                .check_final_installation(storage, attempt.loan)?;
            attempt.issuer.check(storage, attempt.peer, attempt.loan)?;
            attempt
                .peer
                .role_handoff_effect(storage, attempt.issuer, operation)
        })();
        let checked = attempt.issuer.check(storage, attempt.peer, attempt.loan);
        if requested.is_err() || checked.is_err() {
            attempt.peer.refuse();
            attempt.issuer.refuse();
            attempt.loan.refuse();
        }
        let progress = requested?;
        checked?;
        let next = phase.after(operation, progress)?;
        #[cfg(target_os = "linux")]
        if next == RoleHandoffPhase::Delivered {
            use anyhow::Context;
            let observation = attempt.peer.role_handoff_observation(attempt.issuer)?;
            let role = &mut attempt.peer.receiver.receiver.role;
            let frame = role
                .delivered
                .take()
                .context("restore_role_handoff_delivery_missing")?;
            role.transcript
                .as_mut()
                .context("restore_role_handoff_transcript_missing")?
                .delivered(frame, observation)?;
            role.outgoing = None;
            role.started = false;
        }
        attempt.peer.receiver.receiver.role.phase = next;
        attempt.done = true;
        Ok(progress)
    }

    fn role_handoff_observation(
        &mut self,
        completed: &mut CompletedRestoreIssuer,
    ) -> Result<Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = completed;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            self.receiver.admission.preparation.original.remaining()?;
            completed.finishing.original.remaining()?;
            let mut peer = self.receiver.observation()?;
            let (domain, origin, deadline, now) = completed
                .finishing
                .original
                .historical_interval_observation();
            ensure!(
                peer.domain == domain && peer.origin == origin,
                "restore_role_handoff_original_changed"
            );
            let signed = completed
                .finishing
                .signed
                .as_ref()
                .context("restore_role_handoff_completion_missing")?;
            peer.deadline = peer
                .deadline
                .min(deadline)
                .min(std::time::Duration::from_nanos(
                    signed.statement.effective_deadline_ns,
                ));
            peer.now = peer.now.max(now);
            ensure!(peer.now < peer.deadline, "restore_role_handoff_expired");
            Ok(peer)
        }
    }

    fn role_handoff_effect(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        completed: &mut CompletedRestoreIssuer,
        operation: RoleHandoffOperation,
    ) -> Result<ReceiverProgress> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (storage, completed, operation);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let observation = self.role_handoff_observation(completed)?;
            match operation {
                RoleHandoffOperation::Prepare => {
                    let signed = completed
                        .finishing
                        .signed
                        .as_ref()
                        .context("restore_role_handoff_completion_missing")?
                        .clone();
                    let state = &mut self.receiver.receiver;
                    ensure!(
                        state.role.transcript.is_none()
                            && state.role.body.is_none()
                            && state.role.outgoing.is_none()
                            && state.role.delivered.is_none()
                            && !state.role.started,
                        "restore_role_handoff_already_started"
                    );
                    state.role.transcript =
                        Some(state.transcript.derive_restored_role(observation)?);
                    state.role.body = Some(Body::Restore {
                        payload: RestoreBody::RoleReady {
                            exchange: state
                                .exchange
                                .as_ref()
                                .context("restore_receiver_exchange_missing")?
                                .digest()?,
                            completion: Box::new(signed),
                        },
                    });
                    Ok(ReceiverProgress::Advanced)
                }
                RoleHandoffOperation::Sign => {
                    let body = self
                        .receiver
                        .receiver
                        .role
                        .body
                        .take()
                        .context("restore_role_handoff_body_missing")?;
                    let message = self.receiver.sign_restore_body(storage, body)?;
                    let role = &mut self.receiver.receiver.role;
                    let frame = message.body.frame();
                    let transcript = role
                        .transcript
                        .as_mut()
                        .context("restore_role_handoff_transcript_missing")?;
                    ensure!(
                        transcript.next() == Some((Direction::Send, frame)),
                        "restore_role_handoff_frame_changed"
                    );
                    transcript.select_frame(frame)?;
                    role.outgoing = Some(message);
                    Ok(ReceiverProgress::Advanced)
                }
                RoleHandoffOperation::Send => {
                    let state = &mut self.receiver.receiver;
                    let role = &mut state.role;
                    let message = role
                        .outgoing
                        .as_ref()
                        .context("restore_role_handoff_packet_missing")?;
                    let bytes = serde_json::to_vec(message)?;
                    ensure!(
                        !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                        "restore_role_handoff_packet_bound"
                    );
                    let frame = message.body.frame();
                    let transcript = role
                        .transcript
                        .as_mut()
                        .context("restore_role_handoff_transcript_missing")?;
                    if !role.started {
                        transcript.begin(Direction::Send, observation.clone())?;
                        role.started = true;
                    }
                    match net::send(
                        state
                            .socket
                            .as_ref()
                            .context("restore_receiver_socket_missing")?,
                        &bytes,
                        net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
                    ) {
                        Ok(count) => {
                            ensure!(count == bytes.len(), "restore_role_handoff_partial_packet");
                            role.delivered = Some(frame);
                            Ok(ReceiverProgress::Delivered)
                        }
                        Err(Errno::AGAIN) => {
                            transcript.transport(Transport::WouldBlock, observation)?;
                            Ok(ReceiverProgress::WouldBlock)
                        }
                        Err(Errno::INTR) => {
                            transcript.transport(Transport::Interrupted, observation)?;
                            Ok(ReceiverProgress::Interrupted)
                        }
                        Err(error) => Err(error.into()),
                    }
                }
                RoleHandoffOperation::Poll => {
                    let state = &mut self.receiver.receiver;
                    let socket = state
                        .socket
                        .as_ref()
                        .context("restore_receiver_socket_missing")?;
                    let mut fds = [PollFd::new(socket, PollFlags::OUT | PollFlags::RDHUP)];
                    let remaining = observation
                        .deadline
                        .checked_sub(observation.now)
                        .context("restore_role_handoff_expired")?;
                    let timeout = rustix::event::Timespec::try_from(remaining)?;
                    match rustix::event::poll(&mut fds, Some(&timeout)) {
                        Ok(1) => {
                            let flags = fds[0].revents();
                            ensure!(
                                flags.contains(PollFlags::OUT)
                                    && !flags.intersects(
                                        PollFlags::HUP
                                            | PollFlags::RDHUP
                                            | PollFlags::ERR
                                            | PollFlags::NVAL
                                    ),
                                "restore_role_handoff_poll_events"
                            );
                            let observation = self.role_handoff_observation(completed)?;
                            self.receiver
                                .receiver
                                .role
                                .transcript
                                .as_mut()
                                .context("restore_role_handoff_transcript_missing")?
                                .transport(Transport::Ready, observation)?;
                            Ok(ReceiverProgress::Advanced)
                        }
                        Ok(_) => anyhow::bail!("restore_role_handoff_poll_timeout_or_count"),
                        Err(Errno::INTR) => Ok(ReceiverProgress::Interrupted),
                        Err(error) => Err(error.into()),
                    }
                }
            }
        }
    }

    /// Comparison DATA derived inside the actual final-installation boundary.
    /// No caller supplies an App, activation, cohort or expected digest here.
    pub(super) fn finish_binding_data(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<(
        super::super::protocol::RestoreIssuerCompletionData,
        super::super::restore_peer_wire::RestoreAppStatement,
    )> {
        let requested = (|| {
            self.check_final_installation(storage, loan)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                let preparation = &self.receiver.admission.preparation;
                let authorization = preparation
                    .signed
                    .as_ref()
                    .context("restore_receiver_authorization_missing")?;
                let state = &self.receiver.receiver;
                let app = state.app.as_ref().context("restore_receiver_app_missing")?;
                ensure!(
                    &app.authorization == authorization,
                    "restore_issuer_finish_authorization_changed"
                );
                let activation = state
                    .activation
                    .as_ref()
                    .context("restore_receiver_activation_missing")?;
                let acknowledged = state
                    .keeper_ack
                    .as_ref()
                    .context("restore_receiver_keeper_ack_missing")?;
                let data = protocol::RestoreIssuerCompletionData {
                    frozen: preparation.data.frozen.clone(),
                    authorization: authorization.digest_data()?,
                    app: app.digest()?,
                    activation: day2_capabilities::Digest::of(activation)?,
                    cohort: acknowledged.clone(),
                };
                Ok((data, app.clone()))
            }
        })();
        let checked = self.check_final_installation(storage, loan);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            loan.refuse();
        }
        let data = requested?;
        checked?;
        Ok(data)
    }

    /// Final-installation purpose only. No release loan or receipt DATA can
    /// replace the actual complete native transcript and held Controller loan.
    pub(super) fn check_final_installation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            self.receiver.check_inner(storage)?;
            ensure!(
                self.receiver.receiver.phase == Phase::Released && !self.receiver.receiver.waiting,
                "restore_issuer_final_peer_not_released"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let state = &self.receiver.receiver;
                ensure!(
                    !state.started
                        && state.outgoing.is_none()
                        && state.delivered.is_none()
                        && state.transcript.complete()
                        && state.senders.len() == 4,
                    "restore_issuer_final_native_cohort_changed"
                );
                Ok(())
            }
        })();
        let checked: Result<()> = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = &*loan;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                let state = &self.receiver.receiver;
                let activation = state
                    .activation
                    .as_ref()
                    .context("restore_receiver_activation_missing")?;
                let acknowledged = state
                    .keeper_ack
                    .as_ref()
                    .context("restore_receiver_keeper_ack_missing")?;
                loan.check(storage, activation, acknowledged)
            }
        })();
        if requested.is_err() || checked.is_err() {
            self.refuse();
            loan.refuse();
        }
        requested?;
        checked
    }

    fn require_peer_phase(&self) -> Result<()> {
        ensure!(
            !self.receiver.receiver.refused.get()
                && matches!(
                    self.receiver.receiver.phase,
                    Phase::Accepted
                        | Phase::SignActivated
                        | Phase::SendActivated
                        | Phase::ReceiveKeeperAck
                        | Phase::KeeperAcknowledged
                        | Phase::SignReleased
                        | Phase::SendReleased
                        | Phase::Released
                ),
            "restore_writer_peer_refused_or_interrupted"
        );
        Ok(())
    }

    /// Native half only. The candidate keeps the actual file/creator and
    /// whole provider Context; no metadata copy replaces that other half.
    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<()> {
        let requested = self.require_peer_phase();
        let checked = self.receiver.check_inner(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn holder_data(
        &self,
    ) -> Result<crate::security_epoch::kernel::Holder> {
        self.require_peer_phase()?;
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        self.receiver
            .receiver
            .app
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("restore_receiver_app_missing"))?
            .holder_data()
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.receiver.refuse();
    }

    pub(in crate::security_epoch) fn prepare_activated(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterActivationLoan<'_>,
    ) -> Result<()> {
        self.activation_operation(storage, loan, ActivationOperation::Prepare)
            .map(|_| ())
    }

    pub(in crate::security_epoch) fn sign_activated(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterActivationLoan<'_>,
    ) -> Result<()> {
        self.activation_operation(storage, loan, ActivationOperation::Sign)
            .map(|_| ())
    }

    pub(in crate::security_epoch) fn try_send_activated(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterActivationLoan<'_>,
    ) -> Result<ReceiverProgress> {
        self.activation_operation(storage, loan, ActivationOperation::Send)
    }

    pub(in crate::security_epoch) fn poll_activation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterActivationLoan<'_>,
    ) -> Result<ReceiverProgress> {
        self.activation_operation(storage, loan, ActivationOperation::Poll)
    }

    pub(in crate::security_epoch) fn try_receive_keeper_ack(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterActivationLoan<'_>,
    ) -> Result<ReceiverProgress> {
        self.activation_operation(storage, loan, ActivationOperation::ReceiveAck)
    }

    pub(in crate::security_epoch) fn prepare_released(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterReleaseLoan<'_, '_, '_>,
    ) -> Result<()> {
        self.release_operation(storage, loan, ReleaseOperation::Prepare)
            .map(|_| ())
    }

    pub(in crate::security_epoch) fn sign_released(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterReleaseLoan<'_, '_, '_>,
    ) -> Result<()> {
        self.release_operation(storage, loan, ReleaseOperation::Sign)
            .map(|_| ())
    }

    pub(in crate::security_epoch) fn try_send_released(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterReleaseLoan<'_, '_, '_>,
    ) -> Result<ReceiverProgress> {
        self.release_operation(storage, loan, ReleaseOperation::Send)
    }

    pub(in crate::security_epoch) fn poll_release(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterReleaseLoan<'_, '_, '_>,
    ) -> Result<ReceiverProgress> {
        self.release_operation(storage, loan, ReleaseOperation::Poll)
    }

    fn release_guard(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterReleaseLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = self.receiver.check_inner(storage);
        let checked: Result<()> = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = &*loan;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                let state = &self.receiver.receiver;
                ensure!(
                    state.senders.len() == 4,
                    "restore_release_actual_ack_sender_missing"
                );
                let activation = state
                    .activation
                    .as_ref()
                    .context("restore_receiver_activation_missing")?;
                let acknowledged = state
                    .keeper_ack
                    .as_ref()
                    .context("restore_receiver_keeper_ack_missing")?;
                loan.check(storage, activation, acknowledged)
            }
        })();
        if requested.is_err() || checked.is_err() {
            self.refuse();
            loan.refuse();
        }
        requested?;
        checked
    }

    fn release_operation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterReleaseLoan<'_, '_, '_>,
        operation: ReleaseOperation,
    ) -> Result<ReceiverProgress> {
        let entered = self.require_peer_phase();
        if entered.is_err() {
            self.refuse();
            loan.refuse();
        }
        entered?;
        let phase = self.receiver.receiver.phase;
        let waiting = self.receiver.receiver.waiting;
        self.receiver.receiver.phase = Phase::Busy;
        let requested = (|| {
            ensure!(
                operation.permits(phase, waiting),
                "restore_release_operation_order"
            );
            self.release_guard(storage, loan)?;
            match operation {
                ReleaseOperation::Prepare => {
                    #[cfg(not(target_os = "linux"))]
                    {
                        anyhow::bail!("native_restore_platform_unsupported");
                    }
                    #[cfg(target_os = "linux")]
                    {
                        let state = &self.receiver.receiver;
                        ensure!(
                            !state.started
                                && state.outgoing.is_none()
                                && state.delivered.is_none()
                                && release_slot(&state.transcript),
                            "restore_release_ack_prefix_changed"
                        );
                        Ok((Phase::SignReleased, ReceiverProgress::Advanced, false))
                    }
                }
                ReleaseOperation::Sign => self
                    .receiver
                    .sign_packet(storage, phase)
                    .map(|next| (next, ReceiverProgress::Advanced, false)),
                ReleaseOperation::Send => self.receiver.send_packet(phase),
                ReleaseOperation::Poll => self
                    .receiver
                    .poll_once(phase)
                    .map(|progress| (phase, progress, progress == ReceiverProgress::Interrupted)),
            }
        })();
        let checked = self.release_guard(storage, loan);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            loan.refuse();
        }
        let (next, progress, waiting) = requested?;
        checked?;
        if progress == ReceiverProgress::Delivered {
            let completed = self.receiver.complete_packet();
            if completed.is_err() {
                self.refuse();
                loan.refuse();
            }
            completed?;
            #[cfg(target_os = "linux")]
            if !self.receiver.receiver.transcript.complete() {
                self.refuse();
                loan.refuse();
                anyhow::bail!("restore_release_transcript_incomplete");
            }
        }
        self.receiver.receiver.phase = next;
        self.receiver.receiver.waiting = waiting;
        Ok(progress)
    }

    /// Both the actual retained native half and the genuine post-CAS loan
    /// are checked, including after errors. This derives DATA only; the whole
    /// Confirmation retains target/provider/UV/keys around every operation.
    fn activation_guard(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterActivationLoan<'_>,
    ) -> Result<crate::security_epoch::native_enrollment::RestoreWriterActivationData> {
        let requested = self.receiver.check_inner(storage);
        let checked = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = &*loan;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                let state = &self.receiver.receiver;
                let projection = state
                    .projection
                    .as_ref()
                    .context("restore_receiver_projection_missing")?;
                let holder = state
                    .app
                    .as_ref()
                    .context("restore_receiver_app_missing")?
                    .holder_data()?;
                let data = loan.check(storage, projection, &holder)?;
                ensure!(
                    state.activation.as_ref().is_none_or(|old| old == &data),
                    "restore_receiver_activation_changed"
                );
                Ok(data)
            }
        })();
        if requested.is_err() || checked.is_err() {
            self.refuse();
            loan.refuse();
        }
        requested?;
        checked
    }

    fn activation_operation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreWriterActivationLoan<'_>,
        operation: ActivationOperation,
    ) -> Result<ReceiverProgress> {
        let entered = self.require_peer_phase();
        if entered.is_err() {
            self.refuse();
            loan.refuse();
        }
        entered?;
        let phase = self.receiver.receiver.phase;
        let waiting = self.receiver.receiver.waiting;
        self.receiver.receiver.phase = Phase::Busy;
        let requested = (|| {
            ensure!(
                operation.permits(phase, waiting),
                "restore_writer_activation_order"
            );
            let data = self.activation_guard(storage, loan)?;
            match operation {
                ActivationOperation::Prepare => {
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = data;
                        anyhow::bail!("native_restore_platform_unsupported");
                    }
                    #[cfg(target_os = "linux")]
                    {
                        ensure!(
                            self.receiver.receiver.activation.is_none(),
                            "restore_receiver_activation_repeated"
                        );
                        self.receiver.receiver.activation = Some(data);
                        Ok((Phase::SignActivated, ReceiverProgress::Advanced, false))
                    }
                }
                ActivationOperation::Sign => self
                    .receiver
                    .sign_packet(storage, phase)
                    .map(|next| (next, ReceiverProgress::Advanced, false)),
                ActivationOperation::Send => self.receiver.send_packet(phase),
                ActivationOperation::Poll => self
                    .receiver
                    .poll_once(phase)
                    .map(|progress| (phase, progress, progress == ReceiverProgress::Interrupted)),
                ActivationOperation::ReceiveAck => self
                    .receiver
                    .receive_packet(storage, phase)
                    .map(|progress| {
                        let next = if progress == ReceiverProgress::Delivered {
                            Phase::KeeperAcknowledged
                        } else {
                            phase
                        };
                        (next, progress, progress == ReceiverProgress::WouldBlock)
                    }),
            }
        })();
        let checked = self.activation_guard(storage, loan);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            loan.refuse();
        }
        let (next, progress, waiting) = requested?;
        checked?;
        if progress == ReceiverProgress::Delivered {
            let completed = self.receiver.complete_packet();
            if completed.is_err() {
                self.refuse();
                loan.refuse();
            }
            completed?;
        }
        self.receiver.receiver.phase = next;
        self.receiver.receiver.waiting = waiting;
        Ok(progress)
    }
}

#[cfg(test)]
mod final_installation_tests {
    use quote::ToTokens;

    fn tokens(source: &str) -> String {
        fn normalize(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => None,
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '?' => {
                        Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                            '?',
                            proc_macro2::Spacing::Alone,
                        )))
                    }
                    proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(group.delimiter(), normalize(group.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        normalize(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }

    fn named(name: &str) -> String {
        let file = syn::parse_file(include_str!("restore_receiver.rs")).unwrap();
        let mut methods=file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(owner)=item else{return None};
            if !matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.is_ident("RestoredWriterPeer")){return None;}
            owner.items.into_iter().find_map(|item|match item {
                syn::ImplItem::Fn(method) if method.sig.ident==name=>Some(tokens(&method.into_token_stream().to_string())),_=>None,
            })
        });
        let method = methods.next().unwrap();
        assert!(methods.next().is_none());
        method
    }

    fn actual() -> String {
        named("check_final_installation")
    }

    fn guarded(body: &str) -> bool {
        let mut rest = body;
        for part in [
            "RestoreFinalInstallationLoan",
            "let requested:Result<()>",
            "self.receiver.check_inner(storage)?;",
            "self.receiver.receiver.phase==Phase::Released",
            "!state.started && state.outgoing.is_none() && state.delivered.is_none()",
            "state.transcript.complete() && state.senders.len()==4",
            "let checked:Result<()>",
            "state.activation.as_ref()",
            "state.keeper_ack.as_ref()",
            "loan.check(storage,activation,acknowledged)",
            "if requested.is_err() || checked.is_err() {self.refuse();loan.refuse();}",
            "requested?;checked",
        ] {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        body.matches(&tokens("requested?")).count() == 1
            && !body.contains(&tokens("RestoreWriterReleaseLoan"))
            && !body.contains(&tokens("NativeAcquisition::begin"))
    }

    #[test]
    fn actual_final_installation_guard_joins_completed_peer_and_distinct_loan_even_on_error() {
        assert_eq!(
            tokens("loan.check(storage,activation,ack)?;"),
            tokens("loan.check(storage,activation,ack) ? ;")
        );
        let actual = actual();
        assert!(guarded(&actual));
        assert!(!guarded(&tokens(
            "fn check_final_installation()->Result<()> {Ok(())}"
        )));
        for (before, after) in [
            ("RestoreFinalInstallationLoan", "RestoreWriterReleaseLoan"),
            ("self.receiver.check_inner(storage)?;", "let _unchecked=();"),
            (
                "state.transcript.complete() && state.senders.len()==4",
                "true",
            ),
            ("state.keeper_ack.as_ref()", "caller_ack.as_ref()"),
            ("loan.check(storage,activation,acknowledged)", "Ok(())"),
            (
                "let checked:Result<()>",
                "requested?;let checked:Result<()>",
            ),
            ("self.refuse();loan.refuse();", "self.refuse();"),
            ("requested?;checked", "checked?;requested"),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !guarded(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
    }

    fn binding_is_actual(body: &str) -> bool {
        let mut rest = body;
        for part in [
            "RestoreFinalInstallationLoan",
            "self.check_final_installation(storage,loan)?;",
            "let preparation = &self.receiver.admission.preparation;",
            "preparation.signed.as_ref()",
            "let state = &self.receiver.receiver;",
            "state.app.as_ref()",
            "&app.authorization==authorization",
            "state.activation.as_ref()",
            "state.keeper_ack.as_ref()",
            "protocol::RestoreIssuerCompletionData",
            "frozen:preparation.data.frozen.clone()",
            "authorization:authorization.digest_data()?",
            "app:app.digest()?",
            "activation:day2_capabilities::Digest::of(activation)?",
            "cohort:acknowledged.clone()",
            "Ok((data,app.clone()))",
            "let checked=self.check_final_installation(storage,loan);",
            "if requested.is_err() || checked.is_err() {self.refuse();loan.refuse();}",
            "let data=requested?;checked?;Ok(data)",
        ] {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                eprintln!("missing ordered completion binding: {part}");
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        body.matches(&tokens("requested?")).count() == 1
            && !body.contains(&tokens("NativeAcquisition::begin"))
    }

    #[test]
    fn actual_completion_data_comes_only_from_same_prepared_peer_activation_and_ack() {
        for source in [
            "{let preparation = &self.receiver.admission.preparation;}",
            "{let state = &self.receiver.receiver;}",
        ] {
            let parsed: syn::Block = syn::parse_str(source).unwrap();
            assert_eq!(
                tokens(source),
                tokens(&parsed.to_token_stream().to_string())
            );
        }
        let actual_borrow: syn::Block =
            syn::parse_str("{let preparation=&self.receiver.admission.preparation;}").unwrap();
        let foreign_borrow: syn::Block =
            syn::parse_str("{let preparation=&other.receiver.admission.preparation;}").unwrap();
        assert_ne!(
            tokens(&actual_borrow.to_token_stream().to_string()),
            tokens(&foreign_borrow.to_token_stream().to_string())
        );
        let actual = named("finish_binding_data");
        assert!(binding_is_actual(&actual));
        for (before, after) in [
            (
                "self.check_final_installation(storage,loan)?;",
                "let _unchecked=();",
            ),
            ("&app.authorization==authorization", "true"),
            (
                "frozen:preparation.data.frozen.clone()",
                "frozen:caller_frozen",
            ),
            (
                "authorization:authorization.digest_data()?",
                "authorization:caller_authorization",
            ),
            ("app:app.digest()?", "app:caller_app"),
            (
                "activation:day2_capabilities::Digest::of(activation)?",
                "activation:caller_activation",
            ),
            ("cohort:acknowledged.clone()", "cohort:caller_cohort"),
            (
                "let checked=self.check_final_installation(storage,loan);",
                "requested?;let checked=self.check_final_installation(storage,loan);",
            ),
            ("self.refuse();loan.refuse();", "self.refuse();"),
            (
                "let data=requested?;checked?;Ok(data)",
                "checked?;let data=requested?;Ok(data)",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !binding_is_actual(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
    }

    #[test]
    fn role_handoff_keeps_actual_completed_parent_and_independent_posts() {
        let actual = named("role_handoff_operation");
        let valid = |body: &str| {
            let mut rest = body;
            for part in [
                "let mut attempt=RoleHandoffAttempt {peer:self,issuer:completed,loan,done:false};",
                "let phase=attempt.peer.receiver.receiver.role.phase;",
                "attempt.peer.receiver.receiver.role.phase=RoleHandoffPhase::Busy;",
                "let requested=",
                "ensure!(phase==expected,\"restore_role_handoff_order\");",
                "attempt.peer.check_final_installation(storage,attempt.loan)?;",
                "attempt.issuer.check(storage,attempt.peer,attempt.loan)?;",
                "attempt.peer.role_handoff_effect(storage,attempt.issuer,operation)",
                "let checked=attempt.issuer.check(storage,attempt.peer,attempt.loan);",
                "if requested.is_err() || checked.is_err() {attempt.peer.refuse();attempt.issuer.refuse();attempt.loan.refuse();}",
                "let progress=requested?;checked?;",
                "let next=phase.after(operation,progress)?;",
                "RoleHandoffPhase::Delivered",
                ".delivered(frame,observation)?;",
                "attempt.peer.receiver.receiver.role.phase=next;",
                "attempt.done=true;",
                "Ok(progress)",
            ] {
                let part = tokens(part);
                let Some(at) = rest.find(&part) else {
                    return false;
                };
                rest = &rest[at + part.len()..];
            }
            body.matches(&tokens("requested?")).count() == 1
                && !body.contains(&tokens("NativeAcquisition::begin"))
        };
        assert!(valid(&actual));
        for (before, after) in [
            ("done:false", "done:true"),
            (
                "attempt.peer.receiver.receiver.role.phase=RoleHandoffPhase::Busy;",
                "let _unretired=();",
            ),
            (
                "ensure!(phase==expected,\"restore_role_handoff_order\");",
                "let _unchecked=();",
            ),
            (
                "attempt.issuer.check(storage,attempt.peer,attempt.loan)?;",
                "Ok::<(),anyhow::Error>(())?;",
            ),
            (
                "let checked=attempt.issuer.check(storage,attempt.peer,attempt.loan);",
                "let checked=Ok::<(),anyhow::Error>(());",
            ),
            (
                "let progress=requested?;checked?;",
                "checked?;let progress=requested?;",
            ),
            ("attempt.done=true;", "let _never_settled=();"),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !valid(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
        for (name, operation) in [
            ("prepare_role_handoff", "Prepare"),
            ("sign_role_handoff", "Sign"),
            ("try_send_role_handoff", "Send"),
            ("poll_role_handoff", "Poll"),
        ] {
            let body = named(name);
            assert!(body.contains(&tokens("&mut CompletedRestoreIssuer")));
            assert!(body.contains(&tokens("RestoreFinalInstallationLoan")));
            assert!(body.contains(&tokens(&format!("self.role_handoff_operation(storage,completed,loan,RoleHandoffOperation::{operation})"))));
            assert!(!body.contains(&tokens("NativeAcquisition::begin")));
        }
        let file = syn::parse_file(include_str!("../owner.rs")).unwrap();
        let drops = file
            .items
            .into_iter()
            .filter_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                let Some((_, path, _)) = &item.trait_ else {
                    return None;
                };
                if !path.is_ident("Drop") {
                    return None;
                }
                let syn::Type::Path(ty) = &*item.self_ty else {
                    return None;
                };
                if !ty
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "RoleHandoffAttempt")
                {
                    return None;
                }
                Some(tokens(&item.to_token_stream().to_string()))
            })
            .collect::<Vec<_>>();
        assert_eq!(drops.len(), 1);
        assert!(drops[0].contains(&tokens(
            "if !self.done {self.peer.refuse();self.issuer.refuse();self.loan.refuse();}"
        )));
    }

    #[test]
    fn role_handoff_effect_uses_actual_completion_packet_and_earliest_original() {
        let effect = named("role_handoff_effect");
        let guarded = |body: &str| {
            [
                "let observation=self.role_handoff_observation(completed)?;",
                "completed.finishing.signed.as_ref()",
                "state.transcript.derive_restored_role(observation)?",
                "RestoreBody::RoleReady",
                "completion:Box::new(signed)",
                "self.receiver.sign_restore_body(storage,body)?",
                "transcript.next()==Some((Direction::Send,frame))",
                "!bytes.is_empty() && bytes.len()<=MAX_PACKET",
                "transcript.begin(Direction::Send,observation.clone())?",
                "net::send",
                "count==bytes.len()",
                "role.delivered=Some(frame)",
                "Transport::WouldBlock",
                "Transport::Interrupted",
                "observation.deadline.checked_sub(observation.now)",
                "PollFlags::HUP|PollFlags::RDHUP|PollFlags::ERR|PollFlags::NVAL",
                "Transport::Ready",
            ]
            .iter()
            .all(|part| body.contains(&tokens(part)))
        };
        assert!(guarded(&effect));
        for (before, after) in [
            (
                "completed.finishing.signed.as_ref()",
                "other_completion.as_ref()",
            ),
            (
                "state.transcript.derive_restored_role(observation)?",
                "Transcript::new(Protocol::RestoredRole,Actor::Controller)",
            ),
            ("count==bytes.len()", "true"),
            (
                "observation.deadline.checked_sub(observation.now)",
                "Some(std::time::Duration::from_secs(5))",
            ),
            (
                "PollFlags::HUP|PollFlags::RDHUP|PollFlags::ERR|PollFlags::NVAL",
                "PollFlags::ERR",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(effect.matches(&before).count(), 1, "{before}");
            assert!(
                !guarded(&effect.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
        let observation = named("role_handoff_observation");
        for required in [
            "self.receiver.admission.preparation.original.remaining()?;",
            "completed.finishing.original.remaining()?;",
            "peer.domain==domain && peer.origin==origin",
            "peer.deadline.min(deadline).min(std::time::Duration::from_nanos(signed.statement.effective_deadline_ns))",
            "peer.now=peer.now.max(now)",
            "peer.now<peer.deadline",
        ] {
            assert!(observation.contains(&tokens(required)), "{required}");
        }
        let actual_narrow: syn::ExprMethodCall = syn::parse_quote!(original.narrow(5, ceiling));
        assert!(tokens(&actual_narrow.to_token_stream().to_string()).contains(&tokens(".narrow")));
        for forbidden in [
            "NativeAcquisition::begin",
            ".narrow",
            "role_handoff_unavailable",
        ] {
            assert!(!observation.contains(&tokens(forbidden)));
        }
    }

    #[test]
    fn role_handoff_independent_fixed_transition_matrix_rejects_reentry() {
        use super::{ReceiverProgress as P, RoleHandoffOperation as O, RoleHandoffPhase as S};
        let allowed = [
            (S::Fresh, O::Prepare, P::Advanced, S::Sign),
            (S::Sign, O::Sign, P::Advanced, S::Send),
            (S::Send, O::Send, P::Delivered, S::Delivered),
            (S::Send, O::Send, P::WouldBlock, S::Poll),
            (S::Send, O::Send, P::Interrupted, S::Send),
            (S::Poll, O::Poll, P::Advanced, S::Send),
            (S::Poll, O::Poll, P::Interrupted, S::Poll),
        ];
        for phase in [
            S::Fresh,
            S::Busy,
            S::Sign,
            S::Send,
            S::Poll,
            S::Delivered,
            S::Refused,
        ] {
            for operation in [O::Prepare, O::Sign, O::Send, O::Poll] {
                for progress in [P::Advanced, P::Delivered, P::WouldBlock, P::Interrupted] {
                    let expected = allowed
                        .iter()
                        .find(|row| (row.0, row.1, row.2) == (phase, operation, progress));
                    match expected {
                        Some(row) => assert_eq!(phase.after(operation, progress).unwrap(), row.3),
                        None => assert!(phase.after(operation, progress).is_err()),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod release_source_tests {
    use super::{Phase, ReleaseOperation};
    use quote::ToTokens;

    fn tokens(source: &str) -> String {
        fn strip(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => None,
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '?' => {
                        Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                            '?',
                            proc_macro2::Spacing::Alone,
                        )))
                    }
                    proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(group.delimiter(), strip(group.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        strip(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }

    #[test]
    fn release_source_fragments_match_parsed_try_statements_without_dropping_the_try_operator() {
        let source = "{let progress=step()?;progress?;}";
        let parsed: syn::Block = syn::parse_str(source).unwrap();
        assert_eq!(
            tokens(source),
            tokens(&parsed.to_token_stream().to_string())
        );
        assert_ne!(tokens(source), tokens("{let progress=step();progress?;}"));
    }

    fn parsed_method(owner_name: &str, name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("restore_receiver.rs")).unwrap();
        let mut found = file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(owner) = item else {
                return None;
            };
            if owner.trait_.is_some()
                || !matches!(&*owner.self_ty,syn::Type::Path(path)
                if path.path.segments.len()==1 && path.path.segments[0].ident==owner_name)
            {
                return None;
            }
            owner.items.into_iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            })
        });
        let body = found.next().unwrap();
        assert!(found.next().is_none());
        body
    }

    fn method(owner_name: &str, name: &str) -> String {
        tokens(
            &parsed_method(owner_name, name)
                .into_token_stream()
                .to_string(),
        )
    }

    fn uses_release_loan(signature: &syn::Signature) -> bool {
        let expected: syn::Type = syn::parse_quote!(
            &mut crate::security_epoch::bootstrap::RestoreWriterReleaseLoan<'_, '_, '_>
        );
        let expected = tokens(&expected.into_token_stream().to_string());
        let mut loans = signature.inputs.iter().filter_map(|input| {
            let syn::FnArg::Typed(input) = input else {
                return None;
            };
            matches!(&*input.pat, syn::Pat::Ident(binding) if binding.ident == "loan")
                .then_some(&input.ty)
        });
        loans
            .next()
            .is_some_and(|actual| tokens(&actual.to_token_stream().to_string()) == expected)
            && loans.next().is_none()
    }

    fn ordered(body: &str, parts: &[&str]) -> bool {
        let mut rest = body;
        for part in parts {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        true
    }

    fn guarded(body: &str) -> bool {
        ordered(
            body,
            &[
                "let requested=self.receiver.check_inner(storage);",
                "let checked:Result<()>",
                "let state = &self.receiver.receiver;",
                "state.senders.len()==4",
                "state.activation.as_ref()",
                "state.keeper_ack.as_ref()",
                "loan.check(storage,activation,acknowledged)",
                "requested.is_err() || checked.is_err()",
                "self.refuse();loan.refuse();",
                "requested?;checked",
            ],
        )
    }

    fn operation_is_closed(body: &str) -> bool {
        ordered(
            body,
            &[
                "let entered=self.require_peer_phase();",
                "entered?;",
                "let phase=self.receiver.receiver.phase;",
                "let waiting=self.receiver.receiver.waiting;",
                "self.receiver.receiver.phase=Phase::Busy;",
                "let requested=",
                "operation.permits(phase,waiting)",
                "self.release_guard(storage,loan)?;",
                "release_slot(&state.transcript)",
                "ReleaseOperation::Sign",
                "self.receiver.sign_packet(storage,phase)",
                "ReleaseOperation::Send",
                "self.receiver.send_packet(phase)",
                "ReleaseOperation::Poll",
                "self.receiver.poll_once(phase)",
                "let checked=self.release_guard(storage,loan);",
                "requested.is_err() || checked.is_err()",
                "self.refuse();loan.refuse();",
                "let (next,progress,waiting)=requested?;checked?;",
                "self.receiver.complete_packet()",
                "self.receiver.receiver.transcript.complete()",
                "self.receiver.receiver.phase=next;",
                "self.receiver.receiver.waiting=waiting;",
            ],
        ) && ![
            "NativeAcquisition::begin",
            "NativeAcquisition::narrow",
            "activation_guard",
            "loan.clone",
        ]
        .iter()
        .any(|part| body.contains(&tokens(part)))
    }

    #[test]
    fn actual_release_requires_the_same_actual_ack_and_new_cohort_loan_even_after_native_error() {
        let actual = method("RestoredWriterPeer", "release_guard");
        assert!(guarded(&actual));
        for (before, after) in [
            ("self.receiver.check_inner(storage)", "Ok(())"),
            ("state.senders.len()==4", "true"),
            ("state.activation.as_ref()", "other_activation.as_ref()"),
            ("state.keeper_ack.as_ref()", "other_ack.as_ref()"),
            ("loan.check(storage,activation,acknowledged)", "Ok(())"),
            ("requested?;checked", "checked?;requested"),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1);
            assert!(!guarded(&actual.replacen(&before, &tokens(after), 1)));
        }
    }

    #[test]
    fn actual_release_operations_retire_before_effect_and_post_before_delivery_without_clock_reset()
    {
        let actual = method("RestoredWriterPeer", "release_operation");
        assert!(operation_is_closed(&actual));
        for (before, after) in [
            (
                "self.receiver.receiver.phase=Phase::Busy;",
                "let _unretired=();",
            ),
            ("self.release_guard(storage,loan)?;", "let _unchecked=();"),
            (
                "let checked=self.release_guard(storage,loan);",
                "let checked:Result<()>=Ok(());",
            ),
            (
                "let (next,progress,waiting)=requested?;checked?;",
                "checked?;let (next,progress,waiting)=requested?;",
            ),
            ("self.receiver.receiver.transcript.complete()", "true"),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1);
            assert!(!operation_is_closed(&actual.replacen(
                &before,
                &tokens(after),
                1
            )));
        }
        for (name, variant) in [
            ("prepare_released", "Prepare"),
            ("sign_released", "Sign"),
            ("try_send_released", "Send"),
            ("poll_release", "Poll"),
        ] {
            let mut parsed = parsed_method("RestoredWriterPeer", name);
            assert!(uses_release_loan(&parsed.sig));
            for input in &mut parsed.sig.inputs {
                match input {
                    syn::FnArg::Typed(input) if matches!(&*input.pat, syn::Pat::Ident(binding) if binding.ident == "loan") =>
                    {
                        input.ty = syn::parse_quote!(
                            &mut crate::security_epoch::bootstrap::RestoreWriterActivationLoan<'_>
                        );
                    }
                    _ => {}
                }
            }
            assert!(!uses_release_loan(&parsed.sig));
            let actual = method("RestoredWriterPeer", name);
            assert!(actual.contains(&tokens(&format!(
                "self.release_operation(storage,loan,ReleaseOperation::{variant})"
            ))));
            assert!(!actual.contains("RestoreWriterActivationLoan"));
        }
    }

    #[test]
    fn release_operation_choices_cannot_reenter_acknowledged_or_delivered_slots() {
        for phase in [
            Phase::Accepted,
            Phase::SignActivated,
            Phase::SendActivated,
            Phase::ReceiveKeeperAck,
            Phase::KeeperAcknowledged,
            Phase::SignReleased,
            Phase::SendReleased,
            Phase::Released,
            Phase::Busy,
        ] {
            for waiting in [false, true] {
                for operation in [
                    ReleaseOperation::Prepare,
                    ReleaseOperation::Sign,
                    ReleaseOperation::Send,
                    ReleaseOperation::Poll,
                ] {
                    let expected = matches!(
                        (phase, waiting, operation),
                        (Phase::KeeperAcknowledged, false, ReleaseOperation::Prepare)
                            | (Phase::SignReleased, false, ReleaseOperation::Sign)
                            | (Phase::SendReleased, false, ReleaseOperation::Send)
                            | (Phase::SendReleased, true, ReleaseOperation::Poll)
                    );
                    assert_eq!(operation.permits(phase, waiting), expected);
                }
            }
        }
    }
}

#[cfg(test)]
mod decision_send_source_tests {
    use quote::ToTokens;

    pub(super) fn tokens(source: &str) -> String {
        fn strip(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(p) if p.as_char() == ',' => None,
                    proc_macro2::TokenTree::Punct(p) if p.as_char() == '?' => {
                        Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                            '?',
                            proc_macro2::Spacing::Alone,
                        )))
                    }
                    proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(group.delimiter(), strip(group.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        strip(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }

    pub(super) fn method(source: &str, owner: &str, name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(source).unwrap();
        file.items
            .into_iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                let syn::Type::Path(path) = &*item.self_ty else {
                    return None;
                };
                if !path
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == owner)
                {
                    return None;
                }
                item.items.into_iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                    _ => None,
                })
            })
            .unwrap()
    }

    pub(super) fn ordered(body: &str, parts: &[&str]) -> bool {
        let mut remaining = body;
        for part in parts {
            let part = tokens(part);
            let Some(index) = remaining.find(&part) else {
                return false;
            };
            remaining = &remaining[index + part.len()..];
        }
        true
    }

    fn body(owner: &str, name: &str) -> String {
        tokens(
            &method(include_str!("restore_receiver.rs"), owner, name)
                .to_token_stream()
                .to_string(),
        )
    }

    #[test]
    fn decision_sender_arms_four_actual_owners_and_posts_before_delivery() {
        // Source lexing may join ? with the following punctuation while syn
        // emits a standalone question mark. Preserve the operator and normalize
        // only its spacing; this positive witness pins the actual AST form.
        let positive: syn::Stmt = syn::parse_quote!(self.effect(storage,operation)?;);
        assert_eq!(
            tokens("self.effect(storage,operation)?;"),
            tokens(&positive.to_token_stream().to_string())
        );
        let parsed = method(
            include_str!("restore_receiver.rs"),
            "DecisionHandoffAttempt",
            "perform",
        );
        let requested=parsed.block.stmts.iter().find_map(|statement|match statement {
            syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="requested")=>local.init.as_ref(),_=>None,
        }).unwrap();
        assert!(
            matches!(&*requested.expr,syn::Expr::Call(call) if call.args.is_empty()
            && matches!(&*call.func,syn::Expr::Paren(paren) if matches!(&*paren.expr,syn::Expr::Closure(closure) if closure.inputs.is_empty() && matches!(&*closure.body,syn::Expr::Block(_)))))
        );
        let actual = body("DecisionHandoffAttempt", "perform");
        let parts = [
            "self.peer.receiver.receiver.decision.phase=RoleHandoffPhase::Busy;",
            "let requested",
            "self.peer.check_final_installation(storage,self.loan)?;",
            "self.issuer.check(storage,self.peer,self.loan)?;",
            "self.activation.check(storage,self.peer,self.issuer,self.loan)?;",
            "self.effect(storage,operation)",
            "let checked=self.activation.check(storage,self.peer,self.issuer,self.loan);",
            "if requested.is_err() || checked.is_err()",
            "self.peer.refuse();self.issuer.refuse();self.activation.refuse();self.loan.refuse();",
            "let progress=requested?;checked?;",
            "let next=phase.after(operation,progress)?;",
            r#"state.transcript.as_mut().context("restore_role_decision_transcript_missing")?.delivered(frame,observation)?;"#,
            "self.peer.receiver.receiver.decision.phase=next;",
            "self.done=true;Ok(progress)",
        ];
        assert!(ordered(&actual, &parts));
        for before in parts {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !ordered(&actual.replacen(&before, "", 1), &parts),
                "{before}"
            );
        }
        for (name, operation) in [
            ("prepare_role_decision", "Prepare"),
            ("sign_role_decision", "Sign"),
            ("try_send_role_decision", "Send"),
            ("poll_role_decision", "Poll"),
        ] {
            let actual = body("RestoredWriterPeer", name);
            let expected = format!(
                "DecisionHandoffAttempt {{peer:self,issuer:completed,activation,loan,done:false}}.perform(storage,RoleHandoffOperation::{operation})"
            );
            assert!(actual.contains(&tokens(&expected)), "{name}");
            assert!(!actual.contains(&tokens("NativeAcquisition::begin")));
        }
        let dropped = tokens(
            &method(
                include_str!("../owner.rs"),
                "DecisionHandoffAttempt",
                "drop",
            )
            .to_token_stream()
            .to_string(),
        );
        assert!(ordered(
            &dropped,
            &[
                "if !self.done",
                "self.peer.refuse();self.issuer.refuse();self.activation.refuse();self.loan.refuse();"
            ]
        ));
    }

    #[test]
    fn decision_sender_uses_real_retained_grant_history_and_socket_with_all_originals() {
        let effect = body("DecisionHandoffAttempt", "effect");
        let parts = [
            "self.peer.require_role_handoff_delivered()?;",
            r#"let signed=self.activation.pending.signed.as_ref().context("restore_role_decision_missing")?.clone();"#,
            r#"state.role.transcript.as_mut().context("restore_role_history_missing")?.derive_restored_decision(observation)?"#,
            "decision:Box::new(signed)",
            "self.peer.receiver.sign_restore_body(storage,body)?;",
            "transcript.begin(Direction::Send,observation.clone())?;",
            "net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL",
            r#"ensure!(count==bytes.len(),"restore_role_decision_partial_packet");"#,
            "role.delivered=Some(frame);",
        ];
        assert!(ordered(&effect, &parts));
        for part in parts {
            let part = tokens(part);
            assert_eq!(effect.matches(&part).count(), 1, "{part}");
            assert!(!ordered(&effect.replacen(&part, "", 1), &parts));
        }
        let observation = body("DecisionHandoffAttempt", "observation");
        assert!(ordered(
            &observation,
            &[
                "self.peer.role_handoff_observation(self.issuer)?;",
                "self.activation.pending.original.remaining()?;",
                "actual.domain==domain && actual.origin==origin",
                "actual.deadline=actual.deadline.min(deadline).min(std::time::Duration::from_nanos(signed.statement.effective_deadline_ns));",
                "actual.now=actual.now.max(now);",
                r#"ensure!(actual.now<actual.deadline,"restore_role_decision_expired");"#,
            ]
        ));
        assert!(!effect.contains(&tokens("Transcript::new")));
        assert!(!observation.contains(&tokens("NativeAcquisition::begin")));
    }
}

#[cfg(test)]
mod retained_controller_signing_tests {
    use super::require_retained_controller_binding;
    use crate::security_epoch::native_enrollment::{
        NativeRole,
        protocol::StagePurpose,
        restore_peer_wire::RestoreBody,
        storage_peer_wire::{Body, Message, tests::fixture},
    };
    use day2_capabilities::Digest;
    use quote::ToTokens;
    use std::time::Duration;

    #[test]
    fn strict_actual_deadline_reduction_preserves_the_retained_controller_sender()
    -> anyhow::Result<()> {
        // Real signatures over synthetic DATA; no native owner or clock is
        // fabricated. The source control below separately pins the real caller.
        let (_, retained, key) = fixture(NativeRole::EpochController);
        let mut current = retained.clone();
        current.original.deadline_ns -= 500_000_000;
        current
            .original
            .validate_request(Duration::from_secs(102), StagePurpose::CurrentRole)?;
        require_retained_controller_binding(&current, &retained)?;
        assert_ne!(current.digest()?, retained.digest()?);
        let body = Body::Restore {
            payload: RestoreBody::Released {
                exchange: Digest::new(b"same-retained-exchange"),
                activation: Digest::new(b"same-activation"),
            },
        };
        let sender = retained.digest()?;
        let signature = key.sign("initial-storage-message", &(&sender, &body))?;
        let actual = Message {
            sender,
            body,
            signature,
        };
        actual.verify(&retained)?;
        let mut wrong = actual;
        wrong.sender = current.digest()?;
        wrong.signature = key.sign("initial-storage-message", &(&wrong.sender, &wrong.body))?;
        assert!(wrong.verify(&retained).is_err());
        for cut in 0..11 {
            let mut changed = current.clone();
            match cut {
                0 => changed.certificate.signature.push('x'),
                1 => changed.stage.signature.push('x'),
                2 => changed.stage.data.public_key.push('x'),
                3 => changed.stage.data.process.process += 1,
                4 => changed.stage.data.runtime.container.pod_uid.push('x'),
                5 => changed.stage.data.purpose = StagePurpose::InitialFirstHolder,
                6 => changed.original.purpose = StagePurpose::InitialFirstHolder,
                7 => changed.original.domain = Digest::new(b"another-domain"),
                8 => changed.original.origin_ns += 1,
                9 => changed.original.deadline_ns = retained.original.deadline_ns + 1,
                10 => changed.stage.data.role = NativeRole::AppHost,
                _ => unreachable!(),
            }
            assert!(
                require_retained_controller_binding(&changed, &retained).is_err(),
                "cut {cut}"
            );
        }
        Ok(())
    }

    #[test]
    fn actual_restore_signer_keeps_retained_binding_and_fresh_native_posts() {
        use super::decision_send_source_tests::{method, ordered, tokens};
        let actual = tokens(
            &method(
                include_str!("restore_receiver.rs"),
                "ReceiverRendezvous",
                "sign_restore_body",
            )
            .to_token_stream()
            .to_string(),
        );
        let parts = [
            "self.check_inner(storage)?;",
            "storage.stage.require_current_role()?;",
            "let current=storage.storage_statement()?;",
            r#"let retained=self.receiver.controller.as_ref().context("restore_receiver_controller_missing")?;"#,
            "require_retained_controller_binding(&current,retained)?;",
            "body.sender_role()==super::super::NativeRole::EpochController",
            "body.require_stage_purpose(storage.stage.purpose)?;",
            "let sender=retained.digest()?;",
            "storage.stage.check()?;",
            r#"storage.stage.owner.key.sign("initial-storage-message",&(&sender,&body))?;"#,
            "storage.stage.check()?;",
            "Ok(Message {sender,body,signature})",
            "let checked=self.check_inner(storage);",
            "requested.is_err() || checked.is_err()",
            "self.refuse();",
            "let message=requested?;checked?;Ok(message)",
        ];
        assert!(ordered(&actual, &parts));
        for (before, after) in [
            (
                "let sender=retained.digest()?;",
                "let sender=current.digest()?;",
            ),
            (
                "require_retained_controller_binding(&current,retained)?;",
                "let _unchecked=();",
            ),
            (
                "let checked=self.check_inner(storage);",
                "let checked:Result<()>=Ok(());",
            ),
            (
                "let message=requested?;checked?;Ok(message)",
                "checked?;let message=requested?;Ok(message)",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1);
            assert!(!ordered(
                &actual.replacen(&before, &tokens(after), 1),
                &parts
            ));
        }
        // Preserve the three existing callers and register only the actual
        // prepared acceptance producer. Comparison DATA adds no generic lane.
        fn callers_are_closed(source: &str) -> bool {
            #[derive(Default)]
            struct Calls {
                owner: Option<String>,
                method: Option<String>,
                restore: Vec<String>,
                ordinary: usize,
            }
            impl<'ast> syn::visit::Visit<'ast> for Calls {
                fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
                    let owner = match &*item.self_ty {
                        syn::Type::Path(path) => {
                            path.path.segments.last().map(|part| part.ident.to_string())
                        }
                        _ => None,
                    };
                    let prior = std::mem::replace(&mut self.owner, owner);
                    syn::visit::visit_item_impl(self, item);
                    self.owner = prior;
                }
                fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                    let prior = self.method.replace(item.sig.ident.to_string());
                    syn::visit::visit_impl_item_fn(self, item);
                    self.method = prior;
                }
                fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
                    if node.method == "sign_restore_body" {
                        self.restore.push(format!(
                            "{}::{}",
                            self.owner.as_deref().unwrap_or(""),
                            self.method.as_deref().unwrap_or("")
                        ));
                    }
                    self.ordinary += usize::from(node.method == "sign_storage_message");
                    syn::visit::visit_expr_method_call(self, node);
                }
            }
            let file = syn::parse_file(source).unwrap();
            let mut calls = Calls::default();
            syn::visit::Visit::visit_file(&mut calls, &file);
            calls.restore.sort();
            calls.restore
                == [
                    "DecisionHandoffAttempt::effect",
                    "InstalledAcceptanceAttempt::perform",
                    "PreparedAcceptanceAttempt::perform",
                    "ReceiverRendezvous::sign_packet",
                    "RestoredWriterPeer::role_handoff_effect",
                ]
                && calls.ordinary == 0
        }
        let source = include_str!("restore_receiver.rs");
        assert!(callers_are_closed(source));
        let extra = format!(
            "{source}\nfn unowned_signer() {{let _=unowned.sign_restore_body(storage,body);}}"
        );
        assert!(!callers_are_closed(&extra));
        assert!(!actual.contains(&tokens("NativeAcquisition::begin")));
    }
}

impl PreparedConfirmationReceiveAttempt<'_, '_, '_, '_> {
    fn check(&mut self, storage: &mut EnrolledStorageStage<'_, '_>) -> Result<()> {
        let requested = self
            .activation
            .check(storage, self.peer, self.issuer, self.loan);
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked: Result<()> = (|| {
            if let Some(original) = &mut self.original {
                // The loan post above may have tightened the actual stage.
                // Meet actual views, never the older stage scalar/identity.
                storage
                    .stage
                    .acquisition
                    .as_mut()
                    .exchange_current_views(original)?;
                original.exchange_current_views(&mut self.activation.pending.original)?;
                original.exchange_current_views(&mut self.issuer.finishing.original)?;
                original.exchange_current_views(
                    &mut self.peer.receiver.admission.preparation.original,
                )?;
                if let Some(sender) = &mut self.sender {
                    sender.check_identity(original, &HashCosts::disabled())?;
                }
                original.remaining()?;
            }
            Ok(())
        })();
        let tail = self.peer.check_final_installation(storage, self.loan);
        #[cfg(target_os = "linux")]
        let met: Result<()> = (|| {
            if let Some(original) = &mut self.original {
                storage
                    .stage
                    .acquisition
                    .as_mut()
                    .exchange_current_views(original)?;
            }
            Ok(())
        })();
        #[cfg(not(target_os = "linux"))]
        let met: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        if requested.is_err() || checked.is_err() || tail.is_err() || met.is_err() {
            self.activation.refuse();
            self.peer.refuse();
            self.issuer.refuse();
            self.loan.refuse();
        }
        requested?;
        checked?;
        tail?;
        met
    }

    fn observation(&mut self) -> Result<Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let original = self
                .original
                .as_mut()
                .context("restore_prepared_confirmation_original_missing")?;
            original.remaining()?;
            let (domain, origin, deadline, now) = original.historical_interval_observation();
            Ok(Observation {
                domain,
                origin,
                deadline,
                now,
            })
        }
    }

    pub(super) fn receive(
        mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<PreparedRestoredAppConfirmation> {
        ensure!(
            !self.activation.pending.confirmation_attempted,
            "restore_prepared_confirmation_attempt_spent"
        );
        self.activation.pending.confirmation_attempted = true;
        self.check(storage)?;
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let requested: Result<super::super::protocol::SignedRestorePreparedConfirmation> =
                (|| {
                    let state = &self.peer.receiver.receiver;
                    ensure!(
                        state.decision.phase == RoleHandoffPhase::Delivered
                            && state
                                .decision
                                .transcript
                                .as_ref()
                                .is_some_and(|history| history.complete()),
                        "restore_prepared_confirmation_requires_decision_delivery"
                    );
                    let ceiling = storage.stage.acquisition.as_mut().interval_data()?.1;
                    self.original = Some(self.activation.pending.original.narrow(5, ceiling)?);
                    self.check(storage)?;
                    let observation = self.observation()?;
                    self.transcript = Some(
                        self.peer
                            .receiver
                            .receiver
                            .decision
                            .transcript
                            .as_mut()
                            .context("restore_role_decision_transcript_missing")?
                            .derive_restored_confirmation(observation.clone())?,
                    );
                    self.transcript
                        .as_mut()
                        .context("restore_prepared_confirmation_history_missing")?
                        .begin(Direction::Receive, observation)?;
                    let mut bytes = [0u8; MAX_PACKET];
                    let packet = loop {
                        self.check(storage)?;
                        let received = net::recv_pidfd_packet(
                            self.peer
                                .receiver
                                .receiver
                                .socket
                                .as_ref()
                                .context("restore_receiver_socket_missing")?,
                            &mut [IoSliceMut::new(&mut bytes)],
                        );
                        let checked = self.check(storage);
                        match received {
                            Ok(packet) => {
                                checked?;
                                break packet;
                            }
                            Err(net::RecvPidfdError::Io(Errno::AGAIN)) => {
                                checked?;
                                self.wait(storage)?;
                            }
                            Err(net::RecvPidfdError::Io(Errno::INTR)) => {
                                checked?;
                                let observation = self.observation()?;
                                self.transcript
                                    .as_mut()
                                    .context("restore_prepared_confirmation_history_missing")?
                                    .transport(Transport::Interrupted, observation)?;
                            }
                            Err(error) => {
                                let _ = checked;
                                return Err(error.into());
                            }
                        }
                    };
                    let count = packet.bytes;
                    let admitted = self
                        .peer
                        .receiver
                        .receiver
                        .senders
                        .first_mut()
                        .context("restore_receiver_sender_missing")?;
                    self.sender = Some(MessageProcess::receive_admitted(
                        packet,
                        admitted,
                        self.original
                            .as_mut()
                            .context("restore_prepared_confirmation_original_missing")?,
                        &HashCosts::disabled(),
                    )?);
                    self.check(storage)?;
                    let message = super::super::storage_peer_wire::decode(&bytes[..count])?;
                    let state = &self.peer.receiver.receiver;
                    let app = state.app.as_ref().context("restore_receiver_app_missing")?;
                    let sender = self
                        .sender
                        .as_ref()
                        .context("restore_prepared_confirmation_sender_missing")?;
                    super::super::runtime::require_common(
                        sender.data(),
                        &storage.stage.owner.self_data,
                    )?;
                    let now = self
                        .original
                        .as_mut()
                        .context("restore_prepared_confirmation_original_missing")?
                        .sample()?
                        .elapsed;
                    app.validate(
                        &storage.stage.owner.policy,
                        &self.activation.pending.certificate,
                        sender.data(),
                        now,
                    )?;
                    app.require_controller(
                        state
                            .controller
                            .as_ref()
                            .context("restore_receiver_controller_missing")?,
                    )?;
                    message.verify_restored_app(app)?;
                    let Body::Restore { payload } = &message.body else {
                        anyhow::bail!("restore_prepared_confirmation_message_kind")
                    };
                    let confirmation = payload
                        .prepared_confirmation_data(
                            &state
                                .exchange
                                .as_ref()
                                .context("restore_receiver_exchange_missing")?
                                .digest()?,
                            (
                                self.activation
                                    .pending
                                    .signed
                                    .as_ref()
                                    .context("restore_role_decision_missing")?,
                                &self.activation.pending.completion,
                            ),
                            &storage.stage.owner.policy,
                            app,
                            now,
                        )?
                        .clone();
                    let original = self
                        .original
                        .as_mut()
                        .context("restore_prepared_confirmation_original_missing")?;
                    *original = original.narrow(
                        5,
                        std::time::Duration::from_nanos(
                            confirmation.statement.effective_deadline_ns,
                        ),
                    )?;
                    self.check(storage)?;
                    let observation = self.observation()?;
                    let transcript = self
                        .transcript
                        .as_mut()
                        .context("restore_prepared_confirmation_history_missing")?;
                    transcript.narrow_prepared_receive(observation.clone())?;
                    transcript.delivered(message.body.frame(), observation)?;
                    Ok(confirmation)
                })();
            // Retain/check the real sender even when DATA decoding failed.
            let checked = self.check(storage);
            if requested.is_err() || checked.is_err() {
                self.activation.refuse();
                self.peer.refuse();
                self.issuer.refuse();
                self.loan.refuse();
            }
            let confirmation = requested?;
            checked?;
            let mut receipt = PreparedRestoredAppConfirmation {
                sender: self
                    .sender
                    .take()
                    .context("restore_prepared_confirmation_sender_missing")?,
                same: storage.stage.capture_same_owner()?,
                original: self
                    .original
                    .take()
                    .context("restore_prepared_confirmation_original_missing")?,
                confirmation,
                transcript: self
                    .transcript
                    .take()
                    .context("restore_prepared_confirmation_history_missing")?,
                acceptance: None,
                acceptance_phase: PreparedAcceptancePhase::Fresh,
                installed_attempted: false,
                refused: false,
                local: PhantomData,
            };
            receipt.check_received_confirmation(
                storage,
                self.peer,
                self.issuer,
                self.activation,
                self.loan,
            )?;
            self.done = true;
            Ok(receipt)
        }
    }

    fn wait(&mut self, storage: &mut EnrolledStorageStage<'_, '_>) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = storage;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let observation = self.observation()?;
            self.transcript
                .as_mut()
                .context("restore_prepared_confirmation_history_missing")?
                .transport(Transport::WouldBlock, observation)?;
            loop {
                self.check(storage)?;
                let polled: Result<Transport> = (|| {
                    let observation = self.observation()?;
                    let timeout = rustix::event::Timespec::try_from(
                        observation
                            .deadline
                            .checked_sub(observation.now)
                            .context("restore_prepared_confirmation_expired")?,
                    )?;
                    let socket = self
                        .peer
                        .receiver
                        .receiver
                        .socket
                        .as_ref()
                        .context("restore_receiver_socket_missing")?;
                    let mut fds = [PollFd::new(socket, PollFlags::IN | PollFlags::RDHUP)];
                    match rustix::event::poll(&mut fds, Some(&timeout)) {
                        Ok(1) => {
                            let flags = fds[0].revents();
                            ensure!(
                                flags.contains(PollFlags::IN)
                                    && !flags.intersects(
                                        PollFlags::HUP
                                            | PollFlags::RDHUP
                                            | PollFlags::ERR
                                            | PollFlags::NVAL
                                    ),
                                "restore_prepared_confirmation_poll_events"
                            );
                            Ok(Transport::Ready)
                        }
                        Ok(_) => {
                            anyhow::bail!("restore_prepared_confirmation_poll_timeout_or_count")
                        }
                        Err(Errno::INTR) => Ok(Transport::Interrupted),
                        Err(error) => Err(error.into()),
                    }
                })();
                let checked = self.check(storage);
                let transport = polled?;
                checked?;
                let observation = self.observation()?;
                let decision = self
                    .transcript
                    .as_mut()
                    .context("restore_prepared_confirmation_history_missing")?
                    .transport(transport, observation)?;
                if decision == super::super::handshake::TransportDecision::Retry {
                    return Ok(());
                }
            }
        }
    }
}

impl PreparedRestoredAppConfirmation {
    pub(super) fn check_received_confirmation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = activation.check(storage, peer, completed, loan);
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked: Result<()> = (|| {
            use anyhow::Context;
            ensure!(
                !self.refused && self.acceptance_phase != PreparedAcceptancePhase::Refused,
                "restore_prepared_confirmation_refused"
            );
            ensure!(
                activation.pending.confirmation_attempted,
                "restore_prepared_confirmation_not_attempted"
            );
            if self.acceptance_phase == PreparedAcceptancePhase::Delivered {
                ensure!(
                    self.acceptance.is_some() && self.transcript.complete(),
                    "restore_prepared_acceptance_delivery_missing"
                );
            } else {
                ensure!(
                    self.transcript.next()
                        == Some((
                            Direction::Send,
                            Frame {
                                protocol: Protocol::RestoredConfirmation,
                                step: Step::PreparedAccepted,
                                sequence: None
                            }
                        )),
                    "restore_prepared_confirmation_prefix_changed"
                );
            }
            self.same
                .meet_current_read_view(storage.stage, &mut self.original)?;
            self.original
                .exchange_current_views(&mut activation.pending.original)?;
            self.original
                .exchange_current_views(&mut completed.finishing.original)?;
            self.original
                .exchange_current_views(&mut peer.receiver.admission.preparation.original)?;
            // Complete the min into the actual stage and each existing view;
            // shared observation/refusal alone does not rewrite deadline fields.
            self.same
                .meet_current_read_view(storage.stage, &mut self.original)?;
            self.original
                .exchange_current_views(&mut activation.pending.original)?;
            self.original
                .exchange_current_views(&mut completed.finishing.original)?;
            self.original
                .exchange_current_views(&mut peer.receiver.admission.preparation.original)?;
            let state = &mut peer.receiver.receiver;
            let admitted = state
                .senders
                .first_mut()
                .context("restore_receiver_sender_missing")?;
            MessageProcess::check_same_actor(
                &mut [&mut self.sender, admitted],
                &mut self.original,
                &HashCosts::disabled(),
            )?;
            super::super::runtime::require_common(
                self.sender.data(),
                &storage.stage.owner.self_data,
            )?;
            let app = state.app.as_ref().context("restore_receiver_app_missing")?;
            let now = self.original.sample()?.elapsed;
            self.confirmation.verify_data(
                &storage.stage.owner.policy,
                &activation.pending.certificate,
                (
                    activation
                        .pending
                        .signed
                        .as_ref()
                        .context("restore_role_decision_missing")?,
                    &activation.pending.completion,
                ),
                app,
                (
                    &self.confirmation.statement.request,
                    &self.confirmation.statement.challenge,
                ),
                now,
            )?;
            ensure!(
                state.keeper_ack.as_ref()
                    == Some(&activation.pending.completion.statement.data.cohort),
                "restore_prepared_confirmation_keeper_changed"
            );
            if let Some(message) = &self.acceptance {
                let Body::Restore {
                    payload:
                        RestoreBody::PreparedAccepted {
                            effective_deadline_ns,
                            ..
                        },
                } = &message.body
                else {
                    anyhow::bail!("restore_prepared_acceptance_packet_changed")
                };
                let (_, deadline) = self.original.interval_data()?;
                ensure!(
                    u128::from(*effective_deadline_ns) <= deadline.as_nanos()
                        && now.as_nanos() < u128::from(*effective_deadline_ns),
                    "restore_prepared_acceptance_earlier_bound_changed"
                );
            }
            Ok(())
        })();
        let tail = peer.check_final_installation(storage, loan);
        #[cfg(target_os = "linux")]
        let met: Result<()> = (|| {
            self.same
                .meet_current_read_view(storage.stage, &mut self.original)?;
            self.original
                .exchange_current_views(&mut activation.pending.original)?;
            self.original
                .exchange_current_views(&mut completed.finishing.original)?;
            self.original
                .exchange_current_views(&mut peer.receiver.admission.preparation.original)?;
            if let Some(message) = &self.acceptance {
                let Body::Restore {
                    payload:
                        RestoreBody::PreparedAccepted {
                            effective_deadline_ns,
                            ..
                        },
                } = &message.body
                else {
                    anyhow::bail!("restore_prepared_acceptance_packet_changed")
                };
                let (_, deadline) = self.original.interval_data()?;
                ensure!(
                    u128::from(*effective_deadline_ns) <= deadline.as_nanos(),
                    "restore_prepared_acceptance_earlier_bound_changed"
                );
            }
            Ok(())
        })();
        #[cfg(not(target_os = "linux"))]
        let met: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        if requested.is_err() || checked.is_err() || tail.is_err() || met.is_err() {
            self.refuse();
            activation.refuse();
            peer.refuse();
            completed.refuse();
            loan.refuse();
        }
        requested?;
        checked?;
        tail?;
        met
    }
}

impl PreparedAcceptanceAttempt<'_, '_, '_, '_> {
    pub(super) fn perform(
        mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        operation: PreparedAcceptanceOperation,
    ) -> Result<ReceiverProgress> {
        let phase = self.confirmation.acceptance_phase;
        // The negative root already holds every owner before spending this
        // exact attempt, including all possible signing/socket/poll errors.
        self.confirmation.acceptance_phase = PreparedAcceptancePhase::Busy;
        let requested: Result<ReceiverProgress> = (|| {
            ensure!(
                matches!(
                    (operation, phase),
                    (
                        PreparedAcceptanceOperation::Send,
                        PreparedAcceptancePhase::Fresh | PreparedAcceptancePhase::Send
                    ) | (
                        PreparedAcceptanceOperation::Poll,
                        PreparedAcceptancePhase::Poll
                    )
                ),
                "restore_prepared_acceptance_order"
            );
            self.confirmation.check_received_confirmation(
                storage,
                self.peer,
                self.issuer,
                self.activation,
                self.loan,
            )?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                match operation {
                    PreparedAcceptanceOperation::Send => {
                        if phase == PreparedAcceptancePhase::Fresh {
                            ensure!(
                                self.confirmation.acceptance.is_none(),
                                "restore_prepared_acceptance_already_signed"
                            );
                            let (_, deadline) = self.confirmation.original.interval_data()?;
                            let state = &self.peer.receiver.receiver;
                            let payload = RestoreBody::PreparedAccepted {
                                exchange: state
                                    .exchange
                                    .as_ref()
                                    .context("restore_receiver_exchange_missing")?
                                    .digest()?,
                                confirmation: self.confirmation.confirmation.digest_data()?,
                                cohort: day2_capabilities::Digest::of(
                                    &self.activation.pending.completion.statement.data.cohort,
                                )?,
                                effective_deadline_ns: u64::try_from(deadline.as_nanos())?,
                            };
                            let signed = self
                                .peer
                                .receiver
                                .sign_restore_body(storage, Body::Restore { payload });
                            let checked = self.confirmation.check_received_confirmation(
                                storage,
                                self.peer,
                                self.issuer,
                                self.activation,
                                self.loan,
                            );
                            let message = signed?;
                            checked?;
                            self.confirmation.acceptance = Some(message);
                            // A post-sign loan shortening MUST refuse this
                            // immutable packet, never silently re-sign it.
                            self.confirmation.check_received_confirmation(
                                storage,
                                self.peer,
                                self.issuer,
                                self.activation,
                                self.loan,
                            )?;
                            let observation = self.observation()?;
                            self.confirmation
                                .transcript
                                .meet_prepared_acceptance_send(observation.clone())?;
                            self.confirmation
                                .transcript
                                .begin(Direction::Send, observation)?;
                        }
                        let message = self
                            .confirmation
                            .acceptance
                            .as_ref()
                            .context("restore_prepared_acceptance_packet_missing")?;
                        let bytes = serde_json::to_vec(message)?;
                        ensure!(
                            !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                            "restore_prepared_acceptance_packet_bound"
                        );
                        let socket = self
                            .peer
                            .receiver
                            .receiver
                            .socket
                            .as_ref()
                            .context("restore_receiver_socket_missing")?;
                        match net::send(
                            socket,
                            &bytes,
                            net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
                        ) {
                            Ok(count) => {
                                ensure!(
                                    count == bytes.len(),
                                    "restore_prepared_acceptance_partial_packet"
                                );
                                Ok(ReceiverProgress::Delivered)
                            }
                            Err(Errno::AGAIN) => Ok(ReceiverProgress::WouldBlock),
                            Err(Errno::INTR) => Ok(ReceiverProgress::Interrupted),
                            Err(error) => Err(error.into()),
                        }
                    }
                    PreparedAcceptanceOperation::Poll => {
                        let observation = self.observation()?;
                        let timeout = rustix::event::Timespec::try_from(
                            observation
                                .deadline
                                .checked_sub(observation.now)
                                .context("restore_prepared_acceptance_expired")?,
                        )?;
                        let socket = self
                            .peer
                            .receiver
                            .receiver
                            .socket
                            .as_ref()
                            .context("restore_receiver_socket_missing")?;
                        let mut fds = [PollFd::new(socket, PollFlags::OUT | PollFlags::RDHUP)];
                        match rustix::event::poll(&mut fds, Some(&timeout)) {
                            Ok(1) => {
                                let flags = fds[0].revents();
                                ensure!(
                                    flags.contains(PollFlags::OUT)
                                        && !flags.intersects(
                                            PollFlags::HUP
                                                | PollFlags::RDHUP
                                                | PollFlags::ERR
                                                | PollFlags::NVAL
                                        ),
                                    "restore_prepared_acceptance_poll_events"
                                );
                                Ok(ReceiverProgress::Advanced)
                            }
                            Ok(_) => {
                                anyhow::bail!("restore_prepared_acceptance_poll_timeout_or_count")
                            }
                            Err(Errno::INTR) => Ok(ReceiverProgress::Interrupted),
                            Err(error) => Err(error.into()),
                        }
                    }
                }
            }
        })();
        let checked = self.confirmation.check_received_confirmation(
            storage,
            self.peer,
            self.issuer,
            self.activation,
            self.loan,
        );
        if requested.is_err() || checked.is_err() {
            self.confirmation.refuse();
            self.activation.refuse();
            self.peer.refuse();
            self.issuer.refuse();
            self.loan.refuse();
        }
        let progress = requested?;
        checked?;
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let observation = self.observation()?;
            match (operation, progress) {
                (PreparedAcceptanceOperation::Send, ReceiverProgress::Delivered) => {
                    let frame = self
                        .confirmation
                        .acceptance
                        .as_ref()
                        .context("restore_prepared_acceptance_packet_missing")?
                        .body
                        .frame();
                    self.confirmation.transcript.delivered(frame, observation)?;
                    ensure!(
                        self.confirmation.transcript.complete(),
                        "restore_prepared_acceptance_incomplete"
                    );
                }
                (PreparedAcceptanceOperation::Send, ReceiverProgress::WouldBlock) => {
                    self.confirmation
                        .transcript
                        .transport(Transport::WouldBlock, observation)?;
                }
                (_, ReceiverProgress::Interrupted) => {
                    self.confirmation
                        .transcript
                        .transport(Transport::Interrupted, observation)?;
                }
                (PreparedAcceptanceOperation::Poll, ReceiverProgress::Advanced) => {
                    self.confirmation
                        .transcript
                        .transport(Transport::Ready, observation)?;
                }
                _ => anyhow::bail!("restore_prepared_acceptance_progress_changed"),
            }
        }
        self.confirmation.acceptance_phase = match (operation, progress) {
            (PreparedAcceptanceOperation::Send, ReceiverProgress::Delivered) => {
                PreparedAcceptancePhase::Delivered
            }
            (PreparedAcceptanceOperation::Send, ReceiverProgress::WouldBlock) => {
                PreparedAcceptancePhase::Poll
            }
            (PreparedAcceptanceOperation::Send, ReceiverProgress::Interrupted)
            | (PreparedAcceptanceOperation::Poll, ReceiverProgress::Advanced) => {
                PreparedAcceptancePhase::Send
            }
            (PreparedAcceptanceOperation::Poll, ReceiverProgress::Interrupted) => {
                PreparedAcceptancePhase::Poll
            }
            _ => anyhow::bail!("restore_prepared_acceptance_progress_changed"),
        };
        self.done = true;
        Ok(progress)
    }

    fn observation(&mut self) -> Result<Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.confirmation.original.remaining()?;
            let (domain, origin, deadline, now) =
                self.confirmation.original.historical_interval_observation();
            Ok(Observation {
                domain,
                origin,
                deadline,
                now,
            })
        }
    }
}

impl InstalledConfirmationReceiveAttempt<'_, '_, '_, '_> {
    fn check(&mut self, storage: &mut EnrolledStorageStage<'_, '_>) -> Result<()> {
        let requested = self.prepared.check_received_confirmation(
            storage,
            self.peer,
            self.issuer,
            self.activation,
            self.loan,
        );
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked: Result<()> = (|| {
            if let Some(original) = &mut self.original {
                // The loan post above may have tightened the actual stage.
                // Meet actual views, never the older stage scalar/identity.
                storage
                    .stage
                    .acquisition
                    .as_mut()
                    .exchange_current_views(original)?;
                original.exchange_current_views(&mut self.prepared.original)?;
                original.exchange_current_views(&mut self.activation.pending.original)?;
                original.exchange_current_views(&mut self.issuer.finishing.original)?;
                original.exchange_current_views(
                    &mut self.peer.receiver.admission.preparation.original,
                )?;
                if let Some(sender) = &mut self.sender {
                    sender.check_identity(original, &HashCosts::disabled())?;
                }
                original.remaining()?;
            }
            Ok(())
        })();
        let tail = self.peer.check_final_installation(storage, self.loan);
        #[cfg(target_os = "linux")]
        let met: Result<()> = (|| {
            if let Some(original) = &mut self.original {
                storage
                    .stage
                    .acquisition
                    .as_mut()
                    .exchange_current_views(original)?;
            }
            Ok(())
        })();
        #[cfg(not(target_os = "linux"))]
        let met: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        if requested.is_err() || checked.is_err() || tail.is_err() || met.is_err() {
            self.prepared.refuse();
            self.activation.refuse();
            self.peer.refuse();
            self.issuer.refuse();
            self.loan.refuse();
        }
        requested?;
        checked?;
        tail?;
        met
    }

    fn observation(&mut self) -> Result<Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let original = self
                .original
                .as_mut()
                .context("restore_installed_confirmation_original_missing")?;
            original.remaining()?;
            let (domain, origin, deadline, now) = original.historical_interval_observation();
            Ok(Observation {
                domain,
                origin,
                deadline,
                now,
            })
        }
    }

    pub(super) fn receive(
        mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<InstalledRestoredAppConfirmation> {
        ensure!(
            !self.prepared.installed_attempted,
            "restore_installed_confirmation_attempt_spent"
        );
        self.prepared.installed_attempted = true;
        self.check(storage)?;
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let requested: Result<Message> = (|| {
                ensure!(
                    self.prepared.acceptance_phase == PreparedAcceptancePhase::Delivered
                        && self.prepared.transcript.complete(),
                    "restore_installed_confirmation_requires_prepared_delivery"
                );
                let ceiling = storage.stage.acquisition.as_mut().interval_data()?.1;
                self.original = Some(self.prepared.original.narrow(5, ceiling)?);
                self.check(storage)?;
                let observation = self.observation()?;
                self.transcript = Some(
                    self.prepared
                        .transcript
                        .derive_restored_installation(observation.clone())?,
                );
                self.transcript
                    .as_mut()
                    .context("restore_installed_confirmation_history_missing")?
                    .begin(Direction::Receive, observation)?;
                let mut bytes = [0u8; MAX_PACKET];
                let packet = loop {
                    self.check(storage)?;
                    let received = net::recv_pidfd_packet(
                        self.peer
                            .receiver
                            .receiver
                            .socket
                            .as_ref()
                            .context("restore_receiver_socket_missing")?,
                        &mut [IoSliceMut::new(&mut bytes)],
                    );
                    let checked = self.check(storage);
                    match received {
                        Ok(packet) => {
                            checked?;
                            break packet;
                        }
                        Err(net::RecvPidfdError::Io(Errno::AGAIN)) => {
                            checked?;
                            self.wait(storage)?;
                        }
                        Err(net::RecvPidfdError::Io(Errno::INTR)) => {
                            checked?;
                            let observation = self.observation()?;
                            self.transcript
                                .as_mut()
                                .context("restore_installed_confirmation_history_missing")?
                                .transport(Transport::Interrupted, observation)?;
                        }
                        Err(error) => {
                            let _ = checked;
                            return Err(error.into());
                        }
                    }
                };
                let count = packet.bytes;
                self.sender = Some(MessageProcess::receive_admitted(
                    packet,
                    &mut self.prepared.sender,
                    self.original
                        .as_mut()
                        .context("restore_installed_confirmation_original_missing")?,
                    &HashCosts::disabled(),
                )?);
                self.check(storage)?;
                let message = super::super::storage_peer_wire::decode(&bytes[..count])?;
                let state = &self.peer.receiver.receiver;
                let app = state.app.as_ref().context("restore_receiver_app_missing")?;
                let sender = self
                    .sender
                    .as_ref()
                    .context("restore_installed_confirmation_sender_missing")?;
                super::super::runtime::require_common(
                    sender.data(),
                    &storage.stage.owner.self_data,
                )?;
                let now = self
                    .original
                    .as_mut()
                    .context("restore_installed_confirmation_original_missing")?
                    .sample()?
                    .elapsed;
                app.validate(
                    &storage.stage.owner.policy,
                    &self.activation.pending.certificate,
                    sender.data(),
                    now,
                )?;
                app.require_controller(
                    state
                        .controller
                        .as_ref()
                        .context("restore_receiver_controller_missing")?,
                )?;
                message.verify_restored_app(app)?;
                let Body::Restore { payload } = &message.body else {
                    anyhow::bail!("restore_installed_confirmation_message_kind")
                };
                let app_stage = payload
                    .installed_confirmation_data(
                        &state
                            .exchange
                            .as_ref()
                            .context("restore_receiver_exchange_missing")?
                            .digest()?,
                        (
                            &self.prepared.confirmation,
                            self.activation
                                .pending
                                .signed
                                .as_ref()
                                .context("restore_role_decision_missing")?,
                            &self.activation.pending.completion,
                        ),
                        &storage.stage.owner.policy,
                        app,
                        now,
                    )?
                    .clone();
                storage.check_storage_app_statement(
                    &app_stage,
                    self.sender
                        .as_ref()
                        .context("restore_installed_confirmation_sender_missing")?
                        .data(),
                    self.original
                        .as_mut()
                        .context("restore_installed_confirmation_original_missing")?,
                )?;
                let original = self
                    .original
                    .as_mut()
                    .context("restore_installed_confirmation_original_missing")?;
                *original = original.narrow(
                    5,
                    std::time::Duration::from_nanos(app_stage.original.deadline_ns),
                )?;
                self.check(storage)?;
                let observation = self.observation()?;
                let transcript = self
                    .transcript
                    .as_mut()
                    .context("restore_installed_confirmation_history_missing")?;
                transcript.narrow_installed_receive(observation.clone())?;
                transcript.delivered(message.body.frame(), observation)?;
                Ok(message)
            })();
            // Retain/check the real sender even when DATA decoding failed.
            let checked = self.check(storage);
            if requested.is_err() || checked.is_err() {
                self.prepared.refuse();
                self.activation.refuse();
                self.peer.refuse();
                self.issuer.refuse();
                self.loan.refuse();
            }
            let message = requested?;
            checked?;
            let mut receipt = InstalledRestoredAppConfirmation {
                sender: self
                    .sender
                    .take()
                    .context("restore_installed_confirmation_sender_missing")?,
                same: storage.stage.capture_same_owner()?,
                original: self
                    .original
                    .take()
                    .context("restore_installed_confirmation_original_missing")?,
                message,
                transcript: Some(
                    self.transcript
                        .take()
                        .context("restore_installed_confirmation_history_missing")?,
                ),
                acceptance: None,
                acceptance_phase: PreparedAcceptancePhase::Fresh,
                refused: false,
                local: PhantomData,
            };
            receipt.check_received_installation(
                storage,
                self.peer,
                self.issuer,
                self.activation,
                self.prepared,
                self.loan,
            )?;
            self.done = true;
            Ok(receipt)
        }
    }

    fn wait(&mut self, storage: &mut EnrolledStorageStage<'_, '_>) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = storage;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let observation = self.observation()?;
            self.transcript
                .as_mut()
                .context("restore_installed_confirmation_history_missing")?
                .transport(Transport::WouldBlock, observation)?;
            loop {
                self.check(storage)?;
                let polled: Result<Transport> = (|| {
                    let observation = self.observation()?;
                    let timeout = rustix::event::Timespec::try_from(
                        observation
                            .deadline
                            .checked_sub(observation.now)
                            .context("restore_installed_confirmation_expired")?,
                    )?;
                    let socket = self
                        .peer
                        .receiver
                        .receiver
                        .socket
                        .as_ref()
                        .context("restore_receiver_socket_missing")?;
                    let mut fds = [PollFd::new(socket, PollFlags::IN | PollFlags::RDHUP)];
                    match rustix::event::poll(&mut fds, Some(&timeout)) {
                        Ok(1) => {
                            let flags = fds[0].revents();
                            ensure!(
                                flags.contains(PollFlags::IN)
                                    && !flags.intersects(
                                        PollFlags::HUP
                                            | PollFlags::RDHUP
                                            | PollFlags::ERR
                                            | PollFlags::NVAL
                                    ),
                                "restore_installed_confirmation_poll_events"
                            );
                            Ok(Transport::Ready)
                        }
                        Ok(_) => {
                            anyhow::bail!("restore_installed_confirmation_poll_timeout_or_count")
                        }
                        Err(Errno::INTR) => Ok(Transport::Interrupted),
                        Err(error) => Err(error.into()),
                    }
                })();
                let checked = self.check(storage);
                let transport = polled?;
                checked?;
                let observation = self.observation()?;
                let decision = self
                    .transcript
                    .as_mut()
                    .context("restore_installed_confirmation_history_missing")?
                    .transport(transport, observation)?;
                if decision == super::super::handshake::TransportDecision::Retry {
                    return Ok(());
                }
            }
        }
    }
}

impl InstalledRestoredAppConfirmation {
    pub(super) fn check_received_installation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        prepared: &mut PreparedRestoredAppConfirmation,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested =
            prepared.check_received_confirmation(storage, peer, completed, activation, loan);
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked: Result<()> = (|| {
            use anyhow::Context;
            ensure!(
                !self.refused && self.acceptance_phase != PreparedAcceptancePhase::Refused,
                "restore_installed_confirmation_refused"
            );
            ensure!(
                prepared.installed_attempted,
                "restore_installed_confirmation_not_attempted"
            );
            if self.acceptance_phase == PreparedAcceptancePhase::Delivered {
                ensure!(
                    self.acceptance.is_some()
                        && self
                            .transcript
                            .as_mut()
                            .context("restore_installed_cursor_transferred")?
                            .complete(),
                    "restore_installed_acceptance_delivery_missing"
                );
            } else {
                ensure!(
                    self.transcript
                        .as_mut()
                        .context("restore_installed_cursor_transferred")?
                        .next()
                        == Some((
                            Direction::Send,
                            Frame {
                                protocol: Protocol::RestoredInstallation,
                                step: Step::InstalledAccepted,
                                sequence: None
                            }
                        )),
                    "restore_installed_confirmation_prefix_changed"
                );
            }
            self.same
                .meet_current_read_view(storage.stage, &mut self.original)?;
            self.original
                .exchange_current_views(&mut prepared.original)?;
            self.original
                .exchange_current_views(&mut activation.pending.original)?;
            self.original
                .exchange_current_views(&mut completed.finishing.original)?;
            self.original
                .exchange_current_views(&mut peer.receiver.admission.preparation.original)?;
            // Complete the min into the actual stage and each existing view;
            // shared observation/refusal alone does not rewrite deadline fields.
            self.same
                .meet_current_read_view(storage.stage, &mut self.original)?;
            self.original
                .exchange_current_views(&mut prepared.original)?;
            self.original
                .exchange_current_views(&mut activation.pending.original)?;
            self.original
                .exchange_current_views(&mut completed.finishing.original)?;
            self.original
                .exchange_current_views(&mut peer.receiver.admission.preparation.original)?;
            let state = &mut peer.receiver.receiver;
            let admitted = state
                .senders
                .first_mut()
                .context("restore_receiver_sender_missing")?;
            MessageProcess::check_same_actor(
                &mut [&mut self.sender, &mut prepared.sender, admitted],
                &mut self.original,
                &HashCosts::disabled(),
            )?;
            super::super::runtime::require_common(
                self.sender.data(),
                &storage.stage.owner.self_data,
            )?;
            let app = state.app.as_ref().context("restore_receiver_app_missing")?;
            let now = self.original.sample()?.elapsed;
            app.validate(
                &storage.stage.owner.policy,
                &activation.pending.certificate,
                self.sender.data(),
                now,
            )?;
            app.require_controller(
                state
                    .controller
                    .as_ref()
                    .context("restore_receiver_controller_missing")?,
            )?;
            self.message.verify_restored_app(app)?;
            let Body::Restore { payload } = &self.message.body else {
                anyhow::bail!("restore_installed_confirmation_message_kind");
            };
            let exchange = state
                .exchange
                .as_ref()
                .context("restore_receiver_exchange_missing")?
                .digest()?;
            let statement = payload
                .installed_confirmation_data(
                    &exchange,
                    (
                        &prepared.confirmation,
                        activation
                            .pending
                            .signed
                            .as_ref()
                            .context("restore_role_decision_missing")?,
                        &activation.pending.completion,
                    ),
                    &storage.stage.owner.policy,
                    app,
                    now,
                )?
                .clone();
            let acceptance_payload = self
                .acceptance
                .as_ref()
                .map(|message| match &message.body {
                    Body::Restore { payload } => Ok(payload),
                    _ => Err(anyhow::anyhow!(
                        "restore_installed_acceptance_packet_changed"
                    )),
                })
                .transpose()?;
            if let Some(acceptance) = acceptance_payload {
                acceptance.installed_acceptance_deadline_data(&exchange, payload, now)?;
            }
            ensure!(
                state.keeper_ack.as_ref()
                    == Some(&activation.pending.completion.statement.data.cohort),
                "restore_installed_confirmation_keeper_changed"
            );
            if let Some(message) = &self.acceptance {
                let Body::Restore {
                    payload:
                        RestoreBody::InstalledAccepted {
                            effective_deadline_ns,
                            ..
                        },
                } = &message.body
                else {
                    anyhow::bail!("restore_installed_acceptance_packet_changed")
                };
                let (_, deadline) = self.original.interval_data()?;
                ensure!(
                    u128::from(*effective_deadline_ns) <= deadline.as_nanos()
                        && now.as_nanos() < u128::from(*effective_deadline_ns),
                    "restore_installed_acceptance_earlier_bound_changed"
                );
            }
            storage.check_storage_app_statement(
                &statement,
                self.sender.data(),
                &mut self.original,
            )?;
            Ok(())
        })();
        let tail = peer.check_final_installation(storage, loan);
        #[cfg(target_os = "linux")]
        let met: Result<()> = (|| {
            self.same
                .meet_current_read_view(storage.stage, &mut self.original)?;
            self.original
                .exchange_current_views(&mut prepared.original)?;
            self.original
                .exchange_current_views(&mut activation.pending.original)?;
            self.original
                .exchange_current_views(&mut completed.finishing.original)?;
            self.original
                .exchange_current_views(&mut peer.receiver.admission.preparation.original)?;
            if let Some(message) = &self.acceptance {
                let Body::Restore {
                    payload:
                        RestoreBody::InstalledAccepted {
                            effective_deadline_ns,
                            ..
                        },
                } = &message.body
                else {
                    anyhow::bail!("restore_installed_acceptance_packet_changed")
                };
                let (_, deadline) = self.original.interval_data()?;
                ensure!(
                    u128::from(*effective_deadline_ns) <= deadline.as_nanos(),
                    "restore_installed_acceptance_earlier_bound_changed"
                );
            }
            Ok(())
        })();
        #[cfg(not(target_os = "linux"))]
        let met: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        if requested.is_err() || checked.is_err() || tail.is_err() || met.is_err() {
            self.refuse();
            prepared.refuse();
            activation.refuse();
            peer.refuse();
            completed.refuse();
            loan.refuse();
        }
        requested?;
        checked?;
        tail?;
        met
    }
}

impl InstalledAcceptanceAttempt<'_, '_, '_, '_> {
    pub(super) fn perform(
        mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        operation: PreparedAcceptanceOperation,
    ) -> Result<ReceiverProgress> {
        let phase = self.confirmation.acceptance_phase;
        // The negative root already holds every owner before spending this
        // exact attempt, including all possible signing/socket/poll errors.
        self.confirmation.acceptance_phase = PreparedAcceptancePhase::Busy;
        let requested: Result<ReceiverProgress> = (|| {
            ensure!(
                matches!(
                    (operation, phase),
                    (
                        PreparedAcceptanceOperation::Send,
                        PreparedAcceptancePhase::Fresh | PreparedAcceptancePhase::Send
                    ) | (
                        PreparedAcceptanceOperation::Poll,
                        PreparedAcceptancePhase::Poll
                    )
                ),
                "restore_installed_acceptance_order"
            );
            self.confirmation.check_received_installation(
                storage,
                self.peer,
                self.issuer,
                self.activation,
                self.prepared,
                self.loan,
            )?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                match operation {
                    PreparedAcceptanceOperation::Send => {
                        if phase == PreparedAcceptancePhase::Fresh {
                            ensure!(
                                self.confirmation.acceptance.is_none(),
                                "restore_installed_acceptance_already_signed"
                            );
                            let (_, deadline) = self.confirmation.original.interval_data()?;
                            let state = &self.peer.receiver.receiver;
                            let payload = RestoreBody::InstalledAccepted {
                                exchange: state
                                    .exchange
                                    .as_ref()
                                    .context("restore_receiver_exchange_missing")?
                                    .digest()?,
                                installed: match &self.confirmation.message.body {
                                    Body::Restore { payload } => payload.installed_digest_data()?,
                                    _ => {
                                        anyhow::bail!("restore_installed_confirmation_message_kind")
                                    }
                                },
                                cohort: day2_capabilities::Digest::of(
                                    &self.activation.pending.completion.statement.data.cohort,
                                )?,
                                effective_deadline_ns: u64::try_from(deadline.as_nanos())?,
                            };
                            let signed = self
                                .peer
                                .receiver
                                .sign_restore_body(storage, Body::Restore { payload });
                            let checked = self.confirmation.check_received_installation(
                                storage,
                                self.peer,
                                self.issuer,
                                self.activation,
                                self.prepared,
                                self.loan,
                            );
                            let message = signed?;
                            checked?;
                            self.confirmation.acceptance = Some(message);
                            // A post-sign loan shortening MUST refuse this
                            // immutable packet, never silently re-sign it.
                            self.confirmation.check_received_installation(
                                storage,
                                self.peer,
                                self.issuer,
                                self.activation,
                                self.prepared,
                                self.loan,
                            )?;
                            let observation = self.observation()?;
                            self.confirmation
                                .transcript
                                .as_mut()
                                .context("restore_installed_cursor_transferred")?
                                .meet_installed_acceptance_send(observation.clone())?;
                            self.confirmation
                                .transcript
                                .as_mut()
                                .context("restore_installed_cursor_transferred")?
                                .begin(Direction::Send, observation)?;
                        }
                        let message = self
                            .confirmation
                            .acceptance
                            .as_ref()
                            .context("restore_installed_acceptance_packet_missing")?;
                        let bytes = serde_json::to_vec(message)?;
                        ensure!(
                            !bytes.is_empty() && bytes.len() <= MAX_PACKET,
                            "restore_installed_acceptance_packet_bound"
                        );
                        let socket = self
                            .peer
                            .receiver
                            .receiver
                            .socket
                            .as_ref()
                            .context("restore_receiver_socket_missing")?;
                        match net::send(
                            socket,
                            &bytes,
                            net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
                        ) {
                            Ok(count) => {
                                ensure!(
                                    count == bytes.len(),
                                    "restore_installed_acceptance_partial_packet"
                                );
                                Ok(ReceiverProgress::Delivered)
                            }
                            Err(Errno::AGAIN) => Ok(ReceiverProgress::WouldBlock),
                            Err(Errno::INTR) => Ok(ReceiverProgress::Interrupted),
                            Err(error) => Err(error.into()),
                        }
                    }
                    PreparedAcceptanceOperation::Poll => {
                        let observation = self.observation()?;
                        let timeout = rustix::event::Timespec::try_from(
                            observation
                                .deadline
                                .checked_sub(observation.now)
                                .context("restore_installed_acceptance_expired")?,
                        )?;
                        let socket = self
                            .peer
                            .receiver
                            .receiver
                            .socket
                            .as_ref()
                            .context("restore_receiver_socket_missing")?;
                        let mut fds = [PollFd::new(socket, PollFlags::OUT | PollFlags::RDHUP)];
                        match rustix::event::poll(&mut fds, Some(&timeout)) {
                            Ok(1) => {
                                let flags = fds[0].revents();
                                ensure!(
                                    flags.contains(PollFlags::OUT)
                                        && !flags.intersects(
                                            PollFlags::HUP
                                                | PollFlags::RDHUP
                                                | PollFlags::ERR
                                                | PollFlags::NVAL
                                        ),
                                    "restore_installed_acceptance_poll_events"
                                );
                                Ok(ReceiverProgress::Advanced)
                            }
                            Ok(_) => {
                                anyhow::bail!("restore_installed_acceptance_poll_timeout_or_count")
                            }
                            Err(Errno::INTR) => Ok(ReceiverProgress::Interrupted),
                            Err(error) => Err(error.into()),
                        }
                    }
                }
            }
        })();
        let checked = self.confirmation.check_received_installation(
            storage,
            self.peer,
            self.issuer,
            self.activation,
            self.prepared,
            self.loan,
        );
        if requested.is_err() || checked.is_err() {
            self.confirmation.refuse();
            self.prepared.refuse();
            self.activation.refuse();
            self.peer.refuse();
            self.issuer.refuse();
            self.loan.refuse();
        }
        let progress = requested?;
        checked?;
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let observation = self.observation()?;
            match (operation, progress) {
                (PreparedAcceptanceOperation::Send, ReceiverProgress::Delivered) => {
                    let frame = self
                        .confirmation
                        .acceptance
                        .as_ref()
                        .context("restore_installed_acceptance_packet_missing")?
                        .body
                        .frame();
                    self.confirmation
                        .transcript
                        .as_mut()
                        .context("restore_installed_cursor_transferred")?
                        .delivered(frame, observation)?;
                    ensure!(
                        self.confirmation
                            .transcript
                            .as_mut()
                            .context("restore_installed_cursor_transferred")?
                            .complete(),
                        "restore_installed_acceptance_incomplete"
                    );
                }
                (PreparedAcceptanceOperation::Send, ReceiverProgress::WouldBlock) => {
                    self.confirmation
                        .transcript
                        .as_mut()
                        .context("restore_installed_cursor_transferred")?
                        .transport(Transport::WouldBlock, observation)?;
                }
                (_, ReceiverProgress::Interrupted) => {
                    self.confirmation
                        .transcript
                        .as_mut()
                        .context("restore_installed_cursor_transferred")?
                        .transport(Transport::Interrupted, observation)?;
                }
                (PreparedAcceptanceOperation::Poll, ReceiverProgress::Advanced) => {
                    self.confirmation
                        .transcript
                        .as_mut()
                        .context("restore_installed_cursor_transferred")?
                        .transport(Transport::Ready, observation)?;
                }
                _ => anyhow::bail!("restore_installed_acceptance_progress_changed"),
            }
        }
        self.confirmation.acceptance_phase = match (operation, progress) {
            (PreparedAcceptanceOperation::Send, ReceiverProgress::Delivered) => {
                PreparedAcceptancePhase::Delivered
            }
            (PreparedAcceptanceOperation::Send, ReceiverProgress::WouldBlock) => {
                PreparedAcceptancePhase::Poll
            }
            (PreparedAcceptanceOperation::Send, ReceiverProgress::Interrupted)
            | (PreparedAcceptanceOperation::Poll, ReceiverProgress::Advanced) => {
                PreparedAcceptancePhase::Send
            }
            (PreparedAcceptanceOperation::Poll, ReceiverProgress::Interrupted) => {
                PreparedAcceptancePhase::Poll
            }
            _ => anyhow::bail!("restore_installed_acceptance_progress_changed"),
        };
        self.done = true;
        Ok(progress)
    }

    fn observation(&mut self) -> Result<Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.confirmation.original.remaining()?;
            let (domain, origin, deadline, now) =
                self.confirmation.original.historical_interval_observation();
            Ok(Observation {
                domain,
                origin,
                deadline,
                now,
            })
        }
    }
}

#[cfg(test)]
mod prepared_confirmation_source_tests {
    use super::decision_send_source_tests::{method, tokens};
    use quote::ToTokens;
    use syn::visit::Visit;

    fn body(source: &str, owner: &str, name: &str) -> String {
        tokens(
            &method(source, owner, name)
                .block
                .to_token_stream()
                .to_string(),
        )
    }

    fn ordered(actual: &str, parts: &[&str]) -> bool {
        let mut rest = actual;
        for part in parts {
            let part = tokens(part);
            let Some(index) = rest.find(&part) else {
                return false;
            };
            rest = &rest[index + part.len()..];
        }
        true
    }

    #[test]
    fn actual_prepared_ack_receiver_spends_before_io_and_retains_actual_sender_before_decode() {
        let source = include_str!("restore_receiver.rs");
        let actual = body(source, "PreparedConfirmationReceiveAttempt", "receive");
        let parts = [
            r#"ensure!(!self.activation.pending.confirmation_attempted,"restore_prepared_confirmation_attempt_spent");"#,
            "self.activation.pending.confirmation_attempted=true;",
            "self.check(storage)?;",
            "state.decision.phase==RoleHandoffPhase::Delivered",
            "storage.stage.acquisition.as_mut().interval_data()?.1",
            "self.activation.pending.original.narrow(5,ceiling)?",
            ".derive_restored_confirmation(observation.clone())?",
            ".begin(Direction::Receive,observation)?;",
            "net::recv_pidfd_packet",
            "let checked=self.check(storage);",
            "self.sender=Some",
            "MessageProcess::receive_admitted",
            "storage_peer_wire::decode",
            "runtime::require_common",
            "message.verify_restored_app(app)?;",
            "payload.prepared_confirmation_data",
            "*original=original.narrow",
            "self.check(storage)?;",
            "transcript.narrow_prepared_receive(observation.clone())?;",
            "transcript.delivered(message.body.frame(),observation)?;",
            "let checked=self.check(storage);",
            "let confirmation=requested?;checked?;",
            "PreparedRestoredAppConfirmation",
            "receipt.check_received_confirmation(storage,self.peer,self.issuer,self.activation,self.loan)?;",
            "self.done=true;",
            "Ok(receipt)",
        ];
        assert!(ordered(&actual, &parts));
        for target in [
            "self.activation.pending.confirmation_attempted=true;",
            "message.verify_restored_app(app)?;",
            "transcript.narrow_prepared_receive(observation.clone())?;",
            "receipt.check_received_confirmation(storage,self.peer,self.issuer,self.activation,self.loan)?;",
        ] {
            let target = tokens(target);
            assert_eq!(actual.matches(&target).count(), 1);
            assert!(!ordered(&actual.replacen(&target, "", 1), &parts));
        }
        for forbidden in [
            "NativeAcquisition::begin",
            "KeyOwner::generate",
            "store::open",
            "Runtime::",
        ] {
            assert!(!actual.contains(&tokens(forbidden)));
        }
        let check = body(source, "PreparedConfirmationReceiveAttempt", "check");
        assert!(ordered(
            &check,
            &[
                "self.activation.check(storage,self.peer,self.issuer,self.loan)",
                "sender.check_identity",
                "let tail=self.peer.check_final_installation(storage,self.loan);",
                "storage.stage.acquisition.as_mut().exchange_current_views(original)?;",
                "requested?;checked?;tail?;met"
            ]
        ));
        let drop = body(
            include_str!("../owner.rs"),
            "PreparedConfirmationReceiveAttempt",
            "drop",
        );
        assert!(ordered(
            &drop,
            &[
                "!self.done",
                "self.peer.refuse();",
                "self.issuer.refuse();",
                "self.activation.refuse();",
                "self.loan.refuse();"
            ]
        ));
    }

    #[test]
    fn acceptance_send_meets_actual_loan_after_posts_and_refuses_immutable_wider_packets() {
        let source = include_str!("restore_receiver.rs");
        let check = body(
            source,
            "PreparedRestoredAppConfirmation",
            "check_received_confirmation",
        );
        let parts = [
            "let requested=activation.check(storage,peer,completed,loan);",
            "self.same.meet_current_read_view(storage.stage,&mut self.original)?;",
            "self.original.exchange_current_views(&mut activation.pending.original)?;",
            "self.original.exchange_current_views(&mut completed.finishing.original)?;",
            "self.original.exchange_current_views(&mut peer.receiver.admission.preparation.original)?;",
            "MessageProcess::check_same_actor",
            "let tail=peer.check_final_installation(storage,loan);",
            "self.same.meet_current_read_view(storage.stage,&mut self.original)?;",
            "let (_,deadline)=self.original.interval_data()?;",
            r#"ensure!(u128::from(*effective_deadline_ns)<=deadline.as_nanos(),"restore_prepared_acceptance_earlier_bound_changed");"#,
            "requested?;checked?;tail?;met",
        ];
        assert!(ordered(&check, &parts));
        let last = tokens(
            r#"ensure!(u128::from(*effective_deadline_ns)<=deadline.as_nanos(),"restore_prepared_acceptance_earlier_bound_changed");"#,
        );
        assert_eq!(check.matches(&last).count(), 1);
        assert!(!ordered(&check.replacen(&last, "", 1), &parts));
        let actual = body(source, "PreparedAcceptanceAttempt", "perform");
        let parts = [
            "self.confirmation.acceptance_phase=PreparedAcceptancePhase::Busy;",
            "self.confirmation.check_received_confirmation",
            "self.confirmation.original.interval_data()?;",
            "effective_deadline_ns:u64::try_from(deadline.as_nanos())?",
            "self.peer.receiver.sign_restore_body",
            "let checked=self.confirmation.check_received_confirmation",
            "let message=signed?;checked?;",
            "self.confirmation.acceptance=Some(message);",
            "self.confirmation.check_received_confirmation",
            "self.confirmation.transcript.meet_prepared_acceptance_send(observation.clone())?;",
            "self.confirmation.transcript.begin(Direction::Send,observation)?;",
            "net::send",
            "rustix::event::poll",
            "let checked=self.confirmation.check_received_confirmation",
            "let progress=requested?;checked?;",
            ".transcript.delivered(frame,observation)?;",
            "self.confirmation.acceptance_phase=match",
            "self.done=true;",
            "Ok(progress)",
        ];
        assert!(ordered(&actual, &parts));
        for target in [
            "self.confirmation.acceptance_phase=PreparedAcceptancePhase::Busy;",
            "self.confirmation.acceptance=Some(message);",
            "self.confirmation.transcript.meet_prepared_acceptance_send(observation.clone())?;",
            "let progress=requested?;checked?;",
        ] {
            let target = tokens(target);
            assert_eq!(actual.matches(&target).count(), 1);
            assert!(!ordered(&actual.replacen(&target, "", 1), &parts));
        }
        for forbidden in [
            "storage.stage.deadline",
            "NativeAcquisition::begin",
            "KeyOwner::generate",
        ] {
            assert!(!actual.contains(&tokens(forbidden)));
        }
        let drop = body(
            include_str!("../owner.rs"),
            "PreparedAcceptanceAttempt",
            "drop",
        );
        assert!(ordered(
            &drop,
            &[
                "!self.done",
                "self.confirmation.refuse();",
                "self.peer.refuse();",
                "self.issuer.refuse();",
                "self.activation.refuse();",
                "self.loan.refuse();"
            ]
        ));
    }

    #[test]
    fn prepared_native_receipt_has_one_actual_factory_and_no_data_or_platform_fallback() {
        struct Origins(Vec<String>);
        impl<'ast> Visit<'ast> for Origins {
            fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                if item
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "PreparedRestoredAppConfirmation")
                {
                    self.0.push(item.to_token_stream().to_string());
                }
                syn::visit::visit_expr_struct(self, item);
            }
        }
        let mut origins = Origins(vec![]);
        for source in [
            include_str!("restore_receiver.rs"),
            include_str!("restore.rs"),
            include_str!("../owner.rs"),
        ] {
            origins.visit_file(&syn::parse_file(source).unwrap());
        }
        assert_eq!(origins.0.len(), 1);
        let actual = tokens(&origins.0[0]);
        for part in [
            "sender:self.sender.take()",
            "original:self.original.take()",
            "same:storage.stage.capture_same_owner()?",
            "transcript:self.transcript.take()",
            "acceptance:None",
            "acceptance_phase:PreparedAcceptancePhase::Fresh",
        ] {
            assert!(actual.contains(&tokens(part)), "{part}");
        }
        let facade = body(
            include_str!("restore.rs"),
            "ActivatedRestoredAppRole",
            "receive_app_confirmation",
        );
        assert!(ordered(
            &facade,
            &[
                "PreparedConfirmationReceiveAttempt",
                "peer",
                "issuer:completed",
                "activation:self",
                "loan",
                "done:false",
                ".receive(storage)"
            ]
        ));
        let check = body(
            include_str!("restore.rs"),
            "PreparedRestoredAppConfirmation",
            "check",
        );
        assert_eq!(
            check,
            tokens("{self.check_received_confirmation(storage,peer,completed,activation,loan)}")
        );
    }
}

#[cfg(test)]
mod installed_confirmation_source_tests {
    use super::decision_send_source_tests::{method, tokens};
    use quote::ToTokens;

    fn body(source: &str, owner: &str, name: &str) -> String {
        tokens(
            &method(source, owner, name)
                .block
                .to_token_stream()
                .to_string(),
        )
    }

    fn ordered(actual: &str, parts: &[&str]) -> bool {
        let mut rest = actual;
        for part in parts {
            let part = tokens(part);
            let Some(index) = rest.find(&part) else {
                return false;
            };
            rest = &rest[index + part.len()..];
        }
        true
    }

    #[test]
    fn installed_receiver_requires_real_kernel_sender_and_completed_prepared_prefix() {
        let source = include_str!("restore_receiver.rs");
        let actual = body(source, "InstalledConfirmationReceiveAttempt", "receive");
        let parts = [
            "self.prepared.installed_attempted=true;",
            "self.check(storage)?;",
            "self.prepared.acceptance_phase==PreparedAcceptancePhase::Delivered",
            "self.prepared.transcript.complete()",
            "self.prepared.original.narrow(5,ceiling)?",
            "self.prepared.transcript.derive_restored_installation(observation.clone())?",
            ".begin(Direction::Receive,observation)?;",
            "net::recv_pidfd_packet",
            "let checked=self.check(storage);",
            "MessageProcess::receive_admitted",
            "storage_peer_wire::decode",
            "message.verify_restored_app(app)?;",
            "payload.installed_confirmation_data",
            "storage.check_storage_app_statement",
            "*original=original.narrow",
            "transcript.narrow_installed_receive(observation.clone())?;",
            "transcript.delivered(message.body.frame(),observation)?;",
            "let checked=self.check(storage); if requested.is_err()||checked.is_err() {self.prepared.refuse();self.activation.refuse();self.peer.refuse();self.issuer.refuse();self.loan.refuse();}",
            "let message=requested?;checked?;",
            "InstalledRestoredAppConfirmation",
            "receipt.check_received_installation(storage,self.peer,self.issuer,self.activation,self.prepared,self.loan)?;",
            "self.done=true;",
            "Ok(receipt)",
        ];
        assert!(ordered(&actual, &parts));
        for target in [
            parts[0], parts[11], parts[13], parts[15], parts[17], parts[20],
        ] {
            let target = tokens(target);
            assert_eq!(actual.matches(&target).count(), 1, "{target}");
            assert!(!ordered(&actual.replacen(&target, "", 1), &parts));
        }
        let kernel = tokens(
            "MessageProcess::receive_admitted(packet,&mut self.prepared.sender,self.original.as_mut().context(\"restore_installed_confirmation_original_missing\")?,&HashCosts::disabled(),)?",
        );
        assert_eq!(actual.matches(&kernel).count(), 1);
        assert!(!actual.replacen(&kernel, "", 1).contains(&kernel));
        for forbidden in [
            "NativeAcquisition::begin",
            "StageAcquisition::begin",
            "retire_owned",
            "retire_checked",
            "Runtime::",
            "KeyOwner::generate",
        ] {
            assert!(!actual.contains(&tokens(forbidden)));
        }
        let check = body(source, "InstalledConfirmationReceiveAttempt", "check");
        assert!(ordered(
            &check,
            &[
                "self.prepared.check_received_confirmation",
                "sender.check_identity",
                "let tail=self.peer.check_final_installation",
                "requested?;checked?;tail?;met",
            ]
        ));
        let full = body(
            source,
            "InstalledRestoredAppConfirmation",
            "check_received_installation",
        );
        assert!(ordered(
            &full,
            &[
                "let requested=prepared.check_received_confirmation",
                "self.same.meet_current_read_view",
                "MessageProcess::check_same_actor",
                "self.message.verify_restored_app(app)?;",
                "payload.installed_confirmation_data",
                "state.keeper_ack.as_ref()",
                "storage.check_storage_app_statement",
                "let tail=peer.check_final_installation",
                "requested?;checked?;tail?;met",
            ]
        ));
    }

    #[test]
    fn installed_acceptance_keeps_one_packet_and_checks_actual_owners_after_every_io() {
        let source = include_str!("restore_receiver.rs");
        let actual = body(source, "InstalledAcceptanceAttempt", "perform");
        let parts = [
            "self.confirmation.acceptance_phase=PreparedAcceptancePhase::Busy;",
            "let requested:Result<ReceiverProgress>",
            "self.confirmation.check_received_installation",
            "if phase==PreparedAcceptancePhase::Fresh",
            "let (_,deadline)=self.confirmation.original.interval_data()?;",
            "RestoreBody::InstalledAccepted",
            "payload.installed_digest_data()?",
            "self.peer.receiver.sign_restore_body",
            "let checked=self.confirmation.check_received_installation",
            "let message=signed?;checked?;",
            "self.confirmation.acceptance=Some(message);",
            "self.confirmation.check_received_installation",
            ".meet_installed_acceptance_send(observation.clone())?;",
            ".begin(Direction::Send,observation)?;",
            "net::send",
            "count==bytes.len()",
            "rustix::event::poll",
            "let checked=self.confirmation.check_received_installation",
            "let progress=requested?;checked?;",
            "self.confirmation.transcript.as_mut().context(\"restore_installed_cursor_transferred\")?.delivered",
            "self.confirmation.transcript.as_mut().context(\"restore_installed_cursor_transferred\")?.complete()",
            "self.confirmation.acceptance_phase=match",
            "self.done=true;",
            "Ok(progress)",
        ];
        assert!(ordered(&actual, &parts));
        for target in [
            parts[0], parts[6], parts[9], parts[10], parts[12], parts[15], parts[22],
        ] {
            let target = tokens(target);
            assert_eq!(actual.matches(&target).count(), 1, "{target}");
            assert!(!ordered(&actual.replacen(&target, "", 1), &parts));
        }
        for owner in [
            "InstalledConfirmationReceiveAttempt",
            "InstalledAcceptanceAttempt",
        ] {
            let drop = body(include_str!("../owner.rs"), owner, "drop");
            for target in [
                "self.prepared.refuse();",
                "self.peer.refuse();",
                "self.issuer.refuse();",
                "self.activation.refuse();",
                "self.loan.refuse();",
            ] {
                assert!(drop.contains(&tokens(target)), "{owner}/{target}");
            }
            assert!(drop.contains(&tokens("if !self.done")));
        }
        let facade = include_str!("restore.rs");
        for (name, operation) in [("try_send_acceptance", "Send"), ("poll_acceptance", "Poll")] {
            let body = body(facade, "InstalledRestoredAppConfirmation", name);
            assert!(body.contains(&tokens("InstalledAcceptanceAttempt")));
            assert!(body.contains(&tokens(&format!(
                ".perform(storage,super::PreparedAcceptanceOperation::{operation})"
            ))));
            assert!(!body.contains(&tokens("Ok")));
        }
    }
}
