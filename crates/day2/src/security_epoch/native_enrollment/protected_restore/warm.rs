//! Warm commands authenticate the actual retained connection, kernel sender,
//! next cursor and a fresh signed request interval. No cold admission is
//! repeated, and no Current or peer permission is recovered from wire DATA.

use super::{
    ProtectedRestoreActionGuard, ProtectedRestoreControllerGuard, ProtectedRestoreGuardPeer,
    ProtectedRestorePeer, ProtectedRestorePending, ProtectedRestoreRequest,
};
use crate::security_epoch::native_enrollment::{EnrolledRoleStage, NativeConsumerOrigin};
use anyhow::Result;
use day2_capabilities::Digest;

impl ProtectedRestoreActionGuard {
    /// Only the opaque authenticated receiver-produced guard can enter the
    /// fixed saved-frame hook. No caller-supplied parts or checked token exist.
    pub(in crate::security_epoch::native_enrollment) fn attach_to_request(
        self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        super::super::owner::attach_protected_restore_guard(stage, self)
    }

    fn from_controller(guard: ProtectedRestoreControllerGuard) -> Self {
        Self {
            peer: ProtectedRestoreGuardPeer::Controller(Box::new(guard)),
        }
    }
}

fn check_peer(
    peer: &mut ProtectedRestorePeer,
    pending: Option<&mut ProtectedRestorePending>,
    stage: &mut EnrolledRoleStage<'_>,
    acquisition: &mut crate::security_epoch::native_clock::NativeAcquisition,
) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pending;
        peer.refuse();
        stage.refuse_serving();
        acquisition.refuse();
        anyhow::bail!(super::UNAVAILABLE);
    }
    #[cfg(target_os = "linux")]
    {
        use super::{ServingSender, select_guard_check};
        use crate::security_epoch::native_enrollment::{NativeRole, issuer_costs::HashCosts};
        use anyhow::ensure;
        let mut checked =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                ensure!(!peer.refused.get(), "protected_restore_peer_refused");
                peer._same.check(stage)?;
                stage.require_protected_restore_role(NativeRole::EpochController)?;
                let local = stage.protected_restore_statement()?;
                ensure!(
                    local.same_enrollment(&peer._local_statement),
                    "protected_restore_local_enrollment_changed"
                );
                ensure!(
                    peer._sender.len() == 2,
                    "protected_restore_admission_sender_count"
                );
                peer.channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                    .check_protected_open(stage, acquisition)
            }));
        // Independent observations include both original admission packets and
        // this packet's actual SCM_PIDFD, even after an earlier error or panic.
        for sender in peer
            ._sender
            .iter_mut()
            .chain(pending.map(|pending| &mut pending.sender))
        {
            let observed =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                    match sender {
                        ServingSender::Shell(process) => {
                            process.check_identity(acquisition, &HashCosts::disabled())?;
                            ensure!(
                                process.data() == &peer._remote_statement.stage.data.process,
                                "protected_restore_packet_actor_changed"
                            );
                            Ok(())
                        }
                        ServingSender::Controller(receipt) => {
                            receipt.check_received(acquisition)?;
                            anyhow::bail!("protected_restore_shell_sender_required")
                        }
                    }
                }));
            checked = select_guard_check(checked, observed);
        }
        let local = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.check_serving_acquisition(acquisition)
        }));
        let checked = select_guard_check(checked, local);
        if !matches!(&checked, Ok(Ok(()))) {
            peer.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result,
        }
    }
}

pub(super) fn receive(
    peer: &mut ProtectedRestorePeer,
    stage: &mut EnrolledRoleStage<'_>,
) -> Result<Option<(ProtectedRestoreRequest, NativeConsumerOrigin, Digest)>> {
    #[cfg(not(target_os = "linux"))]
    {
        peer.refuse();
        stage.refuse_serving();
        anyhow::bail!(super::UNAVAILABLE);
    }
    #[cfg(target_os = "linux")]
    {
        use super::{ServingSender, admission, wire};
        use crate::security_epoch::native_enrollment::{owner, protocol::StagePurpose};
        use anyhow::ensure;
        use std::{rc::Rc, time::Duration};
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        let mut sender = None;
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<_> {
            check_peer(peer, sender.as_mut(), stage, &mut acquisition)?;
            if !peer
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .idle_pending()?
            {
                return Ok(None);
            }
            let sequence = peer
                ._sequence
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("protected_restore_sequence_exhausted"))?;
            peer.channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .begin_current_handshake(sequence, StagePurpose::CurrentRole, &mut acquisition)?;
            let (packet, received) = peer
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .receive_protected_command(stage, &mut acquisition)?;
            sender = Some(ProtectedRestorePending {
                sender: received,
                _local: std::marker::PhantomData,
            });
            check_peer(peer, sender.as_mut(), stage, &mut acquisition)?;
            let data = packet.verify_data(&peer._remote_statement.stage.data.public_key)?;
            data.require_binding(
                &peer._connection,
                &admission::enrollment(&peer._remote_statement)?,
                sequence,
                wire::Direction::Request,
            )?;
            let remote = data.original().clone();
            remote.require_request_continuity(&peer.last_remote)?;
            remote.validate_request(acquisition.sample()?.elapsed, StagePurpose::CurrentRole)?;
            let mut statement = peer._remote_statement.clone();
            statement.original = remote.clone();
            stage.check_admitted_serving_statement(
                &statement,
                &peer._remote_statement,
                &mut acquisition,
            )?;
            acquisition = acquisition.narrow(5, Duration::from_nanos(remote.deadline_ns))?;
            peer.channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .meet_protected_received(&mut peer._same, stage, &mut acquisition)?;
            check_peer(peer, sender.as_mut(), stage, &mut acquisition)?;
            let socket = peer
                .channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .protected_restore_observer(stage, &mut acquisition)?;
            let same = stage.capture_same_owner()?;
            let original = NativeConsumerOrigin::received_protected_restore(stage)?;
            let actual_sender = match sender.take() {
                Some(ProtectedRestorePending {
                    sender: ServingSender::Shell(process),
                    ..
                }) => *process,
                _ => anyhow::bail!("protected_restore_shell_sender_required"),
            };
            let guard =
                ProtectedRestoreActionGuard::from_controller(ProtectedRestoreControllerGuard {
                    same,
                    original,
                    root: Rc::clone(&peer.refused),
                    connection: peer._connection.clone(),
                    sequence,
                    remote: remote.clone(),
                    socket,
                    sender: actual_sender,
                    retired: false,
                });
            guard.attach_to_request(stage)?;
            let original = NativeConsumerOrigin::received_protected_restore(stage)?;
            owner::require_protected_restore_guard(
                stage,
                &peer.refused,
                &original,
                &peer._connection,
                sequence,
            )?;
            peer._sequence = sequence;
            peer.last_remote = remote;
            // Decoding command DATA is not the action. The actual guard is
            // already retained in the same saved frame before DATA escapes.
            let request_commitment = data.commitment()?;
            let request = data.into_request()?;
            ensure!(!peer.refused.get(), "protected_restore_peer_refused");
            Ok(Some((request, original, request_commitment)))
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_peer(peer, sender.as_mut(), stage, &mut acquisition)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            peer.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(value)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(value)
                }
            },
        }
    }
}

/// One nonterminal packet under the same received frame. This never finishes
/// a request or restore; the outer saved-request owner owes known settlement.
pub(super) fn reply(
    peer: &mut ProtectedRestorePeer,
    original: &NativeConsumerOrigin,
    stage: &mut EnrolledRoleStage<'_>,
    reply: super::ProtectedRestoreReply,
) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = reply;
        original.refuse();
        peer.refuse();
        stage.refuse_serving();
        anyhow::bail!(super::UNAVAILABLE);
    }
    #[cfg(target_os = "linux")]
    {
        use crate::security_epoch::native_enrollment::owner;
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner::require_protected_restore_guard(
                stage,
                &peer.refused,
                original,
                &peer._connection,
                peer._sequence,
            )?;
            original.check_current(stage)?;
            check_peer(peer, None, stage, &mut acquisition)?;
            let local = stage.protected_restore_statement()?;
            let data = super::wire::Data::reply(
                peer._connection.clone(),
                super::admission::enrollment(&peer._local_statement)?,
                peer._sequence,
                local.original,
                reply,
            )?;
            peer.channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?
                .send_protected_command(data, &peer._local_statement, stage, &mut acquisition)?;
            check_peer(peer, None, stage, &mut acquisition)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_peer(peer, None, stage, &mut acquisition)
        }));
        if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
            original.refuse();
            peer.refuse();
            stage.refuse_serving();
            acquisition.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(())) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => result,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use quote::ToTokens;

    fn text(statement: &syn::Stmt) -> String {
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

    fn statement(source: &str) -> syn::Stmt {
        syn::parse_str(source).unwrap()
    }

    fn receiver() -> syn::Block {
        let functions = syn::parse_file(include_str!("warm.rs"))
            .unwrap()
            .items
            .into_iter()
            .filter_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "receive" => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(functions.len(), 1);
        let linux: syn::Attribute = syn::parse_quote!(#[cfg(target_os = "linux")]);
        let blocks = functions[0]
            .block
            .stmts
            .iter()
            .filter_map(|statement| match statement {
                syn::Stmt::Expr(syn::Expr::Block(block), _)
                    if block.attrs.len() == 1
                        && block.attrs[0].to_token_stream().to_string()
                            == linux.to_token_stream().to_string() =>
                {
                    Some(block.block.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(blocks.len(), 1);
        blocks[0].clone()
    }

    fn requested(body: &mut syn::Block) -> &mut syn::Block {
        let statements = body.stmts.iter_mut().filter_map(|statement| match statement {
            syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(name) if name.ident=="requested") => Some(local), _ => None,
        }).collect::<Vec<_>>();
        assert_eq!(statements.len(), 1);
        let local = statements.into_iter().next().unwrap();
        let syn::Expr::Call(catch) = &mut *local.init.as_mut().unwrap().expr else {
            panic!("actual catch");
        };
        let syn::Expr::Call(safe) = &mut catch.args[0] else {
            panic!("actual unwind boundary");
        };
        let syn::Expr::Closure(closure) = &mut safe.args[0] else {
            panic!("actual executed closure");
        };
        let syn::Expr::Block(body) = &mut *closure.body else {
            panic!("actual request body");
        };
        &mut body.block
    }

    fn critical() -> Vec<syn::Stmt> {
        [
            "sender = Some(ProtectedRestorePending {sender:received,_local:std::marker::PhantomData,});",
            "check_peer(peer,sender.as_mut(),stage,&mut acquisition)?;",
            "let data = packet.verify_data(&peer._remote_statement.stage.data.public_key)?;",
            "data.require_binding(&peer._connection,&admission::enrollment(&peer._remote_statement)?,sequence,wire::Direction::Request)?;",
            "let remote = data.original().clone();",
            "remote.require_request_continuity(&peer.last_remote)?;",
            "remote.validate_request(acquisition.sample()?.elapsed,StagePurpose::CurrentRole)?;",
            "stage.check_admitted_serving_statement(&statement,&peer._remote_statement,&mut acquisition)?;",
            "acquisition = acquisition.narrow(5,Duration::from_nanos(remote.deadline_ns))?;",
            "peer.channel.as_mut().ok_or_else(|| anyhow::anyhow!(\"protected_restore_channel_closed\"))?.meet_protected_received(&mut peer._same,stage,&mut acquisition)?;",
            "check_peer(peer,sender.as_mut(),stage,&mut acquisition)?;",
            "let socket = peer.channel.as_mut().ok_or_else(|| anyhow::anyhow!(\"protected_restore_channel_closed\"))?.protected_restore_observer(stage,&mut acquisition)?;",
            "let same = stage.capture_same_owner()?;",
            "let original = NativeConsumerOrigin::received_protected_restore(stage)?;",
            "let actual_sender = match sender.take() { Some(ProtectedRestorePending{sender:ServingSender::Shell(process),..}) => *process, _ => anyhow::bail!(\"protected_restore_shell_sender_required\"), };",
            "let guard = ProtectedRestoreActionGuard::from_controller(ProtectedRestoreControllerGuard { same, original, root:Rc::clone(&peer.refused),connection:peer._connection.clone(),sequence,remote:remote.clone(),socket,sender:actual_sender,retired:false, });",
            "guard.attach_to_request(stage)?;",
            "owner::require_protected_restore_guard(stage,&peer.refused,&original,&peer._connection,sequence)?;",
            "let request = data.into_request()?;",
        ].into_iter().map(statement).collect()
    }

    fn critical_positions(body: &syn::Block) -> Option<Vec<usize>> {
        let mut cursor = 0;
        let mut positions = Vec::new();
        for required in critical() {
            let position = body.stmts[cursor..]
                .iter()
                .position(|actual| text(actual) == text(&required))?;
            positions.push(cursor + position);
            cursor += position + 1;
        }
        Some(positions)
    }

    fn authenticated_before_data(body: &syn::Block) -> bool {
        critical_positions(body).is_some()
    }

    #[test]
    fn actual_warm_receiver_authenticates_and_meets_the_saved_frame_before_attaching_and_lending_data()
     {
        let mut actual = receiver();
        let body = requested(&mut actual);
        assert!(authenticated_before_data(body));
        // Delete each executed occurrence in the authenticated prefix, not
        // the separate initial peer check before any packet exists.
        for index in critical_positions(body).unwrap() {
            let mut removed = body.clone();
            removed.stmts.remove(index);
            assert!(!authenticated_before_data(&removed));
            let mut deferred = body.clone();
            let actual = deferred.stmts.remove(index);
            deferred
                .stmts
                .insert(index, syn::parse_quote!(if false { #actual }));
            assert!(!authenticated_before_data(&deferred));
        }
        let attach = statement("guard.attach_to_request(stage)?;");
        let data = statement("let request = data.into_request()?;");
        let a = body
            .stmts
            .iter()
            .position(|value| text(value) == text(&attach))
            .unwrap();
        let b = body
            .stmts
            .iter()
            .position(|value| text(value) == text(&data))
            .unwrap();
        let mut late = body.clone();
        late.stmts.swap(a, b);
        assert!(!authenticated_before_data(&late));
    }

    #[test]
    fn actual_warm_receiver_posts_every_retained_sender_before_selecting_the_requested_result() {
        let actual = receiver();
        let expected: syn::Block = syn::parse_quote!({
            let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                check_peer(peer, sender.as_mut(), stage, &mut acquisition)
            }));
            if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
                peer.refuse();
                stage.refuse_serving();
                acquisition.refuse();
            }
            match requested {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(Err(error)) => Err(error),
                Ok(Ok(value)) => match checked {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(result) => {
                        result?;
                        Ok(value)
                    }
                },
            }
        });
        let check = |body: &syn::Block| {
            body.stmts.len() >= 3
                && body.stmts[body.stmts.len() - 3..]
                    .iter()
                    .map(text)
                    .eq(expected.stmts.iter().map(text))
        };
        assert!(check(&actual));
        for index in actual.stmts.len() - 3..actual.stmts.len() {
            let mut removed = actual.clone();
            removed.stmts.remove(index);
            assert!(!check(&removed));
        }
    }
}
