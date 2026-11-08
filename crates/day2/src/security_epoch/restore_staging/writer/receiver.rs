//! Closed receiving-side interface for the genuine writer transition. The
//! native issuer/new-App/file/keeper-ready producer is still being joined.
//! No production or fixture value inhabits this origin. A holder, signed DATA
//! record, receipt, reopened file or boolean cannot construct these owners.
use super::{NativeStagedTarget, RestoredWriterCandidate};
use crate::security_epoch::bootstrap::{RestoreWriterConfirmation, RestoreWriterExchangeContext};
use anyhow::Result;
use std::{marker::PhantomData, rc::Rc};

enum NativeReceiverOrigin {}

/// Owns the actual receiving channel, message handles and positive keeper ACK
/// once the genuine producer exists. It is NOT the final root/file handoff or
/// Current permission. Only the consuming NativeParent finalizer may combine
/// it with its actual owned target/root for Controller continuity installation.
pub(in crate::security_epoch) struct RestoredReceiverAcknowledgement {
    origin: NativeReceiverOrigin,
    local: PhantomData<Rc<()>>,
}

impl<'target, 'state, 'selection> RestoredWriterCandidate<'target, 'state, 'selection> {
    /// Fixed pre-CAS producer. Every native operation retains the whole
    /// consumed parent; only the actual Accepted prefix can yield its peer.
    /// This ends before activation or a read-write SQLite keeper exists.
    pub(in crate::security_epoch) fn receive(
        target: &'target mut NativeStagedTarget<'state, 'selection>,
        context: &mut RestoreWriterExchangeContext<'_, '_, '_, '_>,
    ) -> Result<Self> {
        let requested = (|| {
            let admission = context.prepare_admission(target)?;
            let mut receiver = context.begin_receiver(target, admission)?;
            loop {
                use crate::security_epoch::native_enrollment::ReceiverAction;
                match receiver.next_action()? {
                    ReceiverAction::Send => {
                        context.receiver_try_send(target, &mut receiver)?;
                    }
                    ReceiverAction::Receive => {
                        context.receiver_try_receive(target, &mut receiver)?;
                    }
                    ReceiverAction::Poll => {
                        context.receiver_poll(target, &mut receiver)?;
                    }
                    ReceiverAction::NeedProjection => {
                        context.receiver_bind_projection(target, &mut receiver)?;
                    }
                    ReceiverAction::NeedDurability => {
                        receiver.complete_durability(target, context)?;
                    }
                    ReceiverAction::Complete => break context.finish_receiver(target, receiver),
                }
            }
        })();
        if requested.is_err() {
            target.refuse();
            context.refuse();
        }
        let peer = requested?;
        let mut candidate = Self { target, peer };
        candidate.check(context)?;
        Ok(candidate)
    }

    /// Before CAS, every actual creator/peer/original/P3 and full authority
    /// check remains under the same parent. Each real IO needs a full pre and
    /// unconditional full post; the local file checker is not this context.
    /// This does not acquire a stage or reset a clock.
    pub(in crate::security_epoch) fn check(
        &mut self,
        context: &mut RestoreWriterExchangeContext<'_, '_, '_, '_>,
    ) -> Result<()> {
        context.check_receiver(self.target, &mut self.peer)
    }

    /// Historical projection for the pure kernel request, never an accepting
    /// holder input. The writer transition must consume this actual candidate.
    pub(in crate::security_epoch) fn holder_data(
        &self,
    ) -> Result<crate::security_epoch::kernel::Holder> {
        self.peer.holder_data()
    }

    /// The fixed writer driver sees only this candidate's actual retained
    /// target and peer. Neither becomes a getter or a DATA-based constructor.
    pub(in crate::security_epoch) fn confirm<'confirm, 'loan, 'metadata, 'storage, 'role>(
        &mut self,
        loan: &'confirm mut crate::security_epoch::bootstrap::RestoreWriteLoan<
            'loan,
            'metadata,
            'storage,
            'role,
        >,
    ) -> Result<RestoreWriterConfirmation<'confirm, 'metadata, 'storage, 'role>> {
        loan.confirm_writer(self.target, &mut self.peer)
    }

    /// The confirmation is a genuine same-parent borrow created only after
    /// known CAS, complete strong readback and separate post-CAS checks. The
    /// eventual fixed transport must evaluate both pre/post guards even on an
    /// error, keep the first failure and permanently refuse uncertainty.
    pub(in crate::security_epoch) fn handoff(
        mut self,
        confirmation: &mut RestoreWriterConfirmation<'_, '_, '_, '_>,
    ) -> Result<RestoredReceiverAcknowledgement> {
        self.peer.refuse();
        self.target.refuse();
        confirmation.refuse();
        anyhow::bail!("restore_writer_receiver_handoff_unavailable")
    }
}

#[cfg(test)]
mod tests {
    use quote::ToTokens as _;
    use syn::visit::Visit;

    fn receiving(source: &str) -> bool {
        let file = syn::parse_file(source).unwrap();
        let mut methods = file.items.iter().filter_map(|item| {
            let syn::Item::Impl(owner) = item else {
                return None;
            };
            let syn::Type::Path(path) = &*owner.self_ty else {
                return None;
            };
            if path
                .path
                .segments
                .last()
                .is_none_or(|part| part.ident != "RestoredWriterCandidate")
            {
                return None;
            }
            owner.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "receive" => Some(method),
                _ => None,
            })
        });
        let Some(method) = methods.next() else {
            return false;
        };
        if methods.next().is_some() || method.sig.inputs.len() != 2 {
            return false;
        }
        struct Dispatch {
            count: usize,
            valid: bool,
        }
        impl<'ast> Visit<'ast> for Dispatch {
            fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
                self.count += 1;
                let expected = [
                    (
                        "Send",
                        "context . receiver_try_send (target , & mut receiver) ?",
                    ),
                    (
                        "Receive",
                        "context . receiver_try_receive (target , & mut receiver) ?",
                    ),
                    (
                        "Poll",
                        "context . receiver_poll (target , & mut receiver) ?",
                    ),
                    (
                        "NeedProjection",
                        "context . receiver_bind_projection (target , & mut receiver) ?",
                    ),
                    (
                        "NeedDurability",
                        "receiver . complete_durability (target , context) ?",
                    ),
                    (
                        "Complete",
                        "break context . finish_receiver (target , receiver)",
                    ),
                ];
                self.valid &= node.arms.len() == expected.len()
                    && node.expr.to_token_stream().to_string() == "receiver . next_action () ?";
                for (arm, (variant, call)) in node.arms.iter().zip(expected) {
                    self.valid &= arm.pat.to_token_stream().to_string()
                        == format!("ReceiverAction :: {variant}")
                        && arm.guard.is_none()
                        && arm.body.to_token_stream().to_string().contains(call);
                }
                syn::visit::visit_expr_match(self, node);
            }
        }
        let mut dispatch = Dispatch {
            count: 0,
            valid: true,
        };
        dispatch.visit_block(&method.block);
        let body = method.block.to_token_stream().to_string();
        let mut previous = 0;
        for (index, part) in [
            "context . prepare_admission (target) ?",
            "context . begin_receiver (target , admission) ?",
            "receiver . next_action () ?",
            "let peer = requested ? ;",
            "Self { target , peer }",
            "candidate . check (context) ?",
            "Ok (candidate)",
        ]
        .into_iter()
        .enumerate()
        {
            let Some(position) = body.find(part) else {
                return false;
            };
            if index > 0 && position <= previous {
                return false;
            }
            previous = position;
        }
        dispatch.count == 1
            && dispatch.valid
            && body
                .contains("if requested . is_err () { target . refuse () ; context . refuse () ; }")
            && !body.contains("NativeAcquisition")
            && !body.contains("begin_current")
    }

    #[test]
    fn actual_pre_cas_driver_keeps_closed_steps_and_only_the_complete_parent_constructs_its_peer() {
        let source = include_str!("receiver.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(receiving(source));
        for (from, to) in [
            ("context.prepare_admission(target)?", "caller_preparation"),
            (
                "context.receiver_try_send(target, &mut receiver)?",
                "receiver.try_send(data)?",
            ),
            (
                "receiver.complete_durability(target, context)?",
                "Ok::<(), anyhow::Error>(())?",
            ),
            (
                "context.finish_receiver(target, receiver)",
                "Ok(caller_peer)",
            ),
            ("candidate.check(context)?", "Ok::<(), anyhow::Error>(())?"),
        ] {
            assert_eq!(source.matches(from).count(), 1);
            assert!(!receiving(&source.replacen(from, to, 1)));
        }
    }

    fn field(expression: &syn::Expr, name: &str) -> bool {
        let syn::Expr::Field(field) = expression else {
            return false;
        };
        matches!(&*field.base, syn::Expr::Path(path) if path.path.is_ident("self"))
            && matches!(&field.member, syn::Member::Named(member) if member == name)
    }

    fn whole_parent_delegation(source: &str) -> bool {
        let file = syn::parse_file(source).unwrap();
        let mut checks = file.items.iter().filter_map(|item| {
            let syn::Item::Impl(implementation) = item else {
                return None;
            };
            let syn::Type::Path(owner) = &*implementation.self_ty else {
                return None;
            };
            if owner
                .path
                .segments
                .last()
                .is_none_or(|part| part.ident != "RestoredWriterCandidate")
            {
                return None;
            }
            implementation.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "check" => Some(method),
                _ => None,
            })
        });
        let Some(check) = checks.next() else {
            return false;
        };
        if checks.next().is_some() {
            return false;
        }
        let [syn::Stmt::Expr(syn::Expr::MethodCall(call), None)] = check.block.stmts.as_slice()
        else {
            return false;
        };
        matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("context"))
            && call.method == "check_receiver"
            && call.args.len() == 2
            && field(&call.args[0], "target")
            && matches!(&call.args[1], syn::Expr::Reference(reference)
                if reference.mutability.is_some() && field(&reference.expr, "peer"))
    }

    #[test]
    fn candidate_lends_its_actual_target_and_peer_to_the_complete_parent() {
        let source = include_str!("receiver.rs");
        assert!(whole_parent_delegation(source));
        for (from, to) in [
            (
                "context.check_receiver(self.target, &mut self.peer)",
                "context.check(self.target, &mut self.peer)",
            ),
            (
                "context.check_receiver(self.target, &mut self.peer)",
                "context.check_receiver(other_target, &mut self.peer)",
            ),
            (
                "context.check_receiver(self.target, &mut self.peer)",
                "context.check_receiver(self.target, &mut other_peer)",
            ),
            (
                "context.check_receiver(self.target, &mut self.peer)",
                "let _ = self.peer.holder_data()?; context.check_receiver(self.target, &mut self.peer)",
            ),
        ] {
            // The production expression occurs exactly once; controls never
            // mutate their own fixture strings instead of the actual method.
            let production = source.split("#[cfg(test)]").next().unwrap();
            assert_eq!(production.matches(from).count(), 1);
            let mutant = production.replacen(from, to, 1);
            assert!(!whole_parent_delegation(&mutant));
        }
    }
}
