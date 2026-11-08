//! The actual App's pre-writer file exchange. Confirm/Accepted prove only the
//! retained reset-image observation; they never authorize SQLite or serving.
use super::{CapturedRestoredFile, PreparedRestoredFile, RestoredWriterReadPending};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    handshake::Step,
    restore_peer_wire::RestoreBody,
    storage_peer_wire::{Body, Message},
};
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::ensure;

// Closed local message choice, not a mode, owner or permission.
enum ResetPhase {
    Confirm,
    Accepted,
}

impl CapturedRestoredFile {
    /// Consume the verified physical file without dropping/reopening MAIN or
    /// replacing the process, channel, original or selected creator. Any lost
    /// result drops the same App lifetime and permanently refuses its original.
    pub(in crate::security_epoch::native_enrollment) fn prepare(
        mut self,
    ) -> Result<PreparedRestoredFile> {
        let requested = (|| {
            self.check_image()?;
            self.send_reset_phase(ResetPhase::Confirm)?;
            self.receive_durability()?;
            self.send_reset_phase(ResetPhase::Accepted)
        })();
        // The full image check stays before RW is authorized. Even an error
        // takes this postcheck; it never turns an uncertain send into success.
        let checked = self.check_image();
        if requested.is_err() || checked.is_err() {
            self.refuse_prepared();
        }
        requested?;
        checked?;
        Ok(PreparedRestoredFile { captured: self })
    }

    fn refuse_prepared(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.refused = true;
            self.peer.refused = true;
            self.peer.process.receiver.refuse();
        }
    }

    fn send_reset_phase(&mut self, phase: ResetPhase) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, phase);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check_image()?;
            let requested: Result<()> = (|| {
                let exchange = self.peer.exchange.digest()?;
                let projection = self.peer.projection.digest()?;
                let payload = match phase {
                    ResetPhase::Confirm => RestoreBody::Confirm {
                        exchange,
                        projection,
                    },
                    ResetPhase::Accepted => RestoreBody::Accepted {
                        exchange,
                        projection,
                    },
                };
                let sender = self.peer.local.digest()?;
                let body = Body::Restore { payload };
                // The full same-owner check brackets the actual key use,
                // independently of the subsequent packet transport checks.
                self.check_image()?;
                let signed = self
                    .peer
                    .process
                    .receiver
                    .key
                    .sign("restored-storage-message", &(&sender, &body));
                let checked = self.check_image();
                let signature = signed?;
                checked?;
                let sent = self.peer.channel.send_restore(
                    &Message {
                        sender,
                        body,
                        signature,
                    },
                    &mut self.peer.process,
                );
                let checked = self.check_image();
                sent?;
                checked
            })();
            let checked = self.check_image();
            if requested.is_err() || checked.is_err() {
                self.refuse_prepared();
            }
            requested?;
            checked
        }
    }

    fn receive_durability(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check_image()?;
            let requested: Result<()> = (|| {
                let received = self.peer.channel.receive_restore(&mut self.peer.process);
                let checked = self.check_image();
                let (message, mut receipt) = received?;
                checked?;
                // A new genuine per-message handle is bound before reading
                // the echo. Keep it after the same-controller proof succeeds.
                receipt.bind(&message, &self.peer.controller, &mut self.peer.process)?;
                let Body::Restore { payload } = &message.body else {
                    anyhow::bail!("restore_peer_expected_durability");
                };
                payload.require_file_echo(
                    Step::Complete,
                    &self.peer.exchange.digest()?,
                    &self.peer.projection.digest()?,
                )?;
                ensure!(
                    self.peer.receipts.len() == 2,
                    "restore_peer_durability_repeated"
                );
                self.peer.receipts.push(receipt);
                Ok(())
            })();
            let checked = self.check_image();
            if requested.is_err() || checked.is_err() {
                self.refuse_prepared();
            }
            requested?;
            checked
        }
    }
}

impl PreparedRestoredFile {
    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        self.captured.check_image()
    }

    /// The actual signed message only unblocks the App's OWN subsequent
    /// coherent read. No database, borrowed SQL unit or keeper is opened here.
    pub(in crate::security_epoch::native_enrollment) fn await_writer(
        mut self,
    ) -> Result<RestoredWriterReadPending> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut self;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<_> = (|| {
                let captured = &mut self.captured;
                let received = captured
                    .peer
                    .channel
                    .receive_restore(&mut captured.peer.process);
                let checked = captured.check_image();
                let (message, mut receipt) = received?;
                checked?;
                receipt.bind(
                    &message,
                    &captured.peer.controller,
                    &mut captured.peer.process,
                )?;
                let Body::Restore { payload } = message.body else {
                    anyhow::bail!("restore_peer_expected_writer_activation");
                };
                let activation = payload
                    .writer_activation_data(&captured.peer.exchange.digest()?)?
                    .clone();
                ensure!(
                    captured.peer.receipts.len() == 3,
                    "restore_peer_writer_activation_repeated"
                );
                captured.peer.receipts.push(receipt);
                Ok(activation)
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.captured.refuse_prepared();
            }
            let activation = requested?;
            checked?;
            Ok(RestoredWriterReadPending {
                captured: self.captured,
                activation,
            })
        }
    }
}

impl RestoredWriterReadPending {
    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        self.captured.check_image()
    }
}

#[cfg(test)]
mod tests {
    use syn::visit::Visit;

    fn preparation(source: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(source).unwrap();
        file.items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(implementation) = item else {
                    return None;
                };
                let syn::Type::Path(owner) = &*implementation.self_ty else {
                    return None;
                };
                if !owner.path.is_ident("CapturedRestoredFile") {
                    return None;
                }
                implementation.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == "prepare" => {
                        Some(method.clone())
                    }
                    _ => None,
                })
            })
            .unwrap()
    }

    fn try_result(statement: &syn::Stmt, expected: &str) -> bool {
        matches!(statement, syn::Stmt::Expr(syn::Expr::Try(tried), Some(_))
            if matches!(&*tried.expr, syn::Expr::Path(path) if path.path.is_ident(expected)))
    }

    fn failed(expression: &syn::Expr, expected: &str) -> bool {
        matches!(expression, syn::Expr::MethodCall(call) if call.method == "is_err" && call.args.is_empty()
            && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident(expected)))
    }

    fn prepare_contract(method: &syn::ImplItemFn) -> bool {
        if !matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver))
            if receiver.reference.is_none() && receiver.mutability.is_some())
        {
            return false;
        }
        let statements = &method.block.stmts;
        if statements.len() != 6
            || !try_result(&statements[3], "requested")
            || !try_result(&statements[4], "checked")
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::If(refusal), _) = &statements[2] else {
            return false;
        };
        let syn::Expr::Binary(condition) = &*refusal.cond else {
            return false;
        };
        if !matches!(condition.op, syn::BinOp::Or(_))
            || !failed(&condition.left, "requested")
            || !failed(&condition.right, "checked")
        {
            return false;
        }
        #[derive(Default)]
        struct Calls(Vec<String>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                let name = call.method.to_string();
                if matches!(
                    name.as_str(),
                    "check_image" | "send_reset_phase" | "receive_durability" | "refuse_prepared"
                ) {
                    let phase = call.args.first().and_then(|arg| match arg {
                        syn::Expr::Path(path) => {
                            path.path.segments.last().map(|part| part.ident.to_string())
                        }
                        _ => None,
                    });
                    self.0
                        .push(phase.map_or(name.clone(), |phase| format!("{name}:{phase}")));
                }
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let mut calls = Calls::default();
        calls.visit_block(&method.block);
        calls.0
            == [
                "check_image",
                "send_reset_phase:Confirm",
                "receive_durability",
                "send_reset_phase:Accepted",
                "check_image",
                "refuse_prepared",
            ]
    }

    #[test]
    fn prewriter_preparation_consumes_custody_and_preserves_order_and_error_postcheck() {
        let actual = preparation(include_str!("preparation.rs"));
        assert!(prepare_contract(&actual));
        for cut in 0..7 {
            let mut mutant = actual.clone();
            match cut {
                0 => mutant.sig.inputs[0] = syn::parse_quote!(&mut self),
                1 | 2 => {
                    // Edit the selected actual closure directly. The pinned
                    // unit-test syn context has full/visit, not visit-mut.
                    let syn::Stmt::Local(requested) = &mut mutant.block.stmts[0] else {
                        unreachable!();
                    };
                    let syn::Expr::Call(call) = &mut *requested.init.as_mut().unwrap().expr else {
                        unreachable!();
                    };
                    let syn::Expr::Paren(paren) = &mut *call.func else {
                        unreachable!();
                    };
                    let syn::Expr::Closure(closure) = &mut *paren.expr else {
                        unreachable!();
                    };
                    let syn::Expr::Block(body) = &mut *closure.body else {
                        unreachable!();
                    };
                    assert_eq!(body.block.stmts.len(), 4);
                    let syn::Stmt::Expr(syn::Expr::Try(tried), Some(_)) =
                        &mut body.block.stmts[cut]
                    else {
                        unreachable!();
                    };
                    let syn::Expr::MethodCall(call) = &mut *tried.expr else {
                        unreachable!();
                    };
                    assert!(
                        matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("self"))
                    );
                    if cut == 1 {
                        assert_eq!(call.method, "send_reset_phase");
                        assert_eq!(call.args.len(), 1);
                        assert!(
                            matches!(&call.args[0], syn::Expr::Path(path) if path.path.segments.len() == 2
                            && path.path.segments[0].ident == "ResetPhase" && path.path.segments[1].ident == "Confirm")
                        );
                        call.args[0] = syn::parse_quote!(ResetPhase::Accepted);
                    } else {
                        assert_eq!(call.method, "receive_durability");
                        assert!(call.args.is_empty());
                        call.method = syn::parse_quote!(skip_durability);
                    }
                }
                3 => mutant.block.stmts[1] = syn::parse_quote!(let checked: Result<()> = Ok(());),
                4 => {
                    mutant.block.stmts.remove(2);
                }
                5 => {
                    let syn::Stmt::Expr(syn::Expr::If(refusal), _) = &mut mutant.block.stmts[2]
                    else {
                        unreachable!();
                    };
                    let syn::Expr::Binary(condition) = &mut *refusal.cond else {
                        unreachable!();
                    };
                    condition.op = syn::parse_quote!(&&);
                }
                _ => {
                    let requested = mutant.block.stmts.remove(3);
                    mutant.block.stmts.insert(1, requested);
                }
            }
            assert!(
                !prepare_contract(&mutant),
                "production ownership/order/error cut {cut}"
            );
        }
    }
}
