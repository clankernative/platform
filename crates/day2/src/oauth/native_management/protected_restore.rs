//! Fixed DATA-only Shell courier under the actual saved HTTP original.
//! Native exchanges retain the actual enrolled peer and saved original;
//! returned DATA cannot create authority or prove HTTP delivery.
use super::{OWNERS, OwnerSource, current_sink};
use crate::security_epoch::native_enrollment::{
    NativeRole, ProtectedRestoreReply, ProtectedRestoreRequest, ProtectedRestoreShell,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::security_epoch::AuthorityScope;
use std::cell::{OnceCell, RefCell};

type Slot<T> = OnceCell<RefCell<Option<T>>>;
type Unwind<T> = std::result::Result<T, Box<dyn std::any::Any + Send>>;

// The SAME kernel is exercised with inert DATA by the portable controls.
// None returned here means a first attempt, never an absent/refused supplier.
fn take<T>(slot: &Slot<T>) -> Result<Option<T>> {
    if let Some(connected) = slot.get() {
        return connected
            .try_borrow_mut()?
            .take()
            .map(Some)
            .context("protected restore courier refused");
    }
    slot.set(RefCell::new(None))
        .map_err(|_| anyhow::anyhow!("protected restore courier already initialized"))?;
    Ok(None)
}

fn publish<T>(slot: &Slot<T>, actual: T) -> Result<()> {
    let mut connected = slot
        .get()
        .context("protected restore courier not attempted")?
        .try_borrow_mut()?;
    ensure!(
        connected.is_none(),
        "protected restore courier already connected"
    );
    *connected = Some(actual);
    Ok(())
}

// Both results are already observed. This takes no callback or owner parts;
// uncertainty keeps the request's primary error/panic rather than a post error.
fn checked<T>(attempted: Unwind<Result<T>>, post: Unwind<Result<()>>) -> Result<T> {
    match attempted {
        Err(payload) => std::panic::resume_unwind(payload),
        Ok(Err(error)) => Err(error),
        Ok(Ok(value)) => match post {
            Ok(Ok(())) => Ok(value),
            Ok(Err(error)) => Err(error),
            Err(payload) => std::panic::resume_unwind(payload),
        },
    }
}

/// Inspect only the complete command DATA against the immutable selection
/// already retained by this actual Shell. This begins no native action, lends
/// no owner and cannot replace the Controller's current admission checks.
pub(in crate::oauth) fn command_data(
    scope: &AuthorityScope,
    bytes: &[u8],
) -> Result<crate::security_epoch::ProtectedRestoreCommandData> {
    OWNERS.with(|registry| {
        let registry = registry.try_borrow()?;
        let owner = registry
            .get(scope.app.as_str())
            .context("protected restore Shell owner unavailable")?;
        ensure!(
            owner.kind == NativeRole::SecurityShell
                && owner.selection.scope() == scope
                && matches!(&owner.source, OwnerSource::Initial(_)),
            "protected restore Shell selection changed"
        );
        crate::security_epoch::protected_restore_command_data(bytes, &owner.selection.store)
    })
}

/// A fixed exchange only. No callback, owner getter, stage factory or copied
/// identity can enter this boundary; its caller must already be on Shell HTTP.
pub(crate) fn request(
    scope: &AuthorityScope,
    data: ProtectedRestoreRequest,
) -> Result<ProtectedRestoreReply> {
    let sink = current_sink()?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ensure!(
            !matches!(&data, ProtectedRestoreRequest::Authenticate { .. }),
            "protected_restore_terminal_entry_required"
        );
        OWNERS.with(|registry| {
            let mut registry = registry.try_borrow_mut()?;
            let owner = registry
                .get_mut(scope.app.as_str())
                .context("protected restore Shell owner unavailable")?;
            ensure!(
                owner.kind == NativeRole::SecurityShell && owner.selection.scope() == scope,
                "protected restore Shell selection changed"
            );
            let OwnerSource::Initial(initial) = &mut owner.source else {
                anyhow::bail!("protected restore Shell source unavailable");
            };
            let slot = &initial.protected_restore;
            let mut role = initial.role.try_borrow_mut()?;
            // with_stage binds the SAME captured request before this callback,
            // and independently reborrows/checks that original before return.
            let (courier, reply) = sink.request.with_stage(
                &mut role,
                &owner.selection,
                NativeRole::SecurityShell,
                |mut stage| {
                    let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        // Initialize before any connect. A failed/unknown turn
                        // leaves None in an already initialized, terminal cell.
                        let mut courier = match take(slot)? {
                            Some(actual) => actual,
                            None => Box::new(ProtectedRestoreShell::connect(&mut stage)?),
                        };
                        let reply = courier.request(&mut stage, data)?;
                        Ok::<_, anyhow::Error>((courier, reply))
                    }));
                    // Independent post even after a native Result error; the
                    // primary error or original panic always wins.
                    let post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        stage.check_selection(
                            &owner.selection.policy,
                            &owner.selection.store,
                            NativeRole::SecurityShell,
                        )
                    }));
                    checked(attempted, post)
                },
            )?;
            // No effect/wait separates the original's final check and publish.
            // Refusal above drops the actual courier; no later turn reconnects.
            publish(slot, courier)?;
            Ok(reply)
        })
    }));
    match result {
        Ok(result) => {
            if result.is_err() {
                sink.abort();
            }
            result
        }
        Err(payload) => {
            sink.abort();
            std::panic::resume_unwind(payload)
        }
    }
}

/// A terminal request must consume the already admitted courier, never create
/// a connection or republish it after a send. The complete actual Sink original
/// brackets this fixed native operation and its independent role-selection post.
pub(crate) fn authenticate(
    scope: &AuthorityScope,
    id: &day2_capabilities::Digest,
    assertion: &[u8],
) -> Result<crate::security_epoch::native_enrollment::RestoreInstalledOutputData> {
    let sink = current_sink()?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ensure!(
            !assertion.is_empty() && assertion.len() <= 16_384,
            "protected_restore_assertion_bound"
        );
        OWNERS.with(|registry| {
            let mut registry = registry.try_borrow_mut()?;
            let owner = registry
                .get_mut(scope.app.as_str())
                .context("protected restore Shell owner unavailable")?;
            ensure!(
                owner.kind == NativeRole::SecurityShell && owner.selection.scope() == scope,
                "protected restore Shell selection changed"
            );
            let OwnerSource::Initial(initial) = &mut owner.source else {
                anyhow::bail!("protected restore Shell source unavailable");
            };
            let slot = &initial.protected_restore;
            let mut role = initial.role.try_borrow_mut()?;
            sink.request.with_stage(
                &mut role,
                &owner.selection,
                NativeRole::SecurityShell,
                |mut stage| {
                    // Some(actual) only. Taking None remains terminal; there is no
                    // cold connect, generic reply or replacement after uncertainty.
                    let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let courier = take(slot)?
                            .context("protected restore executor courier unavailable")?;
                        courier.authenticate(&mut stage, id, assertion)
                    }));
                    let post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        stage.check_selection(
                            &owner.selection.policy,
                            &owner.selection.store,
                            NativeRole::SecurityShell,
                        )
                    }));
                    checked(attempted, post)
                },
            )
        })
    }));
    match result {
        Ok(result) => {
            if result.is_err() {
                sink.abort();
            }
            result
        }
        Err(payload) => {
            sink.abort();
            std::panic::resume_unwind(payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    struct Inert(Rc<Cell<usize>>);
    impl Drop for Inert {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn actual_slot_never_reconnects_after_first_or_connected_uncertainty() -> Result<()> {
        let slot: Slot<Inert> = OnceCell::new();
        assert!(take(&slot)?.is_none());
        assert!(take(&slot).is_err());
        let drops = Rc::new(Cell::new(0));
        let known: Slot<Inert> = OnceCell::new();
        assert!(take(&known)?.is_none());
        publish(&known, Inert(drops.clone()))?;
        let actual = take(&known)?.unwrap();
        assert!(take(&known).is_err());
        drop(actual); // an uncertain connect/send/post cannot be republished
        assert_eq!(drops.get(), 1);
        assert!(take(&known).is_err());
        Ok(())
    }

    #[test]
    fn actual_slot_retains_one_known_courier_across_separate_short_turns() -> Result<()> {
        let slot: Slot<Inert> = OnceCell::new();
        let drops = Rc::new(Cell::new(0));
        assert!(take(&slot)?.is_none());
        publish(&slot, Inert(drops.clone()))?;
        let actual = take(&slot)?.unwrap();
        assert_eq!(drops.get(), 0);
        publish(&slot, actual)?;
        assert_eq!(drops.get(), 0);
        let actual = take(&slot)?.unwrap();
        drop(actual);
        assert_eq!(drops.get(), 1);
        assert!(take(&slot).is_err());
        Ok(())
    }
    #[test]
    fn actual_result_merge_preserves_primary_and_drops_success_after_post_refusal() {
        struct Primary(u8);
        impl std::fmt::Debug for Primary {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("foreign error formatting");
            }
        }
        impl std::fmt::Display for Primary {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("foreign error formatting");
            }
        }
        impl std::error::Error for Primary {}
        let error = anyhow::Error::new(Primary(47));
        assert_eq!(error.downcast_ref::<Primary>().unwrap().0, 47);
        let identity = error.downcast_ref::<Primary>().unwrap() as *const Primary;
        let result = checked::<()>(Ok(Err(error)), Ok(Err(anyhow::anyhow!("post refused"))));
        assert_eq!(
            result.unwrap_err().downcast_ref::<Primary>().unwrap() as *const Primary,
            identity
        );
        let drops = Rc::new(Cell::new(0));
        assert!(
            checked(
                Ok(Ok(Inert(drops.clone()))),
                Ok(Err(anyhow::anyhow!("post refused")))
            )
            .is_err()
        );
        assert_eq!(drops.get(), 1);
        let panic =
            std::panic::catch_unwind(|| checked::<()>(Err(Box::new(47u8)), Err(Box::new(99u8))));
        assert_eq!(*panic.unwrap_err().downcast::<u8>().unwrap(), 47);
        let error = anyhow::Error::new(Primary(47));
        assert_eq!(error.downcast_ref::<Primary>().unwrap().0, 47);
        let identity = error.downcast_ref::<Primary>().unwrap() as *const Primary;
        let result = checked::<()>(Ok(Err(error)), Err(Box::new(99u8)));
        assert_eq!(
            result.unwrap_err().downcast_ref::<Primary>().unwrap() as *const Primary,
            identity
        );
        let drops = Rc::new(Cell::new(0));
        let post_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            checked(Ok(Ok(Inert(drops.clone()))), Err(Box::new(99u8)))
        }));
        let Err(payload) = post_panic else {
            panic!("post panic was lost");
        };
        assert_eq!(*payload.downcast::<u8>().unwrap(), 99);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn actual_courier_source_has_one_saved_stage_and_no_fresh_original_or_fallback() -> Result<()> {
        use quote::ToTokens;
        use syn::visit::Visit;
        fn unwind_body(expression: &syn::Expr) -> Option<&syn::Expr> {
            let syn::Expr::Call(catch) = expression else {
                return None;
            };
            if catch.func.to_token_stream().to_string() != "std :: panic :: catch_unwind"
                || catch.args.len() != 1
            {
                return None;
            }
            let syn::Expr::Call(safe) = &catch.args[0] else {
                return None;
            };
            if safe.func.to_token_stream().to_string() != "std :: panic :: AssertUnwindSafe"
                || safe.args.len() != 1
            {
                return None;
            }
            let syn::Expr::Closure(closure) = &safe.args[0] else {
                return None;
            };
            (closure.inputs.is_empty() && closure.asyncness.is_none() && closure.capture.is_none())
                .then_some(&*closure.body)
        }
        fn local<'a>(statement: &'a syn::Stmt, name: &str) -> Option<&'a syn::Expr> {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            if !matches!(&local.pat,syn::Pat::Ident(id) if id.ident == name && id.mutability.is_none())
            {
                return None;
            }
            local
                .init
                .as_ref()
                .filter(|init| init.diverge.is_none())
                .map(|init| &*init.expr)
        }
        fn callback_is_bound(block: &syn::Block) -> bool {
            let [attempted, post, syn::Stmt::Expr(merge, None)] = block.stmts.as_slice() else {
                return false;
            };
            let Some(attempted) = local(attempted, "attempted").and_then(unwind_body) else {
                return false;
            };
            let syn::Expr::Block(attempted) = attempted else {
                return false;
            };
            let [
                syn::Stmt::Local(courier),
                reply,
                syn::Stmt::Expr(returned, None),
            ] = attempted.block.stmts.as_slice()
            else {
                return false;
            };
            if !matches!(&courier.pat,syn::Pat::Ident(id) if id.ident == "courier" && id.mutability.is_some())
            {
                return false;
            }
            let Some(reply) = local(reply, "reply") else {
                return false;
            };
            let syn::Expr::Try(reply) = reply else {
                return false;
            };
            let syn::Expr::MethodCall(reply) = &*reply.expr else {
                return false;
            };
            let args = reply
                .args
                .iter()
                .map(|arg| arg.to_token_stream().to_string())
                .collect::<Vec<_>>();
            if reply.receiver.to_token_stream().to_string() != "courier"
                || reply.method != "request"
                || args != ["& mut stage", "data"]
            {
                return false;
            }
            let expected: syn::Expr = syn::parse_quote!(Ok::<_, anyhow::Error>((courier, reply)));
            if returned.to_token_stream().to_string() != expected.to_token_stream().to_string() {
                return false;
            }
            let Some(post) = local(post, "post").and_then(unwind_body) else {
                return false;
            };
            let post = match post {
                syn::Expr::Block(block) => match block.block.stmts.as_slice() {
                    [syn::Stmt::Expr(value, None)] => value,
                    _ => return false,
                },
                value => value,
            };
            let syn::Expr::MethodCall(post) = post else {
                return false;
            };
            let args = post
                .args
                .iter()
                .map(|arg| arg.to_token_stream().to_string())
                .collect::<Vec<_>>();
            let expected = [
                "&owner.selection.policy",
                "&owner.selection.store",
                "NativeRole::SecurityShell",
            ]
            .map(|arg| {
                syn::parse_str::<syn::Expr>(arg)
                    .unwrap()
                    .to_token_stream()
                    .to_string()
            });
            let expected_merge: syn::Expr = syn::parse_quote!(checked(attempted, post));
            post.receiver.to_token_stream().to_string() == "stage"
                && post.method == "check_selection"
                && args == expected
                && merge.to_token_stream().to_string()
                    == expected_merge.to_token_stream().to_string()
        }
        fn scope_condition(statement: &syn::Stmt) -> bool {
            use syn::parse::Parser;
            let actual = match statement {
                syn::Stmt::Macro(statement) => &statement.mac,
                syn::Stmt::Expr(syn::Expr::Macro(expression), _) => &expression.mac,
                _ => return false,
            };
            if !actual.path.is_ident("ensure") {
                return false;
            }
            let Ok(arguments) =
                syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                    .parse2(actual.tokens.clone())
            else {
                return false;
            };
            let expected: syn::Expr = syn::parse_str(
                "owner.kind == NativeRole::SecurityShell && owner.selection.scope() == scope",
            )
            .unwrap();
            arguments.first().is_some_and(|first| {
                first.to_token_stream().to_string() == expected.to_token_stream().to_string()
            })
        }
        #[derive(Default)]
        struct Calls {
            entries: Vec<(String, Vec<String>, usize)>,
            depth: usize,
            known_tails: usize,
            post: Option<syn::Expr>,
            check: Option<syn::Expr>,
            stage: Option<syn::Expr>,
            callback: Option<syn::Block>,
            owners: Option<syn::Block>,
            bound_callbacks: usize,
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                let target = call.func.to_token_stream().to_string();
                self.entries.push((
                    target.clone(),
                    call.args
                        .iter()
                        .map(|arg| arg.to_token_stream().to_string())
                        .collect(),
                    self.depth,
                ));
                let unwind = target == "std :: panic :: catch_unwind";
                self.depth += usize::from(unwind);
                syn::visit::visit_expr_call(self, call);
                self.depth -= usize::from(unwind);
            }
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                let target = format!("{}.{}", call.receiver.to_token_stream(), call.method);
                self.entries.push((
                    target.clone(),
                    call.args
                        .iter()
                        .map(|arg| arg.to_token_stream().to_string())
                        .collect(),
                    self.depth,
                ));
                if target == "stage.check_selection" {
                    self.check = Some(syn::Expr::MethodCall(call.clone()));
                }
                if target == "sink . request.with_stage" {
                    self.stage = Some(syn::Expr::MethodCall(call.clone()));
                    if let Some(syn::Expr::Closure(closure)) = call.args.last()
                        && let syn::Expr::Block(block) = &*closure.body
                    {
                        self.callback = Some(block.block.clone());
                        self.bound_callbacks += usize::from(callback_is_bound(&block.block));
                    }
                }
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_local(&mut self, local: &'ast syn::Local) {
                if matches!(&local.pat, syn::Pat::Ident(id) if id.ident == "post") {
                    self.post = local.init.as_ref().map(|init| (*init.expr).clone());
                }
                syn::visit::visit_local(self, local);
            }
            fn visit_block(&mut self, block: &'ast syn::Block) {
                if let [
                    ..,
                    syn::Stmt::Local(local),
                    syn::Stmt::Expr(publish, Some(_)),
                    syn::Stmt::Expr(reply, None),
                ] = block.stmts.as_slice()
                {
                    let tuple = matches!(&local.pat, syn::Pat::Tuple(tuple) if tuple.elems.len() == 2 && tuple.elems.iter().zip(["courier", "reply"]).all(|(pat,name)| matches!(pat,syn::Pat::Ident(id) if id.ident == name && id.mutability.is_none())));
                    let stage = local.init.as_ref().is_some_and(|init| matches!(&*init.expr,syn::Expr::Try(tried) if matches!(&*tried.expr,syn::Expr::MethodCall(call) if call.method == "with_stage" && call.receiver.to_token_stream().to_string() == "sink . request")));
                    let expected_publish: syn::Expr = syn::parse_quote!(publish(slot, courier)?);
                    let expected_reply: syn::Expr = syn::parse_quote!(Ok(reply));
                    if tuple
                        && stage
                        && publish.to_token_stream().to_string()
                            == expected_publish.to_token_stream().to_string()
                        && reply.to_token_stream().to_string()
                            == expected_reply.to_token_stream().to_string()
                    {
                        let stage_index = block.stmts.len() - 3;
                        if block.stmts[..stage_index]
                            .iter()
                            .filter(|statement| scope_condition(statement))
                            .count()
                            == 1
                        {
                            self.known_tails += 1;
                            self.owners = Some(block.clone());
                        }
                    }
                }
                syn::visit::visit_block(self, block);
            }
        }
        let source = syn::parse_file(include_str!("protected_restore.rs"))?;
        let entries = source
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "request" => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].sig.generics.params.is_empty());
        assert_eq!(entries[0].sig.inputs.len(), 2);
        let parent = syn::parse_file(include_str!("../native_management.rs"))?;
        let wrappers = parent
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "protected_restore_request" => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(wrappers.len(), 1);
        let expected: syn::Block = syn::parse_quote!({ protected_restore::request(scope, data) });
        assert_eq!(
            wrappers[0].block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );

        let guarded = |body: &syn::Block| {
            let text = body.to_token_stream().to_string();
            let mut calls = Calls::default();
            calls.visit_block(body);
            let arguments = |args: &[&str]| {
                args.iter()
                    .map(|arg| {
                        syn::parse_str::<syn::Expr>(arg)
                            .unwrap()
                            .to_token_stream()
                            .to_string()
                    })
                    .collect::<Vec<_>>()
            };
            let signatures = [
                (
                    "ProtectedRestoreShell :: connect",
                    arguments(&["&mut stage"]),
                    Some(2),
                ),
                (
                    "courier.request",
                    arguments(&["&mut stage", "data"]),
                    Some(2),
                ),
                (
                    "stage.check_selection",
                    arguments(&[
                        "&owner.selection.policy",
                        "&owner.selection.store",
                        "NativeRole::SecurityShell",
                    ]),
                    Some(2),
                ),
                ("checked", arguments(&["attempted", "post"]), None),
                ("take", arguments(&["slot"]), None),
                ("publish", arguments(&["slot", "courier"]), None),
            ];
            let exact = signatures.iter().all(|(target, args, depth)| {
                let found = calls
                    .entries
                    .iter()
                    .filter(|(name, _, _)| name == target)
                    .collect::<Vec<_>>();
                found.len() == 1
                    && found[0].1 == *args
                    && depth.is_none_or(|depth| found[0].2 == depth)
            });
            let stage = calls
                .entries
                .iter()
                .filter(|(name, _, _)| name == "sink . request.with_stage")
                .collect::<Vec<_>>();
            let expected_stage =
                arguments(&["&mut role", "&owner.selection", "NativeRole::SecurityShell"]);
            let actual_stage =
                stage.len() == 1 && stage[0].1.len() == 4 && stage[0].1[..3] == expected_stage;
            let scope: syn::Expr = syn::parse_str(
                "owner.kind == NativeRole::SecurityShell && owner.selection.scope() == scope",
            )
            .unwrap();
            exact
                && actual_stage
                && calls.known_tails == 1
                && calls.bound_callbacks == 1
                && text.matches(&scope.to_token_stream().to_string()).count() == 1
                && [
                    "begin_current_stage",
                    "enroll_current_thread",
                    "NativeAcquisition :: begin",
                    "Sink :: new",
                    "Request :: new",
                ]
                .iter()
                .all(|forbidden| !text.contains(forbidden))
        };
        let actual = &entries[0].block;
        assert!(guarded(actual));
        let text = actual.to_token_stream().to_string();
        for (from, to) in [
            ("owner.selection.scope() == scope", "true"),
            (
                "courier . request (& mut stage",
                "courier . request (& mut other",
            ),
            (
                "checked (attempted , post)",
                "checked (attempted , Ok (Ok (())))",
            ),
        ] {
            let from = if from.starts_with("owner.") {
                syn::parse_str::<syn::Expr>(from)?
                    .to_token_stream()
                    .to_string()
            } else {
                from.into()
            };
            assert_eq!(text.matches(&from).count(), 1);
            assert!(!guarded(&syn::parse_str(&text.replacen(&from, to, 1))?));
        }
        let mut calls = Calls::default();
        calls.visit_block(actual);
        let post = calls.post.unwrap().to_token_stream().to_string();
        let post_check = calls.check.unwrap().to_token_stream().to_string();
        let uncaught = format!("Ok({post_check})");
        assert_eq!(text.matches(&post).count(), 1);
        assert!(!guarded(&syn::parse_str(
            &text.replacen(&post, &uncaught, 1)
        )?));
        let callback = calls.callback.as_ref().unwrap();
        let old_callback = callback.to_token_stream().to_string();
        assert_eq!(text.matches(&old_callback).count(), 1);
        let mut early_post = callback.clone();
        early_post.stmts.swap(0, 1);
        assert!(!guarded(&syn::parse_str(&text.replacen(
            &old_callback,
            &early_post.to_token_stream().to_string(),
            1
        ))?));
        let mut fake_post = callback.clone();
        let real_post = local(&fake_post.stmts[1], "post").unwrap().clone();
        fake_post.stmts[1] = syn::parse_quote!(let post = Ok(Ok(())););
        fake_post
            .stmts
            .insert(2, syn::parse_quote!(let _ = #real_post;));
        assert!(!guarded(&syn::parse_str(&text.replacen(
            &old_callback,
            &fake_post.to_token_stream().to_string(),
            1
        ))?));
        let owners = calls.owners.as_ref().unwrap();
        let old_owners = owners.to_token_stream().to_string();
        assert_eq!(text.matches(&old_owners).count(), 1);
        let mut late_scope = owners.clone();
        let index = late_scope.stmts.iter().position(scope_condition).unwrap();
        let scope = late_scope.stmts.remove(index);
        let after_stage = late_scope.stmts.len() - 2;
        late_scope.stmts.insert(after_stage, scope);
        assert!(!guarded(&syn::parse_str(&text.replacen(
            &old_owners,
            &late_scope.to_token_stream().to_string(),
            1
        ))?));
        let full_stage = calls
            .entries
            .iter()
            .find(|(name, _, _)| name == "sink . request.with_stage")
            .unwrap();
        assert_eq!(full_stage.1.len(), 4);
        let stage = calls.stage.unwrap().to_token_stream().to_string();
        let tried: syn::Expr = syn::parse_str(&format!("{stage}?"))?;
        let tried = tried.to_token_stream().to_string();
        assert_eq!(text.matches(&tried).count(), 1);
        let bypass: syn::Block =
            syn::parse_str(&text.replacen(&tried, &format!("{stage}.unwrap()"), 1))?;
        assert!(!guarded(&bypass));
        let old = "publish (slot , courier) ?";
        assert_eq!(text.matches(old).count(), 1);
        let unpublished: syn::Block = syn::parse_str(&text.replacen(old, "Ok (()) ?", 1))?;
        assert!(!guarded(&unpublished));
        Ok(())
    }
}

#[cfg(test)]
mod terminal_source_tests {
    use quote::ToTokens;
    use syn::visit::Visit;

    fn same(actual: &syn::Expr, expected: &str) -> bool {
        fn equal(actual: &syn::Expr, expected: &syn::Expr) -> bool {
            fn attributes(a: &[syn::Attribute], b: &[syn::Attribute]) -> bool {
                a.len() == b.len()
                    && a.iter().zip(b).all(|(a, b)| {
                        a.to_token_stream().to_string() == b.to_token_stream().to_string()
                    })
            }
            match (actual, expected) {
                (syn::Expr::Call(a), syn::Expr::Call(b)) => {
                    attributes(&a.attrs, &b.attrs)
                        && equal(&a.func, &b.func)
                        && a.args.len() == b.args.len()
                        && a.args.iter().zip(&b.args).all(|(a, b)| equal(a, b))
                }
                (syn::Expr::MethodCall(a), syn::Expr::MethodCall(b)) => {
                    attributes(&a.attrs, &b.attrs)
                        && a.method == b.method
                        && a.turbofish.to_token_stream().to_string()
                            == b.turbofish.to_token_stream().to_string()
                        && equal(&a.receiver, &b.receiver)
                        && a.args.len() == b.args.len()
                        && a.args.iter().zip(&b.args).all(|(a, b)| equal(a, b))
                }
                (syn::Expr::Try(a), syn::Expr::Try(b)) => {
                    attributes(&a.attrs, &b.attrs) && equal(&a.expr, &b.expr)
                }
                _ => actual.to_token_stream().to_string() == expected.to_token_stream().to_string(),
            }
        }
        // Only call-list terminal punctuation is insignificant. Tuple arity,
        // paths, receivers, ownership, argument order and attributes stay exact.
        equal(actual, &syn::parse_str::<syn::Expr>(expected).unwrap())
    }

    fn caught_body(init: &syn::Expr) -> Option<&syn::Expr> {
        let syn::Expr::Call(catch) = init else {
            return None;
        };
        if !same(&catch.func, "std::panic::catch_unwind") || catch.args.len() != 1 {
            return None;
        }
        let syn::Expr::Call(safe) = &catch.args[0] else {
            return None;
        };
        if !same(&safe.func, "std::panic::AssertUnwindSafe") || safe.args.len() != 1 {
            return None;
        }
        let syn::Expr::Closure(closure) = &safe.args[0] else {
            return None;
        };
        if !closure.inputs.is_empty()
            || !closure.attrs.is_empty()
            || closure.capture.is_some()
            || closure.asyncness.is_some()
        {
            return None;
        }
        Some(&closure.body)
    }

    fn guarded(block: &syn::Block) -> bool {
        #[derive(Default)]
        struct Calls {
            with: Vec<syn::ExprMethodCall>,
            methods: Vec<String>,
            functions: Vec<String>,
        }
        impl<'a> Visit<'a> for Calls {
            fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
                self.methods.push(call.method.to_string());
                if call.method == "with_stage" {
                    self.with.push(call.clone());
                }
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
                self.functions.push(call.func.to_token_stream().to_string());
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut calls = Calls::default();
        calls.visit_block(block);
        if calls.with.len() != 1
            || calls.methods.iter().any(|m| {
                matches!(
                    m.as_str(),
                    "connect" | "begin_current_stage" | "begin_current_request"
                )
            })
            || calls.functions.iter().any(|f| f == "publish")
        {
            return false;
        }
        let call = &calls.with[0];
        if !same(&call.receiver, "sink.request")
            || call.args.len() != 4
            || !same(&call.args[0], "&mut role")
            || !same(&call.args[1], "&owner.selection")
            || !same(&call.args[2], "NativeRole::SecurityShell")
        {
            return false;
        }
        let syn::Expr::Closure(closure) = &call.args[3] else {
            return false;
        };
        if closure.inputs.to_token_stream().to_string() != "mut stage"
            || closure.asyncness.is_some()
            || closure.capture.is_some()
        {
            return false;
        }
        let syn::Expr::Block(body) = &*closure.body else {
            return false;
        };
        let [
            syn::Stmt::Local(attempted),
            syn::Stmt::Local(post),
            syn::Stmt::Expr(tail, None),
        ] = body.block.stmts.as_slice()
        else {
            return false;
        };
        fn initializer(local: &syn::Local) -> Option<&syn::Expr> {
            local.init.as_ref().map(|i| &*i.expr)
        }
        let Some(syn::Expr::Block(requested)) = initializer(attempted).and_then(caught_body) else {
            return false;
        };
        let [syn::Stmt::Local(courier), syn::Stmt::Expr(operation, None)] =
            requested.block.stmts.as_slice()
        else {
            return false;
        };
        let Some(post_body) = initializer(post).and_then(caught_body) else {
            return false;
        };
        let post_operation = if let syn::Expr::Block(block) = post_body {
            let [syn::Stmt::Expr(e, None)] = block.block.stmts.as_slice() else {
                return false;
            };
            if !block.attrs.is_empty() || block.label.is_some() {
                return false;
            }
            e
        } else {
            post_body
        };
        requested.attrs.is_empty()
            && requested.label.is_none()
            && courier.pat.to_token_stream().to_string() == "courier"
            && initializer(courier).is_some_and(|e| {
                same(
                    e,
                    "take(slot)?.context(\"protected restore executor courier unavailable\")?",
                )
            })
            && attempted.pat.to_token_stream().to_string() == "attempted"
            && same(operation, "courier.authenticate(&mut stage,id,assertion)")
            && post.pat.to_token_stream().to_string() == "post"
            && same(
                post_operation,
                "stage.check_selection(&owner.selection.policy,&owner.selection.store,NativeRole::SecurityShell)",
            )
            && same(tail, "checked(attempted,post)")
    }

    #[test]
    fn actual_terminal_courier_uses_saved_request_existing_connection_and_unconditional_posts() {
        let file = syn::parse_file(include_str!("protected_restore.rs")).unwrap();
        let methods = file
            .items
            .iter()
            .filter_map(|i| match i {
                syn::Item::Fn(f) if f.sig.ident == "authenticate" => Some(f),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 1);
        let actual = methods[0];
        assert!(guarded(&actual.block));
        // Actual parsed block mutants retain syntax; no duplicated fake
        // transport or scalar-native owner is invoked by these controls.
        let text = actual.block.to_token_stream().to_string();
        fn expr(s: &str) -> String {
            syn::parse_str::<syn::Expr>(s)
                .unwrap()
                .to_token_stream()
                .to_string()
        }
        for (before, after) in [
            (
                "courier.authenticate(&mut stage,id,assertion)",
                "courier.authenticate(&mut other,id,assertion)",
            ),
            (
                "courier.authenticate(&mut stage,id,assertion)",
                "Ok(caller_data)",
            ),
            (
                "stage.check_selection(&owner.selection.policy,&owner.selection.store,NativeRole::SecurityShell)",
                "Ok(())",
            ),
            (
                "take(slot)?.context(\"protected restore executor courier unavailable\")?",
                "Some(Box::new(ProtectedRestoreShell::connect(&mut stage)?)).context(\"protected restore executor courier unavailable\")?",
            ),
            ("checked(attempted,post)", "checked(post,attempted)"),
        ] {
            struct Matches<'a> {
                expected: &'a str,
                expressions: Vec<syn::Expr>,
            }
            impl<'a> Visit<'a> for Matches<'_> {
                fn visit_expr(&mut self, e: &'a syn::Expr) {
                    if same(e, self.expected) {
                        self.expressions.push(e.clone());
                    }
                    syn::visit::visit_expr(self, e);
                }
            }
            let mut matches = Matches {
                expected: before,
                expressions: Vec::new(),
            };
            matches.visit_block(&actual.block);
            assert_eq!(
                matches.expressions.len(),
                1,
                "one actual courier mutation target"
            );
            let before = matches.expressions[0].to_token_stream().to_string();
            assert_eq!(text.matches(&before).count(), 1);
            let changed: syn::Block =
                syn::parse_str(&text.replacen(&before, &expr(after), 1)).unwrap();
            assert!(!guarded(&changed));
        }
        let before: syn::Stmt = syn::parse_quote!(let courier = take(slot)?.context("protected restore executor courier unavailable")?;);
        let after: syn::Stmt = syn::parse_quote!(let mut courier = take(slot)?.context("protected restore executor courier unavailable")?;);
        let before = before.to_token_stream().to_string();
        assert_eq!(
            text.matches(&before).count(),
            1,
            "the actual consuming courier local"
        );
        let old_borrow: syn::Block =
            syn::parse_str(&text.replacen(&before, &after.to_token_stream().to_string(), 1))
                .unwrap();
        assert!(!guarded(&old_borrow));
        #[derive(Default)]
        struct StageCalls(Vec<syn::ExprMethodCall>);
        impl<'a> Visit<'a> for StageCalls {
            fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
                if call.method == "with_stage" {
                    self.0.push(call.clone());
                }
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let mut stages = StageCalls::default();
        stages.visit_block(&actual.block);
        assert_eq!(stages.0.len(), 1);
        let old = &stages.0[0];
        let mut foreign = old.clone();
        foreign.args[1] = syn::parse_quote!(&other.selection);
        let before = old.to_token_stream().to_string();
        assert_eq!(text.matches(&before).count(), 1);
        let changed: syn::Block =
            syn::parse_str(&text.replacen(&before, &foreign.to_token_stream().to_string(), 1))
                .unwrap();
        assert!(!guarded(&changed));
    }
}
