//! Native identity join of the WHOLE genuine post-installed carrier.
//! Every borrowed counter/physical/target owner stays in that carrier. This is
//! not an owned Controller, ordinary Current or a successful restore result.
use super::ControllerCurrentInstallationLoan;
use crate::security_epoch::native_enrollment::{
    NativeRole, RetainedControllerNative, SameEnrolledOwner,
};
use anyhow::{Context, Result};

pub(in crate::security_epoch) struct PendingControllerCurrentInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    loan: ControllerCurrentInstallationLoan<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
    same: SameEnrolledOwner,
}

/// The old administrative Current is terminal, but ALL of its actual installed
/// resources and lexical borrows remain retained. The native field is only the
/// SAME admitted Controller role borrow. This is neither a fresh App peer nor
/// an ordinary Controller/storage owner or a completed restore result.
///
/// In particular, the old SQL/file/source/original negative guards are not
/// disarmed here. No old parent check can run after its counter is finished or
/// its original retired. The subsequent fixed fresh-peer/file handoff must
/// still consume this whole carrier; dropping it refuses both real owners.
pub(in crate::security_epoch) struct RetiredControllerCurrentInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    native: RetainedControllerNative<'role>,
    pending: PendingControllerCurrentInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
}

impl Drop for RetiredControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        self.pending.refuse();
    }
}

struct NativeControllerPreparing<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
{
    loan: Option<
        ControllerCurrentInstallationLoan<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    >,
    completed: bool,
}

impl Drop for NativeControllerPreparing<'_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed
            && let Some(loan) = &mut self.loan
        {
            loan.refuse();
        }
    }
}

struct NativeControllerChecking<
    'borrow,
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    owner: &'borrow mut PendingControllerCurrentInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
    completed: bool,
}

impl Drop for NativeControllerChecking<'_, '_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.refuse();
        }
    }
}

impl Drop for PendingControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        self.loan.refuse();
    }
}

impl<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
    PendingControllerCurrentInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >
{
    /// Consume the genuine installed carrier before any checks or native work.
    /// The same old original remains live through the independent full post.
    pub(super) fn prepare(
        loan: ControllerCurrentInstallationLoan<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    ) -> Result<Self> {
        let mut attempt = NativeControllerPreparing {
            loan: Some(loan),
            completed: false,
        };
        let requested = (|| {
            let loan = attempt
                .loan
                .as_mut()
                .context("restore_native_controller_loan_missing")?;
            loan.check()?;
            capture_controller(loan)
        })();
        let checked = (|| {
            attempt
                .loan
                .as_mut()
                .context("restore_native_controller_loan_missing")?
                .check()
        })();
        if (requested.is_err() || checked.is_err())
            && let Some(loan) = &mut attempt.loan
        {
            loan.refuse();
        }
        let same = requested?;
        checked?;
        let loan = attempt
            .loan
            .take()
            .context("restore_native_controller_loan_missing")?;
        // No I/O, effect, wait or callback follows the full post before this
        // owning move. The future holder still retains ALL seven lifetimes.
        let pending = Self { loan, same };
        attempt.completed = true;
        Ok(pending)
    }

    /// Consume the genuine installed ACK carrier. Its final independent full
    /// parent/lineage and native identity posts precede old counter completion.
    /// From then on only the fixed old release, terminal physical close and
    /// owned native retirement are allowed; no parent/provider read follows.
    pub(in crate::security_epoch) fn retire_old_current(
        mut self,
    ) -> Result<
        RetiredControllerCurrentInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        self.check()?;
        let accepted = self.loan.send_installed_acceptance();
        // Run the actual full installed/native/lineage post even on a send,
        // poll or primary native error. A sent packet is not final permission.
        let checked = self.check();
        if accepted.is_err() || checked.is_err() {
            self.refuse();
        }
        accepted?;
        checked?;
        let native = retire_controller(&mut self.loan)?;
        // Moving the WHOLE actual carrier preserves every lifetime and all
        // negative destructors. No I/O, callback or positive old check follows.
        Ok(RetiredControllerCurrentInstallation {
            native,
            pending: self,
        })
    }
}

impl PendingControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {
    /// Fixed installation check only, never a request or stage getter. A
    /// caught unwind permanently refuses the actual carrier before reuse.
    pub(super) fn check(&mut self) -> Result<()> {
        let mut attempt = NativeControllerChecking {
            owner: self,
            completed: false,
        };
        let requested = (|| {
            attempt.owner.loan.check()?;
            check_controller(&mut attempt.owner.loan, &mut attempt.owner.same)
        })();
        let checked = attempt.owner.loan.check();
        if requested.is_err() || checked.is_err() {
            attempt.owner.refuse();
        }
        requested?;
        checked?;
        attempt.completed = true;
        Ok(())
    }

    pub(super) fn refuse(&mut self) {
        self.loan.refuse();
    }
}

/// Native field partition is private to this fixed post-ACK implementation.
/// A stage borrow ends here, before the caller's independent whole-carrier
/// post. No original, key, file, stage or callback is supplied by a caller.
fn capture_controller(
    loan: &mut ControllerCurrentInstallationLoan<'_, '_, '_, '_, '_, '_, '_>,
) -> Result<SameEnrolledOwner> {
    let frame = &mut loan
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .frame;
    let reader = &mut frame.confirmation.owner.auth.action.reader.loan;
    let physical = reader
        .physical
        .as_mut()
        .context("native_restore_physical_closed")?;
    let stage = physical.controller_stage()?;
    stage.require_current_role()?;
    stage.check_selection(
        &reader.policy,
        &reader.selection,
        NativeRole::EpochController,
    )?;
    stage.capture_same_owner()
}

fn check_controller(
    loan: &mut ControllerCurrentInstallationLoan<'_, '_, '_, '_, '_, '_, '_>,
    same: &mut SameEnrolledOwner,
) -> Result<()> {
    let frame = &mut loan
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .frame;
    let reader = &mut frame.confirmation.owner.auth.action.reader.loan;
    let physical = reader
        .physical
        .as_mut()
        .context("native_restore_physical_closed")?;
    let stage = physical.controller_stage()?;
    stage.require_current_role()?;
    stage.check_selection(
        &reader.policy,
        &reader.selection,
        NativeRole::EpochController,
    )?;
    same.check(stage)
}

/// This fixed field partition exists only under the genuine post-ACK carrier.
/// Stop data comes from the SAME retained accepting owner, never a caller.
/// The actual counter completion must precede the old release, while the
/// complete parent/ten-record checks must precede that counter completion.
fn retire_controller<'role>(
    loan: &mut ControllerCurrentInstallationLoan<'_, '_, '_, '_, 'role, '_, '_>,
) -> Result<RetainedControllerNative<'role>> {
    let frame = &mut loan
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .frame;
    let owner = &mut *frame.confirmation.owner;
    let reader = &mut owner.auth.action.reader.loan;
    reader.disposition.require_closed()?;
    reader.reads.finish(
        reader
            .physical
            .as_mut()
            .context("native_restore_physical_closed")?
            .controller_stage()?,
    )?;
    reader
        .physical
        .as_mut()
        .context("native_restore_physical_closed")?
        .release_restore_stop(&owner.stopped)?;
    reader
        .physical
        .take()
        .context("native_restore_physical_closed")?
        .retire_restore_native()
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <PendingControllerCurrentInstallation<
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
            > as Ambiguous<_>>::check;
            let _ = <RetiredControllerCurrentInstallation<
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
            > as Ambiguous<_>>::check;
            let _ = <NativeControllerPreparing<
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
            > as Ambiguous<_>>::check;
            let _ = <NativeControllerChecking<
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
            > as Ambiguous<_>>::check;
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

#[cfg(test)]
mod source_tests {
    use quote::ToTokens;

    fn method(owner: &str, name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("native_current.rs")).unwrap();
        let mut found=file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(item)=item else{return None;};
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident==owner)) {return None;}
            item.items.into_iter().find_map(|item|match item {syn::ImplItem::Fn(item) if item.sig.ident==name=>Some(item),_=>None})
        });
        let result = found.next().unwrap();
        assert!(found.next().is_none());
        result
    }

    fn root_native_flow(body: &syn::Block, final_call: &str) -> bool {
        let expected: syn::Block = syn::parse_quote!({
            let frame = &mut loan
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .frame;
            let reader = &mut frame.confirmation.owner.auth.action.reader.loan;
            let physical = reader
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let stage = physical.controller_stage()?;
            stage.require_current_role()?;
        });
        if body.stmts.len() != 7
            || body.stmts[..5]
                .iter()
                .map(ToTokens::to_token_stream)
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                != expected
                    .stmts
                    .iter()
                    .map(ToTokens::to_token_stream)
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::Try(selection), Some(_)) = &body.stmts[5] else {
            return false;
        };
        let syn::Expr::MethodCall(selection) = &*selection.expr else {
            return false;
        };
        if selection.method != "check_selection"
            || !matches!(&*selection.receiver,syn::Expr::Path(path) if path.path.is_ident("stage"))
        {
            return false;
        }
        let args = selection
            .args
            .iter()
            .map(|x| x.to_token_stream().to_string())
            .collect::<Vec<_>>();
        if args
            != [
                "& reader . policy",
                "& reader . selection",
                "NativeRole :: EpochController",
            ]
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::MethodCall(tail), None) = &body.stmts[6] else {
            return false;
        };
        match final_call {
            "capture" => {
                tail.method == "capture_same_owner"
                    && tail.args.is_empty()
                    && matches!(&*tail.receiver,syn::Expr::Path(path) if path.path.is_ident("stage"))
            }
            "check" => {
                tail.method == "check"
                    && matches!(&*tail.receiver,syn::Expr::Path(path) if path.path.is_ident("same"))
                    && tail.args.len() == 1
                    && matches!(tail.args.first(),Some(syn::Expr::Path(path)) if path.path.is_ident("stage"))
            }
            _ => false,
        }
    }

    #[test]
    fn actual_native_partition_borrows_only_whole_installed_frame_and_current_controller() {
        let file = syn::parse_file(include_str!("native_current.rs")).unwrap();
        for (name, tail) in [
            ("capture_controller", "capture"),
            ("check_controller", "check"),
        ] {
            let items = file
                .items
                .iter()
                .filter_map(|item| match item {
                    syn::Item::Fn(item) if item.sig.ident == name => Some(item),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(items.len(), 1);
            let actual = &items[0].block;
            assert!(root_native_flow(actual, tail));
            let rendered = actual.to_token_stream().to_string();
            for (from, to) in [
                ("NativeRole :: EpochController", "NativeRole :: AppHost"),
                ("loan . installation", "other . installation"),
                ("reader . physical", "other . physical"),
                ("stage . require_current_role () ? ;", ""),
            ] {
                assert_eq!(rendered.matches(from).count(), 1);
                let changed: syn::Block = syn::parse_str(&rendered.replacen(from, to, 1)).unwrap();
                assert!(!root_native_flow(&changed, tail));
            }
        }
    }

    fn negative_start(method: &syn::ImplItemFn, guard: &str, field: &str, value: &str) -> bool {
        let Some(syn::Stmt::Local(first)) = method.block.stmts.first() else {
            return false;
        };
        let Some(init) = &first.init else {
            return false;
        };
        let syn::Expr::Struct(init) = &*init.expr else {
            return false;
        };
        init.path.segments.last().is_some_and(|part|part.ident==guard) && init.rest.is_none() && init.fields.len()==2
            && init.fields.iter().any(|item|matches!(&item.member,syn::Member::Named(name) if name==field) && item.expr.to_token_stream().to_string()==value)
            && init.fields.iter().any(|item|matches!(&item.member,syn::Member::Named(name) if name=="completed") && matches!(&item.expr,syn::Expr::Lit(value) if matches!(&value.lit,syn::Lit::Bool(value) if !value.value)))
    }

    fn prepare_flow(method: &syn::ImplItemFn) -> bool {
        if !negative_start(method, "NativeControllerPreparing", "loan", "Some (loan)") {
            return false;
        }
        let expected: syn::Block = syn::parse_quote!({
            let mut attempt = NativeControllerPreparing {
                loan: Some(loan),
                completed: false,
            };
            let requested = (|| {
                let loan = attempt
                    .loan
                    .as_mut()
                    .context("restore_native_controller_loan_missing")?;
                loan.check()?;
                capture_controller(loan)
            })();
            let checked = (|| {
                attempt
                    .loan
                    .as_mut()
                    .context("restore_native_controller_loan_missing")?
                    .check()
            })();
            if (requested.is_err() || checked.is_err())
                && let Some(loan) = &mut attempt.loan
            {
                loan.refuse();
            }
            let same = requested?;
            checked?;
            let loan = attempt
                .loan
                .take()
                .context("restore_native_controller_loan_missing")?;
            let pending = Self { loan, same };
            attempt.completed = true;
            Ok(pending)
        });
        let mut actual = method.block.clone();
        // Only the optional final named-field comma of this actual Self
        // literal is normalized; no tuple/call/struct-update token is dropped.
        if let Some(syn::Stmt::Local(pending)) = actual.stmts.get_mut(7)
            && let Some(init) = &mut pending.init
            && let syn::Expr::Struct(value) = &mut *init.expr
            && value.path.is_ident("Self")
            && value.rest.is_none()
        {
            value.fields.pop_punct();
        }
        actual.stmts.len() == expected.stmts.len()
            && actual.stmts[1..]
                .iter()
                .map(ToTokens::to_token_stream)
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                == expected.stmts[1..]
                    .iter()
                    .map(ToTokens::to_token_stream)
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
    }

    #[test]
    fn actual_native_checks_arm_before_work_and_keep_independent_post_and_primary() {
        let prepare = method("PendingControllerCurrentInstallation", "prepare");
        let check = method("PendingControllerCurrentInstallation", "check");
        assert!(prepare_flow(&prepare));
        assert!(negative_start(
            &check,
            "NativeControllerChecking",
            "owner",
            "self"
        ));
        let expected_check: syn::Block = syn::parse_quote!({
            let mut attempt = NativeControllerChecking {
                owner: self,
                completed: false,
            };
            let requested = (|| {
                attempt.owner.loan.check()?;
                check_controller(&mut attempt.owner.loan, &mut attempt.owner.same)
            })();
            let checked = attempt.owner.loan.check();
            if requested.is_err() || checked.is_err() {
                attempt.owner.refuse();
            }
            requested?;
            checked?;
            attempt.completed = true;
            Ok(())
        });
        // Optional terminal field separators do not alter the actual struct
        // fields; all other statements stay exact. The first was checked above.
        assert_eq!(
            check.block.stmts[1..]
                .iter()
                .map(ToTokens::to_token_stream)
                .map(|x| x.to_string())
                .collect::<Vec<_>>(),
            expected_check.stmts[1..]
                .iter()
                .map(ToTokens::to_token_stream)
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
        );
        let body = check.block.to_token_stream().to_string();
        for (from, to) in [
            (
                "let checked = attempt . owner . loan . check () ;",
                "let checked = Ok (()) ;",
            ),
            ("requested ? ; checked ? ;", "checked ? ; requested ? ;"),
            ("attempt . owner . refuse () ;", ""),
        ] {
            assert_eq!(body.matches(from).count(), 1);
            assert_ne!(
                syn::parse_str::<syn::Block>(&body.replacen(from, to, 1))
                    .unwrap()
                    .to_token_stream()
                    .to_string(),
                check.block.to_token_stream().to_string()
            );
        }
        let prepare_body = prepare.block.to_token_stream().to_string();
        let actual_posts = prepare_body.matches(". check ()").count();
        assert_eq!(actual_posts, 2);
        let mut conditional_post = prepare.clone();
        conditional_post.block.stmts[1] = syn::parse_quote! {
            let requested=(|| {
                let loan=attempt.loan.as_mut().context("restore_native_controller_loan_missing")?;
                loan.check()?;
                let same=capture_controller(loan)?;
                loan.check()?;
                Ok(same)
            })();
        };
        conditional_post.block.stmts[2] =
            syn::parse_quote! {let checked=Ok::<(),anyhow::Error>(());};
        assert_eq!(
            conditional_post
                .block
                .to_token_stream()
                .to_string()
                .matches(". check ()")
                .count(),
            actual_posts
        );
        assert!(
            !prepare_flow(&conditional_post),
            "two calls do not prove an independent outer post after primary error"
        );
        let requested_at = prepare_body.find("let same = requested ? ;").unwrap();
        let post_at = prepare_body.find("checked ? ;").unwrap();
        let take_at = prepare_body.find("attempt . loan . take ()").unwrap();
        let complete_at = prepare_body.find("attempt . completed = true").unwrap();
        assert!(requested_at < post_at && post_at < take_at && take_at < complete_at);
        for forbidden in [
            "NativeAcquisition :: begin",
            "begin_current",
            "finish_known",
            "store :: open",
            "release",
            "capture_current",
        ] {
            assert!(!prepare_body.contains(forbidden));
            assert!(!body.contains(forbidden));
        }
    }

    #[test]
    fn actual_native_negative_drop_refuses_the_same_carrier_without_io_or_clock() {
        let pending = method("PendingControllerCurrentInstallation", "drop").block;
        let expected: syn::Block = syn::parse_quote!({
            self.loan.refuse();
        });
        assert_eq!(
            pending.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let checking = method("NativeControllerChecking", "drop").block;
        let expected: syn::Block = syn::parse_quote!({
            if !self.completed {
                self.owner.refuse();
            }
        });
        assert_eq!(
            checking.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let preparing = method("NativeControllerPreparing", "drop").block;
        let expected: syn::Block = syn::parse_quote!({
            if !self.completed
                && let Some(loan) = &mut self.loan
            {
                loan.refuse();
            }
        });
        assert_eq!(
            preparing.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }

    fn retirement_flow(method: &syn::ImplItemFn) -> bool {
        if method.sig.inputs.len() != 1
            || !matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver)) if receiver.reference.is_none())
            || method.block.stmts.len() != 8
        {
            return false;
        }
        let expected: syn::Block = syn::parse_quote!({
            self.check()?;
            let accepted = self.loan.send_installed_acceptance();
            let checked = self.check();
            if accepted.is_err() || checked.is_err() {
                self.refuse();
            }
            accepted?;
            checked?;
            let native = retire_controller(&mut self.loan)?;
        });
        if method.block.stmts[..7]
            .iter()
            .map(|item| item.to_token_stream().to_string())
            .collect::<Vec<_>>()
            != expected
                .stmts
                .iter()
                .map(|item| item.to_token_stream().to_string())
                .collect::<Vec<_>>()
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::Call(result), None) = &method.block.stmts[7] else {
            return false;
        };
        if !matches!(&*result.func, syn::Expr::Path(path) if path.path.is_ident("Ok"))
            || result.args.len() != 1
        {
            return false;
        }
        let Some(syn::Expr::Struct(carrier)) = result.args.first() else {
            return false;
        };
        carrier
            .path
            .is_ident("RetiredControllerCurrentInstallation")
            && carrier.rest.is_none()
            && carrier.fields.len() == 2
            && carrier.fields.iter().all(|field| match &field.member {
                syn::Member::Named(name) if name == "native" => {
                    matches!(&field.expr, syn::Expr::Path(path) if path.path.is_ident("native"))
                }
                syn::Member::Named(name) if name == "pending" => {
                    matches!(&field.expr, syn::Expr::Path(path) if path.path.is_ident("self"))
                }
                _ => false,
            })
    }

    fn scoped_arguments(ty: &syn::Type, expected: &str) -> Option<Vec<String>> {
        let syn::Type::Path(path) = ty else {
            return None;
        };
        if path.qself.is_some() || path.path.segments.len() != 1 {
            return None;
        }
        let part = path.path.segments.first()?;
        if part.ident != expected {
            return None;
        }
        let syn::PathArguments::AngleBracketed(args) = &part.arguments else {
            return None;
        };
        args.args
            .iter()
            .map(|arg| match arg {
                syn::GenericArgument::Lifetime(lifetime) => Some(lifetime.ident.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn actual_retirement_consumes_whole_post_ack_carrier_after_final_full_checks() {
        let actual = method("PendingControllerCurrentInstallation", "retire_old_current");
        assert!(retirement_flow(&actual));
        let mut no_post = actual.clone();
        no_post.block.stmts.remove(0);
        assert!(!retirement_flow(&no_post));
        let mut late_post = actual.clone();
        late_post.block.stmts.swap(0, 1);
        assert!(!retirement_flow(&late_post));
        let mut omitted_loan = actual.clone();
        omitted_loan.block.stmts[6] = syn::parse_quote! {
            let native = retire_controller(&mut other.loan)?;
        };
        assert!(!retirement_flow(&omitted_loan));
        let mut detached = actual.clone();
        detached.block.stmts[7] = syn::Stmt::Expr(syn::parse_quote!(Ok(native)), None);
        assert!(!retirement_flow(&detached));
        let mut wrong_acceptance = actual.clone();
        wrong_acceptance.block.stmts[1] = syn::parse_quote! {
            let accepted = other.loan.send_installed_acceptance();
        };
        assert!(!retirement_flow(&wrong_acceptance));
        let mut conditional_post = actual.clone();
        conditional_post.block.stmts[2] = syn::parse_quote! {
            let checked = if accepted.is_ok() { self.check() } else { Ok(()) };
        };
        assert!(!retirement_flow(&conditional_post));
        let mut replaced_primary = actual.clone();
        replaced_primary.block.stmts.swap(4, 5);
        assert!(!retirement_flow(&replaced_primary));
        let syn::ReturnType::Type(_, returned) = actual.sig.output else {
            panic!("missing owned output");
        };
        let syn::Type::Path(path) = *returned else {
            panic!("unexpected output");
        };
        let part = path.path.segments.first().unwrap();
        assert!(path.qself.is_none() && path.path.segments.len() == 1 && part.ident == "Result");
        let syn::PathArguments::AngleBracketed(args) = &part.arguments else {
            panic!("missing result argument");
        };
        assert_eq!(args.args.len(), 1);
        let Some(syn::GenericArgument::Type(carrier)) = args.args.first() else {
            panic!("unexpected result argument");
        };
        assert_eq!(
            scoped_arguments(carrier, "RetiredControllerCurrentInstallation").unwrap(),
            [
                "frame",
                "confirm",
                "metadata",
                "storage",
                "role",
                "target",
                "selection"
            ]
        );
    }

    fn terminal_flow(body: &syn::Block) -> bool {
        let expected: syn::Block = syn::parse_quote!({
            let frame = &mut loan
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .frame;
            let owner = &mut *frame.confirmation.owner;
            let reader = &mut owner.auth.action.reader.loan;
            reader.disposition.require_closed()?;
            reader.reads.finish(
                reader
                    .physical
                    .as_mut()
                    .context("native_restore_physical_closed")?
                    .controller_stage()?,
            )?;
            reader
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?
                .release_restore_stop(&owner.stopped)?;
            reader
                .physical
                .take()
                .context("native_restore_physical_closed")?
                .retire_restore_native()
        });
        body.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }

    #[test]
    fn actual_terminal_order_finishes_same_counter_then_same_stop_then_owned_physical() {
        let file = syn::parse_file(include_str!("native_current.rs")).unwrap();
        let actual = file
            .items
            .into_iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "retire_controller" => Some(item),
                _ => None,
            })
            .unwrap();
        assert!(terminal_flow(&actual.block));
        for index in 0..actual.block.stmts.len() {
            let mut changed = actual.block.clone();
            changed.stmts.remove(index);
            assert!(!terminal_flow(&changed));
        }
        let mut early_release = actual.block.clone();
        early_release.stmts.swap(4, 5);
        assert!(!terminal_flow(&early_release));
        let mut parent_after_counter = actual.block.clone();
        parent_after_counter
            .stmts
            .insert(5, syn::parse_quote! {loan.check()?;});
        assert!(!terminal_flow(&parent_after_counter));
        let rendered = actual.block.to_token_stream().to_string();
        for (from, to) in [
            ("& owner . stopped", "& other.stopped"),
            ("reader . reads . finish", "other.reads.finish"),
            (". take ()", ". as_mut ()"),
            (". retire_restore_native ()", ". finish_app_known ()"),
        ] {
            assert_eq!(rendered.matches(from).count(), 1);
            let changed: syn::Block = syn::parse_str(&rendered.replacen(from, to, 1)).unwrap();
            assert!(!terminal_flow(&changed));
        }
    }

    #[test]
    fn retired_carrier_retains_all_scoped_owners_and_negative_drop_without_getters() {
        let file = syn::parse_file(include_str!("native_current.rs")).unwrap();
        let carrier = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "RetiredControllerCurrentInstallation" => {
                    Some(item)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(carrier.generics.lifetimes().count(), 7);
        assert_eq!(carrier.fields.len(), 2);
        for field in &carrier.fields {
            assert!(matches!(field.vis, syn::Visibility::Inherited));
        }
        let pending = carrier
            .fields
            .iter()
            .find(|field| field.ident.as_ref().is_some_and(|name| name == "pending"))
            .unwrap();
        assert_eq!(
            scoped_arguments(&pending.ty, "PendingControllerCurrentInstallation").unwrap(),
            [
                "frame",
                "confirm",
                "metadata",
                "storage",
                "role",
                "target",
                "selection"
            ]
        );
        let native = carrier
            .fields
            .iter()
            .find(|field| field.ident.as_ref().is_some_and(|name| name == "native"))
            .unwrap();
        assert_eq!(
            scoped_arguments(&native.ty, "RetainedControllerNative").unwrap(),
            ["role"]
        );
        let negative = method("RetiredControllerCurrentInstallation", "drop");
        let expected: syn::Block = syn::parse_quote!({
            self.pending.refuse();
        });
        assert_eq!(
            negative.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        for item in file.items {
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == "RetiredControllerCurrentInstallation"))
            {
                assert!(
                    item.trait_
                        .as_ref()
                        .is_some_and(|(_, path, _)| path.is_ident("Drop"))
                );
            }
        }
    }
}
