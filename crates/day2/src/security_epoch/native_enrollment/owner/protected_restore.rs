//! Fixed protected-message signing on the actual enrolled thread/key/stage.
//! No parsed certificate, caller key, scalar clock or generic signing purpose
//! can replace this owner. These hooks do not admit a native peer or Current.

use super::{
    EnrolledCurrentRequest, EnrolledProcessRoleOwner, EnrolledRoleStage, NativeConsumerOrigin,
};
use crate::security_epoch::native_clock::StageAcquisition;
use crate::security_epoch::native_enrollment::{
    NativeRole,
    protected_restore::{ProtectedRestoreMessage, ProtectedRestoreTurn},
    protocol::StagePurpose,
    serving_peer_wire::Statement,
};
use anyhow::{Result, ensure};

/// A consuming transfer is still an outstanding use of the original. Failure
/// or unwinding poisons both actual roots; taking the request is not settlement.
struct ProtectedRequestTransfer<'role> {
    owner: Option<&'role mut EnrolledProcessRoleOwner>,
    original: NativeConsumerOrigin,
    completed: bool,
}

impl Drop for ProtectedRequestTransfer<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.original.refuse();
            if let Some(owner) = self.owner.as_deref_mut() {
                owner.refused = true;
            }
        }
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <ProtectedRequestTransfer<'static> as Ambiguous<_>>::check;
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

impl EnrolledProcessRoleOwner {
    /// The fixed native Authenticate turn consumes the SAME saved request.
    /// Its genuine acquisition moves only after requested and independent post
    /// checks. No borrowed stage is detached, and no clock is captured or copied.
    pub(in crate::security_epoch::native_enrollment) fn take_protected_restore_request<'role>(
        &'role mut self,
        mut request: EnrolledCurrentRequest,
        turn: &mut ProtectedRestoreTurn<'_>,
    ) -> Result<EnrolledRoleStage<'role>> {
        let mut attempt = ProtectedRequestTransfer {
            original: request.consumer_origin(),
            owner: Some(self),
            completed: false,
        };
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let owner = attempt
                .owner
                .as_deref_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_transfer_owner_missing"))?;
            turn.require_accepting_original(&attempt.original, owner)?;
            let mut stage = owner.borrow_current_request(&mut request)?;
            stage.require_protected_restore_role(NativeRole::EpochController)?;
            attempt.original.check_current(&mut stage)
        }));
        // This observes the actual saved request even after a requested error
        // or panic. A repaired clock cannot rescue either failed check.
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<_> {
            let owner = attempt
                .owner
                .as_deref_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_transfer_owner_missing"))?;
            let mut stage = owner.borrow_current_request(&mut request)?;
            stage.require_protected_restore_role(NativeRole::EpochController)?;
            attempt.original.check_current(&mut stage)?;
            Ok(stage.deadline)
        }));
        if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(_))) {
            turn.refuse_transfer();
        }
        // Preserve the requested primary result or panic. Only the actual
        // independent post can supply the final already-checked deadline DATA.
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(())) => {}
        }
        let deadline = match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result?,
        };
        let acquisition = request
            .acquisition
            .take()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_transfer_original_missing"))?;
        let owner = attempt
            .owner
            .take()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_transfer_owner_missing"))?;
        // After these successful takes, only construction of the SAME owned
        // stage and disarming this guard remain. Request Drop has no acquisition
        // left to finish/refuse; the returned stage and outer attempt own it.
        let stage = EnrolledRoleStage {
            owner,
            purpose: StagePurpose::CurrentRole,
            acquisition: StageAcquisition::owned(acquisition),
            deadline,
        };
        attempt.completed = true;
        Ok(stage)
    }
}

impl EnrolledRoleStage<'_> {
    pub(in crate::security_epoch::native_enrollment) fn require_protected_restore_role(
        &mut self,
        expected: NativeRole,
    ) -> Result<()> {
        let result = (|| {
            self.require_purpose(StagePurpose::CurrentRole)?;
            ensure!(
                matches!(
                    expected,
                    NativeRole::SecurityShell | NativeRole::EpochController
                ) && self.owner.role == expected,
                "protected_restore_native_role_changed"
            );
            Ok(())
        })();
        if result.is_err() {
            self.refuse_serving();
        }
        result
    }

    /// The one-way attempt is recorded BEFORE issuer/connection I/O. Cold
    /// admission narrows the SAME captured original, never starts another one.
    pub(in crate::security_epoch::native_enrollment) fn begin_protected_restore_attempt(
        &mut self,
        expected: NativeRole,
    ) -> Result<()> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.require_protected_restore_role(expected)?;
            ensure!(
                !self.owner.protected_restore_attempted,
                "protected_restore_native_attempt_already_started"
            );
            self.owner.protected_restore_attempted = true;
            self.admit_peer_connection()?;
            self.require_protected_restore_role(expected)
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse_serving();
                }
                result
            }
            Err(payload) => {
                self.refuse_serving();
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// Enrollment/original DATA only. The shared native identity statement is
    /// not a serving connection, native peer or permission in this protocol.
    pub(in crate::security_epoch::native_enrollment) fn protected_restore_statement(
        &mut self,
    ) -> Result<Statement> {
        let result = (|| {
            ensure!(
                self.owner.protected_restore_attempted,
                "protected_restore_native_admission_not_attempted"
            );
            // Reuse the actual closed-role/current-purpose native statement
            // validator; do not repeat its full check immediately before it.
            self.serving_statement()
        })();
        if result.is_err() {
            self.refuse_serving();
        }
        result
    }

    /// Only the protocol's immutable closed DATA view selects one of its two
    /// fixed signature purposes. No arbitrary domain, bytes or key is accepted.
    pub(in crate::security_epoch::native_enrollment) fn sign_protected_restore_message(
        &mut self,
        message: &ProtectedRestoreMessage<'_>,
    ) -> Result<String> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let local = self.protected_restore_statement()?;
            let commitment = message.commitment_for(&local)?;
            self.owner.key.sign(message.domain(), &commitment)
        }));
        // Observe the SAME original even if DATA/signing failed. Neither an
        // uncertainty nor a repaired clock can make this owner reusable.
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check()));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse_serving();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(signature)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(signature)
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;
    use std::{marker::PhantomData, rc::Weak, time::Duration};

    fn fixture_request() -> EnrolledCurrentRequest {
        // Clock/refusal fixture only. No enrolled owner, peer or native stage
        // is fabricated, and no accepting transfer can run on this value.
        EnrolledCurrentRequest {
            identity: Weak::new(),
            incarnation: day2_capabilities::Digest::new(b"transfer-clock-fixture"),
            role: NativeRole::EpochController,
            process: std::process::id(),
            thread: std::thread::current().id(),
            acquisition: Some(crate::security_epoch::NativeAcquisition::fixture(
                day2_capabilities::Digest::new(b"transfer-clock-domain"),
                std::process::id(),
                Duration::from_secs(100),
                Duration::from_secs(5),
            )),
            finished: false,
            local: PhantomData,
        }
    }

    #[test]
    fn saved_request_drop_still_refuses_its_actual_clock_before_any_transfer() {
        let request = fixture_request();
        let original = request.consumer_origin();
        original.require_same(&original).unwrap();
        drop(request);
        assert!(original.require_same(&original).is_err());
    }

    #[test]
    fn actual_transfer_guard_refuses_the_moved_clock_on_error_and_unwind() {
        for unwind in [false, true] {
            for cut in 0..3 {
                let mut request = fixture_request();
                let mut moved = None;
                let mut stage = None;
                let original = request.consumer_origin();
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                        let _attempt = ProtectedRequestTransfer {
                            owner: None,
                            original: request.consumer_origin(),
                            completed: false,
                        };
                        if cut >= 1 {
                            moved = Some(request.acquisition.take().unwrap());
                        }
                        if cut >= 2 {
                            stage = Some(StageAcquisition::owned(moved.take().unwrap()));
                        }
                        if unwind {
                            panic!("transfer fixture unwind");
                        }
                        anyhow::bail!("transfer fixture error")
                    }));
                if unwind {
                    assert!(result.is_err());
                } else {
                    assert!(result.unwrap().is_err());
                }
                assert!(original.require_same(&original).is_err());
                if let Some(original) = &mut request.acquisition {
                    assert!(original.sample().is_err());
                }
                if let Some(original) = &mut moved {
                    assert!(original.sample().is_err());
                }
                if let Some(stage) = &mut stage {
                    assert!(stage.as_mut().sample().is_err());
                }
                if cut >= 1 {
                    assert!(request.original_mut().is_err());
                }
            }
        }
    }

    #[test]
    fn moving_the_actual_acquisition_preserves_identity_and_an_equal_clock_cannot_replace_it() {
        let mut request = fixture_request();
        let original = request.consumer_origin();
        let mut stage = StageAcquisition::owned(request.acquisition.take().unwrap());
        drop(request);
        let moved = NativeConsumerOrigin {
            refusal: stage.as_mut().retained_refusal(),
            domain: stage.as_mut().historical_interval_observation().0,
        };
        original.require_same(&moved).unwrap();
        stage.as_mut().sample().unwrap();
        let other = fixture_request();
        assert!(original.require_same(&other.consumer_origin()).is_err());
        assert!(stage.as_mut().sample().is_err());
        assert!(
            other
                .consumer_origin()
                .require_same(&other.consumer_origin())
                .is_err()
        );
    }

    fn method(name: &str) -> syn::ImplItemFn {
        method_in(include_str!("protected_restore.rs"), name)
    }

    fn method_in(source: &str, name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(source).unwrap();
        let methods = file
            .items
            .into_iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item) => Some(item),
                _ => None,
            })
            .flat_map(|item| item.items)
            .filter_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 1, "one actual {name}");
        methods.into_iter().next().unwrap()
    }

    fn captured(block: &syn::Block, name: &str) -> syn::Block {
        let syn::Stmt::Local(local) = &block.stmts[0] else {
            panic!("first actual operation");
        };
        assert!(matches!(&local.pat, syn::Pat::Ident(id) if id.ident == name));
        let syn::Expr::Call(catch) = &*local.init.as_ref().unwrap().expr else {
            panic!("catch");
        };
        assert_eq!(
            catch.func.to_token_stream().to_string(),
            "std :: panic :: catch_unwind"
        );
        assert_eq!(catch.args.len(), 1);
        let syn::Expr::Call(safe) = &catch.args[0] else {
            panic!("unwind-safe wrapper");
        };
        assert_eq!(
            safe.func.to_token_stream().to_string(),
            "std :: panic :: AssertUnwindSafe"
        );
        assert_eq!(safe.args.len(), 1);
        let syn::Expr::Closure(closed) = &safe.args[0] else {
            panic!("actual closed work");
        };
        assert!(closed.inputs.is_empty() && closed.asyncness.is_none() && closed.capture.is_none());
        let syn::Expr::Block(body) = &*closed.body else {
            panic!("actual work block");
        };
        body.block.clone()
    }

    fn same(actual: &syn::Stmt, expected: &syn::Stmt) -> bool {
        actual.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }

    fn transfer_statement_tokens(statement: &syn::Stmt) -> String {
        fn statement_value(statement: &mut syn::Stmt) {
            match statement {
                syn::Stmt::Local(local) => {
                    if let Some(initializer) = &mut local.init {
                        expression(&mut initializer.expr);
                    }
                }
                syn::Stmt::Expr(value, _) => expression(value),
                _ => {}
            }
        }

        fn expression(value: &mut syn::Expr) {
            match value {
                syn::Expr::Closure(closure) => {
                    // Only a bare block containing this exact error macro may
                    // differ because of formatting. Keep all closure inputs,
                    // captures and attributes, and every other AST node intact.
                    let replacement = match closure.body.as_ref() {
                        syn::Expr::Block(block)
                            if block.attrs.is_empty() && block.label.is_none() =>
                        {
                            match block.block.stmts.as_slice() {
                                [syn::Stmt::Expr(syn::Expr::Macro(value), None)]
                                    if value.attrs.is_empty()
                                        && value.mac.path.leading_colon.is_none()
                                        && value.mac.path.segments.len() == 2
                                        && value.mac.path.segments[0].ident == "anyhow"
                                        && value.mac.path.segments[1].ident == "anyhow" =>
                                {
                                    Some(syn::Expr::Macro(value.clone()))
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    if let Some(replacement) = replacement {
                        *closure.body = replacement;
                    }
                    expression(&mut closure.body);
                }
                syn::Expr::Block(block) => {
                    for statement in &mut block.block.stmts {
                        statement_value(statement);
                    }
                }
                syn::Expr::Try(attempt) => expression(&mut attempt.expr),
                syn::Expr::Call(call) => {
                    expression(&mut call.func);
                    for argument in &mut call.args {
                        expression(argument);
                    }
                }
                syn::Expr::MethodCall(call) => {
                    expression(&mut call.receiver);
                    for argument in &mut call.args {
                        expression(argument);
                    }
                }
                _ => {}
            }
        }

        let mut statement = statement.clone();
        statement_value(&mut statement);
        statement.to_token_stream().to_string()
    }

    #[test]
    fn transfer_oracle_accepts_only_a_bare_error_expression_block() {
        let direct: syn::Stmt =
            syn::parse_quote!(let value = input.ok_or_else(|| anyhow::anyhow!("fixed"))?;);
        let formatted: syn::Stmt =
            syn::parse_quote!(let value = input.ok_or_else(|| { anyhow::anyhow!("fixed") })?;);
        let expected = transfer_statement_tokens(&direct);
        assert_eq!(transfer_statement_tokens(&formatted), expected);
        for source in [
            "let value = input.ok_or_else(|| { foreign(); anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|| 'scope: { anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|| { #[allow(unused)] anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|| #[allow(unused)] { anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|| { anyhow::anyhow!(\"fixed\"); })?;",
            "let value = input.ok_or_else(move || { anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|other| { anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|| { anyhow::anyhow!(\"different\") })?;",
            "let value = input.ok_or_else(|| { foreign::anyhow!(\"fixed\") })?;",
        ] {
            let changed = syn::parse_str(source).unwrap();
            assert_ne!(transfer_statement_tokens(&changed), expected);
        }
    }

    fn fixed_transfer(body: &syn::Block) -> bool {
        if body.stmts.len() != 11 {
            return false;
        }
        let expected: syn::Block =
            syn::parse_quote!({
                let mut attempt = ProtectedRequestTransfer {
                    original: request.consumer_origin(),
                    owner: Some(self),
                    completed: false,
                };
                let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let owner = attempt.owner.as_deref_mut().ok_or_else(|| {
                        anyhow::anyhow!("protected_restore_transfer_owner_missing")
                    })?;
                    turn.require_accepting_original(&attempt.original, owner)?;
                    let mut stage = owner.borrow_current_request(&mut request)?;
                    stage.require_protected_restore_role(NativeRole::EpochController)?;
                    attempt.original.check_current(&mut stage)
                }));
                let checked =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<_> {
                        let owner = attempt.owner.as_deref_mut().ok_or_else(|| {
                            anyhow::anyhow!("protected_restore_transfer_owner_missing")
                        })?;
                        let mut stage = owner.borrow_current_request(&mut request)?;
                        stage.require_protected_restore_role(NativeRole::EpochController)?;
                        attempt.original.check_current(&mut stage)?;
                        Ok(stage.deadline)
                    }));
                if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(_))) {
                    turn.refuse_transfer();
                }
                match requested {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(Err(error)) => return Err(error),
                    Ok(Ok(())) => {}
                }
                let deadline = match checked {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(result) => result?,
                };
                let acquisition = request.acquisition.take().ok_or_else(|| {
                    anyhow::anyhow!("protected_restore_transfer_original_missing")
                })?;
                let owner = attempt
                    .owner
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_transfer_owner_missing"))?;
                let stage = EnrolledRoleStage {
                    owner,
                    purpose: StagePurpose::CurrentRole,
                    acquisition: StageAcquisition::owned(acquisition),
                    deadline,
                };
                attempt.completed = true;
                Ok(stage)
            });
        body.stmts
            .iter()
            .zip(&expected.stmts)
            .all(|(actual, expected)| {
                transfer_statement_tokens(actual) == transfer_statement_tokens(expected)
            })
    }

    #[test]
    fn actual_consuming_transfer_checks_the_same_request_then_moves_its_whole_acquisition() {
        let actual = method("take_protected_restore_request");
        assert!(fixed_transfer(&actual.block));
        for index in 0..actual.block.stmts.len() {
            let mut missing = actual.block.clone();
            missing.stmts.remove(index);
            assert!(!fixed_transfer(&missing));
        }
        for (first, second) in [(0, 1), (2, 4), (5, 6), (6, 9)] {
            let mut moved = actual.block.clone();
            moved.stmts.swap(first, second);
            assert!(!fixed_transfer(&moved));
        }
        let statement = |source: &str| {
            syn::parse_str::<syn::Stmt>(source)
                .unwrap()
                .to_token_stream()
                .to_string()
        };
        let expression = |source: &str| {
            syn::parse_str::<syn::Expr>(source)
                .unwrap()
                .to_token_stream()
                .to_string()
        };
        let field = |source: &str| {
            let parsed = syn::parse_str::<syn::Expr>(&format!("Transfer {{ {source} }}")).unwrap();
            let syn::Expr::Struct(parsed) = parsed else {
                panic!("field wrapper");
            };
            assert_eq!(parsed.fields.len(), 1);
            parsed.fields[0].to_token_stream().to_string()
        };
        for (needle, replacement) in [
            (
                statement("turn.require_accepting_original(&attempt.original,owner)?;"),
                String::new(),
            ),
            (
                expression("owner.borrow_current_request(&mut request)?"),
                expression("owner.begin_current_stage()?"),
            ),
            (
                statement("stage.require_protected_restore_role(NativeRole::EpochController)?;"),
                String::new(),
            ),
            (
                expression("attempt.original.check_current(&mut stage)"),
                expression("Ok(())"),
            ),
            (
                expression("StageAcquisition::owned(acquisition)"),
                expression("StageAcquisition::owned(acquisition.narrow(5,deadline)?)"),
            ),
            (
                field("original:request.consumer_origin()"),
                field("original:other.consumer_origin()"),
            ),
        ] {
            let text = actual.block.to_token_stream().to_string();
            assert!(
                text.contains(&needle),
                "missing actual mutation target: {needle}"
            );
            let changed = syn::parse_str(&text.replacen(&needle, &replacement, 1)).unwrap();
            assert!(!fixed_transfer(&changed));
        }
        let negative = method("drop");
        let expected: syn::Block = syn::parse_quote!({
            if !self.completed {
                self.original.refuse();
                if let Some(owner) = self.owner.as_deref_mut() {
                    owner.refused = true;
                }
            }
        });
        assert_eq!(
            negative.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }

    #[test]
    fn actual_cold_factory_records_its_attempt_before_issuer_work_and_refuses_unwind() {
        use syn::parse::Parser;
        fn guarded(body: &syn::Block) -> bool {
            if body.stmts.len() != 5 {
                return false;
            }
            let expected: [(usize, syn::Stmt); 4] = [
                (
                    0,
                    syn::parse_quote!(self.require_protected_restore_role(expected)?;),
                ),
                (
                    2,
                    syn::parse_quote!(self.owner.protected_restore_attempted = true;),
                ),
                (3, syn::parse_quote!(self.admit_peer_connection()?;)),
                (
                    4,
                    syn::Stmt::Expr(
                        syn::parse_quote!(self.require_protected_restore_role(expected)),
                        None,
                    ),
                ),
            ];
            if !expected
                .iter()
                .all(|(i, expected)| same(&body.stmts[*i], expected))
            {
                return false;
            }
            let syn::Stmt::Macro(guard) = &body.stmts[1] else {
                return false;
            };
            if !guard.mac.path.is_ident("ensure") {
                return false;
            }
            let Ok(args) =
                syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                    .parse2(guard.mac.tokens.clone())
            else {
                return false;
            };
            let predicate: syn::Expr = syn::parse_quote!(!self.owner.protected_restore_attempted);
            args.len() == 2
                && args[0].to_token_stream().to_string() == predicate.to_token_stream().to_string()
                && matches!(&args[1], syn::Expr::Lit(expr) if matches!(&expr.lit, syn::Lit::Str(value) if value.value() == "protected_restore_native_attempt_already_started"))
        }
        let actual = method("begin_protected_restore_attempt");
        assert_eq!(actual.block.stmts.len(), 2);
        let body = captured(&actual.block, "result");
        assert!(guarded(&body));
        for index in 0..body.stmts.len() {
            let mut missing = body.clone();
            missing.stmts.remove(index);
            assert!(!guarded(&missing));
        }
        let mut late = body.clone();
        late.stmts.swap(2, 3);
        assert!(!guarded(&late));
        let cleanup: syn::Stmt = syn::parse_quote! {
            match result {
                Ok(result) => { if result.is_err() { self.refuse_serving(); } result }
                Err(payload) => { self.refuse_serving(); std::panic::resume_unwind(payload) }
            }
        };
        assert!(same(actual.block.stmts.last().unwrap(), &cleanup));
        let text = actual.block.to_token_stream().to_string();
        for forbidden in [
            "NativeAcquisition",
            "begin_current",
            "exchange_current_views",
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn actual_signer_checks_its_native_statement_and_independent_post_before_returning_bytes() {
        let actual = method("sign_protected_restore_message");
        assert_eq!(actual.block.stmts.len(), 4);
        let body = captured(&actual.block, "requested");
        let expected: syn::Block = syn::parse_quote!({
            let local = self.protected_restore_statement()?;
            let commitment = message.commitment_for(&local)?;
            self.owner.key.sign(message.domain(), &commitment)
        });
        assert_eq!(
            body.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let checked: syn::Stmt = syn::parse_quote!(let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check())););
        assert!(same(&actual.block.stmts[1], &checked));
        let refused: syn::Stmt = syn::parse_quote! {
            if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
                self.refuse_serving();
            }
        };
        assert!(same(&actual.block.stmts[2], &refused));
        let selected: syn::Stmt = syn::parse_quote! {
            match requested {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(Err(error)) => Err(error),
                Ok(Ok(signature)) => match checked {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(result) => { result?; Ok(signature) }
                },
            }
        };
        assert!(same(&actual.block.stmts[3], &selected));
        let refusal = method_in(include_str!("serving.rs"), "refuse_serving");
        let negative: syn::Block = syn::parse_quote!({
            self.owner.refused = true;
            self.acquisition.as_mut().refuse();
        });
        assert_eq!(
            refusal.block.to_token_stream().to_string(),
            negative.to_token_stream().to_string()
        );
    }
}
