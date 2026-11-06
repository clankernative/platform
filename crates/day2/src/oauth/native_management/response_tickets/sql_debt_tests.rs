//! Real issuer/SQLite negatives joined to the private denial ledger. These
//! tests install no native role, storage owner, Current, stage or Stop witness.
#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::{protocol::Instruction, store::delegation_capability_tests::Granted};
    use serde_json::json;

    // The negative index intentionally retains history. Give each test its own
    // executor; never clear, replace or weaken the production thread-local index.
    fn isolated(test: impl FnOnce() -> Result<()> + Send + 'static) -> Result<()> {
        match std::thread::spawn(test).join() {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn scope() -> AuthorityScope {
        AuthorityScope {
            installation: "delegationco".to_owned().try_into().unwrap(),
            environment: "test".to_owned().try_into().unwrap(),
            app: "caller".to_owned().try_into().unwrap(),
        }
    }

    fn bind() -> Instruction {
        Instruction {
            kind: "observe".into(),
            model: crate::resources::BIND.into(),
            data: json!({"binding":"directory","invocation":"sql-issuance"}).to_string(),
            ..Instruction::default()
        }
    }

    fn attenuate(parent: &str) -> Result<Instruction> {
        let parent: serde_json::Value = serde_json::from_str(parent)?;
        Ok(Instruction {
            kind: "observe".into(),
            model: crate::resources::ATTENUATE.into(),
            data: json!({"handle":parent["token"],"limits":{
            "max_request_bytes":512,"max_response_bytes":32768,
            "max_calls_per_invocation":2}})
            .to_string(),
            ..Instruction::default()
        })
    }

    #[test]
    fn caught_real_issuer_error_and_commit_remain_debt_after_known_response_completion()
    -> Result<()> {
        isolated(|| {
            let fixture = Granted::for_issuance()?;
            let runtime = fixture.metadata_native_runtime()?;
            let mut rights = ResponseRights::new();
            rights.install_issuance(&scope())?;
            let response = ResponseIdentity::new();
            let tickets = ResponseTickets::new();
            tickets
                .tickets
                .borrow_mut()
                .push(rights.register(&response)?);
            let (result, rows) =
                fixture.caught_issuance(&runtime, &fixture.imported_instruction(true))?;
            assert!(matches!(
                result.unwrap_err().downcast_ref::<crate::error::Failure>(),
                Some(crate::error::Failure::ResourceLimitExceeded)
            ));
            assert_eq!(
                rows, 1,
                "caught Err did not roll back the real handle INSERT"
            );
            assert!(rights.ledger.unfenced_authority.get());
            tickets.prepare_native(&response, &rights)?.complete();
            assert!(
                rights
                    .ledger
                    .records
                    .borrow()
                    .iter()
                    .all(|record| record.state.get() == State::Complete)
            );
            assert!(
                rights.ledger.unfenced_authority.get(),
                "known response completion cannot forgive issuance"
            );
            assert!(rights.seal_issuance().is_err());
            assert!(
                rights.ledger.issuance_sealed.get(),
                "refused sealing remains terminal"
            );
            assert!(rights.require_drained().is_err());
            assert!(record_unfenced(&scope()).is_err());
            Ok(())
        })
    }

    #[test]
    fn missing_or_sealed_premark_prevents_actual_imported_issuance_even_when_error_is_committed()
    -> Result<()> {
        for sealed in [false, true] {
            isolated(move || {
                let fixture = Granted::for_issuance()?;
                let runtime = fixture.metadata_native_runtime()?;
                let mut rights = ResponseRights::new();
                if sealed {
                    rights.install_issuance(&scope())?;
                    rights.seal_issuance()?;
                }
                let (result, rows) =
                    fixture.caught_issuance(&runtime, &fixture.imported_instruction(true))?;
                assert!(result.is_err());
                assert_eq!(
                    rows, 0,
                    "refused premark must run before HMAC/INSERT, not after authorize"
                );
                assert!(!rights.ledger.unfenced_authority.get());
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn real_bind_and_attenuate_each_mark_before_issuing_and_refuse_when_cohort_is_sealed()
    -> Result<()> {
        for attenuation in [false, true] {
            for sealed in [false, true] {
                isolated(move || {
                    let fixture = Granted::for_issuance()?;
                    let (instruction, before) = if attenuation {
                        // The parent is issued under the ordinary fixture. It is
                        // not authority for the metadata-only native caller.
                        let (parent, rows) =
                            fixture.caught_issuance(fixture.ordinary_runtime(), &bind())?;
                        assert_eq!(rows, 1);
                        (attenuate(&parent?.context("bound parent")?)?, rows)
                    } else {
                        (bind(), 0)
                    };
                    let runtime = fixture.metadata_native_runtime()?;
                    let mut rights = ResponseRights::new();
                    rights.install_issuance(&scope())?;
                    if sealed {
                        rights.seal_issuance()?;
                    }
                    let (result, rows) = fixture.caught_issuance(&runtime, &instruction)?;
                    if sealed {
                        assert!(result.is_err());
                        assert_eq!(
                            rows, before,
                            "actual issue must not run after refused premark"
                        );
                        assert!(!rights.ledger.unfenced_authority.get());
                    } else {
                        assert!(result?.is_some());
                        assert_eq!(rows, before + 1);
                        assert!(rights.ledger.unfenced_authority.get());
                        assert!(rights.seal_issuance().is_err());
                        assert!(rights.require_drained().is_err());
                    }
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    #[test]
    fn ordinary_local_sql_is_debt_free_but_missing_native_owner_suppresses_callback() -> Result<()>
    {
        isolated(|| {
            let fixture = Granted::for_issuance()?;
            let rights = ResponseRights::new();
            rights.install_issuance(&scope())?;
            // Schema birth belongs to fixture setup. RuntimeSql correctly
            // refuses DDL; the guarded business unit performs only the INSERT.
            crate::store::open(fixture.ordinary_runtime().db())?
                .execute_batch("CREATE TABLE local_only(value INTEGER) STRICT")?;
            fixture.ordinary_runtime().sql_write(|connection| {
                connection.execute("INSERT INTO local_only VALUES(7)", [])?;
                Ok(())
            })?;
            assert_eq!(
                fixture
                    .ordinary_runtime()
                    .sql_read(|connection| Ok(connection.query_row(
                        "SELECT value FROM local_only",
                        [],
                        |row| row.get::<_, i64>(0)
                    )?))?,
                7
            );
            assert!(!rights.ledger.unfenced_authority.get());
            let runtime = fixture.metadata_native_runtime()?;
            let invoked = Cell::new(false);
            assert!(
                runtime
                    .sql_write(|_| {
                        invoked.set(true);
                        Ok(())
                    })
                    .is_err()
            );
            assert!(
                !invoked.get(),
                "classification DATA cannot authorize the actual callback"
            );
            assert!(!rights.ledger.unfenced_authority.get());
            Ok(())
        })
    }

    // Portable tests cannot manufacture the Native variant. Bind the actual
    // callback wiring to check/arm and the negative hook, alongside the real
    // SQLite issuer tests above; this is not native admission qualification.
    fn callback_order(source: &str) -> Result<bool> {
        use quote::ToTokens as _;
        use syn::visit::Visit as _;
        fn statements(source: &str) -> Result<Vec<String>> {
            Ok(syn::parse_str::<syn::Block>(&format!("{{{source}}}"))?
                .stmts
                .iter()
                .map(|statement| statement.to_token_stream().to_string())
                .collect())
        }
        struct NativeCallback {
            count: usize,
            valid: bool,
        }
        impl<'ast> syn::visit::Visit<'ast> for NativeCallback {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if call.method == "run"
                    && let syn::Expr::Struct(receiver) = &*call.receiver
                    && receiver.path.is_ident("RuntimeConsumer")
                    && receiver
                        .to_token_stream()
                        .to_string()
                        .contains("RuntimeSource :: Native")
                {
                    self.count += 1;
                    self.valid &= call.args.len() == 1
                        && call.args[0].to_token_stream().to_string()
                            == syn::parse_str::<syn::Expr>("|current| { if !matches!(phase, RuntimePhase::SqlRead | RuntimePhase::SqlWrite) { record_unfenced_runtime(runtime)?; } operation(current) }").unwrap().to_token_stream().to_string();
                }
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let file = syn::parse_file(source)?;
        let mut run = Vec::new();
        let mut send = Vec::new();
        let mut callback = NativeCallback {
            count: 0,
            valid: true,
        };
        for item in &file.items {
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.segments.last().is_some_and(|part| part.ident == "RuntimeConsumer"))
            {
                for member in &item.items {
                    if let syn::ImplItem::Fn(method) = member {
                        let body = method
                            .block
                            .stmts
                            .iter()
                            .map(|statement| statement.to_token_stream().to_string())
                            .collect::<Vec<_>>();
                        if method.sig.ident == "run" {
                            run.push(body);
                        } else if method.sig.ident == "send" {
                            send.push(body);
                        }
                    }
                }
            }
            if let syn::Item::Fn(function) = item
                && function.sig.ident == "with_runtime_consumer"
            {
                callback.visit_block(&function.block);
            }
        }
        Ok(run.len() == 1 && send.len() == 1
            && run[0].starts_with(&statements("self.check()?; if let RuntimeSource::Native { current, stage } = &mut self.source { current.arm(stage)?; }")?)
            && send[0].first() == statements("let result = (|| { self.check()?; if let RuntimeSource::Native { .. } = &self.source { let runtime = self.runtime.context(\"native_authority_runtime_missing\")?; record_unfenced_runtime(runtime)?; } let value = operation()?; self.check()?; Ok(value) })();")?.first()
            && callback.count == 1 && callback.valid)
    }

    #[test]
    fn actual_native_callback_checks_arm_and_debt_hook_precede_material_work() -> Result<()> {
        use quote::ToTokens as _;
        let source = include_str!("../../native_management.rs");
        assert!(callback_order(source)?);
        for method_name in ["run", "send"] {
            for index in [0, 1] {
                let mut file = syn::parse_file(source)?;
                let mut changed = 0;
                for item in &mut file.items {
                    if let syn::Item::Impl(item) = item
                        && matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.segments.last().is_some_and(|part| part.ident == "RuntimeConsumer"))
                    {
                        for member in &mut item.items {
                            if let syn::ImplItem::Fn(method) = member
                                && method.sig.ident == method_name
                            {
                                if method_name == "run" {
                                    method.block.stmts.remove(index);
                                } else {
                                    let syn::Stmt::Local(local) = &mut method.block.stmts[0] else {
                                        panic!("actual send result")
                                    };
                                    let syn::Expr::Call(call) =
                                        &mut *local.init.as_mut().unwrap().expr
                                    else {
                                        panic!("actual send closure call")
                                    };
                                    let syn::Expr::Paren(paren) = &mut *call.func else {
                                        panic!("actual send closure parentheses")
                                    };
                                    let syn::Expr::Closure(closure) = &mut *paren.expr else {
                                        panic!("actual send closure")
                                    };
                                    let syn::Expr::Block(block) = &mut *closure.body else {
                                        panic!("actual send body")
                                    };
                                    block.block.stmts.remove(index);
                                }
                                changed += 1;
                            }
                        }
                    }
                }
                assert_eq!(changed, 1);
                assert!(!callback_order(&file.to_token_stream().to_string())?);
            }
        }
        let normalized = syn::parse_file(source)?.to_token_stream().to_string();
        let mark = syn::parse_str::<syn::Expr>("if !matches!(phase, RuntimePhase::SqlRead | RuntimePhase::SqlWrite) { record_unfenced_runtime(runtime)?; }")?.to_token_stream().to_string();
        assert_eq!(
            normalized.matches(&mark).count(),
            1,
            "actual native wrapper target"
        );
        for replacement in [
            String::new(),
            "operation(current)?;".into(),
            mark.replace(
                "RuntimePhase :: SqlWrite",
                "RuntimePhase :: SqlWrite | RuntimePhase :: Read",
            ),
        ] {
            assert!(!callback_order(&normalized.replacen(
                &mark,
                &replacement,
                1
            ))?);
        }
        Ok(())
    }
}
