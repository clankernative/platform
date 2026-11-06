//! Closed administrative restore authentication, not a business Current scope.
//! The actual owner type is the classification: only its consuming fixed reader
//! factory can create it. No purpose flag exempts arbitrary AdminRead/CurrentRole
//! callbacks. It retains the accepting reader and existing auth ledger; no human
//! wait, new original, business continuation or ordinary SQL fallback exists.
use super::ControllerAdminReader;
use crate::security_epoch::{
    restore_approval::ApprovalIntent, storage_authority::AuthenticationStoreFiles,
};
use anyhow::{Context, Result, ensure};
use rusqlite::Connection;

// SQLite closes first on unwinding; the unfinished file guard then poisons the
// same shared original before the actual reader/peer/counter owner is released.
pub(in crate::security_epoch) struct RestoreAuthenticationAction<'metadata, 'storage, 'role> {
    sqlite: Option<Box<Connection>>,
    files: AuthenticationStoreFiles,
    reader: ControllerAdminReader<'metadata, 'storage, 'role>,
    intent: ApprovalIntent,
    refused: bool,
}

impl<'metadata, 'storage, 'role> ControllerAdminReader<'metadata, 'storage, 'role> {
    pub(in crate::security_epoch) fn admit_restore_authentication(
        mut self,
        expected: &ApprovalIntent,
    ) -> Result<RestoreAuthenticationAction<'metadata, 'storage, 'role>> {
        let requested = (|| {
            expected.validate()?;
            ensure!(
                self.selected.operation == expected.commitment()?
                    && self.selected.executor == expected.executor.email
                    && self.loan.selection.scope == expected.target.scope
                    && self.loan.selection.authority_key()? == expected.target.authority
                    && day2_capabilities::Digest::of(&self.loan.selection)?
                        == expected.target.selection,
                "restore_auth_intent_selection_changed"
            );
            let operation = self.selected.operation.clone();
            let approver = self.selected.approver.clone();
            let executor = self.selected.executor.clone();
            self.check(self.metadata, &operation, &approver, &executor)?;
            let mut files = self
                .loan
                .physical
                .as_mut()
                .context("restore_auth_reader_closed")?
                .admit_authentication_store()?;
            let opened = crate::store::open_authentication_sqlite(&mut files);
            let checked = self.check_registry_local();
            let sqlite = opened?;
            checked?;
            // Admission never initializes an empty or unknown ledger. Use the
            // producer's ONE canonical schema validator inside the same actual
            // native/file lifetime; no shadow DDL or supplied success exists.
            self.check_registry_local()?;
            crate::store::check_authentication_sqlite(&mut files, &sqlite)?;
            let schema = crate::security_epoch::restore_webauthn::require_existing_schema(&sqlite);
            let held = crate::store::check_authentication_sqlite(&mut files, &sqlite);
            let native = self.check_registry_local();
            schema?;
            held?;
            native?;
            Ok((sqlite, files))
        })();
        let (sqlite, files) = match requested {
            Ok(value) => value,
            Err(error) => {
                self.refuse();
                return Err(error);
            }
        };
        let mut action = RestoreAuthenticationAction {
            sqlite: Some(sqlite),
            files,
            reader: self,
            intent: expected.clone(),
            refused: false,
        };
        action.check(expected)?;
        Ok(action)
    }
}

impl RestoreAuthenticationAction<'_, '_, '_> {
    pub(in crate::security_epoch) fn check(&mut self, expected: &ApprovalIntent) -> Result<()> {
        let requested = (|| {
            ensure!(!self.refused, "restore_auth_action_refused");
            // This is the ACTUAL other SQLite connection. The App reader's
            // state cannot authorize a policy/config/provider read here.
            let sqlite = self.sqlite.as_ref().context("restore_auth_sqlite_closed")?;
            require_outside_unit(sqlite)?;
            self.intent.require_exact(expected)?;
            let operation = self.reader.selected.operation.clone();
            let approver = self.reader.selected.approver.clone();
            let executor = self.reader.selected.executor.clone();
            self.reader
                .check(self.reader.metadata, &operation, &approver, &executor)?;
            self.check_local()
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn check_local(&mut self) -> Result<()> {
        let requested = (|| {
            ensure!(!self.refused, "restore_auth_action_refused");
            self.reader.check_registry_local()?;
            let sqlite = self.sqlite.as_ref().context("restore_auth_sqlite_closed")?;
            let result = crate::store::check_authentication_sqlite(&mut self.files, sqlite);
            let checked = self.reader.check_registry_local();
            result?;
            checked
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn finish_checked(mut self) -> Result<()> {
        let expected = self.intent.clone();
        let requested = self.check(&expected);
        // All mandatory close/postchecks run even when the primary check failed.
        let closed = match self.sqlite.take() {
            Some(sqlite) => match (*sqlite).close() {
                Ok(()) => Ok(()),
                Err((sqlite, error)) => {
                    drop(sqlite);
                    Err(error.into())
                }
            },
            None => Err(anyhow::anyhow!("restore_auth_sqlite_closed")),
        };
        let native = self.reader.check_registry_local();
        let files = self.files.check();
        if requested.is_err() || closed.is_err() || native.is_err() || files.is_err() {
            self.refuse();
        }
        requested?;
        closed?;
        native?;
        files?;
        self.files.finish_checked()?;
        self.reader.finish_checked()
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused = true;
        self.files.refuse();
        self.reader.refuse();
    }
}

fn require_outside_unit(sqlite: &Connection) -> Result<()> {
    ensure!(sqlite.is_autocommit(), "restore_auth_transaction_open");
    Ok(())
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <RestoreAuthenticationAction<'static, 'static, 'static> as Ambiguous<_>>::check;
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
mod tests {
    use super::*;

    // The exemption is the fixed actual owner, never a caller-controlled
    // purpose value. It cannot lend a business callback, stage or SQL handle.
    fn closed_administrative_action(source: &str) -> bool {
        use quote::ToTokens;
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let Some(owner) = file.items.iter().find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "RestoreAuthenticationAction" => Some(item),
            _ => None,
        }) else {
            return false;
        };
        if owner
            .fields
            .iter()
            .any(|field| !matches!(field.vis, syn::Visibility::Inherited))
        {
            return false;
        }
        let fields = owner.fields.to_token_stream().to_string();
        if !fields.contains("reader : ControllerAdminReader < 'metadata , 'storage , 'role >")
            || !fields.contains("intent : ApprovalIntent")
            || fields.contains("purpose :")
            || fields.contains("business :")
        {
            return false;
        }
        let mut factories = 0;
        for item in &file.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            let self_type = item.self_ty.to_token_stream().to_string();
            for member in &item.items {
                let syn::ImplItem::Fn(method) = member else {
                    continue;
                };
                let signature = method.sig.to_token_stream().to_string();
                if self_type.starts_with("RestoreAuthenticationAction") {
                    if !matches!(
                        method.sig.ident.to_string().as_str(),
                        "check" | "check_local" | "finish_checked" | "refuse"
                    ) || signature.contains("Fn")
                        || signature.contains("EnrolledRoleStage")
                        || signature.contains("Connection")
                    {
                        return false;
                    }
                } else if signature.contains("RestoreAuthenticationAction") {
                    factories += 1;
                    if !self_type.starts_with("ControllerAdminReader")
                        || method.sig.ident != "admit_restore_authentication"
                        || method
                            .sig
                            .generics
                            .params
                            .iter()
                            .any(|parameter| !matches!(parameter, syn::GenericParam::Lifetime(_)))
                        || signature.contains("purpose")
                        || signature.contains("bool")
                        || signature.contains("Fn")
                    {
                        return false;
                    }
                    let body = method.block.to_token_stream().to_string();
                    let (Some(checked), Some(opened), Some(created)) = (
                        body.find("self . check (self . metadata"),
                        body.find("admit_authentication_store ()"),
                        body.find("let mut action = RestoreAuthenticationAction"),
                    ) else {
                        return false;
                    };
                    if checked >= opened
                        || opened >= created
                        || !body
                            .contains("self . selected . operation == expected . commitment () ?")
                        || !body.contains("intent : expected . clone ()")
                    {
                        return false;
                    }
                }
            }
        }
        factories == 1
    }

    #[test]
    fn restore_authentication_classification_requires_the_actual_closed_owner() {
        let source = include_str!("authentication_store.rs");
        assert!(closed_administrative_action(source));
        for (old, new) in [
            (
                "reader: ControllerAdminReader<'metadata, 'storage, 'role>,",
                "pub reader: ControllerAdminReader<'metadata, 'storage, 'role>,",
            ),
            (
                "expected: &ApprovalIntent,",
                "expected: &ApprovalIntent, purpose: bool,",
            ),
            (
                "self.check(self.metadata, &operation, &approver, &executor)?;",
                "",
            ),
            (
                "pub(in crate::security_epoch) fn refuse(&mut self)",
                "pub(in crate::security_epoch) fn business(&mut self)",
            ),
        ] {
            let mutant = source.replacen(old, new, 1);
            assert_ne!(mutant, source, "actual administrative boundary");
            assert!(!closed_administrative_action(&mutant));
        }
    }

    #[test]
    fn actual_auth_begin_refuses_full_check_even_while_app_connection_is_outside_unit() -> Result<()>
    {
        let auth = Connection::open_in_memory()?;
        let app = Connection::open_in_memory()?;
        require_outside_unit(&auth)?;
        auth.execute_batch("BEGIN")?;
        assert!(app.is_autocommit());
        assert!(require_outside_unit(&auth).is_err());
        auth.execute_batch("ROLLBACK")?;
        require_outside_unit(&auth)
    }
    fn outside_before_reader(source: &str) -> bool {
        use quote::ToTokens;
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let check = file.items.iter().find_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            if !item
                .self_ty
                .to_token_stream()
                .to_string()
                .starts_with("RestoreAuthenticationAction")
            {
                return None;
            }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "check" => Some(method),
                _ => None,
            })
        });
        let Some(check) = check else {
            return false;
        };
        let text = check.block.to_token_stream().to_string();
        let (Some(actual), Some(outside), Some(reader)) = (
            text.find("self . sqlite . as_ref ()"),
            text.find("require_outside_unit (sqlite) ?"),
            text.find("self . reader . check ("),
        ) else {
            return false;
        };
        let Some(helper) = file.items.iter().find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "require_outside_unit" => Some(item),
            _ => None,
        }) else {
            return false;
        };
        let expected: syn::Block = syn::parse_quote!({
            ensure!(sqlite.is_autocommit(), "restore_auth_transaction_open");
            Ok(())
        });
        actual < outside
            && outside < reader
            && text.matches("require_outside_unit (sqlite)").count() == 1
            && helper.block.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }

    #[test]
    fn actual_auth_transaction_guard_precedes_full_reader_and_rejects_removal_or_reordering() {
        let source = include_str!("authentication_store.rs");
        assert!(outside_before_reader(source));
        for (old, new) in [
            ("require_outside_unit(sqlite)?;", ""),
            (
                "require_outside_unit(sqlite)?;",
                "let delayed_auth = sqlite;",
            ),
            (
                r#"ensure!(sqlite.is_autocommit(), "restore_auth_transaction_open");"#,
                r#"ensure!(true, "restore_auth_transaction_open");"#,
            ),
        ] {
            let mutant = source.replacen(old, new, 1);
            assert_ne!(source, mutant, "must mutate actual production guard");
            assert!(!outside_before_reader(&mutant));
        }
        let removed = source.replacen("require_outside_unit(sqlite)?;", "", 1);
        let delayed = removed.replacen(
            "self.check_local()",
            "require_outside_unit(sqlite)?; self.check_local()",
            1,
        );
        assert!(!outside_before_reader(&delayed));
    }
    #[test]
    fn admission_uses_actual_auth_schema_result_then_both_real_postchecks_before_success() {
        use quote::ToTokens;
        fn wired(source: &str) -> bool {
            let Ok(file) = syn::parse_file(source) else {
                return false;
            };
            let Some(factory) = file.items.iter().find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if !item
                    .self_ty
                    .to_token_stream()
                    .to_string()
                    .starts_with("ControllerAdminReader")
                {
                    return None;
                }
                item.items.iter().find_map(|member| match member {
                    syn::ImplItem::Fn(method)
                        if method.sig.ident == "admit_restore_authentication" =>
                    {
                        Some(method)
                    }
                    _ => None,
                })
            }) else {
                return false;
            };
            let text = factory.block.to_token_stream().to_string();
            let ordered = [
                "let schema = crate :: security_epoch :: restore_webauthn :: require_existing_schema (& sqlite) ;",
                "let held = crate :: store :: check_authentication_sqlite (& mut files , & sqlite) ;",
                "let native = self . check_registry_local () ;",
                "schema ? ; held ? ; native ? ; Ok ((sqlite , files))",
            ];
            let mut previous = None;
            for target in ordered {
                let Some(index) = text.find(target) else {
                    return false;
                };
                if previous.is_some_and(|prior| prior >= index) {
                    return false;
                }
                previous = Some(index);
            }
            text.matches("require_existing_schema").count() == 1
        }
        let source = include_str!("authentication_store.rs");
        assert!(wired(source));
        for (old, new) in [
            (
                "crate::security_epoch::restore_webauthn::require_existing_schema(&sqlite)",
                "Ok::<(), anyhow::Error>(())",
            ),
            (
                "let native = self.check_registry_local();",
                "let native = Ok::<(), anyhow::Error>(());",
            ),
            ("schema?;", "let _discarded_schema_failure = schema;"),
        ] {
            let mutant = source.replacen(old, new, 1);
            assert_ne!(source, mutant, "actual admission target");
            assert!(!wired(&mutant));
        }
    }
}
