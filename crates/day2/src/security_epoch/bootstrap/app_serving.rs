//! Same active App owner through the fixed serving acquisition and consumer.
use super::{
    ActiveAppStorageContinuity, AppRuntimeImage, CurrentAppServingPhase, ServingDisposition,
};
use crate::security_epoch::{
    native_enrollment::{EnrolledRoleStage, StoragePeerRequest},
    serving::CurrentServingPhase,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
impl ActiveAppStorageContinuity {
    pub(in crate::security_epoch) async fn with_serving_async<'role, T>(
        &mut self,
        stage: &mut EnrolledRoleStage<'role>,
        binding: Digest,
        purpose: crate::security_epoch::serving::ScopePurpose,
        operation: impl AsyncFnOnce(
            &mut dyn CurrentServingPhase,
            &mut EnrolledRoleStage<'role>,
        ) -> Result<T>,
    ) -> crate::security_epoch::serving::ScopeOutcome<T> {
        match self.begin_serving(stage, binding, purpose) {
            Ok(scope) => scope.run_async(stage, operation).await,
            Err(error) => crate::security_epoch::serving::ScopeOutcome::Refused(error),
        }
    }

    fn begin_serving<'storage>(
        &'storage mut self,
        stage: &mut EnrolledRoleStage<'_>,
        binding: Digest,
        purpose: crate::security_epoch::serving::ScopePurpose,
    ) -> Result<CurrentAppServingPhase<'storage>> {
        ensure!(self.valid, "active_app_storage_refused");
        self.valid = false;
        let image = match purpose {
            crate::security_epoch::serving::ScopePurpose::Runtime(
                crate::security_epoch::serving::RuntimeServingUse::InitialStorage,
            ) => AppRuntimeImage::Initial(Box::new(self.storage.bootstrap_core()?)),
            _ => AppRuntimeImage::Existing,
        };
        let request = StoragePeerRequest::CurrentServing {
            binding: self.lineage.serving_binding(&binding)?,
        };
        let evidence = crate::security_epoch::serving::ConsumerScopeEvidence::app(
            Digest::of(&(
                "day2-controller-evidence-selection-v1",
                &self.policy,
                &self.store,
            ))?,
            stage.incarnation_data()?,
            request.binding().clone(),
            purpose,
        );
        // The admitted credential's fixed ceiling meets the actual stage
        // BEFORE a peer statement/signature captures its immutable interval.
        let mut reads = self.counter.request(
            stage,
            &self.policy,
            &self.store,
            day2_capabilities::security_epoch::bootstrap::NativeRole::AppHost,
        )?;
        let mut physical = self.storage.begin_current(stage, request)?;
        physical.await_known(stage)?;
        let observed = self.lineage.read(&self.store, &mut reads, stage)?;
        physical.check(stage)?;
        Ok(CurrentAppServingPhase {
            physical,
            reads,
            observed,
            selection: self.store.clone(),
            lineage: &self.lineage,
            image,
            policy: self.policy.clone(),
            continuation: &mut self.valid,
            disposition: ServingDisposition::Unarmed,
            purpose,
            evidence,
        })
    }

    pub(in crate::security_epoch) fn with_serving<'role, T>(
        &mut self,
        stage: &mut EnrolledRoleStage<'role>,
        binding: Digest,
        purpose: crate::security_epoch::serving::ScopePurpose,
        operation: impl FnOnce(&mut dyn CurrentServingPhase, &mut EnrolledRoleStage<'role>) -> Result<T>,
    ) -> crate::security_epoch::serving::ScopeOutcome<T> {
        match self.begin_serving(stage, binding, purpose) {
            Ok(scope) => scope.run(stage, operation),
            Err(error) => crate::security_epoch::serving::ScopeOutcome::Refused(error),
        }
    }
}
impl<'storage> CurrentAppServingPhase<'storage> {
    pub(in crate::security_epoch) fn begin_runtime_database(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        let result = (|| {
            self.check_runtime_selection(stage, metadata)?;
            ensure!(
                self.disposition == ServingDisposition::Armed,
                "native_sqlite_birth_before_arm"
            );
            self.physical.begin_sqlite(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn check_runtime_opened_database(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        db: &rusqlite::Connection,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage)?;
            ensure!(
                matches!(
                    self.purpose,
                    crate::security_epoch::serving::ScopePurpose::Runtime(
                        crate::security_epoch::serving::RuntimeServingUse::InitialStorage
                    )
                ) && self.disposition == ServingDisposition::Armed,
                "native_sqlite_birth_purpose_required"
            );
            self.physical.check_opened_sqlite(stage, db)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn retain_runtime_database(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        keeper: crate::store::NativeSqliteKeeper,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage)?;
            ensure!(
                matches!(
                    self.purpose,
                    crate::security_epoch::serving::ScopePurpose::Runtime(
                        crate::security_epoch::serving::RuntimeServingUse::InitialStorage
                    )
                ) && self.disposition == ServingDisposition::Armed,
                "native_sqlite_birth_purpose_required"
            );
            self.physical.retain_sqlite(stage, keeper)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn reobserve(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        let result = (|| {
            // Check the old observation BEFORE replacing DATA: an expired
            // read/authentication origin cannot be renewed by a fresh reply.
            self.check(stage)?;
            let observed = self.lineage.read(&self.selection, &mut self.reads, stage)?;
            self.observed = observed;
            self.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                !*self.continuation && self.disposition != ServingDisposition::Refused,
                "native_serving_scope_refused"
            );
            self.physical.check(stage)?;
            self.lineage
                .check(&self.selection, &mut self.reads, stage, &mut self.observed)?;
            self.physical.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn admit_runtime_database(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        metadata: &crate::store::InitialStoreMetadata,
        db: &rusqlite::Connection,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage)?;
            ensure!(
                matches!(
                    self.purpose,
                    crate::security_epoch::serving::ScopePurpose::Runtime(
                        crate::security_epoch::serving::RuntimeServingUse::InitialStorage
                    )
                ),
                "native_runtime_initial_admission_purpose_required"
            );
            metadata.require_native_selection(
                &self.selection,
                self.lineage.initial_runtime_artifact_data()?,
                &self.policy,
            )?;
            let AppRuntimeImage::Initial(seed) = &self.image else {
                anyhow::bail!("native_runtime_initial_image_required");
            };
            crate::security_epoch::preparation_image::require_existing_selection(
                db,
                seed,
                &self.selection,
            )?;
            self.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn check_runtime_selection(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage)?;
            ensure!(
                matches!(
                    self.purpose,
                    crate::security_epoch::serving::ScopePurpose::Runtime(
                        crate::security_epoch::serving::RuntimeServingUse::InitialStorage
                    )
                ),
                "native_runtime_initial_admission_purpose_required"
            );
            metadata.require_native_selection(
                &self.selection,
                self.lineage.initial_runtime_artifact_data()?,
                &self.policy,
            )?;
            self.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn arm(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        if self.disposition != ServingDisposition::Unarmed {
            self.refuse();
            anyhow::bail!("native_serving_attempt_already_armed");
        }
        self.disposition = ServingDisposition::Armed;
        self.check(stage)
    }

    pub(in crate::security_epoch) fn finish_known(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        if !matches!(
            self.disposition,
            ServingDisposition::Unarmed | ServingDisposition::Armed
        ) {
            self.refuse();
            anyhow::bail!("native_serving_result_already_recorded");
        }
        if matches!(
            self.purpose,
            crate::security_epoch::serving::ScopePurpose::Runtime(
                crate::security_epoch::serving::RuntimeServingUse::InitialStorage
            )
        ) && let Err(error) = self.physical.require_sqlite(stage)
        {
            self.refuse();
            return Err(error);
        }
        self.disposition = ServingDisposition::Known;
        self.check(stage)
    }

    pub(in crate::security_epoch) fn finish_excluded(&mut self) -> Result<()> {
        if self.disposition != ServingDisposition::Unarmed {
            self.refuse();
            anyhow::bail!("native_serving_exclusion_after_attempt");
        }
        self.disposition = ServingDisposition::Excluded;
        Ok(())
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.disposition = ServingDisposition::Refused;
        *self.continuation = false;
        self.physical.refuse();
        self.reads.refuse();
    }

    fn finish_scope(mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.check(stage)?;
        ensure!(
            matches!(
                self.disposition,
                ServingDisposition::Known | ServingDisposition::Excluded
            ),
            "native_serving_unknown_result"
        );
        let observed = self.lineage.read(&self.selection, &mut self.reads, stage)?;
        self.observed = observed;
        self.check(stage)?;
        // The exact final coherent provider observation is historical DATA.
        // No completion is exported until the actual peer ACK and postcheck.
        self.evidence
            .snapshot(self.lineage.snapshot_data(&self.observed)?);
        let known = self.disposition == ServingDisposition::Known;
        self.physical.finish_checked(stage)?;
        stage.check()?;
        self.reads.finish(stage)?;
        *self.continuation = true;
        if known {
            self.evidence
                .record(crate::security_epoch::serving::ConsumerScopeResult::Completed);
        }
        Ok(())
    }

    pub(super) fn run<'role, T>(
        mut self,
        stage: &mut EnrolledRoleStage<'role>,
        operation: impl FnOnce(&mut dyn CurrentServingPhase, &mut EnrolledRoleStage<'role>) -> Result<T>,
    ) -> crate::security_epoch::serving::ScopeOutcome<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check(stage)?;
            operation(
                &mut crate::security_epoch::serving::borrow_current(&mut self),
                stage,
            )
        }));
        self.finish_result(stage, result)
    }

    pub(super) async fn run_async<'role, T>(
        mut self,
        stage: &mut EnrolledRoleStage<'role>,
        operation: impl AsyncFnOnce(
            &mut dyn CurrentServingPhase,
            &mut EnrolledRoleStage<'role>,
        ) -> Result<T>,
    ) -> crate::security_epoch::serving::ScopeOutcome<T> {
        use futures_util::FutureExt;
        let result = std::panic::AssertUnwindSafe(async {
            self.check(stage)?;
            operation(
                &mut crate::security_epoch::serving::borrow_current(&mut self),
                stage,
            )
            .await
        })
        .catch_unwind()
        .await;
        self.finish_result(stage, result)
    }

    fn finish_result<T>(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
        result: std::thread::Result<Result<T>>,
    ) -> crate::security_epoch::serving::ScopeOutcome<T> {
        match result {
            Ok(Ok(value)) if self.disposition == ServingDisposition::Known => {
                let evidence = self.evidence.clone();
                match self.finish_scope(stage) {
                    Ok(()) => crate::security_epoch::serving::ScopeOutcome::Known(value),
                    Err(error) => {
                        evidence.record(
                            crate::security_epoch::serving::ConsumerScopeResult::FinalScopeRefused,
                        );
                        crate::security_epoch::serving::ScopeOutcome::Refused(error)
                    }
                }
            }
            Ok(Err(error)) if self.disposition == ServingDisposition::Excluded => {
                let evidence = self.evidence.clone();
                match self.finish_scope(stage) {
                    Ok(()) => crate::security_epoch::serving::ScopeOutcome::Excluded(error),
                    Err(cause) => {
                        evidence.record(
                            crate::security_epoch::serving::ConsumerScopeResult::FinalScopeRefused,
                        );
                        crate::security_epoch::serving::ScopeOutcome::Refused(error.context(cause))
                    }
                }
            }
            Ok(Err(error)) => {
                self.refuse();
                self.evidence
                    .record(crate::security_epoch::serving::ConsumerScopeResult::OperationRefused);
                crate::security_epoch::serving::ScopeOutcome::Refused(error)
            }
            Ok(Ok(_)) => {
                self.refuse();
                self.evidence
                    .record(crate::security_epoch::serving::ConsumerScopeResult::Unsettled);
                crate::security_epoch::serving::ScopeOutcome::Refused(anyhow::anyhow!(
                    "native_serving_result_not_settled"
                ))
            }
            Err(payload) => {
                self.refuse();
                self.evidence
                    .record(crate::security_epoch::serving::ConsumerScopeResult::Panicked);
                std::panic::resume_unwind(payload)
            }
        }
    }
}

#[cfg(test)]
mod lineage_source_tests {
    use quote::ToTokens;
    use syn::visit::Visit;

    fn actual(owner: &str, name: &str) -> syn::ImplItemFn {
        syn::parse_file(include_str!("app_serving.rs")).unwrap().items.into_iter().find_map(|item| {
            let syn::Item::Impl(item)=item else {return None;};
            if !matches!(&*item.self_ty,syn::Type::Path(p) if p.path.segments.last().is_some_and(|s|s.ident==owner)) { return None; }
            item.items.into_iter().find_map(|item|match item { syn::ImplItem::Fn(item) if item.sig.ident==name=>Some(item), _=>None })
        }).unwrap()
    }

    fn flow(method: &syn::ImplItemFn) -> Vec<String> {
        fn is_self_field(expr: &syn::Expr, name: &str) -> bool {
            matches!(expr,syn::Expr::Field(field) if matches!(&*field.base,syn::Expr::Path(p) if p.path.is_ident("self"))
                && matches!(&field.member,syn::Member::Named(id) if id==name))
        }
        struct Calls(Vec<String>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                let name = call.method.to_string();
                if is_self_field(&call.receiver, "lineage") {
                    self.0.push(format!("lineage_{name}"));
                } else if name == "check"
                    && matches!(&*call.receiver,syn::Expr::Path(p) if p.path.is_ident("self"))
                {
                    self.0.push("local_check".into());
                } else if is_self_field(&call.receiver, "physical")
                    && (name == "check" || name == "finish_checked")
                {
                    self.0.push(format!("physical_{name}"));
                } else if is_self_field(&call.receiver, "reads")
                    && (name == "finish" || name == "read")
                {
                    self.0.push(format!("reads_{name}"));
                } else if name == "check"
                    && matches!(&*call.receiver,syn::Expr::Path(p) if p.path.is_ident("stage"))
                {
                    self.0.push("role_check".into());
                }
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let mut calls = Calls(Vec::new());
        calls.visit_block(&method.block);
        calls.0
    }

    #[test]
    fn actual_app_reobserve_check_and_finish_retain_the_same_typed_lineage() {
        for (name, expected) in [
            (
                "reobserve",
                vec!["local_check", "lineage_read", "local_check"],
            ),
            (
                "check",
                vec!["physical_check", "lineage_check", "physical_check"],
            ),
            (
                "finish_scope",
                vec![
                    "local_check",
                    "lineage_read",
                    "local_check",
                    "lineage_snapshot_data",
                    "physical_finish_checked",
                    "role_check",
                    "reads_finish",
                ],
            ),
        ] {
            let method = actual("CurrentAppServingPhase", name);
            assert_eq!(flow(&method), expected, "{name}");
            let text = method.to_token_stream().to_string();
            let selected = if name == "check" {
                "self . lineage . check"
            } else {
                "self . lineage . read"
            };
            assert_eq!(text.matches(selected).count(), 1, "{name}");
            let changed = text.replacen(selected, "self . lineage . unchecked", 1);
            let changed = syn::parse_str::<syn::ImplItemFn>(&changed).unwrap();
            assert_ne!(flow(&changed), expected, "{name}");
        }
    }

    #[test]
    fn actual_app_scope_borrows_its_original_lineage_without_rebuilding_metadata() {
        fn borrowed(method: &syn::ImplItemFn) -> bool {
            struct Fields(Vec<bool>);
            impl<'ast> Visit<'ast> for Fields {
                fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                    if item
                        .path
                        .segments
                        .last()
                        .is_some_and(|s| s.ident == "CurrentAppServingPhase")
                    {
                        for field in &item.fields {
                            if matches!(&field.member,syn::Member::Named(id) if id=="lineage") {
                                self.0.push(matches!(&field.expr,syn::Expr::Reference(r) if r.mutability.is_none()
                                    && matches!(&*r.expr,syn::Expr::Field(f) if matches!(&f.member,syn::Member::Named(id) if id=="lineage")
                                        && matches!(&*f.base,syn::Expr::Path(p) if p.path.is_ident("self")))));
                            }
                        }
                    }
                    syn::visit::visit_expr_struct(self, item);
                }
            }
            let mut fields = Fields(Vec::new());
            fields.visit_block(&method.block);
            fields.0 == [true]
        }
        let method = actual("ActiveAppStorageContinuity", "begin_serving");
        assert!(borrowed(&method));
        let text = method.to_token_stream().to_string();
        let target = "lineage : & self . lineage";
        assert_eq!(text.matches(target).count(), 1);
        let changed = text.replacen(target, "lineage : & another_lineage", 1);
        assert!(!borrowed(
            &syn::parse_str::<syn::ImplItemFn>(&changed).unwrap()
        ));
    }

    #[test]
    fn actual_current_carries_an_initial_seed_only_for_initial_runtime_birth() {
        fn initial_only(method: &syn::ImplItemFn) -> bool {
            let mut found = None;
            for statement in &method.block.stmts {
                let syn::Stmt::Local(local) = statement else {
                    continue;
                };
                if !matches!(&local.pat,syn::Pat::Ident(id) if id.ident=="image") {
                    continue;
                }
                let Some(initializer) = &local.init else {
                    return false;
                };
                let syn::Expr::Match(selected) = &*initializer.expr else {
                    return false;
                };
                let [initial, existing] = selected.arms.as_slice() else {
                    return false;
                };
                found = Some(
                    selected.expr.to_token_stream().to_string() == "purpose"
                        && initial.pat.to_token_stream().to_string().replace(" ,", "")
                            == "crate :: security_epoch :: serving :: ScopePurpose :: Runtime (crate :: security_epoch :: serving :: RuntimeServingUse :: InitialStorage)"
                        && initial.body.to_token_stream().to_string()
                            == "AppRuntimeImage :: Initial (Box :: new (self . storage . bootstrap_core () ?))"
                        && matches!(&existing.pat, syn::Pat::Wild(_))
                        && existing.body.to_token_stream().to_string()
                            == "AppRuntimeImage :: Existing",
                );
            }
            found == Some(true)
        }
        let method = actual("ActiveAppStorageContinuity", "begin_serving");
        assert!(initial_only(&method));
        let text = method.to_token_stream().to_string();
        for (from, to) in [
            (
                "RuntimeServingUse :: InitialStorage",
                "RuntimeServingUse :: SqlRead",
            ),
            (
                "AppRuntimeImage :: Existing",
                "AppRuntimeImage :: Initial (Box :: new (self.storage.bootstrap_core()?))",
            ),
        ] {
            assert_eq!(text.matches(from).count(), 1);
            let mutant = syn::parse_str::<syn::ImplItemFn>(&text.replacen(from, to, 1)).unwrap();
            assert!(!initial_only(&mutant));
        }
        let admission = actual("CurrentAppServingPhase", "admit_runtime_database");
        let text = admission.to_token_stream().to_string();
        assert!(text.contains("let AppRuntimeImage :: Initial (seed) = & self . image else"));
        assert!(!text.contains("self . seed"));
    }
}
