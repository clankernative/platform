//! Fixed Controller-side active App serving operation. No callback can execute
//! inside the Controller. The signed peer result is released only while the
//! SAME current physical/first-holder and provider observations remain owned.
use super::{
    ActiveControllerStorageContinuity, ServingObservation, check_active_snapshot, request_names,
};
use crate::security_epoch::controller::serving_timing::{ServingStep, ServingTiming};
use crate::security_epoch::self_check_profile::{self, Category};
use crate::security_epoch::{AuthenticatedReads, native_enrollment::EnrolledRoleStage};
use anyhow::{Result, ensure};
use day2_capabilities::security_epoch::bootstrap::NativeRole;

impl ActiveControllerStorageContinuity {
    pub(in crate::security_epoch) fn app_pending(&mut self) -> Result<bool> {
        ensure!(self.valid, "active_controller_storage_refused");
        self.storage.app_pending()
    }

    pub(in crate::security_epoch) fn serve_app_current(
        &mut self,
        stage: EnrolledRoleStage<'_>,
        trace: &ServingTiming,
    ) -> Result<ServingObservation> {
        let _profile = self_check_profile::enter(Category::ServingLocal);
        ensure!(self.valid, "active_controller_storage_refused");
        self.valid = false;
        let result = (|| {
            let (mut physical, mut reads) = trace.measure(ServingStep::PhysicalBegin, || {
                let _profile = self_check_profile::enter(Category::PhysicalLocal);
                self.storage
                    .begin_current_app(stage, &self.policy, &self.store, trace)
            })?;
            // Authenticated request selection is DATA. This can only be the
            // original App enrollment and a fresh current-serving transcript.
            let binding = trace.measure(ServingStep::RequestBinding, || {
                Ok(physical.app_request()?.binding.clone())
            })?;
            let names = trace.measure(ServingStep::Names, || {
                request_names(&self.store, &self.completion)
            })?;
            let mut observed = trace.measure(ServingStep::CounterBefore, || {
                reads.read(physical.controller_stage()?, &self.store, &names)
            })?;
            trace.measure(ServingStep::ValidateBefore, || {
                check_active_snapshot(
                    &self.store,
                    &self.completion,
                    &self.activation,
                    observed.snapshot(),
                )
            })?;
            // The checked stage getter performs the complete physical
            // post-read check once, immediately before observation use.
            trace.measure(ServingStep::ProviderBefore, || {
                reads.check_observation(physical.controller_stage()?, &mut observed)
            })?;
            // Await the actual App consumer and original postchecks, then
            // reobserve the fixed counter through one closed physical join.
            observed =
                physical.announce_and_read_app_consumed(&mut reads, &self.store, &names, trace)?;
            trace.measure(ServingStep::ValidateAfter, || {
                check_active_snapshot(
                    &self.store,
                    &self.completion,
                    &self.activation,
                    observed.snapshot(),
                )
            })?;
            trace.measure(ServingStep::ProviderAfter, || {
                reads.check_observation(physical.controller_stage()?, &mut observed)
            })?;
            // Snapshot commitment is bounded DATA work. The closed finisher
            // performs the full post-validation check before release work.
            let snapshot = trace.measure(ServingStep::Snapshot, || {
                super::super::journal::snapshot_digest(observed.snapshot())
            })?;
            trace.measure(ServingStep::Release, || physical.finish_app_known())?;
            Ok(ServingObservation { binding, snapshot })
        })();
        if result.is_ok() {
            self.valid = true;
        } else {
            self.storage.refuse();
        }
        result
    }
}

impl ActiveControllerStorageContinuity {
    /// The Shell's actual role channel remains borrowed alongside the SAME
    /// physical file/provider scope. Original App liveness is retained here;
    /// it is never interpreted as a fresh App role or Shell database identity.
    pub(in crate::security_epoch) fn serve_shell_current(
        &mut self,
        mut stage: EnrolledRoleStage<'_>,
        peer: &mut crate::security_epoch::native_enrollment::ControllerServingPeer,
    ) -> Result<ServingObservation> {
        ensure!(self.valid, "active_controller_storage_refused");
        self.valid = false;
        let result = (|| {
            let pending = self.storage.begin_pending_current_controller()?;
            let rendezvous = peer.prepare_current(&mut stage)?;
            let mut physical = pending.acquire(stage)?;
            let mut shell = rendezvous.accept_current(physical.controller_stage()?)?;
            let binding = shell.request_binding().clone();
            let mut reads = AuthenticatedReads::acquire(
                &self.policy,
                &self.store,
                NativeRole::EpochController,
                physical.controller_stage()?,
            )?
            .retain_current()?;
            let names = request_names(&self.store, &self.completion)?;
            let mut observed = reads.read(physical.controller_stage()?, &self.store, &names)?;
            check_active_snapshot(
                &self.store,
                &self.completion,
                &self.activation,
                observed.snapshot(),
            )?;
            // The checked stage getter performs the complete physical
            // post-read check once, immediately before observation use.
            reads.check_observation(physical.controller_stage()?, &mut observed)?;
            shell.check(physical.controller_stage()?)?;
            shell.announce_known(physical.controller_stage()?)?;
            shell.await_consumed(physical.controller_stage()?)?;
            observed = reads.read(physical.controller_stage()?, &self.store, &names)?;
            check_active_snapshot(
                &self.store,
                &self.completion,
                &self.activation,
                observed.snapshot(),
            )?;
            reads.check_observation(physical.controller_stage()?, &mut observed)?;
            physical.check()?;
            shell.check(physical.controller_stage()?)?;
            shell.release(physical.controller_stage()?)?;
            shell.finish_checked(physical.controller_stage()?)?;
            let snapshot = super::super::journal::snapshot_digest(observed.snapshot())?;
            physical.finish_controller_known()?;
            Ok(ServingObservation { binding, snapshot })
        })();
        if result.is_ok() {
            self.valid = true;
        } else {
            self.storage.refuse();
            peer.refuse();
        }
        result
    }
}

#[cfg(test)]
mod observation_boundary_tests {
    use syn::visit::Visit;

    // Inspect the actual fixed native callers. A helper fixture cannot catch
    // a repeated full check added at one of these call sites. This supplies
    // no native role, phase or permission and does not replace Linux tests.
    fn native_observation_shape(source: &str, method_name: &str) -> (usize, usize, usize) {
        #[derive(Default)]
        struct Calls {
            standalone_physical_checks: usize,
            observation_checks: usize,
            checked_observation_stages: usize,
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
                if node.method == "check"
                    && matches!(&*node.receiver, syn::Expr::Path(path) if path.path.is_ident("physical"))
                {
                    self.standalone_physical_checks += 1;
                }
                if node.method == "check_observation" {
                    self.observation_checks += 1;
                    self.checked_observation_stages += usize::from(matches!(
                        node.args.first(),
                        Some(syn::Expr::Try(guard)) if matches!(&*guard.expr,
                            syn::Expr::MethodCall(stage) if stage.method == "controller_stage"
                            && matches!(&*stage.receiver, syn::Expr::Path(path) if path.path.is_ident("physical")))
                    ));
                }
                syn::visit::visit_expr_method_call(self, node);
            }
        }
        let file = syn::parse_file(source).unwrap();
        let method = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item)
                    if matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.is_ident("ActiveControllerStorageContinuity")) =>
                {
                    Some(item)
                }
                _ => None,
            })
            .flat_map(|item| &item.items)
            .find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == method_name => Some(method),
                _ => None,
            })
            .expect("actual fixed native serving method");
        let mut calls = Calls::default();
        calls.visit_block(&method.block);
        (
            calls.standalone_physical_checks,
            calls.observation_checks,
            calls.checked_observation_stages,
        )
    }

    #[test]
    fn app_and_shell_observation_consumers_keep_one_full_boundary_check() {
        for method in ["serve_app_current", "serve_shell_current"] {
            // Both observations keep their full checked getter. App's final
            // post-validation check is the closed finisher's entry check;
            // Shell keeps its separate check before its own peer operations.
            assert_eq!(
                native_observation_shape(include_str!("controller_serving.rs"), method),
                (usize::from(method == "serve_shell_current"), 2, 2)
            );
        }
    }

    fn observation_consumer(source: &str, method: &str) -> usize {
        let start = source.find(&format!("fn {method}(")).unwrap();
        // Bound the mutation to THIS actual native method. The App's trace
        // returns the check result directly; Shell uses an ordinary ? call.
        // A missing App match must never fall through into the Shell body.
        let end = start + source[start..].find("\n    }\n").unwrap();
        let consumer = source[start..end]
            .find("reads.check_observation(physical.controller_stage()?, &mut observed)")
            .expect("checked observation consumer inside this native method");
        start + consumer
    }

    #[test]
    fn each_native_caller_rejects_restoring_the_immediate_physical_repeat() {
        let source = include_str!("controller_serving.rs");
        for method in ["serve_app_current", "serve_shell_current"] {
            let consumer = observation_consumer(source, method);
            let mut repeated = source.to_owned();
            repeated.insert_str(consumer, "physical.check()?; ");
            assert_eq!(
                native_observation_shape(&repeated, method),
                (usize::from(method == "serve_shell_current") + 1, 2, 2)
            );
        }
    }

    #[test]
    fn each_observation_still_requires_the_full_checked_stage_getter() {
        let source = include_str!("controller_serving.rs");
        for method in ["serve_app_current", "serve_shell_current"] {
            let consumer = observation_consumer(source, method);
            let checked = "reads.check_observation(physical.controller_stage()?, &mut observed)";
            let mut mutated = source.to_owned();
            mutated.replace_range(
                consumer..consumer + checked.len(),
                "reads.check_observation(unchecked_stage, &mut observed)",
            );
            assert_ne!(
                native_observation_shape(&mutated, method),
                (usize::from(method == "serve_shell_current"), 2, 2)
            );
        }
    }
}
