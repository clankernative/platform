//! Fixed Controller counter transport. It retains the SAME native physical and
//! authenticated peer phase throughout each request; read credentials or parsed
//! policy DATA alone cannot install this port.

use super::{ControllerEpochReads, ReadScope, RetainedEpochReads};
use crate::security_epoch::CurrentStorageBootstrapPhase;
use crate::security_epoch::{
    controller::evidence::FailureBoundary,
    controller::preparation_timing::{Operation, Timings},
    firestore::{Budget, EpochReply, Port, Sample},
    transport::Route,
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{
        EpochStore,
        bootstrap::{InitialBootstrapPolicy, NativeRole},
    },
};
use std::{cell::RefCell, rc::Rc, time::Duration};

pub(crate) struct ControllerPort<'storage, 'role> {
    owner: Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>,
    reads: ControllerEpochReads,
    selection: Digest,
    valid: bool,
    timings: Timings,
}

/// A short-lived borrow only; it cannot outlive or reconstruct the actual
/// owning material and grants no generic adapter API to that owner.
pub(in crate::security_epoch) struct ControllerBorrow<'io, 'storage, 'role> {
    owner: &'io mut ControllerPort<'storage, 'role>,
}

impl<'storage, 'role> ControllerPort<'storage, 'role> {
    pub(in crate::security_epoch) fn borrow(&mut self) -> ControllerBorrow<'_, 'storage, 'role> {
        ControllerBorrow { owner: self }
    }

    pub(in crate::security_epoch) fn acquire(
        owner: Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        reads: ControllerEpochReads,
        timings: Timings,
    ) -> Result<Self> {
        let state = Rc::clone(&reads.state);
        let guard = state.gate.guard()?;
        let result = (|| {
            let mut phase = owner.try_borrow_mut()?;
            // Resolve the actual phase BEFORE borrowing shared material:
            // phase checks themselves reborrow that same provider context.
            timings.measure(Operation::BootstrapWriterPhase, || {
                phase.check_authenticated_reads(&reads)
            })?;
            let stage = phase.controller_stage()?;
            let borrow = state.gate.enter()?;
            let mut material = state.material.try_borrow_mut()?;
            timings.measure(Operation::BootstrapWriterMaterial, || {
                material.check_bootstrap(stage, policy, store)
            })?;
            let selection = material.selection.clone();
            drop(material);
            borrow.complete()?;
            drop(phase);
            let mut port = Self {
                owner: Rc::clone(&owner),
                reads,
                selection,
                valid: true,
                timings: timings.clone(),
            };
            port.sample()?;
            guard.complete()?;
            Ok(port)
        })();
        if result.is_err() {
            state.refuse();
            if let Ok(mut phase) = owner.try_borrow_mut() {
                phase.refuse();
            }
        }
        result
    }

    fn context_budget(
        &mut self,
        owner: &Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>,
        selection: &EpochStore,
        request: &Digest,
    ) -> Result<(Sample, Budget, Duration)> {
        let result = (|| {
            ensure!(
                Rc::ptr_eq(owner, &self.owner),
                "epoch_writer_original_owner_changed"
            );
            ensure!(
                self.selection == Digest::of(selection)?,
                "epoch_writer_selection_changed"
            );
            ensure!(
                self.owner.try_borrow()?.request_digest()? == *request,
                "security_epoch_native_request_changed"
            );
            // One construction boundary, not an effect or transfer. Release
            // every phase/material borrow before this unchanged FULL sample:
            // the full check itself reborrows the same provider/file/peer.
            self.sample()?;
            let guard = self.reads.state.gate.guard()?;
            let phase = self.owner.try_borrow()?;
            phase.check_budget_liveness()?;
            let borrow = self.reads.state.gate.enter()?;
            let mut material = self.reads.state.material.try_borrow_mut()?;
            ensure!(
                self.valid
                    && material.valid
                    && material.scope == ReadScope::StorageBootstrap
                    && material.purpose == NativeRole::EpochController,
                "epoch_bootstrap_read_purpose_changed"
            );
            // Only this actual original purpose-bound acquisition can issue
            // the budget. No scalar deadline or fresh origin selects 30s.
            // All binding hashes/full work and budget derivation precede this
            // ACTUAL clock checkpoint. Retain each original floor/ceiling.
            let result = material.acquisition.bootstrap_context_budget()?;
            drop(material);
            borrow.complete()?;
            drop(phase);
            guard.complete()?;
            Ok(result)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn budget(&mut self) -> Result<Budget> {
        self.sample()?;
        let guard = self.reads.state.gate.enter()?;
        let result = self
            .reads
            .state
            .material
            .try_borrow_mut()?
            .acquisition
            .budget()?;
        guard.complete()?;
        Ok(result)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.valid = false;
        self.reads.refuse();
        if let Ok(mut phase) = self.owner.try_borrow_mut() {
            phase.refuse();
        }
    }
}

impl ControllerPort<'_, '_> {
    /// Pure decoding consumes THIS retained acquisition, not a reconstructed
    /// clock or successful native-check cache. The same local owners and shared
    /// refusal gate stay borrowed; full sample/post/transfer guards are separate.
    fn decoding_sample(&mut self) -> Result<Sample> {
        let result = (|| {
            let guard = self.reads.state.gate.guard()?;
            ensure!(self.valid, "epoch_writer_refused");
            let phase = self.owner.try_borrow()?;
            phase.check_budget_liveness()?;
            let borrow = self.reads.state.gate.enter()?;
            let mut material = self.reads.state.material.try_borrow_mut()?;
            ensure!(
                material.valid
                    && material.scope == ReadScope::StorageBootstrap
                    && material.purpose == NativeRole::EpochController,
                "epoch_bootstrap_read_purpose_changed"
            );
            material.acquisition.require_storage_bootstrap()?;
            let sample = material.acquisition.sample()?;
            drop(material);
            borrow.complete()?;
            drop(phase);
            guard.complete()?;
            Ok(sample)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn sample(&mut self) -> Result<Sample> {
        // Count every full composite observation, not just acquisition's
        // first one. These inclusive timings do not grant or cache authority.
        let timings = self.timings.clone();
        let result = timings.measure(Operation::BootstrapWriterSample, || {
            let guard = self.reads.state.gate.guard()?;
            timings.profile_self_check(|| {
                ensure!(self.valid, "epoch_writer_refused");
                let mut phase = self.owner.try_borrow_mut()?;
                // The closed leaf borrows the SAME provider state and actual
                // owning stage. It returns no stage/material/permission and ends
                // its exclusive material borrow before the full file/peer check.
                phase.check_authentication(&mut self.reads)?;
                phase.check()?;
                drop(phase);
                Ok::<(), anyhow::Error>(())
            })?;
            // Charge ALL full-check work; the leaf's earlier clock cannot be
            // returned as if it had been sampled after those checks.
            let sample = self.decoding_sample()?;
            guard.complete()?;
            Ok(sample)
        });
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Spend the caller's actual budget against this SAME retained original
    /// acquisition after the full transport postguards. No native proof escapes.
    fn remaining_budget(&mut self, budget: &mut Budget) -> Result<Duration> {
        let guard = self.reads.state.gate.enter()?;
        let mut material = self.reads.state.material.try_borrow_mut()?;
        ensure!(
            self.valid
                && material.valid
                && material.scope == ReadScope::StorageBootstrap
                && material.purpose == NativeRole::EpochController,
            "epoch_writer_refused"
        );
        material.acquisition.require_storage_bootstrap()?;
        let remaining = budget.remaining_native(&mut material.acquisition)?;
        drop(material);
        guard.complete()?;
        Ok(remaining)
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        budget: &mut Budget,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        let timings = self.timings.clone();
        let result = timings.measure(Operation::BootstrapWriterExchange, || {
            let guard = self.reads.state.gate.guard()?;
            ensure!(
                self.valid && max_bytes == 65_536 && body.len() <= 65_536,
                "epoch_writer_budget"
            );
            let mut phase = self.owner.try_borrow_mut()?;
            // Keep FULL physical/file/peer admission before the actual effect;
            // the authentication-only leaf is never used in its place.
            let stage = phase
                .controller_stage()
                .map_err(|error| FailureBoundary::WriterPreStage.at(error))?;
            let borrow = self.reads.state.gate.enter()?;
            let mut material = self.reads.state.material.try_borrow_mut()?;
            material
                .sample(stage)
                .map_err(|error| FailureBoundary::WriterPreAuthentication.at(error))?;
            let (route, operation) = writer_route(url)?;
            ensure!(
                material.http.matches(&route, url)?,
                "epoch_writer_recipient_changed"
            );
            let RetainedEpochReads {
                http,
                credential,
                acquisition,
                ..
            } = &mut *material;
            // Keep this fallible evaluation outside the diagnostic closure:
            // failure must exit before both request and post-request sampling.
            let authorization = credential
                .authorization()
                .map_err(|error| FailureBoundary::WriterCredential.at(error))?;
            // The caller may have a shorter context deadline than this live
            // parent. Charge every preguard before selecting the one HTTP
            // timeout, and fail BEFORE the request closure/post-request path.
            let timeout = budget
                .remaining_native(acquisition)
                .map_err(|error| FailureBoundary::WriterTimeout.at(error))?
                .min(Duration::from_secs(5));
            let requested = self
                .timings
                .measure(operation, || {
                    http.request_with_ceiling(
                        route,
                        &authorization,
                        Some(body),
                        acquisition,
                        timeout,
                    )
                })
                .map_err(|error| FailureBoundary::WriterRequest.at(error));
            // Label each Result at its actual failure. The later mandatory
            // postcheck must still run, and cannot relabel the first error.
            let checked = material
                .sample(stage)
                .map_err(|error| FailureBoundary::WriterAuthenticationAfter.at(error));
            // An attempted transport still receives its authentication
            // postcheck, but its first error exits before completing this
            // exclusive use or doing successful-path physical postwork.
            let bytes = requested?;
            checked?;
            drop(material);
            borrow
                .complete()
                .map_err(|error| FailureBoundary::WriterBorrowAfter.at(error))?;
            drop(phase);
            self.owner
                .try_borrow_mut()?
                .check()
                .map_err(|error| FailureBoundary::WriterOwnerAfter.at(error))?;
            self.remaining_budget(budget)
                .map_err(|error| FailureBoundary::WriterBudgetAfter.at(error))?;
            guard
                .complete()
                .map_err(|error| FailureBoundary::WriterGateAfter.at(error))?;
            Ok(EpochReply {
                status: 200,
                body: bytes,
            })
        });
        if result.is_err() {
            self.refuse();
        }
        result
    }
}

impl<'storage, 'role> ControllerBorrow<'_, 'storage, 'role> {
    fn check_context_owner(
        &mut self,
        owner: &Rc<RefCell<CurrentStorageBootstrapPhase<'_, '_>>>,
    ) -> Result<()> {
        // Both retained Rcs stay live. Compare the actual allocations, even
        // when their borrow lifetimes differ; no pointer or stage escapes.
        let result = (|| {
            ensure!(
                std::ptr::addr_eq(Rc::as_ptr(&self.owner.owner), Rc::as_ptr(owner)),
                "epoch_writer_original_owner_changed"
            );
            Ok(())
        })();
        if result.is_err() {
            self.owner.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn context_budget(
        &mut self,
        owner: &Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>,
        selection: &EpochStore,
        request: &Digest,
    ) -> Result<(Sample, Budget, Duration)> {
        self.owner.context_budget(owner, selection, request)
    }

    pub(in crate::security_epoch) fn budget(&mut self) -> Result<Budget> {
        self.owner.budget()
    }
}

impl Port for ControllerBorrow<'_, '_, '_> {
    fn sample(&mut self) -> Result<Sample> {
        self.owner.sample()
    }

    fn sample_for_context(
        &mut self,
        owner: &Rc<RefCell<CurrentStorageBootstrapPhase<'_, '_>>>,
    ) -> Result<Sample> {
        self.check_context_owner(owner)?;
        self.owner.sample()
    }

    fn clock_for_context(
        &mut self,
        owner: &Rc<RefCell<CurrentStorageBootstrapPhase<'_, '_>>>,
    ) -> Result<Sample> {
        self.check_context_owner(owner)?;
        self.owner.decoding_sample()
    }

    fn decoding_sample(&mut self) -> Result<Sample> {
        self.owner.decoding_sample()
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        budget: &mut Budget,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        self.owner.post(url, body, budget, max_bytes)
    }

    fn refuse(&mut self) {
        self.owner.refuse();
    }
}

// Route selection is DATA; NativeHttp additionally requires the exact selected
// project/database URL. This function cannot issue a request or mint a writer.
fn writer_route(url: &str) -> Result<(Route<'static>, Operation)> {
    if url.ends_with("/documents:batchGet") {
        Ok((Route::EpochRead, Operation::BootstrapFirestoreRead))
    } else if url.ends_with("/documents:rollback") {
        Ok((Route::EpochRollback, Operation::BootstrapFirestoreRollback))
    } else if url.ends_with("/documents:commit") {
        Ok((Route::EpochCommit, Operation::BootstrapFirestoreCommit))
    } else {
        anyhow::bail!("epoch_writer_route_refused")
    }
}

#[cfg(test)]
mod tests {
    use super::writer_route;

    fn request_and_postcheck_order(source: &str) -> bool {
        use syn::visit::Visit;
        fn ident(expr: &syn::Expr, name: &str) -> bool {
            matches!(expr,syn::Expr::Path(path) if path.path.is_ident(name))
        }
        fn mapped(expr: &syn::Expr, boundary: &str, method: &str) -> bool {
            let syn::Expr::MethodCall(call) = expr else {
                return false;
            };
            let syn::Expr::MethodCall(actual) = &*call.receiver else {
                return false;
            };
            let actual_call = if method == "sample" {
                ident(&actual.receiver, "material")
                    && actual.args.len() == 1
                    && ident(&actual.args[0], "stage")
            } else {
                actual.args.len() == 2 && ident(&actual.args[0], "operation")
            };
            call.method == "map_err"
                && actual.method == method
                && actual_call
                && call.args.len() == 1
                && matches!(&call.args[0],syn::Expr::Closure(closure)
                    if matches!(&*closure.body,syn::Expr::MethodCall(label)
                        if label.method=="at" && label.args.len()==1 && ident(&label.args[0],"error")
                        && matches!(&*label.receiver,syn::Expr::Path(path)
                            if path.path.segments.iter().map(|v|v.ident.to_string()).collect::<Vec<_>>()
                                ==["FailureBoundary",boundary])))
        }
        #[derive(Default)]
        struct Ordered {
            found: usize,
            valid: bool,
            requests: usize,
        }
        impl<'ast> Visit<'ast> for Ordered {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if call.method == "request_with_ceiling" {
                    self.requests += 1;
                    self.valid &= ident(&call.receiver, "http") && call.args.len() == 5;
                }
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_block(&mut self, body: &'ast syn::Block) {
                let local = |name: &str| {
                    body.stmts.iter().enumerate().find_map(|(i,stmt)|
                    match stmt { syn::Stmt::Local(local)
                        if matches!(&local.pat,syn::Pat::Ident(id) if id.ident==name)=>Some((i,local)),
                        _=>None })
                };
                if let (Some((request, first)), Some((check, second)), Some((bytes, value))) =
                    (local("requested"), local("checked"), local("bytes"))
                {
                    self.found += 1;
                    self.valid &= check == request + 1
                        && bytes == check + 1
                        && first
                            .init
                            .as_ref()
                            .is_some_and(|v| mapped(&v.expr, "WriterRequest", "measure"))
                        && second.init.as_ref().is_some_and(|v| {
                            mapped(&v.expr, "WriterAuthenticationAfter", "sample")
                        })
                        && matches!(value.init.as_ref().map(|v|&*v.expr),
                            Some(syn::Expr::Try(v)) if ident(&v.expr,"requested"))
                        && matches!(body.stmts.get(bytes+1),
                            Some(syn::Stmt::Expr(syn::Expr::Try(v),Some(_)))
                                if ident(&v.expr,"checked"));
                }
                syn::visit::visit_block(self, body);
            }
        }
        let file = syn::parse_file(source).unwrap();
        let mut ordered = Ordered {
            valid: true,
            ..Default::default()
        };
        ordered.visit_file(&file);
        ordered.valid && ordered.found == 1 && ordered.requests == 1
    }

    #[test]
    fn post_failure_labels_preserve_both_evaluations_and_first_request_error() {
        let source = include_str!("writer.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(request_and_postcheck_order(source));
        for changed in [
            source.replacen("let bytes = requested?;", "let bytes = checked?;", 1),
            source.replacen("checked?;", "requested?;", 1),
            source.replacen(
                "FailureBoundary::WriterRequest.at(error)",
                "FailureBoundary::WriterAuthenticationAfter.at(error)",
                1,
            ),
            source.replacen("let checked =", "let checked = return", 1),
            source.replacen("request_with_ceiling(", "unrelated_callback(", 1),
        ] {
            assert_ne!(
                changed, source,
                "mutation must change the actual production path"
            );
            assert!(
                syn::parse_file(&changed).is_ok(),
                "mutant must be valid syntax"
            );
            assert!(!request_and_postcheck_order(&changed));
        }
        use crate::security_epoch::controller::evidence::{
            FailureBoundary, PreparationFailure, PreparationStep,
        };
        for (first_failed, second_failed) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let mut order = Vec::new();
            order.push("request");
            let requested = if first_failed {
                Err(
                    FailureBoundary::HttpClockAfterHeaders.at(anyhow::Error::new(
                        std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
                    )),
                )
            } else {
                Ok(Vec::<u8>::new())
            };
            order.push("authentication_after");
            let checked = if second_failed {
                Err(FailureBoundary::WriterAuthenticationAfter
                    .at(anyhow::Error::new(rustix::io::Errno::INTR)))
            } else {
                Ok(())
            };
            // This exact selection is tied to the production AST above. Both
            // Results exist before propagation; later failure cannot relabel it.
            let selected = (|| {
                let bytes = requested?;
                checked?;
                Ok(bytes)
            })();
            assert_eq!(order, ["request", "authentication_after"]);
            match selected {
                Ok(_) => assert!(!first_failed && !second_failed),
                Err(error) => {
                    let error =
                        PreparationFailure::at(PreparationStep::BootstrapReserveSend, error);
                    let data =
                        serde_json::to_value(error.downcast_ref::<PreparationFailure>().unwrap())
                            .unwrap();
                    assert_eq!(
                        data["failure"]["boundary"],
                        if first_failed {
                            "http_clock_after_headers"
                        } else {
                            "writer_authentication_after"
                        }
                    );
                    if first_failed {
                        assert!(error.downcast_ref::<std::io::Error>().is_some());
                    } else {
                        assert_eq!(
                            error.downcast_ref::<rustix::io::Errno>(),
                            Some(&rustix::io::Errno::INTR)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn counter_routes_are_closed_and_transport_checks_the_selected_recipient() {
        for operation in ["batchGet", "rollback", "commit"] {
            assert!(writer_route(&format!("https://firestore.googleapis.com/v1/projects/p/databases/d/documents:{operation}")).is_ok());
        }
        for url in [
            "https://other/commit",
            "https://firestore.googleapis.com/v1/projects/p/databases/d/documents:commit?x=1",
            "https://firestore.googleapis.com/v1/projects/p/databases/d/documents:delete",
        ] {
            assert!(writer_route(url).is_err());
        }
    }
}
