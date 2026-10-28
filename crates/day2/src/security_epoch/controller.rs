//! Fixed initial-only protocol executor. All native owners remain on THIS OS
//! thread. Idle probes create DATA, never a role lease or action permission.
use crate::artifact::Instance;
use crate::security_epoch::{
    admission_work,
    bootstrap::{self, ControllerActivationOutcome},
    native_enrollment::{
        ControllerServingListener, ControllerServingPeer, EnrolledProcessRoleOwner,
        InitialHolderListener, NativeRole,
    },
    self_check_profile,
    storage_authority::{self, InitialStorageContinuity, InitialStorageOutcome},
};
use anyhow::{Context, Result, ensure};
use std::{
    path::Path,
    time::{Duration, Instant},
};

pub(in crate::security_epoch) mod bootstrap_timing;
pub(in crate::security_epoch) mod evidence;
mod health;
pub(in crate::security_epoch) mod preparation_timing;
pub(in crate::security_epoch) mod serving_timing;
use evidence::{Evidence, FailurePhase, PreparationFailure, PreparationStep, ServingRole};
use preparation_timing::{Operation, Timings};

pub(crate) fn run(instance_path: &Path, app: &str) -> Result<()> {
    run_mode(instance_path, app, false)
}

/// Authentication/provider-metadata diagnosis on an actually enrolled
/// Controller. It cannot reach /state/block descriptors, mount adoption,
/// private-directory/initial-file creation or any provider mutation.
pub(crate) fn observe_preparation(instance_path: &Path, app: &str) -> Result<()> {
    run_mode(instance_path, app, true)
}

fn run_mode(instance_path: &Path, app: &str, read_only: bool) -> Result<()> {
    let mut evidence = Evidence::new();
    let result = run_inner(instance_path, app, &mut evidence, read_only);
    let recorded = match &result {
        Err(error) => evidence.refuse(Some(error)),
        Ok(()) => Ok(()),
    };
    preserve_native_failure(result, recorded)
}

fn preserve_native_failure(result: Result<()>, recorded: Result<()>) -> Result<()> {
    match result {
        Err(error) if recorded.is_err() => Err(error.context("native_evidence_export_failed")),
        Err(error) => Err(error),
        Ok(()) => recorded,
    }
}

fn run_inner(
    instance_path: &Path,
    app: &str,
    evidence: &mut Evidence,
    read_only: bool,
) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "native_controller_platform_unsupported"
    );
    let instance = Instance::load(instance_path)?;
    let policy = instance
        .native_bootstrap_for(app)?
        .context("native_controller_explicit_profile_required")?
        .clone();
    let store = instance
        .control
        .as_ref()
        .context("native_controller_catalog_required")?
        .security_epochs
        .get(&policy.epoch_store.id)
        .context("native_controller_epoch_required")?
        .clone();
    evidence.select(&policy, &store)?;
    // Artifact/instance admission produces desired DATA, not a role, storage
    // owner or prepared image. Do its worker exchanges before creating any
    // native acquisition; the original phase still rechecks this selection.
    evidence.enter(FailurePhase::Preparation);
    let metadata = crate::store::InitialStoreMetadata::load(instance_path, app)
        .and_then(|metadata| {
            metadata.require_native_selection(
                &store,
                &policy.runtime_profile.app_artifact,
                &policy,
            )?;
            Ok(metadata)
        })
        .map_err(|error| PreparationFailure::at(PreparationStep::ImageAdmission, error))?;
    evidence.enter(FailurePhase::Enrollment);
    let mut role = EnrolledProcessRoleOwner::enroll_current_thread(
        &policy.scope,
        NativeRole::EpochController,
    )?;
    evidence.enrolled(role.historical_incarnation_data())?;
    evidence.enter(FailurePhase::Preparation);
    let timings = Timings::new();
    if read_only {
        let trace = bootstrap_timing::BootstrapTiming::provider_read_only();
        let result = trace
            .measure(Operation::RoleStage, || {
                role.begin_storage_metadata_observation_stage()
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::RoleStage, error))
            .and_then(|stage| {
                trace.measure(Operation::VolumeAcquisition, || {
                    storage_authority::observe_preparation_read_only(stage, &policy, &store, &trace)
                })
            });
        // The actual stage/resources have unwound. This record grants nothing;
        // returning here unconditionally excludes every creation/serving path.
        if result.is_err() {
            // The ordinary single refusal exports both timing and the original
            // native boundary, without a preceding potentially partial record.
            evidence.bootstrap_timing(trace.snapshot());
            return result;
        }
        return evidence.preparation_read_only(
            trace
                .snapshot()
                .context("native_provider_control_snapshot_missing")?,
        );
    }
    let result = timings
        .measure(Operation::RoleStage, || role.begin_current_stage())
        .map_err(|error| PreparationFailure::at(PreparationStep::RoleStage, error))
        .and_then(|stage| {
            storage_authority::prepare_controller_initial(
                &metadata, stage, &policy, &store, &timings,
            )
        });
    // Cache only DATA; no logging while the original phase remains live. A
    // later first-holder/refusal record includes completed diagnostic rows.
    evidence.preparation_timings(timings.summary());
    let mut file = result?;
    evidence.enter(FailurePhase::HolderListener);
    let result = timings
        .measure(Operation::HolderRole, || role.begin_current_stage())
        .map_err(|error| PreparationFailure::at(PreparationStep::HolderRoleStage, error))
        .and_then(|stage| {
            timings.measure(Operation::HolderListener, || {
                let phase = file.begin_initial_phase(stage).map_err(|error| {
                    PreparationFailure::at(PreparationStep::HolderFilePhase, error)
                })?;
                InitialHolderListener::bind(phase).map_err(|error| {
                    PreparationFailure::at(PreparationStep::HolderListenerBind, error)
                })
            })
        });
    // The file phase has completed/unwound before the ending measurement.
    // Cache both outcomes without logging or returning a permission here.
    evidence.preparation_timings(timings.summary());
    let mut holder_listener = result?;
    // The actual bind/file phase has completed. This separate, once-only
    // scheduling DATA lets deployment start App without spending an action
    // while it waits. It grants no peer, holder, P3 or serving permission.
    evidence.holder_listener_bound()?;
    while !holder_listener.idle_ready()? {
        // No role/file permission remains live while waiting for Kubernetes
        // startup. Start a fresh same-owner phase only after actual pending DATA.
        std::thread::park_timeout(Duration::from_millis(5));
    }
    evidence.enter(FailurePhase::FirstHolder);
    let stage = timings
        .measure(Operation::FirstRole, || {
            role.begin_initial_first_holder_stage()
        })
        .map_err(|error| PreparationFailure::at(PreparationStep::FirstRole, error));
    evidence.preparation_timings(timings.summary());
    let result = InitialStorageContinuity::establish(file, holder_listener, stage?, &timings);
    // The holder operation has returned; its failed resources have unwound or
    // its actual continuity is retained. Diagnostic DATA grants no permission.
    evidence.preparation_timings(timings.summary());
    let storage = match result {
        InitialStorageOutcome::Established(storage) => *storage,
        InitialStorageOutcome::Refused { file, error } => {
            let _refused_original = file;
            return Err(error);
        }
    };
    evidence.first_holder(&storage.bootstrap_core()?, &storage.first_holder_data()?)?;
    let mut active =
        match bootstrap::activate_controller(storage, &mut role, &policy, &store, evidence) {
            ControllerActivationOutcome::Active(active) => active,
            ControllerActivationOutcome::Refused { storage, error } => {
                let _refused_original = storage;
                return Err(error);
            }
        };
    evidence.enter(FailurePhase::ServingListener);
    let mut listener = ControllerServingListener::bind(&mut role.begin_current_stage()?)?;
    let mut shell: Option<ControllerServingPeer> = None;
    // Health is idle process/lifecycle DATA, not evidence of a current provider
    // observation or serving permission. It owns no native material.
    evidence.enter(FailurePhase::Health);
    let health = health::Health::bind()?;
    let result = (|| -> Result<()> {
        // Dispatch DATA only. The material supplies a fixed BOOTTIME due
        // projection; sampling this timer BEFORE taking it is conservative.
        // Actual owner/original/old-expiry checks authorize every admission.
        let mut counter_readmission_due: Option<Instant> = None;
        loop {
            if counter_readmission_due.is_none() {
                evidence.enter(FailurePhase::CounterReadmission);
                let now = Instant::now();
                if let Some(delay) = active.take_counter_readmission_delay()? {
                    counter_readmission_due = Some(
                        now.checked_add(delay)
                            .context("counter readmission dispatch timer overflow")?,
                    );
                }
            }
            if counter_readmission_due.is_some_and(|due| Instant::now() >= due) {
                evidence.enter(FailurePhase::CounterReadmission);
                match role.begin_idle_credential_admission() {
                    Ok((stage, publication)) => {
                        active.readmit_counter_idle(stage, publication)?;
                        counter_readmission_due = None;
                    }
                    Err(error)
                        if error
                            .downcast_ref::<super::native_enrollment::IdleCredentialBusy>()
                            .is_some() =>
                    {
                        // Actual early owner preflight observed live work. No
                        // new original exists and the same due stays latched.
                        std::thread::park_timeout(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            // Serving still acquires an original only for actual pending
            // work. Maintenance never enters or renews a serving request.
            evidence.enter(FailurePhase::AppPending);
            let admission_before = admission_work::snapshot();
            if active.app_pending()? {
                evidence.enter(FailurePhase::AppServing);
                let trace = serving_timing::ServingTiming::new();
                let (result, profile) = self_check_profile::sample_current(|| {
                    trace
                        .measure(serving_timing::ServingStep::RoleStage, || {
                            let _profile =
                                self_check_profile::enter(self_check_profile::Category::RoleLocal);
                            role.begin_current_stage()
                        })
                        .and_then(|stage| {
                            trace.bind_progress(stage.diagnostic_progress());
                            trace.measure(serving_timing::ServingStep::Operation, || {
                                active.serve_app_current(stage, &trace)
                            })
                        })
                });
                let admission_now = admission_work::snapshot();
                evidence.current_admission_work(ServingRole::App, admission_before, admission_now);
                // Both records contain only historical DATA after all native
                // role/physical/provider borrows have returned or unwound.
                evidence.serving_timing(trace.snapshot(result.as_ref().err()));
                evidence.current_serving_profile(profile);
                let observed = result?;
                evidence.serving(ServingRole::App, observed)?;
            }
            if let Some(peer) = &mut shell {
                evidence.enter(FailurePhase::ShellPending);
                let admission_before = admission_work::snapshot();
                if peer.idle_ready()? {
                    evidence.enter(FailurePhase::ShellServing);
                    let result =
                        (|| active.serve_shell_current(role.begin_current_stage()?, peer))();
                    let admission_now = admission_work::snapshot();
                    evidence.current_admission_work(
                        ServingRole::Shell,
                        admission_before,
                        admission_now,
                    );
                    let observed = result?;
                    evidence.serving(ServingRole::Shell, observed)?;
                }
            } else {
                evidence.enter(FailurePhase::ShellPending);
                if listener.idle_ready()? {
                    evidence.enter(FailurePhase::ShellAccept);
                    shell = Some(listener.accept(&mut role.begin_current_stage()?)?);
                }
            }
            evidence.enter(FailurePhase::Health);
            health.serve_one()?;
            // Dispatch pacing only; no expiry cleanup, permit regrant, retry,
            // hidden provider polling, role refresh or holder change happens
            // here. The explicit pre-expiry idle operation above is separate.
            std::thread::park_timeout(Duration::from_millis(5));
        }
    })();
    active.refuse();
    if let Some(peer) = &mut shell {
        peer.refuse();
    }
    // Failure stops this process. A restarted executor encounters existing
    // original objects and refuses; it cannot adopt or recreate authority.
    result
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    fn current_work_brackets_are_present(source: &str) -> bool {
        use syn::visit::Visit;
        fn name(local: &syn::Local, expected: &str) -> bool {
            matches!(&local.pat,syn::Pat::Ident(id) if id.ident==expected)
        }
        fn snapshot(statement: &syn::Stmt, expected: &str) -> bool {
            let syn::Stmt::Local(local) = statement else {
                return false;
            };
            name(local, expected)
                && matches!(local.init.as_ref().map(|v|&*v.expr),Some(syn::Expr::Call(call))
                if call.args.is_empty() && matches!(&*call.func,syn::Expr::Path(path)
                    if path.path.segments.iter().map(|v|v.ident.to_string()).collect::<Vec<_>>()==["admission_work","snapshot"]))
        }
        #[derive(Default)]
        struct Brackets {
            app: usize,
            shell: usize,
            valid: bool,
        }
        impl<'a> Visit<'a> for Brackets {
            fn visit_block(&mut self, block: &'a syn::Block) {
                for (index, statement) in block.stmts.iter().enumerate() {
                    let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else {
                        continue;
                    };
                    let syn::Expr::Try(attempt) = &*branch.cond else {
                        continue;
                    };
                    let syn::Expr::MethodCall(ready) = &*attempt.expr else {
                        continue;
                    };
                    let syn::Expr::Path(receiver) = &*ready.receiver else {
                        continue;
                    };
                    let role = if ready.method == "app_pending" && receiver.path.is_ident("active")
                    {
                        self.app += 1;
                        "App"
                    } else if ready.method == "idle_ready" && receiver.path.is_ident("peer") {
                        self.shell += 1;
                        "Shell"
                    } else {
                        continue;
                    };
                    if index == 0 || !snapshot(&block.stmts[index - 1], "admission_before") {
                        self.valid = false;
                        continue;
                    }
                    let stmts = &branch.then_branch.stmts;
                    let Some(end) = stmts.iter().position(|s| snapshot(s, "admission_now")) else {
                        self.valid = false;
                        continue;
                    };
                    let before_end = if end > 0 {
                        &stmts[end - 1]
                    } else {
                        self.valid = false;
                        continue;
                    };
                    let syn::Stmt::Local(result) = before_end else {
                        self.valid = false;
                        continue;
                    };
                    let result_name = if role == "App" {
                        matches!(&result.pat,syn::Pat::Tuple(tuple)
                        if matches!(tuple.elems.first(),Some(syn::Pat::Ident(id)) if id.ident=="result"))
                    } else {
                        name(result, "result")
                    };
                    #[derive(Default)]
                    struct Warm {
                        role: usize,
                        app: usize,
                        shell: usize,
                        snapshots: usize,
                        captures: usize,
                        invalid: bool,
                    }
                    impl<'b> Visit<'b> for Warm {
                        fn visit_expr_call(&mut self, call: &'b syn::ExprCall) {
                            match &*call.func {
                                syn::Expr::Path(path) => {
                                    let parts = path
                                        .path
                                        .segments
                                        .iter()
                                        .map(|v| v.ident.to_string())
                                        .collect::<Vec<_>>();
                                    if parts == ["admission_work", "snapshot"] {
                                        self.snapshots += 1;
                                    } else if parts != ["self_check_profile", "sample_current"]
                                        && parts != ["self_check_profile", "enter"]
                                        && parts != ["serving_timing", "ServingTiming", "new"]
                                    {
                                        self.invalid = true;
                                    }
                                }
                                syn::Expr::Paren(paren)
                                    if matches!(&*paren.expr, syn::Expr::Closure(_)) => {}
                                _ => self.invalid = true,
                            }
                            syn::visit::visit_expr_call(self, call);
                        }
                        fn visit_expr_method_call(&mut self, call: &'b syn::ExprMethodCall) {
                            match call.method.to_string().as_str() {
                                "begin_current_stage" => self.role += 1,
                                "serve_app_current" => self.app += 1,
                                "serve_shell_current" => self.shell += 1,
                                "current_admission_work" => self.captures += 1,
                                "measure"
                                | "and_then"
                                | "bind_progress"
                                | "diagnostic_progress"
                                | "enter"
                                | "snapshot"
                                | "serving_timing"
                                | "current_serving_profile"
                                | "serving"
                                | "as_ref"
                                | "err" => {}
                                _ => self.invalid = true,
                            }
                            syn::visit::visit_expr_method_call(self, call);
                        }
                    }
                    let mut warm = Warm::default();
                    if let Some(init) = &result.init {
                        let retained_result = matches!(&*init.expr,syn::Expr::Call(call)
                        if match &*call.func {
                            syn::Expr::Path(path)=>role=="App" && path.path.segments.iter().map(|s|s.ident.to_string()).collect::<Vec<_>>()==["self_check_profile","sample_current"],
                            syn::Expr::Paren(parenthesized)=>role=="Shell" && matches!(&*parenthesized.expr,syn::Expr::Closure(_)),
                            _=>false,
                        });
                        warm.invalid |= !retained_result;
                    } else {
                        warm.invalid = true;
                    }
                    warm.visit_block(&branch.then_branch);
                    let set = matches!(stmts.get(end+1),Some(syn::Stmt::Expr(syn::Expr::MethodCall(call),Some(_)))
                        if call.method=="current_admission_work" && call.args.len()==3
                        && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("evidence"))
                        && matches!(&call.args[0],syn::Expr::Path(path) if path.path.segments.last().unwrap().ident==role)
                        && matches!(&call.args[1],syn::Expr::Path(path) if path.path.is_ident("admission_before"))
                        && matches!(&call.args[2],syn::Expr::Path(path) if path.path.is_ident("admission_now")));
                    let result_propagated_later=stmts.iter().skip(end+2).any(|s|matches!(s,syn::Stmt::Local(local)
                        if matches!(local.init.as_ref().map(|v|&*v.expr),Some(syn::Expr::Try(attempt))
                            if matches!(&*attempt.expr,syn::Expr::Path(path) if path.path.is_ident("result")))));
                    self.valid &= result_name
                        && !warm.invalid
                        && warm.role == 1
                        && warm.snapshots == 1
                        && warm.captures == 1
                        && warm.app == usize::from(role == "App")
                        && warm.shell == usize::from(role == "Shell")
                        && set
                        && result_propagated_later;
                }
                syn::visit::visit_block(self, block);
            }
        }
        let file = syn::parse_file(source).unwrap();
        let mut audit = Brackets {
            valid: true,
            ..Default::default()
        };
        for item in &file.items {
            if let syn::Item::Fn(function) = item
                && function.sig.ident == "run_inner"
            {
                audit.visit_block(&function.block);
            }
        }
        audit.valid && audit.app == 1 && audit.shell == 1
    }

    #[test]
    fn current_work_capture_brackets_role_operation_and_error_on_both_paths() {
        let source = include_str!("controller.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(current_work_brackets_are_present(source));
        for changed in [
            source.replacen("let admission_before = admission_work::snapshot();", "", 1),
            source.replacen("let admission_now = admission_work::snapshot();", "", 1),
            source.replacen(
                "if active.app_pending()? {",
                "if active.app_pending()? { force_full_check();",
                1,
            ),
            source.replacen(
                "let observed = result?;",
                "force_full_check(); let observed = result?;",
                1,
            ),
            source.replacen(
                "evidence.current_admission_work(",
                "foreign.current_admission_work(",
                1,
            ),
            source.replacen(
                "self_check_profile::enter(self_check_profile::Category::RoleLocal);",
                "self_check_profile::enter(self_check_profile::Category::RoleLocal); force_full_check();",
                1,
            ),
            source.replacen(
                "active.serve_app_current(stage, &trace)",
                "{ force_full_check(); active.serve_app_current(stage, &trace) }",
                1,
            ),
            source.replacen(
                "active.serve_shell_current",
                "active.full_check_and_serve_shell_current",
                1,
            ),
            source.replacen(
                "let observed = result?;",
                "let observed = result.unwrap();",
                1,
            ),
        ] {
            assert_ne!(source, changed);
            assert!(syn::parse_file(&changed).is_ok(), "Current mutant must be valid Rust syntax");
            assert!(!current_work_brackets_are_present(&changed));
        }
    }

    #[test]
    fn interrupted_diagnostic_export_retains_original_native_failure_and_stays_terminal() {
        let native = PreparationFailure::at(
            PreparationStep::DiskBinding,
            anyhow::anyhow!("storage_provider_disk_binding"),
        );
        let error =
            preserve_native_failure(Err(native), Err(anyhow::anyhow!("private output failure")))
                .unwrap_err();
        assert!(error.downcast_ref::<PreparationFailure>().is_some());
        assert!(
            error
                .chain()
                .any(|cause| cause.to_string() == "storage_provider_disk_binding")
        );
        assert_eq!(error.to_string(), "native_evidence_export_failed");
        assert!(preserve_native_failure(Ok(()), Err(anyhow::anyhow!("output failed"))).is_err());
    }
}
