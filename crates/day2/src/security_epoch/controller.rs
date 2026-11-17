//! Fixed initial-only protocol executor. All native owners remain on THIS OS
//! thread. Idle probes create DATA, never a role lease or action permission.
use crate::artifact::Instance;
use crate::security_epoch::{
    bootstrap::{self, ControllerActivationOutcome, ProtectedRestoreSession},
    native_enrollment::{
        ControllerServingListener, ControllerServingPeer, EnrolledProcessRoleOwner,
        InitialHolderListener, NativeRole, ProtectedRestoreListener,
    },
    self_check_profile,
    storage_authority::{self, InitialStorageContinuity, InitialStorageOutcome},
};
use anyhow::{Context, Result, ensure};
use std::{path::Path, time::Duration};

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
    // Mandatory fixed setup, only after the read-only early return and before
    // creating the original file. No setup Current survives human idle time.
    // This private activation must ship with the genuine native backend; the
    // genuine backend propagates missing or refused admission, never a fallback.
    let mut protected_listener = ProtectedRestoreListener::bind(&mut role)?;
    let mut protected_session: Option<ProtectedRestoreSession> = None;
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
        loop {
            if protected_session.is_none() {
                protected_session =
                    ProtectedRestoreSession::try_accept(&mut protected_listener, &mut role)?;
            }
            if let Some(session) = &mut protected_session {
                let trace = serving_timing::ServingTiming::new();
                if let Some(prepared) = session.poll(&mut active, &mut role, &metadata, &trace)? {
                    // Consuming tail: the whole actual carrier drives native
                    // output/retirement/new serving. No old loop resumption,
                    // ordinary success reply or part extraction follows it.
                    return prepared.run();
                }
            }
            // Only acquire a role after actual pending work. An idle wait must
            // not renew or silently spend a previously issued five-second stage.
            evidence.enter(FailurePhase::AppPending);
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
                // Both records contain only historical DATA after all native
                // role/physical/provider borrows have returned or unwound.
                evidence.serving_timing(trace.snapshot(result.as_ref().err()));
                evidence.current_serving_profile(profile);
                let observed = result?;
                evidence.serving(ServingRole::App, observed)?;
            }
            if let Some(peer) = &mut shell {
                evidence.enter(FailurePhase::ShellPending);
                if peer.idle_ready()? {
                    evidence.enter(FailurePhase::ShellServing);
                    let observed = active.serve_shell_current(role.begin_current_stage()?, peer)?;
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
            // provider polling, role refresh or holder change happens here.
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

#[cfg(test)]
mod protected_loop_source_tests {
    use quote::ToTokens;
    use syn::visit::Visit;

    fn same(actual: &syn::Expr, expected: &str) -> bool {
        let expected: syn::Expr = syn::parse_str(expected).unwrap();
        match (actual, &expected) {
            (syn::Expr::Try(a), syn::Expr::Try(b)) => {
                same(&a.expr, &b.expr.to_token_stream().to_string())
            }
            (syn::Expr::Call(a), syn::Expr::Call(b)) => {
                a.attrs.is_empty()
                    && b.attrs.is_empty()
                    && same(&a.func, &b.func.to_token_stream().to_string())
                    && a.args.len() == b.args.len()
                    && a.args
                        .iter()
                        .zip(&b.args)
                        .all(|(a, b)| same(a, &b.to_token_stream().to_string()))
            }
            (syn::Expr::MethodCall(a), syn::Expr::MethodCall(b)) => {
                a.attrs.is_empty()
                    && b.attrs.is_empty()
                    && a.method == b.method
                    && a.turbofish.to_token_stream().to_string()
                        == b.turbofish.to_token_stream().to_string()
                    && same(&a.receiver, &b.receiver.to_token_stream().to_string())
                    && a.args.len() == b.args.len()
                    && a.args
                        .iter()
                        .zip(&b.args)
                        .all(|(a, b)| same(a, &b.to_token_stream().to_string()))
            }
            _ => actual.to_token_stream().to_string() == expected.to_token_stream().to_string(),
        }
    }

    fn local<'a>(stmt: &'a syn::Stmt, name: &str) -> Option<&'a syn::Local> {
        let syn::Stmt::Local(local) = stmt else {
            return None;
        };
        if !local.attrs.is_empty() {
            return None;
        }
        let pat = if let syn::Pat::Type(typed) = &local.pat {
            &*typed.pat
        } else {
            &local.pat
        };
        matches!(pat,syn::Pat::Ident(id) if id.ident==name && id.subpat.is_none()).then_some(local)
    }

    #[derive(Default)]
    struct Calls {
        loops: Vec<syn::ExprLoop>,
        binds: usize,
        accepts: usize,
        polls: usize,
        runs: usize,
        prepare: bool,
        session_patterns: usize,
        session_paths: usize,
        session_assigns: usize,
        session_mut_borrows: usize,
        foreign_session_methods: usize,
    }
    impl<'a> Visit<'a> for Calls {
        fn visit_expr_loop(&mut self, e: &'a syn::ExprLoop) {
            self.loops.push(e.clone());
            syn::visit::visit_expr_loop(self, e);
        }
        fn visit_expr_call(&mut self, e: &'a syn::ExprCall) {
            self.binds += usize::from(same(&e.func, "ProtectedRestoreListener::bind"));
            self.accepts += usize::from(same(&e.func, "ProtectedRestoreSession::try_accept"));
            self.prepare |= same(&e.func, "storage_authority::prepare_controller_initial");
            syn::visit::visit_expr_call(self, e);
        }
        fn visit_expr_method_call(&mut self, e: &'a syn::ExprMethodCall) {
            self.polls += usize::from(e.method == "poll");
            self.runs += usize::from(e.method == "run");
            self.foreign_session_methods += usize::from(
                same(&e.receiver, "protected_session")
                    && !(e.method == "is_none" && e.args.is_empty() && e.turbofish.is_none()),
            );
            syn::visit::visit_expr_method_call(self, e);
        }
        fn visit_pat_ident(&mut self, p: &'a syn::PatIdent) {
            self.session_patterns += usize::from(p.ident == "protected_session");
            syn::visit::visit_pat_ident(self, p);
        }
        fn visit_expr_path(&mut self, p: &'a syn::ExprPath) {
            self.session_paths += usize::from(p.path.is_ident("protected_session"));
            syn::visit::visit_expr_path(self, p);
        }
        fn visit_expr_assign(&mut self, e: &'a syn::ExprAssign) {
            self.session_assigns += usize::from(same(&e.left, "protected_session"));
            syn::visit::visit_expr_assign(self, e);
        }
        fn visit_expr_reference(&mut self, e: &'a syn::ExprReference) {
            self.session_mut_borrows +=
                usize::from(e.mutability.is_some() && same(&e.expr, "protected_session"));
            syn::visit::visit_expr_reference(self, e);
        }
    }

    fn consuming_loop(body: &syn::Block) -> Option<&syn::ExprLoop> {
        let candidates = body
            .stmts
            .iter()
            .enumerate()
            .filter_map(|(index, stmt)| {
                let init = local(stmt, "result")?.init.as_ref()?;
                if init.diverge.is_some() {
                    return None;
                }
                let syn::Expr::Call(call) = &*init.expr else {
                    return None;
                };
                if !call.attrs.is_empty() || !call.args.is_empty() {
                    return None;
                }
                let syn::Expr::Paren(paren) = &*call.func else {
                    return None;
                };
                let syn::Expr::Closure(closure) = &*paren.expr else {
                    return None;
                };
                if closure.asyncness.is_some()
                    || closure.capture.is_some()
                    || !closure.inputs.is_empty()
                {
                    return None;
                }
                let syn::Expr::Block(block) = &*closure.body else {
                    return None;
                };
                let [syn::Stmt::Expr(syn::Expr::Loop(loop_body), None)] =
                    block.block.stmts.as_slice()
                else {
                    return None;
                };
                Some((index, loop_body))
            })
            .collect::<Vec<_>>();
        let [(index, loop_body)] = candidates.as_slice() else {
            return None;
        };
        let expected: syn::Block = syn::parse_quote!({
            active.refuse();
            if let Some(peer) = &mut shell {
                peer.refuse();
            }
            result
        });
        let tail = &body.stmts[index + 1..];
        if tail.len() != expected.stmts.len()
            || !tail.iter().zip(&expected.stmts).all(|(actual, expected)| {
                actual.to_token_stream().to_string() == expected.to_token_stream().to_string()
            })
        {
            return None;
        }
        Some(loop_body)
    }

    fn guarded(body: &syn::Block) -> bool {
        let Some(executed_loop) = consuming_loop(body) else {
            return false;
        };
        let Some(bind) = body
            .stmts
            .iter()
            .position(|s| local(s, "protected_listener").is_some())
        else {
            return false;
        };
        let Some(read_only)=body.stmts.iter().position(|s|matches!(s,syn::Stmt::Expr(syn::Expr::If(branch),_) if same(&branch.cond,"read_only") && matches!(branch.then_branch.stmts.last(),Some(syn::Stmt::Expr(syn::Expr::Return(_),_))))) else{return false;};
        let Some(first_file) = body.stmts.iter().position(|s| {
            let mut c = Calls::default();
            c.visit_stmt(s);
            c.prepare
        }) else {
            return false;
        };
        let Some(session) = body
            .stmts
            .iter()
            .position(|s| local(s, "protected_session").is_some())
        else {
            return false;
        };
        let declared = local(&body.stmts[session], "protected_session").unwrap();
        let expected: syn::Stmt =
            syn::parse_quote!(let mut protected_session:Option<ProtectedRestoreSession>=None;);
        if !(bind < session && session < first_file)
            || declared.pat.to_token_stream().to_string()
                != local(&expected, "protected_session")
                    .unwrap()
                    .pat
                    .to_token_stream()
                    .to_string()
            || !declared
                .init
                .as_ref()
                .is_some_and(|i| i.diverge.is_none() && same(&i.expr, "None"))
        {
            return false;
        }
        let Some(init) =
            local(&body.stmts[bind], "protected_listener").and_then(|s| s.init.as_ref())
        else {
            return false;
        };
        if !(read_only < bind
            && bind < first_file
            && init.diverge.is_none()
            && same(&init.expr, "ProtectedRestoreListener::bind(&mut role)?"))
        {
            return false;
        }
        let mut c = Calls::default();
        c.visit_block(body);
        if c.loops.len() != 1
            || c.binds != 1
            || c.accepts != 1
            || c.polls != 1
            || c.runs != 1
            || c.session_patterns != 1
            || c.session_paths != 3
            || c.session_assigns != 1
            || c.session_mut_borrows != 1
            || c.foreign_session_methods != 0
        {
            return false;
        }
        if c.loops[0].to_token_stream().to_string() != executed_loop.to_token_stream().to_string() {
            return false;
        }
        let loop_body = &executed_loop.body;
        let Some(syn::Stmt::Expr(syn::Expr::If(accept), None)) = loop_body.stmts.first() else {
            return false;
        };
        let [syn::Stmt::Expr(syn::Expr::Assign(assign), Some(_))] =
            accept.then_branch.stmts.as_slice()
        else {
            return false;
        };
        if accept.else_branch.is_some()
            || !same(&accept.cond, "protected_session.is_none()")
            || !same(&assign.left, "protected_session")
            || !same(
                &assign.right,
                "ProtectedRestoreSession::try_accept(&mut protected_listener,&mut role)?",
            )
        {
            return false;
        }
        let Some(syn::Stmt::Expr(syn::Expr::If(selected), None)) = loop_body.stmts.get(1) else {
            return false;
        };
        let syn::Expr::Let(selected_let) = &*selected.cond else {
            return false;
        };
        if selected.else_branch.is_some()
            || selected_let.pat.to_token_stream().to_string() != "Some (session)"
            || !same(&selected_let.expr, "&mut protected_session")
        {
            return false;
        }
        let [trace, syn::Stmt::Expr(syn::Expr::If(prepared), None)] =
            selected.then_branch.stmts.as_slice()
        else {
            return false;
        };
        let Some(trace) = local(trace, "trace").and_then(|s| s.init.as_ref()) else {
            return false;
        };
        if !same(&trace.expr, "serving_timing::ServingTiming::new()") {
            return false;
        }
        let syn::Expr::Let(prepared_let) = &*prepared.cond else {
            return false;
        };
        if prepared.else_branch.is_some()
            || prepared_let.pat.to_token_stream().to_string() != "Some (prepared)"
            || !same(
                &prepared_let.expr,
                "session.poll(&mut active,&mut role,&metadata,&trace)?",
            )
        {
            return false;
        }
        let [syn::Stmt::Expr(syn::Expr::Return(returned), Some(_))] =
            prepared.then_branch.stmts.as_slice()
        else {
            return false;
        };
        returned
            .expr
            .as_ref()
            .is_some_and(|e| same(e, "prepared.run()"))
    }

    #[test]
    fn actual_protected_loop_has_mandatory_bind_same_session_and_consuming_tail_without_fallback() {
        let file = syn::parse_file(include_str!("controller.rs")).unwrap();
        let functions = file
            .items
            .iter()
            .filter_map(|i| match i {
                syn::Item::Fn(f) if f.sig.ident == "run_inner" => Some(f),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(functions.len(), 1);
        let body = &functions[0].block;
        assert!(guarded(body));
        let bind = body
            .stmts
            .iter()
            .position(|s| local(s, "protected_listener").is_some())
            .unwrap();
        let mut missing = body.clone();
        missing.stmts.remove(bind);
        assert!(!guarded(&missing));
        let mut foreign = body.clone();
        foreign.stmts[bind] = syn::parse_quote!(let mut protected_listener=ProtectedRestoreListener::bind(&mut foreign_role)?;);
        assert!(!guarded(&foreign));
        let mut swallowed = body.clone();
        swallowed.stmts[bind] = syn::parse_quote!(let mut protected_listener=ProtectedRestoreListener::bind(&mut role).ok(););
        assert!(!guarded(&swallowed));
        let mut early = body.clone();
        let old = early.stmts.remove(bind);
        early.stmts.insert(0, old);
        assert!(!guarded(&early));
        let session = body
            .stmts
            .iter()
            .position(|s| local(s, "protected_session").is_some())
            .unwrap();
        let mut rebound = body.clone();
        rebound.stmts[session] = syn::parse_quote!(let mut protected_session:Option<ProtectedRestoreSession>=Some(other_session););
        assert!(!guarded(&rebound));
        let mut calls = Calls::default();
        calls.visit_block(body);
        let original = &calls.loops[0];
        let old = original.to_token_stream().to_string();
        let text = body.to_token_stream().to_string();
        assert_eq!(text.matches(&old).count(), 1);
        for cut in 0..10 {
            let mut changed = original.clone();
            match cut {
                0 => {
                    changed.body.stmts[0] = syn::parse_quote!(if true {
                        protected_session = ProtectedRestoreSession::try_accept(
                            &mut protected_listener,
                            &mut role,
                        )?;
                    })
                }
                1 => {
                    changed.body.stmts[1] =
                        syn::parse_quote!(if let Some(session) = &mut protected_session {
                            let trace = serving_timing::ServingTiming::new();
                            if let Some(prepared) =
                                session.poll(&mut active, &mut foreign_role, &metadata, &trace)?
                            {
                                return prepared.run();
                            }
                        })
                }
                2 => {
                    changed.body.stmts[1] =
                        syn::parse_quote!(if let Some(session) = &mut protected_session {
                            let trace = serving_timing::ServingTiming::new();
                            if let Some(prepared) =
                                session.poll(&mut active, &mut role, &metadata, &trace)?
                            {
                                return Ok(());
                            }
                        })
                }
                3 => {
                    changed.body.stmts[1] =
                        syn::parse_quote!(if let Some(session) = &mut protected_session {
                            let trace = serving_timing::ServingTiming::new();
                            if let Some(prepared) =
                                session.poll(&mut active, &mut role, &metadata, &trace)?
                            {
                                prepared.run()?;
                            }
                        })
                }
                4 => changed
                    .body
                    .stmts
                    .insert(2, syn::parse_quote!(protected_session=None;)),
                5 => changed
                    .body
                    .stmts
                    .insert(2, syn::parse_quote!(protected_session=Some(other_session);)),
                6 => changed
                    .body
                    .stmts
                    .insert(2, syn::parse_quote!(drop(protected_session.take());)),
                7 => changed.body.stmts.insert(
                    2,
                    syn::parse_quote!(let _=std::mem::take(&mut protected_session);),
                ),
                8 => changed
                    .body
                    .stmts
                    .insert(2, syn::parse_quote!(drop(protected_session);)),
                9 => changed
                    .body
                    .stmts
                    .insert(2, syn::parse_quote!(let mut protected_session=None;)),
                _ => unreachable!(),
            }
            let changed: syn::Block =
                syn::parse_str(&text.replacen(&old, &changed.to_token_stream().to_string(), 1))
                    .unwrap();
            assert!(!guarded(&changed));
        }
    }

    #[test]
    fn actual_consuming_loop_executes_now_and_preserves_final_refusal_and_primary_result() {
        let file = syn::parse_file(include_str!("controller.rs")).unwrap();
        let functions = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == "run_inner" => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(functions.len(), 1);
        let body = &functions[0].block;
        assert!(guarded(body));
        let selected = body.stmts.iter().enumerate().filter_map(|(index, stmt)| {
            let init = local(stmt, "result")?.init.as_ref()?;
            matches!(&*init.expr, syn::Expr::Call(call) if matches!(&*call.func, syn::Expr::Paren(_))).then_some(index)
        }).collect::<Vec<_>>();
        assert_eq!(selected.len(), 1);
        let index = selected[0];
        for cut in 0..7 {
            let mut changed = body.clone();
            match cut {
                0 => {
                    changed.stmts.remove(index + 1);
                }
                1 => changed.stmts[index + 1] = syn::parse_quote!(active.check()?;),
                2 => {
                    changed.stmts[index + 2] = syn::parse_quote!(if let Some(peer) = &mut shell {
                        peer.check()?;
                    })
                }
                3 => changed.stmts[index + 3] = syn::Stmt::Expr(syn::parse_quote!(Ok(())), None),
                4 => changed
                    .stmts
                    .insert(index + 1, syn::parse_quote!(role.begin_current_stage()?;)),
                5 => {
                    let syn::Stmt::Local(local) = &mut changed.stmts[index] else {
                        unreachable!();
                    };
                    let init = local.init.as_mut().unwrap();
                    let syn::Expr::Call(call) = &*init.expr else {
                        unreachable!();
                    };
                    init.expr = call.func.clone();
                }
                6 => {
                    let syn::Stmt::Local(local) = &mut changed.stmts[index] else {
                        unreachable!();
                    };
                    let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr else {
                        unreachable!();
                    };
                    let syn::Expr::Paren(paren) = &mut *call.func else {
                        unreachable!();
                    };
                    let syn::Expr::Closure(closure) = &mut *paren.expr else {
                        unreachable!();
                    };
                    closure.asyncness = Some(Default::default());
                }
                _ => unreachable!(),
            }
            assert!(
                !guarded(&changed),
                "consuming-loop mutation {cut} must refuse"
            );
        }
    }
}
