//! Full selected-byte admission, followed by actual retained-handle checks.
//! A private stamp joins held/current/final-path FDs. It grants no permission
//! and proves no immutable contents; ongoing integrity belongs to the trusted
//! enrolled services/node under the selected connection contract.

use super::issuer_costs::HashCosts;
use crate::security_epoch::native_clock::NativeAcquisition;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn identity(file: &File) -> Result<Stamp> {
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.len() > 0 && m.len() <= 512 * 1024 * 1024,
        "native_enrollment_executable_bound"
    );
    Ok(Stamp {
        device: m.dev(),
        inode: m.ino(),
        length: m.len(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}

pub(super) fn hash(
    file: &mut File,
    acquisition: &mut NativeAcquisition,
    costs: &HashCosts,
) -> Result<Digest> {
    let mut work = crate::security_epoch::admission_work::begin(
        crate::security_epoch::admission_work::Work::ExecutableSha256,
    );
    let _profile = crate::security_epoch::self_check_profile::enter(
        crate::security_epoch::self_check_profile::Category::ExecutableBytes,
    );
    let result = costs.hash(|read_bytes| {
        acquisition.remaining()?;
        let before = identity(file)?;
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buffer = [0_u8; 65_536];
        let mut total = 0_u64;
        loop {
            acquisition.remaining()?;
            let count = file.read(&mut buffer)?;
            work.bytes(
                crate::security_epoch::admission_work::Bytes::ShaRead,
                count as u64,
            );
            if count == 0 {
                break;
            }
            total += count as u64;
            *read_bytes = total;
            ensure!(
                total <= before.length,
                "native_enrollment_executable_changed"
            );
            hasher.update(&buffer[..count]);
        }
        ensure!(
            total == before.length && identity(file)? == before,
            "native_enrollment_executable_changed"
        );
        acquisition.remaining()?;
        format!("sha256:{}", crate::hex(hasher.finish().as_ref())).try_into()
    });
    work.finish(result.is_ok());
    result
}

/// Admit one actual executable by reading all selected bytes, joining EVERY
/// retained descriptor before and after it. Only a genuine new process capture
/// calls this; later checks retain these actual descriptors and their stamp.
pub(super) fn admit(
    held: &[&File],
    current: &mut File,
    selected: &Digest,
    acquisition: &mut NativeAcquisition,
    costs: &HashCosts,
) -> Result<Stamp> {
    let result = (|| {
        acquisition.remaining()?;
        ensure!(
            (1..=5).contains(&held.len()),
            "native_enrollment_executable_owner_bound"
        );
        let before = identity(current)?;
        for file in held {
            ensure!(
                identity(file)? == before,
                "native_enrollment_executable_replaced"
            );
        }
        ensure!(
            hash(current, acquisition, costs)? == *selected,
            "native_enrollment_code_mismatch"
        );
        for file in held.iter().copied().chain([&*current]) {
            ensure!(
                identity(file)? == before,
                "native_enrollment_executable_changed"
            );
        }
        acquisition.remaining()?;
        Ok(before)
    })();
    if result.is_err() {
        acquisition.refuse();
    }
    result
}

/// Join actual held/current/final procfs executable descriptors to their original
/// admitted stamp, without another content read. The caller retains the actual
/// actor and original clock. Metadata is not an immutable content version or a
/// substitute for fresh authority; drift invisible to it is a trusted assumption.
pub(super) fn check_handles(
    held: &[&File],
    current: &File,
    final_path: &File,
    before: &Stamp,
    acquisition: &mut NativeAcquisition,
) -> Result<()> {
    let result = (|| {
        acquisition.remaining()?;
        ensure!(
            (1..=5).contains(&held.len()),
            "native_enrollment_executable_owner_bound"
        );
        for file in held.iter().copied().chain([current, final_path]) {
            ensure!(
                identity(file)? == *before,
                "native_enrollment_executable_changed"
            );
        }
        acquisition.remaining()?;
        Ok(())
    })();
    if result.is_err() {
        acquisition.refuse();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::native_enrollment::issuer_costs::{Outcome, Recorder, Subject};
    use std::{
        fs::{self, FileTimes},
        time::Duration,
    };

    fn acquisition(limit: Duration) -> NativeAcquisition {
        NativeAcquisition::fixture(
            Digest::new(b"byte-check-only"),
            std::process::id(),
            Duration::ZERO,
            limit,
        )
    }

    fn admit(
        held: &File,
        current: &mut File,
        selected: &Digest,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Stamp> {
        super::admit(
            &[held],
            current,
            selected,
            acquisition,
            &HashCosts::disabled(),
        )
    }

    fn check_handles(
        held: &File,
        current: &File,
        final_path: &File,
        before: &Stamp,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        super::check_handles(&[held], current, final_path, before, acquisition)
    }

    #[test]
    fn distinct_admissions_each_read_the_selected_bytes() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        let bytes = vec![23; 65_536 + 17];
        fs::write(&p, &bytes)?;
        let held = (0..5)
            .map(|_| File::open(&p))
            .collect::<std::io::Result<Vec<_>>>()?;
        let held = held.iter().collect::<Vec<_>>();
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        let mut output = Vec::new();
        {
            let mut recorder = Recorder::new(&mut output);
            let costs = recorder.connection();
            let hashes = costs.hashes(Subject::Requester);
            for _ in 0..2 {
                let stamp =
                    super::admit(&held, &mut current, &Digest::new(&bytes), &mut a, &hashes)?;
                assert_eq!(current.stream_position()?, bytes.len() as u64);
                super::check_handles(&held, &current, &File::open(&p)?, &stamp, &mut a)?;
            }
            recorder.emit(&costs, Outcome::Completed)?;
        }
        let output = String::from_utf8(output)?;
        let record: serde_json::Value =
            serde_json::from_str(output.strip_prefix("day2-native-issuer-cost ").unwrap())?;
        let rows = record["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], "hash_requester");
        assert_eq!(rows[0][1][0], 2);
        assert_eq!(rows[0][1][1], 2 * bytes.len());
        Ok(())
    }

    #[test]
    fn admitted_handle_checks_leave_every_executable_cursor_unchanged() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("selected");
        let bytes = vec![23; 65_536 + 17];
        fs::write(&path, &bytes)?;
        let mut held = File::open(&path)?;
        let mut current = File::open(&path)?;
        let mut original = acquisition(Duration::from_secs(5));
        let admitted = admit(&held, &mut current, &Digest::new(&bytes), &mut original)?;
        held.seek(SeekFrom::Start(2))?;
        current.seek(SeekFrom::Start(7))?;
        let mut final_path = File::open(&path)?;
        for _ in 0..2 {
            check_handles(&held, &current, &final_path, &admitted, &mut original)?;
            assert_eq!(held.stream_position()?, 2);
            assert_eq!(current.stream_position()?, 7);
            assert_eq!(final_path.stream_position()?, 0);
        }
        original.remaining()?;
        Ok(())
    }

    fn native_result_body(function: &syn::ImplItemFn) -> Option<&syn::Block> {
        let (_, expression) = native_local(&function.block, "result")?;
        let syn::Expr::Call(call) = expression else {
            return None;
        };
        let syn::Expr::Paren(parenthesized) = &*call.func else {
            return None;
        };
        let syn::Expr::Closure(closure) = &*parenthesized.expr else {
            return None;
        };
        let syn::Expr::Block(body) = &*closure.body else {
            return None;
        };
        Some(&body.block)
    }

    fn native_local<'a>(body: &'a syn::Block, name: &str) -> Option<(usize, &'a syn::Expr)> {
        let mut found = None;
        for (index, statement) in body.stmts.iter().enumerate() {
            if let syn::Stmt::Local(local) = statement
                && matches!(&local.pat, syn::Pat::Ident(binding)
                    if binding.ident == name && binding.mutability.is_none() && binding.by_ref.is_none())
            {
                if found.is_some() {
                    return None;
                }
                found = Some((index, local.init.as_ref()?.expr.as_ref()));
            }
        }
        found
    }

    fn native_path(expression: &syn::Expr, name: &str) -> bool {
        matches!(expression, syn::Expr::Path(path) if path.path.is_ident(name))
    }

    fn native_reference(expression: &syn::Expr, name: &str) -> bool {
        matches!(expression, syn::Expr::Reference(reference)
            if reference.mutability.is_none() && native_path(&reference.expr, name))
    }

    fn native_field(expression: &syn::Expr, owner: &str, field: &str) -> bool {
        matches!(expression, syn::Expr::Field(member)
            if matches!(&member.member, syn::Member::Named(name) if name == field)
            && native_path(&member.base, owner))
    }

    fn native_fallible_call<'a>(
        expression: &'a syn::Expr,
        names: &[&str],
    ) -> Option<&'a syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>> {
        let syn::Expr::Try(attempt) = expression else {
            return None;
        };
        let syn::Expr::Call(call) = &*attempt.expr else {
            return None;
        };
        let syn::Expr::Path(path) = &*call.func else {
            return None;
        };
        (path.path.segments.len() == names.len()
            && path
                .path
                .segments
                .iter()
                .zip(names)
                .all(|(part, name)| part.ident == *name))
        .then_some(&call.args)
    }

    fn native_current_executable(expression: &syn::Expr) -> bool {
        let Some(args) = native_fallible_call(expression, &["executable"]) else {
            return false;
        };
        args.len() == 2
            && native_reference(&args[0], "current")
            && native_path(&args[1], "acquisition")
    }

    fn native_held_executables(expression: &syn::Expr) -> bool {
        let syn::Expr::MethodCall(collect) = expression else {
            return false;
        };
        let syn::Expr::MethodCall(map) = &*collect.receiver else {
            return false;
        };
        let syn::Expr::MethodCall(iter) = &*map.receiver else {
            return false;
        };
        if collect.method != "collect"
            || !collect.args.is_empty()
            || map.method != "map"
            || map.args.len() != 1
            || iter.method != "iter"
            || !iter.args.is_empty()
            || !native_path(&iter.receiver, "processes")
        {
            return false;
        }
        let syn::Expr::Closure(mapper) = &map.args[0] else {
            return false;
        };
        mapper.inputs.len() == 1
            && matches!(&mapper.inputs[0], syn::Pat::Ident(binding) if binding.ident == "owner")
            && matches!(&*mapper.body, syn::Expr::Reference(reference)
                if reference.mutability.is_none() && native_field(&reference.expr, "owner", "executable"))
    }

    fn native_handle_check(statement: &syn::Stmt, final_path: &str) -> bool {
        let syn::Stmt::Expr(expression, Some(_)) = statement else {
            return false;
        };
        let Some(args) = native_fallible_call(expression, &["executable_bytes", "check_handles"])
        else {
            return false;
        };
        args.len() == 5
            && native_reference(&args[0], "held_executables")
            && native_reference(&args[1], "current_executable")
            && native_reference(&args[2], final_path)
            && native_path(&args[3], "executable_stamp")
            && native_path(&args[4], "acquisition")
    }

    fn native_retained_check_flow(function: &syn::ImplItemFn) -> bool {
        use syn::visit::Visit;
        struct EarlyReturn(bool);
        impl<'ast> Visit<'ast> for EarlyReturn {
            fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
                self.0 = true;
            }
        }
        let Some(body) = native_result_body(function) else {
            return false;
        };
        let mut early = EarlyReturn(false);
        early.visit_block(body);
        if early.0 {
            return false;
        }
        let Some((first, expression)) = native_local(body, "first") else {
            return false;
        };
        if !matches!(expression, syn::Expr::Reference(reference)
            if reference.mutability.is_none()
            && matches!(&*reference.expr, syn::Expr::Unary(unary)
                if matches!(unary.op, syn::UnOp::Deref(_))
                && matches!(&*unary.expr, syn::Expr::Index(index)
                    if native_path(&index.expr, "processes")
                    && matches!(&*index.index, syn::Expr::Lit(literal)
                        if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_digits() == "0")))))
        {
            return false;
        }
        let Some((proc, expression)) = native_local(body, "proc") else {
            return false;
        };
        let Some(args) = native_fallible_call(expression, &["ns", "open_root"]) else {
            return false;
        };
        if args.len() != 1 || !native_path(&args[0], "acquisition") {
            return false;
        }
        let Some((process, expression)) = native_local(body, "current") else {
            return false;
        };
        let Some(args) = native_fallible_call(expression, &["open_process"]) else {
            return false;
        };
        if args.len() != 3
            || !native_reference(&args[0], "proc")
            || !matches!(&args[1], syn::Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "process")
                && native_field(&field.base, "first", "data"))
            || !native_path(&args[2], "acquisition")
        {
            return false;
        }
        let Some((current, expression)) = native_local(body, "current_executable") else {
            return false;
        };
        if !native_current_executable(expression) {
            return false;
        }
        let Some((held, expression)) = native_local(body, "held_executables") else {
            return false;
        };
        if !native_held_executables(expression) {
            return false;
        }
        let Some((stamp, expression)) = native_local(body, "executable_stamp") else {
            return false;
        };
        if !matches!(expression, syn::Expr::Reference(reference)
            if reference.mutability.is_none() && native_field(&reference.expr, "first", "executable_stamp"))
        {
            return false;
        }
        let Some((final_path, expression)) = native_local(body, "final_executable") else {
            return false;
        };
        if !native_current_executable(expression) {
            return false;
        }
        let checks = body
            .stmts
            .iter()
            .enumerate()
            .filter_map(|(index, statement)| {
                (native_handle_check(statement, "current_executable")
                    || native_handle_check(statement, "final_executable"))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        checks.len() == 2
            && first < proc
            && proc < process
            && process < current
            && current < held
            && held < stamp
            && stamp < checks[0]
            && checks[0] < final_path
            && final_path < checks[1]
            && native_handle_check(&body.stmts[checks[0]], "current_executable")
            && native_handle_check(&body.stmts[checks[1]], "final_executable")
    }

    fn actual_process_capture_and_check_shape(source: &str) -> bool {
        use syn::visit::Visit;

        #[derive(Default)]
        struct Calls {
            admits: usize,
            handle_checks: usize,
            final_checks: usize,
        }

        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func {
                    let segments = path.path.segments.iter().collect::<Vec<_>>();
                    if segments.len() == 2 && segments[0].ident == "executable_bytes" {
                        self.admits += usize::from(segments[1].ident == "admit");
                        self.handle_checks += usize::from(segments[1].ident == "check_handles");
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }

            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                self.final_checks += usize::from(call.method == "check_identity");
                syn::visit::visit_expr_method_call(self, call);
            }
        }

        let source = syn::parse_file(source).unwrap();
        let mut capture = None;
        let mut check = None;
        let mut retained_flow = false;
        for item in source.items {
            let syn::Item::Impl(implementation) = item else {
                continue;
            };
            if !matches!(&*implementation.self_ty, syn::Type::Path(path) if path.path.is_ident("MessageProcess"))
            {
                continue;
            }
            for item in implementation.items {
                let syn::ImplItem::Fn(function) = item else {
                    continue;
                };
                let mut calls = Calls::default();
                calls.visit_block(&function.block);
                if function.sig.ident == "observe" {
                    assert!(capture.replace(calls).is_none());
                } else if function.sig.ident == "check_same_actor" {
                    retained_flow = native_retained_check_flow(&function);
                    assert!(check.replace(calls).is_none());
                }
            }
        }
        matches!(
            capture,
            Some(Calls {
                admits: 1,
                handle_checks: 0,
                final_checks: 1
            })
        ) && retained_flow
            && matches!(
                check,
                Some(Calls {
                    admits: 0,
                    handle_checks: 2,
                    final_checks: 0
                })
            )
    }

    #[test]
    fn actual_process_capture_admits_once_and_retained_checks_only_join_handles() {
        assert!(actual_process_capture_and_check_shape(include_str!(
            "process.rs"
        )));
    }

    #[test]
    fn actual_process_guard_rejects_skipped_admission_or_restored_full_checks() {
        let source = include_str!("process.rs");
        for (before, after) in [
            (
                "executable_bytes::admit(",
                "executable_bytes::metadata_only(",
            ),
            (
                "executable_bytes::check_handles(",
                "executable_bytes::admit(",
            ),
            (
                "executable_bytes::check_handles(",
                "executable_bytes::metadata_only(",
            ),
            (
                "owner.check_identity(acquisition, costs)?",
                "owner.skip_final_check(acquisition, costs)?",
            ),
        ] {
            let mutated = source.replacen(before, after, 1);
            assert_ne!(mutated, source);
            assert!(!actual_process_capture_and_check_shape(&mutated));
        }
    }

    fn packet_calls(
        source: &str,
        owner: &str,
        method: &str,
    ) -> std::collections::BTreeMap<String, usize> {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Calls(std::collections::BTreeMap<String, usize>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func {
                    let name = path
                        .path
                        .segments
                        .iter()
                        .map(|part| part.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::");
                    *self.0.entry(name).or_default() += 1;
                }
                syn::visit::visit_expr_call(self, call);
            }
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                *self.0.entry(call.method.to_string()).or_default() += 1;
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
                if matches!(&*assignment.left, syn::Expr::Field(field)
                    if matches!(&field.member, syn::Member::Named(name) if name == "pidfd")
                    && matches!(&*field.base, syn::Expr::Path(path) if path.path.is_ident("received")))
                    && matches!(&*assignment.right, syn::Expr::Path(path) if path.path.is_ident("pidfd"))
                {
                    *self
                        .0
                        .entry("retain_actual_packet_pidfd".into())
                        .or_default() += 1;
                }
                syn::visit::visit_expr_assign(self, assignment);
            }
        }
        let source = syn::parse_file(source).unwrap();
        let mut calls = Calls::default();
        for item in source.items {
            if let syn::Item::Impl(implementation) = item
                && matches!(&*implementation.self_ty, syn::Type::Path(path) if path.path.is_ident(owner))
            {
                for item in implementation.items {
                    if let syn::ImplItem::Fn(function) = item
                        && function.sig.ident == method
                    {
                        calls.visit_block(&function.block);
                        return calls.0;
                    }
                }
            }
        }
        calls.0
    }

    fn actual_packet_reborrow_shape(
        channel: &str,
        process: &str,
        storage: &str,
        serving: &str,
    ) -> bool {
        let receive = packet_calls(channel, "Channel", "receive_unprivileged_sender");
        let current = packet_calls(process, "MessageProcess", "receive_admitted");
        let anchor = packet_calls(process, "MessageProcess", "retain_message_anchor");
        let count = |calls: &std::collections::BTreeMap<String, usize>, name: &str| {
            calls.get(name).copied().unwrap_or(0)
        };
        count(&receive, "MessageProcess::receive") == 1
            && count(&receive, "MessageProcess::receive_admitted") == 1
            && count(&receive, "retain_message_anchor") == 1
            && count(&current, "retain_message_anchor") == 1
            && count(&current, "Self::check_same_actor") == 1
            && count(&current, "retain_actual_packet_pidfd") == 1
            && count(&current, "executable_bytes::admit") == 0
            && count(&current, "Self::observe") == 0
            && count(&anchor, "check_identity") == 1
            && count(&anchor, "Self::check_same_actor") == 1
            && count(&anchor, "File::try_clone") == 5
            && count(&anchor, "executable_bytes::admit") == 0
            && [(storage, "receive_storage"), (serving, "receive_serving")]
                .iter()
                .all(|(source, method)| {
                    let calls = packet_calls(source, "Channel", method);
                    count(&calls, "net::recv_pidfd_packet") == 1
                        && count(&calls, "receive_unprivileged_sender") == 1
                        && count(&calls, "MessageProcess::receive") == 0
                })
    }

    #[test]
    fn actual_storage_and_serving_receivers_join_each_packet_to_the_channel_sender() {
        assert!(actual_packet_reborrow_shape(
            include_str!("channel.rs"),
            include_str!("process.rs"),
            include_str!("channel/storage.rs"),
            include_str!("channel/serving.rs")
        ));
    }

    #[test]
    fn packet_guard_rejects_restored_scans_or_lost_actual_pidfd_and_sender_checks() {
        let channel = include_str!("channel.rs");
        let process = include_str!("process.rs");
        let storage = include_str!("channel/storage.rs");
        let serving = include_str!("channel/serving.rs");
        for (before, after) in [
            (
                "MessageProcess::receive_admitted(",
                "MessageProcess::receive(",
            ),
            (
                "MessageProcess::receive(packet,",
                "MessageProcess::skip_capture(packet,",
            ),
        ] {
            let mutated = channel.replacen(before, after, 1);
            assert_ne!(mutated, channel);
            assert!(!actual_packet_reborrow_shape(
                &mutated, process, storage, serving
            ));
        }
        for (before, after) in [
            ("received.pidfd = pidfd;", ""),
            (
                "Self::check_same_actor(&mut [&mut *admitted, &mut received]",
                "Self::skip_sender_join(&mut [&mut *admitted, &mut received]",
            ),
            ("File::try_clone(&self.pidfd)", "self.pidfd.try_clone()"),
            ("File::try_clone(&self.proc)", "self.proc.try_clone()"),
            ("File::try_clone(&self.process)", "self.process.try_clone()"),
            (
                "File::try_clone(&self.executable)",
                "self.executable.try_clone()",
            ),
            ("File::try_clone(file)", "file.try_clone()"),
        ] {
            let mutated = process.replacen(before, after, 1);
            assert_ne!(mutated, process);
            assert!(!actual_packet_reborrow_shape(
                channel, &mutated, storage, serving
            ));
        }
        let mutated = storage.replacen(
            "self.receive_unprivileged_sender(",
            "MessageProcess::receive(",
            1,
        );
        assert_ne!(mutated, storage);
        assert!(!actual_packet_reborrow_shape(
            channel, process, &mutated, serving
        ));
    }

    #[test]
    fn actual_process_guard_rejects_conditional_checks_and_substituted_handle_dataflow() {
        let source = include_str!("process.rs");
        let close = "                acquisition,\n            )?;";
        assert_eq!(source.matches(close).count(), 2);
        let conditional = source
            .replace(
                "executable_bytes::check_handles(",
                "if held_executables.is_empty() { executable_bytes::check_handles(",
            )
            .replace(close, "                acquisition,\n            )?; }");
        assert_eq!(
            conditional
                .matches("executable_bytes::check_handles(")
                .count(),
            2
        );
        assert!(!actual_process_capture_and_check_shape(&conditional));
        for (before, after) in [
            ("&held_executables,", "&[],"),
            ("&final_executable,", "&current_executable,"),
            (
                "let executable_stamp = &first.executable_stamp;",
                "let executable_stamp = &other.executable_stamp;",
            ),
            (
                ".map(|owner| &owner.executable)",
                ".map(|owner| &other.executable)",
            ),
        ] {
            let changed = source.replacen(before, after, 1);
            assert_ne!(changed, source);
            assert!(!actual_process_capture_and_check_shape(&changed));
        }
    }

    #[test]
    fn every_retained_descriptor_must_join_before_and_after_the_read() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        let q = d.path().join("other");
        fs::write(&p, b"selected")?;
        fs::write(&q, b"selected")?;
        let held = (0..5)
            .map(|_| File::open(&p))
            .collect::<std::io::Result<Vec<_>>>()?;
        let other = File::open(&q)?;
        for index in 0..5 {
            let mut current = File::open(&p)?;
            let mut owners = held.iter().collect::<Vec<_>>();
            owners[index] = &other;
            let mut a = acquisition(Duration::from_secs(5));
            assert!(
                super::admit(
                    &owners,
                    &mut current,
                    &Digest::new(b"selected"),
                    &mut a,
                    &HashCosts::disabled(),
                )
                .is_err()
            );
            assert!(a.remaining().is_err());

            let mut a = acquisition(Duration::from_secs(5));
            let stamp = admit(&held[0], &mut current, &Digest::new(b"selected"), &mut a)?;
            assert!(
                super::check_handles(&owners, &current, &File::open(&p)?, &stamp, &mut a).is_err()
            );
            assert!(a.remaining().is_err());
        }
        Ok(())
    }

    #[test]
    fn complete_fresh_bytes_and_all_three_descriptors_must_match() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        let bytes = vec![23; 65_536 + 17];
        fs::write(&p, &bytes)?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        let stamp = admit(&held, &mut current, &Digest::new(&bytes), &mut a)?;
        assert_eq!(current.stream_position()?, bytes.len() as u64);
        check_handles(&held, &current, &File::open(&p)?, &stamp, &mut a)?;
        a.remaining()?;
        Ok(())
    }

    #[test]
    fn identical_bytes_in_a_different_inode_are_not_the_retained_executable() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("held");
        let q = d.path().join("other");
        fs::write(&p, b"selected")?;
        fs::write(&q, b"selected")?;
        let held = File::open(&p)?;
        let mut current = File::open(&q)?;
        let mut a = acquisition(Duration::from_secs(5));
        assert!(admit(&held, &mut current, &Digest::new(b"selected"), &mut a).is_err());
        let mut restored = File::open(&p)?;
        assert!(admit(&held, &mut restored, &Digest::new(b"selected"), &mut a).is_err());
        Ok(())
    }

    #[test]
    fn a_new_admission_rejects_same_length_wrong_bytes() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        fs::write(&p, b"selected")?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        admit(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        fs::write(&p, b"changed!")?;
        assert!(admit(&held, &mut current, &Digest::new(b"selected"), &mut a).is_err());
        Ok(())
    }

    #[test]
    fn distinct_ctime_after_mtime_restore_does_not_settle_the_byte_check() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        fs::write(&p, b"selected")?;
        let modified = fs::metadata(&p)?.modified()?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        let stamp = admit(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        // The assertion is conditional on an OBSERVED distinct stamp, not on
        // every rapid write advancing ctime. Coarse timestamp resolution is
        // allowed; bound fixture preparation without skipping the oracle.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            fs::write(&p, b"changed!")?;
            File::options()
                .write(true)
                .open(&p)?
                .set_times(FileTimes::new().set_modified(modified))?;
            if identity(&current)?.changed != stamp.changed {
                break;
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "fixture requires an observed distinguishable ctime"
            );
            std::thread::yield_now();
        }
        assert_eq!(fs::metadata(&p)?.modified()?, modified);
        assert!(check_handles(&held, &current, &File::open(&p)?, &stamp, &mut a).is_err());
        assert!(a.remaining().is_err());
        Ok(())
    }

    #[test]
    fn final_path_replacement_is_rejected_even_when_earlier_fds_and_bytes_match() -> Result<()> {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir()?;
        let p = d.path().join("exe");
        let q = d.path().join("new");
        let original = d.path().join("original");
        fs::write(&original, b"selected")?;
        fs::write(&q, b"selected")?;
        symlink(&original, &p)?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        let stamp = admit(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        fs::remove_file(&p)?;
        symlink(&q, &p)?;
        assert!(identity(&held)? == stamp && identity(&current)? == stamp);
        assert!(check_handles(&held, &current, &File::open(&p)?, &stamp, &mut a).is_err());
        Ok(())
    }

    #[test]
    fn expired_budget_cannot_finish_an_existing_byte_check() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("selected");
        fs::write(&p, b"selected")?;
        let held = File::open(&p)?;
        let mut current = File::open(&p)?;
        let mut a = acquisition(Duration::from_secs(5));
        let stamp = admit(&held, &mut current, &Digest::new(b"selected"), &mut a)?;
        let mut expired = acquisition(Duration::ZERO);
        assert!(check_handles(&held, &current, &File::open(&p)?, &stamp, &mut expired).is_err());
        assert!(expired.remaining().is_err());
        Ok(())
    }
}
