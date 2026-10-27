//! Cumulative production-work DATA, independent of timed/capped detail records.
//! This process-wide ledger holds no native resource, permission or clock. Every
//! update releases its lock before native work. Poison, loss, overflow, missing
//! leaf coverage and unfinished work are UNKNOWN, never evidence of zero work.

use serde::Serialize;
use std::sync::{
    Mutex, TryLockError,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
pub(super) enum Work {
    ExecutableSha256,
    IssuerClientExchange,
    IssuerServiceAdmission,
    /// One full physical-profile invocation, including an incomplete refusal.
    PhysicalAdmission,
    /// Each actual PVC/PV/Node/Disk/Instance provider request, not a round.
    PhysicalProfile,
    /// The actual metadata-token GET, not a fresh epoch read.
    MetadataAdmission,
    /// The actual Kubernetes TokenReview POST.
    TokenReview,
    /// Actual project/cluster/KSA/Pod/ReplicaSet/workload/GSA/database reads.
    WorkloadAdmission,
    /// Actual IAM mint/tokeninfo requests, distinct from epoch counter RPCs.
    CredentialAdmission,
}

const WORK: [Work; 9] = [
    Work::ExecutableSha256,
    Work::IssuerClientExchange,
    Work::IssuerServiceAdmission,
    Work::PhysicalAdmission,
    Work::PhysicalProfile,
    Work::MetadataAdmission,
    Work::TokenReview,
    Work::WorkloadAdmission,
    Work::CredentialAdmission,
];

// This source union contains all nine actual enrollment/storage leaves and
// their production wiring guards. Numeric ledger completeness is evidence
// metadata, never a native producer/owner join, runtime switch or permission.
const COVERED: [bool; 9] = [true; 9];

#[derive(Clone, Copy)]
#[repr(usize)]
pub(super) enum Bytes {
    ShaRead,
    RequestBody,
    ResponseBody,
}

#[derive(Clone, Copy)]
struct Counts {
    attempted: Option<u64>,
    returned: Option<u64>,
    succeeded: Option<u64>,
    abandoned: Option<u64>,
    in_flight: Option<u64>,
    bytes: [Option<u64>; 3],
}

impl Counts {
    const ZERO: Self = Self {
        attempted: Some(0),
        returned: Some(0),
        succeeded: Some(0),
        abandoned: Some(0),
        in_flight: Some(0),
        bytes: [Some(0); 3],
    };

    fn known(&self) -> bool {
        [
            self.attempted,
            self.returned,
            self.succeeded,
            self.abandoned,
            self.in_flight,
        ]
        .into_iter()
        .chain(self.bytes)
        .all(|value| value.is_some())
    }
}

struct Ledger {
    rows: [Counts; 9],
    sequence: Option<u64>,
    loss: bool,
}

impl Ledger {
    const ZERO: Self = Self {
        rows: [Counts::ZERO; 9],
        sequence: Some(0),
        loss: false,
    };

    fn start(&mut self, work: Work) {
        let row = &mut self.rows[work as usize];
        row.attempted = row.attempted.and_then(|n| n.checked_add(1));
        row.in_flight = row.in_flight.and_then(|n| n.checked_add(1));
    }

    fn bytes(&mut self, work: Work, kind: Bytes, actual: u64) {
        let bytes = &mut self.rows[work as usize].bytes[kind as usize];
        *bytes = bytes.and_then(|n| n.checked_add(actual));
    }

    fn end(&mut self, work: Work, returned: Option<bool>) {
        let row = &mut self.rows[work as usize];
        row.in_flight = row.in_flight.and_then(|n| n.checked_sub(1));
        match returned {
            Some(success) => {
                row.returned = row.returned.and_then(|n| n.checked_add(1));
                if success {
                    row.succeeded = row.succeeded.and_then(|n| n.checked_add(1));
                }
            }
            None => {
                row.abandoned = row.abandoned.and_then(|n| n.checked_add(1));
                self.loss = true;
            }
        }
    }

    fn snapshot(&mut self) -> Snapshot {
        self.sequence = self.sequence.and_then(|n| n.checked_add(1));
        let overflowed = self.sequence.is_none() || self.rows.iter().any(|row| !row.known());
        let in_flight = self.rows.iter().any(|row| row.in_flight != Some(0));
        Snapshot {
            format: "native_admission_work_v1",
            sequence: self.sequence,
            complete: !overflowed && !in_flight && !self.loss && COVERED.into_iter().all(|v| v),
            overflowed: Some(overflowed),
            in_flight: Some(in_flight),
            loss: self.loss,
            poisoned: false,
            rows: std::array::from_fn(|index| {
                let row = &self.rows[index];
                let covered = COVERED[index];
                Row {
                    work: WORK[index],
                    covered,
                    attempted: covered.then_some(row.attempted).flatten(),
                    returned: covered.then_some(row.returned).flatten(),
                    succeeded: covered.then_some(row.succeeded).flatten(),
                    abandoned: covered.then_some(row.abandoned).flatten(),
                    in_flight: covered.then_some(row.in_flight).flatten(),
                    sha_bytes_read: covered
                        .then_some(row.bytes[Bytes::ShaRead as usize])
                        .flatten(),
                    request_body_bytes_supplied: covered
                        .then_some(row.bytes[Bytes::RequestBody as usize])
                        .flatten(),
                    response_body_bytes_read: covered
                        .then_some(row.bytes[Bytes::ResponseBody as usize])
                        .flatten(),
                }
            }),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Row {
    work: Work,
    covered: bool,
    attempted: Option<u64>,
    /// All known returns, including errors. This is not known delivery/commit.
    returned: Option<u64>,
    succeeded: Option<u64>,
    abandoned: Option<u64>,
    in_flight: Option<u64>,
    sha_bytes_read: Option<u64>,
    /// Body bytes supplied to the HTTP client, never socket/TLS bytes sent.
    request_body_bytes_supplied: Option<u64>,
    /// Application-body bytes actually read, including partial failed reads.
    response_body_bytes_read: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Snapshot {
    format: &'static str,
    sequence: Option<u64>,
    complete: bool,
    overflowed: Option<bool>,
    in_flight: Option<bool>,
    loss: bool,
    poisoned: bool,
    rows: [Row; 9],
}

static LEDGER: Mutex<Ledger> = Mutex::new(Ledger::ZERO);
static LOST: AtomicBool = AtomicBool::new(false);

/// Owns only a diagnostic attempt label; it cannot grant or refuse native work.
pub(super) struct Attempt {
    work: Work,
    finished: bool,
}

pub(super) fn begin(work: Work) -> Attempt {
    if let Ok(mut ledger) = LEDGER.try_lock() {
        ledger.start(work);
    } else {
        LOST.store(true, Ordering::Relaxed);
    }
    Attempt {
        work,
        finished: false,
    }
}

impl Attempt {
    pub(super) fn bytes(&mut self, kind: Bytes, actual: u64) {
        if let Ok(mut ledger) = LEDGER.try_lock() {
            if self.finished {
                ledger.loss = true;
            } else {
                ledger.bytes(self.work, kind, actual);
            }
        } else {
            LOST.store(true, Ordering::Relaxed);
        }
    }

    pub(super) fn finish(&mut self, success: bool) {
        if let Ok(mut ledger) = LEDGER.try_lock() {
            if self.finished {
                ledger.loss = true;
            } else {
                ledger.end(self.work, Some(success));
            }
        } else {
            LOST.store(true, Ordering::Relaxed);
        }
        self.finished = true;
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(mut ledger) = LEDGER.try_lock() {
                ledger.end(self.work, None);
            } else {
                LOST.store(true, Ordering::Relaxed);
            }
        }
    }
}

/// No resets, scope disabling or detailed-record cap. The caller must bind
/// this historical DATA to its actual producer/owner and request boundaries.
pub(super) fn snapshot() -> Snapshot {
    snapshot_ledger(&LEDGER, &LOST)
}

fn snapshot_ledger(ledger: &Mutex<Ledger>, lost: &AtomicBool) -> Snapshot {
    let unknown = |poisoned| {
        let mut empty = Ledger::ZERO;
        let mut unavailable = empty.snapshot();
        unavailable.sequence = None;
        unavailable.complete = false;
        unavailable.overflowed = None;
        unavailable.in_flight = None;
        unavailable.poisoned = poisoned;
        unavailable.loss = true;
        for row in &mut unavailable.rows {
            row.attempted = None;
            row.returned = None;
            row.succeeded = None;
            row.abandoned = None;
            row.in_flight = None;
            row.sha_bytes_read = None;
            row.request_body_bytes_supplied = None;
            row.response_body_bytes_read = None;
        }
        unavailable
    };
    match ledger.try_lock() {
        Ok(mut ledger) => {
            if lost.load(Ordering::Relaxed) {
                unknown(false)
            } else {
                ledger.snapshot()
            }
        }
        Err(error) => {
            lost.store(true, Ordering::Relaxed);
            unknown(matches!(error, TryLockError::Poisoned(_)))
        }
    }
}

impl Snapshot {
    #[cfg(test)]
    pub(super) fn maximal_fixture() -> Self {
        let mut empty = Ledger::ZERO;
        let mut data = empty.snapshot();
        data.sequence = Some(u64::MAX);
        for row in &mut data.rows {
            row.covered = true;
            row.attempted = Some(u64::MAX);
            row.returned = Some(u64::MAX);
            row.succeeded = Some(u64::MAX);
            row.abandoned = Some(u64::MAX);
            row.in_flight = Some(u64::MAX);
            row.sha_bytes_read = Some(u64::MAX);
            row.request_body_bytes_supplied = Some(u64::MAX);
            row.response_body_bytes_read = Some(u64::MAX);
        }
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_global_updates_and_paused_writer_run_in_an_isolated_process() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "security_epoch::admission_work::tests::production_global_ledger_child",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated production ledger control failed"
        );
    }

    #[test]
    #[ignore = "isolated process-wide DATA ledger control, invoked by its parent test"]
    fn production_global_ledger_child() {
        let before = snapshot();
        assert_eq!(before.rows[0].attempted, Some(0));
        let mut hash = begin(Work::ExecutableSha256);
        hash.bytes(Bytes::ShaRead, 13);
        hash.bytes(Bytes::ShaRead, 7);
        hash.finish(false);
        for _ in 0..40 {
            let mut request = begin(Work::IssuerClientExchange);
            request.finish(true);
        }
        let after = snapshot();
        assert_eq!(after.rows[0].attempted, Some(1));
        assert_eq!(after.rows[0].returned, Some(1));
        assert_eq!(after.rows[0].succeeded, Some(0));
        assert_eq!(after.rows[0].sha_bytes_read, Some(20));
        assert_eq!(after.rows[1].attempted, Some(40));
        assert_eq!(after.rows[1].returned, Some(40));
        assert!(!after.loss && !after.poisoned);
        assert_eq!(after.in_flight, Some(false));
        assert!(after.sequence > before.sequence);

        let held = LEDGER.lock().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let producer = std::thread::spawn(move || {
            let mut attempt = begin(Work::IssuerServiceAdmission);
            attempt.finish(false);
            send.send(()).unwrap();
        });
        let nonblocking = receive
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok();
        // Always release/join before asserting: a blocking regression fails
        // boundedly instead of leaving the test child or its worker hanging.
        drop(held);
        producer.join().unwrap();
        assert!(
            nonblocking,
            "production diagnostic update blocked behind a writer"
        );
        let lost = snapshot();
        assert!(lost.loss && !lost.complete);
        assert!(lost.rows.iter().all(|row| row.attempted.is_none()));
        assert!(snapshot().rows.iter().all(|row| row.returned.is_none()));
    }

    fn path(expression: &syn::Expr, expected: &[&str]) -> bool {
        matches!(expression, syn::Expr::Path(path)
            if path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>() == expected)
    }

    fn begin_shape(statement: &syn::Stmt, kind: &str) -> bool {
        let syn::Stmt::Local(local) = statement else {
            return false;
        };
        if !matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "work" && name.mutability.is_some())
        {
            return false;
        }
        let Some(initializer) = &local.init else {
            return false;
        };
        let syn::Expr::Call(call) = &*initializer.expr else {
            return false;
        };
        path(
            &call.func,
            &["crate", "security_epoch", "admission_work", "begin"],
        ) && call.args.len() == 1
            && path(
                &call.args[0],
                &["crate", "security_epoch", "admission_work", "Work", kind],
            )
    }

    fn returned_shape(statement: &syn::Stmt, name: &str) -> bool {
        let syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_)) = statement else {
            return false;
        };
        call.method == "finish"
            && path(&call.receiver, &["work"])
            && call.args.len() == 1
            && matches!(&call.args[0], syn::Expr::MethodCall(result)
                if result.method == "is_ok" && path(&result.receiver, &[name]) && result.args.is_empty())
    }

    fn result_wiring(source: &str, name: &str, kind: &str) -> bool {
        let syntax = syn::parse_file(source).unwrap();
        let Some(body) = syntax.items.iter().find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(&function.block),
            _ => None,
        }) else {
            return false;
        };
        body.stmts.len() >= 4
            && begin_shape(&body.stmts[0], kind)
            && returned_shape(&body.stmts[body.stmts.len()-2], "result")
            && matches!(body.stmts.last(), Some(syn::Stmt::Expr(expression, None)) if path(expression, &["result"]))
            && body.stmts.iter().filter(|statement| matches!(statement,
                syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "result")
                && local.init.is_some())).count() == 1
    }

    fn hash_bytes_wiring(source: &str) -> bool {
        let syntax = syn::parse_file(source).unwrap();
        let Some(hash) = syntax.items.iter().find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "hash" => Some(function),
            _ => None,
        }) else {
            return false;
        };
        hash_bytes_in_body(
            &hash.block,
            "file",
            &[
                "crate",
                "security_epoch",
                "admission_work",
                "Bytes",
                "ShaRead",
            ],
        )
    }

    fn hash_bytes_in_body(body: &syn::Block, file: &str, byte_kind: &[&str]) -> bool {
        use syn::visit::Visit;
        struct Loops(Vec<syn::Block>);
        impl<'ast> Visit<'ast> for Loops {
            fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
                self.0.push(expression.body.clone());
                syn::visit::visit_expr_loop(self, expression);
            }
        }
        let mut loops = Loops(Vec::new());
        loops.visit_block(body);
        let [body] = loops.0.as_slice() else {
            return false;
        };
        let Some(syn::Stmt::Local(read)) = body.stmts.get(1) else {
            return false;
        };
        if !matches!(&read.pat, syn::Pat::Ident(name) if name.ident == "count") {
            return false;
        }
        let Some(initializer) = &read.init else {
            return false;
        };
        let syn::Expr::Try(attempt) = &*initializer.expr else {
            return false;
        };
        if !matches!(&*attempt.expr, syn::Expr::MethodCall(read)
            if read.method == "read" && path(&read.receiver, &[file]) && read.args.len() == 1
            && matches!(&read.args[0], syn::Expr::Reference(buffer)
                if buffer.mutability.is_some() && path(&buffer.expr, &["buffer"])))
        {
            return false;
        }
        let Some(syn::Stmt::Expr(syn::Expr::MethodCall(charge), Some(_))) = body.stmts.get(2)
        else {
            return false;
        };
        charge.method == "bytes"
            && path(&charge.receiver, &["work"])
            && charge.args.len() == 2
            && path(&charge.args[0], byte_kind)
            && matches!(&charge.args[1], syn::Expr::Cast(count)
                if path(&count.expr, &["count"])
                && matches!(&*count.ty, syn::Type::Path(ty) if ty.path.is_ident("u64")))
    }

    fn service_wiring(source: &str) -> bool {
        let syntax = syn::parse_file(source).unwrap();
        let Some(run) = syntax.items.iter().find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "run" => Some(function),
            _ => None,
        }) else {
            return false;
        };
        let Some(syn::Stmt::Expr(syn::Expr::Loop(body), _)) = run.block.stmts.last() else {
            return false;
        };
        let statements = &body.body.stmts;
        if !statements
            .get(1)
            .is_some_and(|statement| begin_shape(statement, "IssuerServiceAdmission"))
        {
            return false;
        }
        let Some(syn::Stmt::Expr(syn::Expr::If(failed), _)) = statements.get(4) else {
            return false;
        };
        let Some(syn::Stmt::Expr(syn::Expr::MethodCall(finish), Some(_))) =
            failed.then_branch.stmts.first()
        else {
            return false;
        };
        if finish.method != "finish"
            || !path(&finish.receiver, &["work"])
            || !matches!(finish.args.first(), Some(syn::Expr::Lit(literal)) if matches!(&literal.lit, syn::Lit::Bool(value) if !value.value))
        {
            return false;
        }
        statements.windows(2).any(|pair| {
            let syn::Stmt::Expr(syn::Expr::MethodCall(finish), Some(_)) = &pair[0] else { return false; };
            let Some(syn::Expr::Binary(success)) = finish.args.first() else { return false; };
            let result = |expression: &syn::Expr, name: &str| matches!(expression,
                syn::Expr::MethodCall(result) if result.method == "is_ok" && path(&result.receiver, &[name]) && result.args.is_empty());
            finish.method == "finish" && path(&finish.receiver, &["work"]) && finish.args.len() == 1
                && matches!(success.op, syn::BinOp::And(_))
                && result(&success.left, "served") && result(&success.right, "checked")
                && matches!(&pair[1], syn::Stmt::Local(local)
                    if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "exported"))
        })
    }

    fn self_hash_wiring(source: &str) -> bool {
        let syntax = syn::parse_file(source).unwrap();
        let Some(acquire) = syntax.items.iter().find_map(|item| {
            let syn::Item::Impl(implementation) = item else { return None; };
            if implementation.trait_.is_some()
                || !matches!(&*implementation.self_ty, syn::Type::Path(ty) if ty.path.is_ident("NativeProcessObservation")) { return None; }
            implementation.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident == "acquire" => Some(function),
                _ => None,
            })
        }) else { return false; };
        let Some(syn::Stmt::Local(local)) = acquire.block.stmts.first() else {
            return false;
        };
        let Some(initializer) = &local.init else {
            return false;
        };
        let syn::Expr::Call(call) = &*initializer.expr else {
            return false;
        };
        let syn::Expr::Paren(parenthesized) = &*call.func else {
            return false;
        };
        let syn::Expr::Closure(closure) = &*parenthesized.expr else {
            return false;
        };
        let syn::Expr::Block(body) = &*closure.body else {
            return false;
        };
        let Some(syn::Stmt::Expr(syn::Expr::Block(linux), _)) = body.block.stmts.first() else {
            return false;
        };
        if linux.attrs.len() != 1
            || !matches!(&linux.attrs[0].meta,
            syn::Meta::List(meta) if meta.path.is_ident("cfg") && meta.tokens.to_string() == "target_os = \"linux\"")
        {
            return false;
        }
        linux.block.stmts.windows(4).any(|statements| {
            if !begin_shape(&statements[0], "ExecutableSha256") || !returned_shape(&statements[2], "code") { return false; }
            let syn::Stmt::Local(code) = &statements[1] else { return false; };
            if !matches!(&code.pat, syn::Pat::Type(ty) if matches!(&*ty.pat, syn::Pat::Ident(name) if name.ident == "code")) { return false; }
            let Some(initializer) = &code.init else { return false; };
            let syn::Expr::MethodCall(hash) = &*initializer.expr else { return false; };
            if hash.method != "hash" || !path(&hash.receiver, &["costs"]) || hash.args.len() != 1 { return false; }
            let syn::Expr::Closure(hash) = &hash.args[0] else { return false; };
            let syn::Expr::Block(hash) = &*hash.body else { return false; };
            if !hash_bytes_in_body(&hash.block, "executable", &["crate", "security_epoch", "admission_work", "Bytes", "ShaRead"]) { return false; }
            let syn::Stmt::Local(output) = &statements[3] else { return false; };
            matches!(&output.pat, syn::Pat::Ident(name) if name.ident == "code")
                && output.init.as_ref().is_some_and(|initializer| matches!(&*initializer.expr,
                    syn::Expr::Try(attempt) if path(&attempt.expr, &["code"])))
        })
    }

    #[test]
    fn actual_separate_self_sha_cannot_escape_executable_scan_coverage() {
        let source = include_str!("native_identity.rs");
        assert!(self_hash_wiring(source));
        for (before, after) in [
            ("Work::ExecutableSha256", "Work::PhysicalProfile"),
            ("work.finish(code.is_ok());", "work.finish(true);"),
            (
                "work.finish(code.is_ok());",
                "if false { work.finish(code.is_ok()); }",
            ),
            ("count as u64", "0_u64"),
            ("Bytes::ShaRead", "Bytes::ResponseBody"),
            ("let code = code?;", "let code = unrelated?;"),
            (
                "let count = executable.read(&mut buffer)?;",
                "let count = foreign.read(&mut buffer)?;",
            ),
        ] {
            let changed = source.replacen(before, after, 1);
            assert_ne!(changed, source);
            assert!(!self_hash_wiring(&changed));
        }
    }

    #[test]
    fn actual_hash_bytes_and_issuer_refusals_cannot_skip_the_ledger() {
        let hash = include_str!("native_enrollment/executable_bytes.rs");
        assert!(hash_bytes_wiring(hash));
        for (before, after) in [
            ("count as u64", "0_u64"),
            ("work.bytes(", "unrelated.bytes("),
            ("Bytes::ShaRead", "Bytes::ResponseBody"),
            (
                "let count = file.read(&mut buffer)?;",
                "let count = foreign.read(&mut buffer)?;",
            ),
        ] {
            let changed = hash.replacen(before, after, 1);
            assert_ne!(changed, hash);
            assert!(!hash_bytes_wiring(&changed));
        }
        let service = include_str!("native_enrollment/service.rs");
        assert!(service_wiring(service));
        for (before, after) in [
            ("Work::IssuerServiceAdmission", "Work::PhysicalProfile"),
            ("work.finish(false);", "work.finish(true);"),
            ("work.finish(false);", "if false { work.finish(false); }"),
            (
                "work.finish(served.is_ok() && checked.is_ok());",
                "work.finish(true);",
            ),
            (
                "work.finish(served.is_ok() && checked.is_ok());",
                "if false { work.finish(served.is_ok() && checked.is_ok()); }",
            ),
        ] {
            let changed = service.replacen(before, after, 1);
            assert_ne!(changed, service);
            assert!(!service_wiring(&changed));
        }
    }

    #[test]
    fn actual_hash_and_client_leaves_count_failures_and_return_the_original_result() {
        for (source, name, kind) in [
            (
                include_str!("native_enrollment/executable_bytes.rs"),
                "hash",
                "ExecutableSha256",
            ),
            (
                include_str!("native_enrollment/owner.rs"),
                "exchange",
                "IssuerClientExchange",
            ),
        ] {
            assert!(result_wiring(source, name, kind));
            for (before, after) in [
                (format!("Work::{kind}"), "Work::PhysicalProfile".to_owned()),
                (
                    "let mut work =".to_owned(),
                    "let mut unrelated =".to_owned(),
                ),
                (
                    "work.finish(result.is_ok());".to_owned(),
                    "if false { work.finish(result.is_ok()); }".to_owned(),
                ),
                (
                    "work.finish(result.is_ok());".to_owned(),
                    "work.finish(true);".to_owned(),
                ),
                (
                    "work.finish(result.is_ok());\n    result".to_owned(),
                    "work.finish(result.is_ok());\n    Ok(fixture)".to_owned(),
                ),
            ] {
                let changed = source.replacen(&before, &after, 1);
                assert_ne!(changed, source);
                assert!(!result_wiring(&changed, name, kind));
            }
        }
    }

    #[test]
    fn ledger_counts_failed_partial_work_and_never_resets_at_a_snapshot() {
        let mut ledger = Ledger::ZERO;
        let before = ledger.snapshot();
        ledger.start(Work::ExecutableSha256);
        ledger.bytes(Work::ExecutableSha256, Bytes::ShaRead, 13);
        assert_eq!(ledger.snapshot().in_flight, Some(true));
        ledger.bytes(Work::ExecutableSha256, Bytes::ShaRead, 7);
        ledger.end(Work::ExecutableSha256, Some(false));
        for _ in 0..40 {
            ledger.start(Work::IssuerClientExchange);
            ledger.end(Work::IssuerClientExchange, Some(true));
        }
        let after = ledger.snapshot();
        assert_eq!(before.rows[0].attempted, Some(0));
        assert_eq!(after.rows[0].attempted, Some(1));
        assert_eq!(after.rows[0].returned, Some(1));
        assert_eq!(after.rows[0].succeeded, Some(0));
        assert_eq!(after.rows[0].sha_bytes_read, Some(20));
        assert_eq!(after.rows[1].attempted, Some(40));
        assert_eq!(ledger.snapshot().rows[1].attempted, Some(40));
        assert!(after.complete);
        assert!(after.rows.iter().all(|row| row.covered));
        assert_eq!(after.rows[3].attempted, Some(0));
    }

    #[test]
    fn abandoned_overflowed_and_missing_work_never_look_like_zero() {
        let mut ledger = Ledger::ZERO;
        ledger.start(Work::IssuerServiceAdmission);
        ledger.end(Work::IssuerServiceAdmission, None);
        assert!(ledger.snapshot().loss);
        assert_eq!(ledger.snapshot().rows[2].abandoned, Some(1));
        ledger.rows[0].attempted = Some(u64::MAX);
        ledger.start(Work::ExecutableSha256);
        ledger.rows[0].bytes[0] = Some(u64::MAX);
        ledger.bytes(Work::ExecutableSha256, Bytes::ShaRead, 1);
        let overflowed = ledger.snapshot();
        assert_eq!(overflowed.overflowed, Some(true));
        assert!(!overflowed.complete);
        assert_eq!(overflowed.rows[0].attempted, None);
        assert_eq!(overflowed.rows[0].sha_bytes_read, None);
        assert_eq!(ledger.snapshot().rows[0].attempted, None);
        let json = serde_json::to_value(overflowed).unwrap();
        assert!(json["rows"][0]["attempted"].is_null());
        assert_eq!(json["rows"][3]["attempted"], 0);
    }

    #[test]
    fn poisoned_process_ledger_stays_unknown_without_zero_rows() {
        let ledger = Mutex::new(Ledger::ZERO);
        let lost = AtomicBool::new(false);
        let _ = std::panic::catch_unwind(|| {
            let _held = ledger.lock().unwrap();
            panic!("diagnostic fixture poison");
        });
        for _ in 0..2 {
            let snapshot = snapshot_ledger(&ledger, &lost);
            assert!(snapshot.poisoned && snapshot.loss && !snapshot.complete);
            assert_eq!(snapshot.sequence, None);
            assert_eq!(snapshot.in_flight, None);
            assert_eq!(snapshot.overflowed, None);
            assert!(snapshot.rows.iter().all(|row| row.attempted.is_none()
                && row.returned.is_none()
                && row.sha_bytes_read.is_none()));
        }
    }

    #[test]
    fn concurrent_producers_share_one_cumulative_ledger() {
        let ledger = Mutex::new(Ledger::ZERO);
        let lost = AtomicBool::new(false);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let ledger = &ledger;
                scope.spawn(move || {
                    for _ in 0..40 {
                        let mut held = ledger.lock().unwrap();
                        held.start(Work::ExecutableSha256);
                        held.bytes(Work::ExecutableSha256, Bytes::ShaRead, 3);
                        held.end(Work::ExecutableSha256, Some(true));
                    }
                });
            }
        });
        let snapshot = snapshot_ledger(&ledger, &lost);
        assert_eq!(snapshot.rows[0].attempted, Some(160));
        assert_eq!(snapshot.rows[0].returned, Some(160));
        assert_eq!(snapshot.rows[0].succeeded, Some(160));
        assert_eq!(snapshot.rows[0].sha_bytes_read, Some(480));
        assert_eq!(snapshot.in_flight, Some(false));
        assert!(!snapshot.loss && !snapshot.poisoned);
    }

    #[test]
    fn paused_diagnostic_writer_never_blocks_or_returns_zero_coverage() {
        let ledger = Mutex::new(Ledger::ZERO);
        let lost = AtomicBool::new(false);
        let held = ledger.lock().unwrap();
        let snapshot = snapshot_ledger(&ledger, &lost);
        assert!(snapshot.loss && !snapshot.complete && !snapshot.poisoned);
        assert!(snapshot.rows.iter().all(|row| row.attempted.is_none()));
        drop(held);
        // Releasing the paused writer cannot erase the lost observation.
        let restored = snapshot_ledger(&ledger, &lost);
        assert!(restored.loss && !restored.complete);
        assert!(restored.rows.iter().all(|row| row.returned.is_none()));
    }
}
