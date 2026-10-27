//! Private bounded diagnostic DATA for one issuer connection. Measurements are
//! inclusive and perturb the unchanged original deadlines. They grant nothing.
use serde::Serialize;
use std::{cell::RefCell, io::Write, rc::Rc, time::Duration};

const PREFIX: &str = "day2-native-issuer-cost ";
const RECORD_LIMIT: u8 = 16;
const RECORD_BYTES: usize = 8192;
const WORK_PREFIX: &str = "day2-native-issuer-work ";
const WORK_RECORD_BYTES: usize = 12_288;

/// Keep bounded issuer records on the provisioner's private stderr. Startup
/// and listener descriptors remain the birth protocol's separate stdin/stdout.
#[cfg(any(target_os = "linux", test))]
pub(super) fn issuer_stderr() -> std::process::Stdio {
    std::process::Stdio::inherit()
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Operation {
    ParentBefore,
    Serve,
    IssuerSnapshot,
    Hello,
    Bind,
    Runtime,
    ContainerdRpcGroup,
    KubernetesGroup,
    ParentBeforeGrant,
    ParentBeforePublish,
    ParentAfter,
    HashIssuer,
    HashParentBefore,
    HashParentAfter,
    HashRequester,
    HashContainerd,
    IdentityParentBeforeBody,
    IdentityParentAfterBody,
    IdentityRequesterBody,
    IdentityContainerdBody,
}

const OPERATIONS: [Operation; 20] = [
    Operation::ParentBefore,
    Operation::Serve,
    Operation::IssuerSnapshot,
    Operation::Hello,
    Operation::Bind,
    Operation::Runtime,
    Operation::ContainerdRpcGroup,
    Operation::KubernetesGroup,
    Operation::ParentBeforeGrant,
    Operation::ParentBeforePublish,
    Operation::ParentAfter,
    Operation::HashIssuer,
    Operation::HashParentBefore,
    Operation::HashParentAfter,
    Operation::HashRequester,
    Operation::HashContainerd,
    Operation::IdentityParentBeforeBody,
    Operation::IdentityParentAfterBody,
    Operation::IdentityRequesterBody,
    Operation::IdentityContainerdBody,
];

/// [attempts, bytes actually returned by hash reads, inclusive total us, max us].
/// Non-hash bytes and unavailable/rewound/overflowed values are null.
#[derive(Clone, Copy, Serialize, PartialEq, Eq, Debug)]
struct Measurement(Option<u32>, Option<u64>, Option<u32>, Option<u32>);

impl Measurement {
    const EMPTY: Self = Self(Some(0), Some(0), Some(0), Some(0));

    fn add(&mut self, bytes: Option<u64>, elapsed: Option<Duration>) {
        self.0 = self.0.and_then(|n| n.checked_add(1));
        self.1 = self.1.zip(bytes).and_then(|(a, b)| a.checked_add(b));
        let us = elapsed.and_then(|v| v.as_micros().try_into().ok());
        self.2 = self.2.zip(us).and_then(|(a, b)| a.checked_add(b));
        self.3 = self.3.zip(us).map(|(a, b)| a.max(b));
    }
}

#[derive(Clone)]
pub(in crate::security_epoch) struct Costs(Option<Rc<RefCell<[Measurement; 20]>>>);

pub(super) struct Started {
    operation: Operation,
    before: Option<Duration>,
}

fn diagnostic_clock() -> Option<Duration> {
    crate::security_epoch::native_clock::boottime().ok()
}

fn elapsed(before: Option<Duration>, after: Option<Duration>) -> Option<Duration> {
    before.zip(after).and_then(|(a, b)| b.checked_sub(a))
}

impl Costs {
    fn new() -> Self {
        Self(Some(Rc::new(RefCell::new([Measurement::EMPTY; 20]))))
    }

    pub(super) fn disabled() -> Self {
        Self(None)
    }

    pub(super) fn hashes(&self, subject: Subject) -> HashCosts {
        HashCosts {
            costs: self.clone(),
            subject,
        }
    }

    fn start(&self, operation: Operation) -> Option<Started> {
        self.0.as_ref()?;
        Some(Started {
            operation,
            before: diagnostic_clock(),
        })
    }

    fn finish(&self, started: &mut Option<Started>, bytes: Option<u64>) {
        if let Some(started) = started.take() {
            let elapsed = elapsed(started.before, diagnostic_clock());
            self.record(started.operation, bytes, elapsed);
        }
    }

    fn record(&self, operation: Operation, bytes: Option<u64>, elapsed: Option<Duration>) {
        if let Some(values) = &self.0 {
            values.borrow_mut()[operation as usize].add(bytes, elapsed);
        }
    }

    pub(super) fn measure<T>(&self, operation: Operation, call: impl FnOnce() -> T) -> T {
        let mut started = self.start(operation);
        let result = call();
        self.finish(&mut started, None);
        result
    }

    fn rows(&self) -> Vec<(Operation, Measurement)> {
        self.0.as_ref().map_or_else(Vec::new, |values| {
            OPERATIONS
                .iter()
                .copied()
                .zip(*values.borrow())
                .filter(|(_, row)| row.0 != Some(0))
                .collect()
        })
    }
}

#[derive(Clone, Copy)]
pub(in crate::security_epoch) enum Subject {
    Issuer,
    ParentBefore,
    ParentAfter,
    Requester,
    Containerd,
}

/// Explicit measurement input, holding only counters and fixed labels. No
/// process, executable, credential, acquisition or native owner is captured.
pub(in crate::security_epoch) struct HashCosts {
    costs: Costs,
    subject: Subject,
}

impl HashCosts {
    pub(in crate::security_epoch) fn disabled() -> Self {
        Costs::disabled().hashes(Subject::Requester)
    }

    pub(in crate::security_epoch) fn hash<T>(&self, call: impl FnOnce(&mut u64) -> T) -> T {
        let operation = match self.subject {
            Subject::Issuer => Operation::HashIssuer,
            Subject::ParentBefore => Operation::HashParentBefore,
            Subject::ParentAfter => Operation::HashParentAfter,
            Subject::Requester => Operation::HashRequester,
            Subject::Containerd => Operation::HashContainerd,
        };
        let mut started = self.costs.start(operation);
        let mut bytes = 0;
        let result = call(&mut bytes);
        self.costs.finish(&mut started, Some(bytes));
        result
    }

    /// Finish this measurement BEFORE the existing final pidfd guard. Error
    /// paths may finish after refusal, but never change the original error.
    pub(super) fn start_identity(&self) -> Option<Started> {
        let operation = match self.subject {
            Subject::ParentBefore => Operation::IdentityParentBeforeBody,
            Subject::ParentAfter => Operation::IdentityParentAfterBody,
            Subject::Containerd => Operation::IdentityContainerdBody,
            Subject::Issuer | Subject::Requester => Operation::IdentityRequesterBody,
        };
        self.costs.start(operation)
    }

    pub(super) fn finish_identity(&self, started: &mut Option<Started>) {
        self.costs.finish(started, None);
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
    Completed,
    RequestError,
    ParentBeforeError,
    ParentAfterError,
}

pub(super) struct Recorder<W> {
    output: W,
    records: u8,
    work_records: Option<u64>,
    failed: bool,
}

/// Historical DATA cutpoints for one accepted issuer connection. Capture the
/// first snapshot before any counted work, including the parent-before check.
/// The next cold probe's first snapshot can close an earlier warm bracket;
/// that probe's own work must never enter the bracket.
pub(super) struct WorkCapture {
    ordinal: Option<u64>,
    before: crate::security_epoch::admission_work::Snapshot,
    signed_grant: Option<day2_capabilities::Digest>,
}

impl WorkCapture {
    pub(super) fn bind_grant(&mut self, grant: &super::protocol::SignedStage) {
        // No raw public key, nonce, process, runtime or provider value is
        // exported. Missing serialization is unknown diagnostic provenance.
        self.signed_grant = day2_capabilities::Digest::of(grant).ok();
    }
}

impl<W: Write> Recorder<W> {
    pub(super) fn new(output: W) -> Self {
        Self {
            output,
            records: 0,
            work_records: Some(0),
            failed: false,
        }
    }

    pub(super) fn begin_work_capture(&mut self) -> WorkCapture {
        self.work_records = self.work_records.and_then(|n| n.checked_add(1));
        WorkCapture {
            ordinal: self.work_records,
            before: crate::security_epoch::admission_work::snapshot(),
            signed_grant: None,
        }
    }

    /// Export only after actual connection work has returned and its channel,
    /// acquisitions and temporary peer observations have unwound. Cumulative
    /// work records continue after the independent 16-record timing cap.
    pub(super) fn emit_connection(
        &mut self,
        costs: &Costs,
        capture: WorkCapture,
        outcome: Outcome,
    ) -> anyhow::Result<()> {
        let result = (|| {
            anyhow::ensure!(!self.failed, "native_issuer_cost_closed");
            self.emit_work_inner(
                capture,
                outcome,
                crate::security_epoch::admission_work::snapshot(),
            )?;
            self.emit(costs, outcome)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn emit_work_inner(
        &mut self,
        capture: WorkCapture,
        outcome: Outcome,
        after: crate::security_epoch::admission_work::Snapshot,
    ) -> anyhow::Result<()> {
        #[derive(Serialize)]
        struct Record {
            format: &'static str,
            connection_ordinal: Option<u64>,
            signed_grant: Option<day2_capabilities::Digest>,
            outcome: Outcome,
            before: crate::security_epoch::admission_work::Snapshot,
            after: crate::security_epoch::admission_work::Snapshot,
        }
        let json = serde_json::to_string(&Record {
            format: "day2_native_issuer_work_v1",
            connection_ordinal: capture.ordinal,
            signed_grant: capture.signed_grant,
            outcome,
            before: capture.before,
            after,
        })?;
        anyhow::ensure!(
            WORK_PREFIX.len() + json.len() < WORK_RECORD_BYTES,
            "native_issuer_work_record_bound"
        );
        self.output
            .write_all(format!("{WORK_PREFIX}{json}\n").as_bytes())
            .map_err(|_| anyhow::anyhow!("native_issuer_cost_export_failed"))
    }

    pub(super) fn connection(&self) -> Costs {
        if self.records < RECORD_LIMIT {
            Costs::new()
        } else {
            Costs::disabled()
        }
    }

    /// Only call after the connection channel/acquisitions and temporary peer
    /// observations have unwound. Long-lived issuer owners remain idle.
    pub(super) fn emit(&mut self, costs: &Costs, outcome: Outcome) -> anyhow::Result<()> {
        if costs.0.is_none() {
            return Ok(());
        }
        anyhow::ensure!(
            !self.failed && self.records < RECORD_LIMIT,
            "native_issuer_cost_closed"
        );
        let result = self.emit_inner(
            costs,
            outcome,
            crate::security_epoch::admission_work::snapshot(),
        );
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn emit_inner(
        &mut self,
        costs: &Costs,
        outcome: Outcome,
        admission_work: crate::security_epoch::admission_work::Snapshot,
    ) -> anyhow::Result<()> {
        #[derive(Serialize)]
        struct Record {
            format: &'static str,
            sequence: u8,
            limit: u8,
            outcome: Outcome,
            rows: Vec<(Operation, Measurement)>,
            admission_work: crate::security_epoch::admission_work::Snapshot,
        }
        let record = Record {
            format: "day2_native_issuer_cost_v2",
            sequence: self.records + 1,
            limit: RECORD_LIMIT,
            outcome,
            rows: costs.rows(),
            admission_work,
        };
        let json = serde_json::to_string(&record)?;
        anyhow::ensure!(
            PREFIX.len() + json.len() < RECORD_BYTES,
            "native_issuer_cost_record_bound"
        );
        self.output
            .write_all(format!("{PREFIX}{json}\n").as_bytes())
            .map_err(|_| anyhow::anyhow!("native_issuer_cost_export_failed"))?;
        self.records += 1;
        Ok(())
    }
}

/// Diagnostic failure is terminal; a preexisting native cause keeps precedence.
pub(super) fn preserve_error(
    native: anyhow::Result<()>,
    export: anyhow::Result<()>,
) -> anyhow::Result<()> {
    match native {
        Err(error) if export.is_err() => Err(error.context("native_issuer_cost_export_failed")),
        Err(error) => Err(error),
        Ok(()) => export,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production_capture_order(source: &str) -> bool {
        use syn::visit::Visit;

        fn named(expression: &syn::Expr, name: &str) -> bool {
            matches!(expression, syn::Expr::Path(path) if path.path.is_ident(name))
        }
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
        let Some(syn::Stmt::Local(capture)) = body.body.stmts.get(1) else {
            return false;
        };
        if !matches!(&capture.pat, syn::Pat::Ident(binding) if binding.ident == "capture")
            || !matches!(&capture.init, Some(init)
                if matches!(&*init.expr, syn::Expr::MethodCall(call)
                    if named(&call.receiver, "recorder")
                        && call.method == "begin_work_capture" && call.args.is_empty()))
        {
            return false;
        }
        let Some(syn::Stmt::Local(work)) = body.body.stmts.get(2) else {
            return false;
        };
        if !matches!(&work.pat, syn::Pat::Ident(binding) if binding.ident == "work")
            || !matches!(&work.init, Some(init)
                if matches!(&*init.expr, syn::Expr::Call(call)
                    if matches!(&*call.func, syn::Expr::Path(path)
                        if path.path.segments.last().is_some_and(|s| s.ident == "begin"))))
        {
            return false;
        }
        #[derive(Default)]
        struct Wiring {
            captures: usize,
            exports: usize,
            serve: usize,
        }
        impl<'ast> Visit<'ast> for Wiring {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if named(&call.receiver, "recorder") {
                    self.captures += usize::from(call.method == "begin_work_capture");
                    self.exports += usize::from(
                        call.method == "emit_connection"
                            && call.args.len() == 3
                            && named(&call.args[1], "capture"),
                    );
                }
                syn::visit::visit_expr_method_call(self, call);
            }

            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                self.serve += usize::from(
                    named(&call.func, "serve")
                        && call.args.len() == 6
                        && matches!(&call.args[5], syn::Expr::Reference(reference)
                            if reference.mutability.is_some() && named(&reference.expr, "capture")),
                );
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut wiring = Wiring::default();
        wiring.visit_block(&run.block);
        let Some(serve) = syntax.items.iter().find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "serve" => Some(function),
            _ => None,
        }) else {
            return false;
        };
        let Some(stage) = serve.block.stmts.iter().position(|statement| {
            matches!(statement, syn::Stmt::Local(local)
                if matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "stage")
                    && matches!(&local.init, Some(init)
                        if matches!(&*init.expr, syn::Expr::Struct(value)
                            if value.path.is_ident("SignedStage"))))
        }) else {
            return false;
        };
        let joined = matches!(serve.block.stmts.get(stage + 1),
            Some(syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_)))
                if named(&call.receiver, "capture") && call.method == "bind_grant"
                    && call.args.len() == 1
                    && matches!(&call.args[0], syn::Expr::Reference(reference)
                        if reference.mutability.is_none() && named(&reference.expr, "stage")));
        wiring.captures == 1 && wiring.exports == 2 && wiring.serve == 1 && joined
    }

    #[test]
    fn actual_service_captures_before_all_counted_work_and_exports_both_paths() {
        let source = include_str!("service.rs");
        assert!(production_capture_order(source));
        for (before, after) in [
            ("recorder.begin_work_capture()", "recorder.connection()"),
            (
                "let mut capture = recorder.begin_work_capture();",
                "let mut capture = if false { recorder.begin_work_capture() } else { unrelated };",
            ),
            (
                "recorder.emit_connection(&costs, capture, Outcome::ParentBeforeError)",
                "recorder.emit(&costs, Outcome::ParentBeforeError)",
            ),
            (
                "recorder.emit_connection(&costs, capture, outcome)",
                "recorder.emit(&costs, outcome)",
            ),
            ("&mut capture,", "&mut unrelated,"),
            (
                "capture.bind_grant(&stage);",
                "capture.bind_grant(&unrelated);",
            ),
            (
                "capture.bind_grant(&stage);",
                "if false { capture.bind_grant(&stage); }",
            ),
        ] {
            let changed = source.replacen(before, after, 1);
            assert_ne!(changed, source);
            assert!(!production_capture_order(&changed));
        }
        let capture = "let mut capture = recorder.begin_work_capture();";
        let moved = source.replacen(capture, "", 1).replacen(
            "let costs = recorder.connection();",
            &format!("let costs = recorder.connection(); {capture}"),
            1,
        );
        assert!(!production_capture_order(&moved));
    }

    #[test]
    fn issuer_record_bound_covers_all_maximal_work_and_timing_rows() {
        let costs = Costs::new();
        *costs.0.as_ref().unwrap().borrow_mut() = [Measurement(
            Some(u32::MAX),
            Some(u64::MAX),
            Some(u32::MAX),
            Some(u32::MAX),
        ); 20];
        let mut recorder = Recorder::new(Vec::new());
        recorder
            .emit_inner(
                &costs,
                Outcome::Completed,
                crate::security_epoch::admission_work::Snapshot::maximal_fixture(),
            )
            .unwrap();
        assert!(recorder.output.len() < RECORD_BYTES);
        let text = std::str::from_utf8(&recorder.output).unwrap();
        let record: serde_json::Value =
            serde_json::from_str(text.strip_prefix(PREFIX).unwrap()).unwrap();
        assert_eq!(
            record["admission_work"]["rows"].as_array().unwrap().len(),
            9
        );
        assert_eq!(record["rows"].as_array().unwrap().len(), 20);
    }

    #[test]
    fn uncapped_work_record_bound_covers_two_maximal_snapshots() {
        let mut recorder = Recorder::new(Vec::new());
        recorder
            .emit_work_inner(
                WorkCapture {
                    ordinal: Some(u64::MAX),
                    before: crate::security_epoch::admission_work::Snapshot::maximal_fixture(),
                    signed_grant: Some(day2_capabilities::Digest::new(b"diagnostic-only")),
                },
                Outcome::Completed,
                crate::security_epoch::admission_work::Snapshot::maximal_fixture(),
            )
            .unwrap();
        assert!(recorder.output.len() < WORK_RECORD_BYTES);
        let text = std::str::from_utf8(&recorder.output).unwrap();
        let record: serde_json::Value =
            serde_json::from_str(text.strip_prefix(WORK_PREFIX).unwrap()).unwrap();
        assert_eq!(record["connection_ordinal"], u64::MAX);
        assert_eq!(record["before"]["rows"].as_array().unwrap().len(), 9);
        assert_eq!(record["after"]["rows"].as_array().unwrap().len(), 9);
    }

    #[test]
    fn uncapped_work_cutpoints_reach_stderr_after_timing_details_are_disabled() {
        let output = stderr_probe("work-relay").output().unwrap();
        assert!(output.status.success());
        assert!(
            !String::from_utf8(output.stdout)
                .unwrap()
                .contains(WORK_PREFIX)
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        let work: Vec<serde_json::Value> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix(WORK_PREFIX))
            .map(|json| serde_json::from_str(json).unwrap())
            .collect();
        assert_eq!(work.len(), 40);
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.starts_with(PREFIX))
                .count(),
            usize::from(RECORD_LIMIT)
        );
        for (index, record) in work.iter().enumerate() {
            assert_eq!(record["format"], "day2_native_issuer_work_v1");
            assert_eq!(record["connection_ordinal"], index + 1);
            assert_eq!(record["outcome"], "completed");
            assert!(record["signed_grant"].is_null()); // No native grant fixture.
            assert_eq!(record["before"]["rows"][2]["attempted"], index);
            assert_eq!(record["after"]["rows"][2]["attempted"], index + 1);
            assert_eq!(record["after"]["rows"][2]["returned"], index + 1);
            assert_eq!(record["after"]["rows"][2]["in_flight"], 0);
            assert!(record["before"]["producer_incarnation"].is_string());
            assert_eq!(
                record["before"]["producer_incarnation"],
                record["after"]["producer_incarnation"]
            );
            assert_eq!(record["before"]["loss"], false);
            assert_eq!(record["after"]["loss"], false);
        }
        let overflow = stderr_probe("work-overflow").output().unwrap();
        assert!(overflow.status.success());
        let stderr = String::from_utf8(overflow.stderr).unwrap();
        let record: serde_json::Value =
            serde_json::from_str(stderr.trim().strip_prefix(WORK_PREFIX).unwrap()).unwrap();
        assert!(record["connection_ordinal"].is_null());
    }

    const STDERR_PROBE: &str =
        "security_epoch::native_enrollment::issuer_costs::tests::issuer_stderr_subprocess";
    const STDERR_STAGE: &str = "DAY2_NATIVE_ISSUER_STDERR_TEST_STAGE";

    fn stderr_probe(stage: &str) -> std::process::Command {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", STDERR_PROBE, "--ignored", "--nocapture"])
            .env(STDERR_STAGE, stage)
            .stdin(std::process::Stdio::null());
        command
    }

    #[test]
    fn issuer_record_reaches_captured_parent_stderr_through_production_stdio() {
        let output = stderr_probe("relay").output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(!String::from_utf8(output.stdout).unwrap().contains(PREFIX));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.len() < RECORD_BYTES);
        assert!(stderr.ends_with('\n'));
        let lines: Vec<_> = stderr.lines().collect();
        assert_eq!(lines.len(), 1, "{stderr}");
        let mut record: serde_json::Value =
            serde_json::from_str(lines[0].strip_prefix(PREFIX).unwrap()).unwrap();
        let work = record
            .as_object_mut()
            .unwrap()
            .remove("admission_work")
            .unwrap();
        assert_eq!(work["format"], "native_admission_work_v1");
        assert_eq!(work["sequence"], 1);
        assert_eq!(work["complete"], false);
        assert!(work["producer_incarnation"].is_null());
        assert_eq!(work["loss"], false);
        assert_eq!(work["poisoned"], false);
        let work_rows = work["rows"].as_array().unwrap();
        assert_eq!(work_rows.len(), 9);
        for row in work_rows {
            assert_eq!(row["covered"], true);
            assert_eq!(row["attempted"], 0);
            assert_eq!(row["returned"], 0);
            assert_eq!(row["in_flight"], 0);
        }
        assert_eq!(
            record,
            serde_json::json!({
                "format": "day2_native_issuer_cost_v2",
                "sequence": 1,
                "limit": 16,
                "outcome": "completed",
                "rows": [["hash_requester", [1, 17, 3, 3]]]
            })
        );
    }

    #[test]
    #[ignore = "subprocess fixture for issuer stderr inheritance"]
    fn issuer_stderr_subprocess() {
        match std::env::var(STDERR_STAGE).unwrap().as_str() {
            "relay" => {
                let status = stderr_probe("record")
                    .stdout(std::process::Stdio::null())
                    .stderr(issuer_stderr())
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            "record" => {
                let mut recorder = Recorder::new(std::io::stderr());
                let costs = recorder.connection();
                costs.record(
                    Operation::HashRequester,
                    Some(17),
                    Some(Duration::from_micros(3)),
                );
                recorder.emit(&costs, Outcome::Completed).unwrap();
            }
            "work-relay" => {
                let status = stderr_probe("work-record")
                    .stdout(std::process::Stdio::null())
                    .stderr(issuer_stderr())
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            "work-record" => {
                use crate::security_epoch::admission_work::{self, Work};
                // DATA-only process ledger fixture. It constructs no native
                // process, role, connection, acquisition or request owner.
                admission_work::bind_producer(
                    &day2_capabilities::Digest::new(b"work-stderr-data"),
                    std::process::id(),
                );
                let mut recorder = Recorder::new(std::io::stderr());
                for _ in 0..40 {
                    let capture = recorder.begin_work_capture();
                    let costs = recorder.connection();
                    let mut work = admission_work::begin(Work::IssuerServiceAdmission);
                    work.finish(true);
                    recorder
                        .emit_connection(&costs, capture, Outcome::Completed)
                        .unwrap();
                }
            }
            "work-overflow" => {
                let mut recorder = Recorder::new(std::io::stderr());
                recorder.work_records = Some(u64::MAX);
                let capture = recorder.begin_work_capture();
                assert!(capture.ordinal.is_none());
                recorder
                    .emit_connection(&Costs::disabled(), capture, Outcome::RequestError)
                    .unwrap();
            }
            _ => panic!("unexpected issuer stderr fixture stage"),
        }
    }

    #[test]
    fn rewound_or_missing_diagnostic_samples_are_not_zero_duration() {
        assert_eq!(
            elapsed(Some(Duration::from_secs(2)), Some(Duration::from_secs(1))),
            None
        );
        assert_eq!(elapsed(None, Some(Duration::from_secs(1))), None);
        assert_eq!(
            elapsed(Some(Duration::from_secs(1)), Some(Duration::from_secs(1))),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn failed_hash_attempt_records_partial_read_bytes_without_replacing_result() {
        let costs = Costs::new();
        let calls = std::cell::Cell::new(0);
        let result = costs.hashes(Subject::Requester).hash(|bytes| {
            calls.set(calls.get() + 1);
            *bytes = 11;
            Err::<(), _>(73_u8)
        });
        assert_eq!(result, Err(73));
        assert_eq!(calls.get(), 1);
        let row = costs.0.as_ref().unwrap().borrow()[Operation::HashRequester as usize];
        assert_eq!((row.0, row.1), (Some(1), Some(11)));
    }

    #[test]
    fn identity_body_finishes_once_before_the_callers_final_guard() {
        let costs = Costs::new();
        let hashes = costs.hashes(Subject::ParentAfter);
        let mut started = hashes.start_identity();
        hashes.finish_identity(&mut started);
        assert!(started.is_none());
        hashes.finish_identity(&mut started);
        let row = costs.0.as_ref().unwrap().borrow()[Operation::IdentityParentAfterBody as usize];
        assert_eq!(row.0, Some(1));
    }

    #[test]
    fn failed_and_nested_work_has_independent_inclusive_counts_and_bytes() {
        let costs = Costs::new();
        costs.record(Operation::Serve, None, Some(Duration::from_micros(90)));
        costs.record(
            Operation::HashParentBefore,
            Some(17),
            Some(Duration::from_micros(20)),
        );
        costs.record(
            Operation::HashParentBefore,
            Some(3),
            Some(Duration::from_micros(5)),
        );
        let rows = costs.0.as_ref().unwrap().borrow();
        assert_eq!(
            rows[Operation::HashParentBefore as usize],
            Measurement(Some(2), Some(20), Some(25), Some(20))
        );
        assert_eq!(
            rows[Operation::Serve as usize],
            Measurement(Some(1), None, Some(90), Some(90))
        );
    }

    #[test]
    fn unavailable_and_overflowed_measurements_stay_missing() {
        let mut m = Measurement::EMPTY;
        m.add(Some(u64::MAX), Some(Duration::from_micros(1)));
        m.add(Some(1), None);
        m.add(Some(1), Some(Duration::from_micros(3)));
        assert_eq!(m, Measurement(Some(3), None, None, None));
        let mut m = Measurement::EMPTY;
        m.add(None, Some(Duration::MAX));
        assert_eq!(m, Measurement(Some(1), None, None, None));
    }

    #[test]
    fn disabled_measurements_keep_the_original_result_and_bytes_callback() {
        let hashes = HashCosts::disabled();
        let result = hashes.hash(|bytes| {
            *bytes = 7;
            Err::<(), _>("native failure")
        });
        assert_eq!(result, Err("native failure"));
        assert!(hashes.start_identity().is_none());
    }

    #[test]
    fn maximum_numeric_records_and_generation_limit_are_bounded() {
        let mut recorder = Recorder::new(Vec::new());
        let stale = recorder.connection();
        for _ in 0..RECORD_LIMIT {
            let costs = recorder.connection();
            for operation in OPERATIONS {
                costs.0.as_ref().unwrap().borrow_mut()[operation as usize] = Measurement(
                    Some(u32::MAX),
                    Some(u64::MAX),
                    Some(u32::MAX),
                    Some(u32::MAX),
                );
            }
            recorder.emit(&costs, Outcome::RequestError).unwrap();
        }
        let disabled = recorder.connection();
        assert!(disabled.0.is_none());
        recorder.emit(&disabled, Outcome::Completed).unwrap();
        assert!(recorder.emit(&stale, Outcome::Completed).is_err());
        let text = String::from_utf8(recorder.output).unwrap();
        assert_eq!(text.lines().count(), usize::from(RECORD_LIMIT));
        assert!(text.lines().all(|line| line.len() < RECORD_BYTES));
    }

    #[test]
    fn export_failure_preserves_the_native_cause_and_never_formats_it() {
        struct Broken(std::cell::Cell<usize>);
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                self.0.set(self.0.get() + 1);
                Err(std::io::Error::other("private output cause"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for uncapped in [false, true] {
            let mut recorder = Recorder::new(Broken(std::cell::Cell::new(0)));
            let costs = recorder.connection();
            let exported = if uncapped {
                let capture = recorder.begin_work_capture();
                recorder.emit_connection(&costs, capture, Outcome::ParentBeforeError)
            } else {
                recorder.emit(&costs, Outcome::ParentBeforeError)
            };
            let error = preserve_error(Err(anyhow::anyhow!("original native failure")), exported)
                .unwrap_err();
            assert_eq!(error.to_string(), "native_issuer_cost_export_failed");
            assert!(
                error
                    .chain()
                    .any(|e| e.to_string() == "original native failure")
            );
            assert!(!format!("{error:#}").contains("private output cause"));
            assert!(recorder.emit(&costs, Outcome::Completed).is_err());
            let capture = recorder.begin_work_capture();
            assert!(
                recorder
                    .emit_connection(&costs, capture, Outcome::Completed)
                    .is_err()
            );
            assert_eq!(recorder.output.0.get(), 1);
        }
    }
}
