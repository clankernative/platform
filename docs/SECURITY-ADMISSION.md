# Explicit security requirements

`apps[app].security` is an optional company-authored prerequisite. Activation
copies it into the same authority document as the artifact, business permissions
and resolved resource grants. Changing desired JSON has no immediate effect.
An absent prerequisite retains the explicit local-spike admission mode; it does
not assert Linux qualification or production readiness.

A requirement pins the exact app artifact, Roc compiler version and complete
platform/SDK source inventory. New builds also capture `compiler/roc`, the hash
of the actual verified compiler binary. Strict prerequisites reject older
artifacts lacking that evidence. The SDK's dual compiler admission checks,
private effect constructors and independent host guards remain mandatory.

The Linux profile additionally requires a completed qualification receipt for
the same platform inventory, native toolchain, runtime image, supervisor binary
and sandbox launcher. Its required checks cover native isolation, worker/HTTP/
backup tests, the ordinary Reports build/check workflow, actual packaged startup,
read/write, revocation, graceful and forced restart, company isolation, restore
and clean shutdown. Missing checks, failed receipts, runtime exclusions or
different compiler/platform inputs cannot produce an accepted review.

The receipt's Reports artifact is the concrete runtime-profile witness. Another
app must have its own admitted artifact and mandatory app verification, and an
operator must approve a requirement pinning that artifact. A platform receipt
does not prove another app's business invariants or all application semantics.

Produce a review document from the actual qualification receipt:

```text
day2 platform resources security-review INSTANCE APP LOCAL_OPERATOR REVIEW_JSON_FILE
```

The input is `{"receipt_file":"/absolute/path/to/receipt.json"}`. The returned
requirements are review data. Put them in the app's desired `security` field,
then use the ordinary transactional authority activation workflow. Review does
not enable the app, activate grants or change existing authority.

At deployment export the selected image must match the approved image digest.
At server startup and every app authorization the actual supervisor/launcher
must match the approved binaries. Existing Linux kernel checks still verify
Landlock/seccomp, finite cgroups, read-only inputs and process isolation; the
qualification record does not replace those checks. An incompatible runtime
cannot resume an invocation or use cached observations under an old approval.
Operator inspection and authority revocation remain possible from the operator
CLI: those operations validate the artifact prerequisites without requiring the
operator CLI binary to equal the app server binary.

Security requirements survive ordinary policy changes, participate in authority
CAS/audit receipts, and cannot be changed by the resource-policy administration
screen as an incidental side effect. Restore retains historical evidence but
disables authority and rotates its epoch; explicit current approval is still
required before serving restored business operations.

Receipts and approvals use the current trusted local operator model. They are
not signed production provenance, enterprise identity or certification against
hostile native code and kernel vulnerabilities. Browser scripts retain the
existing app-authored UI model; this increment does not implement the separate
declarative UI proposal. Resource grants constrain available actions and targets,
not information flow between separately authorized reads and writes.
