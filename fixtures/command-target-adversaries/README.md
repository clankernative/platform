# Command Target and Effect Adversaries

This is an adversarial source overlay, not a reports application. It tests
transactional observation, captured revision, target boundaries and dependent effects.
The build uses the public `examples/reports` app as its positive control and overlays
`commands/submit/SubmitReport.roc`, `commands/analyze/AnalyzeReport.roc` and
`commands/notify/NotifyReady.roc` in a staged copy, preserving
the root registry, nominal models and codecs. The probe's submit effect bound explicitly allows its attempted text
update so the command guard remains the boundary under test. Required positive
verification still runs before this artifact is published.

- `forged` fabricates a row named by the document text without a transactional observation.
- `after_request` changes the captured row after requesting the child command.
- A two-line document encodes another real row ID in its second line. Analysis
  performs an allowed target update and then attempts to write that other row.
- Notification delivery sends twice; the second send consumes the first receipt.
  Recovery must reuse both receipts without duplicating either message.

The host, not these handlers, must reject the operations and roll back changes.
Never install this artifact as the ordinary reports app.

Build with `cargo run --locked -p xtask -- build-command-target-adversaries`.
`xtask verify-reports` also builds this overlay; `command_adversarial` and
`command_recovery` consume its artifact via `DAY2_TEST_REPORTS_PROBE_ARTIFACT`.
