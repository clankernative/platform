# Row Authority Adversaries

The verifier copies `row-authority-web-conformance` and replaces `domain/Title.roc`,
`commands/create/CreateLink.roc` and `commands/edit/EditLink.roc`
with these files before building a separate test artifact. No normal app source
or existing database is changed.

The declared Title rules permit empty values, and edit handlers attempt
forbidden ownership transfers, immutable-field changes, changes to another row,
and a valid write followed by a denied write. The `noop` branch ignores the
caller version and writes nothing. Host policy must reject stale edit invocations
before even that no-op handler runs.

These are negative acceptance fixtures, not application development examples.
They retain the normal app's nominal schema and typed obligations while declaring
the broader text rule explicitly. The stricter company-owned policy must still
constrain their behavior. The app's revision guard remains mandatory under
CurrentState policy too; policy cannot disable it.

Build with `cargo run --locked -p xtask -- build-row-authority-adversaries`.
`xtask verify` builds the positive control and this overlay separately; the
`owned_runtime` tests exercise the resulting artifacts under the same policy.
