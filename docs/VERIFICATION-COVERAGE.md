# Public verification coverage

`ops/Verify.roc` is the executable regression policy. `xtask verify` builds only
the public Reports example and fixtures under `fixtures/`. It runs platform,
SDK, CLI, real SQLite, native worker, HTTP, authority, migration, simulation and
Temporal tests, including isolated build/receipt recovery checks.

`xtask verify-fast` is a narrower edit-loop gate. `xtask verify-reports` exercises
the teaching example and selected platform contracts. Neither replaces the full
gate. Receipts are written under ignored `artifacts/` and name their input snapshot;
historical receipts are not evidence for a modified source tree.

The shared lint capability also runs `xtask architecture-check`. Its explicit
source catalog and reviewed ambient-effect allowances are in
`architecture-rules.json`; the policy bytes enter build and verification
fingerprints. New/increased effects, unknown sources and obsolete exceptions
fail the gate. See [the structural rollout](PLATFORM-STRUCTURAL-RULES.md) for
enforcement scope and the remaining dependency/proof/runtime slices.

Private app migrations and company acceptance tests belong to downstream private
repositories. Passing this public gate makes no claim about those applications.
Linux kernel/runtime qualification is a separate native campaign documented in
[the runtime guide](../deploy/linux-sqlite/README.md).

OAuth's required seeded host/protocol campaigns, effect-boundary guard, catalog
coverage gate, implementation-bound replay, and durable schema upgrades are
documented in [OAuth simulation and durable invariants](OAUTH-SIMULATION.md).
They run in both library gates and complement real adapter/crash qualification.
