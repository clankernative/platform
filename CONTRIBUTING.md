# Contributing

Follow the [quickstart](README.md) on Apple Silicon macOS. No private company app,
instance repository, cloud credential or existing cluster is needed for public
platform development. Read [AGENTS.md](AGENTS.md) for source boundaries and style.

Run `cargo run --locked -p xtask -- fmt` and `verify-fast` while editing. Run
`cargo run --locked -p xtask -- verify` against a stable tree before submitting a
release change. The full gate starts a disposable Temporal server, runs native
fixtures and produces local evidence under ignored `artifacts/`.

Run `cargo run --locked -p xtask -- source-check`, Gitleaks and `cargo audit` before
publishing source. Source checks reject links/includes outside this repository,
ignored inputs and accidental binaries. Treat test data as public: use synthetic
identities, reserved example domains and generic business scenarios. Keep customer
migrations and acceptance tests in downstream private repositories.

Changes to SDK catalogs, workflow sources, compiler/glue pins, authorization or
admission require the corresponding source-bound checks. Never bypass admission
or silently drop test obligations to obtain a passing gate. Provider integration
tests use explicit disposable sandbox authority; production credentials do not
belong in contribution CI.

When updating dependencies, run `cargo run --locked -p xtask -- notices` after
`cargo fetch --locked`, review both the lockfile and notice inventory, then rerun
the relevant gates. The one informational fxhash maintenance exception expires
for review on 2026-12-23; there are no accepted vulnerability exceptions.

Describe the concrete behavior changed and tests performed in each pull request.
Use [private security reporting](SECURITY.md) for vulnerabilities.
