# Platform

A Roc application SDK and Rust runtime for company-owned internal tools.
The platform repository is public. Each company keeps its instance configuration,
application repositories, operational state and credentials private.

The supported development host is Apple Silicon macOS with Xcode Command Line
Tools and rustup. Native Linux ARM64 and x86_64 runtime images use pinned toolchains
and require the documented kernel qualification. Production browser authentication
currently uses Google IAP and one hosted domain. The application runtime uses
single-replica SQLite; it does not promise multi-writer HA or arbitrary identity
provider support. The isolated control-plane builder is currently macOS-only.

## Start locally

Install OpenTofu **1.11.5** and Temporal CLI **1.6.1** on PATH. Rust **1.98.1** is
selected by `rust-toolchain.toml`. From this repository's root:

```console
cargo run --locked -p xtask -- bootstrap
cargo run --locked -p xtask -- bootstrap-formatter
cargo run --locked -p xtask -- configure-tofu
cargo run --locked -p xtask -- cli
./cli/day2 platform local-dev examples/reports --directory ../my-private-instance
```

Open the one-use login URL printed by the local server. This is loopback-only
development authentication. The Reports app is an explicitly public teaching
example: it calculates text statistics and sends notifications to a local mailbox.
It contains no company data or business integrations. The local-development
workflow creates the private instance and state in the requested directory.
Keep that directory out of the public repository.

The compiler and formatter are installed into a sibling `.toolchains` directory.
Bootstrap downloads only pinned, hash-verified bytes. The formatter release is
published by `clankernative/platform`; [its source and review procedure](tools/roc-formatter/README.md)
remain available. `configure-tofu` records your local executable and digest in
ignored `.cache/tofu.json`; machine-specific paths are never source inputs.

## Develop and verify

```console
cargo run --locked -p xtask -- verify-fast
cargo run --locked -p xtask -- verify
```

`verify-fast` runs formatting, Clippy and fixture-free library checks. Full
`verify` builds the public fixtures and exercises native execution, SQLite,
HTTP, authorization, recovery, simulations and the Temporal control plane.
It requires substantial time and disk space. Private company apps are never
discovered or included by either command. Company acceptance suites run in their
own private repos against the platform version they deploy.

Both gates check the reviewed [platform structural rules](docs/PLATFORM-STRUCTURAL-RULES.md).
Use `cargo run --locked -p xtask -- architecture-check` for focused feedback.
`architecture-inventory` prints source/effect facts without changing policy.

Use `cargo run --locked -p xtask -- fmt` for authored Rust and Roc. Run
`cargo run --locked -p xtask -- build /absolute/path/to/private-app` to build a
separate app. Build outputs stay in ignored `artifacts/`; they can contain private
application inputs and must not be uploaded as public release assets.

## Deploy a company instance

[The GKE deployment guide](deploy/gke/README.md) describes the public infrastructure
stacks and the order for creating a cluster, app edge and workload. Project IDs,
domains, IAM grants, private state backends, authority policies and app images
belong in the company's private instance repository. [The instance template](examples/instance/README.md)
shows that boundary without containing live values.

[Linux runtime qualification](deploy/linux-sqlite/README.md) is required before
using a native artifact on a target kernel. Cloud infrastructure tests are mocked
contract tests; they are not evidence that a company's live deployment is qualified.

## Read next

- [Public Reports example](examples/reports/README.md) and [application layout](docs/APP-LAYOUT.md)
- [SDK contracts](sdk/README.md), [command runtime](docs/COMMAND-RUNTIME.md) and [authority](docs/AUTHORITY.md)
- [Platform operations](ops/README.md), [edge identity](docs/EDGE-IDENTITY.md) and [live integrations](docs/LIVE-INTEGRATIONS.md)
- [Contributing](CONTRIBUTING.md), [security reporting](SECURITY.md) and [release procedure](RELEASING.md)
- [License](LICENSE) and [third-party notices](THIRD-PARTY-NOTICES.txt)
