# Roc descriptions and OpenTofu

[Stack.roc](Stack.roc) is pure platform code. The private Roc workflow reads a
checked settings projection, builds a resource graph, and sends it to the Rust
adapter. Rust rejects duplicate addresses, unknown/dangling references, cycles,
unsupported attributes and ambiguous values, then emits `main.tf.json`.
[`ops/Infra.roc`](../ops/Infra.roc) selects each engine operation and its order.
Rust executes one admitted engine command per request and refuses a receipt until
all required operations succeed. It checks the pinned inputs again between steps.
Literal strings are escaped so `${...}` and `%{...}` cannot become expressions.
References are explicit edges such as `terraform_data.scope.output`.

Resource keys come from stable names, never list positions. Reordering the input
does not change addresses. OpenTofu evaluates deferred values and retains provider,
dependency, planning and state responsibilities. There is no bespoke IaC engine.

The first qualified resource subset is OpenTofu's built-in `terraform_data`.
It proves the complete description → graph → JSON → init → validate → saved plan
path without cloud credentials. The plan has a scope resource and one resource
per app. These are infrastructure metadata, not deployed application services.

```console
./cli/day2 platform infra plan .cache/tofu.json /tmp/reports-infra-plan
```

Run `cargo run --locked -p xtask -- configure-tofu` to record your installed
OpenTofu 1.11.5 path, version and SHA-256 in ignored `.cache/tofu.json`.
The host copies the verified engine into a fresh private directory,
clears inherited provider/CLI environment, runs fixed commands with deadlines and
log limits, and records graph, configuration, engine and saved-plan hashes. It
prints a receipt and leaves `plan.bin` and `show.log` for review. It never applies.

GCP, Kubernetes and Cloudflare resources are not implemented by this initial
subset. Extend the graph with narrow typed resource/provider schemas and pinned
providers; retain stable addresses and deferred references. Existing HCL can stay
under platform ownership during migration, but the new CLI does not yet import
or execute arbitrary legacy HCL roots. Apply, shared state locking, cloud identity,
drift and recovery must use the platform's durable operational host before live
infrastructure is migrated. Browser tests and faster-whisper remain deferred.
