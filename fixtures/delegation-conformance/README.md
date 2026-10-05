# Request identity and cross-app delegation

A complete conformance caller with a separately built `delegation-peer` exporter.
`who` exposes sealed Roc context; `forward` calls the generated typed
`ImportedContracts.peer_identity_who`; `record` writes one effective-actor-owned entry.
HTTP tests authenticate real local sessions and assert both databases' receipts,
replay and audit evidence. No application input can select identity.

The mandatory disposable app campaign uses one exact simulated peer response.
The native HTTP suite instead installs a real callee and pins its actual schema
digest; no simulated integration is used in that suite.

`cargo run --locked -p xtask -- build-delegation` builds the peer first, resolves
the caller's exact import lock and builds the caller through the normal pipeline.
The two addressed artifacts are recorded in `artifacts/delegation-fixtures.json`.
The control crate's `release_execution` HTTP suite uses independently served normal
app hosts and separate databases, a signed human edge request, generated native
Roc observations, two IAP workload gates and current source-grant admission.
