# Request identity and cross-app delegation

A complete conformance application, installed twice by `tests/request_identity.rs`.
`who` exposes sealed Roc context; `forward` resolves the operator-owned `delegation`
binding and calls `Delegate.query`; `record` writes one effective-actor-owned entry.
HTTP tests authenticate real local sessions and assert both databases' receipts,
replay and audit evidence. No application input can select identity.

The mandatory disposable app campaign uses one exact simulated peer response.
The native HTTP suite instead installs a real callee and pins its actual schema
digest; no simulated integration is used in that suite.
