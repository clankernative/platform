# CLI verification

The Roc CLI dispatches platform operations through the same [workflows](../ops/README.md)
as xtask. Its [integration tests](checks/src/lib.rs) check the public distribution.
Run `cargo run --locked -p xtask -- verify` from the repository root.
App-specific acceptance and migration tests belong to private downstream repos.
