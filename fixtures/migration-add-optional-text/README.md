# Add An Optional Text Field

This two-module overlay tests an additive database migration.
`storage/Models.roc` adds `Deal.note : [None, Some(Str)]`; `commands/seed/Seed.roc` supplies
`None` when creating new rows under the changed schema. Other modules come from
a staged copy of `fixtures/relational-conformance`, preserving its model identities.

`xtask verify` builds both versions. The migration tests in
`crates/day2/tests/runtime.rs` check explicit planning, data preservation, SQL NULL
decoding, new-value round trips, repeat application, and fail-closed activation.
This fixture is not evidence that arbitrary schema changes are supported.

Build only this fixture from the platform directory:

```text
cargo run --locked -p xtask -- build-migration-fixture
```

Building does not migrate an existing company database or change an app binding.
