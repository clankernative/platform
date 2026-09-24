# Relational conformance

A platform fixture for a four-write transaction across deals, stages and history.
It has no pages. Runtime tests independently track the current stage, row revision,
stage counts and history length, inject failure after each write, and replay every
completed decision. The fixture's own invariants are an additional check, not the
reference model. The migration overlay adds a nullable field without changing
model identities.

The move uses `Api.current_state` with declared writes and an explicit pure
revision check. `Api.edit` intentionally permits updating only its single target
row. The fixture's registered `app:stale_revision` failure preserves the
concurrent-revision rejection check for this transaction across several rows.
