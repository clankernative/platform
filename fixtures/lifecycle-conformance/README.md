# Lifecycle conformance

This admitted Roc app creates two parents and one child, then exercises removal
and restoration through target/version-bound operations. Titles use the standard
nonblank text domain; ownership remains instance policy. The child references one
parent, while the spare parent permits independent lifecycle scenarios.

Every operation owns its handler, contract and mandatory verification. Generators
decode `Data.verification_snapshot(raw)` and explicitly select either `live` or
`deleted` rows. Ordinary invariants receive only live state through `Data.snapshot`.
The seeded campaign runs create, remove child, remove spare parent, restore child
and restore spare parent for each generated case.

The child commands' `attempt_other` input deliberately requests a mutation on
another owned row so native tests can prove that `Api.edit` still restricts the
actual target. Create's `reuse_parent` input attempts a child attachment to a
specified existing parent after two earlier writes; a deleted target must reject
the attachment and roll back the complete transaction. Positive generators leave
these probes disabled.

`crates/day2/tests/lifecycle.rs` covers live/trash visibility, preserved values,
owner denial, stale revisions, wrong targets, repeated transitions, restrictive
references, interruption rollback, ambiguous commit recovery, duplicate delivery,
generated restoration checks and artifact-bound replay. The full `xtask verify`
recipe builds this fixture and supplies `DAY2_TEST_LIFECYCLE_ARTIFACT` to that suite.
