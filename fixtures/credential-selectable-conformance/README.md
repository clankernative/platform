# Selectable local credential conformance

This overlays `credential-metadata-conformance`, reusing its single model/domain,
read, use, revoke and invariant implementations. Family declarations, issuance
inputs and typed rotation inputs change. There is no product management page.
Both rotation handlers require an explicit closed keep-existing/narrow choice,
using the same protected confirmation and atomic product/credential writer.

Both local profiles require an explicit typed selection. Pure examples and
verification generators explicitly choose the complete generated catalog;
runtime tests choose narrower subsets and never infer a default grant. Option
values carry the full canonical family contract, not a hardcoded fixture digest.
These are contract DATA. The host still requires actual confirmation, current
selection/subject/readiness and the ordinary atomic product/credential commit.

Rotation examples explicitly keep the predecessor grant. Runtime controls also
narrow it and prove that a later choice cannot re-expand it. The original lineage
ceiling is retained separately from each authenticated version grant.

This fixture does not qualify a live native CredentialIntent producer, reveal
transport, provider integration or production custody.
