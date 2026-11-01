# Selectable local credential conformance

This overlays `credential-metadata-conformance`, reusing its single model/domain,
read, use, revoke and invariant implementations. Only family declarations and
issuance inputs/handlers change. No product page or selectable rotation is
registered. Rotation requires its later closed grant-choice contract.

Both local profiles require an explicit typed selection. Pure examples and
verification generators explicitly choose the complete generated catalog;
runtime tests choose narrower subsets and never infer a default grant. Option
values carry the full canonical family contract, not a hardcoded fixture digest.
These are contract DATA. The host still requires actual confirmation, current
selection/subject/readiness and the ordinary atomic product/credential commit.

This fixture does not qualify a live native CredentialIntent producer, reveal
transport, provider integration or production custody.
