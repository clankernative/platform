# Credential metadata conformance

Ordinary Roc queries call generated `Credentials.clients.list` and `inspect`
readers. Each query declares `Credential.metadata_access(KeyFamilies.clients)`.
The host inherits the accepted invocation principal, selects current activated
family authority, and applies bounded creator visibility before pagination.

The fixed client and personal declarations share a credential-ready query and
product write. Interactive create commands issue a key and write a public
product registration atomically. Fixed-family rotate and revoke commands use
canonical input selectors for the confirmed lineage/head/revision and commit
public product receipts with the transition. Native host tests exercise protected
confirmation and replacement delivery, ordinary bearer reads/writes, concurrent
rotations, rollback, lost-response/reopen recovery and terminal revocation fencing.
Build verification uses disposable authority and keys; it provides no deployed
provider readiness. Metadata tests also seed rows independently.
