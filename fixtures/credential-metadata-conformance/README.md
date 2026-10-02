# Credential metadata conformance

Ordinary Roc queries call generated `Credentials.clients.list` and `inspect`
readers. Each query declares `Credential.metadata_access(KeyFamilies.clients)`.
The host inherits the accepted invocation principal, selects current activated
family authority, and applies bounded creator visibility before pagination.

The fixed client and personal declarations share a credential-ready query and
product write. Interactive create commands issue a key and write a public
product registration atomically. Native host tests exercise protected shell
confirmation/reveal, credential HTTP reads/writes, retry and revocation during
durable execution. Generated rotate/revoke commands are not yet included.
Build verification uses disposable authority and keys; it provides no deployed
provider readiness. Metadata tests also seed rows independently.
