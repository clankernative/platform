# Credential metadata conformance

Ordinary Roc queries call generated `Credentials.clients.list` and `inspect`
readers. Each query declares `Credential.metadata_access(KeyFamilies.clients)`.
The host inherits the accepted invocation principal, selects current activated
family authority, and applies bounded creator visibility before pagination.

The client and personal declarations share one credential-ready local root.
The fixture has no issue, rotate, revoke, reveal, or credential ingress path.
Build verification uses empty metadata and disposable static authority pins;
it provides no key provider or production credential readiness. Runtime tests
seed metadata rows independently and exercise native, replay, and HTTP paths.
