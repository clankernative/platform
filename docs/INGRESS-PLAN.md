# Ingress contract

Inbound provider events need provider-specific verification, bounded parsing,
replay protection and explicit instance authority before becoming app commands.
An event's authenticity does not grant general outgoing provider authority.

The public [Ingress SDK](../sdk/contracts/Ingress.roc) and
[host implementation](../crates/day2/src/ingress.rs) define the current surface.
Keep company webhook inventories, event payloads and migration runbooks private.
Do not infer production support for a provider from a planned integration.
