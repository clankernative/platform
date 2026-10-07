## Context

See proposal.md for motivation. The checked-out branches are Platform 8632b5f, Clanker UI a45d3ae, GoLinks 920964c and Studio 828d12e. PR #126 contains generic contract export separately from the provider-neutral preprocessing branch. Linux x86-64 Rust 1.98.1 is installed locally; macOS is still the isolated-builder target.

## Goals / Non-Goals

**Goals:** finish one consistent authoring/build dependency contract; independently prove value semantics; supply verified relocatable installation and explicit hosted-release acquisition; integrate real Studio contracts; give agents CLI onboarding and reusable component guidance.

**Non-Goals:** choose a CI vendor, make repositories public, publish releases, deploy apps, invent a registry service, weaken executable approval, add arbitrary app build scripts, port the isolated builder, or claim production containment/readiness.

## Decisions

1. Keep the existing provider-neutral `ui/ui.lock.json` schema and byte-manifest algorithm. Remove legacy consumer loaders rather than maintaining two locks. Other repositories implement this contract in their own scoped worktrees.
2. Integrate only PR #126's generic exporter onto the current branch. Artifacts remain authoritative for types/forms/routes; Studio reads projections, not authored duplicate domain schemas.
3. Host `ui_*` semantics are the binding ABI baseline. Share versioned conformance vectors with independent preview implementations; no Clanker runtime dependency enters Platform. Exact numeric handling is bounded and tested.
4. Separate compiler/package identity, acquisition, materialization and execution approval. Use existing relocatable bundles plus bounded Rust install adapters. Versioned GitHub release assets are an initial replaceable distribution adapter, not a custom registry or CI commitment. Tests inject local/loopback sources; unsigned hashes are identity, not provenance authentication.
5. First-party CLI composition recommends Clanker and vanilla while the core build port remains generic. Roc operational recipes own workflow order; Rust operations perform atomic writes, downloads/verification and admission.
6. Expand consumer presentation only when component contracts preserve app data/routes/commands. Cursor pagination must not acquire invented page totals. Current interaction/no-JS limitations remain explicit.
7. Parallel workers use separate worktrees and commit exact handoffs. Progress reports are required at least every minute. Coordinator owns integration, source freeze, final verification and agent-guidance consistency.

## Risks / Trade-offs

- [Cross-repository drift] -> one agreed lock and ABI vector contract, integration tests and exact commit handoffs.
- [Release hashes mistaken for trust] -> explicit operator approval and separate provenance/publication gates.
- [Local test success mistaken for native admission] -> record unit/scoped/native/browser gates separately; do not skip unavailable gates and claim verification.
- [Overengineering CI] -> retain supported build adapter boundaries and do not implement speculative Linux isolation.
- [Debug compiler exceeds executable budget] -> fix the test/build profile; preserve the 64 MiB guard.
- [Agent instructions stale] -> every behavior-changing slice updates its owned guidance; coordinator checks cross-repo references.

## Integration Plan

First complete lock and ABI work plus Platform contract export. Release/install can proceed independently with frozen bundle identity. Studio consumes the canonical contract; onboarding consumes reviewed installer semantics. Consumer expansion follows supported contracts. Full Platform gate runs only on stable covered sources with actual prerequisites. Public publication and production qualification remain explicit later operator actions.

## Drawings

Editable Excalidraw diagrams and companion SVG previews are in `docs/architecture/ui-toolchain/`. They cover ownership/build flow and the Studio saved/preview/admitted loop. Captions distinguish architecture intent from completed verification. No private app data, credentials or installation state is included. `docs/UI-TOOLCHAIN-TDD.md` records the implementation checkpoint, exact handoffs, scoped results and remaining gates.
