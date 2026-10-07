# Finish first-party UI toolchain

## Why

The provider-neutral build boundary exists, but component discovery, Studio and clean dependency installation do not yet agree. Finish the contracts and supported tooling without selecting a CI vendor, requiring sibling checkouts, or coupling the Platform runtime to Clanker components.

## What Changes

- **BREAKING**: make the existing `ui/ui.lock.json` the only Native app UI dependency contract; no legacy compatibility.
- Integrate the generic artifact contract exporter from PR #126 onto the provider-neutral Platform branch.
- Specify and test generic binding ABI 2 with identical versioned conformance cases in independent host and preview implementations.
- Supply explicit verified compiler/package installation and restore from local bundles and versioned hosted release artifacts; do not publish or make repositories public in this change.
- Align Studio discovery, static previews, pinned compiler verification and real local-dev build observation.
- Add optional first-party CLI onboarding: UI choice, Clanker recommendation and vanilla default, with noninteractive equivalents and app-owned theme/guidance.
- Expand GoLinks presentation adoption only where supported components preserve existing domain behavior.
- Keep agent guidance current and supply editable Excalidraw architecture/build/edit-loop drawings.

## Capabilities

### New Capabilities

- `ui-toolchain-contract`: generic app-contract export, binding conformance and first-party opt-in authoring/installation boundaries.

### Modified Capabilities

None: no existing OpenSpec capability files in this checkout.

## Impact

Platform changes are scoped to this repository's generic contracts, tests, approved operational recipes/CLI and documentation. Separately scoped workers in Clanker UI, Studio and GoLinks own their repository changes. Component rendering remains external to Platform. Existing macOS isolated-builder constraints remain; Linux is used for available local compiler/test execution, not a promise of a new isolated CI backend. Public publication, production deployment and CI vendor selection require subsequent explicit operator actions.
