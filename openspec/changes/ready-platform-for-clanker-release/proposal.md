## Why

Clanker UI 0.1.0 is public, but Platform's reviewed integration is not on current main. The user requests clean Platform readiness, preserving its architectural/security rules and avoiding app-specific workarounds.

## What Changes

- Reconcile the qualified integration with current main, preserving upstream credential/effect/schema and verification changes.
- Organize the existing #98 provider-neutral preprocessing and #126 contract-export work into reviewable, nonduplicated changes; retain evidence and describe actual dependencies.
- **BREAKING:** require the published bundle's mandatory legal closure during optional app creation; remove support for the unreleased no-legal bundle shape, with no compatibility path.
- Retain verified project/third-party notices outside the catalog and served UI without changing catalog bytes or inventing executable authority from an app lock.
- Document exact released installation, independent operator pin approval, dependency paths and optional scaffolding; no per-app automation.
- Run targeted regressions, supported scoped builds and the normal frozen-source Platform gates before claiming merge readiness.

## Capabilities

### New Capabilities

- `released-bundle-authoring`: Optional app creation consumes an approved complete released bundle, including bounded verified legal bytes, without modifying app domain code or granting downloads/runtime capabilities.

### Modified Capabilities

None. Existing pending integration/export contracts remain subject to their original requirements rather than being redefined by this change.

## Impact

Platform only: history/PR preparation, `crates/day2-ops/src/app_create.rs`, tests, onboarding documentation, and reviewed integration overlaps with latest main. Keep operational composition in existing `ops/AppCreate.roc` through `ops/Runner.roc`; Rust remains bounded capture/admission enforcement. Update explicit automation sources only if workflow sources actually change. No sibling day2/Clanker/GoLinks/Studio edits, public visibility, deployment, credentials, billing, registry, app job SDK, or browser campaign. Preserve GoLinks persisted links and existing live sessions.
