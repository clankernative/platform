## Why

Clanker UI has passed bounded real Native and manual Studio integration but remains a development-checkout dependency. The user authorizes a public early-access release so apps can obtain exact reviewed bytes without cloning Clanker or compiling its Rust source.

## What Changes

- Qualify Clanker CLI 0.1.0 with the existing vanilla 0.7.0 catalog as downloadable GitHub release assets.
- Provide a reviewed prebuilt bootstrap executable and safe exact-version bundle restore, without an install script or automatic build-time networking.
- Prove installed-release consumption by disposable GoLinks and provider-free Studio; retain canonical app locks and separate compiler approval.
- Review the currently private Clanker repository's public surface/history and approved licensing before publication. No other repository becomes public.
- Keep BB, UI polish, broad GoLinks acceptance, npm, new registries and new CI vendors out of scope.

## Capabilities

### New Capabilities

- `ui-release-consumption`: Release acceptance requires independently admitted installed inputs and an honest supported-platform scope.

### Modified Capabilities

None.

## Impact

Platform holds coordination/evidence only; no component-aware Platform runtime is introduced. Packaging implementation is selected explicitly in the isolated Clanker UI release worktree through its own worker workflow; this repo-local change does not authorize direct edits to sibling repositories. GoLinks/Studio original checkouts and running sessions are preserved. Public release and Clanker visibility changes are authorized by the user, but occur only after legal/privacy and byte qualification; MIT licensing is explicitly approved by the user; the candidate retains separately reviewed third-party notices.
