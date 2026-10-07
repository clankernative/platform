## Purpose

Define the generic Platform contracts used by optional UI tooling while preserving app-owned domain behavior and independently admitted build outputs.

## ADDED Requirements

### Requirement: Optional first-party UI authoring
The CLI SHALL offer UI-free, plain-HTML and first-party Clanker UI app creation, with vanilla as the default Clanker package. The same choices MUST be available noninteractively. Clanker-specific choices MUST NOT change application domain contracts or grant executable authority.

#### Scenario: Noninteractive app creation
- **WHEN** an agent chooses Clanker UI and the default package explicitly
- **THEN** the CLI creates canonical app layout, app-owned theme and UI dependency declarations without requiring prompts or registering a second operation catalog

#### Scenario: Plain HTML app
- **WHEN** an app has no UI dependency lock
- **THEN** normal build/admission proceeds without invoking or requiring a UI provider

### Requirement: Generic artifact contract discovery
The Platform SHALL export bounded deterministic contracts from an admitted artifact without running app code or accessing databases/providers. Local-development sessions SHALL report artifact-bound export success or explicit failure separately from app serving.

#### Scenario: Contract export failure
- **WHEN** contract export fails after an admitted app is served
- **THEN** the app remains served and the session reports export failure without presenting stale exports as current

### Requirement: Binding ABI semantic conformance
The host SHALL enforce the published generic binding ABI. Preview tooling MUST have versioned conformance evidence for accepted values, rejected values and canonical output without making the host depend on component implementations.

#### Scenario: Large signed integer
- **WHEN** a signed integer above floating-point exact-integer precision is compared or formatted
- **THEN** the ABI result retains exact integer ordering and text

### Requirement: Locked build inputs independent of provisioning location
The build SHALL consume exact captured dependency/executable bytes and independently admit returned templates/resources. Acquisition MAY occur during explicit setup/restore; building MUST NOT silently select new versions or use mutable sibling worktrees. Installation MUST NOT imply executable approval.

#### Scenario: Cold dependency restore
- **WHEN** a clean environment restores dependencies using exact approved identities
- **THEN** materialized inputs are verified before build and caches do not affect selected identities

#### Scenario: Tampered dependency
- **WHEN** dependency bytes differ from the recorded digest
- **THEN** restore/build fails without updating pins or serving the rejected artifact

### Requirement: Honest readiness and maintained guidance
Tooling SHALL distinguish saved sources, static previews, admitted artifacts and hosted publication. Changed public CLI/contract behavior MUST include updated agent guidance and reproducible checks. No CI vendor or new isolated runner SHALL be selected implicitly.

#### Scenario: Saved source rejected by admission
- **WHEN** Studio saves UI changes and the subsequent Platform build fails
- **THEN** tooling reports rejection and preserves the previous admitted app rather than treating a static preview as successful deployment
