## Purpose

Defines the acceptance boundary for apps consuming public early-access Clanker UI releases without a producer source checkout.

## ADDED Requirements

### Requirement: Exact installed release consumption
Applications SHALL consume a complete exact-version installed package closure under their canonical lock. The host SHALL separately approve executable identity and independently admit generated app output. Acquisition MUST NOT occur during app compilation or page serving.

#### Scenario: Clean consumer
- **WHEN** an operator obtains approved release bytes with no Clanker source checkout in the consumer environment
- **THEN** a disposable GoLinks build restores the locked catalog and passes independent admission, and provider-free Studio uses the same installed CLI for checked static preview

### Requirement: Honest bootstrap and platform scope
The public release SHALL provide prebuilt bootstrap bytes, integrity metadata and installation guidance that does not require compiling Clanker, running an install script, weakening the 64 MiB guard, or granting execution from an app lock. Unsupported platforms and adapter-required components MUST be identified.

#### Scenario: First installation
- **WHEN** the operator verifies and approves the bootstrap identity on a supported platform
- **THEN** exact-version restore verifies the archive before bounded extraction and atomically installs into a fresh destination without overwriting an existing installation

### Requirement: Qualified publication
Publication SHALL identify the exact reviewed source, tool/catalog versions, target and asset hashes and SHALL exclude raw private runtime evidence. The Clanker repository's visibility transition MUST follow public-surface review and approved licensing; unrelated repositories and credentials MUST remain unchanged.

#### Scenario: Release readiness
- **WHEN** qualification succeeds and legal/privacy prerequisites are resolved
- **THEN** the authorized public early-access release is published and anonymous hosted acquisition is verified before declaring availability
