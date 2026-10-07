## Purpose

Defines optional Platform app creation from a complete approved released UI bundle while preserving legal bytes, generic admission and app/operator authority separation.

## ADDED Requirements

### Requirement: Complete approved release capture
Optional UI app creation SHALL require the complete current bundle shape and verify its executable, package and mandatory legal closure against the explicitly approved manifest before publishing an app. It MUST reject missing, unknown, reordered, unsafe, oversized, linked or digest-mismatched legal inputs without weakening existing guards or supporting the old no-legal shape.

#### Scenario: Published bundle accepted
- **WHEN** an operator supplies an explicitly approved, intact supported-target released bundle with its complete legal closure
- **THEN** app creation captures verified inputs and publishes only after normal mandatory app verification/admission succeeds

#### Scenario: Incomplete or tampered bundle rejected
- **WHEN** any required legal member or identity is missing, invalid, oversized, unknown or changed
- **THEN** app creation fails closed and leaves the requested destination absent without partial publication

### Requirement: Legal retention without catalog changes
Generated Clanker apps SHALL retain the required project/third-party legal bytes outside served UI and outside the package input closure. Legal retention MUST NOT change the released catalog bytes, canonical package digest or implicit app domain rights.

#### Scenario: Retained legal closure
- **WHEN** app creation succeeds from the released bundle
- **THEN** the app's dependency area retains verified notices and package hashes/lock inputs still match the released catalog exactly

### Requirement: App and operator authority remain separate
Platform SHALL keep no-UI/plain-HTML apps unchanged and Clanker optional. App locks MUST NOT authorize executables, acquisition during compilation or arbitrary I/O. Compiler approval and explicit restore remain operator-owned; no app installer/build script, second operational SDK or application-domain change is required merely to consume the release.

#### Scenario: Existing Clanker app consumes installed release
- **WHEN** the operator restores exact approved bytes at the app's declared dependency path and separately configures its approved compiler
- **THEN** the existing app builds through generic preprocessing and independent admission without release-driven domain changes or per-app automation

#### Scenario: No provider opt-in
- **WHEN** an app has no UI provider lock
- **THEN** ordinary Platform builds require no Clanker executable or package
