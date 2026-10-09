## Purpose

Permit current authorized view data to undergo approved, bounded pure presentation transformations before ordinary server-side template rendering.

## ADDED Requirements

### Requirement: Independent execution approval and typed admission
A presentation request SHALL require captured input/output contracts and separately approved executable bytes; application metadata SHALL NOT authorize executable selection or arbitrary code.

#### Scenario: Missing or mismatched approval
- **WHEN** a declared renderer lacks approval, differs in digest/ABI/schema, or returns an invalid output
- **THEN** admission/startup or rendering fails closed without executing unapproved bytes or rendering unchecked data

### Requirement: Bounded presentation without markup injection
Transformations SHALL receive only typed request data and SHALL return typed scene data rendered through ordinary admitted templates with unchanged escaping and resource safety.

#### Scenario: Current data changes
- **WHEN** an authorized query or checked range input produces different view data
- **THEN** the renderer receives that current data and the resulting response reflects it without recompilation

#### Scenario: Renderer failure or repeated access
- **WHEN** a renderer times out, crashes or exceeds a frame/schema bound
- **THEN** execution terminates and reports failure without admitting a partial scene
- **WHEN** the same renderer/input is accessed repeatedly within one render
- **THEN** one checked result is reused only within that request

### Requirement: Deterministic conformance and compatibility
The port SHALL support replaceable deterministic test adapters and replay of failure schedules; applications without declarations SHALL retain existing behavior.

#### Scenario: Replay and isolation
- **WHEN** the same bounded inputs and simulated schedules are replayed
- **THEN** accepted scene/state results are identical and cannot leak between requests
