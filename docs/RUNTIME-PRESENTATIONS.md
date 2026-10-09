# Experimental request-time presentations (ABI 1)

Native optionally transforms current authorized query data into checked scene
records before ordinary page/live rendering. The port is provider-neutral: no
chart vocabulary, ECharts dependency or extra app-operation catalog. Apps with
no declarations require no renderer pin.

## Declaration and execution authority

Captured `ui/presentation.json` has `schemaVersion: 1` and a named
`renderers` catalog. Each contract has exact `input`/`output` types using
`"string"`, `"integer"`, `"boolean"`, `{"record": {...}}` and `{"list": ...}`.
Assembly can stage this as ordinary non-browser `metadata`; it grants no code
authority and adds no assembly wire field.

An independently reviewed operator pin, supplied as the **JSON value** in
`DAY2_PRESENTATION_PIN_JSON`, has this shape. Placeholders are invalid, not
approval of a supplied executable:

```json
{
  "schemaVersion": 1,
  "abi": 1,
  "executable": "/absolute/canonical/installed/approved-renderer",
  "digest": "sha256:<reviewed-executable-sha256>",
  "renderers": {
    "label_v1": {
      "input": {"record": {"label": "string"}},
      "output": {"record": {"text": "string"}}
    }
  }
}
```

This text renderer is illustrative. Use the actual approved renderer's matching
catalog; the same `renderers` object is the declaration content. Required
contracts must match exactly, though approval may cover additional renderers.

Provision reviewed bytes before startup. Native verifies a regular, no-follow
executable with exact digest within the unchanged 64 MiB guard, snapshots it
privately, and uses the existing isolated worker installation/transport.
Canonical paths remain required. Hashes identify bytes, not provenance.
Missing/mismatched approval fails closed. No download, latest selection, or
silent execution-authority refresh is provided.

For an operator-owned private pin file:

```sh
DAY2_PRESENTATION_PIN_JSON="$(< /absolute/private/presentation-pin.json)" ./cli/day2 platform local-dev /absolute/app --directory /absolute/private/instance
```

Build-provider approval remains separate via `DAY2_UI_PROVIDER_PIN_JSON`.
Assembly protocol 2, binding ABI 2 and presentation ABI 1 are distinct. The build
provider never runs on HTTP requests.

## Checked rendering and failures

An admitted template could use
`{{ ui_scene('label_v1', {'label': report.label}).text }}`.
Renderer names and projection keys are literal; every field/type is checked.
Dynamic names, arbitrary calls, unknown fields and raw-markup bypasses reject.
Results use ordinary escaping and concrete HTML/form/resource admission.
Collections retain existing API limits; a checked projection can select page
`items`, not relax those limits.

Workers exchange JSON Lines:
`{"abi":1,"renderer":"label_v1","data":{"label":"Example"}}`.
A reply contains matching `abi`, `renderer`, `inputDigest` and one typed
`result` or bounded `error`. The digest hashes exact request bytes excluding
the LF. Invalid envelopes, identity/schema mismatch, oversized frames, timeout
and crashes reject without admitting partial scenes.

- Frame limit: 1 MiB; worker exchange timeout: 3 seconds.
- Separate admission deadline: 2 seconds. Saturation reports
  `presentation_worker_busy`; poisoned state reports
  `presentation_worker_unavailable`.
- Memoization is within one render only, at most eight distinct results.
- Renderer-specific engine/input bounds cannot be enlarged by declarations.
- Slow rendering is followed by authority/binding and persisted-session checks
  before returning the page. Recheck logic still needs revocation HTTP proof.

## Ports and verification

Contract/pin/response validation has no I/O. `Port` supplies rendering;
`PresentationExchange` and the starter supply process/recovery adapters.
`AdmissionWait` supplies scheduler time: `SystemWait` alone reads a monotonic
clock/sleeps, while seeded simulations use virtual time and the same deadline
logic. App query/domain policy receives no ambient clock or renderer effects.

Library tests cover deadline boundaries, typed protocol, restart/contention
schedules and capture adapters. `presentation_templates`,
`presentation_record_projection`, route/resource tests and the opt-in real
`presentation_worker` test establish separate boundaries. The latter needs
independently approved `DAY2_PRESENTATION_PIN_JSON`,
`DAY2_TEST_PRESENTATION_DECLARATIONS` and explicit `--ignored` execution.

[Chart Live](../examples/chart-live/README.md) demonstrates ordinary persisted
Roc data, commands and server-backed ranges. Its injected browser navigation
ports are tested with
`node --test crates/day2/tests/chart_live_navigation.test.mjs`.
Its [verification record](../examples/chart-live/VERIFICATION.md) distinguishes
simulation, confined adapter, Native build, HTTP and browser evidence. Full
application DST, full Platform verification and release qualification are not
implied by these focused checks.
