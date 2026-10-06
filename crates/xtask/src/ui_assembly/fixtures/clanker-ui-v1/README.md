# Recorded Clanker UI assembly protocol fixture

`response.json` is an actual `clanker-ui assemble --request` response, captured
from the producer's ABI-2 implementation on `feat/native-ui-assembly-contract`.
It is not a simulated component renderer. The source-only test package contains
one Button contract and its fixtures, closed icon geometry, and a minimal theme.
The disabled button is illustrative; there is no backend or user data.

The simulator returns these recorded bytes through `UiAssembler`. Native's real
input receipts, template closure, resource, collision and staging checks still
run. Checked Roc page types, form authority and rendered HTML require the
subsequent ordinary Native app build; the simulator does not supply those proofs. A separate
ignored test uses the same sources against an explicitly operator-pinned real
CLI, comparing staged bytes with the recording:

```sh
DAY2_UI_TEST_PROVIDER_PIN_JSON=/absolute/operator-pin.json \
  cargo test --locked --offline -p xtask real_provider_matches_recorded_contract -- --ignored
```

To refresh intentionally, run `native-lock --lock app/ui/ui.lock.json --package
../../package`, supply absolute captured paths in a protocol-2 request, and run
`assemble --request REQUEST_FILE`. Review every source/response change. Do not
update recordings just to hide a conformance failure. This fixture proves the
CLI boundary and Native admission, not gallery migration, transport or browser
behavior, and is not a distributable package or release.
