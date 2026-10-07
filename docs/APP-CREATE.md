# Optional first-party app creation

Existing apps need not use scaffolding. `ops/AppCreate.roc` is the authoring recipe,
executed by the same private workflow runner as ordinary Platform operations.

```text
day2 platform app-create new-app hello --ui none
day2 platform app-create new-app hello --ui html
day2 platform app-create new-app hello --ui clanker --bundle /approved/install --bundle-sha256 sha256:REVIEWED_MANIFEST_DIGEST
day2 platform app-create --help
```

`NEW_DIRECTORY` must not exist, even as an empty directory or dangling symlink.
Its parent must already exist. Parent traversal and symlink ancestors are rejected.
Use an existing canonical real directory for the destination and bundle. On macOS,
`/tmp` and `/var` are links; use their real `/private/tmp` or `/private/var` paths
when deliberately working there. The guard is not bypassed for system aliases.
`NAME` is a checked lowercase app namespace, at most 48 bytes. Options are explicit
and duplicates, unknown flags and incomplete pairs fail. Omitting `--ui` asks on a
terminal whether UI will exist and whether to use optional, recommended Clanker.
Without a terminal, supply `--ui`. Plain HTML and UI-free apps remain first-class.

## Scaffold

The recipe authors the canonical [app layout](APP-LAYOUT.md). The pure `welcome`
query owns its empty input type, full contract, typed example and independent
result/state-preservation check. `App.definition` registers it once. No commands,
demo data, credentials, external connections, arbitrary callbacks or build scripts
are granted. Mandatory model/property admission currently requires a nominal
model, so the scaffold includes an explicitly **educational**, ownership-only
`Models.StarterRecord` and a complete-snapshot nonblank-owner invariant. This is
not an inferred business domain or a recommendation to keep an unused model.
Replace it using the normal register/rename/retire identity authoring operations;
commit `model-identities.json`. The starter property is real, not a TODO or bypass.

UI apps add typed `pages/Routes.roc`, `ui/pages/welcome.html`, app-owned CSS tokens
and `ui/AGENTS.md`. Clanker uses a supported card/body slot containing an ordinary
app-owned anchor with the checked `{{ routes.welcome() }}` internal link helper,
plus app-owned `ui/clanker-theme.css`. Routing stays with the app/host; the producer
does not need to understand Platform route calls as component URL properties. The approved bundle must
contain **`@clanker/vanilla`**; its actual package name/version are preserved.
There is no user-invented package configuration or automatic alternate package.
The copied locked package lives at `.ui-dependencies/vanilla/`, outside `ui/`,
and the existing schema-1 `ui/ui.lock.json` uses `../.ui-dependencies/vanilla`.
Ordinary source traversal excludes this root; the existing assembly capability
independently captures only its explicit locked package closure as build input.
There is no new resource-serving exception. Only admitted expanded resources are served. No component-specific callbacks are
added to Platform runtime code. Company branding remains an independent instance
input; app creation does not rebuild or assign it.

## Install identity is not execution authority

Install/restore [Clanker UI 0.1.0](https://github.com/clankernative/clanker-ui/releases/tag/v0.1.0)
separately using its [installation instructions](https://github.com/clankernative/clanker-ui/blob/v0.1.0/docs/INSTALL.md).
Use the exact qualified target and reviewed bootstrap/archive hashes; no Clanker checkout or Rust compilation is required.
Review the **installed manifest** digest separately for `--bundle-sha256`: it is not the archive checksum.
App creation performs **no download or installation**. This initial capability
accepts only an explicit already-installed directory and a caller-reviewed
`sha256:` digest of its exact `manifest.json` bytes. Supplying
`--bundle-sha256` is an explicit **execution approval** for only the host-target
`bin/clanker-ui` entry named and hashed in that manifest, not an assertion of
publisher provenance, a wildcard executable grant, or authority from the app lock.
Review the manifest's source revision/tool version, target, executable digest and
complete vanilla package closure before approving it. An installed archive's
transport checksum alone does not authorize execution.

Rust validates protocol 2, binding ABI 2, Minijinja 2.12.0 and host target, captures
bounded regular files without links, checks every captured byte/digest and package
manifest, and recreates the provider-neutral pin for the exact private executable.
The current manifest must include exactly the ordered `legal/LICENSE` and
`legal/NOTICES.txt` entries. Each must be nonempty, at most 1 MiB, and match its
captured regular-file bytes and SHA-256. Missing/unknown entries, wrong ordering,
unsafe paths, symlinks, oversized input and tampering fail closed. The old
unreleased no-legal shape is rejected; no alternate parser is retained.
Creation retains these bytes at `.ui-dependencies/legal/`, separately from
`.ui-dependencies/vanilla/`; the package digest, all catalog inputs and lock path
remain unchanged. Keep the notices with redistributed generated CSS/JS/catalog
assets. This does not assign a license to app-owned business code or content.
No other bundle executable is launched. The ordinary locked build then uses that
pin through the existing provider adapter and retains all resource/template/form
admission and mandatory app verification. This is trusted operator tooling, not
hostile-executable containment or production authentication.

After creation, subsequent ordinary Clanker builds/local development still need
the separately approved installed `provider-pin.json` through the existing
`DAY2_UI_PROVIDER_PIN_JSON` operator override. The app carries no executable
approval, compiler binary or hidden persistent platform configuration. Relocating
an app preserves its local package lock; independently relocate/restore the tool
through the installer when needed. Plain HTML/UI-free builds need no provider.
Existing Clanker apps need only exact installed inputs at their declared lock
path and a separately approved operator pin, not new app scripts or domain changes.
The released Linux executable is CLI-only (glibc 2.39+), not full Linux Native
builder qualification; scoped creation/admission is qualified on Apple Silicon.

## Atomicity and checks

Roc orders choice → private stage/capture → bounded source writes → identity
registration → ordinary verified build → publication. Rust refuses publication
unless that ordinary build succeeded for the captured app and returned an admitted
artifact with its exact namespace. All earlier failures drop private staging and
leave the destination absent. Publication is an anchored, same-parent, atomic
no-replace directory rename; a concurrently created destination is never clobbered.
Build evidence/artifacts remain in the ordinary platform build store. App
creation neither publishes a release nor deploys, pushes, configures CI, or changes
repository visibility. It does not port the macOS isolated builder to Linux.

Focused implementation checks are `cargo test --locked -p day2-ops --lib app_create`
and `cargo test --locked -p day2-ops --lib app_creation_` after `xtask workflows`. Authored Rust/Roc
formatting is checked through `xtask fmt` / `fmt-check`; real scaffold builds need
the reviewed compiler/ABI pins. A successful scoped check is not the full Platform
gate (`cargo run --locked -p xtask -- verify`).
