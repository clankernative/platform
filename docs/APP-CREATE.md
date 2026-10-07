# Create an app

`day2 platform app-create` creates an ordinary app and runs its build and
required verification before publishing a fresh directory.

```text
day2 platform app-create new-app hello --ui none
day2 platform app-create new-app hello --ui html
day2 platform app-create new-app hello --ui clanker --bundle /approved/install --bundle-sha256 sha256:MANIFEST_DIGEST
```

The destination must not exist; its parent must be an existing real directory
without symlink ancestors. On macOS, use `/private/tmp`, not the `/tmp` alias.
App names start with a lowercase letter and contain only lowercase letters,
digits and underscores, at most 48 characters. Without `--ui`, the CLI prompts
on a terminal; noninteractive callers must supply it.

The scaffold follows [APP-LAYOUT.md](APP-LAYOUT.md): a pure welcome query, its
contract/example/check, and registered model identities. Its ownership-only
`StarterRecord` model is educational; replace it through normal identity
authoring for your domain. HTML and Clanker variants add an app-owned page,
route and styles. No app build scripts or runtime provider are introduced.

## Clanker installation and approval

Install [Clanker UI 0.1.0](https://github.com/clankernative/clanker-ui/releases/tag/v0.1.0)
separately using its [installation guide](https://github.com/clankernative/clanker-ui/blob/v0.1.0/docs/INSTALL.md).
App creation neither downloads nor installs executables.

`--bundle-sha256` is the reviewed SHA-256 of installed `manifest.json`, **not**
the archive checksum. Supplying it approves execution of that manifest's exact
host-target CLI. Review its executable hash and package closure first; an app
lock or download checksum cannot grant execution authority.

The bundle must contain `@clanker/vanilla`, protocol 2 / binding ABI 2, and
verified `legal/LICENSE` and `legal/NOTICES.txt` (ordered, nonempty, each ≤1 MiB).
Creation retains notices at `.ui-dependencies/legal/` and locked package inputs
at `.ui-dependencies/vanilla/`, outside served UI. Keep the notices with
redistributed generated assets; app-owned code and content retain their own rights.

For later builds and local development, set `DAY2_UI_PROVIDER_PIN_JSON` to the
separately approved installed `provider-pin.json`. UI-free and plain HTML apps
need no provider. The released Linux CLI is not a full Linux Native builder;
native app creation currently uses Apple Silicon tooling.

`ops/AppCreate.roc` owns the recipe. Publication is atomic and no-clobber;
failure leaves the destination absent and normal build evidence retained.
