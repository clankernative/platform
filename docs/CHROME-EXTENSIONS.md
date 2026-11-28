# Chrome extensions

An app can ship one Manifest V3 Chrome extension that managed browsers
force-install from the app's own domain. The instance pins it: the app's
`extension` in `day2.json` is the extension ID, and every other name is derived
from the app and that ID (see [INSTANCE.md](INSTANCE.md)). The Platform owns the
release format: it packs the extension as a deterministic CRX3, injecting the
names the pin derives, writes the Chrome update manifest, and verifies both in
app CI. Apps own only the extension source and their extension's tests.

## Layout

```text
.chrome-extension/
  src/             the unpacked extension; src/manifest.json is required
  local/           optional files that replace src/ files in local builds only
public-downloads/
  <app>.crx        signed release, written by `instance extension pack`
  updates.xml      Chrome update manifest, written by `instance extension pack`
```

`.chrome-extension/` sits at the app root, `app/` in the app repository. The
app build never captures it. Other files there, such as
the extension's own JavaScript tests, are app-owned and ignored by the Platform.
An app whose instance pins no extension may have neither `.chrome-extension/`
nor anything in `public-downloads/`.

The pin is the extension identity: the first 128 bits of SHA-256 over the
signing key's public key. Changing the key creates a different extension in
every browser, along with its storage, OAuth client binding and policy entry.
From the pin and the app the instance derives:

- the CRX filename `<app>.crx`, which with `updates.xml` is exactly what the app edge
  serves without IAP;
- the update URL `https://<app host>/downloads/updates.xml`;
- the signing key's secret, `<app>-chrome-extension-signing-key`.

`src/manifest.json` must be a JSON object that declares `manifest_version: 3`,
`name` and a Chrome `version` (one to four integers 0-65535, no leading zeros),
and must not declare `key` or `update_url`. Every release's manifest is
`src/manifest.json` byte for byte with both inserted as its first two members:
`key` is the signing key's base64 public key, so unpacked builds keep the
release identity (`chrome.identity` OAuth clients and extension-origin CORS
allowlists depend on it), and `update_url` is the derived update URL.

`minimum_chrome_version`, when present, is published as `prodversionmin`. File
paths use ASCII letters, digits, `.`, `_` and `-`; hidden files and `_`-prefixed
names other than `_locales` are refused, and `.DS_Store` is ignored. The packed
extension, like any public download, is at most 2 MiB.

## Releasing

Change anything under `src/`, increase `version`, then sign with the key from
the instance's secret store, naming the instance directory, the app and the
app's directory. Process substitution keeps the key off disk:

```console
day2 instance extension pack INSTANCE_DIRECTORY APP APP_DIRECTORY \
  <(gcloud secrets versions access latest --secret=APP-chrome-extension-signing-key)
```

`pack` refuses a key whose ID differs from the pin, a key file inside the app or
readable by group or others, a version older than the published one, and
changed contents under an unchanged version. It replaces only the CRX and
`updates.xml`, verifies them, and prints the release and its browser policy.
Commit `src/` and both release files together. Packing is deterministic, so
packing unchanged sources again reproduces the same bytes.

App CI verifies the release whenever the change selects the native or the
extension lane, against the pin rendered into the org-scoped workflow
(`DAY2_CI_EXTENSION`). `day2 instance extension verify` runs the same check
locally; `platform check` does not, because it has no instance. Verification
refuses the change unless:

- `public-downloads/` holds exactly `<app>.crx` and `updates.xml`;
- the CRX3 carries exactly one RSA proof, by a key whose ID is the pin;
- its archive is byte-for-byte the archive of the current `src/`, with that
  key and the update URL injected into the manifest;
- `updates.xml` matches the pinned ID, the derived codebase, the version and
  `prodversionmin`.

CI never holds a signing key.

## Serving and installing

The app serves both files anonymously at `/downloads/<filename>` (see
[public release downloads](APP-LAYOUT.md#public-release-downloads)). Behind IAP,
the instance renders exactly these two paths into the app edge's
`public_download_paths` from the app's `extension` pin.

`day2 instance extension policy INSTANCE_DIRECTORY APP APP_DIRECTORY` prints the
extension ID, update URL, the Google Admin console settings and the equivalent
`ExtensionSettings` policy. In Google Admin, add the extension by ID **from a custom URL**, set it to
**Force install**, set **Installation URL** to the update URL and set **Update
URL** to **Installation URL (see above)**. That last setting overrides the
update URL inside installed copies, so a browser still holding an older release
with another `update_url` moves to this one. After deploying, request both URLs
without cookies: expect 200 with `application/xml` and
`application/x-chrome-extension`, and no login redirect. Then check
`chrome://policy` and `chrome://extensions` on a managed test browser before
rolling out widely.

A person makes browser-policy changes. The Platform never holds a credential
that can change Google Admin or any other browser policy: such a credential
could force-install any extension on every managed browser, which is more than
any one extension's signing key can do. Admin entries change only when an
extension is added or its URL changes; releases never touch them.

## Fleet uptake

`day2 instance extension fleet INSTANCE_DIRECTORY APP APP_DIRECTORY` verifies the
release, then reads the last 24 hours of the instance project's load-balancer
request logs for its downloads with the operator's own gcloud credentials
(`roles/logging.viewer`).
Every managed Chrome update check names the extension, its installed version and
whether policy installed it, so the report shows what the browsers are actually
running:

- update checks, those from a policy install, and successful package downloads;
- client addresses by the version their latest check reported, and how many are
  on the published release. `0.0.0.0` is a first install in progress. One
  address can hide several browsers, so counts are lower bounds;
- responses of 500 or above for either download.

Client addresses never leave the command. Its `problems` list names:

- `no_policy_update_checks`: no policy-installed browser checked in. The Admin
  entry is missing or names another URL, or browsers cannot reach it.
- `server_errors`: the edge failed update-manifest or package requests.
- `clients_ahead_of_release`: browsers report a newer version than this
  checkout. Run it against the deployed commit; otherwise the served release
  went backwards.

Chrome checks about every five hours, and a browser reports a new version only
on the check after it downloads it, so most browsers move within a day. Browsers
behind one address count as one client: a client that downloads the package and
then reports the old version again is usually a second browser, not a failed
install.

## Local builds

`day2 instance extension local INSTANCE_DIRECTORY APP APP_DIRECTORY NEW_DIRECTORY`
writes an unpacked build of the current sources for **Load unpacked**. It never
checks for updates and omits `webRequestBlocking`, which Chrome grants only to
policy-installed extensions. Without `local/`, it adds the release `key`, taken
from the committed package (which must be the pinned extension's, though it may
predate the sources), so OAuth and extension-origin allowlists still work; pack
a first release before such a build. A managed install of the same extension
takes precedence, so remove it from the test profile first. When `local/`
exists, its files replace the matching release files, and the build has no `key`
and appends `(local)` to the name, because a behaviorally different build must
not impersonate the release.
