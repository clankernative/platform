# Chrome extensions

An app can ship one Manifest V3 Chrome extension that managed browsers
force-install from the app's own domain. The Platform owns the release format:
it packs the extension as a deterministic CRX3, writes the Chrome update
manifest, and verifies both in `platform check`. Apps own only the extension
source and their extension's tests.

## Layout

```text
.chrome-extension/
  extension.json   {"id": "<32 letters a-p>", "package": "<app>.crx"}
  src/             the exact unpacked extension; src/manifest.json is required
  local/           optional files that replace src/ files in local builds only
public-downloads/
  <app>.crx        signed release, written by `extension pack`
  updates.xml      Chrome update manifest, written by `extension pack`
```

The instance spec also pins each app's extension ID and derives its names
(`/downloads/<app>.crx`, the update URL and `<app>-chrome-extension-signing-key`;
see [INSTANCE.md](INSTANCE.md)). The instance already exposes exactly the derived
download paths at the app edge, so `package` must be `<app>.crx`: another name
publishes a CRX that browsers cannot fetch through IAP. Nothing checks this yet.
Until roadmap step 4 makes the other derived names authoritative and removes
`extension.json`, `extension.json` remains what `extension pack` and `verify`
read.

`.chrome-extension/` sits at the app root, which is the directory passed to
`platform check`. The app build never captures it. Other files there, such as
the extension's own JavaScript tests, are app-owned and ignored by the Platform.

`id` pins the extension identity: the first 128 bits of SHA-256 over the
signing key's public key. Changing the key creates a different extension in
every browser, along with its storage, OAuth client binding and policy entry.

`src/manifest.json` must declare:

- `manifest_version: 3`, `name` and a Chrome `version` (one to four integers
  0-65535, no leading zeros);
- `key`: the base64 public key whose ID is `id`, so unpacked builds keep the
  release identity (`chrome.identity` OAuth clients and extension-origin CORS
  allowlists depend on it);
- `update_url`: exactly `https://<app domain>/downloads/updates.xml`.

`minimum_chrome_version`, when present, is published as `prodversionmin`. File
paths use ASCII letters, digits, `.`, `_` and `-`; hidden files and `_`-prefixed
names other than `_locales` are refused, and `.DS_Store` is ignored. The packed
extension, like any public download, is at most 2 MiB.

## Releasing

Change anything under `src/`, increase `version`, then sign with the key from
the instance's secret store. Process substitution keeps the key off disk:

```console
day2 platform extension pack APP_DIRECTORY \
  <(gcloud secrets versions access latest --secret=APP-chrome-extension-signing-key)
```

`pack` refuses a key whose ID differs from `extension.json`, a key file inside
the app or readable by group or others, a version older than the published one,
and changed contents under an unchanged version. It replaces only the CRX and
`updates.xml`, verifies them, and prints the release and its browser policy.
Commit `src/` and both release files together. Packing is deterministic, so
packing unchanged sources again reproduces the same bytes.

`platform check`, and therefore app CI, runs `extension verify` first. It
refuses the change unless:

- `public-downloads/` holds exactly the declared CRX and `updates.xml`;
- the CRX3 carries exactly one RSA proof, by the declared key;
- its archive is byte-for-byte the archive of the current `src/`;
- `updates.xml` matches the declared ID, codebase, version and `prodversionmin`.

An app without `.chrome-extension/` may not publish a `.crx` or `updates.xml`.
CI never holds a signing key.

## Serving and installing

The app serves both files anonymously at `/downloads/<filename>` (see
[public release downloads](APP-LAYOUT.md#public-release-downloads)). Behind IAP,
the instance renders exactly these two paths into the app edge's
`public_download_paths` from the app's `extension` pin.

`day2 platform extension policy APP_DIRECTORY` prints the extension ID, update
URL, the Google Admin console settings and the equivalent `ExtensionSettings`
policy. In Google Admin, add the extension by ID **from a custom URL**, set it to
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

`day2 platform extension fleet APP_DIRECTORY GCP_PROJECT` verifies the release,
then reads the last 24 hours of the project's load-balancer request logs for its
downloads with the operator's own gcloud credentials (`roles/logging.viewer`).
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

`day2 platform extension local APP_DIRECTORY NEW_DIRECTORY` writes an unpacked
build for **Load unpacked**. It never checks for updates and omits
`webRequestBlocking`, which Chrome grants only to policy-installed extensions.
Without `local/`, it
keeps the release `key`, so OAuth and extension-origin allowlists still work.
A managed install of the same extension takes precedence, so remove it from the
test profile first. When `local/` exists, its files replace the matching
release files, and the build drops `key` and appends `(local)` to the name,
because a behaviorally different build must not impersonate the release.
