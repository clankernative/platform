# Chrome extensions

An app can ship one Manifest V3 Chrome extension that managed browsers
force-install from the app's own domain. The Platform owns the release format:
it packs the extension as a deterministic CRX3, writes the Chrome update
manifest, and verifies both in `platform check`. Apps own only the extension
source and their extension's tests.

## Layout

```text
.chrome-extension/
  extension.json   {"id": "<32 letters a-p>", "package": "<name>.crx"}
  src/             the exact unpacked extension; src/manifest.json is required
  local/           optional files that replace src/ files in local builds only
public-downloads/
  <name>.crx       signed release, written by `extension pack`
  updates.xml      Chrome update manifest, written by `extension pack`
```

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
list both exact paths in the app's `app-edge.public_download_paths`.

`day2 platform extension policy APP_DIRECTORY` prints the extension ID, update
URL and the equivalent `ExtensionSettings` policy. In Google Admin, add the
extension by ID **from a custom URL** with that update URL and set it to
**Force install**. After deploying, request both URLs without cookies: expect
200 with `application/xml` and `application/x-chrome-extension`, and no login
redirect. Then check `chrome://policy` and `chrome://extensions` on a managed
test browser before rolling out widely.

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
