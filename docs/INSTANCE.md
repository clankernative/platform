# Instance repositories

An instance is one company's installation of this platform. Its repository is
data: one authored file, `day2.json`, at the repository root. The platform owns
every name, layout rule, validator, workflow and recipe that consumes it, at the
platform commit the spec pins. Two companies' instance repositories differ only
in their `day2.json` values.

```console
day2 instance check DIRECTORY [--agent]
```

`instance check` reads exactly `DIRECTORY/day2.json` and prints every derived
name. It reads no other file. [InstanceSpec.roc](../cli/InstanceSpec.roc) is the
parser and the derivation; there is no second schema.

## The spec

```json
{
  "kind": "instance",
  "version": 1,
  "installation": "exampleco",
  "platform": "fe4320b189b98ed08fccc183db3e70aee76319ee",
  "gcp": { "project": "exampleco-tools", "region": "us-central1", "zone": "us-central1-a" },
  "forge": { "kind": "gitea", "server": "https://git.example.com", "org": "tools" },
  "domains": { "people": "example.com", "apps": "apps.example.com" },
  "operators": ["ada@example.com", "grace@example.com"],
  "apps": {
    "go": {
      "sdk": "sha256:<release manifest digest>",
      "delivery": "automatic",
      "extension": "jldmikbinomhomcbmeppagennfohakni",
      "owners": ["grace@example.com"],
      "size": "standard",
      "verification": 4,
      "schedules": "enabled"
    },
    "home": {
      "sdk": "sha256:<release manifest digest>",
      "delivery": "manual",
      "extension": null,
      "owners": ["ada@example.com", "grace@example.com"],
      "size": "large",
      "verification": 6,
      "schedules": "paused"
    }
  }
}
```

- Every object is exact. Each field is required and unknown fields fail.
- `operators` and the `apps` keys must be strictly sorted, so one spec has
  exactly one spelling.
- `platform` is a full commit of `github.com/clankernative/platform`. The
  repository is a platform constant, not an input, so an instance cannot select a
  fork.
- `forge.kind` is `gitea`. Other forges become new closed values, never free text.
- Operators are lowercase addresses in `domains.people`.
- `delivery` is `automatic`, `manual` or `paused`.
- `extension` is required and is either `null` or the app's pinned Chrome
  extension ID: exactly 32 letters `a`–`p`.
- `owners` lists 1 to 32 people, strictly sorted, as lowercase addresses in
  `domains.people`. Owners are the app's accountable people; they are distinct
  from `operators`, who run the installation.
- `size` is `standard` or `large`. It is a preset, never raw resource numbers.
- `verification` is the number of verification campaign cases, an integer from
  4 to 100.
- `schedules` is `enabled` or `paused`, for every schedule the selected app
  artifact declares.
- App IDs are 2–20 lowercase letters or digits, starting with a letter. They
  have no separators, so the same string is valid as a repository name, DNS
  label, Kubernetes namespace suffix, bucket component and Roc identifier.
  `instance`, `day2` and `tofu` are reserved because derived names already use
  them.

## Derived names

Nothing below can be configured, restated or overridden.

| Name | Value |
| --- | --- |
| Instance repository | `<org>/instance` |
| App CI repository | `<org>/app-ci` |
| Required app check | `<org>/app-ci: day2 / verification (pull_request)` |
| SDK image registry | `<region>-docker.pkg.dev/<project>/day2` |
| Shared OpenTofu state bucket | `<project>-tofu-state` |
| App repository | `<org>/<id>` |
| App hostname | `<id>.<domains.apps>` |
| App namespace | `app-<id>` |
| App image | `<region>-docker.pkg.dev/<project>/<id>/<id>` |
| App state | bucket `<project>-<id>-state`, prefix `day2-app/<id>` |
| App edge state | bucket `<project>-tofu-state`, prefix `platform/app/<id>` |
| App backups | `<project>-<id>-backups` |
| Extension downloads | `/downloads/<id>.crx` and `/downloads/updates.xml`, when `extension` is set |
| Extension update URL | `https://<id>.<domains.apps>/downloads/updates.xml`, when `extension` is set |
| Extension signing key | Secret Manager secret `<id>-chrome-extension-signing-key`, when `extension` is set |

The required app check is the status Gitea posts for the required org-scoped
workflow in `<org>/app-ci`. Gitea counts it only when its Actions user produced
it for that source workflow. Neither an app's own workflow nor an API caller
can satisfy it, even with the same context name.

The forge org belongs to the instance: its repositories are exactly `instance`,
`app-ci` and one repository per app.

## Roadmap

1. **Spec and derivation (done).** `day2.json`, its exact parser and
   `day2 instance check`. Nothing consumes the spec yet.
2. **Render inputs.** The platform renders every OpenTofu input (variables and
   backends) from the spec, and instance repositories stop committing them.
   Fields are added only for real choices (size presets, verification cases,
   schedules), never to restate a derived name.
3. **Platform-owned control.** Deployment, promotion, webhook and artifact
   provenance logic moves from instance repositories into `ops/*.roc` recipes
   with narrow Rust capabilities. Instance workflows become rendered shims that
   call `day2 instance plan` and `day2 instance apply`; any edit to a shim fails
   the check.
4. **Fixed forge layout.** Apply reconciles the forge org: the fixed
   repositories, branch protection (apps require the derived app check) and
   webhooks. App CI is the required org-scoped workflow in `<org>/app-ci`, so an
   app repository can neither edit, skip nor impersonate it. App repositories
   keep only their own `day2.json` (`"kind": "app"`).
5. **Closed world.** The check rejects any file outside the fixed layout and
   any org repository the spec does not declare.

**Roc only, throughout.** The platform's existing rule extends to everything it
renders or runs for an instance or app: no shell, Python, JavaScript or YAML
logic. A rendered workflow is a logic-free shim that runs one `day2` command.
The only exception is the VM first-boot scripts named in AGENTS.md. Each step
deletes the scripts it replaces:
- steps 2 and 3 remove instance-repository validators, deployment controllers
  and bootstrap scripts;
- step 4 removes app `.ci/` scripts and their npm toolchain.

Linting app browser JavaScript becomes part of platform admission or is dropped;
app CI does not install npm.
