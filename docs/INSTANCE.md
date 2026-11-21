# Instance repositories

An instance is one company's installation of this platform. Its repository is
data: one authored file, `day2.json`, at the repository root. The platform owns
every name, layout rule, validator, workflow and recipe that consumes it, at the
platform commit the spec pins. Two companies' instance repositories differ only
in their `day2.json` values.

```console
day2 instance check DIRECTORY [--agent]
day2 instance render DIRECTORY [--agent]
day2 instance plan DIRECTORY PLATFORM NEW_DIRECTORY [--agent]
day2 instance apply DIRECTORY PLATFORM NEW_DIRECTORY [--agent]
```

`instance check` reads exactly `DIRECTORY/day2.json` and prints every derived
name. It reads no other file. `instance render` validates the same file and
prints the [OpenTofu inputs](#rendered-inputs) the platform renders from it.
`instance plan` runs a [read-only plan](#plan) of the core roots with those
inputs, and `instance apply` [applies](#apply) them. [InstanceSpec.roc](../cli/InstanceSpec.roc) is the parser and the
derivation; there is no second schema.

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
| Platform root state | bucket `<project>-tofu-state`, prefixes `foundation` (project), `platform/cluster`, `platform/tenancy`, `platform/app` (app edges) and `day2` (roots an instance opts into, such as its CI integration); the security shell's prefix is not derived yet |
| Cluster | `day2`, kube context `gke_<project>_<zone>_day2` |
| App repository | `<org>/<id>` |
| App hostname | `<id>.<domains.apps>` |
| App namespace | `app-<id>` (prefix `app-`) |
| App image | `<region>-docker.pkg.dev/<project>/<id>/<id>` |
| App state | bucket `<project>-<id>-state`, prefix `day2-app/<id>` |
| App edge state | bucket `<project>-tofu-state`, prefix `platform/app/<id>` |
| App backups | `<project>-<id>-backups` |
| App resources | from `size`: `standard` 512 MiB, `large` 2048 MiB; both 1000m CPU, 1024 processes, 4 concurrent requests, 30 s shutdown and a 5 GiB SQLite volume |
| Extension downloads | `/downloads/<id>.crx` and `/downloads/updates.xml`, when `extension` is set |
| Extension update URL | `https://<id>.<domains.apps>/downloads/updates.xml`, when `extension` is set |
| Extension signing key | Secret Manager secret `<id>-chrome-extension-signing-key`, when `extension` is set |

No two apps may pin the same `extension`: an extension ID is one key, one
update URL and one Admin policy entry.

The required app check is the status Gitea posts for the required org-scoped
workflow in `<org>/app-ci`. The derived name is the required pattern of that
workflow's registration in the org's Actions settings, not a branch protection
status context: a protection context matches any status by name, so anyone who
can post a status could satisfy it. Through the registration, Gitea counts the
status only when its Actions user produced it for that source workflow, so
neither an app's own workflow nor an API caller can satisfy it. The gate
applies to every branch in the org that has a protection rule, even one with
its own status checks off; a branch with no rule is not gated. Gitea exposes
scoped-workflow registration only in its web settings, so until it has an API,
apply cannot set or read the registration and it is a manual precondition.

The forge org belongs to the instance: its repositories are exactly `instance`,
`app-ci` and one repository per app.

## Rendered inputs

`instance render` lists the core roots every instance applies to serve apps, in
apply order, with each root's platform stack and state backend:

| Root | Stack | State |
| --- | --- | --- |
| `project` | `deploy/gke/stacks/project` | `<project>-tofu-state` / `foundation` |
| `cluster` | `deploy/gke/stacks/cluster` | `<project>-tofu-state` / `platform/cluster` |
| `tenancy` | `deploy/gke/stacks/tenancy` | `<project>-tofu-state` / `platform/tenancy` |
| `app-edge`, per app | `deploy/gke/stacks/app-edge` | `<project>-tofu-state` / `platform/app/<id>` |
| `day2-app`, per app | `deploy/gke/stacks/day2-app` | `<project>-<id>-state` / `day2-app/<id>` |

Every value is a derived name. `foundation` predates the `platform/<root>`
scheme and stays because moving it is a state move. The renderer emits no root
the spec cannot yet describe: the installation security shell
(`security-shell-edge`, `security-shell`), opt-in integrations under
`deploy/integrations/` (such as `gitea-instance-ci`), optional stacks (such as
`qualification-runner`) and roots an instance owns itself. Access policy
(day2-app's `readers`, `writers` and `authority`) is rendered at release
activation (step 3), not by this command.

### Variables

Each root also carries its variables as one `.tfvars.json` document, named
exactly as its stack declares them. Every value is a derived name, the app's
size preset or a fixed platform constant:

| Root | Rendered variables |
| --- | --- |
| `project` | `project_id`, `region`, `state_bucket_name`, `state_prefixes` |
| `cluster` | `project_id`, `region`, `zone`, `cluster_name`, `cluster_labels`, `subnet_cidr`, `pod_cidr`, `service_cidr`, `shared_node_pod_pids_limit` |
| `tenancy` | `kube_context`, `app_namespace_prefix` |
| `app-edge` | `project_id`, `region`, `cluster_name`, `cluster_location`, `kube_context`, `app_id`, `namespace_prefix`, `domain`, `iap_members`, `deployer_subjects`, `offsite_backup_readers`, `sqlite_storage_gb`, `storage_class_name`, `kube_dns_service_ip`, `cluster_cidrs` |
| `day2-app` | `kube_context`, `app_id`, `namespace`, `installation`, `environment`, `hosted_domain`, `edge_origin`, `runtime_resources`, `pod_pids_limit`, `backup_bucket` |

- **People.** Only the `operators` deploy an app by hand
  (`deployer_subjects`). They also hold every app's off-site backups and are
  named in its IAP members, which also admit `domain:<domains.people>`.
  `owners` get no infrastructure authority. CI service accounts hold
  project-level grants from the instance's bootstrap and are never listed.
- **Sizes.** The app resources row above. Every preset has the same volume
  until resizing is designed: moving an app to a size with a smaller volume
  would try to shrink its PVC, which cannot shrink.
- **Constants.** The cluster network (nodes `10.10.0.0/20`, pods
  `10.20.0.0/16`, services `10.30.0.0/20`, kube-dns `10.30.0.10`), the 1024
  pod PID limit, the `app-sqlite-rwo` storage class and the `production`
  environment. An input at its stack default is rendered only when another
  rendered value is computed from it, so two roots always read the same
  constant.
- **`state_prefixes` is byte-exact.** Each key and value names a conditional
  IAM binding, so changing one replaces that binding.

Everything else is still committed by the instance until the spec can describe
it:
- identity lists that may name its CI service accounts
  (`state_reader_members`, `state_writer_members`,
  `platform_automation_usernames`);
- node counts, the Cloud Asset API opt-in and other project or cluster choices;
- discovered IDs (`project_number`, `cloudflare_zone_id`,
  `backend_service_name`);
- images and artifact IDs;
- access policy (step 3) and extension download routes (step 4);
- per-app extras: runtime identities, secrets, provider credentials, resource
  catalogs and policies, schedules, pod labels and guardrail overrides
  (`container_max`, `resource_guardrails`).

The instance commits those at fixed paths: `gcp/config/<root>.tfvars` for
`project`, `cluster` and `tenancy`, `gcp/config/app-edge/<id>.tfvars` and
`gcp/config/apps/<id>.tfvars`. Instance CI switches to the rendered variables
before an instance deletes its committed copies.

## Plan

`instance plan DIRECTORY PLATFORM NEW_DIRECTORY` validates `day2.json`, renders
its inputs and runs a read-only OpenTofu plan of the core roots in apply order:
`project`, `cluster`, `tenancy`, then `app-edge` per app.

- **Platform.** `PLATFORM` is a git repository that contains the `platform`
  commit. Each root plans a private copy of `deploy/gke/stacks/<stack>` read
  as that commit's git objects. Local or ignored files, replace refs,
  attributes and filters cannot change it. The CLI and its platform host must
  carry exactly that commit's rendering sources (`InstanceSpec`,
  `InstanceRender`, `Names`, `JsonValue`); anything else is refused.
- **Engine.** OpenTofu 1.12.3, found on `PATH` and admitted only if it is the
  official release binary for the host (Linux amd64 or macOS arm64). It is
  copied into `NEW_DIRECTORY` and checked again before every operation, with a
  private CLI configuration, so ambient provider overrides never apply.
- **Inputs.** Each root initializes against its rendered backend and plans with
  a copy of its committed `.tfvars` file, then its rendered variables, so a
  rendered value wins over a committed copy.
- **New roots.** Each root first lists its exact state object, which needs only
  object read access. If the listing is empty, the root plans against an empty
  local state and is reported as a new root, so no state is created. A missing
  bucket or a denied listing fails the root.
- **Credentials.** Google credentials come from the environment. Only these
  variables pass through: `PATH`, `HOME`, Google credential and account
  selection (including impersonation), and proxy and CA settings. A private
  kubeconfig for the cluster is built from derived names in a temporary
  directory that is removed afterwards. It overrides any committed
  `kubeconfig_path`. App edges read the DNS provider token from the project's
  `cloudflare-api-token` secret, in memory only, and only their plan step sees
  it.
- **Read-only.** It never takes a state lock, never applies, and never writes
  into the platform checkout or the instance. `NEW_DIRECTORY` must be outside
  both and outside the instance's repository, and is created with mode 0700.
- **Output.**
  - Each root's plan, its `tofu show -json` output and logs go to
    `NEW_DIRECTORY`, with `receipt.json`, which records the stacks tree, the
    engine digest and each root's input, plan and show digests.
  - Plans hold state values in plain text, so treat the directory like state.
  - Providers are cached once for all roots.
  - Credential material is refused there.
- **Failures.**
  - A root that fails stops only itself; the others still plan. This includes
    a root whose cluster or DNS credentials could not be read.
  - The command exits 6 if any root failed, or if the plan could not start.
  - A plan with changes exits 0; its receipt lists every changed resource,
    pending move, import and output change.
- **Not planned:**
  - `day2-app`, whose image and artifact inputs come from the release
    controller (step 3);
  - instances with OAuth workload inputs (`gcp/config/oauth-workloads.json`),
    which fail closed.
- **Known limits:**
  - Interrupting the command does not yet stop OpenTofu or remove the
    temporary kubeconfig directory.
  - Any file in `NEW_DIRECTORY` that the plan did not write fails the receipt.
  - Platform CI pins OpenTofu 1.11.5, while instance plans pin 1.12.3, the
    version that writes instance state.

## Apply

`instance apply DIRECTORY PLATFORM NEW_DIRECTORY` runs the same roots with the
same platform, engine, inputs, credentials and output rules as `instance plan`,
and applies them. Only operators apply by hand; app owners never do.

- **Each root, in apply order:** init against its rendered backend, plan with
  the state lock, show, then apply exactly that saved plan. OpenTofu refuses a
  saved plan whose state changed after it was made, so what was shown is what
  is applied.
- **New roots.** The real backend is always initialized, and the apply creates
  the root's state. The receipt reports the root as new.
- **Locks.** Plans and applies wait up to five minutes for a root's state lock.
- **Destructive plans are refused.** A plan that deletes, replaces or forgets a
  resource is never applied; the root reports `refused_destroy` and lists those
  resources. Output removals do not count. Destructive changes need a reviewed
  operator path outside this command.
- **Order.** `project`, `cluster` and `tenancy` are shared: every later root
  reads their state. The host runs no root until each shared root before it has
  applied, so a failed or refused shared root stops the apply and the roots
  after it report `skipped`. An `app-edge` root reads only the shared roots, so
  its failure stops only itself.
- **Mode.** The host action fixes plan or apply, and the request must name the
  same mode, so `instance plan` can never apply.
- **Output.** As for a plan. Root statuses are `no_changes`, `applied`,
  `refused_destroy`, `skipped` and the plan's failures plus `failed_apply`. The
  command exits 6 if any root failed or was refused.
- **Not applied:** `day2-app` and the stacks the spec does not model yet; the
  instance's own tooling still applies those.

## Roadmap

1. **Spec and derivation (done).** `day2.json`, its exact parser and
   `day2 instance check`. Nothing consumes the spec yet.
2. **Render inputs (started: core-root backends and derived variables, a
   read-only `instance plan` and `instance apply` of the core roots except
   `day2-app`).** The platform renders every
   OpenTofu input (variables and backends) from the spec, and instance
   repositories stop committing them.
   Fields are added only for real choices (size presets, verification cases,
   schedules), never to restate a derived name.
3. **Platform-owned control.** Deployment, promotion, webhook and artifact
   provenance logic moves from instance repositories into `ops/*.roc` recipes
   with narrow Rust capabilities. Instance workflows become rendered shims that
   call `day2 instance plan` and `day2 instance apply`; any edit to a shim fails
   the check.
4. **Fixed forge layout.** Apply reconciles the forge org: the fixed
   repositories, a protection rule on every app's default branch (which is what
   subjects it to the required org workflow) and webhooks. App CI is the required org-scoped workflow in `<org>/app-ci`, so an
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
