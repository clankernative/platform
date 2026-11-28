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
day2 instance apply DIRECTORY PLATFORM PLAN_DIRECTORY NEW_DIRECTORY [--agent]
day2 instance release publish DIRECTORY REQUEST NEW_MANIFEST [--agent]
day2 instance release fetch DIRECTORY DIGEST BYTES [--agent]
day2 instance source head DIRECTORY BINDING [--agent]
day2 instance source archive DIRECTORY BINDING COMMIT NEW_ARCHIVE [--agent]
day2 instance source controls ARCHIVE [--agent]
day2 instance source verify-controls DIRECTORY BINDING ARCHIVE [--agent]
day2 instance source checked-artifact DIRECTORY BINDING COMMIT INPUTS NEW_ARCHIVE [--agent]
day2 instance candidate build DIRECTORY BINDING COMMIT NEW_CANDIDATE [--agent]
day2 instance candidate preflight DIRECTORY CANDIDATE [--agent]
day2 instance candidate check DIRECTORY APP CANDIDATE [--agent]
day2 instance candidate native-build JOB [--agent]
day2 instance candidate native-probe JOB [--agent]
day2 instance deploy DIRECTORY PLATFORM APP CANDIDATE NEW_DIRECTORY [--deadline UNIX_SECONDS] [--agent]
day2 instance ci-workflow DIRECTORY [--agent]
day2 ci fetch NEW_DIRECTORY [--agent]
day2 ci store DIRECTORY [--agent]
```

`instance check` reads exactly `DIRECTORY/day2.json` and prints every derived
name. It reads no other file. `instance render` validates the same file and
prints the [OpenTofu inputs](#rendered-inputs) the platform renders from it.
`instance plan` runs a [read-only plan](#plan) of the core roots with those
inputs, each app's day2-app root with its [release inputs](#release-inputs),
and `instance apply` [applies](#apply) them. `instance release`
[publishes and fetches](#release) the qualified SDK releases apps pin, and
`instance source` [reads an app's source and checked artifact](#source) from the
forge, and `instance candidate` [builds, probes and checks](#candidate) an app's
deployment candidate. `ci fetch` and `ci store` are steps of [app CI](#app-ci), the
required org-scoped workflow. [InstanceSpec.roc](../cli/InstanceSpec.roc) is the parser and the
derivation; there is no second schema.

## The spec

```json
{
  "kind": "instance",
  "version": 1,
  "installation": "exampleco",
  "platform": "fe4320b189b98ed08fccc183db3e70aee76319ee",
  "gcp": { "project": "exampleco-tools", "region": "us-central1", "zone": "us-central1-a" },
  "forge": {
    "kind": "gitea",
    "server": "https://git.example.com",
    "org": "tools",
    "oidc": "https://git-oidc.example.com"
  },
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

- Every object is exact. Each field is required, except `forge.oidc`, and unknown
  fields fail.
- `operators` and the `apps` keys must be strictly sorted, so one spec has
  exactly one spelling.
- `platform` is a full commit of `github.com/clankernative/platform`. The
  repository is a platform constant, not an input, so an instance cannot select a
  fork.
- `forge.kind` is `gitea`. Other forges become new closed values, never free text.
- `forge.org` is 2–24 lowercase letters, digits or inner hyphens, starting with
  a letter. It also names the instance's apply identity, `<org>-infra`, and GCP
  caps a service-account ID at 30 bytes.
- `forge.oidc` is the instance's OIDC broker for its forge's Actions jobs
  (git-oidc), `https://<host>` other than `forge.server`. Gitea mints no OIDC
  token itself, and which broker an instance federates through is its own
  choice. App CI's store step requests its token there. It is optional, so an
  instance adds it once its platform pin reads it. `instance check` passes
  without it. `instance ci-workflow` refuses to render without it, and so
  does `ci store` when a push run needs the token request. Only with it do
  the rendered roots hold app CI's [infrastructure](#infrastructure).
- `domains.people` is not a service-account domain: owners become rendered
  admins, and day2-app requires a person among them.
- Operators are lowercase addresses in `domains.people`. Every address is at
  most 256 bytes, the longest authority actor day2 accepts.
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
  `tofu` and every ID starting with `day2` are reserved. Wherever an app ID
  names something, the platform's own name beside it starts with `day2` (the
  `day2-<name>` repositories and the SDK image repository `<registry>/day2`),
  and the shared state bucket `<project>-tofu-state` sits beside each app's
  `<project>-<id>-state`.

## Derived names

Nothing below can be configured, restated or overridden.

| Name | Value |
| --- | --- |
| Apply identity | `<org>-infra@<project>.iam.gserviceaccount.com` |
| Instance repository | `<org>/day2-instance` |
| CI repository | `<org>/day2-ci` |
| Required app check | `<org>/day2-ci: day2 / verification (pull_request)` |
| App CI workload identity | pool `day2-ci`, provider `gitea`, in the `project` root when `forge.oidc` is set; the store step's audience is `https://iam.googleapis.com/projects/<project number>/locations/global/workloadIdentityPools/day2-ci/providers/gitea` |
| App CI principal | `principalSet://iam.googleapis.com/projects/<project number>/locations/global/workloadIdentityPools/day2-ci/attribute.repository_id/<forge ID of <org>/<id>>` |
| App CI token request | `<forge.oidc>/token?v=1&repository=<org>/<id>`, rendered into the store step when `forge.oidc` is set |
| Artifact registry | `<region>-docker.pkg.dev/<project>` |
| SDK image registry | `<region>-docker.pkg.dev/<project>/day2` |
| Shared OpenTofu state bucket | `<project>-tofu-state` |
| Platform root state | bucket `<project>-tofu-state`, prefixes `foundation` (project), `platform/cluster`, `platform/tenancy`, `platform/app` (app edges) and `day2` (roots an instance opts into, such as its CI integration); the security shell's prefix is not derived yet |
| Cluster | `day2`, kube context `gke_<project>_<zone>_day2` |
| Build host | VM `day2-x86-qualify` in `<zone>`, the qualification runner stack's, reached through IAP as the apply identity |
| App admins | the app's `owners` and the apply identity, sorted |
| App repository | `<org>/<id>` |
| App hostname | `<id>.<domains.apps>` |
| App namespace | `app-<id>` (prefix `app-`) |
| App image | `<region>-docker.pkg.dev/<project>/<id>/<id>` |
| App state | bucket `<project>-<id>-state`, prefix `day2-app/<id>` |
| App edge state | bucket `<project>-tofu-state`, prefix `platform/app/<id>` |
| App backups | `<project>-<id>-backups` |
| App CI results | `<project>-<id>-ci`, where the required workflow's store step writes; in the app's `app-edge` root when `forge.oidc` is set |
| App resources | from `size`: `standard` 512 MiB, `large` 2048 MiB; both 1000m CPU, 1024 processes, 4 concurrent requests, 30 s shutdown and a 5 GiB SQLite volume |
| Extension downloads | `/downloads/<id>.crx` and `/downloads/updates.xml`, when `extension` is set |
| Extension update URL | `https://<id>.<domains.apps>/downloads/updates.xml`, when `extension` is set |
| Extension signing key | Secret Manager secret `<id>-chrome-extension-signing-key`, when `extension` is set |

The apply identity is the service account the instance applies its roots and
maintains its apps as. The instance's bootstrap creates it; the platform only
names it. It is one of every app's admins so automatic maintenance can act on
the app after activation. Like every admin it passes the app's owner checks,
which cover audit history, app secrets and SQLite downloads; it already
controls the cluster the app runs on, and it is not among the IAP members. The
`owners` authority selector still admits only the people among the admins.

No two apps may pin the same `extension`: an extension ID is one key, one
update URL and one Admin policy entry.

The required app check is the status Gitea posts for the required org-scoped
workflow in `<org>/day2-ci`. The derived name is the required pattern of that
workflow's registration in the org's Actions settings, not a branch protection
status context: a protection context matches any status by name, so anyone who
can post a status could satisfy it. Through the registration, Gitea counts the
status only when its Actions user produced it for that source workflow, so
neither an app's own workflow nor an API caller can satisfy it. The gate
applies to every branch in the org that has a protection rule, even one with
its own status checks off; a branch with no rule is not gated. Gitea exposes
scoped-workflow registration only in its web settings, so until it has an API,
apply cannot set or read the registration and it is a manual precondition.

The forge org belongs to the instance: its repositories are exactly
`day2-instance`, `day2-ci` and one repository per app. Every repository the
platform owns is named `day2-<name>`, and no app ID starts with `day2`, so an
app can never take a platform name.

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
`qualification-runner`) and roots an instance owns itself. Day2 renders an
app's access policy at release activation from day2-app's `admins`, which this
command renders. `instance plan` and `apply` run every root in this table; a
day2-app root's image, artifact and native admission are its app's
[release inputs](#release-inputs), read when it runs.

### Variables

Each root also carries its variables as one `.tfvars.json` document, named
exactly as its stack declares them. Every value is a derived name, the app's
size preset or a fixed platform constant:

| Root | Rendered variables |
| --- | --- |
| `project` | `project_id`, `region`, `state_bucket_name`, `state_prefixes`; `app_ci` with `forge.oidc` |
| `cluster` | `project_id`, `region`, `zone`, `cluster_name`, `cluster_labels`, `subnet_cidr`, `pod_cidr`, `service_cidr`, `shared_node_pod_pids_limit` |
| `tenancy` | `kube_context`, `app_namespace_prefix` |
| `app-edge` | `project_id`, `region`, `cluster_name`, `cluster_location`, `kube_context`, `app_id`, `namespace_prefix`, `domain`, `iap_members`, `deployer_subjects`, `offsite_backup_readers`, `sqlite_storage_gb`, `storage_class_name`, `kube_dns_service_ip`, `cluster_cidrs`; `app_ci` with `forge.oidc` |
| `day2-app` | `kube_context`, `app_id`, `namespace`, `installation`, `environment`, `hosted_domain`, `admins`, `edge_origin`, `runtime_resources`, `pod_pids_limit`, `backup_bucket` |

- **People.** Only the `operators` deploy an app by hand
  (`deployer_subjects`). They also hold every app's off-site backups and are
  named in its IAP members, which also admit `domain:<domains.people>`.
  `owners` get no infrastructure authority. CI service accounts hold
  project-level grants from the instance's bootstrap and are never listed in
  infrastructure inputs. An app's `admins` are its owners and the apply
  identity: in-app authority, not infrastructure.
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
- extension download routes (step 4);
- per-app extras: runtime identities, secrets, provider credentials, resource
  catalogs and policies, schedules, pod labels and guardrail overrides
  (`container_max`, `resource_guardrails`).

The instance commits those at fixed paths: `gcp/config/<root>.tfvars` for
`project`, `cluster` and `tenancy`, `gcp/config/app-edge/<id>.tfvars` and
`gcp/config/apps/<id>.tfvars`. Instance CI switches to the rendered variables
before an instance deletes its committed copies.

A committed day2-app input may not set a variable the platform owns: a top-level
assignment (a line that starts with the name, bare or quoted, then `=`) of any
rendered day2-app variable, of `security_requirements`, of the release-profile
switches `release_managed` and `rolling_deploys` (with either, the stack would
ignore the release inputs; the platform deploys only the direct single-app
profile), of `workload_name` (a deploy derives `day2-<id>`) or of
`security_shell_contract` (the security shell is not a rendered root yet). That
root fails with `failed_inputs`. OpenTofu receives the direct release profile,
derived workload name and absent security shell at command-line precedence.
A committed `image` and `artifact_id` are
allowed but never used: the release inputs win over them, and an app with no
release is not run. The instance's own deploy controller still reads the
committed `image` as its source binding's image repository until the
controller moves into the platform.

### Release inputs

A day2-app root's image, artifact and native admission come from its app's
release selection, which the instance's deploy controller writes at
`gs://<project>-tofu-state/day2/app-releases/<id>/selection.json` once a
candidate is approved for deployment. The platform only reads it, in-process,
before the root's init:

- **Read.** The object's generation is read first, then its bytes at exactly
  that generation (at most 1 MiB, no duplicate key at any depth). Only a
  describe that finds the object absent means the app has no release yet; any
  other failure (authentication, network, a server error, a timeout, an object
  replaced between the two reads) fails the root. A failure is never absence,
  and nothing ever falls back to a committed image.
- **Shape.** Exactly `version` (the integer 1), `status` (`activating` or
  `ready`) and `candidate`. A rolling selection is refused: the platform
  deploys only the single-app profile. Plans may inspect an `activating`
  candidate while the stack's activation guards still govern what it can plan.
  A normal apply requires `ready`. The deployment controller finishes
  activations and guarded first installs before recording that status.
- **Candidate.** Checked as [`instance candidate check`](#candidate) checks a
  record, never against the app's current `sdk`, so a selection stays
  deployable across an SDK bump until the next release.
- **SDK release.** The candidate's `qualified_release` manifest is read through
  the [release cache](#release) (only the manifest; a hit after the first
  read). It must be `linux_sqlite_single_v1`, pinned under the registry, and
  the candidate's `security_requirements.containment.evidence.receipt_digest`
  must be its native evidence digest.
- **Rendered.** `release.tfvars.json` holds exactly `image`, `artifact_id` and
  `security_requirements`, values as decoded, keys sorted. It is passed after
  the committed and rendered variables, so it wins.
- **No selection.** The root is `unreleased`: it is not initialized, planned or
  applied, and that is not a failure. A new app is installed by its first
  deploy. `delivery: paused` does not change any of this: it gates promotion,
  not the installed release.
- **Failures** are permanent: the root is `failed_release` with the reason in
  its `release.error`, and the command exits 6. Plan and apply are rerun, not
  retried.
- **Reads.** `gcloud storage` with the ambient credentials, as `instance
  candidate` reads release state: the plan identity needs only object read
  access to the state bucket. The release cache is `$DAY2_RELEASE_CACHE`, else
  `~/.cache/day2-platform-releases`, and must be writable: in instance CI the
  job's environment sets `DAY2_RELEASE_CACHE` to a job-local directory.

## Plan

`instance plan DIRECTORY PLATFORM NEW_DIRECTORY` validates `day2.json`, renders
its inputs and runs a read-only OpenTofu plan of every root in apply order:
`project`, `cluster`, `tenancy`, then `app-edge` per app, then `day2-app` per
app.

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
  rendered value wins over a committed copy. With `forge.oidc`, the project
  root and each app edge then plan with [app CI's forge IDs](#infrastructure).
  A day2-app root first reads its [release inputs](#release-inputs) and plans
  with them last; an app with no release selection is `unreleased` and not
  planned.
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
    engine digest and each root's input, plan and show digests, and the
    digest of its changes that a later `instance apply` must match.
  - Each root's `plan.txt` is the plan as OpenTofu prints it, with sensitive
    values masked: what an operator reviews before an apply.
  - The receipt (format 2) also records each day2-app root's `release`: where
    it was read (`selection`, the record's URI, generation, status and digest),
    the candidate record's digest, its source commit, image, artifact, tooling
    image and qualified release, and the digest of its `release.tfvars.json`.
  - Plans hold state values in plain text, so treat the directory like state.
  - Providers are cached once for all roots.
  - Credential material is refused there.
- **Failures.**
  - A root that fails stops only itself; the others still plan. This includes
    a root whose cluster or DNS credentials could not be read, and a project or
    app-edge root whose app CI repository could not be read from the forge
    (`failed_forge`).
  - The command exits 6 if any root failed, or if the plan could not start.
  - A plan with changes exits 0; its receipt lists every changed resource,
    pending move, import and output change.
- **Not planned:** instances with OAuth workload inputs
  (`gcp/config/oauth-workloads.json`), which fail closed; day2-app's OAuth
  runtime is not in the single-app release profile.
- **Known limits:**
  - Interrupting the command does not yet stop OpenTofu or remove the
    temporary kubeconfig directory; an interrupted apply runs its current root
    to completion without a receipt.
  - Any file in `NEW_DIRECTORY` that the plan did not write fails the receipt.
  - Platform CI pins OpenTofu 1.11.5, while instance plans pin 1.12.3, the
    version that writes instance state.

## Apply

`instance apply DIRECTORY PLATFORM PLAN_DIRECTORY NEW_DIRECTORY` runs the same
roots with the same platform, engine, inputs, credentials and output rules as
`instance plan`, and applies them as reviewed. Only operators apply by hand; app
owners never do.

- **Reviewed.** `PLAN_DIRECTORY` is a prior `instance plan` output whose
  `plan.txt` files an operator has read. Its receipt records a digest of each
  root's changes: every resource and output change with its actions, its values
  before, after and known only after apply, and their sensitivity. That plan
  must be for the same platform commit and stacks, the same roots, and the same
  backends, committed inputs and rendered variables. A root whose new plan has
  other changes, or that the reviewed plan could not plan, is refused
  (`refused_unreviewed`) unless it has nothing to change; plan and review again.
  A day2-app root's release is read again and compared root by root: a release
  that changed or appeared since the reviewed plan is `refused_unreviewed`, one
  that disappeared is `failed_release`, and one that only moved from
  `activating` to `ready` with the same candidate still applies.
  The receipt is not signed: this binds the apply to a reviewed plan as a
  process step, not as a security boundary against whoever can write the files.
- **One cycle per dependency.** Each root plans again in the apply, after the
  roots before it. A root whose plan depends on what an earlier root just
  applied, such as tenancy right after the cluster is created, differs from the
  reviewed plan and is refused; plan, review and apply again for the next step.
- **Committed.** The instance must be a clean git checkout whose `day2.json` and
  every committed input equal their bytes at `HEAD`.
- **day2-app roots,** after their release: init, plan, show and apply as every
  other root; an unreleased app's root runs nothing.
- **Each root, in apply order:** init against its rendered backend, plan with
  the state lock, show, then apply exactly that saved plan. The saved plan's
  digest is checked again before apply, and OpenTofu refuses a saved plan whose
  state changed after it was made, so what was shown is what is applied.
- **New roots.** The real backend is always initialized, and the apply creates
  the root's state. The receipt reports the root as new.
- **Locks and time.** Plans and applies wait up to five minutes for a root's
  state lock. A step that holds the lock (the plan and the apply) and overruns
  (15 minutes for a plan, two hours for an apply) is interrupted so OpenTofu can
  save state and release the lock, and is killed only 30 minutes later.
- **Destructive plans are refused.** A plan that deletes, replaces or forgets a
  resource is never applied; the root reports `refused_destroy` and lists those
  resources. Output removals do not count. Destructive changes need a reviewed
  operator path outside this command.
- **Order.** `project`, `cluster` and `tenancy` are shared: every later root
  reads their state. The host runs no root until each shared root before it has
  applied, so a failed or refused shared root stops the apply and the roots
  after it report `skipped`. An `app-edge` root reads only the shared roots, so
  its failure stops only itself and its own app's `day2-app` root, which reads
  the edge's platform contract and is then `skipped`. A failed `day2-app` root
  stops nothing else. The host also requires the roots in that order: the core
  roots on one state bucket with distinct prefixes, and each `day2-app` root on
  its app's own `<project>-<id>-state` / `day2-app/<id>`.
- **Cluster credentials.** If the apply changed the cluster root, or the first
  read failed, the kubeconfig is read again once, before the first root that
  needs it.
- **Mode.** The host action fixes plan, apply or deploy, and the request must
  name the same mode, so `instance plan` can never apply.
- **Output.** As for a plan. Root statuses are `no_changes`, `applied`,
  `unreleased`, `refused_destroy`, `refused_unreviewed`, `skipped` and the
  plan's failures (`failed_credentials`, `failed_forge`, `failed_inputs`,
  `failed_release`, `failed_init`, `failed_plan`, `failed_show`) plus
  `failed_apply`. The command
  exits 6 if any root failed or was refused; an unreleased root is not a
  failure. If the output audit fails after an apply, `receipt.json` is still
  written, with `ok: false` and the audit error.
- **Not applied:** the stacks the spec does not model yet; the instance's own
  tooling still applies those.

### Deploy mode

A deploy (`instance deploy`, the stopped-app sequence) runs one app's day2-app
root in a third host mode. Only the deploy's own host action starts it; plan and
apply can never reach it. Its request holds exactly that root, rendered as plan
and apply render it, and the candidate record file being deployed.

- **Stages:** `release` (the candidate file, checked as a selection's candidate
  is, and the committed-input rule), `init` (always the real backend: on a new
  app's first install there is no state yet, and the apply creates it), an
  optional `target`, then `selected`, `plan` (with the state lock), `show` and
  `apply`.
- **Target.** The `instance.json` the root's plan would publish, which `day2
  platform maintain activate` takes as its target: a plan of only
  `kubernetes_config_map_v1.instance`, without the state lock, into its own plan
  file that is never applied. The stack's release admission is not in that
  resource's dependency graph, so it renders while the new image is not yet
  activated. The string's exact bytes go to `instance.json` (mode 0600) in the
  root's directory, with the plan as `target.json` and `target.txt`. It runs at
  most once, after init and before `selected`; a deploy that installs a new
  app skips it. A failure is `failed_target`.
- **Selected.** Just before the locked plan, the app's selection is read again
  at its exact generation and must name exactly the request's candidate, with
  status `activating` or `ready`; otherwise the root is `failed_release` and
  nothing is planned. The selection is the approval record: there is no
  reviewed plan, and destructive plans are still refused.
- **Deadlines.** Shorter than an apply's, because the app is stopped while it
  runs: a lock wait of up to five minutes within each step, 10 minutes for a
  plan and 15 for the apply, then one minute's grace after an interrupt.
  Each OpenTofu show capture has one minute.
- **Output.** As for an apply, with statuses `no_changes`, `applied`,
  `not_applied` (the deploy stopped before the apply), `refused_destroy` and the
  failures, including `failed_target`. The root's `release` records the
  candidate file and the selection `selected` checked, and `target` the
  rendered `instance.json`'s path, digest and size.

## Release

An app's `sdk` is the digest of a qualified SDK release manifest. `instance
release` publishes and fetches those releases in the instance's state bucket,
one object per blob at `gs://<project>-tofu-state/day2/platform-releases/sha256/<hex>`,
named by its sha256. Both names come from `day2.json`.

- **Profile.** `linux_sqlite_single_v1` carries native and strict-admission
  evidence. `linux_sqlite_rwo_v1` adds a passing same-node rolling receipt
  bound to the exact platform commit, images, native qualification and operator.
- **Images.** Each image is digest-pinned in the artifact registry:
  `<region>-docker.pkg.dev/<project>/<repository>/<name>@sha256:<hex>`, in any
  repository there. They are checked against the registry root, not the SDK
  image registry, because existing releases mirror the SDK under an app's
  repository (such as `home/`), the only one app CI's pull credential can read.
- **Publish.** For operators. `REQUEST` names exactly `profile`,
  `platform_commit`, `runtime` and `tooling` (each `{image, config}`), and the
  paths of the `distribution`, `operator` archive and `native` and `strict`
  evidence, relative to the current directory. The rolling profile also
  requires a `rolling` receipt file with all nine acceptance checks and zero
  availability failures.
  - Before anything is pulled or uploaded, the manifest is built from the
    files' identities and checked, and the distribution and evidence must bind
    it: the same commit, images, workflows, toolchain, distribution, operator
    archive and worker.
  - Both images must pull for `linux/amd64` as their qualified image IDs.
  - Each blob is created only if absent. An object that already exists counts
    only once a download of its exact generation has the same digest, so a
    publication resumes but never replaces bytes.
  - The manifest is written to `NEW_MANIFEST`, which must be new, and published
    last, so an incomplete publication is never selectable. Its bytes are its
    fields sorted, indented two spaces, with a final newline. The command prints
    its digest and size; selecting it is a reviewed `day2.json` change.
- **Fetch.** Reads the approved manifest, then the distribution and evidence it
  names, including the rolling receipt for a rolling release. It checks them
  as a publication does and then installs the operator
  CLI and prints its path and the cached manifest, distribution and evidence. It
  needs only read access to the bucket. It verifies integrity and qualification
  evidence, not approval: approval is the digest the caller pinned.
- **Cache.** `$DAY2_RELEASE_CACHE`, else `~/.cache/day2-platform-releases`.
  - Each blob is at `<hex>` (mode 0444) and each operator at `<hex>.operator/`
    (`cli/` executables 0555, other files 0444). Each is guarded by an exclusive
    lock on `<name>.lock`.
  - A miss downloads the object's exact generation into a temporary directory in
    the cache, and renames it in only once verified and synced.
  - Every hit is verified again, operator files one by one, and a changed file
    is refused, never repaired.
  - An operator is extracted with exactly its fixed files, regular files only,
    each of its qualified size and digest.
  - Instance CI images bake an operator at
    `/opt/day2-platform-releases/<hex>.operator/cli/day2` in this layout.
- **Tools.** `gcloud storage` and `docker` from `PATH`, with the ambient
  credentials, each with a deadline.
- **Failures** after the spec validates exit 6 with `release_failed`; argument
  and spec errors exit 2, 3 or 5, as for the other instance commands.
- **Known limits:** an interrupted release command may leave `download-*` or
  `operator-*` temporary directories in the cache root. They are never treated
  as cache hits.

## Source

`instance source` reads an app's source on the instance's Gitea forge for the
instance's existing deploy controller, value for value: a proof either one
writes is valid to the other.

- **Binding.** `BINDING` is a file holding the controller's source binding for
  one app, exactly: `app`, `repository`, `directory`, `runtime_image`,
  `tooling_image`, `image_repository`, `source` (`forge`, `server`,
  `repository`, `repository_id`, `branch`), `qualified_release`,
  `verification` and `ci_artifact`. It is validated as the controller validates
  it (closed objects, integers that are not booleans, no duplicate keys), then
  against `day2.json`: the source server is `forge.server`, the repository is in
  `forge.org` and is not one of the platform's own repositories (a name that
  starts with `day2-`, in any case), the app is one of `apps`, and
  `qualified_release` and `verification.cases` are that app's `sdk` and
  `verification`. Images must be under the app's directory in the artifact
  registry.
  - The binding is the transitional input from the instance's existing deploy
    controller, not a spec field. Its repository and image names restate names
    `day2.json` derives, so they are checked only for ownership (the org and the
    app): one live app still predates the derived names.
  - The binding goes away when the deploy controller moves into the platform;
    the rename to the derived names happens in roadmap step 4.
- **head.** The repository must still have the bound ID; prints the head commit
  of the bound branch, an exact non-zero commit.
- **archive.** Writes `COMMIT`'s Gitea archive (at most 64 MiB) to
  `NEW_ARCHIVE`.
- **controls.** Reads no spec. Prints the CI-control digest of a source archive
  with one root directory: the sha256 of
  `{"files":[[name,bytes,hex],...],"version":1}`, sorted by name, over every
  non-Markdown file under `.ci/` except the app-owned `.ci/roc.json`, and
  `.gitea/workflows/roc.yml`. `.ci/roc.json`, `.ci/platform-release.json`,
  `.ci/publish_artifact.py`, `.ci/sdk_release.py` and the workflow must be
  present. Budgets: 8192 entries, 16 MiB per entry, 128 MiB in all, 2 MiB per
  control file. Decompression stops at 160 MiB, and a pax or GNU long-name
  header may declare at most 1 MiB, checked before it is read. An operator
  approves an app's controls by pinning this digest as `ci_artifact.digest`.
- **verify-controls.** First, with no network read, the archive's control digest
  must be the approved one and `.ci/platform-release.json` must be the binding's
  qualified release manifest. Then it reads that manifest through the
  [release cache](#release) and requires `.ci/roc.json` to name its platform
  commit, the binding's app root and its verification seed and cases, with only
  safe Roc test paths. A failed bucket read is permanent (exit 6).
- **checked-artifact.** Waits within the job, up to 2100 s and reading at most
  every 20 s (it prints `Waiting for the exact main commit's checked artifact`
  to stderr once), for the newest push run of `roc.yml` on main at exactly
  `COMMIT`, which must be this repository's own run and must succeed. Then its
  one `roc` job of that attempt must have succeeded, its log must carry exactly
  one `DAY2_CHECKED_APP_V1` receipt for this repository, commit, `INPUTS`, SDK
  and verification profile, and the upload it names must be this run's and not
  expired. The ZIP must hold exactly one unencrypted `app.tar.gz` of the
  receipt's size and digest. Only once the run is still the same successful
  attempt is the archive written to `NEW_ARCHIVE`; the receipt carries the proof
  `{version, run, attempt, job, receipt}` with the log's receipt exactly as
  decoded. This is the path without `forge.oidc`, unchanged.
  - With `forge.oidc`, the same steps read [app CI's stored
    artifact](#deploy-reads) instead, for every app, and the app repository's
    own workflow, its jobs, logs and Gitea artifacts are never read. The receipt
    carries app CI's proof, version 2;
    [cli/fixtures/source-receipt-app-ci.json](../cli/fixtures/source-receipt-app-ci.json)
    pins its shape.
- **Forge reads.** Only the instance's forge, with `AUTODEPLOY_SOURCE_TOKEN`,
  else `GITEA_TOKEN`, sent as `Authorization: token`, never printed. Each read
  has one 90 s window up to its response headers, then 90 s for each read of its
  body, and is bounded: 1 MiB for JSON, 64 MiB for an archive, 8 MiB for a log
  and 130 MiB for an artifact ZIP. Redirects are never followed, except one 302
  from an artifact's ZIP route to an https URL on the forge itself,
  `storage.googleapis.com` or a bucket host under it, with no userinfo, port or
  fragment; only that artifact's same-origin `/raw` route receives the token.
- **ZIP reader.** Hand-written for the one layout the upload transport writes:
  one stored or deflated entry at offset 0, its data descriptor if it has one,
  one central header and the end record, with no extra fields, comments,
  prepended bytes or ZIP64. Local and central headers must agree, a descriptor
  must repeat the central CRC and sizes, and the CRC-32 is checked.
- **Files.** New files are created exclusively and synced; an existing file is
  refused before anything is read from the forge. If a write fails, the partial
  file the command created is removed, and nothing else.
- **Failures** after the spec validates exit 6 with `source_failed` and the
  controller's own message (`source_metadata_http_<code>`,
  `source_repository_identity_changed`, `source_branch_commit_invalid`,
  `source_archive_http_<code>`, `checked_artifact_download_http_<code>`,
  `checked_artifact_redirect_refused`, `main CI did not succeed; ...` and the
  rest). A platform host that cannot start or crashes also exits 6.
- **Retryable failures** exit 7 with `source_unavailable`, `"retryable": true`
  and the code `checked_main_artifact_not_ready` or
  `source_temporarily_unavailable`: HTTP 408, 429 or 5xx, a failed connection, a
  disconnect before the response headers, a failed or short body read, or a
  timeout. Unlike the earlier controller, which treated a disconnect before the
  headers or during a body as permanent, these are retryable on purpose: a
  network blip during a 64 MiB archive or a 130 MiB ZIP must not block a
  deployment until an operator steps in. Argument and spec errors exit 2, 3
  or 5.
- **Known limits:**
  - Only Gitea, and only the instance's own forge.
  - Some archive shapes are refused that other tar readers interpret
    differently; git never writes them, so only a malicious forge could. They
    are:
    - a pax global header with a record other than `comment`, or after a
      pending extension, and an extension with no member after it;
    - a GNU long name or link beside a different pax path or link path, two
      pax headers for one member, and a duplicate `path`, `size` or
      `linkpath` record;
    - `GNU.sparse.*` records, and a pax `size` that is not canonical decimal or
      differs from the header's;
    - a name with a NUL, and a non-ustar header with a prefix field;
    - sparse and Solaris entries;
    - data on a link, device, FIFO or directory entry.
  - JSON the earlier controller accepted is refused when it holds:
    - a float or boolean where an integer is required;
    - an integer of 2^64 or more;
    - nesting deeper than 32 levels.
  - A `.ci/roc.json` with a UTF-8 byte-order mark, or in UTF-16, is refused; the
    earlier controller accepted it.

## Candidate

`instance candidate` is the instance deploy controller's candidate build, value
for value: a record either one writes serves the other. It runs in the
instance's CI job, from the job image's linux-x86_64 CLI, with the apply
identity's credentials and the forge token of [`instance source`](#source).

- **Binding.** `build` takes the same transitional binding file as `instance
  source`, checked the same way against `day2.json`. A binding without
  `qualified_release`, `verification` and `ci_artifact`, one of the earlier
  controller's shapes that compiled the app on the build host, is refused:
  candidates are only ever built from the exact main commit's checked artifact.
- **Records.** In the state bucket, under
  `gs://<project>-tofu-state/day2/app-releases/<app>/`:
  - `candidates/<binding digest>/<commit>.json`: the candidate for a binding and
    a source commit;
  - `checked-inputs/<binding digest>/<inputs hex>.json`: the same shape, for the
    binding and the app's checked source inputs;
  - `builds/<binding digest>/<commit>.log`: the native build's log, or a reuse
    proof.

  A record's bytes are its fields with sorted keys, `", "` and `": "`
  separators, ASCII escapes and a final newline (Python's `json.dumps(value,
  sort_keys=True)`); the binding digest is the sha256 hex of the binding encoded
  the same way, without the newline. A record is read at its exact generation
  and created only while absent (`--if-generation-match=0`); an object that
  cannot be read for any reason other than absence is a refusal. Logs and reuse
  proofs replace what is there.
- **build.**
  - The stored candidate record for the binding and `COMMIT`, validated as
    `check` does and required to be this binding's and commit's, is the answer.
  - Otherwise: the commit's archive and its source inputs (below); its CI
    controls, verified as `verify-controls` verifies them, before any cached
    result can be used; then the checked-inputs record. A cached result must be
    for this binding and inputs and checked at its own commit. For its own
    commit it is the answer as it is; for another commit the answer is the same
    record with this commit and this commit's build log, which receives the
    reuse proof (`kind: checked-input-reuse`, the binding digest, both commits,
    the inputs, the checked log, the image and the artifact).
  - Otherwise: the checked artifact, as `checked-artifact` fetches it (with
    `forge.oidc`, from [app CI](#deploy-reads), and only a version 2 proof is
    accepted; without it, only version 1); the
    binding's release manifest, distribution and evidence through the [release
    cache](#release), bound as a fetch binds them (the operator is not
    installed); then a native build on the build host (below). Its result must
    be this binding's, commit's, inputs' and checked artifact's; its log is
    archived and the checked-inputs record is created.
  - A record's `ci_artifact` is the proof it was built from, and `check`,
    deploys and release reads check either version exactly.
  - With `forge.oidc`, a build writes only version 2 records. A cached
    checked-inputs record of version 1 is kept as it is but never reused or
    written over: the artifact is read from app CI and built again, and only the
    commit's candidate record is created.
  - Version 1 records written before `forge.oidc` was set stay valid. They are
    grandfathered under the trust model they were built with, not a downgrade
    path: no new version 1 record can be created once `forge.oidc` is set. A
    record is created once, at a path keyed by the binding digest and the commit
    or the source inputs, so a version 1 record is never replaced; refusing it
    would fail every app's current selection in plan and apply until the app is
    rebuilt and selected again.
  - Last, the candidate record is created if it is new, and its exact bytes are
    written to `NEW_CANDIDATE`. The receipt names the outcome (`stored`,
    `reused` or `built`), the record, the build log, the image and the artifact,
    and, for a native build, the bytes and milliseconds the copy to the build
    host took.
- **Source inputs.** The sha256 of `{"files":[[name,size,hex],...],"version":1}`
  (compact, sorted keys) over the app's files below its directory, in path-part
  order, with tarfile's (surrogateescape) names. The archive is read as
  `instance source` reads one; a member is in the app when the directory is `.`
  or the member is the directory or below it, and a top-level `.ci/` or
  `.gitea/` member never is. Every member counts against 16 MiB each, 128 MiB in
  all and 8192 entries; only directories, regular files and links outside the
  app are allowed; a duplicate file, a file where a directory is or a file below
  a file is refused; at least one file and `<directory>/App.roc` must exist.
- **Build host.** The derived build host, through `gcloud compute ssh` and `scp`
  over IAP as the apply identity. A private job directory
  `/tmp/day2-build-<32 hex>` (`/tmp/day2-sdk-probe-<32 hex>` for `preflight`)
  is created mode 0700 and filled with the request, its inputs and the running
  CLI's four `cli/` files, compressed in transit over the authenticated SSH
  channel; the CLI runs there as root. Each gcloud command runs in its own
  process group, killed whole at its deadline. A failed command's stderr (the
  remote run's included) goes to the job's stderr, the job log, never to an
  error, a receipt or a record. Once the directory exists, a build's failure
  copies its build log back to the build log path as private evidence (`build
  failed; private evidence: <uri>` on stderr). The directory is then removed,
  unless the session there may still be running (this job's deadline passed, or
  ssh lost the connection): it is left in place, said so, and that session ends
  by its own budget.
- **Budgets.** The deploy job allows the remote build 5400 s and gives the build
  host's session a budget of 4800 s, from its start: the slot wait (at most
  900 s) and every Docker command (each at most its own deadline, 60 s to
  3600 s) fit in what is left, and no step starts after it. The 600 s margin
  covers SSH and IAP setup, starting the CLI and the cleanup after a failure (at
  most 120 s of operation logs, then two Docker removals of at most 120 s
  each). A probe has 300 s and a budget of 180 s (a probe lock wait of at most
  60 s, the login and the probe).
- **native-build.** On the build host, as root, in the job directory (which must
  be private):
  - every other job file is checked against the request's identity first
    (which catches a short or corrupt copy; the running CLI cannot vouch for
    itself, and logs its own files' digests), then the binding's release, images
    and native evidence; each file read later is checked again on the bytes
    read;
  - one of two build slots is taken: an exclusive lock on
    `/var/lock/day2-app-builds/<slot>` within 900 s, container
    `day2-app-slot-<slot>`, reaped first;
  - the source inputs are computed again and the checked artifact's provenance
    is validated; the artifact is extracted for transport only (one directory,
    regular files of mode 0444 or 0555, at most 4096 entries and 128 MiB);
  - the binding's tooling image runs with the native profile (no network,
    6 GiB, 4 CPUs, 512 processes, private cgroup namespace, bounded tmpfs), its
    own ABI seed restored when it has one; its maintenance protocol is proven.
    Files copied out of the image (the ABI seed and the Dockerfile) land in the
    slot's root-only staging directory and are used only when each is a single
    regular file within its bound, checked and made read-only on its opened
    descriptor; anything else, a link included, is refused;
    its `linux-artifact-security` admits the artifact against the release's
    native evidence; the artifact is packaged on the runtime image with the
    tooling's own Dockerfile, pushed, and its one exact digest read back;
  - `result.json` and `build.log` belong to the directory's owner, mode 0600.
    The log starts with the promotion header and the provenance proof, then
    names the CLI files' digests. After a Docker failure up to 16 native
    operation logs are kept, and the error is logged last.
- **native-probe.** The tooling image's maintenance protocol, under the probe's
  own lock (`/var/lock/day2-app-builds/probe`) and from its fresh private Docker
  configuration, without a build slot. `preflight` runs it for a candidate
  record before any app is stopped.
- **Registry token.** The build host's own service account token from its
  metadata server, given to `docker login` on stdin only, twice per build (the
  second just before the push). The Docker configuration is in a root-only
  directory under `/run/day2-app-builds` (tmpfs), wiped when a slot or the
  probe lock is taken and on every exit, and the token's bytes are overwritten
  once used. The token never appears in an argument, a log, a receipt or an
  error.
- **Build host directories.** The lock directory `/var/lock/day2-app-builds`
  and `/run/day2-app-builds` must be root-owned with mode 0700; otherwise every
  build is refused with what they are.
- **check.** Reads only `day2.json` and the record: the record's exact fields,
  its binding, its native admission, its checked artifact's provenance, its
  app-local images and its build log path, for `APP`, against the derived
  registry and state bucket only, never the app's current `sdk`. Unlike the
  earlier controller, it also requires the binding's source to be an app
  repository on the instance's forge, as `instance source` does:
  `forge.server`, `forge.org`, and no `day2-` repository. `build` checks stored
  and cached records the same way, and so does `preflight`; the build host
  refuses a `day2-` repository too.
- **Failures** after the spec validates exit 6 with `candidate_failed` and the
  controller's own message (`builder returned another source or toolchain`,
  `checked-input cache identity changed`, `native build pool wait budget
  exhausted`, `SDK lacks the required offline admission protocol; ...` and the
  rest). State reads and writes, IAP copies and commands and Docker failures are
  permanent. Only the forge reads of `instance source` stay retryable: exit 7
  with `source_unavailable`.
- **Known limits:**
  - JSON the earlier controller accepted is refused when a record or the
    tooling's admission output holds a duplicate key, a float (`-0`
    included, which Python reads as the integer 0), a boolean where an integer
    is required or an integer of 2^64 or more. The admission output is checked
    before anything is pushed.
  - The CLI copied to the build host must run there: the job image's operator
    and the build host share the Debian 13 / glibc family.
  - A killed `build`, or one whose session may still be running, leaves its job
    directory on the build host's tmpfs until the next reboot; the next build in
    its slot reaps the container.
  - Build logs have no size bound, as before.

## Deploy

`day2 instance deploy DIRECTORY PLATFORM APP CANDIDATE NEW_DIRECTORY` deploys a
selected, preflighted candidate to a single-replica app. Run it with the
instance's apply identity, tools, and a clean checkout, using the CLI built
from `day2.json`'s `platform` commit. The instance controller owns selection
writes, event delivery, promotion policy and the rolling deploy path.

The deploy checks the record against the instance forge, the app, the registry
and the candidate's qualified SDK release. The candidate's verified SDK CLI
runs maintenance using its matching tooling image. A `ready` or `activating`
selection in the instance state bucket must name the exact candidate before
backup, before activation and before the locked apply.

- **Fresh deploy.** Render the target `instance.json` from the `day2-app` root
  before the first stop. Back up and restore the current app, archive the
  backup, then activate the candidate with the rendered target. Apply the
  saved plan for `day2-app/<app>`, wait for rollout and verify the running
  workload, pod, bound artifact and scheduled backup job. Readback also
  compares `instance.json` with the target used for activation.
- **Previously activated or already serving the target.** Apply or confirm the
  same selected candidate, wait for rollout, then verify readback. The
  maintenance backup and activation steps are skipped on these paths.
- **First install.** When the StatefulSet is absent, apply only if app-edge
  has created the app's `data` claim and it is still unbound. A claim with a
  bound volume requires an operator to restore the existing workload and run
  activation against it.

Archives use create-only objects in the app backup bucket under
`deployments/<commit>/<attempt>/{before,after}-activation/`. The deploy checks
each uploaded object's name, size and CRC32C against its local manifest.
`NEW_DIRECTORY` must be new, private and outside the instance and platform
checkouts. It contains the deploy receipt, the app root's receipt and logs,
the operator's output and a private kubeconfig. A successful receipt also
appears as `result.receipt` with `--agent`.

With `--deadline UNIX_SECONDS`, the deploy checks the upper bound on the
remaining steps just before the first stop or roll. If the job cannot fit the
remaining steps, the command exits 7 before it makes a change. The fresh path
reserves up to 9,420 seconds after this check. Account for build, preflight,
and target rendering separately when allocating CI job time.

| Exit | Agent code | Meaning |
| --- | --- | --- |
| 0 | | The selected release passed rollout and readback. |
| 6 | `deploy_failed` | A permanent refusal, a pre-fence failure, or a verified deploy whose final archive failed. Follow the archived maintenance journal if the workload was not restored. |
| 7 | `deploy_unavailable` | A retryable read or insufficient time before the first change. |
| 8 | `deploy_fenced` | The migration fence was crossed, or the resulting workload state is uncertain. Keep the same candidate and recover or roll forward. |

An active checkpoint with a migration fence needs the operator's recovery
journal. This command can resume a rollout for a candidate that the operator
already stamped as activated, but it does not persist the exact request bytes
needed to resume an interrupted migration. Use `day2 platform maintain
recover` with the archived journal when the error requests recovery. The
failure-injection and first-install checks use local substitutes for the
operator, kubectl, gcloud, and the app-root runner. Production rollout and
recovery behavior still needs live qualification.

## App CI

App CI is the [required check](#derived-names): one org-scoped workflow in
`<org>/day2-ci` runs for every app repository, so an app repository can neither
edit, skip nor impersonate it. Its job runs three `day2` commands and nothing
else. The YAML holds no logic beyond choosing the check's optional base (see
[Workflow](#workflow)).

1. `day2 ci fetch DIRECTORY` reads the run and its trees from the forge.
2. `day2 ci check DIRECTORY/head [DIRECTORY/base] CASES DIRECTORY/out`
   checks them, reading only local trees (see the CLI's
   [README](../cli/README.md)).
3. `day2 ci store DIRECTORY` stores what the check wrote in the app's CI
   bucket.

The bucket and the federation it trusts are rendered roots' resources (see
[Infrastructure](#infrastructure)).

### Workflow

`day2 instance ci-workflow DIRECTORY` prints the workflow file,
`.gitea/scoped_workflows/verification.yml` in `<org>/day2-ci`, rendered from
`day2.json` by a pure renderer
([InstanceCiWorkflow.roc](../cli/InstanceCiWorkflow.roc)). The host reads two
inputs for it, with the ambient Google credentials. `--agent` returns the file in
`result.workflow`. [cli/fixtures/ci-workflow.yml](../cli/fixtures/ci-workflow.yml)
pins the fixture instance's file.

- **Inputs.** The project's number (`gcloud projects describe`), which the
  provider audience names. Each app's tooling image and tooling distribution:
  the digest-pinned `tooling.image` and the `distribution` digest of the
  release manifest its `sdk` selects, read through the [release cache](#release)
  and pinned under the instance's registry, as a binding's `tooling_image` is.
- **Name.** The workflow is `day2` with one job, `verification`, so the
  statuses are `day2 / verification (pull_request)` and
  `day2 / verification (push)`.
- **Triggers.** `pull_request` and `push` to `main`.
- **Repositories.** A map, keyed by app repository and rendered inline into
  each expression that needs it, gives each app its tooling image, `verification`
  cases, CI bucket, provider audience, `sdk` and tooling distribution. The
  job's `if:` runs only for
  repositories in the map. The map is never a repository or org variable: a
  repository variable overrides an org one, so an app could redirect its own CI.
- **Job.** `runs-on: [self-hosted, <org>, linux, X64]`, the SDK tooling image
  as the container, with the apps' earlier `roc` job's options: 6 GiB, 4 CPUs,
  512 processes and the bounded tmpfs mounts over `/workspace/platform/artifacts`
  and `/workspace/platform/crates/worker/generated`. `ci check` initializes that
  generated mount from the image's reviewed ABI seed, and the build still
  requires its glue to equal it. `permissions` are `contents: read` and
  `id-token: write`, as the instance CI workflow has; fetch reads the merge
  base from the event, so no pull request permission is needed.
- **Steps.** fetch, check and store, each one `/workspace/platform/cli/day2`
  command in `/tmp/day2-ci`. Only fetch receives `GITHUB_TOKEN`, and only store
  `ACTIONS_ID_TOKEN_REQUEST_TOKEN` (both `${{ secrets.GITHUB_TOKEN }}`) and the
  store inputs. The step `env:` holds every store input, the token request
  `ACTIONS_ID_TOKEN_REQUEST_URL: <forge.oidc>/token?v=1&repository=${{
  github.repository }}` included: Gitea mints no OIDC token itself, and a
  value in a step's own `env:` is one an earlier step cannot replace through
  `$GITHUB_ENV`.
- **Logic.** The check step passes `/tmp/day2-ci/base` only for
  `pull_request` (`${{ github.event_name == 'pull_request' && ... || '' }}`),
  because `ci check` takes its base as an optional positional. That expression
  is the one choice the YAML makes.
- **Trust.** Check runs the app's code (its Roc build and tests, its
  verification campaign) in the same container as the other steps, and the
  platform claims no hostile-code containment. Keeping the tokens out of the
  check step's `env:` therefore stops only accidental exposure. Code that
  check runs could still:
  - rewrite `DIRECTORY`, including the artifact, the receipt and the record;
  - set variables for later steps through `$GITHUB_ENV` (such as
    `LD_PRELOAD`);
  - replace platform files that are writable in the image;
  - read a token that a runner exports to every step. act's
    `ACTIONS_RUNTIME_TOKEN` is unverified here.

  So a pull request run's artifact cannot be trusted, and store keeps none
  ([Store](#store)). Main's push run runs reviewed code. Store checks a
  push run's record, receipt and inputs for consistency, not for tampering,
  and it ignores proxy variables. Running check as another user, with the
  platform and the run directory read-only except `out/`, is the open fix.

### Fetch

`ci fetch NEW_DIRECTORY` is the job's first step and the only one, with the
store step, that receives the job token.

- **Run.** It reads the Gitea Actions variables `GITHUB_EVENT_NAME`,
  `GITHUB_EVENT_PATH`, `GITHUB_REPOSITORY`, `GITHUB_SERVER_URL`, `GITHUB_SHA`,
  `GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT`, all required, and
  `GITHUB_WORKFLOW_SHA` when the runner exports it. A scoped run's
  repository, commit and token are the consuming app repository's.
  `GITHUB_REPOSITORY` must be `<org>/<id>` for an app ID, never a `day2-`
  repository. A refusal names a variable, never its value.
- **Events.** The payload must describe the same repository and commit.
  - `pull_request`: the head is the pull request's head commit. The base is
    its merge base, as the apps' earlier routing used (`git merge-base` of the
    base and head commits). The event names it: `pull_request.merge_base`, the
    merge base Gitea computed. Gitea's compare API reports none. A pull request
    whose head repository is not the base repository is refused: a fork's, or
    one whose head repository was deleted. Gitea's AGit-flow pull requests
    have the base repository as their head, so they are not refused.
  - `push`: only to `refs/heads/main`, with no base, so every lane runs and
    the run produces its artifact.
  - Any other event is refused.
- **Forge reads.** The job token comes from `GITHUB_TOKEN`, which the workflow
  sets for this step alone, and goes only to the run's own repository on
  `GITHUB_SERVER_URL`. It is never printed. The repository the token reads must
  have the payload's ID and name. A failed connection or HTTP 408, 429 or 5xx is
  retried as the instance workflows wait for git-oidc: a pause of 2 s doubling
  to 16 s plus up to as much jitter, while the pause and 5 s more fit in 120 s.
  Any other status fails at once with [`instance source`](#source)'s code.
- **Trees.** Each tree is its commit's Gitea archive, read by the code deploy
  uses (`instance_source::Forge::archive`, at most 64 MiB). It is unpacked into
  `NEW_DIRECTORY/head` or `NEW_DIRECTORY/base` by the walk that computes deploy's
  source inputs, so `app/` in the head tree has exactly the source inputs a
  deploy of that commit computes. The report prints them. Both trees get the
  walk's refusals: one root directory, safe paths, deploy's budgets, and only
  directories, regular files and symlinks. A symlink is refused inside the
  head's `app/`, where deploy refuses it. Outside `app/` it is kept with its
  target unresolved, as Home's top-level module links are. Beyond deploy,
  every path is written once and nothing is written below a file or a link,
  so no entry leaves the tree. A name must be UTF-8. A file is 0755 when any
  execute bit is set and 0644 otherwise.
- **Record.** `NEW_DIRECTORY/event.json` is written last. It holds exactly
  `format` (1), `repository`, `repository_id`, `event`, `head`, `base` (null for
  a push), `pull_request` (null for a push), `run`, `attempt` and
  `workflow_commit` (null when the runner does not export it).
  `NEW_DIRECTORY` must be new and is created 0700.
- **Failures** exit 6 with `ci_fetch_failed` and the host's message. A forge
  read that stayed transient for 120 s exits 7 with `ci_fetch_unavailable`,
  `"retryable": true` and `source_temporarily_unavailable`, as
  [`instance source`](#source) does.

### Store

`ci store DIRECTORY` is the job's last step. For main's push run it stores the
artifact `ci check` wrote to `DIRECTORY/out`, write-once, in the app's CI bucket:

```text
gs://<project>-<id>-ci/<sdk>/<source inputs>-<cases>/<run>/<attempt>/artifact.tar.gz
gs://<project>-<id>-ci/<sdk>/<source inputs>-<cases>/<run>/<attempt>/receipt.json
```

`<sdk>` is the hex of the app's selected release manifest digest, `<source
inputs>` the hex of the receipt's source inputs and `<cases>` its verification
cases. `<run>` and `<attempt>` are the run's.

- **Only push runs.** A `pull_request` record stores nothing, whether or not
  `ci check` wrote an artifact. The command reports "pull_request runs are
  verified, not stored" and succeeds. It reads no store input, mints no token
  and reaches no service. A push run checks every lane, so a missing artifact
  is a failure. The workload identity provider admits only `push` runs on
  `refs/heads/main`, so git-oidc needs no pull request grant for this audience.
- **Not a goal: reusing a pull request's result on main.** The check step runs
  the pull request's code in the job's container. That code can rewrite
  `DIRECTORY` and set later steps' variables through `$GITHUB_ENV` (see
  [Workflow](#workflow)), so a pull request run's artifact is its author's
  evidence, not the platform's. Main's push run, of reviewed code, builds
  and stores its own. Reuse waits until check is isolated from store.
- **Run.** `DIRECTORY/event.json` must be this run's record: its repository,
  event, head commit, run, attempt and workflow commit are checked against the
  step's own `GITHUB_*` variables.
- **Inputs.** They come from the rendered workflow, never from the app
  repository, and are read only when there is an artifact:
  - `ACTIONS_ID_TOKEN_REQUEST_URL` must be exactly
    `https://<host>/token?v=1&repository=<the run's repository>`, with no
    port, credentials or other query.
  - `DAY2_CI_BUCKET` must be `<project>-<id>-ci` for the run's app.
  - `DAY2_CI_AUDIENCE` is the workload identity provider's audience,
    `https://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`.
  - `DAY2_CI_SDK` is the app's selected release.
  - `DAY2_CI_DISTRIBUTION` is that release's tooling distribution.
- **Output.** `DIRECTORY/out` must hold exactly `app.tar.gz` and
  `receipt.json`.
  - The receipt is a complete run's: every lane, seed 42, 4 to 100 cases,
    and an archive of the file's size.
  - Its `sdk_distribution` must be `DAY2_CI_DISTRIBUTION`.
  - Its `source_inputs` must be those of `DIRECTORY/head/app`, recomputed.
- **Credential.** git-oidc mints an OIDC token as the instance workflows
  request it: `GET ${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=<audience>` with
  `Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}`, reading `.value`. A failed connection,
  408, 429 or 5xx is retried with the wait [fetch](#fetch) uses; any other
  answer fails at once with git-oidc's reason. Google STS exchanges the token
  for a federated access token: the audience is the provider's resource name
  (`//iam.googleapis.com/...`), the scope only
  `https://www.googleapis.com/auth/devstorage.read_write`. There is no service
  account and no key. No token is ever printed, and proxy variables are
  ignored.
- **Uploads.** Each is a multipart upload with `ifGenerationMatch=0`, so an
  object is never replaced. The object's custom metadata holds `run`,
  `attempt`, `head`, `event` and, when the runner exports it,
  `workflow_commit`. Uploads go in this order:
  1. `artifact.tar.gz`. Its bytes are read once, and their digest must still
     be the receipt's, immediately before they are sent.
  2. `receipt.json` last, the commit marker, unchanged since it was checked.

  The response must name the object in the bucket with its size, a generation
  and the metadata sent.
- **Failures** exit 6 with `ci_store_failed`: a refused mint or exchange, a
  precondition failure (this run and attempt already stored), a changed
  artifact or receipt, anything. The required job fails with it.

### Infrastructure

`instance plan` and `apply` render app CI's federation and results buckets
only when `day2.json` sets `forge.oidc`. Without it, no root renders an app CI
variable, nothing is read from the forge, every root plans exactly as before,
and `instance render`, `plan` and `apply` say why under `APP CI`.

- **Federation, in `project`.** Workload identity pool `day2-ci` and its OIDC
  provider `gitea`, once per instance: the project layer is the instance's
  identity, applied first, so the pool exists before any app edge names its
  principal sets. The pool impersonates no service account and grants nothing.
  - Issuer `forge.oidc`; the only allowed audience is the provider's canonical
    URL, which `ci store` requests.
  - Attribute condition, exactly: `assertion.is_scoped == 'true' &&
    assertion.workflow_repository_id == '<day2-ci ID>' &&
    assertion.repository_owner_id == '<org ID>' &&
    assertion.workflow_ref.startsWith('<org>/day2-ci/.gitea/scoped_workflows/verification.yml@')
    && assertion.event_name == 'push' && assertion.ref == 'refs/heads/main'`.
  - Mapping: `google.subject = 'gitea:' + assertion.sub` (git-oidc's
    `repo:<org>/<app>:ref:refs/heads/main`, at most 76 bytes for an app
    repository, under Google's 127) and `attribute.repository_id`, the app
    repository's ID.
- **Results bucket, in each `app-edge`.** `<project>-<id>-ci`, rendered from
  the same derivation `ci store` and the workflow use, in the instance region:
  uniform bucket-level access, public access prevention enforced, no
  versioning, soft delete off (0 s), lifecycle deletion 30 days after an
  object is written, no `force_destroy`. It keeps `prevent_destroy`, so its
  global name is never released while a build may read it; removing
  `forge.oidc` once buckets exist fails those app edges' plans.
- **Grants, per bucket, and nothing else.** `roles/storage.objectCreator` and
  `roles/storage.objectViewer` for the app CI principal, the principal set of
  the app repository's ID in `day2-ci`; `roles/storage.objectViewer` for the
  apply identity, which builds candidates.
- **Forge IDs.** The trust is pinned to native IDs, discovered on every run and
  never configured. After the credentials, plan and apply read
  `<org>/day2-ci` (its ID and its owner's) for the project root and
  `<org>/<id>` (its ID) for each app edge, through `GET
  /api/v1/repos/<repository>` on `forge.server` with `AUTODEPLOY_SOURCE_TOKEN`,
  else `GITEA_TOKEN`, as [`instance source`](#source) reads. Each must exist
  under exactly that name in the org; a redirect is not followed. The IDs reach
  OpenTofu as the root's `forge.tfvars.json`, after the rendered variables.
  - The token must read `day2-ci` and every app repository. A job's own token
    (`GITHUB_TOKEN`, passed as `GITEA_TOKEN`) reads only its own repository,
    so instance CI must set `AUTODEPLOY_SOURCE_TOKEN`.
  - The reads share one retry budget, the wait [fetch](#fetch) uses: a failed
    connection, a timeout, a failed or short body read, 408, 429 or 5xx
    retries the reads still unanswered. Retries begin only within 120 s, and
    each read is bounded by its own 90 s windows.
  - A repository that cannot be read fails its root (`failed_forge`, reason
    in its `forge.error`, which also says when no token was set); in an apply,
    a failed project root stops the apply. So every app's repository must be
    at its derived name before `forge.oidc` is set.
  - A repository deleted and created again has a new ID. Its bucket grants are
    then replaced, which apply refuses as destructive: that change needs the
    reviewed operator path.
- **Owned variables.** `app_ci` (rendered) and `app_ci_forge` (read) belong to
  the platform: a committed `project` or `app-edge` input with a line that
  assigns either, however indented, fails its root (`failed_inputs`, reason in
  its `inputs.error`). A nested key of the same name fails it too.
- **Adoption.** A `day2-ci` pool or `<project>-<id>-ci` bucket made by hand
  before `forge.oidc` is set must be imported, or the first apply fails because
  it already exists.

### Deploy reads

With `forge.oidc`, `instance source checked-artifact`, and so `instance
candidate build`, reads every app's checked main artifact from its results
bucket, with the same steps and the same interface. There is no per-app switch,
and the app repository's own workflow artifacts are never read. Without
`forge.oidc`, the earlier path runs unchanged and its outputs are byte for byte
the same.

- **Repository.** The binding's repository must be the derived `<org>/<id>`:
  `ci store` keys results by the run's repository name.
- **Custody** is the forge's run record, never a commit status, which any writer
  on the app repository can post. `run` reads `<org>/day2-ci` (exactly that
  name, owned by the org) for its ID, then lists
  `GET /repos/<org>/<id>/actions/workflows/verification.yml/runs` with
  `scoped_workflow_source_repo_id=<that ID>`, `event=push`, `branch=main` and
  `head_sha=<COMMIT>`. Runs of other commits are ignored. Every run listed for
  `COMMIT` must be app CI's: `is_scoped` true, `workflow_repository_id` and
  `workflow_repository` the CI repository's ID and name, `path`
  `verification.yml@refs/heads/main`, `event` `push`, `head_branch` `main`, the
  app repository's ID, an attempt and an exact `workflow_commit_sha`; anything
  else fails closed. The newest such run (the highest run ID) is the one: its
  current attempt replaces any earlier one. Until that attempt is terminal the
  step waits as the earlier path does; a terminal attempt that did not succeed
  is a refusal. Its run ID, attempt, `started_at` and `completed_at` are taken
  from that record.
- **Objects.** `gs://<project>-<id>-ci/<sdk>/<source inputs>-<cases>/<run>/<attempt>/`
  with `<sdk>` the binding's release, `<source inputs>` those of `COMMIT`'s
  archive (`INPUTS`) and `<cases>` the binding's. `job` reads `receipt.json`,
  `artifact` describes `artifact.tar.gz` and `download` reads it, each at the
  generation described. Each object's custom metadata must be exactly `run`,
  `attempt`, `head` (`COMMIT`) and `event` (`push`), plus `workflow_commit`, the
  run's, when the runner exported it, and its server-set `timeCreated` must fall
  inside the attempt's start and stop. The forge keeps whole seconds, so the
  comparison is in whole seconds.
- **Receipt.** A complete run's, checked as `ci store` checks it, bound to
  `INPUTS`, the binding's verification profile and the tooling distribution of
  the binding's release (read through the [release cache](#release)). The
  artifact must be the receipt's size and digest.
- **Reads** are the apply identity's, which holds object read access only: its
  token from `gcloud auth print-access-token`, held in memory. Each is one GCS
  JSON API request under its own total deadline (60 s for metadata, 900 s for a
  download), and each reply is closed data: the selected fields, at most 16 KiB,
  decoded exactly, or exactly the bytes asked for. A missing object is waited
  for within the same 2100 s as the run, printing the same waiting line once;
  past the deadline it is retryable (exit 7), as are a failed connection, a
  timeout, 408, 429 and 5xx. Any mismatch is a refusal.
- **attempt.** The run is read again and must still be the same successful
  attempt with the same window; only then is the archive written.
- **Proof** (version 2, exact): `version`, `repository`, `commit`, `run`,
  `attempt`, `started_at` and `completed_at` as the forge reported them (kept
  in UTC, whole seconds),
  `workflow` (`repository`, `repository_id`, `commit`), `objects` (`receipt`
  and `artifact`, each `uri`, `generation` and `time_created`) and `receipt`,
  the receipt as stored. Every check that needs no forge or bucket is checked
  again wherever a record is: the build host, `instance candidate check`,
  deploys and release reads.
- **Clocks.** The window compares the forge's clock with Google's. The receipt
  is the job's last write, so the margin before the recorded stop is small; a
  skew larger than it is a permanent refusal, and the deploy is retried after a
  new push.
- **Rollout.** After `forge.oidc` is set, an app gets a new candidate only once
  app CI has run for a push to its main. The instance's own deploy controller,
  outside this repository, still validates candidate records as the earlier
  Python controller wrote them; it must accept version 2 proofs before
  `forge.oidc` is set, or move into the platform first.

## Selection

`day2 instance selection DIRECTORY APP [--agent]` reads the durable
single-replica release selection for an app declared in `day2.json`. Run it
with read access to the instance's private state bucket. It reports
`unreleased` if the object is absent. An existing selection is read at its
exact generation, and the command checks the saved candidate's app, forge,
artifact and provenance using the same validator as `instance candidate check`.

For an activating selection, the command also reads the saved
`blocked-activation` record. A matching commit and image mean that recovery
requires explicit approval of the selected commit. Malformed records and
failed reads fail the command. The command writes no state and makes no
promotion decision.

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
3. **Platform-owned control (started: slice 1, publishing and fetching SDK
   releases with `day2 instance release`; slice 2, reading app sources and
   checked artifacts with `day2 instance source`; slice 3, building, probing and
   checking deployment candidates with `day2 instance candidate`; slice 4a,
   planning and applying each app's day2-app root with its release inputs, and
   the deploy mode a deploy runs it in; slice 4b, deploying one selected
   non-rolling candidate with `day2 instance deploy`; slice 5 started with
   checked release selection and recovery reads).** Deployment, promotion, webhook and
   artifact provenance logic moves from instance repositories into `ops/*.roc` recipes
   with narrow Rust capabilities. Instance workflows become rendered shims that
   call `day2 instance plan` and `day2 instance apply`; any edit to a shim fails
   the check.
4. **Fixed forge layout (started: [app CI](#app-ci)'s `ci check`, `ci fetch` and
   `ci store`, its rendered workflow, `instance ci-workflow`, and its federation and results buckets in the
   rendered roots).** Apply reconciles the forge org: the fixed
   repositories, a protection rule on every app's default branch (which is what
   subjects it to the required org workflow) and webhooks. App CI is the required org-scoped workflow in `<org>/day2-ci`, so an
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
