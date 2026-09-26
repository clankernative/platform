# Linux SQLite Single-Node Profile

Qualification is evidence-bound: require a successful scoped Linux receipt for
the captured platform inputs and explicit operator-reviewed security admission
for each deployed artifact. An image build alone does not qualify this profile.
Without that receipt, treat the profile as unqualified. The qualification output
records the tested environment and its limits; it is not production identity or
hostile-code certification.

This is one platform-owned runtime image and one container per installed app.
There are no app Dockerfiles, entrypoints, package installers or deployment scripts.
The app artifact contains its Roc worker, admitted HTML/CSS/JS and assets.
Company configuration and branding remain independent instance inputs.

## Existing Workflows

`ops/Build.roc` still owns build order. `ops/Check.roc` still owns examples,
generated cases, replay, duplicates, invalid-input checks, properties and command
draining. Linux changes native capabilities beneath those workflows:

- `xtask::native_toolchain` selects the reviewed compiler pin and linker inputs.
  Linux ARM64 and x86_64 GNU/glibc are the build targets, both on the official
  September 12 compiler that macOS also uses.
- `day2-compiler-sandbox` confines the pinned compiler to platform-owned staging
  inputs/outputs, without sockets or subprocesses. Compiler threads are allowed.
- `day2-sandbox` confines app workers before execution. It requires fully enforced
  Landlock ABI 3, a seccomp syscall allowlist, hard resource limits, a clean
  environment, closed inherited descriptors and parent-death cleanup. Failure
  never falls back to unsandboxed execution.
- `day2-serve` hosts HTTP and durable command invocations. It does not compile apps,
  run CI or interpret arbitrary operator scripts.
- `day2-package` atomically exports one app and declarative Compose configuration.
  It does not invoke Docker, create cloud resources or copy database contents.

The [Landlock kernel documentation](https://docs.kernel.org/userspace-api/landlock.html)
describes the kernel boundary. This spike requires enforcement, not best-effort
fallback. Denial probes provide evidence for specific restrictions, not
certification against hostile native code or kernel vulnerabilities.

## Instance Contract

Add `runtime` to the app's existing `instance.json` binding:

```json
"runtime": {
  "kind": "linux_sqlite_single_v1",
  "resources": {
    "memory_mib": 512,
    "cpu_millis": 1000,
    "process_limit": 64,
    "http_concurrency": 4,
    "shutdown_seconds": 30
  }
}
```

There is no second company config. Replicas, arbitrary database paths and runtime
commands are not configurable in this type. Resource values are bounded nonzero
types. Local-development bindings can omit `runtime`; deployment cannot.
App execution needs no `background` binding. The HTTP server owns the local
command scheduler; accepted invocations resume from SQLite after restart.

At start the container reads its own cgroup and refuses to serve when a memory,
CPU or process bound is looser than the profile, or missing. Docker bounds a
container's processes, so the process bound is observed there. Kubernetes bounds
a pod's processes one cgroup above the container, which a container in its own
cgroup namespace cannot see. There the operator declares it instead:

```json
"process_limit": 1024,
"process_limit_enforced_by": "pod"
```

With `pod`, the container's own `pids.max` is not held to the profile: it may be
`max`, or a looser value the container runtime writes itself (containerd 2 on
GKE writes a node-derived one, such as `629145`). Memory and CPU are
always observed. The declaration is the operator's promise that the orchestrator
bounds the whole pod at no more than `process_limit` — on GKE, a node pool
`pod_pids_limit` (1024 at least) no greater than it. See
[the GKE deployment](../gke/README.md).

The artifact must be built for Linux. The exporter rejects macOS workers rather
than pretending an addressed native artifact is portable across operating systems.

## Build And Package

Prerequisites: a native ARM64 or x86_64 Linux Docker engine with Landlock and seccomp enabled,
cgroup v2 with private container cgroup namespaces, Docker Compose, and enough
free disk space for both Rust build profiles. On macOS these kernel capabilities
belong to the VM, not macOS. Both Docker base images are pinned by digest.

The operator-owned qualification entrypoint runs on the source host against its
Linux Docker engine. The architecture is the engine's own — ARM64 on macOS,
x86_64 on an x86_64 Linux host — and selects the matching compiler pin in
`toolchains/`. It is never chosen and never emulated: a seccomp filter or
Landlock ruleset qualified under Rosetta or QEMU says nothing about the target.

```text
cargo run --locked -p xtask -- qualify-linux artifacts/linux-qualification-NEW_RUN
```

`ops/Linux.roc` captures the platform, Reports and GoLinks inputs, builds those captured
bytes into the platform-owned tooling/runtime images, and calls the normal
`platform check` workflow inside a bounded Linux container. It also builds and
checks GoLinks there, the first application deployed on this platform, and records
its artifact in the receipt; the runtime suites still use Reports. It then runs native
confinement, worker, HTTP, and backup suites and exercises packaged runtime
startup, authorization changes, restarts, company isolation, and recovery.
The output directory must be new. Only a complete successful campaign whose
source inputs still match can write `qualification.json`; failures preserve
private diagnostic evidence without a passing receipt. Receipts bind the exact
artifact, worker, images, toolchain pin and platform-input fingerprint. This is
scoped runtime qualification, excluding the custom formatter and complete
platform verification gate. It does not establish production authentication or
certify hostile native code containment.
Reports is the profile's application witness. Other apps still require their own
artifact admission and app checks; this campaign does not test their business
workflows.

After a successful campaign, exercise explicit security admission separately:

```text
cargo run --locked -p xtask -- strict-linux QUALIFICATION_DIRECTORY NEW_OUTPUT
```

This private Roc recipe consumes the actual completed `qualification.json`, checks
that the platform and Reports sources still match, and packages a new disposable
installation with the native reviewed security requirements. An explicit local
operator applies those requirements before the first server startup. The smoke
test checks a protected query in the exact qualified runtime image, then requires
the same artifact and launcher to deny a different supervisor binary with
`security_runtime_mismatch`. Its generated fixture login stays inside the native
harness. It writes `strict-admission.json`; it neither changes the original
receipt nor contributes checks to the 21-step qualification campaign.

The tooling image omits development debug symbols and incremental caches to
reduce image storage; release behavior and the app checks are unchanged.

From the platform repository, build the tooling image:

```text
docker build --target tooling -f deploy/linux-sqlite/Dockerfile -t day2-tooling:spike .
```

The tooling image contains the existing `cli/day2` distribution. Its compiler
requires a finite memory cgroup and bounded tmpfs mounts for both staging and
generated ABI files. Roc reserves sparse memory larger than its physical usage;
tmpfs quotas bound real output independently of those virtual reservations.
Use a disposable container, with `APP_SOURCE` replaced by an absolute app path:

```text
docker run -d --name day2-linux-tooling --memory=6g --cpus=4 --pids-limit=512 --cgroupns=private --tmpfs /workspace/platform/artifacts:rw,exec,nosuid,nodev,size=1g --tmpfs /workspace/platform/crates/worker/generated:rw,nosuid,nodev,size=64m --mount type=bind,source=APP_SOURCE,target=/workspace/reports-app,readonly day2-tooling:spike sleep infinity
docker exec day2-linux-tooling cli/day2 platform check /workspace/reports-app 42 16
```

Artifacts and receipts land under `/workspace/platform/artifacts`. Copy the
content-addressed artifact and check evidence out after the check passes and
before stopping this container: its tmpfs is intentionally disposable. Never
deploy the mutable staging directory. No second Linux build/check recipe is
introduced. The container's bootstrap and source-build privileges do not belong
to runtime images or applications.

Build the generic runtime image and inspect its immutable local image ID:

```text
docker build --target runtime -f deploy/linux-sqlite/Dockerfile -t day2-runtime:spike .
docker image inspect day2-runtime:spike --format '{{.Id}}'
```

Explicitly bind that Linux artifact and the runtime profile in an operator
instance, then export to a new directory:

```text
cargo run --locked -p day2 --bin day2-package -- INSTANCE APP ACTOR IMAGE_DIGEST PUBLISHED_PORT NEW_DIRECTORY
docker compose -f NEW_DIRECTORY/compose.json up -d
docker compose -f NEW_DIRECTORY/compose.json logs app
```

`IMAGE_DIGEST` is the actual `sha256:...` image ID, not a tag or placeholder.
Export rejects existing outputs, unapproved actors, missing policy,
wrong-architecture workers, unsupported execution bindings and symlinked inputs.
`deployment.json` binds the instance, artifact, Compose bytes and image digest.
Only the selected app is exported; source-control/CI credentials are not copied.
Export neither changes the original instance nor copies its SQLite data.
Migration, activation and restore remain explicit platform operations.

Apps with live provider grants also require `--provisioning PRIVATE_INPUT_JSON`.
Use the explicit [packaged credential provisioning workflow](../../docs/LIVE-INTEGRATIONS.md#packaged-linux-provisioning)
before starting the app. It mounts reviewed external private files read-only and
registers them through an opt-in, network-disabled tooling container using the
same state volume and UID as the runtime. App-facing exports retain no control
administrators, and neither the package nor image contains token bytes.

## Runtime Guards

- Non-root container, read-only root filesystem and inputs, all capabilities
  dropped, and no privilege escalation.
- Internal port 8080; generated publication is `127.0.0.1:PUBLISHED_PORT`.
  HTTP validates that exact advertised authority.
- Private 64 MiB `/tmp`, executable only because the supervisor materializes
  verified worker bytes there. One private executable is shared across a loaded
  artifact's sessions; each session still starts a fresh sandboxed process.
  Source identity and private executable bytes, type and permissions are checked
  on each use. This avoids accumulating deleted executable copies in tmpfs while
  Linux releases their storage. The app worker cannot write to it.
- SQLite, WAL, session secret and journals persist in `.state` on a local named
  volume. Its name includes the installation/environment/app scope digest.
  An exclusive file lock rejects a second server using the same app state.
  This is not a distributed lease or network-filesystem HA.
- Startup checks actual finite cgroup memory, CPU and process limits against the
  instance, not just JSON settings. See [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/).
- Startup runs the sandbox denial probe before admitting HTTP. `/health/live`
  and `/health/ready` return redacted status. The native health checker needs
  no shell, curl or package manager in the runtime image.
- SIGTERM stops request admission and new command execution, then drains active work
  within the deadline. Committed pending intents remain in SQLite for restart.

The restart policy is `unless-stopped`; an unhealthy status alone does not make
Compose restart a still-running process. Supervisor failures terminate the
process. Deleting the volume is a destructive operator action, not part of restart.

## Online Backup In The Runtime Image

The runtime image carries `/usr/local/bin/day2-backup`, the one operator
executable beside `day2-serve`, `day2-health` and `day2-inspect`:

```text
day2-backup INSTANCE_JSON APP NEW_OUTPUT_DIRECTORY
```

It runs the same native operations as `day2 platform backup`
(`ops/Backup.roc`), in the same order and with no logic of its own: an online
snapshot of the app database and its local provider stores through SQLite's
backup API over read-only connections (15 s deadline each), a copy of the
active artifact, then verification of the stored bundle. It does not take the
`.state/<app>.serve.lock` lease, so it runs beside a serving `day2-serve` on the
same state volume; the volume must be writable because SQLite maintains the
WAL's shared-memory file even for readers. The output directory must be new.
On success it prints one JSON line (`backup`, `app`, `installation`,
`environment`, `scope`, `artifact`, `database`, `provider_databases`,
`authority`, `verified: true`); any failure exits non-zero and leaves no
`backup.json`, so a partial directory is never a backup. Restore stays a
tooling-image operation (`day2 platform restore`, which verifies again). As
with every online snapshot, each store is individually consistent;
cross-store coherence needs quiesced provider work.

Qualification runs it from the runtime image beside the serving runtime
(`linux-runtime-restore`: read-only root, no network, no capabilities, the
serving volume) and restores its bundle with the tooling image, requiring the
same domain and journal contents. The `linux-backup` suite runs the CLI test
too. The GKE reference schedules it hourly
([Backups](../gke/README.md#scheduled-off-cluster-backups)).

## Authentication And Limits

Authentication is **disposable local-operator authentication**, not enterprise
SSO. The actor must already be authorized. Startup logs a short-lived sign-in
link; treat its token as sensitive. GET shows a confirmation form and POST
consumes the grant, avoiding consumption by link previews. Expired/consumed links
cannot choose another actor. Restart prints a fresh link. Do not expose this
deployment through a public reverse proxy or tunnel.

App presentation, commands, queries, mandatory audit events and journal-backed
commands use the same host code as local development. App workers cannot inspect
SQLite. The trusted supervisor and machine operator can: this does not create an
externally immutable audit store or solve encryption at rest and backup retention.

Outside this increment: enterprise identity/TLS, Temporal in this deployment
profile, distributed SQL/HA, remote hosted CI isolation, Kubernetes/cloud IaC,
fleet rollouts, automatic migration/activation, x86_64 qualification and a reviewed
Linux distribution of the custom formatter. These are implementation gaps,
not architectural prohibitions.

Before promotion, complete the real Linux build, confinement and HTTP tests;
command/audit persistence across graceful and forced restarts; two-company
volume isolation; and backup/restore using the existing operations.
