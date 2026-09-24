# Linux Native Boundaries

`day2-sandbox` is a trusted worker launcher, not an application API or an
operational recipe. The supervisor selects its fixed installed sibling and an
already-admitted worker. The launcher clears the environment, closes inherited
descriptors, requires pipe-based protocol handles, and replaces itself with the
worker only after enforcing every restriction. Missing kernel support fails
closed.

The worker policy requires Landlock ABI 3 filesystem enforcement and a
default-deny seccomp filter. Read access is limited to the worker and exact
glibc runtime files selected from fixed system locations. It does not run `ldd`,
grant a library directory, permit sockets, or permit process/thread creation.
The trusted runtime image must protect those executable and library bytes.

One `execve` handoff is necessary. The inherited filesystem and syscall policy
permits re-executing the same admitted worker or approved loader, but cannot
create another process or relax the restrictions. This is not a claim that all
execution syscalls are unavailable. Filesystem metadata and native timing or
randomness are not made deterministic by Linux confinement; the pure Roc
contract and replay protocol remain separate requirements.

Hard per-worker bounds are 256 MiB address space, 5 CPU seconds, 32 descriptors,
zero new processes, and zero core/file-output bytes. The syscall filter denies
process creation independently of UID-sensitive `RLIMIT_NPROC` behavior. The
parent additionally limits protocol frames and response time, kills and reaps
failed workers immediately, and arranges kernel parent-death termination. Host
deployment still needs aggregate resource limits and a protected installation.

`day2-sandbox-probe` is a host-only executable used by mandatory Linux startup
qualification and real denial tests. It is not linked into any Roc application.
`day2-compiler-sandbox` has a separate trusted-compiler policy and is not installed
in the application runtime image. Existing Roc `ops/Build.roc` and `ops/Check.roc`
remain the operational composition layer.

Focused Linux checks, after building the workspace's host binaries:

```text
cargo test --locked -p day2-sandbox --test isolation
cargo test --locked -p day2 --test linux_worker
```

These are bounded local conformance checks, not proof of hostile multi-tenant
containment or production readiness.
