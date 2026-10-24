# Freetool executor bridge

The Freetool SDK contract lets Roc compose a complete bounded execution plan
while the native Platform host supplies trusted installation, artifact, actor,
and operation identity. The host translates the typed request through the
`FreetoolExecutor` adapter to a private executor service. The executor owns its
SQLite manifests, receipts, results, and encrypted user-entered credentials; it
does not make application decisions or accept a browser-supplied target.

## Deployment boundary

On GKE, `day2-app.loopback_services` runs the executor as a companion container
in the day2 pod. Both containers share the pod network namespace, so the host
connects to `http://127.0.0.1:<port>`. The companion listens only on loopback;
its container port is not added to the app Service or Ingress. The connection
contract also rejects endpoints other than an explicit `127.0.0.1` address.

The executor config is a private JSON file from an exact Secret Manager version.
The GKE Secret Manager CSI add-on reads it with the app runtime identity; an init
container copies it into memory as a regular UID/GID 10001 file with mode `0600`.
Only the companion mounts that file, read-only, as its `serve` argument. Do not
put config bytes in tfvars or Terraform state. List both its Secret Manager ID
and the transport-key secret ID in `app-edge.runtime_secret_ids`.

The companion's durable directory is a subpath of the existing app PVC under
`.state/companions/`. The state init container gives that subpath to UID 10001;
the service runs non-root with a read-only root filesystem, no capabilities,
`RuntimeDefault` seccomp, and no privilege escalation. `day2-app` requires a
digest-pinned image and bounded CPU/memory requests equal to limits. Configure a liveness command that probes the service's loopback health path
from inside the container; a Kubernetes HTTP probe would target the pod IP, not
the companion's loopback listener. `health_check.command` names an in-image
program that accepts the full health URL as its final argument; the stack
appends `http://127.0.0.1:<port><path>`.

The off-cluster `day2-backup` bundle includes every declared companion state
subpath. Companion snapshots are bounded to 20 GiB, 16,384 regular files,
65,536 filesystem entries, and ten nested directories. When `state_database_file`
is set, the backup uses SQLite's online backup API for that database (including
the executor's WAL contents), copies other regular files, and pins the complete
subtree digest in backup manifest format 3. `day2 platform restore` verifies and restores these trees under
`.state/companions/`; the scheduled upload's `COMPLETE` marker includes their
files. Set `backup_scratch_size_limit`, the app PVC size, and the backup deadline
for the combined app database, provider stores, companion stores, and artifact.
Other non-SQLite companion files are copied as ordinary files; if a service needs
a transactional snapshot of mutable non-SQLite data, it must provide its own
quiescence or snapshot contract before relying on that copy.

## Instance contract and GKE values

The following is a complete shape for one Freetool connection, one approved
executor resource, one capability policy, the HMAC provider credential, and the
generic companion input. Replace the example scope, IDs, secret versions,
fingerprints, artifact, addresses, and policy owner with reviewed deployment
values. A resource target's `scope` is a tagged object: use
`{ kind = "explicit", allowed_resources = ["resource_id"] }` for a non-empty
explicit set, or `{ kind = "any_app_resource" }` for Freetool resources this
bound app registers at run time. The latter does not grant another app access
to the service. The executor independently restricts execution to its configured
HTTP/PostgreSQL targets, approved DNS IPs, and read-only PostgreSQL policy; the
Platform binding limits which app may invoke which service and which credential
managers may enroll secrets. Policy-slot `allowed_resources` still names the
exact Platform resource catalog entries, not Freetool business resource IDs.

```hcl
resource_catalog = {
  version = 1
  connections = {
    freetool_executor = {
      revision = 1
      provider = "freetool_executor"
      live = {
        provider       = "freetool_executor"
        endpoint       = "http://127.0.0.1:43210"
        credential_ref = { id = "freetool_transport_key", revision = 1 }
      }
    }
  }
  resources = {
    freetool_resource = {
      revision   = 1
      connection = { id = "freetool_executor", revision = 1 }
      target = {
        kind                = "freetool_executor"
        service_id          = "freetool_executor"
        scope               = { kind = "any_app_resource" }
        credential_managers = ["operator@wonderly.com"]
      }
    }
  }
  policies = {
    freetool_access = {
      revision             = 1
      owner                = "operator@wonderly.com"
      delegates            = []
      # Requires Platform PR #245, merged to main as c4047a21.
      actors               = ["domain:wonderly.com"]
      allowed_apps         = ["freetool"]
      max_duration_seconds = null
      slots = {
        freetool_executor = {
          kind = "freetool_executor_resource"
          allowed_resources = [{ id = "freetool_resource", revision = 1 }]
          actions = [
            "freetool_fingerprint",
            "freetool_status",
            "freetool_result_page",
            "freetool_register",
            "freetool_execute",
          ]
          limits = {
            max_request_bytes         = 65536
            max_response_bytes        = 1048576
            max_calls_per_invocation = 32
          }
          budgets = []
        }
      }
    }
  }
  budgets = {}
}

resource_policies = [
  {
    policy    = { id = "freetool_access", revision = 1 }
    operation = "freetool.run"
    bindings  = { freetool_executor = { id = "freetool_resource", revision = 1 } }
  }
]

credential_operator = "operator@wonderly.com"
provider_credentials = [{
  credential_ref = { id = "freetool_transport_key", revision = 1 }
  secret_version = "projects/123456789/secrets/freetool-transport-key/versions/1"
  fingerprint    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}]

loopback_services = {
  freetool = {
    image                 = "us-central1-docker.pkg.dev/PROJECT/freetool/executor@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    port                  = 43210
    config_secret_version = "projects/123456789/secrets/freetool-executor-config/versions/1"
    state_subpath         = "companions/freetool-executor"
    state_database_file   = "executor.sqlite"
    health_check = {
      path    = "/healthz"
      command = ["/usr/local/bin/freetool-executor", "healthcheck"]
    }
    resources = { cpu_millis = 250, memory_mib = 256 }
  }
}
```

In `app-edge` values, grant the two selected Secret Manager IDs to the runtime
service account used by the CSI add-on:

```hcl
runtime_secret_ids = [
  "freetool-transport-key",
  "freetool-executor-config",
]
```

For the production policy, `domain:wonderly.com` must also appear in the
Freetool app's `readers`, `writers`, and the `actors` of both `run_app` and
`run_result_page`; the verified identity contract must set
`hosted_domain = "wonderly.com"`. Platform PR #245 is required for this resource
policy and is merged to main as `c4047a21`: it admits a verified domain in
non-delegation resource-grant
`actors`, and `freetool_executor_resource` is a non-delegation grant. #245 leaves
local app-delegation grants exact-actor only. Deployments on a Platform revision
before #245 must name individual employees in the resource policy instead.

The config version contains a `bind` of `127.0.0.1:43210`,
`database` of `/var/lib/day2/loopback-state/executor.sqlite`, the matching
`transport_key_hex`, a distinct 32-byte `credential_vault_key_hex`, and the
executor's reviewed egress/resource policy. Its `allowed_installations`,
`allowed_actors`, `allowed_artifacts`, and `allowed_operations` must cover only
the selected deployment. HTTP targets pin scheme, host, port, approved IPs, and
allowed path prefixes; PostgreSQL targets pin the binding, TLS policy, approved
IPs, time/row/result limits, and expected username. The executor refuses DNS
answers outside the approved IP set and does not follow redirects.

`provider_credentials` registers only the host-to-executor transport HMAC key in
the Platform credential store. The config secret delivers the executor's
separate vault key and egress policy directly to the companion. No provider
credential or config value is embedded in the instance contract.

## User-entered credential enrollment

Freetool resource editors navigate to
`/__freetool/credentials/{resource_id}` through the validated
`platform.freetool_credentials(...)` URL helper. This is a native Platform
secret-entry page, not a Roc command form: submitted credential bytes never
enter Roc inputs or ordinary invocation records. The page uses the active
session, CSRF protection, and a short-lived ticket bound to the installation,
artifact, actor, resource revision, approved destination, grant, and custody
version. The host rechecks the live session, current resource and edit
permission before mutation. The ticket lifetime is at most 30 minutes.

Enable `freetool.credential_enrollment_access` only for a resource grant whose
scope covers the requested business resource ID, includes `FreetoolStatus`, and
names the managers in `credential_managers`. With `any_app_resource`, the host
still binds each enrollment to the app-registered resource and the executor's
own configured resource policy. The resource's `service_id`
must match its connection ID. Execution and result-read actions do not imply
credential-management authority. The executor must independently allow the same
installation, actor, artifact, and operation. Simulated-provider mode never
connects to credential custody and cannot claim that a live secret was stored.

The Platform-to-executor protocol signs each POST with HMAC-SHA256 over the
method, fixed path, timestamp, nonce, and body digest. The executor checks the
body digest in constant time, rejects stale timestamps and replayed nonces, and
accepts only its authenticated fixed protocol routes. The unauthenticated
`GET /healthz` is limited to liveness; the service binds loopback and exposes no
public listener.

## Key rotation

Keep the transport HMAC key and credential-vault encryption key separate and
retain their exact Secret Manager versions for recovery.

- **Transport key:** create a new key version, advance the connection's
  `credential_ref.revision`, update the matching `provider_credentials` exact
  version and fingerprint, and publish a new exact executor config version with
  the same new `transport_key_hex`. Keep the secret IDs in `runtime_secret_ids`
  (or add the new IDs if using new secrets), then apply the app values together.
  The pod-template digest changes when a companion image, config version, port,
  state path, health check, or resource limit changes, so Kubernetes rolls the
  pod and the staged config is refreshed. Keep app writes paused until the host
  and executor use the same key.
- **Vault key:** create a new distinct 32-byte key and a new config version. The
  executor does not transparently rewrap existing ciphertext. During a planned
  maintenance window, switch the config version and restart the companion, then
  replace every stored provider credential through the enrollment page while
  Freetool executions are paused. Replacements encrypt under the new key; until
  each one is replaced, attempts to use its old ciphertext fail closed. Retain
  the old config version until all resources have been re-entered and verified,
  so the operator can restore the previous key/config if the rotation is
  abandoned. Do not change the transport key as part of this step.

## Backup and restore

The executor database is inside the named companion state subpath. Set
`state_database_file` to its path relative to that subpath so `day2-backup` uses
a consistent SQLite online snapshot instead of copying an active database and
its WAL as unrelated files. The signed app backup then carries the snapshot and
its digest; the backup job already mounts the same RWO PVC and uploads the
verified bundle. Secret Manager values are not included. Restore the matching
config and key versions separately before restarting the companion: the vault
key is needed to decrypt enrolled credentials, and the transport key must match
the Platform credential projection.

`day2 platform restore` verifies the bundle and writes companion files under
`.state/companions/<name>/` beside the restored app database. Follow the
[off-cluster restore procedure](../deploy/gke/README.md#restore-from-an-off-cluster-backup),
including stopping the StatefulSet before copying restored state to the PVC.
Restore into a disposable/private environment first, verify the executor's
receipt/result reads and credential enrollment, then resume app writes. A PVC
snapshot or an incomplete GCS prefix without its final `COMPLETE` marker is not
a verified day2 backup.
