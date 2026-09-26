# Workload consuming the public app-edge stack contract.

data "kubernetes_config_map_v1" "platform_contract" {
  metadata {
    name      = var.platform_contract_config_map
    namespace = var.namespace
  }
}

locals {
  contract = data.kubernetes_config_map_v1.platform_contract.data

  contract_iap_audience = trimspace(lookup(local.contract, "IAP_JWT_AUDIENCE", ""))
  iap_audience          = var.iap_audience_override != "" ? var.iap_audience_override : local.contract_iap_audience
  contract_app_domain   = trimspace(lookup(local.contract, "APP_DOMAIN", ""))
  pvc_name              = lookup(local.contract, "PVC_NAME", "data")
  service_name          = lookup(local.contract, "SERVICE_NAME", "app")
  # The label the platform's Service selects. Required from the contract; the
  # fallback only keeps the plan renderable until the precondition reports it.
  contract_label_key   = trimspace(lookup(local.contract, "REQUIRED_SERVICE_LABEL_KEY", ""))
  contract_label_value = trimspace(lookup(local.contract, "REQUIRED_SERVICE_LABEL_VALUE", ""))
  required_label_key   = local.contract_label_key != "" ? local.contract_label_key : "day2.dev/app"
  required_label_value = local.contract_label_value != "" ? local.contract_label_value : var.app_id
  # Published by platforms whose telemetry agent resolves services by pod label.
  contract_pod_labels = (
    trimspace(lookup(local.contract, "O11Y_SERVICE_LABEL_KEY", "")) != "" && trimspace(lookup(local.contract, "O11Y_SERVICE_LABEL_VALUE", "")) != ""
    ? { (trimspace(local.contract["O11Y_SERVICE_LABEL_KEY"])) = trimspace(local.contract["O11Y_SERVICE_LABEL_VALUE"]) }
    : {}
  )

  workload_name = var.workload_name != "" ? var.workload_name : "day2-${replace(var.app_id, "_", "-")}"

  root_dir      = "/srv/day2"
  instance_path = "${local.root_dir}/instance.json"
  state_dir     = "${local.root_dir}/.state"

  # Shape: platform/crates/day2/src/artifact.rs (Instance, AppBinding, Edge,
  # IdentityProvider) and day2-capabilities/src/runtime.rs (RuntimeProfile).
  # Every struct denies unknown fields; do not add keys here.
  instance = {
    installation = var.installation
    environment  = var.environment
    identity = {
      scheme        = "google_iap"
      hosted_domain = var.hosted_domain
    }
    apps = {
      (var.app_id) = {
        artifact  = "artifacts/${var.artifact_id}"
        readers   = sort(distinct(var.readers))
        writers   = sort(distinct(var.writers))
        authority = var.authority
        runtime = {
          kind = "linux_sqlite_single_v1"
          resources = {
            memory_mib    = var.runtime_resources.memory_mib
            cpu_millis    = var.runtime_resources.cpu_millis
            process_limit = var.runtime_resources.process_limit
            # Kubernetes bounds processes per pod (kubelet podPidsLimit), in a
            # cgroup the container cannot see; its own pids.max reads "max".
            # This declares that the pod holds the bound (checked below
            # against pod_pids_limit).
            process_limit_enforced_by = "pod"
            http_concurrency          = var.runtime_resources.http_concurrency
            shutdown_seconds          = var.runtime_resources.shutdown_seconds
          }
        }
        edge = {
          origin       = var.edge_origin
          iap_audience = local.iap_audience
        }
      }
    }
  }
  instance_json = jsonencode(local.instance)

  selector_labels = {
    (local.required_label_key) = local.required_label_value
    "app.kubernetes.io/name"   = local.workload_name
  }
  pod_labels = merge(var.extra_pod_labels, local.contract_pod_labels, local.selector_labels, {
    "app.kubernetes.io/managed-by" = "opentofu"
    "app.kubernetes.io/part-of"    = "day2"
  })

  # Limits equal the runtime profile. day2-serve reads its private cgroup and
  # requires memory.max <= memory_mib MiB and cpu.max quota/period <= cpu_millis.
  # With the default 100ms CFS period, "<cpu_millis>m" yields exactly
  # "<cpu_millis*100> 100000". Requests equal limits (Guaranteed QoS).
  container_limits = {
    cpu               = "${var.runtime_resources.cpu_millis}m"
    memory            = "${var.runtime_resources.memory_mib}Mi"
    ephemeral-storage = "256Mi"
  }
}

resource "kubernetes_config_map_v1" "instance" {
  metadata {
    name      = "${local.workload_name}-instance"
    namespace = var.namespace
    labels = {
      "app.kubernetes.io/name"       = local.workload_name
      "app.kubernetes.io/managed-by" = "opentofu"
    }
  }

  data = {
    "instance.json" = local.instance_json
  }

  lifecycle {
    precondition {
      condition     = can(regex("^/projects/[0-9]{1,24}/global/backendServices/[0-9]{1,24}$", local.iap_audience))
      error_message = "IAP_JWT_AUDIENCE in ${var.namespace}/${var.platform_contract_config_map} is missing or malformed. Apply the platform's app stack first (it resolves the IAP backend service after the Ingress exists)."
    }

    precondition {
      condition     = local.contract_label_key != "" && local.contract_label_value != ""
      error_message = "The platform contract must publish REQUIRED_SERVICE_LABEL_KEY and REQUIRED_SERVICE_LABEL_VALUE: the pod label its Service selects."
    }

    precondition {
      condition     = local.contract_app_domain != "" && "https://${local.contract_app_domain}" == var.edge_origin
      error_message = "edge_origin (${var.edge_origin}) must equal https:// plus the platform contract's APP_DOMAIN (${local.contract_app_domain}). Day2 refuses requests whose Host differs from the edge origin."
    }

    precondition {
      condition     = try(var.authority.version == 1 && length(keys(var.authority.operations)) > 0, false)
      error_message = "authority must be a version 1 day2 authority policy that lists the artifact's operations; the placeholder has not been replaced."
    }

    precondition {
      condition     = var.pod_pids_limit <= var.runtime_resources.process_limit
      error_message = "pod_pids_limit (${var.pod_pids_limit}) must not exceed runtime_resources.process_limit (${var.runtime_resources.process_limit}). The instance declares process_limit_enforced_by = \"pod\", so the node pool's podPidsLimit is the only process bound; it must be at least as tight as the admitted profile."
    }

    precondition {
      condition     = var.runtime_resources.cpu_millis <= var.container_max.cpu_millis && var.runtime_resources.memory_mib <= var.container_max.memory_mib
      error_message = "runtime_resources exceed the namespace LimitRange maximum (container_max); raise the platform's per-app guardrail override first."
    }

    precondition {
      condition     = length(local.instance_json) <= 1048576
      error_message = "day2 refuses instance files larger than 1 MiB."
    }
  }
}

resource "kubernetes_stateful_set_v1" "day2" {
  metadata {
    name      = local.workload_name
    namespace = var.namespace
    labels    = local.pod_labels
  }

  spec {
    # day2's runtime profile fixes replicas at 1, and day2-serve holds an
    # exclusive lock on .state/<app>.serve.lock. A StatefulSet never starts a
    # replacement pod while the old one may still be running.
    replicas              = 1
    service_name          = local.service_name
    pod_management_policy = "OrderedReady"

    selector {
      match_labels = local.selector_labels
    }

    update_strategy {
      type = "RollingUpdate"
    }

    template {
      metadata {
        labels = local.pod_labels
        annotations = {
          # subPath mounts do not follow ConfigMap updates; roll the pod instead.
          "day2.dev/instance-sha256" = sha256(local.instance_json)
        }
      }

      spec {
        # The internal-tools tenancy policy admits only serviceAccountName=runtime
        # in app-* namespaces. day2 needs no Kubernetes API access.
        service_account_name             = var.service_account_name
        automount_service_account_token  = false
        enable_service_links             = false
        termination_grace_period_seconds = var.runtime_resources.shutdown_seconds + 15

        node_selector = var.node_selector

        # No fsGroup on purpose: kubelet's fsGroup handling would re-add group
        # rwx and setgid to the state directory day2 keeps at 0700.
        security_context {
          run_as_non_root = true
          run_as_user     = 10001
          run_as_group    = 10001

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        dynamic "init_container" {
          for_each = var.state_ownership_init_enabled ? [true] : []

          content {
            name              = "state-ownership"
            image             = var.state_ownership_image
            image_pull_policy = "IfNotPresent"
            # The app image is distroless and has no shell, so this runs in a
            # separate pinned image that carries busybox. Only chown: CAP_CHOWN
            # permits it whoever owns the directory, so it is idempotent on
            # every later start. day2 chmods .state to 0700 itself as its
            # owner. (A chmod here would need CAP_FOWNER once the directory is
            # 10001's, and failed every start after the first.)
            command = ["/busybox/chown", "10001:10001", local.state_dir]

            security_context {
              run_as_non_root            = false
              run_as_user                = 0
              run_as_group               = 0
              allow_privilege_escalation = false
              read_only_root_filesystem  = true
              privileged                 = false

              capabilities {
                drop = ["ALL"]
                add  = ["CHOWN"]
              }

              seccomp_profile {
                type = "RuntimeDefault"
              }
            }

            resources {
              requests = {
                cpu               = "50m"
                memory            = "32Mi"
                ephemeral-storage = "16Mi"
              }
              limits = {
                cpu               = "100m"
                memory            = "32Mi"
                ephemeral-storage = "16Mi"
              }
            }

            volume_mount {
              name       = "state"
              mount_path = local.state_dir
            }
          }
        }

        container {
          name              = "day2"
          image             = var.image
          image_pull_policy = "IfNotPresent"
          command           = ["/usr/local/bin/day2-serve"]
          args              = [local.instance_path, var.app_id, "--edge"]

          port {
            name           = "http"
            container_port = 8080
            protocol       = "TCP"
          }

          security_context {
            run_as_non_root            = true
            run_as_user                = 10001
            run_as_group               = 10001
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            privileged                 = false

            capabilities {
              drop = ["ALL"]
            }

            seccomp_profile {
              type = "RuntimeDefault"
            }
          }

          resources {
            requests = local.container_limits
            limits   = local.container_limits
          }

          # The instance must be a regular file on a read-only mount (a
          # ConfigMap directory mount would be a symlink), hence subPath.
          volume_mount {
            name       = "instance"
            mount_path = local.instance_path
            sub_path   = "instance.json"
            read_only  = true
          }

          volume_mount {
            name       = "state"
            mount_path = local.state_dir
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }

          # /srv/day2/artifacts/<artifact_id> is baked into the image and read-only
          # through readOnlyRootFilesystem; no volume may be mounted under it.

          readiness_probe {
            http_get {
              path = "/health/ready"
              port = "http"
            }
            period_seconds    = 5
            timeout_seconds   = 2
            failure_threshold = 3
          }

          liveness_probe {
            http_get {
              path = "/health/live"
              port = "http"
            }
            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 2
            failure_threshold     = 6
          }
        }

        volume {
          name = "instance"

          config_map {
            name         = kubernetes_config_map_v1.instance.metadata[0].name
            default_mode = "0444"

            items {
              key  = "instance.json"
              path = "instance.json"
            }
          }
        }

        volume {
          name = "state"

          persistent_volume_claim {
            claim_name = local.pvc_name
          }
        }

        volume {
          name = "tmp"

          empty_dir {
            medium     = "Memory"
            size_limit = var.tmp_size_limit
          }
        }
      }
    }
  }

  timeouts {
    create = "15m"
    update = "15m"
  }
}

# --- Scheduled off-cluster backup -------------------------------------------
# Every run takes an online snapshot with the runtime image's day2-backup (the
# same native backup and verification as `day2 platform backup`), beside the
# serving pod and without its lock, then uploads the verified bundle as one
# tar.gz to the app-edge backup bucket. The uploader identity (Workload
# Identity, no key, no mounted token) may only create objects; ifGenerationMatch=0
# refuses to replace one. The state PVC is ReadWriteOnce, so the pod must run on
# the app pod's node: while the app is stopped (maintenance) a run stays Pending
# and fails at its deadline instead of competing for the volume.

locals {
  backup_name = "${local.workload_name}-backup"
  # Outside the Service selector (the required label says backup, not app) and
  # outside the StatefulSet's app.kubernetes.io/name, which the maintenance
  # procedure uses to find the app's pods.
  backup_labels = merge(var.extra_pod_labels, local.contract_pod_labels, {
    (local.required_label_key)     = "backup"
    "app.kubernetes.io/name"       = local.backup_name
    "app.kubernetes.io/component"  = "backup"
    "app.kubernetes.io/managed-by" = "opentofu"
    "app.kubernetes.io/part-of"    = "day2"
  })
  backup_output   = "/backup"
  backup_snapshot = "${local.backup_output}/snapshot"
  # Object names: <app_id>-<UTC yyyymmddThhmmssZ>.tar.gz.
  backup_object_prefix = "${var.app_id}-"

  backup_security_context = {
    run_as_non_root            = true
    run_as_user                = 10001
    run_as_group               = 10001
    allow_privilege_escalation = false
    read_only_root_filesystem  = true
    privileged                 = false
  }

  # POSIX sh (busybox in the pinned uploader image). No ${...} or %{...} here:
  # this is an OpenTofu heredoc.
  backup_upload_script = <<-SCRIPT
    set -eu
    umask 077
    test -f "$SNAPSHOT/backup.json" || { echo "no verified day2 backup at $SNAPSHOT" >&2; exit 1; }
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    object="$OBJECT_PREFIX$stamp.tar.gz"
    archive="$OUTPUT/$stamp.tar.gz"
    tar -czf "$archive" -C "$OUTPUT" snapshot
    size="$(wc -c < "$archive" | tr -d ' ')"
    token="$(curl -fsS --max-time 30 --retry 3 -H 'Metadata-Flavor: Google' \
      "$METADATA_TOKEN_URL" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    test -n "$token" || { echo "no access token from the GKE metadata server" >&2; exit 1; }
    # The token goes to curl on stdin, never on a command line. Media upload of
    # a new object only: ifGenerationMatch=0 fails (412) if the name exists.
    printf 'Authorization: Bearer %s\n' "$token" | curl -fsS --max-time "$UPLOAD_TIMEOUT_SECONDS" \
      -X POST -H @- -H 'Content-Type: application/gzip' --upload-file "$archive" \
      -o "$OUTPUT/upload.json" \
      "$UPLOAD_URL/$BUCKET/o?uploadType=media&ifGenerationMatch=0&name=$object"
    stored="$(sed -n 's/.*"size"[[:space:]]*:[[:space:]]*"\([0-9]*\)".*/\1/p' "$OUTPUT/upload.json")"
    test "$stored" = "$size" || { echo "gs://$BUCKET/$object stored $stored bytes, expected $size" >&2; exit 1; }
    generation="$(sed -n 's/.*"generation"[[:space:]]*:[[:space:]]*"\([0-9]*\)".*/\1/p' "$OUTPUT/upload.json")"
    echo "{\"uploaded\":\"gs://$BUCKET/$object\",\"bytes\":$size,\"generation\":\"$generation\"}"
  SCRIPT
}

resource "kubernetes_cron_job_v1" "backup" {
  metadata {
    name      = local.backup_name
    namespace = var.namespace
    labels    = local.backup_labels
  }

  spec {
    schedule                      = var.backup_schedule
    timezone                      = "Etc/UTC"
    concurrency_policy            = "Forbid"
    starting_deadline_seconds     = var.backup_starting_deadline_seconds
    successful_jobs_history_limit = 3
    failed_jobs_history_limit     = 3
    suspend                       = false

    job_template {
      metadata {
        labels = local.backup_labels
      }

      spec {
        backoff_limit           = 1
        active_deadline_seconds = var.backup_active_deadline_seconds

        template {
          metadata {
            labels = local.backup_labels
          }

          spec {
            # The tenancy policy admits serviceAccountName=backup only for Jobs
            # labelled service=backup with token automount off. Workload Identity
            # needs no mounted token: the GKE metadata server exchanges it.
            service_account_name            = var.backup_service_account_name
            automount_service_account_token = false
            enable_service_links            = false
            restart_policy                  = "Never"

            node_selector = var.node_selector

            security_context {
              run_as_non_root = true
              run_as_user     = 10001
              run_as_group    = 10001

              seccomp_profile {
                type = "RuntimeDefault"
              }
            }

            affinity {
              pod_affinity {
                required_during_scheduling_ignored_during_execution {
                  label_selector {
                    match_labels = {
                      "app.kubernetes.io/name" = local.workload_name
                    }
                  }
                  topology_key = "kubernetes.io/hostname"
                }
              }
            }

            # The app's own image (the same digest as the StatefulSet), so the
            # active artifact the database names is present at the same path.
            init_container {
              name              = "snapshot"
              image             = var.image
              image_pull_policy = "IfNotPresent"
              command           = ["/usr/local/bin/day2-backup"]
              args              = [local.instance_path, var.app_id, local.backup_snapshot]

              security_context {
                run_as_non_root            = local.backup_security_context.run_as_non_root
                run_as_user                = local.backup_security_context.run_as_user
                run_as_group               = local.backup_security_context.run_as_group
                allow_privilege_escalation = local.backup_security_context.allow_privilege_escalation
                read_only_root_filesystem  = local.backup_security_context.read_only_root_filesystem
                privileged                 = local.backup_security_context.privileged

                capabilities {
                  drop = ["ALL"]
                }

                seccomp_profile {
                  type = "RuntimeDefault"
                }
              }

              resources {
                requests = {
                  cpu               = "100m"
                  memory            = "256Mi"
                  ephemeral-storage = "64Mi"
                }
                limits = {
                  cpu               = "1"
                  memory            = var.backup_snapshot_memory
                  ephemeral-storage = var.backup_scratch_size_limit
                }
              }

              # Mirrors the StatefulSet: instance.json as a regular read-only
              # file (subPath), the artifact baked into the image under
              # /srv/day2/artifacts, and the state volume read-write (SQLite
              # opens the WAL's -shm even for a read-only connection).
              volume_mount {
                name       = "instance"
                mount_path = local.instance_path
                sub_path   = "instance.json"
                read_only  = true
              }

              volume_mount {
                name       = "state"
                mount_path = local.state_dir
              }

              volume_mount {
                name       = "tmp"
                mount_path = "/tmp"
              }

              volume_mount {
                name       = "backup"
                mount_path = local.backup_output
              }
            }

            container {
              name              = "upload"
              image             = var.backup_uploader_image
              image_pull_policy = "IfNotPresent"
              command           = ["/bin/sh", "-c", local.backup_upload_script]

              env {
                name  = "BUCKET"
                value = var.backup_bucket
              }

              env {
                name  = "OBJECT_PREFIX"
                value = local.backup_object_prefix
              }

              env {
                name  = "OUTPUT"
                value = local.backup_output
              }

              env {
                name  = "SNAPSHOT"
                value = local.backup_snapshot
              }

              env {
                name  = "METADATA_TOKEN_URL"
                value = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
              }

              env {
                name  = "UPLOAD_URL"
                value = "https://storage.googleapis.com/upload/storage/v1/b"
              }

              env {
                name  = "UPLOAD_TIMEOUT_SECONDS"
                value = tostring(var.backup_active_deadline_seconds)
              }

              security_context {
                run_as_non_root            = local.backup_security_context.run_as_non_root
                run_as_user                = local.backup_security_context.run_as_user
                run_as_group               = local.backup_security_context.run_as_group
                allow_privilege_escalation = local.backup_security_context.allow_privilege_escalation
                read_only_root_filesystem  = local.backup_security_context.read_only_root_filesystem
                privileged                 = local.backup_security_context.privileged

                capabilities {
                  drop = ["ALL"]
                }

                seccomp_profile {
                  type = "RuntimeDefault"
                }
              }

              resources {
                requests = {
                  cpu               = "50m"
                  memory            = "64Mi"
                  ephemeral-storage = "64Mi"
                }
                limits = {
                  cpu               = "500m"
                  memory            = "256Mi"
                  ephemeral-storage = var.backup_scratch_size_limit
                }
              }

              volume_mount {
                name       = "backup"
                mount_path = local.backup_output
              }

              volume_mount {
                name       = "tmp"
                mount_path = "/tmp"
              }
            }

            volume {
              name = "instance"

              config_map {
                name         = kubernetes_config_map_v1.instance.metadata[0].name
                default_mode = "0444"

                items {
                  key  = "instance.json"
                  path = "instance.json"
                }
              }
            }

            volume {
              name = "state"

              persistent_volume_claim {
                claim_name = local.pvc_name
              }
            }

            volume {
              name = "tmp"

              empty_dir {
                medium     = "Memory"
                size_limit = "16Mi"
              }
            }

            # The verified bundle and its tar.gz; gone with the pod.
            volume {
              name = "backup"

              empty_dir {
                size_limit = var.backup_scratch_size_limit
              }
            }
          }
        }
      }
    }
  }
}
