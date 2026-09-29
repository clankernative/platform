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
  instance = merge({
    installation = var.installation
    environment  = var.environment
    identity = {
      scheme        = "google_iap"
      hosted_domain = var.hosted_domain
    }
    apps = {
      (var.app_id) = merge({
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
        },
        length(var.resource_policies) == 0 ? {} : { resource_policies = var.resource_policies },
        length(var.schedules) == 0 ? {} : { schedules = var.schedules },
        length(var.ingress) == 0 ? {} : { ingress = var.ingress },
      var.journal_trace_hours == null ? {} : { journal = { trace_hours = var.journal_trace_hours } })
    }
  }, var.resource_catalog == null ? {} : { resources = var.resource_catalog })
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
      condition     = alltrue([for actor in concat(var.readers, var.writers) : !startswith(actor, "domain:") || actor == "domain:${var.hosted_domain}"])
      error_message = "A domain: entry in readers or writers must be exactly domain:${var.hosted_domain}. Day2 admits a domain only when it is the hosted_domain its identity provider verifies, and refuses the instance otherwise."
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
        annotations = merge({
          # subPath mounts do not follow ConfigMap updates; roll the pod instead.
          "day2.dev/instance-sha256" = sha256(local.instance_json)
          }, local.has_credentials ? {
          "day2.dev/credentials-sha256" = sha256(local.provisioning_plan_json)
        } : {})
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

        # See credentials.tf. BusyBox install sets the owner before the mode,
        # so changing the mode of the now-10001-owned file needs CAP_FOWNER.
        dynamic "init_container" {
          for_each = local.has_credentials ? [true] : []

          content {
            name              = "credential-files"
            image             = var.state_ownership_image
            image_pull_policy = "IfNotPresent"
            command = concat(
              ["/busybox/install", "-o", "10001", "-g", "10001", "-m", "0400", "-t", local.credential_dir],
              [for credential in local.credentials : "${local.credential_source_dir}/${credential.key}"],
            )

            security_context {
              run_as_non_root            = false
              run_as_user                = 0
              run_as_group               = 0
              allow_privilege_escalation = false
              read_only_root_filesystem  = true
              privileged                 = false

              capabilities {
                drop = ["ALL"]
                add  = ["CHOWN", "FOWNER"]
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
              name       = "credential-sources"
              mount_path = local.credential_source_dir
              read_only  = true
            }

            volume_mount {
              name       = "credentials"
              mount_path = local.credential_dir
            }
          }
        }

        dynamic "init_container" {
          for_each = local.has_credentials ? [true] : []

          content {
            name              = "credential-registration"
            image             = var.image
            image_pull_policy = "IfNotPresent"
            command           = ["/usr/local/bin/day2-provision-credentials"]
            args              = [local.operator_instance, var.app_id, var.credential_operator, local.provisioning_plan]

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

            # Every input is a regular file (subPath): provisioning refuses
            # symlinks, which a ConfigMap directory mount would present.
            volume_mount {
              name       = "credential-metadata"
              mount_path = local.operator_instance
              sub_path   = "operator-instance.json"
              read_only  = true
            }

            volume_mount {
              name       = "credential-metadata"
              mount_path = local.provisioning_plan
              sub_path   = "provisioning.json"
              read_only  = true
            }

            dynamic "volume_mount" {
              for_each = keys(local.provisioning_inputs)

              content {
                name       = "credential-metadata"
                mount_path = "${local.provisioning_dir}/${volume_mount.value}"
                sub_path   = volume_mount.value
                read_only  = true
              }
            }

            volume_mount {
              name       = "credentials"
              mount_path = local.credential_dir
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

          # The registered mounts' paths; see credentials.tf.
          dynamic "volume_mount" {
            for_each = local.has_credentials ? [true] : []

            content {
              name       = "credentials"
              mount_path = local.credential_dir
              read_only  = true
            }
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

        dynamic "volume" {
          for_each = local.has_credentials ? [true] : []

          content {
            name = "credential-sources"

            csi {
              driver    = "secrets-store-gke.csi.k8s.io"
              read_only = true
              volume_attributes = {
                secretProviderClass = kubernetes_manifest.credentials[0].manifest.metadata.name
              }
            }
          }
        }

        dynamic "volume" {
          for_each = local.has_credentials ? [true] : []

          content {
            name = "credentials"

            empty_dir {
              medium     = "Memory"
              size_limit = "1Mi"
            }
          }
        }

        dynamic "volume" {
          for_each = local.has_credentials ? [true] : []

          content {
            name = "credential-metadata"

            config_map {
              name         = kubernetes_config_map_v1.credentials[0].metadata[0].name
              default_mode = "0444"
            }
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
# Every run is one container of the app's own image running day2-backup: an
# online snapshot beside the serving pod, without its lock, verified (the same
# native backup and verification as `day2 platform backup`), then uploaded file
# by file to the app-edge backup bucket under <app_id>/<UTC stamp>/ with a
# COMPLETE marker written last. The uploader identity (Workload Identity via
# the GKE metadata server; no key, no mounted token) may only create objects,
# and every upload uses ifGenerationMatch=0. The state PVC is ReadWriteOnce, so
# the pod must run on the app pod's node: while the app is stopped
# (maintenance) a run stays Pending and fails at its deadline instead of
# competing for the volume.

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
  backup_output = "/backup"
  # day2-backup appends /<UTC yyyymmddThhmmssZ> to the object prefix itself.
  backup_args = [
    local.instance_path, var.app_id, "${local.backup_output}/snapshot",
    "--upload-gcs", var.backup_bucket,
    "--object-prefix", var.app_id,
  ]
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
            # needs no mounted token: the GKE metadata server issues it.
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
            container {
              name              = "backup"
              image             = var.image
              image_pull_policy = "IfNotPresent"
              command           = ["/usr/local/bin/day2-backup"]
              args              = local.backup_args

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
                requests = {
                  cpu               = "100m"
                  memory            = "256Mi"
                  ephemeral-storage = "64Mi"
                }
                limits = {
                  cpu               = "1"
                  memory            = var.backup_memory
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

              # day2-backup loads the artifact as day2-serve does, copying its
              # worker executable here first: the same size as the app's /tmp.
              empty_dir {
                medium     = "Memory"
                size_limit = var.tmp_size_limit
              }
            }

            # The verified bundle before upload; gone with the pod.
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
