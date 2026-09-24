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
        auditors  = sort(distinct(var.auditors))
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
            # separate pinned image that carries busybox. chmod before chown:
            # root owns the fresh directory, so only CAP_CHOWN is needed.
            # Idempotent on later starts.
            command = ["/busybox/sh", "-eu", "-c", "/busybox/chmod 0700 ${local.state_dir} && /busybox/chown 10001:10001 ${local.state_dir}"]

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
