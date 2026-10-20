# Existing namespace, KSA/GSA, disk and enrollment issuer are owned elsewhere.
# This optional root creates no IAM, database, identity, disk, node or secret.
locals {
  name       = "${replace(var.app, "_", "-")}-epoch-controller"
  instance   = jsondecode(var.instance_json)
  enrollment = jsondecode(var.enrollment_json)
  storage    = jsondecode(var.storage_json)
  policy     = try(local.instance.control.security_bootstraps[var.bootstrap_alias], null)
  labels = {
    "app.kubernetes.io/name" = local.name
    "day2.dev/service"       = "security-epoch-controller"
  }
  config_name = "${local.name}-inputs"
}

resource "kubernetes_config_map_v1" "inputs" {
  count = var.activate ? 1 : 0
  metadata {
    name      = local.config_name
    namespace = var.namespace
  }
  data = {
    "instance.json"          = var.instance_json
    "native-enrollment.json" = var.enrollment_json
    "storage.json"           = var.storage_json
  }
  lifecycle {
    precondition {
      condition = try(
        local.policy.scope.app == var.app && local.policy.scope.installation == local.instance.installation &&
        local.policy.scope.environment == local.instance.environment &&
        local.policy.controller.namespace.name == var.namespace &&
        local.policy.controller.kubernetes_service_account.name == local.name &&
        local.policy.controller.workload.name == local.name &&
        local.policy.controller.workload_kind == "deployment_v1" &&
        local.policy.controller.container.name == "epoch-controller" &&
        endswith(var.image, local.policy.controller.container.image) &&
        jsonencode(local.enrollment.bootstrap) == jsonencode(local.policy) &&
        jsonencode(local.enrollment.store) == jsonencode(local.instance.control.security_epochs[local.policy.epoch_store.id]) &&
      contains(keys(local.instance.apps), var.app), false)
      error_message = "Instance, enrollment, artifact image and the separate real Controller workload must select the SAME complete profile. Native admission remains mandatory."
    }
    precondition {
      condition = try(
        local.storage.disk_id == local.policy.fresh_storage.provider_volume_uid &&
        local.storage.node.name == local.enrollment.runtime.node_name &&
        local.storage.node.uid == local.enrollment.runtime.node_uid &&
        local.storage.claim.name == "data" &&
        can(regex("^[1-9][0-9]{0,23}$", local.storage.disk_id)) &&
      can(regex("^[1-9][0-9]{0,23}$", local.storage.instance_id)), false)
      error_message = "Storage must select the same immutable volume/node metadata; none of this establishes an actual mount, P3 or current writer."
    }
  }
}

resource "kubernetes_deployment_v1" "controller" {
  metadata {
    name      = local.name
    namespace = var.namespace
    labels    = local.labels
  }
  # The first App exchange completes activation, so a single apply must not
  # synchronously wait for an App that is deployed by another state root.
  wait_for_rollout = false
  spec {
    replicas = var.activate ? 1 : 0
    strategy { type = "Recreate" }
    selector { match_labels = local.labels }
    template {
      metadata {
        labels = local.labels
        annotations = {
          "day2.dev/native-inputs" = sha256(jsonencode([var.instance_json, var.enrollment_json, var.storage_json]))
        }
      }
      spec {
        service_account_name            = local.name
        automount_service_account_token = false
        enable_service_links            = false
        host_pid                        = true
        host_network                    = false
        host_ipc                        = false
        node_selector = {
          "day2.dev.node-restriction.kubernetes.io/enrollment" = var.node_profile
          "kubernetes.io/arch"                                 = "amd64"
          "kubernetes.io/hostname"                             = local.storage.node.name
          "iam.gke.io/gke-metadata-server-enabled"             = "true"
        }
        toleration {
          key      = "day2.dev/native-enrollment"
          operator = "Equal"
          value    = var.node_profile
          effect   = "NoSchedule"
        }
        termination_grace_period_seconds = 10
        security_context {
          run_as_non_root = true
          run_as_user     = 10001
          run_as_group    = 10001
        }
        container {
          name              = "epoch-controller"
          image             = var.image
          image_pull_policy = "IfNotPresent"
          command           = ["/usr/local/bin/day2-epoch-controller"]
          args              = ["/srv/day2/instance.json", var.app]
          security_context {
            privileged                = true
            read_only_root_filesystem = true
          }
          resources {
            requests = { cpu = "250m", memory = "256Mi" }
            limits   = { cpu = "1", memory = "512Mi" }
          }
          port {
            name           = "health"
            container_port = 8080
          }
          volume_mount {
            name       = "inputs"
            mount_path = "/srv/day2/instance.json"
            sub_path   = "instance.json"
            read_only  = true
          }
          volume_mount {
            name       = "inputs"
            mount_path = "/etc/day2/native-enrollment.json"
            sub_path   = "native-enrollment.json"
            read_only  = true
          }
          volume_mount {
            name       = "inputs"
            mount_path = "/etc/day2-native/storage.json"
            sub_path   = "storage.json"
            read_only  = true
          }
          volume_mount {
            name       = "state"
            mount_path = "/state"
          }
          volume_mount {
            name       = "enrollment"
            mount_path = "/run/day2-native-enrollment"
            read_only  = true
          }
          volume_mount {
            name       = "storage-peer"
            mount_path = "/run/day2-native-enrollment/storage"
          }
          volume_mount {
            name       = "disk-names"
            mount_path = "/dev/disk/by-id"
            read_only  = true
          }
          volume_mount {
            name       = "api-token"
            mount_path = "/var/run/secrets/kubernetes.io/serviceaccount"
            read_only  = true
          }
          volume_mount {
            name       = "subject-token"
            mount_path = "/var/run/secrets/day2-native"
            read_only  = true
          }
          readiness_probe {
            http_get {
              path = "/health/ready"
              port = "health"
            }
            period_seconds    = 5
            timeout_seconds   = 2
            failure_threshold = 3
          }
          # No liveness restart loop: an uncertain original is never adopted.
        }
        volume {
          name = "inputs"
          config_map {
            name         = local.config_name
            default_mode = "0444"
          }
        }
        volume {
          name = "state"
          host_path {
            path = var.host_state_path
            type = "Directory"
          }
        }
        volume {
          name = "enrollment"
          host_path {
            path = "/run/day2-native-enrollment"
            type = "Directory"
          }
        }
        volume {
          name = "storage-peer"
          host_path {
            path = "/run/day2-native-enrollment/storage"
            type = "Directory"
          }
        }
        volume {
          name = "disk-names"
          host_path {
            path = "/dev/disk/by-id"
            type = "Directory"
          }
        }
        volume {
          name = "api-token"
          projected {
            default_mode = "0444"
            sources {
              service_account_token {
                path               = "token"
                expiration_seconds = 3600
              }
            }
            sources {
              config_map {
                name = "kube-root-ca.crt"
                items {
                  key  = "ca.crt"
                  path = "ca.crt"
                }
              }
            }
          }
        }
        volume {
          name = "subject-token"
          projected {
            default_mode = "0444"
            sources {
              service_account_token {
                path               = "subject-token"
                audience           = try(local.policy.controller.token_review_audience, "invalid")
                expiration_seconds = 600
              }
            }
          }
        }
      }
    }
  }
}

output "controller_uid" {
  description = "Registration DATA only. Select the actual UID in enrollment/instance profiles before first activation."
  value       = kubernetes_deployment_v1.controller.metadata[0].uid
}
