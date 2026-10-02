# This root consumes the installation edge. It creates no identity, IAM grant,
# database, credential mount or alternate endpoint catalog.
data "kubernetes_config_map_v1" "edge" {
  metadata {
    name      = var.edge_contract_config_map
    namespace = var.namespace
  }
}

locals {
  contract    = data.kubernetes_config_map_v1.edge.data
  instance    = jsondecode(var.instance_json)
  resources   = local.instance.oauth_runtime.shell_resources
  connections = flatten([for app in values(local.instance.apps) : values(try(app.oauth_connections, {}))])
  shell_secret_names = toset(concat(
    [local.instance.oauth_clients.reauthentication.credential],
    [for registration in values(local.instance.oauth_clients.registrations) : registration.client.credential],
    [for connection in local.connections : connection.shell_attestation_secret],
  ))
  custody_secret_names = toset(flatten([for connection in local.connections : [connection.custody_verifier_secret, connection.custody_encryption_secret]]))
  shell_secrets        = [for name in local.shell_secret_names : local.instance.control.secrets[name]]
  custody_secrets      = [for name in local.custody_secret_names : local.instance.control.secrets[name]]
  shell_containers     = toset([for secret in local.shell_secrets : "${secret.project_number}/${secret.secret}"])
  custody_containers   = toset([for secret in local.custody_secrets : "${secret.project_number}/${secret.secret}"])
  labels = {
    "day2.dev/service"             = "security-shell"
    "app.kubernetes.io/name"       = "security-shell"
    "app.kubernetes.io/part-of"    = "day2-security"
    "app.kubernetes.io/managed-by" = "opentofu"
  }
  limits = {
    cpu               = "${local.resources.cpu_millis}m"
    memory            = "${local.resources.memory_mib}Mi"
    ephemeral-storage = "64Mi"
  }
}

resource "kubernetes_config_map_v1" "instance" {
  metadata {
    name      = "security-shell-instance"
    namespace = var.namespace
    labels    = local.labels
  }
  data = { "instance.json" = var.instance_json }
  lifecycle {
    precondition {
      condition = try(
        local.contract["EDGE_ROLE"] == "security_shell" &&
        local.contract["SERVICE_NAME"] == "security-shell" &&
        local.contract["SERVICE_ACCOUNT_NAME"] == "security-shell" &&
        local.contract["REQUIRED_SERVICE_LABEL_KEY"] == "day2.dev/service" &&
        local.contract["REQUIRED_SERVICE_LABEL_VALUE"] == "security-shell" &&
        can(regex("^/projects/[1-9][0-9]{0,23}/global/backendServices/[1-9][0-9]{0,23}$", local.contract["IAP_JWT_AUDIENCE"])) &&
        local.instance.security_shell.origin == local.contract["SECURITY_SHELL_ORIGIN"] &&
        local.instance.security_shell.iap_audience == local.contract["IAP_JWT_AUDIENCE"] &&
        local.instance.oauth_shell_transport.service_account == local.contract["OAUTH_SHELL_SERVICE_ACCOUNT"] &&
      local.instance.oauth_runtime.shell.kubernetes_service == "${var.namespace}/security-shell", false)
      error_message = "The instance must select the exact resolved security-shell edge, audience and workload identity."
    }
    precondition {
      condition = try(
        length(local.connections) > 0 &&
        toset(keys(local.instance.oauth_clients.registrations)) == toset([for connection in local.connections : connection.registration.id]) &&
        alltrue([for app in values(local.instance.apps) : length(try(app.oauth_connections, {})) == 0 || can(regex("^artifacts/[0-9a-f]{64}$", app.artifact))]) &&
        length(setintersection(local.shell_containers, local.custody_containers)) == 0 &&
        alltrue([for secret in local.shell_secrets : secret.kind == "gcp_version" && secret.version >= 1 && tostring(secret.project_number) == split("/", local.contract["IAP_JWT_AUDIENCE"])[2]]) &&
      toset(jsondecode(local.contract["OAUTH_SHELL_SECRET_IDS"])) == toset([for secret in local.shell_secrets : secret.secret]), false)
      error_message = "Shell IAM must select exactly its client/attestation secret containers in the edge project, with no app custody container even at another version."
    }
    precondition {
      condition = try(
        local.resources.memory_mib >= 64 && local.resources.memory_mib <= 65536 &&
        local.resources.cpu_millis >= 50 && local.resources.cpu_millis <= 64000 &&
        local.resources.process_limit >= 16 && local.resources.process_limit <= 4096 &&
        local.resources.process_limit_enforced_by == "pod" &&
        local.resources.http_concurrency >= 1 && local.resources.http_concurrency <= 32 &&
      local.resources.shutdown_seconds >= 5 && local.resources.shutdown_seconds <= 300, false)
      error_message = "Shell resource bounds must match the native profile and declare the separately qualified GKE pod PID bound."
    }
  }
}

resource "kubernetes_deployment_v1" "shell" {
  metadata {
    name      = "security-shell"
    namespace = var.namespace
    labels    = local.labels
  }
  spec {
    replicas = 1
    strategy { type = "Recreate" }
    selector { match_labels = local.labels }
    template {
      metadata {
        labels      = local.labels
        annotations = { "day2.dev/instance-sha256" = sha256(var.instance_json) }
      }
      spec {
        service_account_name             = "security-shell"
        automount_service_account_token  = false
        enable_service_links             = false
        host_network                     = false
        host_pid                         = false
        host_ipc                         = false
        node_selector                    = var.node_selector
        termination_grace_period_seconds = local.resources.shutdown_seconds + 5
        security_context {
          run_as_non_root = true
          run_as_user     = 10001
          run_as_group    = 10001
          seccomp_profile { type = "RuntimeDefault" }
        }
        container {
          name              = "security-shell"
          image             = var.image
          image_pull_policy = "IfNotPresent"
          command           = ["/usr/local/bin/day2-security-shell"]
          args              = ["/srv/day2/instance.json"]
          env {
            name  = "DAY2_EXPECTED_SHELL_INSTANCE"
            value = "sha256:${sha256(var.instance_json)}"
          }
          port {
            name           = "http"
            container_port = 8080
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            privileged                 = false
            capabilities { drop = ["ALL"] }
          }
          resources {
            requests = local.limits
            limits   = local.limits
          }
          volume_mount {
            name       = "instance"
            mount_path = "/srv/day2/instance.json"
            sub_path   = "instance.json"
            read_only  = true
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
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
            period_seconds        = 10
            timeout_seconds       = 2
            failure_threshold     = 6
            initial_delay_seconds = 10
          }
        }
        volume {
          name = "instance"
          config_map {
            name         = kubernetes_config_map_v1.instance.metadata[0].name
            default_mode = "0444"
          }
        }
        volume {
          name = "tmp"
          empty_dir {
            medium     = "Memory"
            size_limit = "64Mi"
          }
        }
      }
    }
  }
}
