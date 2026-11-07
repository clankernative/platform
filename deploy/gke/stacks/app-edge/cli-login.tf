# Native clients need public metadata before they can obtain an IAP ID token.
# Only this exact path reaches the anonymous backend. The native host publishes
# an allowlisted projection of the instance, never a static arbitrary file.
variable "cli_desktop_client" {
  description = "Opt-in company-owned Google Desktop public-client registration. Both fields are intentionally published in anonymous CLI discovery. Never supply a confidential Web application secret or user token. Null publishes no bootstrap route or IAP settings."
  type        = object({ client_id = string, client_secret = string })
  default     = null
  validation {
    condition = var.cli_desktop_client == null ? true : (
      can(regex("^[A-Za-z0-9-]{1,200}\\.apps\\.googleusercontent\\.com$", var.cli_desktop_client.client_id)) &&
      can(regex("^[A-Za-z0-9_-]{16,256}$", var.cli_desktop_client.client_secret))
    )
    error_message = "cli_desktop_client must be null or a complete bounded Google Desktop registration."
  }
}

resource "google_iap_settings" "cli_login" {
  count = var.cli_desktop_client != null && local.backend_service_resolved ? 1 : 0
  name  = "projects/${var.project_number}/iap_web/compute/services/${data.google_compute_backend_service.app[0].generated_id}"
  access_settings {
    oauth_settings {
      programmatic_clients = [var.cli_desktop_client.client_id]
    }
  }
}

resource "kubernetes_service_v1" "cli_discovery" {
  count = var.cli_desktop_client == null ? 0 : 1
  metadata {
    name      = "cli-discovery"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
    annotations = {
      "cloud.google.com/backend-config" = jsonencode({ default = "cli-discovery" })
      "cloud.google.com/neg"            = jsonencode({ ingress = true })
    }
  }
  lifecycle {
    ignore_changes = [metadata[0].annotations["cloud.google.com/neg-status"]]
  }
  spec {
    selector = local.service_selector
    port {
      name        = "http"
      port        = 8080
      target_port = 8080
    }
    type = "ClusterIP"
  }
}

resource "kubernetes_manifest" "cli_discovery" {
  count = var.cli_desktop_client == null ? 0 : 1
  manifest = {
    apiVersion = "cloud.google.com/v1"
    kind       = "BackendConfig"
    metadata = {
      name      = "cli-discovery"
      namespace = kubernetes_namespace_v1.app.metadata[0].name
    }
    spec = {
      iap                = { enabled = false }
      timeoutSec         = var.backend_timeout_seconds
      connectionDraining = { drainingTimeoutSec = var.backend_connection_draining_timeout_seconds }
      healthCheck = {
        checkIntervalSec = 10
        timeoutSec       = 5
        port             = 8080
        requestPath      = var.health_check_path
        type             = "HTTP"
      }
    }
  }
}
