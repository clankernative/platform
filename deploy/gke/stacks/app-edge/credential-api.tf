# Managed tokens enter a dedicated backend. The app host authenticates each
# request; human routes and the default backend still require IAP.
variable "credential_api" {
  description = "Expose only /_day2/credentials/api/* for an installation with an explicitly selected credential verifier. Disabled by default."
  type        = bool
  default     = false
}

resource "kubernetes_service_v1" "credential_api" {
  count = var.credential_api ? 1 : 0
  metadata {
    name      = "credential-api"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
    annotations = {
      "cloud.google.com/backend-config" = jsonencode({ default = "credential-api" })
      "cloud.google.com/neg"            = jsonencode({ ingress = true })
    }
  }
  lifecycle { ignore_changes = [metadata[0].annotations["cloud.google.com/neg-status"]] }
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

resource "kubernetes_manifest" "credential_api" {
  count = var.credential_api ? 1 : 0
  manifest = {
    apiVersion = "cloud.google.com/v1"
    kind       = "BackendConfig"
    metadata   = { name = "credential-api", namespace = local.namespace_name }
    spec = {
      iap                = { enabled = false }
      timeoutSec         = var.backend_timeout_seconds
      connectionDraining = { drainingTimeoutSec = var.backend_connection_draining_timeout_seconds }
      healthCheck        = { checkIntervalSec = 10, timeoutSec = 5, port = 8080, requestPath = var.health_check_path, type = "HTTP" }
    }
  }
}
