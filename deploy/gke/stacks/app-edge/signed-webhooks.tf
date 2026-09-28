# Only exact Day2 signed-ingress paths bypass IAP. Human/API routes continue
# through the existing IAP backend, including the default backend. Day2 verifies
# the provider signature before parsing/admitting each webhook.
variable "signed_webhook_paths" {
  description = "Exact /ingress/<endpoint> paths verified by the app host, reachable by providers without an IAP login. Empty creates no public provider backend."
  type        = set(string)
  default     = []
  validation {
    condition     = length(var.signed_webhook_paths) <= 16 && alltrue([for path in var.signed_webhook_paths : can(regex("^/ingress/[a-z][a-z0-9_]{0,47}$", path))])
    error_message = "Only exact /ingress/<endpoint> paths are supported; wildcards, queries and human routes are forbidden."
  }
}

resource "kubernetes_service_v1" "signed_webhooks" {
  count = length(var.signed_webhook_paths) == 0 ? 0 : 1
  metadata {
    name      = "signed-webhooks"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
    annotations = {
      "cloud.google.com/backend-config" = jsonencode({ default = "signed-webhooks" })
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

resource "kubernetes_manifest" "signed_webhooks" {
  count = length(var.signed_webhook_paths) == 0 ? 0 : 1
  manifest = {
    apiVersion = "cloud.google.com/v1"
    kind       = "BackendConfig"
    metadata = {
      name      = "signed-webhooks"
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
