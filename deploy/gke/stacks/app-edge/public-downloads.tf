# Chrome's updater cannot log in through IAP. Only explicitly selected download
# filenames use this backend; the host also requires artifact publication.
variable "public_download_paths" {
  description = "Exact /downloads/<filename>.crx or .xml paths published by the app artifact, reachable without an IAP login. Empty creates no download backend."
  type        = set(string)
  default     = []
  validation {
    condition = length(var.public_download_paths) <= 32 && alltrue([
      for path in var.public_download_paths : can(regex("^/downloads/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,155}\\.(crx|xml)$", path))
    ])
    error_message = "Only exact /downloads/<filename>.crx or .xml paths are supported; wildcards, queries, traversal and human routes are forbidden."
  }
}

resource "kubernetes_service_v1" "public_downloads" {
  count = length(var.public_download_paths) == 0 ? 0 : 1
  metadata {
    name      = "public-downloads"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
    annotations = {
      "cloud.google.com/backend-config" = jsonencode({ default = "public-downloads" })
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

resource "kubernetes_manifest" "public_downloads" {
  count = length(var.public_download_paths) == 0 ? 0 : 1
  manifest = {
    apiVersion = "cloud.google.com/v1"
    kind       = "BackendConfig"
    metadata = {
      name      = "public-downloads"
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
