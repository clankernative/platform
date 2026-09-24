data "google_project" "current" { project_id = var.project_id }
resource "kubernetes_namespace_v1" "app" {
  metadata { name = var.namespace }
  lifecycle { prevent_destroy = true }
}
resource "kubernetes_service_account_v1" "runtime" {
  metadata {
    name      = "runtime"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }
  automount_service_account_token = false
}
resource "kubernetes_storage_class_v1" "data" {
  metadata { name = "${var.namespace}-retained" }
  storage_provisioner    = "pd.csi.storage.gke.io"
  reclaim_policy         = "Retain"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true
  parameters             = { type = "pd-balanced" }
}
resource "kubernetes_persistent_volume_claim_v1" "data" {
  metadata {
    name      = "data"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }
  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = kubernetes_storage_class_v1.data.metadata[0].name
    resources { requests = { storage = "${var.storage_gib}Gi" } }
  }
  wait_until_bound = false
  lifecycle { prevent_destroy = true }
}
resource "kubernetes_limit_range_v1" "app" {
  metadata {
    name      = "limits"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }
  spec {
    limit {
      type = "Container"
      max  = { cpu = "4", memory = "4Gi" }
    }
  }
}
resource "kubernetes_resource_quota_v1" "app" {
  metadata {
    name      = "quota"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }
  spec { hard = { pods = "4", "requests.cpu" = "8", "requests.memory" = "8Gi", "persistentvolumeclaims" = "1" } }
}
resource "google_compute_global_address" "app" { name = var.namespace }
resource "google_dns_record_set" "app" {
  managed_zone = var.dns_managed_zone
  name         = "${var.domain}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.app.address]
}
resource "kubernetes_manifest" "backend" {
  manifest = {
    apiVersion = "cloud.google.com/v1"
    kind       = "BackendConfig"
    metadata   = { name = "app", namespace = kubernetes_namespace_v1.app.metadata[0].name }
    spec = {
      iap                = { enabled = true }
      healthCheck        = { type = "HTTP", requestPath = "/health/ready", port = 8080 }
      timeoutSec         = 60
      connectionDraining = { drainingTimeoutSec = 30 }
    }
  }
}
resource "kubernetes_manifest" "certificate" {
  manifest = {
    apiVersion = "networking.gke.io/v1"
    kind       = "ManagedCertificate"
    metadata   = { name = "app", namespace = kubernetes_namespace_v1.app.metadata[0].name }
    spec       = { domains = [var.domain] }
  }
}
resource "kubernetes_service_v1" "app" {
  metadata {
    name      = "app"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    annotations = {
      "cloud.google.com/neg"            = jsonencode({ ingress = true })
      "cloud.google.com/backend-config" = jsonencode({ default = "app" })
    }
  }
  spec {
    selector = { "day2.dev/app" = var.namespace }
    port {
      name        = "http"
      port        = 8080
      target_port = 8080
    }
  }
  depends_on = [kubernetes_manifest.backend]
}
resource "kubernetes_ingress_v1" "app" {
  metadata {
    name      = "app"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    annotations = {
      "kubernetes.io/ingress.class"                 = "gce"
      "kubernetes.io/ingress.global-static-ip-name" = google_compute_global_address.app.name
      "networking.gke.io/managed-certificates"      = "app"
      "kubernetes.io/ingress.allow-http"            = "false"
    }
  }
  spec {
    rule {
      host = var.domain
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service_v1.app.metadata[0].name
              port { number = 8080 }
            }
          }
        }
      }
    }
  }
  wait_for_load_balancer = false
  depends_on             = [kubernetes_manifest.certificate]
}
data "google_compute_backend_service" "app" {
  count = var.backend_service_name == "" ? 0 : 1
  name  = var.backend_service_name
}
resource "google_iap_web_backend_service_iam_member" "access" {
  for_each            = var.backend_service_name == "" ? toset([]) : var.iap_members
  project             = var.project_id
  web_backend_service = var.backend_service_name
  role                = "roles/iap.httpsResourceAccessor"
  member              = each.value
}
resource "kubernetes_config_map_v1" "contract" {
  metadata {
    name      = "platform-contract"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }
  data = {
    APP_DOMAIN                   = var.domain
    IAP_JWT_AUDIENCE             = var.backend_service_name == "" ? "" : "/projects/${data.google_project.current.number}/global/backendServices/${data.google_compute_backend_service.app[0].generated_id}"
    PVC_NAME                     = "data"
    SERVICE_NAME                 = "app"
    REQUIRED_SERVICE_LABEL_KEY   = "day2.dev/app"
    REQUIRED_SERVICE_LABEL_VALUE = var.namespace
  }
  depends_on = [google_iap_web_backend_service_iam_member.access]
}
resource "kubernetes_network_policy_v1" "app" {
  metadata {
    name      = "app-boundary"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
    ingress {
      from {
        ip_block { cidr = "35.191.0.0/16" }
      }
      from {
        ip_block { cidr = "130.211.0.0/22" }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
    }
    egress {
      to {
        namespace_selector { match_labels = { "kubernetes.io/metadata.name" = "kube-system" } }
        pod_selector { match_labels = { "k8s-app" = "kube-dns" } }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }
    egress {
      to {
        ip_block {
          cidr   = "0.0.0.0/0"
          except = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8"]
        }
      }
      ports {
        protocol = "TCP"
        port     = "443"
      }
    }
  }
}
output "iap_audience" { value = kubernetes_config_map_v1.contract.data["IAP_JWT_AUDIENCE"] }
output "address" { value = google_compute_global_address.app.address }
