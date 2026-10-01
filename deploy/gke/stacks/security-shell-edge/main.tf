# Installation-owned security edge. Application stacks only consume its contract.
# The separately qualified shell workload selects this Service; this root never
# deploys an app image, mounts an app database or reads secret values.
locals {
  labels       = { "app.kubernetes.io/part-of" = "day2-security" }
  selector     = { "day2.dev/service" = "security-shell" }
  service_name = "security-shell"
  cert_name    = "security-${substr(sha256(var.domain), 0, 32)}"
  origin       = "https://${var.domain}"
  resolved     = var.backend_service_name != ""
  audience     = local.resolved ? "/projects/${var.project_number}/global/backendServices/${data.google_compute_backend_service.shell[0].generated_id}" : ""
  identity_id  = "day2-security-shell-${substr(sha256(var.namespace), 0, 8)}"
}

resource "google_service_account" "shell" {
  project      = var.project_id
  account_id   = local.identity_id
  display_name = "Day2 dedicated security shell (${var.namespace})"
}

resource "google_service_account_iam_member" "workload" {
  service_account_id = google_service_account.shell.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/security-shell]"
}

# Only JWT signing, scoped to this service account. No private key is created.
resource "google_project_iam_custom_role" "sign_jwt" {
  project     = var.project_id
  role_id     = "day2SecurityShellSignJwt_${substr(sha256(var.namespace), 0, 8)}"
  title       = "Day2 security shell JWT signing"
  permissions = ["iam.serviceAccounts.signJwt"]
}

resource "google_service_account_iam_member" "sign_jwt" {
  service_account_id = google_service_account.shell.name
  role               = google_project_iam_custom_role.sign_jwt.name
  member             = "serviceAccount:${google_service_account.shell.email}"
}

resource "kubernetes_namespace_v1" "shell" {
  metadata {
    name   = var.namespace
    labels = local.labels
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "kubernetes_service_account_v1" "shell" {
  metadata {
    name      = "security-shell"
    namespace = kubernetes_namespace_v1.shell.metadata[0].name
    labels    = local.labels
    annotations = {
      "iam.gke.io/gcp-service-account" = google_service_account.shell.email
    }
  }
  automount_service_account_token = false
}

resource "google_secret_manager_secret_iam_member" "shell" {
  for_each  = var.runtime_secret_ids
  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.shell.email}"
}

resource "kubernetes_service_v1" "shell" {
  metadata {
    name      = local.service_name
    namespace = kubernetes_namespace_v1.shell.metadata[0].name
    labels    = local.labels
    annotations = {
      "cloud.google.com/backend-config" = jsonencode({ default = "security-shell" })
      "cloud.google.com/neg"            = jsonencode({ ingress = true })
    }
  }
  lifecycle {
    ignore_changes = [metadata[0].annotations["cloud.google.com/neg-status"]]
  }
  spec {
    selector = local.selector
    type     = "ClusterIP"
    port {
      name        = "http"
      port        = 8080
      target_port = 8080
    }
  }
}

resource "kubernetes_manifest" "backend" {
  manifest = {
    apiVersion = "cloud.google.com/v1"
    kind       = "BackendConfig"
    metadata   = { name = "security-shell", namespace = var.namespace }
    spec = {
      iap        = { enabled = true }
      timeoutSec = 30
      healthCheck = {
        checkIntervalSec = 10
        timeoutSec       = 5
        port             = 8080
        requestPath      = "/health/ready"
        type             = "HTTP"
      }
    }
  }
  depends_on = [kubernetes_namespace_v1.shell]
}

resource "kubernetes_manifest" "frontend" {
  manifest = {
    apiVersion = "networking.gke.io/v1beta1"
    kind       = "FrontendConfig"
    metadata   = { name = "security-shell", namespace = var.namespace }
    spec       = { redirectToHttps = { enabled = true } }
  }
  depends_on = [kubernetes_namespace_v1.shell]
}

resource "kubernetes_manifest" "certificate" {
  manifest = {
    apiVersion = "networking.gke.io/v1"
    kind       = "ManagedCertificate"
    metadata   = { name = local.cert_name, namespace = var.namespace }
    spec       = { domains = [var.domain] }
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [kubernetes_namespace_v1.shell]
}

resource "google_compute_global_address" "shell" {
  project = var.project_id
  name    = "day2-security-${substr(sha256(var.namespace), 0, 24)}"
}

resource "cloudflare_dns_record" "shell" {
  zone_id = var.cloudflare_zone_id
  name    = var.domain
  type    = "A"
  content = google_compute_global_address.shell.address
  # The dedicated GKE certificate covers arbitrary company subdomain depth.
  proxied = false
  ttl     = 1
}

resource "kubernetes_ingress_v1" "shell" {
  metadata {
    name      = "security-shell"
    namespace = var.namespace
    labels    = local.labels
    annotations = {
      "kubernetes.io/ingress.class"                 = "gce"
      "kubernetes.io/ingress.global-static-ip-name" = google_compute_global_address.shell.name
      "networking.gke.io/managed-certificates"      = local.cert_name
      "networking.gke.io/v1beta1.FrontendConfig"    = "security-shell"
    }
  }
  spec {
    default_backend {
      service {
        name = kubernetes_service_v1.shell.metadata[0].name
        port { name = "http" }
      }
    }
    rule {
      host = var.domain
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service_v1.shell.metadata[0].name
              port { name = "http" }
            }
          }
        }
      }
    }
  }
  depends_on = [kubernetes_manifest.certificate, kubernetes_manifest.backend, kubernetes_manifest.frontend]
}

data "google_compute_backend_service" "shell" {
  count   = local.resolved ? 1 : 0
  project = var.project_id
  name    = var.backend_service_name
}

resource "google_iap_web_backend_service_iam_binding" "shell" {
  count               = local.resolved ? 1 : 0
  project             = var.project_id
  web_backend_service = var.backend_service_name
  role                = "roles/iap.httpsResourceAccessor"
  members             = sort(distinct(var.iap_members))
  lifecycle {
    precondition {
      condition     = try(jsondecode(data.google_compute_backend_service.shell[0].description)["kubernetes.io/service-name"], "") == "${var.namespace}/${local.service_name}"
      error_message = "backend_service_name must name the dedicated security-shell Service, never an app backend."
    }
    precondition {
      condition     = try(data.google_compute_backend_service.shell[0].iap[0].enabled, false)
      error_message = "The selected shell backend must have IAP enabled."
    }
  }
}

resource "kubernetes_config_map_v1" "contract" {
  metadata {
    name      = "security-shell-contract"
    namespace = var.namespace
    labels    = local.labels
  }
  data = {
    EDGE_ROLE                    = "security_shell"
    SECURITY_SHELL_ORIGIN        = local.origin
    IAP_JWT_AUDIENCE             = local.audience
    REAUTH_CALLBACK_URL          = "${local.origin}/_day2/reauth/callback"
    SERVICE_NAME                 = local.service_name
    SERVICE_ACCOUNT_NAME         = kubernetes_service_account_v1.shell.metadata[0].name
    OAUTH_SHELL_SERVICE_ACCOUNT  = google_service_account.shell.email
    REQUIRED_SERVICE_LABEL_KEY   = "day2.dev/service"
    REQUIRED_SERVICE_LABEL_VALUE = "security-shell"
  }
  depends_on = [google_iap_web_backend_service_iam_binding.shell, google_service_account_iam_member.workload, google_service_account_iam_member.sign_jwt]
}
