# Private app calls have distinct IAP backends. The issuer admits only this
# workload; the receiver admits the explicitly selected source workloads.
variable "app_calls" {
  type = object({
    service_account_id = string
    issuer_backend     = string
    receiver_backend   = string
    incoming_workloads = set(string)
    serving_readers    = set(string)
    workload_name      = string
    serving_api_cidr   = string
  })
  default = null
  validation {
    condition = var.app_calls == null ? true : (
      can(regex("^[a-z][-a-z0-9]{4,28}[a-z0-9]$", var.app_calls.service_account_id)) &&
      length(var.app_calls.incoming_workloads) <= 32 && length(var.app_calls.serving_readers) <= 32 &&
      alltrue([for email in setunion(var.app_calls.incoming_workloads, var.app_calls.serving_readers) : can(regex("^[a-z0-9_-]+@[a-z0-9-]+\\.iam\\.gserviceaccount\\.com$", email))]) &&
      can(cidrhost(var.app_calls.serving_api_cidr, 0))
    )
    error_message = "App calls require one workload identity, bounded explicit peer identities and a control-plane CIDR."
  }
}

locals {
  app_call_gates          = var.app_calls == null ? {} : { issuer = var.app_calls.issuer_backend, receiver = var.app_calls.receiver_backend }
  resolved_app_call_gates = { for gate, backend in local.app_call_gates : gate => backend if backend != "" }
  resolved_app_call_backends = merge(
    length(data.google_compute_backend_service.app_call_issuer) == 0 ? {} : { issuer = data.google_compute_backend_service.app_call_issuer[0] },
    length(data.google_compute_backend_service.app_call_receiver) == 0 ? {} : { receiver = data.google_compute_backend_service.app_call_receiver[0] },
  )
  app_call_contract = var.app_calls == null ? {} : {
    APP_CALL_WORKLOAD_EMAIL    = google_service_account.app_calls[0].email
    APP_CALL_ISSUER_AUDIENCE   = try("/projects/${var.project_number}/global/backendServices/${local.resolved_app_call_backends["issuer"].generated_id}", "")
    APP_CALL_RECEIVER_AUDIENCE = try("/projects/${var.project_number}/global/backendServices/${local.resolved_app_call_backends["receiver"].generated_id}", "")
  }
}

resource "google_service_account" "app_calls" {
  count        = var.app_calls == null ? 0 : 1
  project      = var.project_id
  account_id   = var.app_calls.service_account_id
  display_name = "Day2 ${var.app_id} app calls"
}

resource "google_service_account_iam_member" "app_call_workload" {
  count              = var.app_calls == null ? 0 : 1
  service_account_id = google_service_account.app_calls[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${local.namespace_name}/${local.runtime_service_account}]"
}

resource "google_project_iam_custom_role" "app_call_signer" {
  count       = var.app_calls == null ? 0 : 1
  project     = var.project_id
  role_id     = "day2_${replace(var.app_id, "-", "_")}_jwt"
  title       = "Day2 ${var.app_id} JWT signing"
  permissions = ["iam.serviceAccounts.signJwt"]
}

resource "google_service_account_iam_member" "app_call_signer" {
  count              = var.app_calls == null ? 0 : 1
  service_account_id = google_service_account.app_calls[0].name
  role               = google_project_iam_custom_role.app_call_signer[0].name
  member             = "serviceAccount:${google_service_account.app_calls[0].email}"
}

resource "google_project_iam_custom_role" "app_call_discovery" {
  count       = var.app_calls == null ? 0 : 1
  project     = var.project_id
  role_id     = "day2_${replace(var.app_id, "-", "_")}_cluster"
  title       = "Day2 ${var.app_id} cluster discovery"
  permissions = ["container.clusters.get"]
}

resource "google_project_iam_member" "app_call_discovery" {
  count   = var.app_calls == null ? 0 : 1
  project = var.project_id
  role    = google_project_iam_custom_role.app_call_discovery[0].name
  member  = "serviceAccount:${google_service_account.app_calls[0].email}"
}

resource "kubernetes_role_v1" "app_call_serving" {
  count = var.app_calls == null ? 0 : 1
  metadata {
    name      = "app-call-serving"
    namespace = local.namespace_name
  }
  rule {
    api_groups     = ["apps"]
    resources      = ["statefulsets"]
    resource_names = [var.app_calls.workload_name]
    verbs          = ["get"]
  }
  rule {
    api_groups     = [""]
    resources      = ["pods"]
    resource_names = ["${var.app_calls.workload_name}-0"]
    verbs          = ["get"]
  }
  rule {
    api_groups     = [""]
    resources      = ["serviceaccounts"]
    resource_names = [local.runtime_service_account]
    verbs          = ["get"]
  }
}

resource "kubernetes_role_binding_v1" "app_call_serving" {
  count = var.app_calls == null ? 0 : 1
  metadata {
    name      = "app-call-serving"
    namespace = local.namespace_name
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.app_call_serving[0].metadata[0].name
  }
  dynamic "subject" {
    for_each = setunion(var.app_calls.serving_readers, [google_service_account.app_calls[0].email])
    content {
      kind      = "User"
      name      = subject.value
      api_group = "rbac.authorization.k8s.io"
    }
  }
}

resource "kubernetes_network_policy_v1" "app_call_serving_api" {
  count = var.app_calls == null ? 0 : 1
  metadata {
    name      = "app-call-serving-api"
    namespace = local.namespace_name
  }
  spec {
    pod_selector { match_labels = local.service_selector }
    policy_types = ["Egress"]
    egress {
      to {
        ip_block { cidr = var.app_calls.serving_api_cidr }
      }
      ports {
        protocol = "TCP"
        port     = "443"
      }
    }
  }
}

resource "kubernetes_service_v1" "app_calls" {
  for_each = local.app_call_gates
  metadata {
    name      = "app-${each.key}"
    namespace = local.namespace_name
    labels    = local.platform_labels
    annotations = {
      "cloud.google.com/backend-config" = jsonencode({ default = "app-${each.key}" })
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

resource "kubernetes_manifest" "app_calls" {
  for_each = local.app_call_gates
  manifest = {
    apiVersion = "cloud.google.com/v1"
    kind       = "BackendConfig"
    metadata   = { name = "app-${each.key}", namespace = local.namespace_name }
    spec = {
      iap         = { enabled = true }
      timeoutSec  = var.backend_timeout_seconds
      healthCheck = { checkIntervalSec = 10, timeoutSec = 5, port = 8080, requestPath = var.health_check_path, type = "HTTP" }
    }
  }
}

data "google_compute_backend_service" "app_call_issuer" {
  count   = var.app_calls == null ? 0 : (var.app_calls.issuer_backend == "" ? 0 : 1)
  project = var.project_id
  name    = var.app_calls.issuer_backend
}

data "google_compute_backend_service" "app_call_receiver" {
  count   = var.app_calls == null ? 0 : (var.app_calls.receiver_backend == "" ? 0 : 1)
  project = var.project_id
  name    = var.app_calls.receiver_backend
}

resource "google_iap_web_backend_service_iam_binding" "app_calls" {
  for_each            = local.resolved_app_call_gates
  project             = var.project_id
  web_backend_service = each.value
  role                = "roles/iap.httpsResourceAccessor"
  members             = each.key == "issuer" ? ["serviceAccount:${google_service_account.app_calls[0].email}"] : sort([for email in var.app_calls.incoming_workloads : "serviceAccount:${email}"])
  lifecycle {
    precondition {
      condition     = try(jsondecode(local.resolved_app_call_backends[each.key].description)["kubernetes.io/service-name"], "") == "${local.namespace_name}/app-${each.key}" && try(local.resolved_app_call_backends[each.key].iap[0].enabled, false)
      error_message = "The selected app-call backend must belong to the exact protected Service."
    }
  }
}
