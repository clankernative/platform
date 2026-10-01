# Per-app edge for one day2 app: namespace, runtime service account, retained
# data PVC, guardrails, Service, IAP BackendConfig, managed certificate, static
# IP, Cloudflare DNS, Ingress, IAP grant, network policies, Artifact Registry
# repository, workload state bucket, deployer RBAC, Backup for GKE plan,
# off-cluster backup bucket and its write-only identity, and the platform
# contract ConfigMap that stacks/day2-app reads.
#
# Object names and labels match what the first gke-cloudflare app stack
# created, so existing apps adopt this root without replacing anything.

locals {
  namespace_name = "${var.namespace_prefix}${var.app_id}"

  # Labels every platform-owned object in the namespace carries.
  platform_labels = {
    "internal-tools.wonderly.io/app-id" = var.app_id
    "managed-by"                        = "internal-tools-infra"
  }

  runtime_service_account = "runtime"
  pvc_name                = "data"
  service_name            = "app"
  ingress_name            = "app"
  backend_config_name     = "backend"
  frontend_config_name    = "frontend"
  # Named after its domain: GKE cannot change the domains of a ManagedCertificate
  # attached to a load balancer (the controller must delete the in-use
  # SslCertificate first and is refused). A new domain is a new certificate:
  # created first (create_before_destroy), the Ingress repointed, then the old
  # one removed.
  managed_cert_name = "managed-cert-${replace(var.domain, ".", "-")}"
  contract_name     = "platform-contract"
  global_ip_name    = "${var.app_id}-ip"
  artifact_repo_id  = var.app_id
  state_bucket_name = "${var.project_id}-${var.app_id}-state"
  backup_plan_name  = "${var.app_id}-backup"
  # Off-cluster day2 backups (day2-app's CronJob uploads them).
  backup_bucket_name              = "${var.project_id}-${var.app_id}-backups"
  backup_kubernetes_account       = "backup"
  backup_google_account_id        = var.offsite_backup_service_account_id != "" ? var.offsite_backup_service_account_id : "${var.app_id}-backup"
  backup_workload_identity_member = "serviceAccount:${var.project_id}.svc.id.goog[${local.namespace_name}/${local.backup_kubernetes_account}]"
  cluster_id                      = "projects/${var.project_id}/locations/${var.cluster_location}/clusters/${var.cluster_name}"

  # The label the Service (and the load balancer ingress policy) selects;
  # day2-app puts it on the pod from the contract.
  service_label_key   = "internal-tools.wonderly.io/service"
  service_label_value = "app"
  service_selector    = { (local.service_label_key) = local.service_label_value }

  o11y_label_key   = "o11y.wonderly.info/service"
  o11y_label_value = var.o11y_service_label != "" ? var.o11y_service_label : "${var.app_id}-api"

  # Egress policies apply to every pod except ones labelled as one-off smoke
  # pods, which get no egress at all.
  egress_exempt_label_key   = "internal-tools.wonderly.io/deploy-smoke"
  egress_exempt_label_value = "true"

  node_local_dns_cidr = "169.254.20.10/32"
  gke_metadata_cidr   = "169.254.169.252/32"
  gke_metadata_port   = "988"
  # Google Front End health check and proxy ranges.
  load_balancer_cidrs = ["35.191.0.0/16", "130.211.0.0/22"]
  public_egress_except_cidrs = distinct(concat(
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"],
    var.cluster_cidrs,
  ))

  deployer_subjects = [
    for subject in var.deployer_subjects : {
      kind = startswith(subject, "group:") ? "Group" : "User"
      name = trimprefix(trimprefix(trimprefix(subject, "group:"), "user:"), "serviceAccount:")
    }
  ]
  deployer_service_accounts = toset([
    for subject in var.deployer_subjects : subject
    if startswith(subject, "serviceAccount:")
  ])

  backend_service_resolved = var.backend_service_name != ""
  iap_jwt_audience = (
    local.backend_service_resolved
    ? "/projects/${var.project_number}/global/backendServices/${data.google_compute_backend_service.app[0].generated_id}"
    : ""
  )

  # Exactly what stacks/day2-app reads (plus APP_NAMESPACE).
  contract_data = {
    APP_DOMAIN                   = var.domain
    APP_NAMESPACE                = local.namespace_name
    IAP_JWT_AUDIENCE             = local.iap_jwt_audience
    O11Y_SERVICE_LABEL_KEY       = local.o11y_label_key
    O11Y_SERVICE_LABEL_VALUE     = local.o11y_label_value
    PVC_NAME                     = local.pvc_name
    REQUIRED_SERVICE_LABEL_KEY   = local.service_label_key
    REQUIRED_SERVICE_LABEL_VALUE = local.service_label_value
    SERVICE_NAME                 = local.service_name
  }
}

# --- Namespace, identity, storage, guardrails -------------------------------

resource "kubernetes_namespace_v1" "app" {
  metadata {
    name   = local.namespace_name
    labels = local.platform_labels
  }

  lifecycle {
    prevent_destroy = true
  }
}

# The pod's service account (the tenancy policy admits only this name in app
# namespaces). day2-app does not mount its token.
resource "kubernetes_service_account_v1" "runtime" {
  metadata {
    name      = local.runtime_service_account
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
  }
}

# Holds day2's .state directory (host state, per-app SQLite, replica lock).
resource "kubernetes_persistent_volume_claim_v1" "data" {
  # The workload (day2-app) is applied later; do not wait for a consumer.
  wait_until_bound = false

  metadata {
    name      = local.pvc_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
  }

  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = var.storage_class_name

    resources {
      requests = {
        storage = "${var.sqlite_storage_gb}Gi"
      }
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "kubernetes_limit_range_v1" "runtime_guardrails" {
  metadata {
    name      = "runtime-resource-guardrails"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
  }

  spec {
    limit {
      type = "Container"
      default = {
        cpu                 = var.resource_guardrails.container_default_limits.cpu
        memory              = var.resource_guardrails.container_default_limits.memory
        "ephemeral-storage" = var.resource_guardrails.container_default_limits.ephemeral_storage
      }
      default_request = {
        cpu                 = var.resource_guardrails.container_default_requests.cpu
        memory              = var.resource_guardrails.container_default_requests.memory
        "ephemeral-storage" = var.resource_guardrails.container_default_requests.ephemeral_storage
      }
      max = {
        cpu                 = var.resource_guardrails.container_max.cpu
        memory              = var.resource_guardrails.container_max.memory
        "ephemeral-storage" = var.resource_guardrails.container_max.ephemeral_storage
      }
    }
  }
}

resource "kubernetes_resource_quota_v1" "runtime_guardrails" {
  metadata {
    name      = "runtime-resource-guardrails"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
  }

  spec {
    hard = {
      "requests.cpu"               = var.resource_guardrails.namespace_quota.requests_cpu
      "requests.memory"            = var.resource_guardrails.namespace_quota.requests_memory
      "requests.ephemeral-storage" = var.resource_guardrails.namespace_quota.requests_ephemeral_storage
      "limits.cpu"                 = var.resource_guardrails.namespace_quota.limits_cpu
      "limits.memory"              = var.resource_guardrails.namespace_quota.limits_memory
      "limits.ephemeral-storage"   = var.resource_guardrails.namespace_quota.limits_ephemeral_storage
      pods                         = tostring(var.resource_guardrails.namespace_quota.pods)
    }
  }
}

resource "google_gke_backup_backup_plan" "app" {
  project     = var.project_id
  location    = var.region
  name        = local.backup_plan_name
  cluster     = local.cluster_id
  description = "Backup for GKE plan for ${var.app_id}"

  labels = {
    app        = var.app_id
    managed_by = "opentofu"
    purpose    = "sqlite-recovery"
  }

  backup_config {
    include_secrets     = false
    include_volume_data = true

    selected_namespaces {
      namespaces = [kubernetes_namespace_v1.app.metadata[0].name]
    }
  }

  backup_schedule {
    rpo_config {
      target_rpo_minutes = var.backup.target_rpo_minutes
    }
  }

  retention_policy {
    backup_delete_lock_days = var.backup.delete_lock_days
    backup_retain_days      = var.backup.retain_days
  }

  lifecycle {
    # Deleting the plan deletes its backups.
    prevent_destroy = true
  }

  depends_on = [kubernetes_persistent_volume_claim_v1.data]
}

# --- Off-cluster backups -------------------------------------------------------
# day2-app's CronJob runs day2-backup (runtime image) beside the serving pod and
# uploads the verified bundle here, one object per file under
# <app_id>/<UTC stamp>/, with a COMPLETE marker last. The uploader can only
# create objects: it cannot read, list, overwrite or delete them, so a
# compromised backup pod cannot destroy earlier backups. The retention policy
# (not locked) additionally refuses deletion or replacement by anyone before
# retention_days; lifecycle deletes objects one day after that.

resource "google_storage_bucket" "backups" {
  name                        = local.backup_bucket_name
  project                     = var.project_id
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  retention_policy {
    is_locked        = false
    retention_period = var.offsite_backup_retention_days * 86400
  }

  lifecycle_rule {
    condition {
      age = var.offsite_backup_retention_days + 1
    }

    action {
      type = "Delete"
    }
  }

  labels = {
    app        = var.app_id
    managed_by = "opentofu"
    purpose    = "day2-backup"
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = length(local.backup_bucket_name) <= 63
      error_message = "The backup bucket name ${local.backup_bucket_name} exceeds 63 characters; shorten project_id or app_id."
    }
  }
}

resource "google_service_account" "backup" {
  project      = var.project_id
  account_id   = local.backup_google_account_id
  display_name = "day2 backups for ${var.app_id}"
  description  = "Uploads ${var.app_id}'s scheduled day2 backups to ${local.backup_bucket_name}; object create only."

  lifecycle {
    precondition {
      condition     = can(regex("^[a-z]([-a-z0-9]{4,28}[a-z0-9])$", local.backup_google_account_id))
      error_message = "The backup service account id ${local.backup_google_account_id} must be 6-30 lowercase letters, digits and hyphens; set offsite_backup_service_account_id for a long app_id."
    }
  }
}

locals {
  # From the created account's id (not its computed attributes), so the plan
  # shows the exact principal.
  backup_google_account_email = "${google_service_account.backup.account_id}@${var.project_id}.iam.gserviceaccount.com"
}

resource "google_storage_bucket_iam_member" "backup_object_creator" {
  bucket = google_storage_bucket.backups.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${local.backup_google_account_email}"
}

resource "google_storage_bucket_iam_member" "backup_readers" {
  for_each = toset(var.offsite_backup_readers)

  bucket = google_storage_bucket.backups.name
  role   = "roles/storage.objectViewer"
  member = each.value
}

# Only the backup Job's Kubernetes service account in this namespace may act as
# the uploader (GKE Workload Identity through the metadata server; no key and
# no mounted token).
resource "google_service_account_iam_member" "backup_workload_identity" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${local.backup_google_account_email}"
  role               = "roles/iam.workloadIdentityUser"
  member             = local.backup_workload_identity_member
}

# The tenancy policy admits this account only for Jobs labelled
# internal-tools.wonderly.io/service=backup with token automount disabled.
resource "kubernetes_service_account_v1" "backup" {
  metadata {
    name      = local.backup_kubernetes_account
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
    annotations = {
      "iam.gke.io/gcp-service-account" = local.backup_google_account_email
    }
  }

  automount_service_account_token = false
}

# --- Deploy surface: image repository, workload state, deployer RBAC --------

resource "google_artifact_registry_repository" "app" {
  project       = var.project_id
  location      = var.region
  repository_id = local.artifact_repo_id
  description   = "Artifact Registry for ${var.app_id}"
  format        = "DOCKER"

  cleanup_policies {
    id     = "keep-recent-20"
    action = "KEEP"

    most_recent_versions {
      keep_count = 20
    }
  }

  cleanup_policies {
    id     = "delete-everything-else"
    action = "DELETE"

    condition {
      tag_state = "ANY"
    }
  }

  lifecycle {
    # Holds the running workload's image digest.
    prevent_destroy = true
  }
}

resource "google_artifact_registry_repository_iam_member" "deployer_writer" {
  for_each = local.deployer_service_accounts

  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.app.repository_id
  role       = "roles/artifactregistry.writer"
  member     = each.value
}

# OpenTofu state of the app's day2-app root (the instance's backend/apps/<app>.hcl).
resource "google_storage_bucket" "state" {
  name                        = local.state_bucket_name
  project                     = var.project_id
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  labels = {
    app        = var.app_id
    managed_by = "opentofu"
    purpose    = "iac-state"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "deployer_state_bucket_object_admin" {
  for_each = toset(var.deployer_subjects)

  bucket = google_storage_bucket.state.name
  role   = "roles/storage.objectAdmin"
  member = each.value
}

resource "google_storage_bucket_iam_member" "deployer_state_bucket_reader" {
  for_each = toset(var.deployer_subjects)

  bucket = google_storage_bucket.state.name
  role   = "roles/storage.legacyBucketReader"
  member = each.value
}

# What day2-app (and a deploy identity inspecting the rollout) needs in the
# namespace. It cannot touch platform-owned objects; the tenancy stack's
# admission policies enforce that independently of RBAC.
resource "kubernetes_role_v1" "deployer" {
  metadata {
    name      = "app-deployer"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "statefulsets"]
    verbs      = ["create", "delete", "get", "list", "patch", "update", "watch"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["controllerrevisions", "replicasets"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments/scale", "statefulsets/scale"]
    verbs      = ["get", "patch", "update"]
  }

  rule {
    api_groups = ["batch"]
    resources  = ["jobs"]
    verbs      = ["create", "delete", "get", "list", "patch", "update", "watch"]
  }

  rule {
    api_groups = [""]
    resources  = ["configmaps"]
    verbs      = ["create", "delete", "get", "list", "patch", "update", "watch"]
  }

  rule {
    api_groups = [""]
    resources  = ["pods"]
    verbs      = ["delete", "get", "list", "patch", "watch"]
  }

  rule {
    api_groups = [""]
    resources  = ["services"]
    verbs      = ["get", "list", "patch", "update", "watch"]
  }

  rule {
    api_groups = ["discovery.k8s.io"]
    resources  = ["endpointslices"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = [""]
    resources  = ["persistentvolumeclaims"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = [""]
    resources  = ["serviceaccounts"]
    verbs      = ["get"]
  }

  rule {
    api_groups = ["batch"]
    resources  = ["cronjobs"]
    verbs      = ["get", "patch", "update"]
  }

  rule {
    api_groups = [""]
    resources  = ["pods/portforward"]
    verbs      = ["create"]
  }

  rule {
    api_groups = [""]
    resources  = ["pods/exec"]
    verbs      = ["create"]
  }

  rule {
    api_groups = [""]
    resources  = ["events", "pods/log"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["secrets-store.csi.x-k8s.io"]
    resources  = ["secretproviderclasses"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_role_binding_v1" "deployer" {
  count = length(local.deployer_subjects) == 0 ? 0 : 1

  metadata {
    name      = "app-deployer"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.deployer.metadata[0].name
  }

  dynamic "subject" {
    for_each = local.deployer_subjects

    content {
      api_group = "rbac.authorization.k8s.io"
      kind      = subject.value.kind
      name      = subject.value.name
    }
  }
}

# --- Edge: Service, BackendConfig, certificate, IP, DNS, Ingress, IAP -------

resource "kubernetes_service_v1" "app" {
  metadata {
    name      = local.service_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    annotations = {
      "cloud.google.com/backend-config" = jsonencode({
        default = local.backend_config_name
      })
      "cloud.google.com/neg" = jsonencode({
        ingress = true
      })
    }
    labels = merge(local.platform_labels, {
      (local.o11y_label_key) = local.o11y_label_value
    })
  }

  lifecycle {
    ignore_changes = [
      metadata[0].annotations["cloud.google.com/neg-status"],
    ]
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

resource "kubernetes_manifest" "frontend_config" {
  manifest = {
    apiVersion = "networking.gke.io/v1beta1"
    kind       = "FrontendConfig"
    metadata = {
      name      = local.frontend_config_name
      namespace = kubernetes_namespace_v1.app.metadata[0].name
    }
    spec = {
      redirectToHttps = {
        enabled = true
      }
    }
  }
}

resource "kubernetes_manifest" "backend_config" {
  manifest = {
    apiVersion = "cloud.google.com/v1"
    kind       = "BackendConfig"
    metadata = {
      name      = local.backend_config_name
      namespace = kubernetes_namespace_v1.app.metadata[0].name
    }
    spec = {
      # Google-managed OAuth client; no client secret.
      iap = {
        enabled = true
      }
      timeoutSec = var.backend_timeout_seconds
      connectionDraining = {
        drainingTimeoutSec = var.backend_connection_draining_timeout_seconds
      }
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

resource "kubernetes_manifest" "managed_certificate" {
  lifecycle {
    create_before_destroy = true
  }

  manifest = {
    apiVersion = "networking.gke.io/v1"
    kind       = "ManagedCertificate"
    metadata = {
      name      = local.managed_cert_name
      namespace = kubernetes_namespace_v1.app.metadata[0].name
    }
    spec = {
      domains = [var.domain]
    }
  }
}

resource "google_compute_global_address" "app" {
  project = var.project_id
  name    = local.global_ip_name
}

resource "cloudflare_dns_record" "app" {
  zone_id = var.cloudflare_zone_id
  name    = var.domain
  type    = "A"
  content = google_compute_global_address.app.address
  proxied = var.cloudflare_proxied
  ttl     = 1
}

resource "kubernetes_ingress_v1" "app" {
  depends_on = [kubernetes_manifest.managed_certificate]

  metadata {
    name      = local.ingress_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    annotations = {
      "kubernetes.io/ingress.class"                 = "gce"
      "kubernetes.io/ingress.global-static-ip-name" = google_compute_global_address.app.name
      "networking.gke.io/managed-certificates"      = local.managed_cert_name
      "networking.gke.io/v1beta1.FrontendConfig"    = local.frontend_config_name
    }
    labels = local.platform_labels
  }

  spec {
    default_backend {
      service {
        name = kubernetes_service_v1.app.metadata[0].name
        port {
          name = "http"
        }
      }
    }

    rule {
      host = var.domain

      http {
        dynamic "path" {
          for_each = var.signed_webhook_paths
          content {
            path      = path.value
            path_type = "Exact"
            backend {
              service {
                name = kubernetes_service_v1.signed_webhooks[0].metadata[0].name
                port { name = "http" }
              }
            }
          }
        }
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service_v1.app.metadata[0].name
              port {
                name = "http"
              }
            }
          }
        }
      }
    }
  }
}

# The GKE ingress controller names the backend service after it syncs the
# Ingress. Bootstrap: apply with backend_service_name = "", read
#   kubectl -n <namespace> get ingress app \
#     -o jsonpath='{.metadata.annotations.ingress\.kubernetes\.io/backends}'
# then set backend_service_name to that key and apply again. (A name implies
# the Ingress already exists, so this reads at plan time.)
data "google_compute_backend_service" "app" {
  count = local.backend_service_resolved ? 1 : 0

  project = var.project_id
  name    = var.backend_service_name
}

resource "google_iap_web_backend_service_iam_binding" "app_access" {
  count = local.backend_service_resolved ? 1 : 0

  project             = var.project_id
  web_backend_service = var.backend_service_name
  role                = "roles/iap.httpsResourceAccessor"
  members             = local.app_iap_members

  lifecycle {
    precondition {
      condition     = try(jsondecode(data.google_compute_backend_service.app[0].description)["kubernetes.io/service-name"], "") == "${local.namespace_name}/${local.service_name}"
      error_message = "backend_service_name ${var.backend_service_name} is not the backend of Service ${local.namespace_name}/${local.service_name}; take it from the Ingress's ingress.kubernetes.io/backends annotation."
    }

    precondition {
      condition = var.security_shell_contract == null ? true : (
        lookup(local.oauth_shell_contract, "EDGE_ROLE", "") == "security_shell" &&
        can(regex("^[a-z0-9_-]+@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", local.oauth_shell_account)) &&
        can(regex("^/projects/[0-9]{1,24}/global/backendServices/[0-9]{1,24}$", lookup(local.oauth_shell_contract, "IAP_JWT_AUDIENCE", ""))) &&
        lookup(local.oauth_shell_contract, "IAP_JWT_AUDIENCE", "") != "/projects/${var.project_number}/global/backendServices/${data.google_compute_backend_service.app[0].generated_id}"
      )
      error_message = "The OAuth shell contract must publish a dedicated service account and a distinct, resolved shell IAP backend."
    }

    precondition {
      condition     = try(data.google_compute_backend_service.app[0].iap[0].enabled, false)
      error_message = "IAP is not enabled on backend service ${var.backend_service_name}; the BackendConfig ${local.backend_config_name} must be attached before access is granted."
    }
  }
}

# --- Contract read by stacks/day2-app ----------------------------------------

resource "kubernetes_config_map_v1" "platform_contract" {
  metadata {
    name      = local.contract_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels    = local.platform_labels
  }

  data = local.contract_data

  depends_on = [google_iap_web_backend_service_iam_binding.app_access]
}

# --- Network policy -----------------------------------------------------------
# Default deny both ways; allow the Google load balancer to port 8080 on pods
# the Service selects; allow DNS, the GKE metadata server and public internet
# egress (IAP signing keys) from every pod except smoke pods.

resource "kubernetes_network_policy_v1" "deny_all_ingress" {
  metadata {
    name      = "default-deny-ingress"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress"]
  }
}

resource "kubernetes_network_policy_v1" "allow_ingress_from_load_balancer" {
  metadata {
    name      = "allow-ingress-from-gclb"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = local.service_selector
    }

    ingress {
      dynamic "from" {
        for_each = local.load_balancer_cidrs

        content {
          ip_block {
            cidr = from.value
          }
        }
      }

      ports {
        protocol = "TCP"
        port     = 8080
      }
    }

    policy_types = ["Ingress"]
  }
}

resource "kubernetes_network_policy_v1" "deny_all_egress" {
  metadata {
    name      = "default-deny-egress"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Egress"]
  }
}

resource "kubernetes_network_policy_v1" "allow_egress_to_dns" {
  metadata {
    name      = "allow-egress-to-dns"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }

  spec {
    pod_selector {
      match_expressions {
        key      = local.egress_exempt_label_key
        operator = "NotIn"
        values   = [local.egress_exempt_label_value]
      }
    }

    egress {
      to {
        ip_block {
          cidr = local.node_local_dns_cidr
        }
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

    # Pods resolve through the kube-dns Service address.
    egress {
      to {
        ip_block {
          cidr = "${var.kube_dns_service_ip}/32"
        }
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
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }

        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
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

    policy_types = ["Egress"]
  }
}

resource "kubernetes_network_policy_v1" "allow_egress_to_workload_identity" {
  metadata {
    name      = "allow-egress-to-workload-identity"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }

  spec {
    pod_selector {
      match_expressions {
        key      = local.egress_exempt_label_key
        operator = "NotIn"
        values   = [local.egress_exempt_label_value]
      }
    }

    egress {
      to {
        ip_block {
          cidr = local.gke_metadata_cidr
        }
      }

      ports {
        protocol = "TCP"
        port     = local.gke_metadata_port
      }
    }

    policy_types = ["Egress"]
  }
}

resource "kubernetes_network_policy_v1" "allow_public_internet_egress" {
  metadata {
    name      = "allow-egress-to-public-internet"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }

  spec {
    pod_selector {
      match_expressions {
        key      = local.egress_exempt_label_key
        operator = "NotIn"
        values   = [local.egress_exempt_label_value]
      }
    }

    egress {
      to {
        ip_block {
          cidr   = "0.0.0.0/0"
          except = local.public_egress_except_cidrs
        }
      }
    }

    policy_types = ["Egress"]
  }
}
