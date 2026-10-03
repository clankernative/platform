# Secret Manager secrets the app's pod may read through the GKE Secret Manager
# CSI add-on (day2-app provider_credentials). The grant is to the runtime
# Kubernetes service account's Workload Identity principal, or its linked
# app-call or OAuth Google service account, on each named secret only. The add-on
# performs the read. Secret values are never managed here.
variable "runtime_secret_ids" {
  description = "Secret Manager secret ids in project_id whose versions day2-app's provider_credentials mount."
  type        = set(string)
  default     = []

  validation {
    condition     = length(var.runtime_secret_ids) <= 32 && alltrue([for id in var.runtime_secret_ids : can(regex("^[A-Za-z0-9_-]{1,255}$", id))])
    error_message = "runtime_secret_ids must be at most 32 plain Secret Manager secret ids (not resource names)."
  }
}

locals {
  runtime_workload_identity_principal = "principal://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${var.project_id}.svc.id.goog/subject/ns/${local.namespace_name}/sa/${local.runtime_service_account}"
}

resource "google_secret_manager_secret_iam_member" "runtime" {
  for_each = var.runtime_secret_ids

  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = local.runtime_google_email == "" ? local.runtime_workload_identity_principal : "serviceAccount:${local.runtime_google_email}"
}
