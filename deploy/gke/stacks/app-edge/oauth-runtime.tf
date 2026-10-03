# Native OAuth readiness uses the pod's one Google workload identity. Existing
# app-call identities retain their resource addresses and are reused when both
# capabilities are selected. No OAuth-only identity receives signing authority.
variable "oauth_runtime" {
  description = "Optional native OAuth workload identity and named key containers. Secret values/versions remain in the canonical instance; these grants cover all versions in each container."
  type = object({
    service_account_id     = string
    custody_secret_ids     = set(string)
    attestation_secret_ids = set(string)
  })
  default = null
  validation {
    condition = var.oauth_runtime == null ? true : (
      can(regex("^[a-z][-a-z0-9]{4,28}[a-z0-9]$", var.oauth_runtime.service_account_id)) &&
      length(var.oauth_runtime.custody_secret_ids) >= 2 &&
      length(var.oauth_runtime.attestation_secret_ids) >= 1 &&
      length(setunion(var.oauth_runtime.custody_secret_ids, var.oauth_runtime.attestation_secret_ids)) <= 32 &&
      length(setintersection(var.oauth_runtime.custody_secret_ids, var.oauth_runtime.attestation_secret_ids)) == 0 &&
      alltrue([for id in setunion(var.oauth_runtime.custody_secret_ids, var.oauth_runtime.attestation_secret_ids) : can(regex("^[A-Za-z0-9_-]{1,255}$", id))])
    )
    error_message = "OAuth requires one workload identity, distinct custody/attestation containers and at most 32 plain secret ids."
  }
}

locals {
  runtime_google_email = var.app_calls == null && var.oauth_runtime == null ? "" : google_service_account.app_calls[0].email
  oauth_key_ids        = var.oauth_runtime == null ? toset([]) : setunion(var.oauth_runtime.custody_secret_ids, var.oauth_runtime.attestation_secret_ids)
  oauth_runtime_contract = var.oauth_runtime == null ? {} : {
    OAUTH_APP_SERVICE_ACCOUNT = local.runtime_google_email
    OAUTH_APP_SECRET_IDS      = jsonencode(sort(tolist(local.oauth_key_ids)))
    OAUTH_APP_PROJECT         = var.project_id
    OAUTH_SHELL_NAMESPACE     = try(var.security_shell_contract.namespace, "")
    OAUTH_SHELL_CONTRACT      = try(var.security_shell_contract.name, "")
  }
}

resource "google_project_iam_custom_role" "oauth_edge_reads" {
  count   = var.oauth_runtime == null ? 0 : 1
  project = var.project_id
  role_id = "day2_${replace(var.app_id, "-", "_")}_oauth_edge"
  title   = "Day2 ${var.app_id} OAuth edge reads"
  permissions = [
    "compute.projects.get",
    "compute.backendServices.get",
    "compute.urlMaps.get",
    "compute.targetHttpsProxies.get",
    "compute.globalForwardingRules.get",
  ]
}

resource "google_project_iam_member" "oauth_edge_reads" {
  count   = var.oauth_runtime == null ? 0 : 1
  project = var.project_id
  role    = google_project_iam_custom_role.oauth_edge_reads[0].name
  member  = "serviceAccount:${local.runtime_google_email}"
}

resource "google_secret_manager_secret_iam_member" "oauth_keys" {
  for_each  = local.oauth_key_ids
  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.runtime_google_email}"
}
