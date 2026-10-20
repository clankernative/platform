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

variable "oauth_instance_json" {
  description = "Complete single-app native instance metadata used to derive this host's provider-client grants. No secret values or readiness assertions. Required with oauth_runtime."
  type        = string
  default     = null
  validation {
    condition = var.oauth_instance_json == null ? true : try(
      length(var.oauth_instance_json) <= 524288 &&
      length(jsondecode(var.oauth_instance_json).apps) == 1 &&
      length(jsondecode(var.oauth_instance_json).oauth_runtime.apps) == 1 &&
      jsondecode(var.oauth_instance_json).oauth_runtime.version == 1 &&
      jsondecode(var.oauth_instance_json).oauth_clients.version == 2,
    false)
    error_message = "OAuth IAM requires bounded, complete single-app native instance metadata."
  }
}

locals {
  runtime_google_email        = var.runtime_identity != null ? google_service_account.runtime_identity[0].email : (var.app_calls == null && var.oauth_runtime == null ? "" : google_service_account.app_calls[0].email)
  oauth_key_ids               = var.oauth_runtime == null ? toset([]) : setunion(var.oauth_runtime.custody_secret_ids, var.oauth_runtime.attestation_secret_ids)
  oauth_selection             = var.oauth_instance_json == null ? null : jsondecode(var.oauth_instance_json)
  oauth_connections           = try(local.oauth_selection.apps[var.app_id].oauth_connections, {})
  oauth_registration_ids      = toset([for connection in values(local.oauth_connections) : connection.registration.id])
  oauth_provider_client_names = toset(try([for id in local.oauth_registration_ids : local.oauth_selection.oauth_clients.registrations[id].client.credential], []))
  oauth_provider_clients      = try([for name in local.oauth_provider_client_names : local.oauth_selection.control.secrets[name]], [])
  oauth_provider_client_ids   = var.oauth_runtime == null ? toset([]) : toset([for secret in local.oauth_provider_clients : secret.secret])
  oauth_custody_names         = toset(flatten([for connection in values(local.oauth_connections) : [connection.custody_verifier_secret, connection.custody_encryption_secret]]))
  oauth_attestation_names     = toset([for connection in values(local.oauth_connections) : connection.shell_attestation_secret])
  oauth_selected_keys         = try([for name in setunion(local.oauth_custody_names, local.oauth_attestation_names) : local.oauth_selection.control.secrets[name]], [])
  oauth_reauth_secret         = try(local.oauth_selection.control.secrets[local.oauth_selection.oauth_clients.reauthentication.credential], null)
  # Roles come from the native snapshot, not the aggregate shell grant set.
  oauth_roles_valid = var.oauth_runtime == null ? var.oauth_instance_json == null : try(
    var.oauth_runtime != null && var.oauth_instance_json != null &&
    toset(keys(local.oauth_selection.apps)) == toset([var.app_id]) &&
    toset(keys(local.oauth_selection.oauth_runtime.apps)) == toset([var.app_id]) &&
    local.oauth_selection.oauth_runtime.apps[var.app_id].service_account == local.runtime_google_email &&
    local.oauth_selection.oauth_runtime.shell.project == var.project_id &&
    local.oauth_selection.oauth_shell_transport.service_account == local.oauth_shell_account &&
    length(local.oauth_connections) > 0 && length(local.oauth_connections) <= 64 &&
    toset(keys(local.oauth_selection.oauth_clients.registrations)) == local.oauth_registration_ids &&
    alltrue([for connection in values(local.oauth_connections) : connection.namespace.app == var.app_id]) &&
    alltrue([for secret in concat(local.oauth_selected_keys, local.oauth_provider_clients, [local.oauth_reauth_secret]) :
      secret.kind == "gcp_version" && tostring(secret.project_number) == var.project_number &&
      secret.version >= 1 && secret.version == floor(secret.version) &&
      can(regex("^[A-Za-z0-9_-]{1,255}$", secret.secret))
    ]) &&
    var.oauth_runtime.custody_secret_ids == toset([for name in local.oauth_custody_names : local.oauth_selection.control.secrets[name].secret]) &&
    var.oauth_runtime.attestation_secret_ids == toset([for name in local.oauth_attestation_names : local.oauth_selection.control.secrets[name].secret]) &&
    length(local.oauth_provider_client_ids) > 0 &&
    length(setunion(local.oauth_key_ids, local.oauth_provider_client_ids)) <= 32 &&
    length(setintersection(local.oauth_key_ids, local.oauth_provider_client_ids)) == 0 &&
    !contains(setunion(local.oauth_key_ids, local.oauth_provider_client_ids), local.oauth_reauth_secret.secret),
  false)
  oauth_runtime_contract = var.oauth_runtime == null ? {} : {
    OAUTH_APP_SERVICE_ACCOUNT            = local.runtime_google_email
    OAUTH_APP_SERVICE_ACCOUNT_UID        = google_service_account.app_calls[0].unique_id
    OAUTH_APP_SECRET_IDS                 = jsonencode(sort(tolist(local.oauth_key_ids)))
    OAUTH_APP_PROVIDER_CLIENT_SECRET_IDS = jsonencode(sort(tolist(local.oauth_provider_client_ids)))
    OAUTH_APP_PROJECT                    = var.project_id
    OAUTH_SHELL_NAMESPACE                = try(var.security_shell_contract.namespace, "")
    OAUTH_SHELL_CONTRACT                 = try(var.security_shell_contract.name, "")
  }
}

resource "google_project_iam_custom_role" "oauth_edge_reads" {
  count   = var.oauth_runtime == null ? 0 : 1
  project = var.project_id
  role_id = "day2_${replace(var.app_id, "-", "_")}_oauth_edge"
  title   = "Day2 ${var.app_id} OAuth edge reads"
  permissions = [
    "resourcemanager.projects.get",
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
  lifecycle {
    precondition {
      condition     = local.oauth_roles_valid
      error_message = "App OAuth IAM must match its own canonical registrations, workload and same-project numeric-version keys/provider clients. Reauthentication and cross-role container aliases are forbidden."
    }
  }
}

resource "google_secret_manager_secret_iam_member" "oauth_provider_clients" {
  for_each  = local.oauth_provider_client_ids
  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.runtime_google_email}"
  lifecycle {
    precondition {
      condition     = local.oauth_roles_valid
      error_message = "App OAuth IAM must match its own canonical registrations, workload and same-project numeric-version keys/provider clients. Reauthentication and cross-role container aliases are forbidden."
    }
  }
}
