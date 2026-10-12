# Consume the canonical native instance selection from the company repo. Keep
# closed OAuth contracts and their digests intact; deployment checks supplement
# (and do not replace) native instance/artifact admission at startup.
variable "oauth_instance_json" {
  description = "Optional complete single-app canonical instance JSON. OAuth bindings, clients, runtime and scoped immutable epoch/key-set selectors are copied intact. Desired metadata and secret references only; no current epoch or readiness."
  type        = string
  default     = null
  validation {
    condition = var.oauth_instance_json == null ? true : try(
      length(var.oauth_instance_json) <= 524288 &&
      length(jsondecode(var.oauth_instance_json).apps) == 1 &&
      length(jsondecode(var.oauth_instance_json).oauth_runtime.apps) == 1 &&
      length(jsondecode(var.oauth_instance_json).control.security_epochs) == 1 &&
      jsondecode(var.oauth_instance_json).oauth_runtime.version == 1 &&
      contains([1, 2], jsondecode(var.oauth_instance_json).oauth_clients.version),
    false)
    error_message = "oauth_instance_json must be bounded single-app canonical JSON with one scoped current authority selector, version 1 OAuth runtime and version 1 or 2 client selections."
  }
}

data "kubernetes_resource" "oauth_runtime" {
  count       = var.oauth_instance_json == null ? 0 : 1
  api_version = "v1"
  kind        = "ServiceAccount"
  metadata {
    name      = var.service_account_name
    namespace = var.namespace
  }
}

locals {
  oauth_selection   = var.oauth_instance_json == null ? null : jsondecode(var.oauth_instance_json)
  oauth_connections = try(local.oauth_selection.apps[var.app_id].oauth_connections, {})
  oauth_key_names   = toset(flatten([for connection in values(local.oauth_connections) : [connection.custody_verifier_secret, connection.custody_encryption_secret, connection.shell_attestation_secret]]))
  oauth_keys        = [for name in local.oauth_key_names : local.oauth_selection.control.secrets[name]]
  oauth_client_names = toset(concat(
    try([local.oauth_selection.oauth_clients.reauthentication.credential], []),
    try([for registration in values(local.oauth_selection.oauth_clients.registrations) : registration.client.credential], []),
  ))
  oauth_client_containers = toset([for name in local.oauth_client_names : "${local.oauth_selection.control.secrets[name].project_number}/${local.oauth_selection.control.secrets[name].secret}"])
  oauth_metadata = jsondecode(var.oauth_instance_json == null ? "{}" : jsonencode({
    control       = local.oauth_selection.control
    oauth_clients = local.oauth_selection.oauth_clients
    oauth_runtime = local.oauth_selection.oauth_runtime
  }))
}

# Attach preconditions to the rendered instance so bad combinations cannot
# reach the StatefulSet even though all selections are public metadata.
resource "terraform_data" "oauth_admission" {
  count = var.oauth_instance_json == null ? 0 : 1
  lifecycle {
    precondition {
      condition = try(alltrue([for epoch in values(local.oauth_selection.control.security_epochs) :
        epoch.scope == { installation = var.installation, environment = var.environment, app = var.app_id } &&
        epoch.provider.kind == "firestore_native_v1" &&
        epoch.provider.project == local.contract["OAUTH_APP_PROJECT"] &&
        tostring(epoch.provider.project_number) == split("/", local.iap_audience)[2] &&
        epoch.provider.iam_source.kind == "gke_workload_identity_v1" &&
        epoch.provider.iam_source.service_account == local.contract["OAUTH_APP_SERVICE_ACCOUNT"] &&
        length(regexall("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$", epoch.provider.database)) == 1 &&
        length(regexall("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", epoch.provider.database_uid)) == 1 &&
        length(regexall("^sha256:[0-9a-f]{64}$", epoch.key_set)) == 1 &&
        epoch.max_lease_seconds >= 1 && epoch.max_lease_seconds <= 60 && epoch.max_lease_seconds == floor(epoch.max_lease_seconds)
      ]), false)
      error_message = "OAuth requires the exact app scope, project/workload identity, explicit immutable database UID and complete key-set digest. These selectors do not prove native authority or readiness."
    }
    precondition {
      condition = try(
        var.security_shell_contract != null &&
        local.oauth_selection.installation == var.installation && local.oauth_selection.environment == var.environment &&
        local.oauth_selection.identity == { scheme = "google_iap", hosted_domain = var.hosted_domain } &&
        local.oauth_selection.apps[var.app_id].artifact == "artifacts/${var.artifact_id}" &&
        local.oauth_selection.apps[var.app_id].edge == { origin = var.edge_origin, iap_audience = local.iap_audience } &&
        local.oauth_selection.security_shell == { origin = local.shell_origin, iap_audience = local.shell_audience } &&
        local.oauth_selection.oauth_shell_transport.service_account == local.shell_service_account &&
        local.oauth_selection.oauth_runtime.shell.project == local.contract["OAUTH_APP_PROJECT"] &&
        local.oauth_selection.oauth_runtime.shell.kubernetes_service == "${var.security_shell_contract.namespace}/security-shell" &&
        local.contract["OAUTH_SHELL_NAMESPACE"] == var.security_shell_contract.namespace && local.contract["OAUTH_SHELL_CONTRACT"] == var.security_shell_contract.name &&
        local.contract["APP_NAMESPACE"] == var.namespace && local.contract["SERVICE_ACCOUNT_NAME"] == var.service_account_name &&
        local.oauth_selection.oauth_runtime.apps[var.app_id].service_account == local.contract["OAUTH_APP_SERVICE_ACCOUNT"] &&
        local.oauth_selection.oauth_runtime.apps[var.app_id].service_account != local.shell_service_account &&
        data.kubernetes_resource.oauth_runtime[0].object.metadata.annotations["iam.gke.io/gcp-service-account"] == local.contract["OAUTH_APP_SERVICE_ACCOUNT"] &&
        (var.app_calls == null ? true : local.contract["APP_CALL_WORKLOAD_EMAIL"] == local.contract["OAUTH_APP_SERVICE_ACCOUNT"]) &&
        lookup(var.node_selector, "iam.gke.io/gke-metadata-server-enabled", "") == "true",
      false)
      error_message = "OAuth must match this installation, artifact, app/shell edges, same-project shell contract and actual annotated app workload identity on a metadata-enabled node pool."
    }
    precondition {
      condition = try(
        length(local.oauth_connections) > 0 && length(local.oauth_connections) <= 64 &&
        toset(keys(local.oauth_selection.oauth_runtime.apps[var.app_id].accounts)) == toset(keys(local.oauth_connections)) &&
        toset(keys(local.oauth_selection.oauth_clients.registrations)) == toset([for connection in values(local.oauth_connections) : connection.registration.id]) &&
        alltrue([for connection in values(local.oauth_connections) : connection.namespace.installation == var.installation && connection.namespace.environment == var.environment && connection.namespace.app == var.app_id]) &&
        alltrue([for key in local.oauth_keys : key.kind == "gcp_version" && key.version >= 1 && key.version == floor(key.version) && tostring(key.project_number) == split("/", local.iap_audience)[2]]) &&
        toset(jsondecode(local.contract["OAUTH_APP_SECRET_IDS"])) == toset([for key in local.oauth_keys : key.secret]) &&
        length(setintersection(toset([for key in local.oauth_keys : "${key.project_number}/${key.secret}"]), local.oauth_client_containers)) == 0,
      false)
      error_message = "OAuth accounts/clients must exactly cover this app's bindings; app IAM must grant exactly its numeric-version custody/attestation containers in this project, with no client container even at another version."
    }
  }
}
