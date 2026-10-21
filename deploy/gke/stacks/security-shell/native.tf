# Shell enrolls and uses its authenticated Controller peer. It receives no App
# database, Kubernetes API/subject token, Controller credential or device access.
variable "native_enrollment_json" {
  description = "Public bounded EnrollmentPolicy for the SAME selected native bootstrap; no private key or credential payload."
  type        = string
  default     = null
  validation {
    condition     = var.native_enrollment_json == null ? true : length(var.native_enrollment_json) > 0 && length(var.native_enrollment_json) <= 65536 && can(jsondecode(var.native_enrollment_json))
    error_message = "Supply bounded public enrollment JSON, never a private key."
  }
}

locals {
  native_apps        = [for name, app in local.instance.apps : name if length(try(app.oauth_connections, {})) > 0]
  native_policies    = [for policy in values(try(local.instance.control.security_bootstraps, {})) : policy if try(contains(local.native_apps, policy.scope.app), false)]
  native_enabled     = length(local.native_policies) > 0
  native_policy      = try(one(local.native_policies), null)
  native_role        = try(local.native_policy.shell, null)
  native_enrollment  = try(jsondecode(var.native_enrollment_json), null)
  native_live        = try(one(data.kubernetes_resources.native_workload[0].objects), null)
  native_config_name = "security-shell-native-${substr(sha256(var.native_enrollment_json == null ? "" : var.native_enrollment_json), 0, 16)}"
  native_node_selector = merge(var.native_enrollment_placement == null ? {} : {
    "cloud.google.com/gke-nodepool"                      = var.native_enrollment_placement.pool_name
    "day2.dev.node-restriction.kubernetes.io/enrollment" = var.native_enrollment_placement.profile
    }, local.native_enabled ? {
    "kubernetes.io/hostname"                 = try(local.native_enrollment.runtime.node_name, "")
    "kubernetes.io/os"                       = "linux"
    "kubernetes.io/arch"                     = "amd64"
    "iam.gke.io/gke-metadata-server-enabled" = "true"
  } : {})
  native_mounts = local.native_enabled ? {
    policy = { name = "native-policy", path = "/etc/day2/native-enrollment.json", sub_path = "native-enrollment.json", read_only = true }
  } : {}
}

data "kubernetes_resource" "native_namespace" {
  count       = local.native_enabled ? 1 : 0
  api_version = "v1"
  kind        = "Namespace"
  metadata { name = var.namespace }
}

data "kubernetes_resource" "native_account" {
  count       = local.native_enabled ? 1 : 0
  api_version = "v1"
  kind        = "ServiceAccount"
  metadata {
    name      = "security-shell"
    namespace = var.namespace
  }
}

data "kubernetes_resources" "native_workload" {
  count          = local.native_enabled ? 1 : 0
  api_version    = "apps/v1"
  kind           = "Deployment"
  namespace      = var.namespace
  field_selector = "metadata.name=security-shell"
}

resource "terraform_data" "native_admission" {
  lifecycle {
    precondition {
      condition     = alltrue([for key, value in local.native_node_selector : lookup(var.node_selector, key, value) == value])
      error_message = "Node selectors cannot contradict the selected native pool, protected profile or exact enrolled runtime."
    }
    precondition {
      condition = length(local.native_policies) <= 1 && alltrue([
        for policy in values(try(local.instance.control.security_bootstraps, {})) :
        can(policy.scope.app) && can(policy.scope.installation) && can(policy.scope.environment)
      ])
      error_message = "This Shell has one fixed enrollment policy: select at most one native OAuth scope, with explicit unambiguous metadata."
    }
    precondition {
      condition = local.native_enabled ? try(
        var.native_enrollment_json != null && var.native_enrollment_placement != null &&
        local.native_policy.scope.installation == local.instance.installation && local.native_policy.scope.environment == local.instance.environment &&
        jsonencode(local.native_enrollment.bootstrap) == jsonencode(local.native_policy) &&
        jsonencode(local.native_enrollment.store) == jsonencode(local.instance.control.security_epochs[local.native_policy.epoch_store.id]) &&
        local.native_enrollment.runtime.architecture == "amd64" &&
        length(local.native_enrollment.runtime.node_name) > 0 && length(local.native_enrollment.runtime.node_uid) > 0 &&
        local.native_role.namespace.name == var.namespace &&
        local.native_role.namespace.uid == data.kubernetes_resource.native_namespace[0].object.metadata.uid &&
        local.native_role.kubernetes_service_account.name == "security-shell" &&
        local.native_role.kubernetes_service_account.uid == data.kubernetes_resource.native_account[0].object.metadata.uid &&
        local.native_role.google_service_account.service_account == local.instance.oauth_shell_transport.service_account &&
        local.native_role.google_service_account.service_account == data.kubernetes_resource.native_account[0].object.metadata.annotations["iam.gke.io/gcp-service-account"] &&
        local.native_role.workload_kind == "deployment_v1" &&
        local.native_role.workload.name == "security-shell" && local.native_role.workload.uid == local.native_live.metadata.uid &&
        local.native_live.metadata.name == "security-shell" && local.native_live.metadata.namespace == var.namespace &&
        local.native_role.container.name == "security-shell" &&
        can(regex("^sha256:[0-9a-f]{64}$", local.native_role.container.image)) && endswith(var.image, local.native_role.container.image),
      false) : var.native_enrollment_json == null
      error_message = "Native Shell deployment requires the SAME complete enrollment/bootstrap/store, actual namespace/KSA/workload UIDs, Shell image and protected node selection. These selections grant no native owner or serving authority."
    }
  }
}

resource "kubernetes_config_map_v1" "native_policy" {
  count      = local.native_enabled ? 1 : 0
  depends_on = [terraform_data.native_admission]
  immutable  = true
  metadata {
    name      = local.native_config_name
    namespace = var.namespace
  }
  data = { "native-enrollment.json" = var.native_enrollment_json == null ? "" : var.native_enrollment_json }
}
