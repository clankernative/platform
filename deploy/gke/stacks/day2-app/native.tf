# Deployment selections only. Native code still requires the actual enrolled
# App, Controller first holder, original file and current Runtime admission.
variable "native_enrollment_json" {
  description = "Public, bounded EnrollmentPolicy for the SAME selected bootstrap. No private key or credential payload. Required only when this App has a native bootstrap selection."
  type        = string
  default     = null
  validation {
    condition     = var.native_enrollment_json == null ? true : length(var.native_enrollment_json) > 0 && length(var.native_enrollment_json) <= 65536 && can(jsondecode(var.native_enrollment_json))
    error_message = "Supply bounded public enrollment JSON, never a private key."
  }
}

variable "native_node_profile" {
  description = "Existing protected enrollment node label/taint profile; required only for a selected native bootstrap. This root creates no node or pool."
  type        = string
  default     = null
  validation {
    condition     = var.native_node_profile == null ? true : can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.native_node_profile))
    error_message = "Select the existing native enrollment placement profile."
  }
}

locals {
  native_policies    = [for policy in values(try(local.instance.control.security_bootstraps, {})) : policy if try(policy.scope.app == var.app_id, false)]
  native_enabled     = length(local.native_policies) > 0
  native_policy      = try(one(local.native_policies), null)
  native_role        = try(local.native_policy.app, null)
  native_enrollment  = try(jsondecode(var.native_enrollment_json), null)
  native_config_name = "${local.workload_name}-native-${substr(sha256(var.native_enrollment_json == null ? "" : var.native_enrollment_json), 0, 16)}"
  native_node_selector = local.native_enabled ? {
    "day2.dev.node-restriction.kubernetes.io/enrollment" = var.native_node_profile == null ? "" : var.native_node_profile
    "kubernetes.io/hostname"                             = try(local.native_enrollment.runtime.node_name, "")
    "kubernetes.io/os"                                   = "linux"
    "kubernetes.io/arch"                                 = "amd64"
    "iam.gke.io/gke-metadata-server-enabled"             = "true"
  } : {}
  native_mounts = local.native_enabled ? {
    policy     = { name = "native-policy", path = "/etc/day2/native-enrollment.json", sub_path = "native-enrollment.json", read_only = true }
    enrollment = { name = "native-enrollment", path = "/run/day2-native-enrollment", sub_path = null, read_only = true }
    state      = { name = "state", path = "/state", sub_path = null, read_only = false }
    api        = { name = "native-api", path = "/var/run/secrets/kubernetes.io/serviceaccount", sub_path = null, read_only = true }
    subject    = { name = "native-subject", path = "/var/run/secrets/day2-native", sub_path = null, read_only = true }
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
    name      = var.service_account_name
    namespace = var.namespace
  }
}

resource "terraform_data" "native_admission" {
  lifecycle {
    precondition {
      condition = length(local.native_policies) <= 1 && alltrue([
        for policy in values(try(local.instance.control.security_bootstraps, {})) :
        can(policy.scope.app) && can(policy.scope.installation) && can(policy.scope.environment)
      ])
      error_message = "Native bootstrap scope must be explicit and unambiguous; malformed metadata cannot select ordinary mode."
    }
    precondition {
      condition = local.native_enabled ? try(
        var.native_enrollment_json != null && var.native_node_profile != null && !var.release_managed &&
        local.native_policy.scope == { installation = var.installation, environment = var.environment, app = var.app_id } &&
        jsonencode(local.native_enrollment.bootstrap) == jsonencode(local.native_policy) &&
        jsonencode(local.native_enrollment.store) == jsonencode(local.instance.control.security_epochs[local.native_policy.epoch_store.id]) &&
        local.native_enrollment.runtime.architecture == "x86_64" &&
        length(local.native_enrollment.runtime.node_name) > 0 && length(local.native_enrollment.runtime.node_uid) > 0 &&
        local.native_role.namespace.name == var.namespace &&
        local.native_role.namespace.uid == data.kubernetes_resource.native_namespace[0].object.metadata.uid &&
        local.native_role.kubernetes_service_account.name == var.service_account_name &&
        local.native_role.kubernetes_service_account.uid == data.kubernetes_resource.native_account[0].object.metadata.uid &&
        jsonencode(local.native_role.google_service_account) == jsonencode(local.native_enrollment.store.provider.iam_source) &&
        local.native_role.google_service_account.service_account == data.kubernetes_resource.native_account[0].object.metadata.annotations["iam.gke.io/gcp-service-account"] &&
        local.native_role.workload_kind == "stateful_set_v1" &&
        local.native_role.workload.name == local.workload_name && local.native_role.workload.uid == local.live.metadata.uid &&
        local.live.metadata.name == local.workload_name && local.live.metadata.namespace == var.namespace &&
        local.native_role.container.name == "day2" &&
        can(regex("^sha256:[0-9a-f]{64}$", local.native_role.container.image)) && endswith(var.image, local.native_role.container.image) &&
        length(local.native_role.token_review_audience) > 0 && length(local.native_role.token_review_audience) <= 2048 &&
        alltrue([for key, value in local.native_node_selector : lookup(var.node_selector, key, value) == value]),
      false) : var.native_enrollment_json == null && var.native_node_profile == null
      error_message = "Native App deployment requires the SAME complete public enrollment/bootstrap/store, existing namespace/KSA/workload UIDs, App image and protected node selection. Register the workload before selecting its actual UID; no ordinary activation stamp supplies native authority."
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
