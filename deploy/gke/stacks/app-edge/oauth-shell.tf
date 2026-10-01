# The installation shell contract adds its workload to this app's protected
# backend. No shell hostname or second endpoint list is copied.
variable "security_shell_contract" {
  type    = object({ namespace = string, name = string })
  default = null
  validation {
    condition     = var.security_shell_contract == null ? true : alltrue([for value in [var.security_shell_contract.namespace, var.security_shell_contract.name] : can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", value))])
    error_message = "security_shell_contract must name a Kubernetes ConfigMap in a dedicated namespace."
  }
}

data "kubernetes_config_map_v1" "security_shell_contract" {
  count = var.security_shell_contract == null ? 0 : 1
  metadata {
    name      = var.security_shell_contract.name
    namespace = var.security_shell_contract.namespace
  }
}

locals {
  oauth_shell_contract = var.security_shell_contract == null ? {} : data.kubernetes_config_map_v1.security_shell_contract[0].data
  oauth_shell_account  = trimspace(lookup(local.oauth_shell_contract, "OAUTH_SHELL_SERVICE_ACCOUNT", ""))
  app_iap_members      = sort(distinct(concat(tolist(var.iap_members), var.security_shell_contract == null ? [] : ["serviceAccount:${local.oauth_shell_account}"])))
}
