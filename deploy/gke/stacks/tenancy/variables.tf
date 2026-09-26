variable "kubeconfig_path" {
  description = "Optional kubeconfig path for the target cluster. Empty uses the provider's default discovery (KUBE_CONFIG_PATH, in-cluster)."
  type        = string
  default     = ""
}

variable "kube_context" {
  description = "Optional kubeconfig context for the target cluster, e.g. gke_<project>_<zone>_<cluster>."
  type        = string
  default     = ""
}

variable "app_namespace_prefix" {
  description = "Namespaces whose name starts with this prefix are app namespaces and get the admission policies below. Must match the app-edge stack's namespace naming."
  type        = string
  default     = "app-"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?-$", var.app_namespace_prefix))
    error_message = "app_namespace_prefix must be a lowercase DNS label prefix ending in '-', e.g. app-."
  }
}

variable "platform_automation_usernames" {
  description = "Kubernetes usernames allowed to create and change platform-owned objects (Services, Ingresses, NetworkPolicies, PVCs, ServiceAccounts, RBAC, platform-contract) in app namespaces. Must include whoever applies the app-edge and day2-app stacks. GKE reports a Google service account as its bare e-mail."
  type        = list(string)

  validation {
    condition     = length(var.platform_automation_usernames) > 0 && alltrue([for username in var.platform_automation_usernames : trimspace(username) != "" && !strcontains(username, "'")])
    error_message = "platform_automation_usernames must name the identity that applies the app stacks (no empty entries or single quotes), or those stacks' own objects are refused."
  }
}

variable "platform_pvc_update_usernames" {
  description = "Kubernetes control-plane identities allowed to update platform PVCs in app namespaces."
  type        = list(string)
  default = [
    "system:kube-scheduler",
    "system:serviceaccount:kube-system:persistent-volume-binder",
    "system:serviceaccount:kube-system:pvc-protection-controller",
  ]
}

variable "destructive_teardown_namespaces" {
  description = "App namespaces approved for teardown: platform automation may delete their PVCs and the namespace itself. Leave empty otherwise."
  type        = list(string)
  default     = []
}
