variable "kubeconfig_path" {
  type    = string
  default = ""
}

variable "kube_context" {
  type    = string
  default = ""
}

variable "namespace" {
  description = "Existing dedicated namespace from security-shell-edge."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.namespace)) && !startswith(var.namespace, "app-") && !startswith(var.namespace, "kube-") && var.namespace != "default"
    error_message = "namespace must be the dedicated security namespace."
  }
}

variable "edge_contract_config_map" {
  type    = string
  default = "security-shell-contract"
}

variable "image" {
  description = "Digest-pinned platform shell image with all selected admitted Linux artifacts baked in read-only."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be pinned by SHA-256 digest."
  }
}

variable "instance_json" {
  description = "Complete selected instance metadata from the company repo, including native oauth_runtime.shell_resources. Contains exact secret references, never secret bytes. The native launcher performs full closed-schema and artifact admission."
  type        = string
  validation {
    condition     = length(var.instance_json) <= 524288 && can(jsondecode(var.instance_json).oauth_runtime.shell_resources.shutdown_seconds) && can(jsondecode(var.instance_json).oauth_clients.reauthentication.credential)
    error_message = "instance_json must be bounded instance JSON with shell resources and real OAuth client selections."
  }
}

variable "node_selector" {
  type    = map(string)
  default = { "iam.gke.io/gke-metadata-server-enabled" = "true" }
  validation {
    condition     = lookup(var.node_selector, "iam.gke.io/gke-metadata-server-enabled", "") == "true"
    error_message = "The shell requires a GKE metadata-enabled node pool."
  }
}
