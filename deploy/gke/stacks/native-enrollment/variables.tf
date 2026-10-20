variable "image" {
  description = "Reviewed runtime containing the fixed issuer and source-bound Roc runner."
  type        = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9./_:-]+@sha256:[0-9a-f]{64}$", var.image))
    error_message = "Select one immutable runtime image."
  }
}

variable "policy_json" {
  description = "Public operator EnrollmentPolicy DATA. The native entrypoint validates every field. No root private key."
  type        = string
  validation {
    condition = try(
      length(var.policy_json) <= 65536 &&
      length(jsondecode(var.policy_json).root.public_key) == 43 &&
      can(regex("/cryptoKeyVersions/[1-9][0-9]*$", jsondecode(var.policy_json).root.version)) &&
      jsondecode(var.policy_json).runtime.node_name != "", false
    )
    error_message = "Supply bounded native policy DATA with the exact KMS root and node."
  }
}

variable "pool_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,38}[a-z0-9]$", var.pool_name))
    error_message = "Select the dedicated native pool."
  }
}

variable "kube_context" {
  type = string
  validation {
    condition     = length(var.kube_context) > 0 && trimspace(var.kube_context) == var.kube_context
    error_message = "Select the exact operator Kubernetes context."
  }
}

variable "profile" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.profile))
    error_message = "Select the protected enrollment placement label."
  }
}
