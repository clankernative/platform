variable "project_id" {
  type        = string
  description = "Instance-owned project containing the dedicated enrollment signing key."
}

variable "location" {
  type        = string
  description = "Cloud KMS region selected by the instance."
}

variable "key_ring_name" {
  type        = string
  description = "Dedicated native enrollment key ring."
}

variable "key_name" {
  type        = string
  description = "Dedicated operator enrollment root, never an app credential key."
}

variable "provisioner_namespace" {
  type        = string
  description = "Exact Kubernetes namespace of the privileged provisioner."
}

variable "provisioner_service_account" {
  type        = string
  description = "Exact Kubernetes ServiceAccount of the privileged provisioner, shared with its issuer child."
}

variable "signer_role_id" {
  type        = string
  description = "Project-unique custom role containing only the fixed enrollment root permissions."
}
