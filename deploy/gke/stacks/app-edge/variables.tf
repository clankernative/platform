variable "project_id" { type = string }
variable "namespace" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,39}$", var.namespace))
    error_message = "Use a namespace of 1..40 lowercase letters, digits and hyphens."
  }
}
variable "domain" { type = string }
variable "dns_managed_zone" {
  description = "Existing public Cloud DNS zone, with delegation already configured."
  type        = string
}
variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}
variable "kube_context" { type = string }
variable "iap_members" {
  description = "Explicit Google user/group principals. Empty denies access; public/domain-wide principals are rejected."
  type        = set(string)
  validation {
    condition     = alltrue([for member in var.iap_members : can(regex("^(user|group):[^@ ]+@[^@ ]+$", member))])
    error_message = "IAP grants must be explicit user: or group: email principals."
  }
}
variable "backend_service_name" {
  description = "GKE-created backend name from the Ingress backends annotation. Empty only on initial edge bootstrap."
  type        = string
  default     = ""
}
variable "storage_gib" {
  type    = number
  default = 20
}
