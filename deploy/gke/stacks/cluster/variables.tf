variable "project_id" { type = string }
variable "region" { type = string }
variable "zone" { type = string }
variable "name" {
  type    = string
  default = "day2"
}
variable "admin_cidrs" {
  description = "Operator public egress CIDRs allowed to reach the Kubernetes API. Never use 0.0.0.0/0."
  type        = set(string)
  validation {
    condition     = length(var.admin_cidrs) > 0 && alltrue([for cidr in var.admin_cidrs : can(cidrnetmask(cidr)) && try(tonumber(split("/", cidr)[1]) >= 16, false)])
    error_message = "Supply explicit IPv4 operator CIDRs with a prefix of at least /16."
  }
}
variable "node_count" {
  type    = number
  default = 2
}
variable "machine_type" {
  type    = string
  default = "e2-standard-4"
}
variable "pod_pids_limit" {
  type    = number
  default = 1024
  validation {
    condition     = var.pod_pids_limit == floor(var.pod_pids_limit) && var.pod_pids_limit >= 1024 && var.pod_pids_limit <= 4096
    error_message = "Use a whole pod process limit within GKE and day2 bounds (1024..4096)."
  }
}
variable "deletion_protection" {
  type    = bool
  default = true
}
