variable "project_id" {
  type = string
}
variable "zone" {
  type = string
}
variable "cluster_name" {
  type = string
}
variable "pool_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,38}[a-z0-9]$", var.pool_name))
    error_message = "pool_name must be a distinct GKE node-pool name."
  }
}
variable "profile" {
  description = "Instance-owned enrollment placement label; not a native enrollment proof."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.profile))
    error_message = "profile must be a DNS label."
  }
}
variable "machine_type" {
  description = "Supported full-core x86 size for the declared four-service budgets: four CPUs and at least 4 GiB RAM."
  type        = string
  validation {
    condition     = contains(["e2-highcpu-4", "e2-standard-4"], var.machine_type)
    error_message = "Select e2-highcpu-4 (4 GiB) or e2-standard-4 (16 GiB); two-core/shared-core/Arm profiles are unsupported."
  }
}
variable "node_service_account" {
  description = "Existing node GSA, with image/logging/monitoring access only; no enrollment-root signing grant."
  type        = string
}
variable "pod_pids_limit" {
  type = number
  validation {
    condition     = var.pod_pids_limit >= 1024 && var.pod_pids_limit <= 4194304 && var.pod_pids_limit == floor(var.pod_pids_limit)
    error_message = "pod_pids_limit must be a GKE-supported integer of at least 1024."
  }
}
