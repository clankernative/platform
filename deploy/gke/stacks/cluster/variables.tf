variable "project_id" {
  description = "GCP project that hosts the cluster."
  type        = string

  validation {
    condition     = trimspace(var.project_id) != ""
    error_message = "project_id must not be empty."
  }
}

variable "region" {
  description = "Region of the cluster subnet."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zone of the zonal cluster and its node pool."
  type        = string
  default     = "us-central1-a"
}

variable "cluster_name" {
  description = "GKE cluster name."
  type        = string
  default     = "day2"

  validation {
    condition     = can(regex("^[a-z](?:[-a-z0-9]{0,38}[a-z0-9])?$", var.cluster_name))
    error_message = "cluster_name must be a valid GKE cluster name."
  }
}

variable "cluster_labels" {
  description = "Resource labels on the cluster."
  type        = map(string)
  default = {
    managed_by = "opentofu"
    stack      = "platform-cluster"
  }
}

variable "network_name" {
  description = "Name of the cluster's dedicated VPC."
  type        = string
  default     = "day2-vpc"
}

variable "subnet_name" {
  description = "Name of the cluster subnet."
  type        = string
  default     = "day2-subnet"
}

variable "subnet_cidr" {
  description = "Primary (node) range of the cluster subnet."
  type        = string
  default     = "10.10.0.0/20"

  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0))
    error_message = "subnet_cidr must be a valid CIDR block."
  }
}

variable "pod_range_name" {
  description = "Name of the subnet secondary range for pod IPs."
  type        = string
  default     = "day2-pods"
}

variable "pod_cidr" {
  description = "Pod secondary range."
  type        = string
  default     = "10.20.0.0/16"

  validation {
    condition     = can(cidrhost(var.pod_cidr, 0))
    error_message = "pod_cidr must be a valid CIDR block."
  }
}

variable "svc_range_name" {
  description = "Name of the subnet secondary range for Service IPs."
  type        = string
  default     = "day2-services"
}

variable "service_cidr" {
  description = "Service secondary range."
  type        = string
  default     = "10.30.0.0/20"

  validation {
    condition     = can(cidrhost(var.service_cidr, 0))
    error_message = "service_cidr must be a valid CIDR block."
  }
}

variable "daily_maintenance_window_start_time_utc" {
  description = "UTC start (HH:MM) of GKE's four-hour daily maintenance window."
  type        = string
  default     = "09:00"

  validation {
    condition     = can(regex("^(?:[01][0-9]|2[0-3]):[0-5][0-9]$", var.daily_maintenance_window_start_time_utc))
    error_message = "daily_maintenance_window_start_time_utc must be a UTC time in HH:MM format."
  }
}

variable "node_sa_name" {
  description = "Account id of the node service account."
  type        = string
  default     = "day2-gke-nodes"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.node_sa_name))
    error_message = "node_sa_name must be a valid 6-30 character service account id."
  }
}

variable "node_pool_name" {
  description = "Name of the shared node pool."
  type        = string
  default     = "shared"
}

variable "shared_node_machine_type" {
  description = "Machine type of the shared node pool. Must be x86_64; changing it recreates the pool's nodes."
  type        = string
  default     = "c3-standard-4"

  validation {
    condition     = trimspace(var.shared_node_machine_type) != "" && !can(regex("^(t2a|c4a|a4x)-", var.shared_node_machine_type))
    error_message = "shared_node_machine_type must be an x86_64 machine type (not an Arm t2a/c4a/a4x type)."
  }
}

variable "shared_node_min_count" {
  description = "Autoscaler minimum node count of the shared pool."
  type        = number
  default     = 1

  validation {
    condition     = var.shared_node_min_count >= 1 && var.shared_node_min_count == floor(var.shared_node_min_count)
    error_message = "shared_node_min_count must be a positive whole number."
  }
}

variable "shared_node_max_count" {
  description = "Autoscaler maximum node count of the shared pool. Keep headroom for a surge node during upgrades."
  type        = number
  default     = 3

  validation {
    condition     = var.shared_node_max_count >= var.shared_node_min_count && var.shared_node_max_count == floor(var.shared_node_max_count)
    error_message = "shared_node_max_count must be a whole number at least shared_node_min_count."
  }
}

variable "shared_node_pod_pids_limit" {
  description = "Kubelet podPidsLimit of every pod on the shared pool, system pods included. Kubernetes has no per-container pids limit, so day2 apps declare process_limit_enforced_by = \"pod\" and this is their process bound: it must equal pod_pids_limit in the instance's app tfvars. Changing it recreates the pool's nodes."
  type        = number

  validation {
    condition = try(
      var.shared_node_pod_pids_limit == floor(var.shared_node_pod_pids_limit) &&
      var.shared_node_pod_pids_limit >= 1024 &&
      var.shared_node_pod_pids_limit <= 4194304,
      false,
    )
    error_message = "shared_node_pod_pids_limit must be a whole number from 1024 to 4194304 (GKE's allowed podPidsLimit range)."
  }
}

variable "shared_node_inotify_max_user_watches" {
  description = "fs.inotify.max_user_watches on the shared pool."
  type        = number
  default     = 1048576

  validation {
    condition     = var.shared_node_inotify_max_user_watches >= 524288 && var.shared_node_inotify_max_user_watches <= 1048576
    error_message = "shared_node_inotify_max_user_watches must be between 524288 and 1048576."
  }
}

variable "shared_node_inotify_max_user_instances" {
  description = "fs.inotify.max_user_instances on the shared pool."
  type        = number
  default     = 8192

  validation {
    condition     = var.shared_node_inotify_max_user_instances >= 1024 && var.shared_node_inotify_max_user_instances <= 8192
    error_message = "shared_node_inotify_max_user_instances must be between 1024 and 8192."
  }
}
