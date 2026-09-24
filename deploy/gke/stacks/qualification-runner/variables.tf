variable "project_id" {
  description = "GCP project that hosts the runner."
  type        = string

  validation {
    condition     = trimspace(var.project_id) != ""
    error_message = "project_id must not be empty."
  }
}

variable "region" {
  description = "Region for the runner's subnet and Cloud NAT."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zone for the runner VM."
  type        = string
  default     = "us-central1-a"
}

variable "enabled" {
  description = "Create the x86_64 qualification runner and its network. Off by default; everything in this root has count = enabled ? 1 : 0."
  type        = bool
  default     = false
}

variable "desired_status" {
  description = "RUNNING or TERMINATED. Stop the VM between qualification runs without losing its disk (Docker build cache, cargo registry)."
  type        = string
  default     = "RUNNING"

  validation {
    condition     = contains(["RUNNING", "TERMINATED"], var.desired_status)
    error_message = "desired_status must be RUNNING or TERMINATED."
  }
}

variable "name" {
  description = "VM, service account and network resource name stem."
  type        = string
  default     = "day2-x86-qualify"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,24}[a-z0-9]$", var.name))
    error_message = "name must be 6-26 characters of lowercase letters, digits and hyphens (it also names the service account)."
  }
}

variable "machine_type" {
  description = "x86_64 machine type. Qualification builds two Rust images (debug and release) inside Docker; 8 vCPU keeps a run to well under the xtask's 1h image-build timeout."
  type        = string
  default     = "n2-standard-8"

  validation {
    condition     = !can(regex("^(t2a|c4a|a4x)-", var.machine_type))
    error_message = "machine_type must be an x86_64 family (n2, n2d, c3, c3d, c4, e2...), not an Arm family (t2a, c4a, a4x)."
  }
}

variable "boot_image" {
  description = "x86_64 boot image. Landlock ABI 3, which day2-sandbox hard-requires, needs Linux 6.2+: Debian 13 ships 6.12; Debian 12 ships 6.1 and needs the bookworm-backports kernel."
  type        = string
  default     = "projects/debian-cloud/global/images/family/debian-13"

  validation {
    condition     = !can(regex("arm64", var.boot_image))
    error_message = "boot_image must be an x86_64 (amd64) image."
  }
}

variable "boot_disk_gb" {
  description = "Boot disk size. Holds Docker images/build cache for the tooling and runtime images plus the host cargo build of xtask."
  type        = number
  default     = 200

  validation {
    condition     = var.boot_disk_gb >= 100
    error_message = "boot_disk_gb must be at least 100."
  }
}

variable "subnet_cidr" {
  description = "Primary range of the runner's dedicated subnet. Separate VPC from the cluster; ranges may overlap it."
  type        = string
  default     = "10.60.0.0/24"

  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0))
    error_message = "subnet_cidr must be a valid CIDR block."
  }
}

variable "operator_members" {
  description = "IAM members allowed to reach the runner through IAP TCP forwarding and log in with OS Login (with sudo, needed to join the docker group)."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for member in var.operator_members :
      can(regex("^(user|group):[^@\\s]+@[^@\\s]+$", member))
    ])
    error_message = "operator_members entries must be user:<email> or group:<email>."
  }
}

variable "image_push_repository_id" {
  description = "Optional Artifact Registry repository id in this project/region the runner's service account may push to (for example go, created by the platform app stack). Empty grants nothing."
  type        = string
  default     = ""
}
