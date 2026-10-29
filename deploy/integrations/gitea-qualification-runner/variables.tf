variable "project_id" {
  description = "GCP project that owns this optional Gitea qualification runner."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project id."
  }
}

variable "region" {
  description = "Region for the runner subnet and Cloud NAT."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zone for the qualification runner VM."
  type        = string
  default     = "us-central1-a"
}

variable "name" {
  description = "VM, service account, and network resource name stem."
  type        = string
  default     = "day2-qualify-gitea"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,24}[a-z0-9]$", var.name))
    error_message = "name must be 6-26 lowercase letters, digits, or hyphens and start/end with a letter or digit."
  }
}

variable "machine_type" {
  description = "Sapphire Rapids x86_64 C3 machine type. Qualification targets the build host CPU and must not run under another CPU generation or emulation."
  type        = string
  default     = "c3-standard-8"

  validation {
    condition     = can(regex("^c3-[a-z0-9-]+$", var.machine_type))
    error_message = "machine_type must use the x86_64 C3 Sapphire Rapids family."
  }
}

variable "boot_image" {
  description = "Debian 13 x86_64 boot image for the native qualification host."
  type        = string
  default     = "projects/debian-cloud/global/images/family/debian-13"

  validation {
    condition     = !can(regex("arm64", var.boot_image))
    error_message = "boot_image must be an x86_64 image."
  }
}

variable "boot_disk_gb" {
  description = "Boot disk size for the Docker, Bazel, and qualification build caches."
  type        = number
  default     = 200

  validation {
    condition     = var.boot_disk_gb >= 100
    error_message = "boot_disk_gb must be at least 100."
  }
}

variable "subnet_cidr" {
  description = "CIDR of the runner's private subnet."
  type        = string
  default     = "10.62.0.0/24"

  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0))
    error_message = "subnet_cidr must be a valid CIDR block."
  }
}

variable "operator_members" {
  description = "Users or groups allowed to SSH to the VM through IAP with OS Login sudo."
  type        = set(string)

  validation {
    condition = (
      length(var.operator_members) > 0 &&
      alltrue([for member in var.operator_members : can(regex("^(user|group):[^@\\s]+@[^@\\s]+$", member))])
    )
    error_message = "operator_members must contain at least one user:<email> or group:<email>."
  }
}

variable "gitea_url" {
  description = "HTTPS base URL of the Gitea server that owns the selected repository."
  type        = string

  validation {
    condition     = can(regex("^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._/-]*)?$", var.gitea_url))
    error_message = "gitea_url must be an HTTPS URL with a safe host and optional path."
  }
}

variable "repository" {
  description = "The one Gitea repository registered to this host runner, as owner/name."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.repository))
    error_message = "repository must be one owner/name pair."
  }
}

variable "registration_secret_id" {
  description = "Existing Secret Manager secret id containing only this repository's runner registration token. The value is read at boot and is never a Terraform input."
  type        = string
  default     = "day2-qualification-runner-registration-token"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,255}$", var.registration_secret_id))
    error_message = "registration_secret_id must be a Secret Manager id, not a resource path or token value."
  }
}

variable "runner_labels" {
  description = "Unique Gitea Actions labels. The integration registers each as a host-executor label."
  type        = list(string)
  default     = ["qualification-x86"]

  validation {
    condition = (
      length(var.runner_labels) > 0 &&
      length(distinct(var.runner_labels)) == length(var.runner_labels) &&
      alltrue([for label in var.runner_labels : can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", label))])
    )
    error_message = "runner_labels must contain unique, non-empty labels made of letters, digits, dots, underscores, and hyphens."
  }
}

variable "act_runner_version" {
  description = "Pinned act_runner release version. Update together with act_runner_sha256."
  type        = string
  default     = "0.2.11"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.act_runner_version))
    error_message = "act_runner_version must be a numeric semantic version."
  }
}

variable "act_runner_sha256" {
  description = "SHA-256 of the pinned act_runner Linux amd64 release asset."
  type        = string
  default     = "7a5e833793286bbfd9b59ce682bd41fc3f1c096bae1bb2a09b66ab2f6dacf90c"

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.act_runner_sha256))
    error_message = "act_runner_sha256 must be a 64-character lowercase SHA-256 digest."
  }
}

variable "image_push_repository_ids" {
  description = "Artifact Registry repository ids this qualification host may write to. Empty grants no image-push access."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for repository_id in var.image_push_repository_ids :
      can(regex("^[a-z][a-z0-9-]{0,62}$", repository_id))
    ])
    error_message = "image_push_repository_ids must contain valid lowercase Artifact Registry repository ids."
  }
}

variable "desired_status" {
  description = "RUNNING or TERMINATED."
  type        = string
  default     = "RUNNING"

  validation {
    condition     = contains(["RUNNING", "TERMINATED"], var.desired_status)
    error_message = "desired_status must be RUNNING or TERMINATED."
  }
}
