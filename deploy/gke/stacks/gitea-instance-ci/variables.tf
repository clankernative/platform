variable "project_id" {
  description = "GCP project whose infrastructure the instance CI plans and applies. It also hosts the runner."
  type        = string

  validation {
    condition     = trimspace(var.project_id) != ""
    error_message = "project_id must not be empty."
  }
}

variable "project_number" {
  description = "Numeric project number of project_id (workload identity principal sets are addressed by number)."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.project_number))
    error_message = "project_number must be numeric."
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

variable "name" {
  description = "VM, service account and network resource name stem."
  type        = string
  default     = "instance-ci-runner"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,24}[a-z0-9]$", var.name))
    error_message = "name must be 6-26 characters of lowercase letters, digits and hyphens (it also names the service account)."
  }
}

variable "machine_type" {
  description = "x86_64 machine type for the runner. Jobs run OpenTofu plans and applies, not builds."
  type        = string
  default     = "e2-standard-2"

  validation {
    condition     = !can(regex("^(t2a|c4a|a4x)-", var.machine_type))
    error_message = "machine_type must be an x86_64 family, not an Arm family (t2a, c4a, a4x): the job image is linux/amd64."
  }
}

variable "boot_image" {
  description = "Boot image. The startup script targets Debian (Docker's Debian repository)."
  type        = string
  default     = "projects/debian-cloud/global/images/family/debian-13"
}

variable "boot_disk_gb" {
  description = "Boot disk size. Holds the Docker image cache for the runner controller and job image."
  type        = number
  default     = 50
}

variable "subnet_cidr" {
  description = "CIDR of the runner's own subnet."
  type        = string
  default     = "10.61.0.0/24"
}

variable "operator_members" {
  description = "IAM members who may SSH to the runner through IAP (sudo), for runner maintenance."
  type        = set(string)

  validation {
    condition     = length(var.operator_members) > 0
    error_message = "operator_members must name at least one user or group."
  }
}

variable "gitea_url" {
  description = "Company-owned Gitea server the runner registers with, supplied by the private instance configuration."
  type        = string
}

variable "repository" {
  description = "The one Gitea repository (owner/name) whose workflows this runner and these identities serve: the instance configuration repository."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.repository))
    error_message = "repository must be owner/name."
  }
}

variable "repository_id" {
  description = "Gitea's numeric id of repository. Workload identity trusts the id, not the name, so a renamed or recreated repository is refused."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]*$", var.repository_id))
    error_message = "repository_id must be a positive integer."
  }
}

variable "repository_owner_id" {
  description = "Gitea's numeric id of the repository's owner (organization)."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]*$", var.repository_owner_id))
    error_message = "repository_owner_id must be a positive integer."
  }
}

variable "oidc_issuer_uri" {
  description = "Company-owned issuer of the workflow OIDC tokens, supplied by the private instance configuration. Gitea has no Actions OIDC endpoint; git-oidc mints GitHub-shaped tokens for a named repository's running task."
  type        = string
}

variable "workload_identity_pool_id" {
  description = "Existing workload identity pool (created at bootstrap) that holds the Gitea provider."
  type        = string
  default     = "instance-ci"
}

variable "workload_identity_provider_id" {
  description = "Provider id within the pool."
  type        = string
  default     = "gitea"
}

variable "plan_workflow_path" {
  description = "Workflow file whose pull_request runs may plan (read-only identity)."
  type        = string
  default     = ".gitea/workflows/plan.yml"
}

variable "apply_workflow_path" {
  description = "Workflow file whose runs on refs/heads/main (push or workflow_dispatch) may apply."
  type        = string
  default     = ".gitea/workflows/apply.yml"
}

variable "apply_service_account_email" {
  description = "Existing service account that applies the instance's stacks (the bootstrap apply identity)."
  type        = string

  validation {
    condition     = can(regex("^[^@]+@[^@]+\\.iam\\.gserviceaccount\\.com$", var.apply_service_account_email))
    error_message = "apply_service_account_email must be a service account email."
  }
}

variable "plan_service_account_id" {
  description = "Account id of the read-only plan identity this root creates."
  type        = string
  default     = "instance-ci-plan"
}

variable "plan_project_roles" {
  description = "Read-only project roles the plan identity needs to refresh every stack."
  type        = set(string)
  default = [
    "roles/viewer",
    "roles/iam.securityReviewer",
    "roles/container.viewer",
    "roles/secretmanager.viewer",
  ]

  validation {
    condition     = alltrue([for role in var.plan_project_roles : !can(regex("(?i)(admin|editor|owner|writer|creator|user)$", role))])
    error_message = "plan_project_roles must be read-only roles (no admin, editor, owner, writer, creator or user roles)."
  }
}

variable "state_bucket_name" {
  description = "OpenTofu state bucket the plan identity reads."
  type        = string
}

variable "plan_secret_ids" {
  description = "Secret Manager secrets (in project_id) whose values a plan must read, such as the Cloudflare API token the app stack's provider uses."
  type        = set(string)
  default     = []
}

variable "runner_registration_secret_id" {
  description = "Secret Manager secret holding the repository-scoped runner registration token. Read once, at first registration."
  type        = string
  default     = "gitea-instance-ci-runner-registration-token"
}

variable "runner_controller_image" {
  description = "act_runner image, pinned by digest (the fleet runner profile's controller)."
  type        = string
  default     = "docker.io/gitea/act_runner@sha256:578925b4bdec5f60d93b5ba766cf02f2f9f32b1c8a4ec665ddf4d53d45f683c7"

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.runner_controller_image))
    error_message = "runner_controller_image must be pinned by digest."
  }
}

variable "job_image" {
  description = "Image every job runs in, pinned by digest. The slim runner image (Node for JavaScript actions, about 200 MB): the fleet's full image is tens of gigabytes of language toolchains OpenTofu jobs never use. Jobs install their few tools themselves."
  type        = string
  default     = "docker.io/gitea/runner-images@sha256:7c285821aab503cffc21024bbb216822a86326c1b22ea53e341492e2aa6df245"

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.job_image))
    error_message = "job_image must be pinned by digest."
  }
}

variable "runner_label" {
  description = "The runner's only label; workflows select it with runs-on."
  type        = string
  default     = "instance-ci"
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
