variable "project_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Select the exact installation project ID."
  }
}
variable "cluster" {
  type = object({ name = string, location = string, scope = string })
  validation {
    condition = (
      contains(["zonal", "regional"], var.cluster.scope) &&
      can(regex("^[a-z][a-z0-9-]{0,38}[a-z0-9]$", var.cluster.name)) &&
      can(regex("^[a-z][a-z0-9-]{1,62}$", var.cluster.location))
    )
    error_message = "Select the exact cluster name, location and explicit zonal/regional IAM scope."
  }
}
variable "provisioner_namespace" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.provisioner_namespace))
    error_message = "Select the exact provisioner namespace."
  }
}
variable "provisioner_service_account" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.provisioner_service_account))
    error_message = "Select the exact provisioner Kubernetes service account."
  }
}
variable "role_prefix" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]{2,39}$", var.role_prefix))
    error_message = "Use a distinct bounded custom-role prefix for this installation."
  }
}
variable "service_accounts" {
  description = "Exact selected Google service account emails by native role. No impersonation is granted."
  type        = map(string)
  validation {
    condition = (
      toset(keys(var.service_accounts)) == toset(["app", "shell", "controller"]) &&
      length(toset(values(var.service_accounts))) == 3 &&
      alltrue([for email in values(var.service_accounts) :
        can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", email)) &&
        endswith(email, "@${var.project_id}.iam.gserviceaccount.com")
      ])
    )
    error_message = "Select three distinct App/Shell/controller Google accounts in the chosen project, without wildcards."
  }
}
