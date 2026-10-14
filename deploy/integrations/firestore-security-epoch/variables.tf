variable "project_id" {
  type        = string
  description = "Instance-owned GCP project containing the database and both service accounts."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Select a concrete GCP project ID."
  }
}

variable "location" {
  type        = string
  description = "Instance-selected Firestore location; resource placement is not a clock or availability proof."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,62}$", var.location))
    error_message = "Select an explicit Firestore location."
  }
}

variable "database_id" {
  type        = string
  description = "Dedicated named Native database for one app authority; never the default database."

  validation {
    condition = (
      can(regex("^[a-z][a-z0-9-]{2,61}[a-z0-9]$", var.database_id)) &&
      !can(regex("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", var.database_id))
    )
    error_message = "Select a non-default, non-UUID database ID of 4 to 63 lowercase letters, digits or hyphens."
  }
}

variable "authority_scope" {
  type = object({
    installation = string
    environment  = string
    app          = string
  })
  description = "One instance app scope. This metadata does not initialize an epoch or authorize a transition."

  validation {
    condition     = alltrue([for part in values(var.authority_scope) : can(regex("^[a-z][a-z0-9_-]{0,79}$", part))])
    error_message = "Supply explicit bounded installation, environment and app names."
  }
}

variable "app_reader_service_account" {
  type        = string
  description = "Existing app GSA selected by EpochIam; this root grants only database reads to it."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.app_reader_service_account))
    error_message = "Supply a concrete Google service account email."
  }
}

variable "controller_service_account_id" {
  type        = string
  description = "New dedicated controller GSA. No workload binding, token mint permission or serving workload is created here."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.controller_service_account_id))
    error_message = "Select a controller service account ID of 6 to 30 lowercase letters, digits or hyphens."
  }
}
