variable "project_id" {
  description = "GCP project the day2 stacks deploy into."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a GCP project id (6-30 lowercase letters, digits and hyphens, starting with a letter)."
  }
}

variable "region" {
  description = "Location of the OpenTofu state bucket (and the provider's default region). A bucket's location is immutable: changing this replaces the bucket that holds every stack's state, which prevent_destroy refuses."
  type        = string

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must be a GCP region such as us-central1."
  }
}

variable "state_bucket_name" {
  description = "GCS bucket holding the remote state of every day2 stack, this one included. It is created by hand before the first run (the backend needs it before this root can plan) and adopted here."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "state_bucket_name must be 3-63 lowercase letters, digits, hyphens or underscores (no dots: dotted names are domain-verified)."
  }
}

variable "state_prefixes" {
  description = "State object prefixes in the state bucket, by name. Each gets one conditional reader and one conditional writer binding. The name is part of the IAM condition title, so renaming an entry replaces its bindings."
  type        = map(string)

  validation {
    condition     = length(var.state_prefixes) > 0
    error_message = "state_prefixes must name at least the prefix this stack's own state lives under."
  }

  validation {
    condition     = alltrue([for name in keys(var.state_prefixes) : can(regex("^[a-z][a-z0-9_]*$", name))])
    error_message = "state_prefixes names must be lowercase letters, digits and underscores, starting with a letter."
  }

  # The trailing slash keeps "day2/" from also matching "day2-other/...".
  validation {
    condition = alltrue([
      for prefix in values(var.state_prefixes) :
      can(regex("^[a-z0-9][a-z0-9_./-]*/$", prefix)) && !strcontains(prefix, "//")
    ])
    error_message = "state_prefixes values must be relative object prefixes ending in \"/\" (for example \"platform/cluster/\")."
  }
}

variable "state_writer_members" {
  description = "IAM members that apply the stacks (the apply service account, or the bootstrap operator). They get object admin on every state prefix."
  type        = list(string)

  validation {
    condition     = length(var.state_writer_members) > 0
    error_message = "state_writer_members must not be empty: nobody could write state."
  }

  validation {
    condition     = alltrue([for member in var.state_writer_members : can(regex("^(user|serviceAccount|group|principal|principalSet):[^ ]+$", member))])
    error_message = "state_writer_members entries must be IAM members such as serviceAccount:apply@project.iam.gserviceaccount.com."
  }
}

variable "state_reader_members" {
  description = "IAM members that may read state (plan-only operators or a read-only CI identity). Empty grants no reader bindings."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for member in var.state_reader_members : can(regex("^(user|serviceAccount|group|principal|principalSet):[^ ]+$", member))])
    error_message = "state_reader_members entries must be IAM members such as user:operator@example.com."
  }
}
