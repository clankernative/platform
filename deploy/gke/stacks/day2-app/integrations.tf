# Operator-owned authority for apps with scheduled work and provider access.
# No provider secret values belong in these variables or in OpenTofu state.
variable "resource_catalog" {
  description = "Day2 version 1 resource catalog with connection references, scoped targets, policies and budgets. Provider credentials are mounted separately."
  type        = any
  default     = null
  validation {
    condition     = var.resource_catalog == null ? true : try(var.resource_catalog.version == 1, false)
    error_message = "resource_catalog must be absent or a Day2 version 1 catalog."
  }
}

variable "resource_policies" {
  description = "Reviewed resource policy attachments for exact artifact operation names."
  type = list(object({
    policy        = object({ id = string, revision = number })
    operation     = string
    bindings      = map(object({ id = string, revision = number }))
    actors        = optional(set(string))
    expires_at_ms = optional(number)
  }))
  default = []
  validation {
    condition     = length(var.resource_policies) == 0 || var.resource_catalog != null
    error_message = "Provider attachments require a resource_catalog."
  }
}

variable "schedules" {
  description = "Declared schedule names mapped to explicitly authorized actors; disabled pauses a binding."
  type        = map(object({ actor = string, disabled = optional(bool, false) }))
  default     = {}
  validation {
    condition     = alltrue([for name, binding in var.schedules : can(regex("^[a-z][a-z0-9_.]*$", name)) && trimspace(binding.actor) != ""])
    error_message = "Every schedule needs a declared name and an explicit actor."
  }
}

variable "ingress" {
  description = "Declared signed endpoint names mapped to authorized actors and live connection revisions. These do not create a public load-balancer route."
  type = map(object({
    actor      = string
    connection = object({ id = string, revision = number })
    disabled   = optional(bool, false)
  }))
  default = {}
  validation {
    condition = length(var.ingress) == 0 || (var.resource_catalog != null && alltrue([
      for name, binding in var.ingress : can(regex("^[a-z][a-z0-9_]*$", name)) && trimspace(binding.actor) != "" && binding.connection.revision >= 1
    ]))
    error_message = "Signed ingress needs a resource catalog and explicit actor/connection bindings."
  }
}

variable "journal_trace_hours" {
  description = "Hours a completed invocation keeps its full trace before compaction to a receipt (instance journal.trace_hours). Null keeps day2's default (72). Apps with frequent scheduled work should keep this short: each trace carries its admitted authority."
  type        = number
  default     = null
  validation {
    condition     = var.journal_trace_hours == null ? true : (var.journal_trace_hours == floor(var.journal_trace_hours) && var.journal_trace_hours >= 1 && var.journal_trace_hours <= 8784)
    error_message = "journal_trace_hours must be a whole number of hours between 1 and 8784."
  }
}
