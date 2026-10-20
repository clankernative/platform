variable "kubeconfig_path" {
  type    = string
  default = ""
}
variable "kube_context" {
  type    = string
  default = ""
}
variable "namespace" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.namespace))
    error_message = "Use a dedicated namespace name."
  }
}
variable "pool_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,38}[a-z0-9]$", var.pool_name))
    error_message = "Select the dedicated GKE node pool."
  }
}
variable "profile" {
  description = "Exact protected enrollment placement label and taint value."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.profile))
    error_message = "Use the same exact DNS label as the dedicated pool."
  }
}
variable "loader_image" {
  description = "Immutable platform-owned minimal image; parser and its matching shared libraries are read from the trusted Ubuntu x86 node."
  type        = string
  validation {
    condition     = can(regex("^[^[:space:]]+@sha256:[a-f0-9]{64}$", var.loader_image))
    error_message = "Pin the loader image by digest."
  }
}
variable "client_executable_paths" {
  description = "Exact selected App/Shell/Controller native paths, read-only; no globs or AppArmor syntax."
  type        = set(string)
  validation {
    condition = (
      length(var.client_executable_paths) >= 1 && length(var.client_executable_paths) <= 3 &&
      alltrue([for path in var.client_executable_paths : can(regex("^/usr/local/bin/[a-z][a-z0-9-]{0,63}$", path))])
    )
    error_message = "Select one to three exact native executable paths under /usr/local/bin, without globs or policy syntax."
  }
}
