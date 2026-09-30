variable "project_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a Google Cloud project ID."
  }
}

variable "project_number" {
  type = string
  validation {
    condition     = can(regex("^[1-9][0-9]{0,23}$", var.project_number))
    error_message = "project_number must be the numeric project identity."
  }
}

variable "kubeconfig_path" {
  type    = string
  default = ""
}

variable "kube_context" {
  type    = string
  default = ""
}

variable "namespace" {
  description = "Dedicated security namespace; it must not be an app namespace."
  type        = string
  default     = "day2-security"
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.namespace)) && !startswith(var.namespace, "app-") && !startswith(var.namespace, "kube-") && var.namespace != "default"
    error_message = "namespace must be a dedicated DNS label outside app-*, kube-* and default."
  }
}

variable "domain" {
  description = "Installation-owned hostname. This one value drives DNS, TLS, Ingress, the shell origin and reauthentication redirect."
  type        = string
  validation {
    condition     = length(var.domain) <= 253 && can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.domain))
    error_message = "domain must be a lowercase DNS hostname without a scheme, port or path."
  }
}

variable "cloudflare_zone_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_zone_id))
    error_message = "cloudflare_zone_id must be a 32-character zone ID."
  }
}

variable "backend_service_name" {
  description = "Empty for bootstrap; then the GKE backend of this namespace's security-shell Service."
  type        = string
  default     = ""
}

variable "iap_members" {
  description = "Human IAP access for this installation's shell. Runtime still verifies the installation domain and fresh reauthentication."
  type        = list(string)
  validation {
    condition     = length(var.iap_members) > 0 && length(var.iap_members) <= 128 && alltrue([for member in var.iap_members : can(regex("^(user:|group:|domain:)[^[:space:]]+$", member))])
    error_message = "iap_members must contain bounded user, group or domain principals."
  }
}

variable "runtime_secret_ids" {
  description = "Only the shell's selected OAuth key and client-secret containers. Secret values and versions are resolved privately by the host."
  type        = set(string)
  default     = []
  validation {
    condition     = length(var.runtime_secret_ids) <= 32 && alltrue([for id in var.runtime_secret_ids : can(regex("^[A-Za-z0-9_-]{1,255}$", id))])
    error_message = "runtime_secret_ids must contain at most 32 plain secret IDs."
  }
}

variable "kube_dns_service_ip" {
  type = string
  validation {
    condition     = can(cidrhost("${var.kube_dns_service_ip}/32", 0))
    error_message = "kube_dns_service_ip must be the cluster DNS IPv4 address."
  }
}

variable "cluster_cidrs" {
  description = "Pod, service and node ranges excluded from public provider egress."
  type        = list(string)
  validation {
    condition     = length(var.cluster_cidrs) >= 1 && length(var.cluster_cidrs) <= 16 && alltrue([for cidr in var.cluster_cidrs : can(cidrhost(cidr, 0)) && !strcontains(cidr, ":")])
    error_message = "cluster_cidrs must list the cluster's bounded IPv4 ranges."
  }
}
