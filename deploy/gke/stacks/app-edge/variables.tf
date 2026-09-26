variable "project_id" {
  description = "GCP project that hosts the cluster and the app's edge."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a GCP project ID."
  }
}

variable "project_number" {
  description = "Numeric project number of project_id. IAP audiences are /projects/<number>/global/backendServices/<id>."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{1,24}$", var.project_number))
    error_message = "project_number must be the numeric project number."
  }
}

variable "region" {
  description = "Region of the cluster: Artifact Registry repository, state bucket and Backup for GKE plan location."
  type        = string
  default     = "us-central1"
}

variable "cluster_name" {
  description = "GKE cluster the app runs on (the Backup for GKE plan targets it)."
  type        = string
}

variable "cluster_location" {
  description = "Zone or region of cluster_name."
  type        = string
}

variable "kubeconfig_path" {
  description = "Optional kubeconfig path for the target cluster. Empty uses the provider's default discovery (KUBE_CONFIG_PATH, in-cluster)."
  type        = string
  default     = ""
}

variable "kube_context" {
  description = "Optional kubeconfig context for the target cluster, e.g. gke_<project>_<zone>_<cluster>."
  type        = string
  default     = ""
}

variable "app_id" {
  description = "Platform app id. Names the namespace (<namespace_prefix><app_id>), static IP (<app_id>-ip), Artifact Registry repository (<app_id>), state bucket (<project_id>-<app_id>-state) and backup plan (<app_id>-backup)."
  type        = string

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$", var.app_id))
    error_message = "app_id must be 1-30 lowercase letters, digits and hyphens, starting with a letter and not ending with a hyphen."
  }
}

variable "namespace_prefix" {
  description = "Prefix of the app namespace. The tenancy stack's admission policies protect namespaces with this prefix."
  type        = string
  default     = "app-"
}

variable "domain" {
  description = "The app's public host name, e.g. go.v2.example.com. Serves the Ingress rule, the managed certificate, the DNS record and the contract's APP_DOMAIN."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.domain))
    error_message = "domain must be a lowercase DNS name."
  }
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone that holds domain's A record."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_zone_id))
    error_message = "cloudflare_zone_id must be a 32-character Cloudflare zone ID."
  }
}

variable "cloudflare_proxied" {
  description = "Proxy the record through Cloudflare. Leave false when Cloudflare's certificate does not cover domain (Universal SSL covers only one level below the zone apex); the GKE managed certificate terminates TLS."
  type        = bool
  default     = false
}

variable "backend_service_name" {
  description = "Name of the GKE-created backend service for this app's Service (from the Ingress's ingress.kubernetes.io/backends annotation). Empty only on initial edge bootstrap: then no IAP grant is made and IAP_JWT_AUDIENCE is empty, which day2-app refuses."
  type        = string
  default     = ""

  validation {
    condition     = var.backend_service_name == "" || can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.backend_service_name))
    error_message = "backend_service_name must be empty or a compute resource name."
  }
}

variable "iap_members" {
  description = "Principals granted roles/iap.httpsResourceAccessor on the app's backend (authoritative binding). day2 still checks the hosted domain and its own authority policy."
  type        = set(string)

  validation {
    condition     = length(var.iap_members) > 0 && alltrue([for member in var.iap_members : can(regex("^(user|group|serviceAccount):[^@\\s]+@[^@\\s]+$|^domain:[a-z0-9.-]+$", member))])
    error_message = "iap_members must be non-empty user:, group:, serviceAccount: or domain: principals; allUsers and allAuthenticatedUsers are refused."
  }
}

variable "deployer_subjects" {
  description = "Identities that deploy the app's workload (day2-app): app-deployer RBAC in the namespace, object admin on the state bucket, and (serviceAccount: only) writer on the Artifact Registry repository."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for subject in var.deployer_subjects : can(regex("^(user|group|serviceAccount):[^@\\s]+@[^@\\s]+$", subject))])
    error_message = "deployer_subjects must be user:, group: or serviceAccount: principals."
  }
}

variable "sqlite_storage_gb" {
  description = "Size of the data PVC (day2's .state directory). GKE can grow it in place; it cannot shrink."
  type        = number

  validation {
    condition     = var.sqlite_storage_gb == floor(var.sqlite_storage_gb) && var.sqlite_storage_gb >= 1
    error_message = "sqlite_storage_gb must be a whole number of GiB, at least 1."
  }
}

variable "storage_class_name" {
  description = "StorageClass of the data PVC (a Retain class from the tenancy stack)."
  type        = string
}

variable "health_check_path" {
  description = "Load balancer health check path. day2 serves /health/ready without an IAP assertion."
  type        = string
  default     = "/health/ready"
}

variable "backend_timeout_seconds" {
  description = "BackendConfig timeoutSec."
  type        = number
  default     = 30
}

variable "backend_connection_draining_timeout_seconds" {
  description = "BackendConfig connectionDraining.drainingTimeoutSec."
  type        = number
  default     = 60
}

variable "o11y_service_label" {
  description = "Value of the o11y.wonderly.info/service label on the Service, published as O11Y_SERVICE_LABEL_VALUE for day2-app's pod labels. Empty derives <app_id>-api."
  type        = string
  default     = ""
}

variable "kube_dns_service_ip" {
  description = "ClusterIP of kube-dns (the 10th address of the cluster's service range). Pods resolve through it."
  type        = string

  validation {
    condition     = can(cidrhost("${var.kube_dns_service_ip}/32", 0))
    error_message = "kube_dns_service_ip must be an IPv4 address."
  }
}

variable "cluster_cidrs" {
  description = "Cluster pod, service and node subnet ranges, excluded from public egress in addition to the RFC 1918 and link-local ranges."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.cluster_cidrs : can(cidrhost(cidr, 0))])
    error_message = "cluster_cidrs must be CIDR ranges."
  }
}

variable "resource_guardrails" {
  description = "Namespace LimitRange (per container) and ResourceQuota. day2-app's container_max must match container_max here."
  type = object({
    container_default_requests = object({ cpu = string, memory = string, ephemeral_storage = string })
    container_default_limits   = object({ cpu = string, memory = string, ephemeral_storage = string })
    container_max              = object({ cpu = string, memory = string, ephemeral_storage = string })
    namespace_quota = object({
      requests_cpu               = string
      requests_memory            = string
      requests_ephemeral_storage = string
      limits_cpu                 = string
      limits_memory              = string
      limits_ephemeral_storage   = string
      pods                       = number
    })
  })
  default = {
    container_default_requests = { cpu = "100m", memory = "256Mi", ephemeral_storage = "256Mi" }
    container_default_limits   = { cpu = "2", memory = "2Gi", ephemeral_storage = "2Gi" }
    container_max              = { cpu = "4", memory = "4Gi", ephemeral_storage = "8Gi" }
    namespace_quota = {
      requests_cpu               = "4"
      requests_memory            = "4Gi"
      requests_ephemeral_storage = "4Gi"
      limits_cpu                 = "12"
      limits_memory              = "12Gi"
      limits_ephemeral_storage   = "12Gi"
      pods                       = 20
    }
  }
}

variable "backup" {
  description = "Backup for GKE plan for the namespace (volume data included, Secrets excluded)."
  type = object({
    target_rpo_minutes = number
    retain_days        = number
    delete_lock_days   = number
  })
  default = {
    target_rpo_minutes = 720
    retain_days        = 30
    delete_lock_days   = 1
  }
}

variable "offsite_backup_retention_days" {
  description = "Days each off-cluster day2 backup is kept in <project_id>-<app_id>-backups. The bucket's (unlocked) retention policy refuses earlier deletion or replacement; lifecycle deletes objects one day later."
  type        = number
  default     = 30

  validation {
    condition     = var.offsite_backup_retention_days == floor(var.offsite_backup_retention_days) && var.offsite_backup_retention_days >= 1 && var.offsite_backup_retention_days <= 365
    error_message = "offsite_backup_retention_days must be a whole number of days from 1 to 365."
  }
}

variable "offsite_backup_readers" {
  description = "Principals granted roles/storage.objectViewer on the backup bucket, to download backups for restore. The uploader itself can only create objects."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for member in var.offsite_backup_readers : can(regex("^(user|group|serviceAccount):[^@\\s]+@[^@\\s]+$", member))])
    error_message = "offsite_backup_readers must be user:, group: or serviceAccount: principals."
  }
}

variable "offsite_backup_service_account_id" {
  description = "Account id of the backup uploader's Google service account. Empty derives <app_id>-backup; set it when that exceeds 30 characters."
  type        = string
  default     = ""

  validation {
    condition     = var.offsite_backup_service_account_id == "" || can(regex("^[a-z]([-a-z0-9]{4,28}[a-z0-9])$", var.offsite_backup_service_account_id))
    error_message = "offsite_backup_service_account_id must be empty or 6-30 lowercase letters, digits and hyphens, starting with a letter."
  }
}
