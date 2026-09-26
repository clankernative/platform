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
  description = "The app's key in instance.json (the second day2-serve argument)."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,47}$", var.app_id)) && !startswith(var.app_id, "day2_") && !startswith(var.app_id, "sqlite_")
    error_message = "app_id must be a day2 identifier: [a-z][a-z0-9_]*, at most 48 characters, not starting with day2_ or sqlite_."
  }
}

variable "namespace" {
  description = "Existing namespace the platform created for this app (it must already hold the platform contract ConfigMap, the PVC, the Service and the service account)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a Kubernetes namespace name."
  }
}

variable "platform_contract_config_map" {
  description = "ConfigMap in the namespace that publishes the platform contract: IAP_JWT_AUDIENCE and APP_DOMAIN (required), PVC_NAME, SERVICE_NAME and label keys (optional)."
  type        = string
  default     = "platform-contract"
}

variable "service_account_name" {
  description = "Existing Kubernetes service account for the pod. Its token is not mounted; day2 needs no Kubernetes API access."
  type        = string
  default     = "runtime"
}

variable "workload_name" {
  description = "StatefulSet and instance ConfigMap base name. Empty derives day2-<app_id> with underscores as hyphens."
  type        = string
  default     = ""

  validation {
    condition     = var.workload_name == "" || can(regex("^[a-z0-9]([-a-z0-9]{0,40}[a-z0-9])?$", var.workload_name))
    error_message = "workload_name must be empty or a DNS label of at most 42 characters."
  }
}

variable "image" {
  description = "Digest-pinned app image: the day2 linux-sqlite runtime image with the app's qualified artifact baked in under /srv/day2/artifacts/<artifact_id> (see ../../images/app)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be pinned by digest: <registry>/<path>@sha256:<64 lowercase hex>."
  }
}

variable "artifact_id" {
  description = "The artifact id baked into the image: the directory name under /srv/day2/artifacts, equal to the sha256 of its artifact.json."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.artifact_id))
    error_message = "artifact_id must be 64 lowercase hex characters."
  }
}

variable "installation" {
  description = "instance.json installation identifier. Day2 records it on first start and refuses a later change."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,47}$", var.installation)) && !startswith(var.installation, "day2_") && !startswith(var.installation, "sqlite_")
    error_message = "installation must be a day2 identifier."
  }
}

variable "environment" {
  description = "instance.json environment identifier. Like installation, fixed after first start."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,47}$", var.environment)) && !startswith(var.environment, "day2_") && !startswith(var.environment, "sqlite_")
    error_message = "environment must be a day2 identifier."
  }
}

variable "hosted_domain" {
  description = "Google Workspace domain IAP assertions must carry (identity.hosted_domain)."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.hosted_domain))
    error_message = "hosted_domain must be a lowercase DNS name with at least two labels."
  }
}

variable "edge_origin" {
  description = "Exact browser origin of the app: https://<host>, lowercase, no port or path. Must equal https:// plus the platform contract's APP_DOMAIN."
  type        = string

  validation {
    condition     = can(regex("^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.edge_origin))
    error_message = "edge_origin must be https://<lowercase host> with no port, path or trailing slash."
  }
}

variable "iap_audience_override" {
  description = "Leave empty. Only for a documented emergency where the platform contract's IAP_JWT_AUDIENCE is known stale; the normal path renders it from the contract."
  type        = string
  default     = ""

  validation {
    condition     = var.iap_audience_override == "" || can(regex("^/projects/[0-9]{1,24}/global/backendServices/[0-9]{1,24}$", var.iap_audience_override))
    error_message = "iap_audience_override must be empty or /projects/<number>/global/backendServices/<id>."
  }
}

variable "runtime_resources" {
  description = "Day2 linux_sqlite_single_v1 resources. The pod's CPU and memory limits are rendered from these; day2-serve compares the container cgroup against them at start. process_limit is held by the node pool's podPidsLimit (see pod_pids_limit), so it is rendered with process_limit_enforced_by = \"pod\"."
  type = object({
    memory_mib       = number
    cpu_millis       = number
    process_limit    = number
    http_concurrency = number
    shutdown_seconds = number
  })

  validation {
    condition = (
      alltrue([for value in values(var.runtime_resources) : value == floor(value)]) &&
      var.runtime_resources.memory_mib >= 64 && var.runtime_resources.memory_mib <= 65536 &&
      var.runtime_resources.cpu_millis >= 50 && var.runtime_resources.cpu_millis <= 64000 &&
      var.runtime_resources.process_limit >= 16 && var.runtime_resources.process_limit <= 4096 &&
      var.runtime_resources.http_concurrency >= 1 && var.runtime_resources.http_concurrency <= 32 &&
      var.runtime_resources.shutdown_seconds >= 5 && var.runtime_resources.shutdown_seconds <= 300
    )
    error_message = "runtime_resources must be integers within day2's bounds: memory_mib 64..65536, cpu_millis 50..64000, process_limit 16..4096, http_concurrency 1..32, shutdown_seconds 5..300."
  }
}

variable "container_max" {
  description = "The namespace LimitRange's per-container maximum (the app-edge stack defaults to 4 CPU / 4 GiB). Profiles above it would be refused at admission, so they are refused at plan."
  type = object({
    cpu_millis = number
    memory_mib = number
  })
  default = {
    cpu_millis = 4000
    memory_mib = 4096
  }
}

variable "pod_pids_limit" {
  description = "The kubelet podPidsLimit of the node pool this pod runs on, as configured in the cluster (the cluster stack's pod_pids_limit). Declared here because the container cannot observe it. Must not exceed runtime_resources.process_limit."
  type        = number

  validation {
    condition     = var.pod_pids_limit == floor(var.pod_pids_limit) && var.pod_pids_limit >= 1024 && var.pod_pids_limit <= 4194304
    error_message = "pod_pids_limit must be a whole number from 1024 to 4194304 (GKE's allowed podPidsLimit range)."
  }
}

variable "readers" {
  description = "instance.json readers (lowercased IAP e-mail addresses). Seeded into the app database on first start only."
  type        = list(string)

  validation {
    condition     = length(var.readers) > 0 && alltrue([for actor in var.readers : can(regex("^[^\\s@]+@[^\\s@]+$", actor)) && lower(actor) == actor])
    error_message = "readers must be a non-empty list of lowercase e-mail addresses."
  }
}

variable "writers" {
  description = "instance.json writers (lowercased IAP e-mail addresses). Seeded on first start only."
  type        = list(string)

  validation {
    condition     = alltrue([for actor in var.writers : can(regex("^[^\\s@]+@[^\\s@]+$", actor)) && lower(actor) == actor])
    error_message = "writers must be lowercase e-mail addresses."
  }
}

variable "authority" {
  description = "The app's authority policy object (version 1). It must name every operation of the exact artifact being deployed, or every operation fails missing_authority_policy. Seeded on first start only; later changes need day2's explicit activation."
  type        = any
}

variable "state_ownership_init_enabled" {
  description = "Run a root init container (CAP_CHOWN only) that makes the state volume's root directory 10001:10001 mode 0700. Day2 chmods .state itself and must own it; a fresh GCE PD root is root-owned."
  type        = bool
  default     = true
}

variable "tmp_size_limit" {
  description = "Size of the memory-backed /tmp emptyDir. day2-serve copies each worker executable there before sandboxing it. Counts against the memory limit."
  type        = string
  default     = "64Mi"
}

variable "node_selector" {
  description = "Node labels the pod must match. The artifact's worker is a native build, so pin the architecture it was qualified on."
  type        = map(string)
  default = {
    "kubernetes.io/arch" = "amd64"
    "kubernetes.io/os"   = "linux"
  }
}

variable "extra_pod_labels" {
  description = "Additional pod labels required by the hosting platform (for example its telemetry system label). Selector labels win on conflict."
  type        = map(string)
  default     = {}
}

variable "state_ownership_image" {
  description = "Image for the state-ownership init container, pinned by digest. It must carry /busybox/sh, chmod and chown; the distroless app image has no shell."
  type        = string
  default     = "gcr.io/distroless/static-debian13:debug@sha256:07148a6899406df51906b183f581cf66e5b05fd51aca438bdf1d3998df566961"

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.state_ownership_image))
    error_message = "state_ownership_image must be pinned by digest."
  }
}

variable "backup_bucket" {
  description = "The app's off-cluster backup bucket: the app-edge stack's backup_bucket output (<project_id>-<app>-backups). The backup service account may only create objects in it."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$", var.backup_bucket)) && !startswith(var.backup_bucket, "goog")
    error_message = "backup_bucket must be a GCS bucket name without dots (3-63 lowercase letters, digits, hyphens and underscores)."
  }
}

variable "backup_schedule" {
  description = "Cron schedule of the off-cluster backup, in UTC. Default: hourly at minute 17."
  type        = string
  default     = "17 * * * *"

  validation {
    condition     = can(regex("^[0-9*/,-]+ [0-9*/,-]+ [0-9*/,-]+ [0-9*/,-]+ [0-9*/,-]+$", var.backup_schedule))
    error_message = "backup_schedule must be a five-field numeric cron expression (no @-macros or names)."
  }
}

variable "backup_service_account_name" {
  description = "Kubernetes service account of the backup Job: app-edge's \"backup\", bound through Workload Identity to the object-create-only uploader. The tenancy policy admits it only for Jobs labelled service=backup."
  type        = string
  default     = "backup"
}

variable "backup_uploader_image" {
  description = "Image of the upload container, pinned by digest. It needs /bin/sh, tar, gzip, sed, wc, tr, date and curl; the distroless app image has none of them."
  type        = string
  default     = "docker.io/curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777"

  validation {
    condition     = can(regex("^[a-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$", var.backup_uploader_image))
    error_message = "backup_uploader_image must be pinned by digest: <registry>/<path>[:tag]@sha256:<64 lowercase hex>."
  }
}

variable "backup_starting_deadline_seconds" {
  description = "A run that could not start within this many seconds of its schedule is skipped (counted as missed)."
  type        = number
  default     = 600

  validation {
    condition     = var.backup_starting_deadline_seconds == floor(var.backup_starting_deadline_seconds) && var.backup_starting_deadline_seconds >= 60 && var.backup_starting_deadline_seconds <= 3600
    error_message = "backup_starting_deadline_seconds must be a whole number from 60 to 3600."
  }
}

variable "backup_active_deadline_seconds" {
  description = "Hard limit of one backup Job, including a pod left Pending because the app pod is not running."
  type        = number
  default     = 1800

  validation {
    condition     = var.backup_active_deadline_seconds == floor(var.backup_active_deadline_seconds) && var.backup_active_deadline_seconds >= 300 && var.backup_active_deadline_seconds <= 3300
    error_message = "backup_active_deadline_seconds must be a whole number from 300 to 3300 (under an hour, so hourly runs cannot pile up)."
  }
}

variable "backup_scratch_size_limit" {
  description = "Disk emptyDir for the snapshot and its tar.gz (and the containers' ephemeral-storage limit). At least twice the state database, provider stores and artifact."
  type        = string
  default     = "2Gi"
}

variable "backup_snapshot_memory" {
  description = "Memory limit of the day2-backup container. Digesting reads each database (up to 256 MiB) into memory."
  type        = string
  default     = "1Gi"
}
