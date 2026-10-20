variable "kubeconfig_path" {
  type    = string
  default = ""
}
variable "kube_context" {
  type    = string
  default = ""
}
variable "app" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,63}$", var.app))
    error_message = "Select exactly one installed app."
  }
}
variable "bootstrap_alias" {
  type = string
}
variable "namespace" {
  type = string
  validation {
    condition     = var.namespace == "day2-native-enrollment"
    error_message = "Use the separately provisioned native enrollment namespace."
  }
}
variable "image" {
  description = "Qualified Calendar child image, including selected artifact and the real Controller executable."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$", var.image))
    error_message = "Select a digest-pinned artifact-bearing image."
  }
}
variable "instance_json" {
  type = string
  validation {
    condition     = length(var.instance_json) <= 524288 && can(jsondecode(var.instance_json).apps)
    error_message = "Supply bounded complete native instance metadata."
  }
}
variable "enrollment_json" {
  description = "Public operator enrollment selections, no private keys. Native admission validates their complete closed schema."
  type        = string
  validation {
    condition     = length(var.enrollment_json) <= 65536 && can(jsondecode(var.enrollment_json))
    error_message = "Supply bounded JSON. Activation requires the exact complete selected enrollment profile."
  }
}
variable "storage_json" {
  description = "Actual immutable PVC/PV/disk/node selection, not a mount or P3 witness."
  type        = string
  validation {
    condition     = length(var.storage_json) <= 16384 && can(jsondecode(var.storage_json).disk_id)
    error_message = "Supply bounded complete immutable storage selections."
  }
}
variable "host_state_path" {
  description = "Operator-observed existing CSI global mount of the SAME App disk on the selected node. Never guess this from a PVC name."
  type        = string
  validation {
    condition     = can(regex("^/var/lib/kubelet/plugins/kubernetes.io/csi/.+/globalmount$", var.host_state_path)) && !strcontains(var.host_state_path, "..")
    error_message = "Select the observed existing CSI global mount, with no traversal."
  }
}
variable "activate" {
  description = "False registers no running executor. True only after exact workload UID, profiles, App mount and code have been qualified; no original-file adoption on restart."
  type        = bool
  default     = false
}

variable "node_profile" {
  description = "Existing protected native-enrollment placement label and taint value. This root creates no pool or node."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.node_profile))
    error_message = "Select the existing protected native placement profile."
  }
}
