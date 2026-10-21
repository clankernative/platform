variable "project_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Select an explicit project ID."
  }
}

variable "project_number" {
  type = string
  validation {
    condition     = can(regex("^[1-9][0-9]{5,19}$", var.project_number))
    error_message = "Select the actual immutable project number."
  }
}

variable "authority_scope" {
  type = object({ installation = string, environment = string, app = string })
  validation {
    condition = (
      alltrue([for part in values(var.authority_scope) : can(regex("^[a-z][a-z0-9_-]{0,39}$", part))])
    )
    error_message = "Select bounded explicit scope names; these are selection DATA."
  }
}

variable "controller_namespace" {
  type = string
  validation {
    condition = (
      can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.controller_namespace)) &&
      var.controller_namespace != format("app-%s", replace(var.authority_scope.app, "_", "-"))
    )
    error_message = "The trusted controller must use an explicit separate namespace, already owned by its provisioner stack."
  }
}

variable "controller_service_account" {
  type = object({ email = string, unique_id = string })
  validation {
    condition = (
      endswith(var.controller_service_account.email, format("@%s.iam.gserviceaccount.com", var.project_id)) &&
      can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9][.]iam[.]gserviceaccount[.]com$", var.controller_service_account.email)) &&
      can(regex("^[1-9][0-9]{15,24}$", var.controller_service_account.unique_id))
    )
    error_message = "Select the existing same-project controller GSA and actual immutable UID."
  }
}

variable "app_reader" {
  type = object({
    email                      = string
    unique_id                  = string
    kubernetes_service_account = string
    workload_name              = string
  })
  validation {
    condition = (
      endswith(var.app_reader.email, format("@%s.iam.gserviceaccount.com", var.project_id)) &&
      can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9][.]iam[.]gserviceaccount[.]com$", var.app_reader.email)) &&
      can(regex("^[1-9][0-9]{15,24}$", var.app_reader.unique_id)) &&
      var.app_reader.email != var.controller_service_account.email &&
      var.app_reader.unique_id != var.controller_service_account.unique_id &&
      alltrue([for name in [var.app_reader.kubernetes_service_account, var.app_reader.workload_name] : can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", name))])
    )
    error_message = "Select a distinct existing app reader identity, KSA and single-replica StatefulSet."
  }
}

variable "storage" {
  type = object({
    zone                  = string
    disk_name             = string
    persistent_volume     = string
    claim_name            = string
    node_name             = string
    compute_instance_name = string
  })
  validation {
    condition = (
      alltrue([for name in [var.storage.zone, var.storage.disk_name, var.storage.compute_instance_name] :
        can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", name))
      ]) &&
      alltrue([for name in [var.storage.persistent_volume, var.storage.claim_name, var.storage.node_name] :
        can(regex("^[a-z0-9]([-a-z0-9]{0,251}[a-z0-9])?$", name))
      ])
    )
    error_message = "Supply exact selected storage/node names, without wildcard or path selectors."
  }
}

variable "kubeconfig_path" {
  type     = string
  default  = null
  nullable = true
}

variable "kube_context" {
  type     = string
  default  = null
  nullable = true
}
