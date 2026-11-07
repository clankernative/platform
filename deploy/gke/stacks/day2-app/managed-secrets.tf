# Operator-owned material delivery for the app-secret provider. Terraform knows
# only the namespace and an existing Kubernetes Secret name, never its bytes.
variable "managed_secrets" {
  description = "Opt-in app-secret namespace and existing operator-refreshed Kubernetes Secret. Key access-token is copied to a private regular file at pod start. Refresh the Secret and restart the exclusive workload before token expiry."
  type = object({
    project_number    = number
    token_secret_name = string
  })
  default = null

  validation {
    condition = var.managed_secrets == null ? true : try((
      var.managed_secrets.project_number > 0 &&
      var.managed_secrets.project_number <= 9007199254740991 &&
      floor(var.managed_secrets.project_number) == var.managed_secrets.project_number &&
      length(var.managed_secrets.token_secret_name) <= 63 &&
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", var.managed_secrets.token_secret_name))
    ), false)
    error_message = "managed_secrets requires an exact positive integer project number and a Kubernetes Secret DNS-label name of at most 63 characters. Supply no credential values."
  }
}

locals {
  managed_secret_dir    = "/run/day2-app-secrets"
  managed_secret_source = "/run/day2-app-secret-source"
  managed_secret_binding = var.managed_secrets == null ? {} : {
    managed_secrets = {
      project_number    = var.managed_secrets.project_number
      access_token_file = "${local.managed_secret_dir}/access-token"
    }
  }
}

resource "terraform_data" "managed_secret_admission" {
  count = var.managed_secrets == null ? 0 : 1
  lifecycle {
    precondition {
      condition = var.managed_secrets == null || (
        !var.rolling_deploys && !var.release_managed && var.native_enrollment_placement == null
      )
      error_message = "Managed-secret file injection currently requires an exclusive, directly managed StatefulSet. Rolling, release-managed and native-enrollment workloads need their own material-release qualification."
    }
  }
}
