variable "app_calls" {
  description = "Host bindings for the admitted same-instance peers. Signing material is mounted from exact Secret Manager versions; public serving selections are published by the release host."
  type = object({
    workload_key                = object({ id = string, secret_version = string })
    issuer_key                  = object({ issuer = string, id = string, secret_version = string })
    serving_snapshot_config_map = string
    serving                     = any
    outgoing                    = map(object({ issuer_url = string, receiver_url = string }))
    incoming                    = map(object({ workload_email = string, workload_keys = map(string), issuer = string, issuer_keys = map(string) }))
  })
  default = null
  validation {
    condition = var.app_calls == null ? true : (
      length(var.app_calls.outgoing) <= 32 && length(var.app_calls.incoming) <= 32 &&
      alltrue([for version in [var.app_calls.workload_key.secret_version, var.app_calls.issuer_key.secret_version] : can(regex("^projects/[0-9]+/secrets/[A-Za-z0-9_-]+/versions/[1-9][0-9]*$", version))])
    )
    error_message = "App calls require bounded explicit peers and exact numeric Secret Manager key versions."
  }
}

locals {
  app_call_dir = "${local.root_dir}/app-calls"
  app_call_keys = var.app_calls == null ? {} : {
    workload = var.app_calls.workload_key.secret_version
    issuer   = var.app_calls.issuer_key.secret_version
  }
  app_call_config = var.app_calls == null ? null : {
    version           = 1
    own               = { company = var.installation, environment = var.environment, app = var.app_id }
    serving_snapshot  = "${local.app_call_dir}/selection/serving.json"
    workload_email    = lookup(local.contract, "APP_CALL_WORKLOAD_EMAIL", "")
    workload_key      = { id = var.app_calls.workload_key.id, path = "${local.app_call_dir}/keys/workload" }
    issuer_key        = { issuer = var.app_calls.issuer_key.issuer, key = { id = var.app_calls.issuer_key.id, path = "${local.app_call_dir}/keys/issuer" } }
    issuer_audience   = lookup(local.contract, "APP_CALL_ISSUER_AUDIENCE", "")
    receiver_audience = lookup(local.contract, "APP_CALL_RECEIVER_AUDIENCE", "")
    serving           = var.app_calls.serving
    outgoing          = var.app_calls.outgoing
    incoming          = var.app_calls.incoming
  }
  app_call_annotations = {
    "day2.dev/installation" = var.installation
    "day2.dev/environment"  = var.environment
    "day2.dev/app"          = var.app_id
    "day2.dev/artifact"     = "sha256:${var.artifact_id}"
  }
}

resource "kubernetes_config_map_v1" "app_calls" {
  count = var.app_calls == null ? 0 : 1
  metadata {
    name      = "${local.workload_name}-app-calls"
    namespace = var.namespace
  }
  data = { "host.json" = jsonencode(local.app_call_config) }
  lifecycle {
    precondition {
      condition     = alltrue([for key in ["APP_CALL_ISSUER_AUDIENCE", "APP_CALL_RECEIVER_AUDIENCE"] : can(regex("^/projects/[0-9]+/global/backendServices/[0-9]+$", lookup(local.contract, key, "")))])
      error_message = "Resolve both independent app-call IAP backends before starting the host."
    }
    precondition {
      condition     = lookup(local.contract, "APP_CALL_ISSUER_AUDIENCE", "") != lookup(local.contract, "APP_CALL_RECEIVER_AUDIENCE", "") && lookup(local.contract, "APP_CALL_ISSUER_AUDIENCE", "") != local.iap_audience && lookup(local.contract, "APP_CALL_RECEIVER_AUDIENCE", "") != local.iap_audience
      error_message = "Human, issuer and receiver IAP backends must have distinct audiences."
    }
  }
}

resource "kubernetes_manifest" "app_call_keys" {
  count = var.app_calls == null ? 0 : 1
  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata   = { name = "${local.workload_name}-app-call-keys", namespace = var.namespace }
    spec = {
      provider   = "gke"
      parameters = { secrets = yamlencode([for key, version in local.app_call_keys : { resourceName = version, path = key }]) }
    }
  }
}
