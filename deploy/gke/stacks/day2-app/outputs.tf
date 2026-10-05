output "iap_audience" {
  description = "The IAP audience rendered into instance.json (from the platform contract unless overridden)."
  value       = local.iap_audience
}

output "instance_config_map" {
  description = "ConfigMap holding the rendered instance.json."
  value       = "${var.namespace}/${kubernetes_config_map_v1.instance.metadata[0].name}"
}

output "instance_sha256" {
  description = "sha256 of the rendered instance.json, also stamped on the pod template."
  value       = sha256(local.instance_json)
}

output "workload" {
  description = "The day2 StatefulSet."
  value       = "${var.namespace}/${kubernetes_stateful_set_v1.day2.metadata[0].name}"
}

output "backup_cron_job" {
  description = "The off-cluster backup CronJob."
  value       = "${var.namespace}/${kubernetes_cron_job_v1.backup.metadata[0].name}"
}
output "release_deployment" {
  description = "Public candidate metadata for day2-gke-release, rendered from this stack's selected inputs. Key references only; bootstrap and enable release_managed before executing."
  value = var.app_calls == null ? null : {
    serving            = try(var.app_calls.serving[var.app_id], null)
    image              = var.image
    instance           = local.instance
    secret_projection  = kubernetes_manifest.app_call_keys[0].manifest.metadata.name
    serving_config_map = var.app_calls.serving_snapshot_config_map
    secret_versions = [for reference in [var.app_calls.workload_key.secret_version, var.app_calls.issuer_key.secret_version] : {
      project_number = tonumber(split("/", reference)[1])
      secret         = split("/", reference)[3]
      version        = tonumber(split("/", reference)[5])
    }]
  }
}
