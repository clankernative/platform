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
