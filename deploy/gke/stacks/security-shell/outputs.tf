output "workload" {
  value = "${var.namespace}/${kubernetes_deployment_v1.shell.metadata[0].name}"
}

output "instance_sha256" {
  value = sha256(var.instance_json)
}
