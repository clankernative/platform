output "origin" {
  value = local.origin
}

output "reauth_callback_url" {
  value = "${local.origin}/_day2/reauth/callback"
}

output "iap_audience" {
  value = local.audience
}

output "contract" {
  description = "Pass this reference to day2-app.security_shell_contract."
  value = {
    namespace = var.namespace
    name      = kubernetes_config_map_v1.contract.metadata[0].name
  }
}
