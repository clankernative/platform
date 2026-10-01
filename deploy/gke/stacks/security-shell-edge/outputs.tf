output "origin" {
  value = local.origin
}

output "service_account" {
  description = "Dedicated IAM signer; consuming app edges grant only this workload IAP access."
  value       = google_service_account.shell.email
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
