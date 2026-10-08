output "workload_identity_provider" {
  description = "Full provider name for google-github-actions/auth's workload_identity_provider."
  value       = google_iam_workload_identity_pool_provider.gitea.name
}

output "oidc_audience" {
  description = "Audience the provider accepts (its canonical URL, the auth action's default)."
  value       = local.oidc_audience
}

output "plan_service_account_email" {
  description = "Read-only identity for pull-request plans."
  value       = google_service_account.plan.email
}

output "apply_service_account_email" {
  description = "Identity for main-branch applies."
  value       = var.apply_service_account_email
}

output "runner_label" {
  description = "runs-on label of the runner."
  value       = var.runner_label
}

output "runner" {
  description = "Runner VM name and zone."
  value       = { name = google_compute_instance.runner.name, zone = google_compute_instance.runner.zone }
}
