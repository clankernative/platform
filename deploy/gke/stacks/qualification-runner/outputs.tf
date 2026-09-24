output "enabled" {
  value = var.enabled
}

output "instance_name" {
  value = try(google_compute_instance.runner[0].name, null)
}

output "zone" {
  value = try(google_compute_instance.runner[0].zone, null)
}

output "service_account_email" {
  value = try(google_service_account.runner[0].email, null)
}

output "ssh_command" {
  description = "IAP-tunnelled SSH (no external IP, no public port 22)."
  value       = var.enabled ? "gcloud compute ssh ${var.name} --project=${var.project_id} --zone=${var.zone} --tunnel-through-iap" : null
}
