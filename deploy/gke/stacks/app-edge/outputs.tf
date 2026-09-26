output "namespace" {
  description = "The app namespace (day2-app's namespace)."
  value       = kubernetes_namespace_v1.app.metadata[0].name
}

output "app_domain" {
  description = "The app's host name (the contract's APP_DOMAIN); day2-app's edge_origin is https:// plus this."
  value       = var.domain
}

output "static_ip_address" {
  description = "Global static IP the Ingress and the DNS record use."
  value       = google_compute_global_address.app.address
}

output "iap_audience" {
  description = "The contract's IAP_JWT_AUDIENCE. Empty until backend_service_name is set."
  value       = local.iap_jwt_audience
}

output "artifact_registry_repository" {
  description = "Docker repository for the app image."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.app.repository_id}"
}

output "state_bucket" {
  description = "Bucket for the app's day2-app OpenTofu state."
  value       = google_storage_bucket.state.name
}
