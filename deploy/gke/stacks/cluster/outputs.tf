output "cluster_name" {
  value = google_container_cluster.primary.name
}

output "cluster_location" {
  value = google_container_cluster.primary.location
}

output "cluster_endpoint" {
  description = "Control-plane IP endpoint."
  value       = google_container_cluster.primary.endpoint
}

output "cluster_ca_certificate" {
  description = "Base64-encoded cluster CA certificate."
  value       = try(google_container_cluster.primary.master_auth[0].cluster_ca_certificate, "")
  sensitive   = true
}

output "cluster_workload_pool" {
  description = "Workload Identity pool of the cluster."
  value       = google_container_cluster.primary.workload_identity_config[0].workload_pool
}

output "network_name" {
  value = google_compute_network.gke.name
}

output "network_self_link" {
  value = google_compute_network.gke.self_link
}

# App edges build network policy from these ranges (API server and kube-dns
# Service IPs, node and pod sources) and name the cluster for Backup for GKE.
output "project_id" {
  value = var.project_id
}

output "cluster_resource_id" {
  value = google_container_cluster.primary.id
}

output "subnet_cidr" {
  value = var.subnet_cidr
}

output "pod_cidr" {
  value = var.pod_cidr
}

output "service_cidr" {
  value = var.service_cidr
}
