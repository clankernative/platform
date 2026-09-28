output "state_bucket_name" {
  description = "Bucket for every stack's gcs backend."
  value       = google_storage_bucket.opentofu_state.name
}

output "state_prefixes" {
  description = "State object prefixes with reader/writer bindings, by name."
  value       = var.state_prefixes
}

output "enabled_apis" {
  description = "APIs this root keeps enabled."
  value       = sort(tolist(local.apis))
}

output "shared_secret_ids" {
  description = "Secret Manager secret ids created here, by purpose."
  value = {
    cloudflare_api_token = google_secret_manager_secret.cloudflare_api_token.secret_id
  }
}
