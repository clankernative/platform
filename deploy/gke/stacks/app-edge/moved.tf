# Adoption of state written by the first-generation gke-cloudflare app stack,
# which declared all of this inside module.app[0]. Everything kept moves to
# the root unchanged.
#
# Objects that stack also created and this root intentionally drops have no
# configuration here, so a plan destroys them: the app-secrets
# SecretProviderClass and its Secret Manager grant (app-secrets-bootstrap), the
# app-owner-read-only and app-debug-access Roles and their binding, and the
# allow-egress-to-observability NetworkPolicy.

moved {
  from = module.app[0].kubernetes_namespace_v1.app
  to   = kubernetes_namespace_v1.app
}

moved {
  from = module.app[0].kubernetes_service_account_v1.runtime
  to   = kubernetes_service_account_v1.runtime
}

moved {
  from = module.app[0].kubernetes_persistent_volume_claim_v1.data
  to   = kubernetes_persistent_volume_claim_v1.data
}

moved {
  from = module.app[0].kubernetes_limit_range_v1.runtime_guardrails
  to   = kubernetes_limit_range_v1.runtime_guardrails
}

moved {
  from = module.app[0].kubernetes_resource_quota_v1.runtime_guardrails
  to   = kubernetes_resource_quota_v1.runtime_guardrails
}

moved {
  from = module.app[0].google_gke_backup_backup_plan.app
  to   = google_gke_backup_backup_plan.app
}

moved {
  from = module.app[0].google_artifact_registry_repository.app
  to   = google_artifact_registry_repository.app
}

moved {
  from = module.app[0].google_storage_bucket.state
  to   = google_storage_bucket.state
}

moved {
  from = module.app[0].google_storage_bucket_iam_member.deployer_state_bucket_object_admin
  to   = google_storage_bucket_iam_member.deployer_state_bucket_object_admin
}

moved {
  from = module.app[0].google_storage_bucket_iam_member.deployer_state_bucket_reader
  to   = google_storage_bucket_iam_member.deployer_state_bucket_reader
}

moved {
  from = module.app[0].kubernetes_role_v1.deployer
  to   = kubernetes_role_v1.deployer
}

moved {
  from = module.app[0].kubernetes_role_binding_v1.deployer
  to   = kubernetes_role_binding_v1.deployer
}

moved {
  from = module.app[0].kubernetes_service_v1.app
  to   = kubernetes_service_v1.app
}

moved {
  from = module.app[0].kubernetes_manifest.frontend_config
  to   = kubernetes_manifest.frontend_config
}

moved {
  from = module.app[0].kubernetes_manifest.backend_config
  to   = kubernetes_manifest.backend_config
}

moved {
  from = module.app[0].kubernetes_manifest.managed_certificate
  to   = kubernetes_manifest.managed_certificate
}

moved {
  from = module.app[0].google_compute_global_address.app
  to   = google_compute_global_address.app
}

moved {
  from = module.app[0].cloudflare_dns_record.app
  to   = cloudflare_dns_record.app
}

moved {
  from = module.app[0].kubernetes_ingress_v1.app
  to   = kubernetes_ingress_v1.app
}

moved {
  from = module.app[0].google_iap_web_backend_service_iam_binding.app_access
  to   = google_iap_web_backend_service_iam_binding.app_access
}

moved {
  from = module.app[0].kubernetes_config_map_v1.runtime_contract
  to   = kubernetes_config_map_v1.platform_contract
}

moved {
  from = module.app[0].kubernetes_network_policy_v1.deny_all_ingress
  to   = kubernetes_network_policy_v1.deny_all_ingress
}

moved {
  from = module.app[0].kubernetes_network_policy_v1.allow_ingress_from_load_balancer
  to   = kubernetes_network_policy_v1.allow_ingress_from_load_balancer
}

moved {
  from = module.app[0].kubernetes_network_policy_v1.deny_all_egress
  to   = kubernetes_network_policy_v1.deny_all_egress
}

moved {
  from = module.app[0].kubernetes_network_policy_v1.allow_egress_to_dns
  to   = kubernetes_network_policy_v1.allow_egress_to_dns
}

moved {
  from = module.app[0].kubernetes_network_policy_v1.allow_egress_to_workload_identity
  to   = kubernetes_network_policy_v1.allow_egress_to_workload_identity
}

moved {
  from = module.app[0].kubernetes_network_policy_v1.allow_public_internet_egress
  to   = kubernetes_network_policy_v1.allow_public_internet_egress
}

# Bookkeeping of the old stack (a one-time guardrail migration hook that also
# sequenced its backend lookup script). It owns no cloud object; forget it.
removed {
  from = module.app.terraform_data.cleanup_emergency_runtime_guardrails

  lifecycle {
    destroy = false
  }
}
