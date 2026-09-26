# Offline: every provider is mocked and the backend service is overridden per
# run, so this never contacts a cloud or a cluster.
mock_provider "google" {}
mock_provider "kubernetes" {}
mock_provider "cloudflare" {}

variables {
  project_id           = "example-tools"
  project_number       = "123456789012"
  cluster_name         = "day2"
  cluster_location     = "us-central1-a"
  app_id               = "example"
  domain               = "example.apps.example.com"
  cloudflare_zone_id   = "0123456789abcdef0123456789abcdef"
  backend_service_name = "k8s1-0000000-app-example-app-8080-00000000"
  iap_members          = ["domain:example.com", "user:owner@example.com"]
  deployer_subjects    = ["user:owner@example.com"]
  sqlite_storage_gb    = 5
  storage_class_name   = "app-sqlite-rwo"
  kube_dns_service_ip  = "10.30.0.10"
  cluster_cidrs        = ["10.20.0.0/16", "10.30.0.0/20", "10.10.0.0/20"]
}

run "publishes_the_contract_day2_app_reads" {
  command = plan

  # A real 19-digit backend ID: the audience must render it exactly.
  override_data {
    target = data.google_compute_backend_service.app
    values = {
      generated_id = 5486495053471409653
      description  = "{\"kubernetes.io/service-name\":\"app-example\\/app\",\"kubernetes.io/service-port\":\"http\",\"x-features\":[\"NEG\"]}"
      iap          = [{ enabled = true, oauth2_client_id = "", oauth2_client_secret = "", oauth2_client_secret_sha256 = "" }]
    }
  }

  assert {
    condition = kubernetes_config_map_v1.platform_contract.data == tomap({
      APP_DOMAIN                   = "example.apps.example.com"
      APP_NAMESPACE                = "app-example"
      IAP_JWT_AUDIENCE             = "/projects/123456789012/global/backendServices/5486495053471409653"
      O11Y_SERVICE_LABEL_KEY       = "o11y.wonderly.info/service"
      O11Y_SERVICE_LABEL_VALUE     = "example-api"
      PVC_NAME                     = "data"
      REQUIRED_SERVICE_LABEL_KEY   = "internal-tools.wonderly.io/service"
      REQUIRED_SERVICE_LABEL_VALUE = "app"
      SERVICE_NAME                 = "app"
    })
    error_message = "The contract must hold exactly the keys day2-app reads (plus APP_NAMESPACE), with the backend's numeric ID in the audience."
  }

  assert {
    condition = (
      kubernetes_config_map_v1.platform_contract.metadata[0].name == "platform-contract" &&
      kubernetes_persistent_volume_claim_v1.data.metadata[0].name == kubernetes_config_map_v1.platform_contract.data["PVC_NAME"] &&
      kubernetes_service_v1.app.metadata[0].name == kubernetes_config_map_v1.platform_contract.data["SERVICE_NAME"] &&
      kubernetes_service_v1.app.spec[0].selector == tomap({ "internal-tools.wonderly.io/service" = "app" }) &&
      kubernetes_service_v1.app.metadata[0].labels["o11y.wonderly.info/service"] == "example-api"
    )
    error_message = "The contract must describe the PVC, Service and selector label this root creates."
  }

  assert {
    condition = (
      length(google_iap_web_backend_service_iam_binding.app_access) == 1 &&
      google_iap_web_backend_service_iam_binding.app_access[0].web_backend_service == "k8s1-0000000-app-example-app-8080-00000000" &&
      google_iap_web_backend_service_iam_binding.app_access[0].role == "roles/iap.httpsResourceAccessor" &&
      toset(google_iap_web_backend_service_iam_binding.app_access[0].members) == toset(["domain:example.com", "user:owner@example.com"])
    )
    error_message = "IAP access must be one authoritative httpsResourceAccessor binding on the app's backend service."
  }

  assert {
    condition = (
      kubernetes_manifest.backend_config.manifest.spec.iap.enabled &&
      kubernetes_manifest.backend_config.manifest.spec.healthCheck.requestPath == "/health/ready" &&
      kubernetes_manifest.frontend_config.manifest.spec.redirectToHttps.enabled &&
      kubernetes_manifest.managed_certificate.manifest.spec.domains == ["example.apps.example.com"] &&
      kubernetes_ingress_v1.app.metadata[0].annotations["networking.gke.io/managed-certificates"] == "managed-cert-example-apps-example-com" &&
      kubernetes_manifest.managed_certificate.manifest.metadata.name == "managed-cert-example-apps-example-com" &&
      kubernetes_ingress_v1.app.metadata[0].annotations["kubernetes.io/ingress.global-static-ip-name"] == "example-ip" &&
      kubernetes_ingress_v1.app.spec[0].rule[0].host == "example.apps.example.com"
    )
    error_message = "The edge must be IAP-protected, HTTPS-only and health-checked on /health/ready."
  }

  assert {
    condition = (
      kubernetes_network_policy_v1.allow_ingress_from_load_balancer.spec[0].pod_selector[0].match_labels == tomap({ "internal-tools.wonderly.io/service" = "app" }) &&
      tolist([for from in kubernetes_network_policy_v1.allow_ingress_from_load_balancer.spec[0].ingress[0].from : from.ip_block[0].cidr]) == tolist(["35.191.0.0/16", "130.211.0.0/22"]) &&
      kubernetes_network_policy_v1.allow_ingress_from_load_balancer.spec[0].ingress[0].ports[0].port == "8080" &&
      kubernetes_network_policy_v1.allow_public_internet_egress.spec[0].egress[0].to[0].ip_block[0].except == tolist(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "10.20.0.0/16", "10.30.0.0/20", "10.10.0.0/20"])
    )
    error_message = "Only the Google load balancer may reach port 8080; public egress must exclude private, link-local and cluster ranges."
  }

  assert {
    condition = (
      google_gke_backup_backup_plan.app.cluster == "projects/example-tools/locations/us-central1-a/clusters/day2" &&
      google_gke_backup_backup_plan.app.backup_config[0].selected_namespaces[0].namespaces == tolist(["app-example"]) &&
      google_gke_backup_backup_plan.app.backup_config[0].include_volume_data &&
      google_storage_bucket.state.name == "example-tools-example-state" &&
      !google_storage_bucket.state.force_destroy &&
      length(kubernetes_role_binding_v1.deployer) == 1 &&
      length(google_artifact_registry_repository_iam_member.deployer_writer) == 0
    )
    error_message = "Backup, state bucket and deployer access must target this app only."
  }
}

run "bootstrap_publishes_no_audience_and_grants_nothing" {
  command = plan

  variables {
    backend_service_name = ""
  }

  assert {
    condition     = kubernetes_config_map_v1.platform_contract.data["IAP_JWT_AUDIENCE"] == "" && length(google_iap_web_backend_service_iam_binding.app_access) == 0
    error_message = "Before the backend is known, the contract must not invent an audience and no IAP grant may exist."
  }
}

run "refuses_a_backend_of_another_service" {
  command = plan

  override_data {
    target = data.google_compute_backend_service.app
    values = {
      generated_id = 42
      description  = "{\"kubernetes.io/service-name\":\"app-other\\/app\"}"
      iap          = [{ enabled = true, oauth2_client_id = "", oauth2_client_secret = "", oauth2_client_secret_sha256 = "" }]
    }
  }

  expect_failures = [google_iap_web_backend_service_iam_binding.app_access]
}

run "refuses_a_backend_without_iap" {
  command = plan

  override_data {
    target = data.google_compute_backend_service.app
    values = {
      generated_id = 42
      description  = "{\"kubernetes.io/service-name\":\"app-example\\/app\"}"
      iap          = [{ enabled = false, oauth2_client_id = "", oauth2_client_secret = "", oauth2_client_secret_sha256 = "" }]
    }
  }

  expect_failures = [google_iap_web_backend_service_iam_binding.app_access]
}

run "refuses_public_iap_access" {
  command = plan

  variables {
    iap_members = ["allUsers"]
  }

  expect_failures = [var.iap_members]
}

run "offsite_backups_are_write_only_and_retained" {
  command = plan

  variables {
    backend_service_name = ""
  }

  assert {
    condition = (
      google_storage_bucket.backups.name == "example-tools-example-backups" &&
      output.backup_bucket == "example-tools-example-backups" &&
      google_storage_bucket.backups.uniform_bucket_level_access &&
      google_storage_bucket.backups.public_access_prevention == "enforced" &&
      !google_storage_bucket.backups.force_destroy &&
      google_storage_bucket.backups.retention_policy[0].retention_period == 2592000 &&
      !google_storage_bucket.backups.retention_policy[0].is_locked &&
      length(google_storage_bucket.backups.lifecycle_rule) == 1 &&
      one(google_storage_bucket.backups.lifecycle_rule[0].condition).age == 31 &&
      one(google_storage_bucket.backups.lifecycle_rule[0].action).type == "Delete"
    )
    error_message = "The backup bucket must be private, keep backups 30 days under an unlocked retention policy and delete them at 31 days."
  }

  assert {
    condition = (
      google_service_account.backup.account_id == "example-backup" &&
      google_storage_bucket_iam_member.backup_object_creator.bucket == "example-tools-example-backups" &&
      google_storage_bucket_iam_member.backup_object_creator.role == "roles/storage.objectCreator" &&
      google_storage_bucket_iam_member.backup_object_creator.member == "serviceAccount:example-backup@example-tools.iam.gserviceaccount.com" &&
      output.backup_service_account == "example-backup@example-tools.iam.gserviceaccount.com" &&
      length(google_storage_bucket_iam_member.backup_readers) == 0
    )
    error_message = "The backup service account may only create objects in the backup bucket; nobody reads backups unless listed."
  }

  assert {
    condition = (
      google_service_account_iam_member.backup_workload_identity.role == "roles/iam.workloadIdentityUser" &&
      google_service_account_iam_member.backup_workload_identity.member == "serviceAccount:example-tools.svc.id.goog[app-example/backup]" &&
      kubernetes_service_account_v1.backup.metadata[0].name == "backup" &&
      kubernetes_service_account_v1.backup.metadata[0].namespace == "app-example" &&
      google_service_account_iam_member.backup_workload_identity.service_account_id == "projects/example-tools/serviceAccounts/example-backup@example-tools.iam.gserviceaccount.com" &&
      kubernetes_service_account_v1.backup.metadata[0].annotations["iam.gke.io/gcp-service-account"] == "example-backup@example-tools.iam.gserviceaccount.com" &&
      kubernetes_service_account_v1.backup.automount_service_account_token == false
    )
    error_message = "Only the app namespace's backup Kubernetes service account may act as the uploader, and it mounts no token."
  }
}

run "offsite_backup_retention_and_readers_are_configurable" {
  command = plan

  variables {
    backend_service_name          = ""
    offsite_backup_retention_days = 7
    offsite_backup_readers        = ["group:day2-restore@example.com"]
  }

  assert {
    condition = (
      google_storage_bucket.backups.retention_policy[0].retention_period == 604800 &&
      one(google_storage_bucket.backups.lifecycle_rule[0].condition).age == 8 &&
      google_storage_bucket_iam_member.backup_readers["group:day2-restore@example.com"].role == "roles/storage.objectViewer"
    )
    error_message = "Retention days drive both the retention policy and the lifecycle deletion; readers get objectViewer only."
  }
}

run "refuses_unbounded_backup_retention" {
  command = plan

  variables {
    backend_service_name          = ""
    offsite_backup_retention_days = 0
  }

  expect_failures = [var.offsite_backup_retention_days]
}

run "refuses_a_backup_account_id_gcp_cannot_create" {
  command = plan

  variables {
    backend_service_name = ""
    app_id               = "a-very-long-application-name"
  }

  expect_failures = [google_service_account.backup]
}

# prevent_destroy cannot be observed in a plan, so these read the source.
run "retained_objects_keep_prevent_destroy" {
  command = plan

  variables {
    backend_service_name = ""
  }

  assert {
    condition = alltrue([
      for header in [
        "\"kubernetes_namespace_v1\" \"app\"",
        "\"kubernetes_persistent_volume_claim_v1\" \"data\"",
        "\"google_storage_bucket\" \"state\"",
        "\"google_gke_backup_backup_plan\" \"app\"",
        "\"google_artifact_registry_repository\" \"app\"",
        "\"google_storage_bucket\" \"backups\"",
      ] :
      strcontains(one([for block in split("\nresource ", file("${path.module}/main.tf")) : block if startswith(block, header)]), "prevent_destroy = true")
    ])
    error_message = "The namespace, data PVC, state bucket, backup plan, image repository and backup bucket must keep prevent_destroy = true."
  }
}

run "no_first_generation_platform_resources" {
  command = plan

  variables {
    backend_service_name = ""
  }

  assert {
    condition = alltrue([
      for forbidden in [
        "data \"external\"",
        "terraform_data",
        "terraform_remote_state",
        "local-exec",
        "google_secret_manager",
        "SecretProviderClass\"",
        "app-owner-read-only",
        "app-debug-access",
        "allow-egress-to-observability",
        "control_plane",
        "app-it",
      ] :
      !strcontains(join("\n", [for name in fileset(path.module, "*.tf") : file("${path.module}/${name}") if name != "moved.tf"]), forbidden)
    ])
    error_message = "This root must not declare the first-generation platform's secret projection, owner/debug RBAC, observability wiring, control-plane grants or script hooks."
  }
}
