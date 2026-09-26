# Offline: the google provider is mocked.
mock_provider "google" {}

variables {
  project_id        = "example-project"
  region            = "us-central1"
  state_bucket_name = "example-project-tofu-state"
  state_prefixes = {
    foundation = "foundation/"
    cluster    = "platform/cluster/"
    tenancy    = "platform/tenancy/"
    app        = "platform/app/"
    day2       = "day2/"
  }
  state_writer_members = ["serviceAccount:apply@example-project.iam.gserviceaccount.com"]
  state_reader_members = ["user:operator@example.com"]
}

run "state_bucket_is_private_versioned_and_kept" {
  command = plan

  assert {
    condition = (
      google_storage_bucket.opentofu_state.name == "example-project-tofu-state" &&
      google_storage_bucket.opentofu_state.location == "us-central1" &&
      google_storage_bucket.opentofu_state.storage_class == "STANDARD" &&
      google_storage_bucket.opentofu_state.uniform_bucket_level_access == true &&
      google_storage_bucket.opentofu_state.public_access_prevention == "enforced" &&
      google_storage_bucket.opentofu_state.force_destroy == false &&
      google_storage_bucket.opentofu_state.versioning[0].enabled == true
    )
    error_message = "state bucket: uniform access, public access prevented, versioned, never force-destroyed"
  }

  assert {
    condition = google_storage_bucket.opentofu_state.labels == tomap({
      managed_by  = "opentofu"
      stack       = "foundation"
      environment = "prod"
    })
    error_message = "state bucket labels match the live bucket"
  }

  assert {
    condition = toset([
      for config in google_project_iam_audit_config.storage.audit_log_config : config.log_type
    ]) == toset(["ADMIN_READ", "DATA_READ", "DATA_WRITE"])
    error_message = "storage audit logs cover admin reads and data reads and writes"
  }
}

run "enables_exactly_the_day2_apis" {
  command = plan

  assert {
    condition = toset(keys(google_project_service.api)) == toset([
      "artifactregistry.googleapis.com",
      "compute.googleapis.com",
      "container.googleapis.com",
      "gkebackup.googleapis.com",
      "iam.googleapis.com",
      "iamcredentials.googleapis.com",
      "iap.googleapis.com",
      "secretmanager.googleapis.com",
      "serviceusage.googleapis.com",
      "storage.googleapis.com",
      "sts.googleapis.com",
    ])
    error_message = "the API set is the one the day2 stacks use"
  }

  assert {
    condition     = alltrue([for api in google_project_service.api : api.disable_on_destroy == false])
    error_message = "no API is ever disabled by this root"
  }
}

run "state_access_is_per_prefix" {
  command = plan

  assert {
    condition = (
      toset(keys(google_storage_bucket_iam_binding.state_object_writers)) == toset(["foundation", "cluster", "tenancy", "app", "day2"]) &&
      toset(keys(google_storage_bucket_iam_binding.state_object_readers)) == toset(["foundation", "cluster", "tenancy", "app", "day2"])
    )
    error_message = "one reader and one writer binding per state prefix"
  }

  assert {
    condition = alltrue([
      for key, binding in google_storage_bucket_iam_binding.state_object_writers :
      binding.role == "roles/storage.objectAdmin" &&
      binding.members == toset(["serviceAccount:apply@example-project.iam.gserviceaccount.com"]) &&
      binding.condition[0].title == "write_${key}_state"
    ])
    error_message = "writers get object admin under their own condition"
  }

  assert {
    condition = alltrue([
      for key, binding in google_storage_bucket_iam_binding.state_object_readers :
      binding.role == "roles/storage.objectViewer" &&
      binding.members == toset(["user:operator@example.com"]) &&
      binding.condition[0].title == "read_${key}_state"
    ])
    error_message = "readers get object viewer only"
  }

  assert {
    condition = (
      google_storage_bucket_iam_binding.state_object_writers["cluster"].condition[0].expression ==
      "resource.name.startsWith('projects/_/buckets/example-project-tofu-state/objects/platform/cluster/')" &&
      google_storage_bucket_iam_binding.state_object_writers["cluster"].condition[0].description ==
      "CI-only write access to remote OpenTofu state objects under platform/cluster/" &&
      google_storage_bucket_iam_binding.state_object_readers["cluster"].condition[0].description ==
      "Read-only access to remote OpenTofu state objects under platform/cluster/"
    )
    error_message = "conditions keep the exact text the live bindings were created with"
  }
}

run "no_readers_means_no_reader_bindings" {
  command = plan

  variables {
    state_reader_members = []
  }

  assert {
    condition     = length(google_storage_bucket_iam_binding.state_object_readers) == 0
    error_message = "an empty reader list creates no empty-member bindings"
  }
}

run "shared_secrets_are_containers" {
  command = plan

  assert {
    condition = (
      google_secret_manager_secret.cloudflare_api_token.secret_id == "cloudflare-api-token" &&
      google_secret_manager_secret.app_secrets_bootstrap.secret_id == "app-secrets-bootstrap"
    )
    error_message = "shared secret ids other stacks and bootstrap look up"
  }
}

run "declares_only_project_layer_types" {
  command = plan

  module {
    source = "./tests/source-scan"
  }

  assert {
    condition = output.resource_types == toset([
      "google_project_iam_audit_config",
      "google_project_service",
      "google_secret_manager_secret",
      "google_secret_manager_secret_version",
      "google_storage_bucket",
      "google_storage_bucket_iam_binding",
    ])
    error_message = "the root declares only the project layer's resource types"
  }

  assert {
    condition = length(setintersection(output.resource_types, toset([
      "terraform_data",
      "google_project_iam_custom_role",
      "google_project_iam_member",
      "google_service_account",
      "google_service_account_iam_member",
      "google_service_account_iam_binding",
      "google_iam_workload_identity_pool_provider",
      "google_iam_deny_policy",
      "google_logging_project_sink",
      "google_apikeys_key",
      "google_storage_bucket_iam_member",
    ]))) == 0
    error_message = "no resource type from outside the project layer (CI federation, mirrors, FCM role, deny guardrail, log sink, Maps key, catalog bookkeeping)"
  }

  assert {
    condition     = length(output.data_sources) == 0 && length(output.modules) == 0
    error_message = "no data sources or child modules"
  }
}

run "refuses_prefix_without_trailing_slash" {
  command = plan

  variables {
    state_prefixes = { day2 = "day2" }
  }

  expect_failures = [var.state_prefixes]
}

run "refuses_malformed_member" {
  command = plan

  variables {
    state_writer_members = ["apply@example-project.iam.gserviceaccount.com"]
  }

  expect_failures = [var.state_writer_members]
}

run "refuses_no_writers" {
  command = plan

  variables {
    state_writer_members = []
  }

  expect_failures = [var.state_writer_members]
}
