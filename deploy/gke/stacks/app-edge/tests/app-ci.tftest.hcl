# App CI's results bucket. Offline: every provider is mocked and no backend
# service is selected, so this never contacts a cloud or a cluster.
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
  backend_service_name = ""
  iap_members          = ["domain:example.com", "user:owner@example.com"]
  deployer_subjects    = ["user:owner@example.com"]
  sqlite_storage_gb    = 5
  storage_class_name   = "app-sqlite-rwo"
  kube_dns_service_ip  = "10.30.0.10"
  cluster_cidrs        = ["10.20.0.0/16", "10.30.0.0/20", "10.10.0.0/20"]
}

# Without forge.oidc the renderer sets neither app CI variable.
run "app_ci_is_off_without_forge_oidc" {
  command = plan

  assert {
    condition = (
      length(google_storage_bucket.app_ci) == 0 &&
      length(google_storage_bucket_iam_member.app_ci_store) == 0 &&
      length(google_storage_bucket_iam_member.app_ci_reader) == 0 &&
      google_storage_bucket.backups.name == "example-tools-example-backups"
    )
    error_message = "without app_ci the edge creates no results bucket and grants nothing"
  }
}

run "results_bucket_is_private_and_short_lived" {
  command = plan

  variables {
    app_ci = {
      bucket = "example-tools-example-ci"
      reader = "serviceAccount:tools-infra@example-tools.iam.gserviceaccount.com"
    }
    app_ci_forge = {
      repository_id = "245"
    }
  }

  assert {
    condition = (
      google_storage_bucket.app_ci[0].name == "example-tools-example-ci" &&
      google_storage_bucket.app_ci[0].project == "example-tools" &&
      google_storage_bucket.app_ci[0].location == "us-central1" &&
      google_storage_bucket.app_ci[0].storage_class == "STANDARD" &&
      google_storage_bucket.app_ci[0].uniform_bucket_level_access == true &&
      google_storage_bucket.app_ci[0].public_access_prevention == "enforced" &&
      google_storage_bucket.app_ci[0].force_destroy == false &&
      google_storage_bucket.app_ci[0].versioning[0].enabled == false &&
      google_storage_bucket.app_ci[0].soft_delete_policy[0].retention_duration_seconds == 0 &&
      length(google_storage_bucket.app_ci[0].retention_policy) == 0 &&
      length(google_storage_bucket.app_ci[0].lifecycle_rule) == 1 &&
      one(google_storage_bucket.app_ci[0].lifecycle_rule[0].condition).age == 30 &&
      one(google_storage_bucket.app_ci[0].lifecycle_rule[0].action).type == "Delete" &&
      google_storage_bucket.app_ci[0].labels == tomap({
        app        = "example"
        managed_by = "opentofu"
        purpose    = "day2-ci"
      })
    )
    error_message = "the results bucket is <project>-<id>-ci in the instance region: uniform access, public access prevented, no versioning, no soft delete, every object deleted at 30 days, never force-destroyed"
  }

  assert {
    condition = (
      toset(keys(google_storage_bucket_iam_member.app_ci_store)) == toset(["roles/storage.objectCreator", "roles/storage.objectViewer"]) &&
      alltrue([for grant in google_storage_bucket_iam_member.app_ci_store :
        grant.bucket == "example-tools-example-ci" &&
        grant.member == "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/day2-ci/attribute.repository_id/245"
      ])
    )
    error_message = "only the app repository's principal set in the day2-ci pool creates and reads results"
  }

  assert {
    condition = (
      google_storage_bucket_iam_member.app_ci_reader[0].bucket == "example-tools-example-ci" &&
      google_storage_bucket_iam_member.app_ci_reader[0].role == "roles/storage.objectViewer" &&
      google_storage_bucket_iam_member.app_ci_reader[0].member == "serviceAccount:tools-infra@example-tools.iam.gserviceaccount.com"
    )
    error_message = "the apply identity, which builds candidates, only reads results"
  }
}

# prevent_destroy cannot be observed in a plan, so this reads the source.
run "results_bucket_keeps_prevent_destroy" {
  command = plan

  assert {
    condition     = strcontains(one([for block in split("\nresource ", file("${path.module}/app-ci.tf")) : block if startswith(block, "\"google_storage_bucket\" \"app_ci\"")]), "prevent_destroy = true")
    error_message = "the results bucket keeps prevent_destroy, so its global name is never released"
  }
}

run "refuses_a_bucket_name_the_spec_does_not_derive" {
  command = plan

  variables {
    app_ci = {
      bucket = "example-tools-other-ci"
      reader = "serviceAccount:tools-infra@example-tools.iam.gserviceaccount.com"
    }
    app_ci_forge = {
      repository_id = "245"
    }
  }

  expect_failures = [var.app_ci]
}

run "refuses_a_reader_other_than_the_apply_identity" {
  command = plan

  variables {
    app_ci = {
      bucket = "example-tools-example-ci"
      reader = "group:ci-readers@example.com"
    }
    app_ci_forge = {
      repository_id = "245"
    }
  }

  expect_failures = [var.app_ci]
}

run "refuses_app_ci_without_its_forge_id" {
  command = plan

  variables {
    app_ci = {
      bucket = "example-tools-example-ci"
      reader = "serviceAccount:tools-infra@example-tools.iam.gserviceaccount.com"
    }
  }

  expect_failures = [var.app_ci_forge]
}

run "refuses_a_forge_id_without_app_ci" {
  command = plan

  variables {
    app_ci_forge = {
      repository_id = "245"
    }
  }

  expect_failures = [var.app_ci_forge]
}

run "refuses_a_malformed_forge_id" {
  command = plan

  variables {
    app_ci = {
      bucket = "example-tools-example-ci"
      reader = "serviceAccount:tools-infra@example-tools.iam.gserviceaccount.com"
    }
    app_ci_forge = {
      repository_id = "repo:245"
    }
  }

  expect_failures = [var.app_ci_forge]
}
