mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/example-project/serviceAccounts/day2-qualify-gitea@example-project.iam.gserviceaccount.com"
      email = "day2-qualify-gitea@example-project.iam.gserviceaccount.com"
    }
  }
}

variables {
  project_id = "example-project"
  operator_members = [
    "user:operator@example.com",
    "user:reviewer@example.com",
  ]
  gitea_url  = "https://git.example.com"
  repository = "wonderly/platform"
}

run "defaults_are_sapphire_rapids_debian_13_and_least_authority" {
  command = plan

  assert {
    condition = (
      google_compute_instance.runner.machine_type == "c3-standard-8" &&
      google_compute_instance.runner.boot_disk[0].initialize_params[0].image == "projects/debian-cloud/global/images/family/debian-13" &&
      google_compute_instance.runner.desired_status == "RUNNING" &&
      length(google_compute_instance.runner.network_interface[0].access_config) == 0 &&
      google_compute_instance.runner.metadata["enable-oslogin"] == "TRUE" &&
      google_compute_firewall.runner_iap_ssh.source_ranges == toset(["35.235.240.0/20"])
    )
    error_message = "the opt-in host is a private Debian 13 Sapphire Rapids C3 VM reachable through IAP only"
  }

  assert {
    condition = (
      google_secret_manager_secret_iam_member.runner_registration.project == "example-project" &&
      google_secret_manager_secret_iam_member.runner_registration.secret_id == "day2-qualification-runner-registration-token" &&
      google_secret_manager_secret_iam_member.runner_registration.role == "roles/secretmanager.secretAccessor" &&
      google_secret_manager_secret_iam_member.runner_registration.member == "serviceAccount:day2-qualify-gitea@example-project.iam.gserviceaccount.com" &&
      length(google_artifact_registry_repository_iam_member.runner_push) == 0
    )
    error_message = "the VM can read only the named registration secret and receives no image writer grant by default"
  }

  assert {
    condition = (
      strcontains(google_compute_instance.runner.metadata["startup-script"], "docker-buildx-plugin") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "ci_runner_version='0.2.11'") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "act_runner-$${ci_runner_version}-linux-amd64") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "7a5e833793286bbfd9b59ce682bd41fc3f1c096bae1bb2a09b66ab2f6dacf90c") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "wonderly/platform") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "qualification-x86:host") &&
      !strcontains(google_compute_instance.runner.metadata["startup-script"], "registration-token-value") &&
      !strcontains(google_compute_instance.runner.metadata["startup-script"], "register --token") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "register <\"$registration_input\"")
    )
    error_message = "the pinned host runner reuses the core qualification prerequisites and reads its token from temporary stdin, never argv or metadata"
  }

  assert {
    condition = (
      toset(keys(google_iap_tunnel_instance_iam_member.operator_tunnel)) == toset(["user:operator@example.com", "user:reviewer@example.com"]) &&
      toset(keys(google_compute_instance_iam_member.operator_os_admin_login)) == toset(["user:operator@example.com", "user:reviewer@example.com"]) &&
      toset(keys(google_service_account_iam_member.operator_service_account_user)) == toset(["user:operator@example.com", "user:reviewer@example.com"]) &&
      toset(keys(google_project_iam_member.operator_compute_viewer)) == toset(["user:operator@example.com", "user:reviewer@example.com"])
    )
    error_message = "both configured operators receive the complete IAP-only SSH permissions"
  }
}

run "two_labels_and_two_image_repositories_are_bound_independently" {
  command = plan

  variables {
    runner_labels = ["qualify-x86", "release-x86"]
    image_push_repository_ids = [
      "qualification-images",
      "release-images",
    ]
    registration_secret_id = "selected-gitea-runner-token"
  }

  assert {
    condition = (
      google_secret_manager_secret_iam_member.runner_registration.project == "example-project" &&
      google_secret_manager_secret_iam_member.runner_registration.secret_id == "selected-gitea-runner-token" &&
      google_secret_manager_secret_iam_member.runner_registration.role == "roles/secretmanager.secretAccessor" &&
      google_secret_manager_secret_iam_member.runner_registration.member == "serviceAccount:day2-qualify-gitea@example-project.iam.gserviceaccount.com"
    )
    error_message = "only the explicitly named secret grants registration-token access to the runner identity"
  }

  assert {
    condition = (
      toset(keys(google_artifact_registry_repository_iam_member.runner_push)) == toset(["qualification-images", "release-images"]) &&
      alltrue([for repository_id, grant in google_artifact_registry_repository_iam_member.runner_push : grant.repository == repository_id && grant.role == "roles/artifactregistry.writer" && grant.member == "serviceAccount:day2-qualify-gitea@example-project.iam.gserviceaccount.com"])
    )
    error_message = "each configured image repository gets its own writer grant and no other repository is selected"
  }

  assert {
    condition = (
      strcontains(google_compute_instance.runner.metadata["startup-script"], "- \"qualify-x86:host\"") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "- \"release-x86:host\"") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "qualify-x86:host,release-x86:host")
    )
    error_message = "both host-executor labels are rendered into act_runner config and registration"
  }
}

run "rejects_non_repository_scope" {
  command = plan

  variables {
    repository = "wonderly/platform/other"
  }

  expect_failures = [var.repository]
}

run "rejects_duplicate_or_empty_host_labels" {
  command = plan

  variables {
    runner_labels = ["qualify-x86", "qualify-x86"]
  }

  expect_failures = [var.runner_labels]
}

run "rejects_non_c3_machine_types" {
  command = plan

  variables {
    machine_type = "n2-standard-8"
  }

  expect_failures = [var.machine_type]
}

run "rejects_invalid_secret_ids_and_repository_ids" {
  command = plan

  variables {
    registration_secret_id    = "projects/example-project/secrets/token"
    image_push_repository_ids = ["Not_A_Valid_Repository"]
  }

  expect_failures = [var.registration_secret_id, var.image_push_repository_ids]
}
