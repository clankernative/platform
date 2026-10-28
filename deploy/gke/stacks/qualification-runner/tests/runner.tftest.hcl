# Offline: the google provider is mocked.
mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/example-project/serviceAccounts/day2-x86-qualify@example-project.iam.gserviceaccount.com"
      email = "day2-x86-qualify@example-project.iam.gserviceaccount.com"
    }
  }
}

variables {
  project_id = "example-project"
}

run "off_by_default" {
  command = plan

  assert {
    condition = (
      length(google_compute_instance.runner) == 0 &&
      length(google_compute_network.runner) == 0 &&
      length(google_compute_router_nat.runner) == 0 &&
      length(google_service_account.runner) == 0
    )
    error_message = "the runner and its network exist only when enabled"
  }
}

run "enabled_is_private_x86_and_iap_only" {
  command = plan

  variables {
    enabled = true
    operator_members = [
      "user:operator@example.com",
      "user:reviewer@example.com",
    ]
  }

  assert {
    condition = (
      google_compute_instance.runner[0].machine_type == "n2-standard-8" &&
      google_compute_instance.runner[0].boot_disk[0].initialize_params[0].image == "projects/debian-cloud/global/images/family/debian-13" &&
      length(google_compute_instance.runner[0].network_interface[0].access_config) == 0 &&
      google_compute_instance.runner[0].metadata["enable-oslogin"] == "TRUE" &&
      google_compute_instance.runner[0].metadata["block-project-ssh-keys"] == "TRUE"
    )
    error_message = "x86_64 Debian 13 VM with no external IP and OS Login only"
  }

  assert {
    condition = (
      google_compute_firewall.runner_iap_ssh[0].source_ranges == toset(["35.235.240.0/20"]) &&
      one(google_compute_firewall.runner_iap_ssh[0].allow).ports == tolist(["22"])
    )
    error_message = "SSH only from the IAP TCP forwarding range"
  }

  assert {
    condition     = length(google_artifact_registry_repository_iam_member.runner_push) == 0
    error_message = "no repository write access unless image_push_repository_id is set"
  }

  assert {
    condition = (
      toset(keys(google_iap_tunnel_instance_iam_member.operator_tunnel)) == toset(["user:operator@example.com", "user:reviewer@example.com"]) &&
      toset(keys(google_compute_instance_iam_member.operator_os_admin_login)) == toset(["user:operator@example.com", "user:reviewer@example.com"]) &&
      toset(keys(google_service_account_iam_member.operator_service_account_user)) == toset(["user:operator@example.com", "user:reviewer@example.com"]) &&
      toset(keys(google_project_iam_member.operator_compute_viewer)) == toset(["user:operator@example.com", "user:reviewer@example.com"])
    )
    error_message = "every operator IAM for_each entry must be planned independently"
  }
}

run "ci_runner_null_keeps_startup_and_iam_unchanged" {
  command = plan

  variables {
    enabled = true
    operator_members = [
      "user:operator@example.com",
      "user:reviewer@example.com",
    ]
    ci_runner = null
  }

  assert {
    condition = (
      length(google_secret_manager_secret_iam_member.ci_runner_registration) == 0 &&
      google_compute_instance.runner[0].metadata["startup-script"] == file("${path.module}/startup.sh")
    )
    error_message = "null ci_runner must preserve the exact existing startup script and create no secret IAM"
  }
}

run "ci_runner_reads_only_its_secret_and_renders_host_labels" {
  command = plan

  variables {
    enabled = true
    operator_members = [
      "user:operator@example.com",
      "user:reviewer@example.com",
    ]
    ci_runner = {
      gitea_url              = "https://git.example.com"
      repository             = "wonderly/app-go"
      registration_secret_id = "app-go-registration-token"
      labels                 = ["qualify-x86", "release-x86"]
      runner_version         = "0.2.11"
      runner_sha256          = "7a5e833793286bbfd9b59ce682bd41fc3f1c096bae1bb2a09b66ab2f6dacf90c"
    }
  }

  assert {
    condition = (
      length(google_secret_manager_secret_iam_member.ci_runner_registration) == 1 &&
      google_secret_manager_secret_iam_member.ci_runner_registration[0].project == "example-project" &&
      google_secret_manager_secret_iam_member.ci_runner_registration[0].secret_id == "app-go-registration-token" &&
      google_secret_manager_secret_iam_member.ci_runner_registration[0].role == "roles/secretmanager.secretAccessor" &&
      google_secret_manager_secret_iam_member.ci_runner_registration[0].member == "serviceAccount:day2-x86-qualify@example-project.iam.gserviceaccount.com"
    )
    error_message = "CI grants secret access to the VM service account on exactly the selected secret"
  }

  assert {
    condition = (
      strcontains(google_compute_instance.runner[0].metadata["startup-script"], "wonderly/app-go") &&
      strcontains(google_compute_instance.runner[0].metadata["startup-script"], "qualify-x86:host") &&
      strcontains(google_compute_instance.runner[0].metadata["startup-script"], "release-x86:host") &&
      strcontains(google_compute_instance.runner[0].metadata["startup-script"], "app-go-registration-token") &&
      !strcontains(google_compute_instance.runner[0].metadata["startup-script"], "registration-token-value-must-not-be-rendered")
    )
    error_message = "the startup script registers the selected repo and both host labels without embedding a token value"
  }
}

run "ci_runner_rejects_malformed_repository" {
  command = plan

  variables {
    enabled          = true
    operator_members = ["user:operator@example.com"]
    ci_runner = {
      gitea_url              = "https://git.example.com"
      repository             = "wonderly/app/go"
      registration_secret_id = "app-go-registration-token"
      labels                 = ["qualify-x86"]
      runner_version         = "0.2.11"
      runner_sha256          = "7a5e833793286bbfd9b59ce682bd41fc3f1c096bae1bb2a09b66ab2f6dacf90c"
    }
  }

  expect_failures = [var.ci_runner]
}

run "ci_runner_rejects_malformed_secret_id" {
  command = plan

  variables {
    enabled          = true
    operator_members = ["user:operator@example.com"]
    ci_runner = {
      gitea_url              = "https://git.example.com"
      repository             = "wonderly/app-go"
      registration_secret_id = "projects/example/secrets/token"
      labels                 = ["qualify-x86"]
      runner_version         = "0.2.11"
      runner_sha256          = "7a5e833793286bbfd9b59ce682bd41fc3f1c096bae1bb2a09b66ab2f6dacf90c"
    }
  }

  expect_failures = [var.ci_runner]
}

run "ci_runner_rejects_unpinned_runner" {
  command = plan

  variables {
    enabled          = true
    operator_members = ["user:operator@example.com"]
    ci_runner = {
      gitea_url              = "https://git.example.com"
      repository             = "wonderly/app-go"
      registration_secret_id = "app-go-registration-token"
      labels                 = ["qualify-x86"]
      runner_version         = "0.2.11"
      runner_sha256          = ""
    }
  }

  expect_failures = [var.ci_runner]
}

run "refuses_arm_machine_types" {
  command = plan

  variables {
    enabled          = true
    operator_members = ["user:operator@example.com"]
    machine_type     = "t2a-standard-8"
  }

  expect_failures = [var.machine_type]
}

run "requires_an_operator_when_enabled" {
  command = plan

  variables {
    enabled = true
  }

  expect_failures = [google_compute_instance.runner]
}
