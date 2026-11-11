mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/example-project/serviceAccounts/instance-ci-plan@example-project.iam.gserviceaccount.com"
      email = "instance-ci-plan@example-project.iam.gserviceaccount.com"
    }
  }
}

variables {
  project_id                  = "example-project"
  project_number              = "123456789012"
  operator_members            = ["user:operator@example.com"]
  gitea_url                   = "https://git.example.com"
  oidc_issuer_uri             = "https://git-oidc.example.com"
  repository                  = "example-org/instance-config"
  repository_id               = "203"
  repository_owner_id         = "74"
  apply_service_account_email = "infra-apply@example-project.iam.gserviceaccount.com"
  state_bucket_name           = "example-project-tofu-state"
  plan_secret_ids             = ["cloudflare-api-token"]
}

run "identities_are_bound_to_the_repository_ids_and_one_workflow_each" {
  command = plan

  assert {
    condition = (
      strcontains(google_iam_workload_identity_pool_provider.gitea.attribute_condition, "assertion.repository_id == '203'") &&
      strcontains(google_iam_workload_identity_pool_provider.gitea.attribute_condition, "assertion.repository_owner_id == '74'") &&
      strcontains(google_iam_workload_identity_pool_provider.gitea.attribute_condition, "assertion.workflow_ref == 'example-org/instance-config/.gitea/workflows/apply.yml@refs/heads/main'") &&
      strcontains(google_iam_workload_identity_pool_provider.gitea.attribute_condition, "assertion.workflow_ref.startsWith('example-org/instance-config/.gitea/workflows/plan.yml@refs/pull/')")
    )
    error_message = "the provider must accept only the repository's native ids and the apply/plan workflows"
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.gitea.oidc[0].allowed_audiences == tolist(["https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/instance-ci/providers/gitea"])
    error_message = "the provider accepts exactly its own canonical audience"
  }

  assert {
    condition = (
      google_iam_workload_identity_pool_provider.gitea.oidc[0].issuer_uri == "https://git-oidc.example.com" &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "-e GITEA_INSTANCE_URL='https://git.example.com'")
    )
    error_message = "the provider and runner must use the explicitly supplied instance endpoints"
  }

  assert {
    condition = (
      google_service_account_iam_member.apply_workload_identity.member == "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/instance-ci/attribute.ci_role/apply" &&
      google_service_account_iam_member.apply_workload_identity.service_account_id == "projects/example-project/serviceAccounts/infra-apply@example-project.iam.gserviceaccount.com" &&
      google_service_account_iam_member.plan_workload_identity.member == "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/instance-ci/attribute.ci_role/plan"
    )
    error_message = "only ci_role=apply reaches the apply identity, and only ci_role=plan the plan identity"
  }

  assert {
    condition = (
      strcontains(google_iam_workload_identity_pool_provider.gitea.attribute_mapping["attribute.ci_role"], "'apply'") &&
      strcontains(google_iam_workload_identity_pool_provider.gitea.attribute_mapping["attribute.ci_role"], "'plan'") &&
      strcontains(google_iam_workload_identity_pool_provider.gitea.attribute_mapping["attribute.ci_role"], "'none'") &&
      !contains(keys(google_iam_workload_identity_pool_provider.gitea.attribute_mapping), "attribute.actor")
    )
    error_message = "ci_role maps to apply, plan or none, and no actor claim is mapped"
  }
}

run "plan_identity_is_read_only" {
  command = plan

  assert {
    condition = (
      toset(keys(google_project_iam_member.plan)) == toset(["roles/viewer", "roles/iam.securityReviewer", "roles/container.viewer", "roles/secretmanager.viewer"]) &&
      google_storage_bucket_iam_member.plan_state_reader.role == "roles/storage.objectViewer" &&
      toset(keys(google_secret_manager_secret_iam_member.plan_secret_reader)) == toset(["cloudflare-api-token"])
    )
    error_message = "the plan identity reads the project, the state and the named secrets, nothing more"
  }
}

run "plan_identity_refuses_write_roles" {
  command = plan

  variables {
    plan_project_roles = ["roles/viewer", "roles/editor"]
  }

  expect_failures = [var.plan_project_roles]
}

run "runner_is_private_and_jobs_are_isolated" {
  command = plan

  assert {
    condition = (
      length(google_compute_instance.runner.network_interface[0].access_config) == 0 &&
      google_compute_instance.runner.metadata["enable-oslogin"] == "TRUE" &&
      google_compute_firewall.runner_iap_ssh.source_ranges == toset(["35.235.240.0/20"])
    )
    error_message = "no external IP; SSH only through IAP with OS Login"
  }

  assert {
    condition = (
      strcontains(google_compute_instance.runner.metadata["startup-script"], "docker_host: \"-\"") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "privileged: false") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "valid_volumes: []") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "instance-ci:docker://docker.io/gitea/runner-images@sha256:") &&
      !strcontains(google_compute_instance.runner.metadata["startup-script"], "/var/run/docker.sock")
    )
    error_message = "jobs run in the pinned job image without the Docker socket, privileges or host volumes, and the host socket is never mounted"
  }

  assert {
    condition = (
      google_secret_manager_secret_iam_member.runner_registration.role == "roles/secretmanager.secretAccessor" &&
      google_project_iam_member.runner_log_writer.role == "roles/logging.logWriter"
    )
    error_message = "the VM's own identity reads its registration secret and writes logs"
  }
}

run "images_must_be_pinned" {
  command = plan

  variables {
    job_image = "docker.io/gitea/runner-images:latest"
  }

  expect_failures = [var.job_image]
}

run "public_images_add_no_registry_authority_or_prewarm_daemon" {
  command = plan

  assert {
    condition = (
      length(google_artifact_registry_repository_iam_member.runner_job_image) == 0 &&
      !strcontains(google_compute_instance.runner.metadata["startup-script"], "--name act_runner_prewarm")
    )
    error_message = "public-image startup must not add private registry access or a second daemon"
  }
}

run "private_job_image_has_only_its_repository_reader_and_inner_daemon_cache" {
  command = plan

  variables {
    job_image_repository_id = "ci"
    job_image               = "us-central1-docker.pkg.dev/example-project/ci/instance-job@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  assert {
    condition = (
      length(google_artifact_registry_repository_iam_member.runner_job_image) == 1 &&
      google_artifact_registry_repository_iam_member.runner_job_image[0].project == "example-project" &&
      google_artifact_registry_repository_iam_member.runner_job_image[0].location == "us-central1" &&
      google_artifact_registry_repository_iam_member.runner_job_image[0].repository == "ci" &&
      google_artifact_registry_repository_iam_member.runner_job_image[0].role == "roles/artifactregistry.reader" &&
      google_artifact_registry_repository_iam_member.runner_job_image[0].member == "serviceAccount:instance-ci-plan@example-project.iam.gserviceaccount.com"
    )
    error_message = "the VM may only read the selected repository; jobs retain their separate provisioning identities"
  }

  assert {
    condition = (
      strcontains(google_compute_instance.runner.metadata["startup-script"], "--name act_runner_prewarm") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "--tmpfs /root/.docker:rw,nosuid,nodev,noexec,mode=0700") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "docker image inspect 'us-central1-docker.pkg.dev/example-project/ci/instance-job@sha256:") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "--password-stdin 'us-central1-docker.pkg.dev'") &&
      !strcontains(google_compute_instance.runner.metadata["startup-script"], "-v /var/run/docker.sock") &&
      strcontains(google_compute_instance.runner.metadata["startup-script"], "docker_host: \"-\"")
    )
    error_message = "private image startup must warm the job daemon with ephemeral auth and keep sockets out of jobs"
  }
}

run "private_image_cannot_borrow_another_repositorys_reader" {
  command = plan

  variables {
    job_image_repository_id = "ci"
    job_image               = "us-central1-docker.pkg.dev/example-project/other/instance-job@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [google_compute_instance.runner]
}

run "private_image_cannot_borrow_another_projects_reader" {
  command = plan

  variables {
    job_image_repository_id = "ci"
    job_image               = "us-central1-docker.pkg.dev/another-project/ci/instance-job@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [google_compute_instance.runner]
}

run "private_image_cannot_borrow_another_regions_reader" {
  command = plan

  variables {
    job_image_repository_id = "ci"
    job_image               = "europe-west1-docker.pkg.dev/example-project/ci/instance-job@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [google_compute_instance.runner]
}

run "pinned_image_names_cannot_contain_shell_syntax" {
  command = plan

  variables {
    job_image               = "bad'image@sha256:1111111111111111111111111111111111111111111111111111111111111111"
    runner_controller_image = "bad'image@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.job_image, var.runner_controller_image]
}
