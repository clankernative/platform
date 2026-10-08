# Optional Gitea Actions CI example for one private instance configuration
# repository. Not a core GKE runtime root or an installation prerequisite.
#
# Pull requests plan every stack with a read-only identity; runs on the main
# branch apply with the instance's apply identity. Both identities come from
# workflow OIDC tokens through workload identity federation, bound to the
# repository's native Gitea ids and to one workflow file each. No key exists.
#
# The runner is a dedicated VM registered only to that repository. Its
# controller runs its own Docker daemon in a privileged Docker-in-Docker
# container; jobs run in fresh, unprivileged containers without its socket.
# This is configuration, not a hostile-code containment qualification. The
# VM's own service account can read the runner registration secret and write
# logs; job provisioning identities are selected separately.
#
# Expects compute, iap, iam, iamcredentials, sts and secretmanager enabled,
# the workload identity pool to exist, and the registration secret to exist
# (bootstrap creates both).

locals {
  iap_tcp_range = "35.235.240.0/20"
  pool_name     = "projects/${var.project_number}/locations/global/workloadIdentityPools/${var.workload_identity_pool_id}"
  # The provider's canonical audience: what google-github-actions/auth asks
  # for by default, and the form git-oidc issues tokens for.
  oidc_audience = "https://iam.googleapis.com/${local.pool_name}/providers/${var.workload_identity_provider_id}"

  # Each workflow ref is "<owner>/<repo>/<path>@<ref>".
  apply_workflow_ref  = "${var.repository}/${var.apply_workflow_path}@refs/heads/main"
  plan_workflow_start = "${var.repository}/${var.plan_workflow_path}@refs/pull/"

  apply_expression = join(" && ", [
    "assertion.event_name in ['push', 'workflow_dispatch']",
    "assertion.ref == 'refs/heads/main'",
    "assertion.workflow_ref == '${local.apply_workflow_ref}'",
  ])
  plan_expression = join(" && ", [
    "assertion.event_name == 'pull_request'",
    "assertion.ref.matches('^refs/pull/[1-9][0-9]*/head$')",
    "assertion.workflow_ref.startsWith('${local.plan_workflow_start}')",
  ])

  startup_script = templatefile("${path.module}/startup.sh.tftpl", {
    gitea_url           = var.gitea_url
    runner_name         = var.name
    runner_label        = var.runner_label
    job_image           = var.job_image
    controller_image    = var.runner_controller_image
    registration_secret = "projects/${var.project_id}/secrets/${var.runner_registration_secret_id}/versions/latest"
  })
}

# --- network: own VPC, no external IP, egress through Cloud NAT ------------

resource "google_compute_network" "runner" {
  name                    = "${var.name}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "runner" {
  name                     = "${var.name}-subnet"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.runner.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
}

resource "google_compute_router" "runner" {
  name    = "${var.name}-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.runner.id
}

# Jobs reach Gitea, GitHub (the pinned platform sources), the OpenTofu
# registry and the GKE control plane's public endpoint.
resource "google_compute_router_nat" "runner" {
  name                               = "${var.name}-nat"
  project                            = var.project_id
  region                             = var.region
  router                             = google_compute_router.runner.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.runner.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_firewall" "runner_iap_ssh" {
  name      = "${var.name}-iap-ssh"
  project   = var.project_id
  network   = google_compute_network.runner.name
  direction = "INGRESS"
  priority  = 1000

  source_ranges           = [local.iap_tcp_range]
  target_service_accounts = [google_service_account.runner.email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# --- runner VM --------------------------------------------------------------

resource "google_service_account" "runner" {
  account_id   = var.name
  display_name = "Gitea instance CI runner"
  description  = "Identity of the instance CI runner VM itself: reads its registration secret and writes logs. Jobs authenticate separately through workload identity."
  project      = var.project_id
}

resource "google_secret_manager_secret_iam_member" "runner_registration" {
  project   = var.project_id
  secret_id = var.runner_registration_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runner.email}"
}

resource "google_project_iam_member" "runner_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runner.email}"
}

resource "google_compute_instance" "runner" {
  name           = var.name
  project        = var.project_id
  zone           = var.zone
  machine_type   = var.machine_type
  desired_status = var.desired_status

  labels = {
    managed_by = "opentofu"
    component  = "gitea-instance-ci"
  }

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = var.boot_disk_gb
      type  = "pd-balanced"
    }
  }

  # No access_config block: no external IP.
  network_interface {
    subnetwork = google_compute_subnetwork.runner.self_link
  }

  service_account {
    email  = google_service_account.runner.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    block-project-ssh-keys   = "TRUE"
    enable-oslogin           = "TRUE"
    serial-port-enable       = "FALSE"
    disable-legacy-endpoints = "TRUE"
    startup-script           = local.startup_script
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  depends_on = [
    google_compute_firewall.runner_iap_ssh,
    google_compute_router_nat.runner,
    google_secret_manager_secret_iam_member.runner_registration,
  ]
}

resource "google_iap_tunnel_instance_iam_member" "operator_tunnel" {
  for_each = var.operator_members

  project  = var.project_id
  zone     = google_compute_instance.runner.zone
  instance = google_compute_instance.runner.name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = each.value
}

resource "google_compute_instance_iam_member" "operator_os_admin_login" {
  for_each = var.operator_members

  project       = var.project_id
  zone          = google_compute_instance.runner.zone
  instance_name = google_compute_instance.runner.name
  role          = "roles/compute.osAdminLogin"
  member        = each.value
}

resource "google_service_account_iam_member" "operator_service_account_user" {
  for_each = var.operator_members

  service_account_id = google_service_account.runner.name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value
}

# --- workflow identity ------------------------------------------------------

# One provider for both roles. The token's repository is trusted only by its
# native ids, and the role is derived from event, ref and workflow file:
# anything that is neither the main-branch apply workflow nor a pull request's
# plan workflow maps to "none" and is refused outright.
resource "google_iam_workload_identity_pool_provider" "gitea" {
  project                            = var.project_id
  workload_identity_pool_id          = var.workload_identity_pool_id
  workload_identity_pool_provider_id = var.workload_identity_provider_id
  display_name                       = "Gitea instance CI"
  description                        = "Workflow tokens from ${var.repository} (id ${var.repository_id}) through ${var.oidc_issuer_uri}."

  # The issuer carries no actor claim; mapping one would refuse valid tokens.
  attribute_mapping = {
    "google.subject"                = "'gitea:' + assertion.sub"
    "attribute.repository_id"       = "assertion.repository_id"
    "attribute.repository_owner_id" = "assertion.repository_owner_id"
    "attribute.event_name"          = "assertion.event_name"
    "attribute.ref"                 = "assertion.ref"
    "attribute.workflow_ref"        = "assertion.workflow_ref"
    "attribute.ci_role"             = "(${local.apply_expression}) ? 'apply' : ((${local.plan_expression}) ? 'plan' : 'none')"
  }

  attribute_condition = join(" && ", [
    "assertion.repository_id == '${var.repository_id}'",
    "assertion.repository_owner_id == '${var.repository_owner_id}'",
    "assertion.repository == '${var.repository}'",
    "((${local.apply_expression}) || (${local.plan_expression}))",
  ])

  oidc {
    issuer_uri        = var.oidc_issuer_uri
    allowed_audiences = [local.oidc_audience]
  }
}

resource "google_service_account_iam_member" "apply_workload_identity" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.apply_service_account_email}"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.pool_name}/attribute.ci_role/apply"
}

resource "google_service_account" "plan" {
  account_id   = var.plan_service_account_id
  display_name = "Instance CI plan (read-only)"
  description  = "Pull-request plans of ${var.repository}. Read-only: refreshes every stack, changes nothing."
  project      = var.project_id
}

resource "google_service_account_iam_member" "plan_workload_identity" {
  service_account_id = google_service_account.plan.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.pool_name}/attribute.ci_role/plan"
}

resource "google_project_iam_member" "plan" {
  for_each = var.plan_project_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.plan.email}"
}

# roles/viewer does not read objects: plans download the remote state.
resource "google_storage_bucket_iam_member" "plan_state_reader" {
  bucket = var.state_bucket_name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.plan.email}"
}

resource "google_secret_manager_secret_iam_member" "plan_secret_reader" {
  for_each = var.plan_secret_ids

  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.plan.email}"
}
