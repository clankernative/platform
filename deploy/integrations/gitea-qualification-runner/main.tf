locals {
  iap_tcp_range       = "35.235.240.0/20"
  registration_secret = "projects/${var.project_id}/secrets/${var.registration_secret_id}/versions/latest"
  host_labels         = [for label in var.runner_labels : "${label}:host"]

  startup_script = join("\n", [
    # The host prerequisites and qualification report have one source of truth
    # in the core plain-VM startup script; this provider example composes it.
    file("${path.module}/../../gke/stacks/qualification-runner/startup.sh"),
    templatefile("${path.module}/startup.sh.tftpl", {
      gitea_url           = var.gitea_url
      repository          = var.repository
      registration_secret = local.registration_secret
      runner_name         = var.name
      runner_labels       = join(",", local.host_labels)
      runner_labels_yaml  = join("\n", [for label in local.host_labels : "    - \"${label}\""])
      runner_version      = var.act_runner_version
      runner_sha256       = var.act_runner_sha256
    }),
  ])
}

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

resource "google_service_account" "runner" {
  account_id   = var.name
  display_name = "Gitea qualification host runner"
  description  = "Dedicated identity for one repository-scoped Gitea host-executor qualification runner."
  project      = var.project_id
}

resource "google_secret_manager_secret_iam_member" "runner_registration" {
  project   = var.project_id
  secret_id = var.registration_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runner.email}"
}

resource "google_artifact_registry_repository_iam_member" "runner_push" {
  for_each = var.image_push_repository_ids

  project    = var.project_id
  location   = var.region
  repository = each.value
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.runner.email}"
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

resource "google_compute_instance" "runner" {
  name           = var.name
  project        = var.project_id
  zone           = var.zone
  machine_type   = var.machine_type
  desired_status = var.desired_status

  labels = {
    managed_by = "opentofu"
    component  = "gitea-qualification-runner"
    arch       = "x86_64"
  }

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = var.boot_disk_gb
      type  = "pd-balanced"
    }
  }

  # No access_config block: SSH is available only through IAP.
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
  zone          = var.zone
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

resource "google_project_iam_member" "operator_compute_viewer" {
  for_each = var.operator_members

  project = var.project_id
  role    = "roles/compute.viewer"
  member  = each.value
}
