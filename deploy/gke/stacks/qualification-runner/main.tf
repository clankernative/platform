# x86_64 day2 Linux qualification runner.
#
# `xtask qualify-linux` qualifies the architecture of the Docker engine it
# talks to and refuses emulation, and the day2 worker sandbox needs a real
# kernel's Landlock and seccomp. So this is a VM with a native Docker engine,
# not a pod. Off by default. No external IP: SSH only through IAP TCP
# forwarding, egress through Cloud NAT. Its own VPC, away from the cluster.
#
# Expects compute.googleapis.com and iap.googleapis.com enabled (the cluster
# stack enables both).

locals {
  count          = var.enabled ? 1 : 0
  operators      = var.enabled ? var.operator_members : toset([])
  iap_tcp_range  = "35.235.240.0/20"
  push_repo_id   = trimspace(var.image_push_repository_id)
  push_repo_iam  = var.enabled && local.push_repo_id != "" ? 1 : 0
  startup_script = file("${path.module}/startup.sh")
}

resource "google_compute_network" "runner" {
  count = local.count

  name                    = "${var.name}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "runner" {
  count = local.count

  name                     = "${var.name}-subnet"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.runner[0].id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
}

resource "google_compute_router" "runner" {
  count = local.count

  name    = "${var.name}-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.runner[0].id
}

# Qualification downloads Debian packages, the Docker engine, crates, the
# pinned Roc compiler (GitHub) and Docker Hub base images.
resource "google_compute_router_nat" "runner" {
  count = local.count

  name                               = "${var.name}-nat"
  project                            = var.project_id
  region                             = var.region
  router                             = google_compute_router.runner[0].name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.runner[0].id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Minimal identity: no project roles. Optional push access to one repository.
resource "google_service_account" "runner" {
  count = local.count

  account_id   = var.name
  display_name = "day2 x86_64 qualification runner"
  description  = "Identity of the off-by-default day2 Linux qualification VM. No project roles."
  project      = var.project_id
}

resource "google_artifact_registry_repository_iam_member" "runner_push" {
  count = local.push_repo_iam

  project    = var.project_id
  location   = var.region
  repository = local.push_repo_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.runner[0].email}"
}

# The only ingress: SSH from Google's IAP TCP forwarding range. The VPC's
# implied deny-all ingress covers everything else.
resource "google_compute_firewall" "runner_iap_ssh" {
  count = local.count

  name      = "${var.name}-iap-ssh"
  project   = var.project_id
  network   = google_compute_network.runner[0].name
  direction = "INGRESS"
  priority  = 1000

  source_ranges           = [local.iap_tcp_range]
  target_service_accounts = [google_service_account.runner[0].email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_instance" "runner" {
  count = local.count

  name           = var.name
  project        = var.project_id
  zone           = var.zone
  machine_type   = var.machine_type
  desired_status = var.desired_status

  labels = {
    managed_by = "opentofu"
    component  = "day2-qualification"
    arch       = "x86_64"
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
    subnetwork = google_compute_subnetwork.runner[0].self_link
  }

  service_account {
    email  = google_service_account.runner[0].email
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

  lifecycle {
    precondition {
      condition     = length(var.operator_members) > 0
      error_message = "operator_members must name at least one user or group when the qualification runner is enabled."
    }
  }

  depends_on = [
    google_compute_firewall.runner_iap_ssh,
    google_compute_router_nat.runner,
  ]
}

resource "google_iap_tunnel_instance_iam_member" "operator_tunnel" {
  for_each = local.operators

  project  = var.project_id
  zone     = google_compute_instance.runner[0].zone
  instance = google_compute_instance.runner[0].name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = each.value
}

# osAdminLogin (sudo) rather than osLogin: operators add themselves to the
# docker group, and qualification talks to the Docker socket.
resource "google_compute_instance_iam_member" "operator_os_admin_login" {
  for_each = local.operators

  project       = var.project_id
  zone          = google_compute_instance.runner[0].zone
  instance_name = google_compute_instance.runner[0].name
  role          = "roles/compute.osAdminLogin"
  member        = each.value
}

# OS Login to a VM with an attached service account requires actAs on it.
resource "google_service_account_iam_member" "operator_service_account_user" {
  for_each = local.operators

  service_account_id = google_service_account.runner[0].name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value
}

# `gcloud compute ssh` reads the instance before tunnelling.
resource "google_project_iam_member" "operator_compute_viewer" {
  for_each = local.operators

  project = var.project_id
  role    = "roles/compute.viewer"
  member  = each.value
}
