# Project layer for a day2 GKE instance: the APIs the other stacks call, the
# bucket that holds every stack's state and who may read or write it, audit
# logging on that bucket, and the shared Secret Manager containers.
#
# Apply it first. The state bucket has to exist before any backend can
# initialise, including this root's, so an operator creates the bucket and the
# empty "foundation/" prefix by hand and this root adopts it (README,
# "Prepare the private project and identity").

locals {
  # APIs the day2 stacks use. Enabling an API is idempotent and the provider
  # refuses to disable one on destroy (disable_on_destroy = false), so
  # removing an entry here only stops managing it.
  apis = toset([
    # cluster: the day2 image repository.
    "artifactregistry.googleapis.com",
    # cluster, app-edge, qualification-runner, gitea-instance-ci: VPC, NAT,
    # load balancer, persistent disks, VMs.
    "compute.googleapis.com",
    # cluster: GKE.
    "container.googleapis.com",
    # cluster: the Backup for GKE agent add-on is enabled on the cluster.
    "gkebackup.googleapis.com",
    # Service accounts and IAM policy, in every stack.
    "iam.googleapis.com",
    # Workload identity federation: CI identities exchange OIDC tokens (sts)
    # and impersonate their service account (iamcredentials).
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    # app-edge: IAP in front of each app; runner VMs: IAP TCP forwarding.
    "iap.googleapis.com",
    # The shared secrets below, and the CI runner registration secret.
    "secretmanager.googleapis.com",
    # Service Usage itself, so this root can manage the others.
    "serviceusage.googleapis.com",
    # The state bucket.
    "storage.googleapis.com",
  ])

  state_object_path = "projects/_/buckets/${var.state_bucket_name}/objects/"
}

resource "google_project_service" "api" {
  for_each = local.apis

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# The bucket every stack's state lives in, this root's included.
# Versioning keeps every previous state generation, so a bad apply or a
# corrupted write can be rolled back by restoring a noncurrent object. The
# settings match the bucket as created by hand; anything left out here
# (soft-delete policy, hierarchical namespace) keeps the GCS default.
resource "google_storage_bucket" "opentofu_state" {
  name                        = var.state_bucket_name
  project                     = var.project_id
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  # "stack = foundation" names the state prefix this bucket was adopted
  # under; relabelling is harmless but shows up as an in-place update.
  labels = {
    managed_by  = "opentofu"
    stack       = "foundation"
    environment = "prod"
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.api]
}

# Who may touch which state objects.
#
# Each entry grants a role on the state bucket under an IAM condition that
# matches only objects whose name starts with that prefix, so one identity
# can be scoped to some stacks' state. A bucket IAM binding is authoritative
# for its (role, condition) pair: these members are the only holders of that
# role under that exact condition, and grants of the same role without the
# condition, or under another one, are left alone.
#
# The condition is evaluated against object names. Listing objects is
# authorised against the bucket itself, which never matches, so these
# bindings give get/create/delete on objects under the prefix and nothing
# at bucket level; any list access comes from elsewhere.
#
# The condition title and description are part of the binding's identity:
# rewording them replaces the binding (a remove-then-add window), so they
# keep the text they were created with.
#
# Readers: roles/storage.objectViewer, enough to read a stack's state (plan,
# output, terraform_remote_state) but not to write it or take its lock.
resource "google_storage_bucket_iam_binding" "state_object_readers" {
  for_each = length(var.state_reader_members) > 0 ? var.state_prefixes : {}

  bucket  = google_storage_bucket.opentofu_state.name
  role    = "roles/storage.objectViewer"
  members = sort(distinct(var.state_reader_members))

  condition {
    title       = "read_${each.key}_state"
    description = "Read-only access to remote OpenTofu state objects under ${each.value}"
    expression  = "resource.name.startsWith('${local.state_object_path}${each.value}')"
  }
}

# Writers: roles/storage.objectAdmin, which apply needs: the gcs backend
# creates and deletes a <prefix>/<workspace>.tflock object to hold the lock
# and overwrites <prefix>/<workspace>.tfstate.
resource "google_storage_bucket_iam_binding" "state_object_writers" {
  for_each = var.state_prefixes

  bucket  = google_storage_bucket.opentofu_state.name
  role    = "roles/storage.objectAdmin"
  members = sort(distinct(var.state_writer_members))

  condition {
    title       = "write_${each.key}_state"
    description = "CI-only write access to remote OpenTofu state objects under ${each.value}"
    expression  = "resource.name.startsWith('${local.state_object_path}${each.value}')"
  }
}

# State holds secrets (provider-generated passwords, keys, tokens). Data
# access logs record every read and write of it, and of any other object in
# the project, with the caller's identity.
resource "google_project_iam_audit_config" "storage" {
  project = var.project_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# Cloudflare API token for DNS. Only the container is managed here: an
# operator adds the token as a version outside OpenTofu, so the value never
# enters state. Bootstrap and the instance CI plan identity read it.
resource "google_secret_manager_secret" "cloudflare_api_token" {
  project   = var.project_id
  secret_id = "cloudflare-api-token"

  replication {
    auto {}
  }

  labels = {
    managed_by = "opentofu"
    stack      = "foundation"
    purpose    = "shared-api-token"
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.api["secretmanager.googleapis.com"]]
}

# Shared bootstrap secret. The app stack grants each app's runtime identity
# secretAccessor on it (live today for app "go") and mounts it into the app's
# secret volume, refusing to render without an enabled version. It stays
# until nothing grants or mounts it.
resource "google_secret_manager_secret" "app_secrets_bootstrap" {
  project   = var.project_id
  secret_id = "app-secrets-bootstrap"

  replication {
    auto {}
  }

  labels = {
    managed_by = "opentofu"
    stack      = "foundation"
    purpose    = "shared-bootstrap"
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.api["secretmanager.googleapis.com"]]
}

# The enabled version the app stack checks for. The payload is a fixed,
# non-secret marker; the secret exists so the mount is never empty. Changing
# the text adds a new version and destroys this one.
resource "google_secret_manager_secret_version" "app_secrets_bootstrap" {
  secret      = google_secret_manager_secret.app_secrets_bootstrap.id
  secret_data = "internal-tools app-secrets bootstrap"
}
