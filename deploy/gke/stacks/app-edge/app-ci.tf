# App CI's results (docs/INSTANCE.md, "App CI"): the bucket the required org
# workflow's store step writes this app's checked artifact and receipt to, for
# each push to main of the app's repository.
#
# Only runs of the app's own repository, federated through the instance's
# day2-ci pool (project root), may create and read objects here; the apply
# identity reads them when it builds candidates. Nothing else is granted here.
# Uploads are write-once and no grant here overwrites or deletes an object;
# lifecycle deletes each one 30 days after it was written. No versioning and no
# soft delete keep a deleted object.
#
# Without forge.oidc, app_ci is null and nothing here exists. Once the bucket
# exists it keeps prevent_destroy: its global name must never be released for
# another project to take while a build may still read it.

locals {
  # The project root's derived pool, day2-ci; one principal set per repository id.
  app_ci_store_member = var.app_ci_forge == null ? "" : "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/day2-ci/attribute.repository_id/${var.app_ci_forge.repository_id}"
}

resource "google_storage_bucket" "app_ci" {
  count = var.app_ci == null ? 0 : 1

  name                        = var.app_ci.bucket
  project                     = var.project_id
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = false
  }

  soft_delete_policy {
    retention_duration_seconds = 0
  }

  lifecycle_rule {
    condition {
      age = 30
    }

    action {
      type = "Delete"
    }
  }

  labels = {
    app        = var.app_id
    managed_by = "opentofu"
    purpose    = "day2-ci"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# The store step creates objects with ifGenerationMatch=0; the app's own runs
# may also read its stored results. Neither role overwrites or deletes.
resource "google_storage_bucket_iam_member" "app_ci_store" {
  for_each = var.app_ci == null ? toset([]) : toset(["roles/storage.objectCreator", "roles/storage.objectViewer"])

  bucket = google_storage_bucket.app_ci[0].name
  role   = each.value
  member = local.app_ci_store_member
}

resource "google_storage_bucket_iam_member" "app_ci_reader" {
  count = var.app_ci == null ? 0 : 1

  bucket = google_storage_bucket.app_ci[0].name
  role   = "roles/storage.objectViewer"
  member = var.app_ci.reader
}
