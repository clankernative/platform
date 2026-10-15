locals {
  database_name    = "projects/${var.project_id}/databases/${var.database_id}"
  controller_email = "${var.controller_service_account_id}@${var.project_id}.iam.gserviceaccount.com"
  scope_id         = substr(sha256(jsonencode({ database = local.database_name, scope = var.authority_scope })), 0, 16)

  # getMetadata reads the immutable database UID; databases.get authorizes
  # transactions. IAM does not distinguish read-only transaction mode.
  reader_permissions = toset([
    "datastore.databases.getMetadata",
    "datastore.databases.get",
    "datastore.entities.get",
  ])
  writer_permissions = setunion(local.reader_permissions, toset([
    "datastore.entities.create",
    "datastore.entities.update",
  ]))
}

data "google_project" "selected" {
  project_id = var.project_id
}

data "google_service_account" "app_reader" {
  project    = var.project_id
  account_id = split("@", var.app_reader_service_account)[0]
}

resource "google_project_service" "firestore" {
  project            = var.project_id
  service            = "firestore.googleapis.com"
  disable_on_destroy = false
}

resource "google_firestore_database" "authority" {
  project                           = var.project_id
  name                              = var.database_id
  location_id                       = var.location
  type                              = "FIRESTORE_NATIVE"
  database_edition                  = "STANDARD"
  concurrency_mode                  = "PESSIMISTIC"
  app_engine_integration_mode       = "DISABLED"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_DISABLED"
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"
  deletion_policy                   = "ABANDON"

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.firestore]
}

resource "google_service_account" "controller" {
  project      = var.project_id
  account_id   = var.controller_service_account_id
  display_name = "Day2 security epoch controller"
  description  = "Dedicated ${var.authority_scope.app} authority writer; native policy and execution evidence separately authorize bootstrap."
}

resource "google_project_iam_custom_role" "reader" {
  project     = var.project_id
  role_id     = "day2EpochReader_${local.scope_id}"
  title       = "Day2 app security epoch reader"
  description = "Database metadata and coherent document reads; no entity mutation."
  permissions = sort(tolist(local.reader_permissions))
}

resource "google_project_iam_custom_role" "controller" {
  project     = var.project_id
  role_id     = "day2EpochController_${local.scope_id}"
  title       = "Day2 security epoch controller"
  description = "Database read/create/update access; native guards enforce accepted requests and conditional transitions."
  permissions = sort(tolist(local.writer_permissions))
}

# Additive members leave other grants visible for the separate effective-IAM
# qualification. These conditions scope REST access to a database NAME, not its
# immutable UID, a document path, request precondition or kernel transition.
resource "google_project_iam_member" "app_reader" {
  project = var.project_id
  role    = google_project_iam_custom_role.reader.name
  member  = "serviceAccount:${var.app_reader_service_account}"

  condition {
    title       = "day2_epoch_reader_${local.scope_id}"
    description = "Read the selected app authority database."
    expression  = "resource.name == '${local.database_name}'"
  }

  lifecycle {
    precondition {
      condition = (
        endswith(var.app_reader_service_account, "@${var.project_id}.iam.gserviceaccount.com") &&
        var.app_reader_service_account != local.controller_email &&
        data.google_service_account.app_reader.email == var.app_reader_service_account
      )
      error_message = "The reader must be the exact existing same-project app GSA, distinct from the controller."
    }
  }

  depends_on = [google_firestore_database.authority]
}

resource "google_project_iam_member" "controller" {
  project = var.project_id
  role    = google_project_iam_custom_role.controller.name
  member  = "serviceAccount:${google_service_account.controller.email}"

  condition {
    title       = "day2_epoch_controller_${local.scope_id}"
    description = "Create and update the selected app authority database."
    expression  = "resource.name == '${local.database_name}'"
  }

  lifecycle {
    precondition {
      condition     = var.app_reader_service_account != local.controller_email
      error_message = "The controller writer must be distinct from the app reader."
    }
  }

  depends_on = [google_firestore_database.authority]
}
