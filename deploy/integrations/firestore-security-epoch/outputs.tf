output "resource_facts" {
  description = "Provider resource metadata for later native selection/readback; never a current authority or readiness proof."
  value = {
    scope          = var.authority_scope
    project        = var.project_id
    project_number = data.google_project.selected.number
    database       = google_firestore_database.authority.name
    database_uid   = google_firestore_database.authority.uid
    location       = google_firestore_database.authority.location_id
    app_reader = {
      service_account = data.google_service_account.app_reader.email
      unique_id       = data.google_service_account.app_reader.unique_id
      role            = google_project_iam_custom_role.reader.name
    }
    controller = {
      service_account = google_service_account.controller.email
      unique_id       = google_service_account.controller.unique_id
      role            = google_project_iam_custom_role.controller.name
    }
  }
}
