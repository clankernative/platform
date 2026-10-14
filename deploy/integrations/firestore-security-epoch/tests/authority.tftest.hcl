# All provider operations are mocked. Values below are test DATA, never live
# instance selectors or readiness evidence.
mock_provider "google" {
  mock_data "google_project" {
    defaults = { number = "123456789012" }
  }
  mock_data "google_service_account" {
    defaults = {
      email     = "calendar-app@example-tools.iam.gserviceaccount.com"
      unique_id = "123456789012345678901"
    }
  }
  mock_resource "google_service_account" {
    defaults = {
      email     = "epoch-controller@example-tools.iam.gserviceaccount.com"
      unique_id = "223456789012345678901"
    }
  }
  mock_resource "google_firestore_database" {
    defaults = { uid = "01234567-89ab-4cde-8fab-0123456789ab" }
  }
}

variables {
  project_id  = "example-tools"
  location    = "us-central1"
  database_id = "calendar-authority"
  authority_scope = {
    installation = "example"
    environment  = "staging"
    app          = "calendar"
  }
  app_reader_service_account    = "calendar-app@example-tools.iam.gserviceaccount.com"
  controller_service_account_id = "epoch-controller"
}

run "native_database_is_protected_and_outside_app_storage" {
  command = plan

  assert {
    condition = (
      google_firestore_database.authority.type == "FIRESTORE_NATIVE" &&
      google_firestore_database.authority.database_edition == "STANDARD" &&
      google_firestore_database.authority.name == "calendar-authority" &&
      google_firestore_database.authority.location_id == "us-central1" &&
      google_firestore_database.authority.delete_protection_state == "DELETE_PROTECTION_ENABLED" &&
      google_firestore_database.authority.deletion_policy == "ABANDON" &&
      google_firestore_database.authority.app_engine_integration_mode == "DISABLED" &&
      google_firestore_database.authority.point_in_time_recovery_enablement == "POINT_IN_TIME_RECOVERY_DISABLED" &&
      google_project_service.firestore.service == "firestore.googleapis.com" &&
      !google_project_service.firestore.disable_on_destroy
    )
    error_message = "Select one protected Native database without App Engine or managed restore paths."
  }
}

run "grants_separate_reader_and_bounded_writer" {
  command = plan

  assert {
    condition = (
      toset(google_project_iam_custom_role.reader.permissions) == toset([
        "datastore.databases.getMetadata", "datastore.databases.get", "datastore.entities.get",
      ]) &&
      toset(google_project_iam_custom_role.controller.permissions) == toset([
        "datastore.databases.getMetadata", "datastore.databases.get", "datastore.entities.get",
        "datastore.entities.create", "datastore.entities.update",
      ]) &&
      google_project_iam_member.app_reader.member == "serviceAccount:calendar-app@example-tools.iam.gserviceaccount.com" &&
      google_project_iam_member.controller.member == "serviceAccount:epoch-controller@example-tools.iam.gserviceaccount.com" &&
      google_project_iam_member.app_reader.role == google_project_iam_custom_role.reader.name &&
      google_project_iam_member.controller.role == google_project_iam_custom_role.controller.name
    )
    error_message = "The app gets only reads; only the distinct controller gets create/update, without delete/list/admin."
  }

  assert {
    condition = (
      one(google_project_iam_member.app_reader.condition).expression == "resource.name == 'projects/example-tools/databases/calendar-authority'" &&
      one(google_project_iam_member.controller.condition).expression == "resource.name == 'projects/example-tools/databases/calendar-authority'"
    )
    error_message = "Both REST grants must be restricted to the exact selected database name."
  }
}

run "provider_facts_remain_data_with_distinct_immutable_ids" {
  command = plan

  assert {
    condition = (
      output.resource_facts.database_uid == "01234567-89ab-4cde-8fab-0123456789ab" &&
      output.resource_facts.project_number == "123456789012" &&
      output.resource_facts.app_reader.unique_id == "123456789012345678901" &&
      output.resource_facts.controller.unique_id == "223456789012345678901" &&
      output.resource_facts.scope == var.authority_scope &&
      toset(keys(output.resource_facts)) == toset([
        "scope", "project", "project_number", "database", "database_uid", "location", "app_reader", "controller",
      ])
    )
    error_message = "Expose observed resource metadata only, with no epoch/holder/ready/key-set assertion."
  }
}

run "refuses_reader_controller_alias" {
  command = plan
  variables { controller_service_account_id = "calendar-app" }
  expect_failures = [google_project_iam_member.app_reader, google_project_iam_member.controller]
}

run "refuses_foreign_project_reader" {
  command = plan
  variables { app_reader_service_account = "calendar-app@foreign-tools.iam.gserviceaccount.com" }
  expect_failures = [google_project_iam_member.app_reader]
}

run "refuses_mismatched_observed_reader" {
  command = plan
  variables { app_reader_service_account = "other-reader@example-tools.iam.gserviceaccount.com" }
  expect_failures = [google_project_iam_member.app_reader]
}

run "refuses_default_database" {
  command = plan
  variables { database_id = "(default)" }
  expect_failures = [var.database_id]
}

run "refuses_uuid_database_name" {
  command = plan
  variables { database_id = "abcdefab-abcd-abcd-abcd-abcdefabcdef" }
  expect_failures = [var.database_id]
}

run "refuses_condition_injection" {
  command = plan
  variables { database_id = "calendar' || true || 'authority" }
  expect_failures = [var.database_id]
}

run "refuses_unbounded_scope" {
  command = plan
  variables {
    authority_scope = { installation = "example", environment = "staging", app = "" }
  }
  expect_failures = [var.authority_scope]
}

run "refuses_non_service_account_reader" {
  command = plan
  variables { app_reader_service_account = "operator@example.com" }
  expect_failures = [var.app_reader_service_account]
}
