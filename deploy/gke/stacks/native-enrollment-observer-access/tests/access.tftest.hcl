mock_provider "google" {
  mock_data "google_project" { defaults = { number = "123456789012" } }
}
variables {
  project_id                  = "company-tools"
  cluster                     = { name = "native", location = "us-central1-a", scope = "zonal" }
  provisioner_namespace       = "native-enrollment"
  provisioner_service_account = "provisioner"
  role_prefix                 = "NativeObservation"
  service_accounts = {
    app        = "native-app@company-tools.iam.gserviceaccount.com"
    shell      = "native-shell@company-tools.iam.gserviceaccount.com"
    controller = "native-controller@company-tools.iam.gserviceaccount.com"
  }
}
run "only_selected_metadata_and_principal" {
  command = plan
  assert {
    condition = (
      toset(google_project_iam_custom_role.project.permissions) == toset(["resourcemanager.projects.get"]) &&
      toset(google_project_iam_custom_role.cluster.permissions) == toset(["container.clusters.get"]) &&
      toset(google_project_iam_custom_role.service_account.permissions) == toset(["iam.serviceAccounts.get"])
    )
    error_message = "Metadata roles must contain only their one required read permission."
  }
  assert {
    condition = (
      google_project_iam_member.project.member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/company-tools.svc.id.goog/subject/ns/native-enrollment/sa/provisioner" &&
      google_project_iam_member.cluster.member == google_project_iam_member.project.member &&
      google_project_iam_member.cluster.condition[0].expression == "resource.type == 'container.googleapis.com/Cluster' && resource.name == 'projects/company-tools/zones/us-central1-a/clusters/native'" &&
      length(google_service_account_iam_member.selected) == 3 &&
      alltrue([for role, grant in google_service_account_iam_member.selected :
        grant.member == google_project_iam_member.project.member &&
        grant.service_account_id == "projects/company-tools/serviceAccounts/${var.service_accounts[role]}"
      ])
    )
    error_message = "Only the exact provisioner may observe the selected project, cluster and three account resources."
  }
}
run "regional_condition_uses_locations" {
  command = plan
  variables { cluster = { name = "native", location = "us-central1", scope = "regional" } }
  assert {
    condition     = local.cluster_condition == "resource.type == 'container.googleapis.com/Cluster' && resource.name == 'projects/company-tools/locations/us-central1/clusters/native'"
    error_message = "Regional GKE IAM resource names use locations."
  }
}
run "refuses_shared_account_aliases" {
  command = plan
  variables {
    service_accounts = {
      app        = "native-app@company-tools.iam.gserviceaccount.com"
      shell      = "native-app@company-tools.iam.gserviceaccount.com"
      controller = "native-controller@company-tools.iam.gserviceaccount.com"
    }
  }
  expect_failures = [var.service_accounts]
}
run "refuses_foreign_project_account" {
  command = plan
  variables {
    service_accounts = {
      app        = "native-app@company-tools.iam.gserviceaccount.com"
      shell      = "native-shell@foreign-tools.iam.gserviceaccount.com"
      controller = "native-controller@company-tools.iam.gserviceaccount.com"
    }
  }
  expect_failures = [var.service_accounts]
}
run "refuses_ambiguous_cluster_scope" {
  command = plan
  variables { cluster = { name = "native", location = "us-central1-a", scope = "project" } }
  expect_failures = [var.cluster]
}
