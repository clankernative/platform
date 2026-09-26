# State migrations from the layout this root's state was first written with.
# All of these are no-ops on a fresh state.

# The APIs kept moved from google_project_service.foundation to
# google_project_service.api. `moved` has no for_each, hence one per key.
moved {
  from = google_project_service.foundation["artifactregistry.googleapis.com"]
  to   = google_project_service.api["artifactregistry.googleapis.com"]
}

moved {
  from = google_project_service.foundation["compute.googleapis.com"]
  to   = google_project_service.api["compute.googleapis.com"]
}

moved {
  from = google_project_service.foundation["container.googleapis.com"]
  to   = google_project_service.api["container.googleapis.com"]
}

moved {
  from = google_project_service.foundation["gkebackup.googleapis.com"]
  to   = google_project_service.api["gkebackup.googleapis.com"]
}

moved {
  from = google_project_service.foundation["iam.googleapis.com"]
  to   = google_project_service.api["iam.googleapis.com"]
}

moved {
  from = google_project_service.foundation["iamcredentials.googleapis.com"]
  to   = google_project_service.api["iamcredentials.googleapis.com"]
}

moved {
  from = google_project_service.foundation["iap.googleapis.com"]
  to   = google_project_service.api["iap.googleapis.com"]
}

moved {
  from = google_project_service.foundation["secretmanager.googleapis.com"]
  to   = google_project_service.api["secretmanager.googleapis.com"]
}

moved {
  from = google_project_service.foundation["serviceusage.googleapis.com"]
  to   = google_project_service.api["serviceusage.googleapis.com"]
}

moved {
  from = google_project_service.foundation["storage.googleapis.com"]
  to   = google_project_service.api["storage.googleapis.com"]
}

moved {
  from = google_project_service.foundation["sts.googleapis.com"]
  to   = google_project_service.api["sts.googleapis.com"]
}

# The rest of google_project_service.foundation (admin, calendar-json,
# cloudidentity, cloudkms, docs, drive, fcm, memorystore, networkconnectivity,
# pubsub) is not used by day2. Forget them and leave them enabled: disabling a
# live API can break whatever else calls it, for nothing gained.
removed {
  from = google_project_service.foundation

  lifecycle {
    destroy = false
  }
}

# A hash of an unrelated source-forge catalog, recorded by an earlier layout
# of this root. It exists only in state; forgetting it touches nothing.
removed {
  from = terraform_data.gitea_actions_catalog_authority

  lifecycle {
    destroy = false
  }
}

# Deliberately absent, so a plan against the old state destroys them:
# - google_project_iam_custom_role.internal_tools_fcm_message_sender: a
#   Firebase Cloud Messaging sender role nothing in day2 grants.
# - google_storage_bucket_iam_binding.state_object_{readers,writers}["apps"]:
#   grants on "platform/apps/", a prefix no day2 stack writes.
