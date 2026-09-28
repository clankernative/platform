terraform {
  required_version = ">= 1.8.0"

  # Partial backend: pass -backend-config=<instance>/backend/foundation.hcl.
  # The prefix stays "foundation": this root adopts the state the project
  # layer has always been applied with, it does not start a new one.
  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}
