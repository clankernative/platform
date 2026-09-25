terraform {
  required_version = ">= 1.8.0"

  # Partial backend: pass -backend-config=<instance>/backend/gitea-instance-ci.hcl.
  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}
