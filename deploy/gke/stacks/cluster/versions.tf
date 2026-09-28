terraform {
  # 1.10 adds lifecycle { destroy = false } to removed blocks.
  required_version = ">= 1.10.0"

  # Partial backend: pass -backend-config=<instance>/backend/cluster.hcl.
  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}
