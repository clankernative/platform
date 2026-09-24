terraform {
  required_version = ">= 1.8.0"

  # Partial backend: the instance supplies it with
  # -backend-config=<instance>/backend/apps/<app>.hcl.
  backend "gcs" {}

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.2"
    }
  }
}
