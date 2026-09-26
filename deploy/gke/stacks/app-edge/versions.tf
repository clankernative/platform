terraform {
  required_version = ">= 1.8.0"

  # Partial backend: pass -backend-config=<instance>/backend/app/<app-id>.hcl
  # (one prefix per app, e.g. platform/app/<app-id>).
  backend "gcs" {}

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.35"
    }
  }
}
