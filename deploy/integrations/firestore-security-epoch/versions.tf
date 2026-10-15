terraform {
  required_version = ">= 1.11.0"

  # The private instance selects this optional root and its own state prefix.
  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}
