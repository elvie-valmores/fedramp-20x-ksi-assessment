terraform {
  required_version = ">= 1.10.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }

  # State lives in the same S3 bucket the AWS roots use, under a different
  # key. The backend only stores a JSON file and has no opinion about
  # which cloud the resources it tracks live in, so a second state bucket
  # on GCP would be redundant.
  #
  # Bucket and key are supplied at init time via -backend-config; see
  # backend.hcl.example.
  backend "s3" {}
}
