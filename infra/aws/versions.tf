terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Bucket, key, region and locking are supplied at `terraform init` time via
  # -backend-config=backend.hcl (see backend.hcl.example). Not hardcoded here:
  # the bucket name is account-specific and comes from infra/bootstrap's
  # output, not something to fix into version-controlled config.
  backend "s3" {}
}
