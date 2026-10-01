terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # This config creates the bucket every other root uses as its backend, so
  # it started with local state: it could not use the bucket before the
  # bucket existed. On 2026-10-01 its state was migrated into that bucket,
  # under bootstrap/terraform.tfstate, so the collector in CI can read what
  # this root declares (the state bucket itself, and the ACM certificate).
  # Checked first: the state holds no secret -- the certificate is
  # Amazon-issued, so its private_key attribute is empty.
  #
  # The one consequence, accepted: if the state bucket were ever destroyed
  # and recreated, this root must go back to local state first
  # (`terraform init -migrate-state` with this block removed), because it
  # cannot read its state from a bucket it is about to create. The bucket
  # has prevent_destroy, so this is a recovery path, not a routine one.
  #
  # Configured at init, as the other roots are:
  #   terraform init -migrate-state \
  #     -backend-config="bucket=<state bucket>" \
  #     -backend-config="key=bootstrap/terraform.tfstate" \
  #     -backend-config="region=us-east-1" \
  #     -backend-config="use_lockfile=true" -backend-config="encrypt=true"
  backend "s3" {}
}
