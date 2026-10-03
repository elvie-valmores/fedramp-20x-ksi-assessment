# The bucket that holds Terraform state for every other root.
#
# This root keeps its own state on local disk, because it cannot store
# state in a bucket it has not created yet. See infra/README.md.

data "aws_caller_identity" "current" {}

locals {
  # S3 bucket names are globally unique across all AWS accounts, so the
  # account ID is appended to guarantee no collision without anyone
  # having to invent a unique name by hand.
  state_bucket_name = "fedramp-20x-ksi-tfstate-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket" "tfstate" {
  bucket = local.state_bucket_name

  # Losing this bucket means losing the record of every resource
  # Terraform manages. A stray destroy in this root should not be able to
  # take it out.
  lifecycle {
    prevent_destroy = true
  }
}

# Keeps prior versions of the state file, which is the recovery path if a
# bad apply corrupts it.
resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Prior state versions kept 90 days, current ones forever (Security Hub
# S3.13, 2026-10-03). Ninety days is the depth a state rollback can reach,
# which is far beyond any session gap here; until then every version since
# the first apply was kept. Nothing expires a current state file.
resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id     = "expire-superseded-state"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.tfstate]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# State files contain resource attributes and can contain secrets, so
# unencrypted transport is refused outright rather than merely discouraged.
data "aws_iam_policy_document" "tfstate_tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_tls_only.json
}
