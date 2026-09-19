# KSI-MLA-OSM, build items 1 and 4 (partial): the central log store and
# the query layer scaffolding. Schema normalization (build item 2),
# Parquet conversion/partitioning (build item 3), detection queries
# (build item 5), and delivery-failure alarms (build item 6) are
# deliberately deferred to a following session — see chat, 2026-09-18:
# this indicator's full build is flagged in docs/PROJECT-CONTEXT.md as
# "most likely to overrun."
#
# Retention: 7 days, Object Lock compliance mode. Chosen for the reasons
# recorded in docs/DECISIONS.md — cost is negligible either way at this
# log volume; 7 days bounds the irreversible-lock risk window to
# something that survives a normal pause between sessions without
# leaving early, likely-malformed test data locked in for too long.
# COMPLIANCE mode cannot be shortened by anyone, including AWS root, once
# an object is written under it.

locals {
  log_store_retention_days = 7
}

resource "aws_s3_bucket" "log_store" {
  bucket = "fedramp-20x-ksi-log-store-${data.aws_caller_identity.current.account_id}"

  # Object Lock can only be enabled at bucket creation, never added later.
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

# Object Lock requires versioning; must exist before the lock config below.
resource "aws_s3_bucket_versioning" "log_store" {
  bucket = aws_s3_bucket.log_store.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "log_store" {
  bucket = aws_s3_bucket.log_store.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = local.log_store_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.log_store]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_store" {
  bucket = aws_s3_bucket.log_store.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "log_store" {
  bucket = aws_s3_bucket.log_store.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "log_store_bucket" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.log_store.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_store.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.log_store.arn, "${aws_s3_bucket.log_store.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "log_store" {
  bucket = aws_s3_bucket.log_store.id
  policy = data.aws_iam_policy_document.log_store_bucket.json
}

resource "aws_cloudtrail" "main" {
  name                          = "fedramp-20x-ksi-trail"
  s3_bucket_name                = aws_s3_bucket.log_store.bucket
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true # no extra cost for multi-region, and AU mappings emphasize coverage

  depends_on = [aws_s3_bucket_policy.log_store]
}

# --- Query layer scaffolding ---
#
# The Glue database and Athena workgroup exist now so cost guardrails
# (scan limits) are in place before any query ever runs. The actual
# partitioned table isn't registered yet: its schema depends on the OCSF
# field mapping the normalization Lambda will produce, which is part of
# the deferred work above.

resource "aws_glue_catalog_database" "log_corpus" {
  name = "fedramp_20x_ksi_log_corpus"
}

# Query results are transient and re-derivable — deliberately a separate,
# non-locked bucket rather than reusing the compliance-locked log store,
# which should hold only authoritative audit data.
resource "aws_s3_bucket" "athena_results" {
  bucket = "fedramp-20x-ksi-athena-results-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-query-results"
    status = "Enabled"

    filter {}

    expiration {
      days = 7
    }
  }
}

resource "aws_athena_workgroup" "log_corpus" {
  name = "fedramp-20x-ksi-log-corpus"

  configuration {
    enforce_workgroup_configuration = true
    # 1 GB per query -- costs roughly half a cent at Athena's per-TB
    # rate, a safety net set before rather than after a billing surprise,
    # per the design rationale.
    bytes_scanned_cutoff_per_query     = 1073741824
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"
    }
  }
}
