# The central log store, and the query engine that reads it.
#
# Everything that produces an audit trail writes here, and nothing can
# delete what lands. That tamper-resistance comes from S3 Object Lock in
# COMPLIANCE mode: for the retention period, an object cannot be deleted
# or overwritten by anyone -- not the account owner, not AWS root, not
# AWS support. The only escape is closing the account.
#
# That irreversibility is why retention is set in days rather than the
# months or years a production deployment would use. Seven days survives
# a normal gap between working sessions without locking in a week's worth
# of mistakes made while the pipeline is still being built.
#
# Two properties are needed for tamper-resistance and Object Lock only
# provides one: it stops deletion, but not undetected alteration. That's
# what CloudTrail's log file validation below adds -- it writes signed
# digests, so a modified log file can be detected after the fact.

locals {
  log_store_retention_days = 7
}

resource "aws_s3_bucket" "log_store" {
  bucket = "fedramp-20x-ksi-log-store-${data.aws_caller_identity.current.account_id}"

  # Only settable at creation. A bucket that wasn't created with Object
  # Lock enabled can never have it added -- it has to be recreated.
  object_lock_enabled = true

  # This bucket outlives the destroy-and-rebuild cycle the rest of the
  # environment follows; its contents are the audit record.
  lifecycle {
    prevent_destroy = true
  }
}

# Object Lock is implemented on top of object versions, so versioning has
# to be on before the lock configuration below will apply.
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

# The evidence key (evidence_key.tf), since 2026-09-30. Objects written
# before then stay SSE-S3 until the 7-day retention ages them out.
resource "aws_s3_bucket_server_side_encryption_configuration" "log_store" {
  bucket = aws_s3_bucket.log_store.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    # One KMS call per bucket key rather than per object, which is what keeps
    # a CloudTrail-and-Config write rate cheap under a customer key.
    bucket_key_enabled = true
  }

  # After the trail has its own key, never before. If the bucket default
  # switched first and the trail update then failed, CloudTrail would write
  # with no key of its own, S3 would apply this one under an encryption
  # context the key policy does not grant CloudTrail, and delivery would
  # stop without an error anyone sees.
  depends_on = [aws_cloudtrail.main]
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
  name           = "fedramp-20x-ksi-trail"
  s3_bucket_name = aws_s3_bucket.log_store.bucket

  # Writes a signed digest of each log file, which is what makes
  # after-the-fact tampering detectable rather than merely prevented.
  enable_log_file_validation = true

  # Global services (IAM, STS) only report into one region; multi-region
  # capture costs nothing extra and avoids a blind spot.
  include_global_service_events = true
  is_multi_region_trail         = true

  # CloudTrail encrypts each file itself with this key, rather than relying
  # on the bucket default, so the encryption context names the trail and the
  # key policy can scope CloudTrail to it. UpdateTrail checks that CloudTrail
  # can use the key, so a wrong key policy fails the apply rather than
  # silently stopping delivery.
  kms_key_id = aws_kms_key.evidence.arn

  depends_on = [aws_s3_bucket_policy.log_store]
}

# --- Query engine ---
#
# Athena runs SQL directly against files in S3. It needs two things: a
# Glue database, which holds the table definitions describing those files
# (see log_normalization.tf), and a workgroup, which carries the
# execution settings -- including the spend guardrail below.

resource "aws_glue_catalog_database" "log_corpus" {
  name = "fedramp_20x_ksi_log_corpus"
}

# Athena writes every query's results to S3. Those results go in their
# own bucket, not the log store: they're re-derivable scratch output, and
# writing them into an Object Lock bucket would make them undeletable for
# the retention period.
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

# KSI-SVC-SIN build row 2: TLS-only bucket policies. Every other bucket in
# the account had one and this one had no policy at all -- found on
# 2026-09-23 by the collector check written for that row, which is how a
# row with no verify line ends up unmet. Query results are derived from the
# log store, so they are audit data in transit like the store itself.
data "aws_iam_policy_document" "athena_results_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.athena_results.arn, "${aws_s3_bucket.athena_results.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  policy = data.aws_iam_policy_document.athena_results_bucket.json
}

# Query results are evidence derived from the log store, so the same key.
resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    # One KMS call per bucket key rather than per object, which is what keeps
    # a CloudTrail-and-Config write rate cheap under a customer key.
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

# Athena's built-in workgroup. AWS creates it in every account and it cannot
# be deleted, so it is governed instead: the same enforced settings as the
# evidence workgroup below, so a query run in it cannot write unencrypted
# results or scan without a limit. It had none of that until 2026-10-01,
# when svc-sin-cfg-aws-stores-use-declared-keys found it.
import {
  to = aws_athena_workgroup.primary
  id = "primary"
}

resource "aws_athena_workgroup" "primary" {
  name = "primary"

  configuration {
    enforce_workgroup_configuration    = true
    bytes_scanned_cutoff_per_query     = 1073741824
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/primary/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.evidence.arn
      }
    }
  }

  # Deleting the primary workgroup is refused by Athena; a destroy would
  # fail rather than do anything, and this says so before one is tried.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_athena_workgroup" "log_corpus" {
  name = "fedramp-20x-ksi-log-corpus"

  configuration {
    # Forces every query to use the settings below, including the scan
    # limit. Without this, a client can override them per query.
    enforce_workgroup_configuration = true

    # Athena bills per byte scanned, so a careless query against a large
    # dataset is the expensive failure mode. This caps any single query
    # at 1 GB -- about half a cent -- and cancels anything that exceeds
    # it. Set now, while the corpus is small and the limit costs nothing.
    bytes_scanned_cutoff_per_query     = 1073741824
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"

      # Stated as well as inherited from the bucket default, because
      # enforce_workgroup_configuration above makes this the setting every
      # query uses, and a result written with an explicit weaker setting
      # would otherwise override the bucket's.
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.evidence.arn
      }
    }
  }
}
