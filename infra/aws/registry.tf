# Image registry, and the bucket the worker lands extracts in.
#
# KSI-SVC-SIN's build row 8: registries with customer-managed keys and
# immutable tags. KSI-SVC-VRI's build row 4 asks for the same immutability
# from the other direction -- if a tag can be overwritten, then a digest
# recorded yesterday and a tag resolved today can disagree, and every
# integrity claim made against the tag is unfalsifiable.

locals {
  services = toset(["api", "worker"])
}

resource "aws_ecr_repository" "service" {
  for_each = local.services

  name = "fedramp-20x-ksi/${each.key}"

  # The whole of KSI-SVC-VRI's build row 4. Once a tag points at a digest
  # it cannot be moved to another one.
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.artifacts.arn
  }

  image_scanning_configuration {
    # Scan on push. Security Hub Essentials brings Inspector's deeper
    # scanning, which covers application dependencies rather than OS
    # packages alone -- basic scanning here is the floor, not the answer,
    # and KSI-SVC-EIS's build row 1 records why basic alone was rejected.
    scan_on_push = true
  }

  tags = {
    Service = each.key
  }
}

# KSI-SVC-PRR's build row 3: image retention windows, so old images are
# residue with an expiry rather than residue that accumulates.
resource "aws_ecr_lifecycle_policy" "service" {
  for_each = aws_ecr_repository.service

  repository = each.value.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the last 10 images; older ones are superseded and unreferenced."
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = { type = "expire" }
      },
    ]
  })
}

# The AWS end of the cross-cloud data path. The worker writes here; the GCP
# analytics pipeline reads from here. Kept separate from the log store
# because it holds customer data rather than audit records, and the two
# have different retention, different keys and different readers.

resource "aws_s3_bucket" "extracts" {
  bucket = "fedramp-20x-ksi-extracts-${data.aws_caller_identity.current.account_id}"

  tags = {
    DataClass = "customer-data"
  }
}

resource "aws_s3_bucket_public_access_block" "extracts" {
  bucket = aws_s3_bucket.extracts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "extracts" {
  bucket = aws_s3_bucket.extracts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.artifacts.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "extracts" {
  bucket = aws_s3_bucket.extracts.id

  versioning_configuration {
    status = "Enabled"
  }
}

# KSI-SVC-PRR again. An extract is intermediate data the analytics pipeline
# has already consumed; keeping it forever is residue, and the design
# records the landing zone as regenerable under KSI-RPL-RRO, so expiry
# costs nothing recoverable.
resource "aws_s3_bucket_lifecycle_configuration" "extracts" {
  bucket = aws_s3_bucket.extracts.id

  rule {
    id     = "expire-extracts"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}
