# The grants on the persistent stores, which are not themselves persistent.
#
# Split out of registry.tf on 2026-09-22. The registry and the extract bucket
# moved to the persistent side of boundary.py so that images survive a
# teardown; these policies did not, and the split is the point rather than an
# artefact of it.
#
# THE STORE PERSISTS, THE GRANTS TO TRANSIENT PRINCIPALS DO NOT
#
# Both policies name roles from compute.tf -- task_execution may pull images,
# worker_task may write extracts -- and those roles exist only while the
# application environment does. A policy naming a deleted role is not an
# error, but a policy that Terraform cannot compute is: the reference needs
# the role in state.
#
# So a repository outlives the roles permitted to pull from it, and the
# permission reappears with them. That is the same shape as the artifacts key
# next door, which persists while its per-role grants moved to IAM, and as
# pipeline_identity.tf, which persists while the build role does not.
#
# If a check ever asks whether the registry is readable from outside the
# account, note that it is answered by this file and not by registry.tf, and
# that between sessions the honest answer is that no principal is granted
# anything -- which is narrower than the claim, not broader.

# Only this account's roles may pull, and nothing outside the account may
# do anything. KSI-CNA-MAT's validation includes "no external access paths
# beyond the declared public-facing list", and a registry readable from
# outside the account is exactly such a path.
data "aws_iam_policy_document" "ecr_repository" {
  statement {
    sid    = "AllowAccountPull"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [
        aws_iam_role.task_execution.arn,
      ]
    }

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
  }
}

resource "aws_ecr_repository_policy" "service" {
  for_each = aws_ecr_repository.service

  repository = each.value.name
  policy     = data.aws_iam_policy_document.ecr_repository.json
}

# --- The extract landing bucket ---
#
data "aws_iam_policy_document" "extracts_bucket" {
  # KSI-CNA-RNT's second resource category: resources with no network
  # interface, limited by resource policy and access boundary rather than
  # by security group. The determination's point is that a check built
  # only around interfaces misses this category entirely, and that it is
  # the more damaging exposure because it is data rather than a path.
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.extracts.arn, "${aws_s3_bucket.extracts.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # The network-boundary dimension KSI-CNA-RNT adds for this category:
  # whether access is restricted to the VPC or reachable from anywhere
  # with the right credential. Writes must arrive through the S3 gateway
  # endpoint.
  statement {
    sid    = "DenyWritesOutsideVPC"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.worker_task.arn]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.extracts.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpce"
      values   = [aws_vpc_endpoint.s3.id]
    }
  }

  # Unencrypted writes rejected at the bucket, not merely defaulted. The
  # bucket's default encryption would encrypt an object that arrived
  # without a header; this rejects one that arrived asking for something
  # weaker.
  statement {
    sid    = "DenyUnencryptedWrites"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.extracts.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "extracts" {
  bucket = aws_s3_bucket.extracts.id
  policy = data.aws_iam_policy_document.extracts_bucket.json
}
