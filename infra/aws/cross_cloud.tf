# The AWS end of the single cross-cloud path.
#
# The GCP analytics pipeline reaches in here to read measurement extracts.
# KSI-SVC-VCM is determined against this path, and its build row 1 is the
# constraint: "OIDC trust scoped to a specific subject and audience, no
# wildcards."
#
# Google issues its service accounts identity tokens signed by
# accounts.google.com, which AWS already trusts as an OIDC provider without
# any provider resource being declared -- unlike GitHub, which needs one.
# That is why there is no aws_iam_openid_connect_provider here: adding one
# for Google would fail, because it is built in.
#
# The direction is deliberate and is the reason this file is small. GCP
# reaches into AWS, so there is one federation rather than two, and the AWS
# side holds no Google credential. KSI-IAM-SNU's hierarchy is satisfied on
# both ends: nothing static exists anywhere on this path.

variable "gcp_pipeline_sa_unique_id" {
  description = <<-EOT
    Numeric unique ID of the GCP pipeline service account, from the gcp
    root's pipeline_service_account_unique_id output.

    Empty means the cross-cloud role is not created, which is the state
    before the GCP side has been applied.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.gcp_pipeline_sa_unique_id == "" || can(regex("^[0-9]{18,25}$", var.gcp_pipeline_sa_unique_id))
    error_message = "Must be the numeric unique ID, not the service account email."
  }
}

data "aws_iam_policy_document" "gcp_pipeline_assume" {
  count = var.gcp_pipeline_sa_unique_id == "" ? 0 : 1

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["accounts.google.com"]
    }

    # The subject is the service account's numeric unique ID, matched
    # exactly.
    #
    # Matching on the ID rather than the email is the point. A service
    # account email can be deleted and recreated, and the recreated
    # account would inherit trust that was granted to a different
    # principal. The numeric ID is never reused, so the trust cannot be
    # re-pointed by anyone who can create a service account with a
    # familiar name.
    condition {
      test     = "StringEquals"
      variable = "accounts.google.com:sub"
      values   = [var.gcp_pipeline_sa_unique_id]
    }

    # The audience, pinned. Without this, any Google-issued token for this
    # subject would be accepted regardless of what it was minted for,
    # which is how a token obtained for an unrelated service becomes a
    # credential here.
    condition {
      test     = "StringEquals"
      variable = "accounts.google.com:aud"
      values   = [var.gcp_pipeline_sa_unique_id]
    }
  }
}

resource "aws_iam_role" "gcp_pipeline" {
  count = var.gcp_pipeline_sa_unique_id == "" ? 0 : 1

  name               = "fedramp-20x-ksi-gcp-pipeline"
  description        = "Assumed by the GCP analytics pipeline to read measurement extracts."
  assume_role_policy = data.aws_iam_policy_document.gcp_pipeline_assume[0].json

  # KSI-CNA-ULN's session layer, applied to the cross-cloud hop as well as
  # the internal ones.
  max_session_duration = 3600

  tags = {
    Component = "cross-cloud"
  }
}

data "aws_iam_policy_document" "gcp_pipeline" {
  count = var.gcp_pipeline_sa_unique_id == "" ? 0 : 1

  # Read only, and only the extract prefix. The pipeline consumes what the
  # worker produces and has no reason to write, delete, or read anything
  # else in the account.
  #
  # KSI-CNA-MAT's identity surface is what a compromised resource reaches
  # with the credentials it holds. A compromised analytics pipeline reaches
  # exactly one prefix of one bucket, read-only.
  statement {
    sid    = "ReadExtracts"
    effect = "Allow"

    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.extracts.arn}/measurements/*"]
  }

  statement {
    sid    = "ListExtracts"
    effect = "Allow"

    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.extracts.arn]

    # Listing is scoped to the same prefix the read grant covers, so the
    # role cannot enumerate the rest of the bucket to discover what else
    # is there.
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["measurements/*"]
    }
  }

  # The extracts are encrypted with the artifacts key, so reading them
  # requires decrypting under it. Bounded to S3 so the role cannot use the
  # key for anything else encrypted under it.
  statement {
    sid    = "DecryptExtracts"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    resources = [aws_kms_key.artifacts.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "gcp_pipeline" {
  count = var.gcp_pipeline_sa_unique_id == "" ? 0 : 1

  name   = "read-extracts"
  role   = aws_iam_role.gcp_pipeline[0].id
  policy = data.aws_iam_policy_document.gcp_pipeline[0].json
}

output "gcp_pipeline_role_arn" {
  description = "Set as TF_VAR_aws_extract_role_arn when applying the gcp root."
  value       = var.gcp_pipeline_sa_unique_id == "" ? "" : aws_iam_role.gcp_pipeline[0].arn
}

output "extract_bucket_name" {
  description = "Set as TF_VAR_aws_extract_bucket when applying the gcp root."
  value       = aws_s3_bucket.extracts.bucket
}
