# The pipeline's identity in this account.
#
# KSI-IAM-SNU's determination defines "appropriately secure" as a durability
# hierarchy: no credential first, then short-lived federated exchange, then
# static keys as failing. This file is the middle rung, and the reason there
# are no access keys anywhere in this project.
#
# GitHub Actions presents an OIDC token describing the workflow run. AWS
# trusts that token's issuer and exchanges it for a short-lived role session.
# Nothing is stored on either side.
#
# KSI-SVC-VCM build row 1 is the constraint that shapes the trust policy:
# "OIDC trust scoped to a specific subject and audience, no wildcards."

locals {
  # From the repository's own origin remote. Hardcoded rather than a
  # variable because it is not environment-specific -- a different value
  # here would mean a different project's pipeline could assume this role.
  github_repository = "elvie-valmores/fedramp-20x-ksi-assessment"
}

# GitHub publishes its OIDC configuration at a well-known URL and AWS
# fetches the signing keys from it. The thumbprint argument is deliberately
# omitted: AWS now validates these certificates against its own trust store
# for the GitHub issuer, and a pinned thumbprint is a value that expires and
# breaks authentication when GitHub rotates its certificate.
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  # The audience. Paired with the subject condition below, this is what
  # makes the trust specific rather than "any GitHub workflow anywhere".
  client_id_list = ["sts.amazonaws.com"]

  tags = {
    Name = "fedramp-20x-ksi-github"
  }
}

# --- The build role ---
#
# What the pipeline holds when it builds and publishes images. Scoped to
# exactly that: it cannot apply Terraform, read a secret, or touch the
# database.
#
# KSI-CMT-RMV build row 2 requires registry push be permitted only to the
# pipeline principal. This role is that principal.

data "aws_iam_policy_document" "github_build_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # The subject claim, pinned to this repository's default branch.
    #
    # StringEquals rather than StringLike, and a specific ref rather than
    # `repo:owner/name:*`. The wildcard form is the common one and it is
    # what KSI-SVC-VCM's build row bars: it would let a pull request from a
    # fork assume this role, which is the standard way this pattern is
    # exploited.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.github_repository}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "github_build" {
  name               = "fedramp-20x-ksi-github-build"
  assume_role_policy = data.aws_iam_policy_document.github_build_assume.json

  # KSI-CNA-ULN's session layer. One hour is the floor AWS permits and is
  # far longer than a build needs, but it is the shortest declarable value.
  max_session_duration = 3600

  tags = {
    Component = "pipeline"
  }
}

data "aws_iam_policy_document" "github_build" {
  # Authentication to the registry. Takes no resource, which is why it is
  # a separate statement rather than folded into the one below.
  statement {
    sid       = "AuthenticateToRegistry"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  # Push, and read back for signing. Scoped to this project's two
  # repositories -- not every repository in the account.
  statement {
    sid    = "PublishImages"
    effect = "Allow"

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      # Signature storage. cosign writes the signature as an OCI artifact
      # alongside the image, so signing is a registry write rather than a
      # separate service.
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:DescribeImages",
    ]

    resources = [for repo in aws_ecr_repository.service : repo.arn]
  }

  # The image layers are encrypted with the artifacts key, so publishing
  # requires being able to encrypt under it.
  statement {
    sid    = "EncryptImageLayers"
    effect = "Allow"

    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    resources = [aws_kms_key.artifacts.arn]
  }

  # KSI-CMT-LMC build row 1: repository events into the corpus. The
  # 2026-09-19 decision chose this over a webhook precisely so that no new
  # ingress and no new shared secret exist -- the pipeline emits using the
  # identity it already holds.
  statement {
    sid       = "EmitRepositoryEvents"
    effect    = "Allow"
    actions   = ["events:PutEvents"]
    resources = ["arn:aws:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/default"]
  }
}

resource "aws_iam_role_policy" "github_build" {
  name   = "build"
  role   = aws_iam_role.github_build.id
  policy = data.aws_iam_policy_document.github_build.json
}

# --- The drift-detection role ---
#
# KSI-SVC-ACM build row 3: a scheduled plan in check mode across both
# clouds, with exit status treated as the drift signal.
#
# Read-only, and separate from the build role rather than folded into it. A
# plan needs to read most of the account, which is a much wider grant than
# publishing an image, and combining them would give the build path
# account-wide read for no reason.
#
# Note this role can plan but not apply. Apply remains with a human
# identity under the dated exception recorded in docs/DECISIONS.md on
# 2026-09-19, which closes when KSI-IAM-JIT's elevation workflow lands.
# Until then KSI-CMT-RMV build row 3 is satisfied by exception rather than
# by enforcement, and that is recorded rather than implied.

data "aws_iam_policy_document" "github_drift_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Scheduled workflows run against the default branch, so the same
    # subject applies.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.github_repository}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "github_drift" {
  name               = "fedramp-20x-ksi-github-drift"
  assume_role_policy = data.aws_iam_policy_document.github_drift_assume.json

  max_session_duration = 3600

  tags = {
    Component = "pipeline"
  }
}

data "aws_iam_policy_document" "github_drift" {
  # Read-only across the resource types this project declares. A plan must
  # refresh every resource in state, so this is necessarily broad in
  # breadth while staying narrow in depth: it can describe anything and
  # change nothing.
  statement {
    sid    = "RefreshDeclaredState"
    effect = "Allow"

    actions = [
      "acm:Describe*",
      "acm:List*",
      "budgets:Describe*",
      "budgets:View*",
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "config:Describe*",
      "config:Get*",
      "config:List*",
      "ec2:Describe*",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
      "ecs:Describe*",
      "ecs:List*",
      "elasticloadbalancing:Describe*",
      "events:Describe*",
      "events:List*",
      "glue:Get*",
      "guardduty:Get*",
      "guardduty:List*",
      "iam:Get*",
      "iam:List*",
      "inspector2:Get*",
      "inspector2:List*",
      "kms:Describe*",
      "kms:Get*",
      "kms:List*",
      "lambda:Get*",
      "lambda:List*",
      "logs:Describe*",
      "logs:List*",
      "rds:Describe*",
      "rds:List*",
      "s3:Get*",
      "s3:List*",
      "securityhub:Describe*",
      "securityhub:Get*",
      "sns:Get*",
      "sns:List*",
      "sts:GetCallerIdentity",
      "wafv2:Get*",
      "wafv2:List*",
    ]

    resources = ["*"]
  }

  # The plan reads and writes the state lock, so state access is read-write
  # even though nothing else is. Scoped to the state bucket alone.
  statement {
    sid    = "AccessRemoteState"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::fedramp-20x-ksi-tfstate-${data.aws_caller_identity.current.account_id}",
      "arn:aws:s3:::fedramp-20x-ksi-tfstate-${data.aws_caller_identity.current.account_id}/*",
    ]
  }

  # Refreshing a secret's state reads its metadata, never its value. Stated
  # as an explicit deny so that a later widening of the read grant above
  # cannot quietly pick it up.
  statement {
    sid       = "NeverReadSecretValues"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "github_drift" {
  name   = "drift"
  role   = aws_iam_role.github_drift.id
  policy = data.aws_iam_policy_document.github_drift.json
}

output "github_build_role_arn" {
  description = "Assumed by the build workflow. Set as the AWS_BUILD_ROLE repository variable."
  value       = aws_iam_role.github_build.arn
}

output "github_drift_role_arn" {
  description = "Assumed by the drift workflow. Set as the AWS_DRIFT_ROLE repository variable."
  value       = aws_iam_role.github_drift.arn
}

output "ecr_registry" {
  description = "Registry hostname the build workflow pushes to."
  value       = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com"
}
