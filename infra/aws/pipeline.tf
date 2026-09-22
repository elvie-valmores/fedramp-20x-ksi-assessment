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
  github_owner = "elvie-valmores"
  github_name  = "fedramp-20x-ksi-assessment"

  # The numeric owner and repository IDs, which are the load-bearing half of
  # the subject claim below.
  #
  # GitHub now issues *immutable* subject claims: the subject carries these
  # IDs alongside the names, and the IDs are what make it immutable. A login
  # or a repository can be renamed, deleted and recreated, and the recreated
  # one would inherit trust granted to a different principal. The numeric IDs
  # are never reused.
  #
  # This is the same decision this project already made on the other
  # federation. cross_cloud.tf matches the GCP service account's numeric
  # unique ID rather than its email, for exactly this reason, and records
  # why. GitHub has since made that choice on its users' behalf.
  #
  # Re-derive with:
  #   gh api /repos/<owner>/<name> --jq '{owner: .owner.id, repo: .id}'
  #
  # Confirm the form the repository actually sends with:
  #   gh api /repos/<owner>/<name>/actions/oidc/customization/sub
  #
  # `use_immutable_subject: true` means the prefix below is what arrives. If
  # that setting is ever false, the subject reverts to the legacy
  # `repo:<owner>/<name>` form and these conditions stop matching. Fix it by
  # turning the setting back on, not by widening the condition -- the legacy
  # form is the one that can be re-pointed by recreating a repository with a
  # familiar name.
  github_owner_id = "181586876"
  github_repo_id  = "1375137942"

  # repo:<owner>@<owner_id>/<name>@<repo_id>:ref:refs/heads/main
  #
  # Both roles are assumed only from the default branch, so both use this.
  github_subject = "repo:${local.github_owner}@${local.github_owner_id}/${local.github_name}@${local.github_repo_id}:ref:refs/heads/main"
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
      values   = [local.github_subject]
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
      values   = [local.github_subject]
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
      # Athena's workgroup read. Absent entirely until 2026-09-22, which is
      # one of the four gaps that made every drift run error rather than
      # report.
      "athena:Get*",
      "athena:List*",
      "budgets:Describe*",
      # ListTagsForResource, which Terraform calls on every budget refresh.
      # `Describe*` and `View*` do not cover it.
      "budgets:List*",
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
      # BatchGetAccountStatus is how the enabler resource reads its own
      # state, and it matches neither `Get*` nor `List*`.
      "inspector2:BatchGet*",
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
      # Metadata about the secret, not its contents. DescribeSecret and
      # GetResourcePolicy return the ARN, rotation config and resource
      # policy; neither returns secret material. GetSecretValue is
      # deliberately NOT here -- see the note below the statement.
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:ListSecrets",
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

  # Reading the one secret whose *version* is in state.
  #
  # This reverses the original premise of the deny below, which held that
  # "refreshing a secret's state reads its metadata, never its value". That
  # is true of `aws_secretsmanager_secret` and false of
  # `aws_secretsmanager_secret_version`: refreshing a version calls
  # GetSecretValue. With the deny in force the plan errored on every run, so
  # KSI-SVC-ACM's drift signal did not exist at all -- the control was
  # blocked by a guard protecting a claim it could not keep.
  #
  # Scoped to the single secret Terraform holds a version of, and the
  # decrypt is further conditioned on the call arriving through Secrets
  # Manager rather than directly against the key.
  #
  # What this costs, stated rather than buried: the drift principal can read
  # the task TLS private key. That is accepted because the certificate is
  # self-signed, Terraform generates it itself on every apply, and the
  # task-side TLS hop is already a declared stopgap under KSI-SVC-ASM. It
  # would not be acceptable for a secret the project did not generate.
  statement {
    sid       = "ReadTheOneSecretVersionInState"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.task_tls.arn]
  }

  statement {
    sid       = "DecryptThatSecretOnly"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.secrets.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }

  # The original guard, kept and narrowed rather than deleted.
  #
  # Its intent was that a later widening of the read grant above could not
  # quietly pick up secret values. That intent still holds for every secret
  # but the one named above -- including the RDS-managed master password,
  # which is the genuinely sensitive one in this account and which nothing
  # here has any reason to read.
  statement {
    sid           = "NeverReadAnyOtherSecretValue"
    effect        = "Deny"
    actions       = ["secretsmanager:GetSecretValue"]
    not_resources = [aws_secretsmanager_secret.task_tls.arn]
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
