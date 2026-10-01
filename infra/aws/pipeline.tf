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
  # requires being able to encrypt under it -- through ECR only. Until
  # 2026-10-01 this had no condition, so the build role could decrypt any
  # artifacts-key ciphertext, the worker's extracts included, given read on
  # them; svc-sin-cfg-aws-keys-decrypt-only-declared resolved it as an
  # unconditioned decrypt. Narrowed, then proven by a CI build that pushed
  # and signed under the narrowed grant (DECISIONS.md, 2026-10-01).
  statement {
    sid    = "EncryptImageLayers"
    effect = "Allow"

    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    resources = [aws_kms_key.artifacts.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ecr.${data.aws_region.current.name}.amazonaws.com"]
    }
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

# Lives here rather than beside the drift role's output, because it names a
# resource declared here. Moved on 2026-09-22 after the persistence-boundary
# check caught it referencing across the split -- the output was carried into
# pipeline_identity.tf when that file was created, and an output is a
# reference like any other.
output "github_build_role_arn" {
  description = "Assumed by the build workflow. Set as the AWS_BUILD_ROLE repository variable."
  value       = aws_iam_role.github_build.arn
}
