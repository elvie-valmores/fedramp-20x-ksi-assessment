# The grants on the persistent stores, which are not themselves persistent.
#
# Split out of registry.tf on 2026-09-22. The registry and the extract bucket
# moved to the persistent side of boundary.py so that images survive a
# teardown; these policies did not, and the split is the point rather than an
# artefact of it.
#
# THE STORE PERSISTS, THE GRANTS TO TRANSIENT PRINCIPALS DO NOT
#
# The repository policy names a role from compute.tf -- task_execution may
# pull images -- and that role exists only while the application environment
# does. A policy naming a deleted role is not an error, but a policy that
# Terraform cannot compute is: the reference needs the role in state.
#
# So a repository outlives the roles permitted to pull from it, and the
# permission reappears with them. That is the same shape as the artifacts key
# next door, which persists while its per-role grants moved to IAM, and as
# pipeline_identity.tf, which persists while the build role does not.
#
# The extract bucket's policy used to live here too, and it held protections
# as well as a grant, so the protections went down with the grant. Its
# protections are now in registry.tf; the grant half -- worker writes only
# through the VPC endpoint -- is in the worker role's policy in compute.tf.
# Only grants belong in this file. See DECISIONS.md, 2026-09-23.
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
