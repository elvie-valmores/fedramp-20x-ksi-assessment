# Account-wide guardrails: settings that apply to everything in the account
# rather than to any one resource.
#
# Persistent (see boundary.py). A guardrail that went down with the
# application environment would be off for most of every week, which is
# the shape of the extract bucket's policy problem found on 2026-09-23.

# KSI-SVC-SIN build row 4, "public access block on all S3", at the level
# where "all" is actually enforced. Every bucket here already blocks public
# access individually, and the collector checks that. What this adds is the
# bucket nobody has created yet: without it, a new bucket's protection
# depends on whoever writes it remembering the four settings.
#
# Nothing in this project serves from a public bucket. security.txt is a
# fixed response on the load balancer, not an object in S3, so there is no
# path this closes that anything uses.
resource "aws_s3_account_public_access_block" "main" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Security Hub SSM.7, which was failing (DECISIONS.md, 2026-09-30). Nothing
# here uses SSM documents, and that is the point: the default lets anyone
# with ssm:ModifyDocumentPermission share a document publicly, and a shared
# document can carry commands, parameters and account details. The block
# costs nothing and closes a path before anything uses it.
resource "aws_ssm_service_setting" "document_public_sharing" {
  setting_id    = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:servicesetting/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}
