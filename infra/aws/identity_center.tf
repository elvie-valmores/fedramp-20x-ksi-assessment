# The operator's way into AWS: a Google sign-in through Identity Center,
# replacing the terraform-admin IAM user's static access key.
#
# Persistent (see boundary.py). The operator has to be able to sign in while
# the application environment is down, since that is when it gets applied.
#
# This is a standing grant to the platform engineer, and KSI-IAM-JIT says the
# platform engineer holds none. It does not open a new exception. It moves an
# existing one to a better identity: DECISIONS.md, 2026-09-19, lets a human
# identity keep apply until KSI-IAM-JIT build step 5 lands, because the
# elevation workflow is deployed by the pipeline it would gate. Until
# 2026-09-29 that identity was an IAM user with a key that never expired and
# no MFA. It is now a four-hour session behind a passkey. When the elevation
# workflow exists, the assignment below goes and this permission set becomes
# an elevated one, assigned only for the length of an elevation.
#
# The user is created by hand, not by SCIM, which needs Cloud Identity
# Premium. That is recorded as an exception too (DECISIONS.md, 2026-09-29).
# Only the user is by hand. The permission set and the assignment are here,
# per the 2026-09-05 decision that assignments are declared.

data "aws_ssoadmin_instances" "main" {}

locals {
  sso_instance_arn  = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.main.identity_store_ids)[0]
}

resource "aws_ssoadmin_permission_set" "interim_operator_admin" {
  name         = "InterimOperatorAdmin"
  description  = "Operator apply under the CMT-RMV exception; closes at KSI-IAM-JIT build step 5"
  instance_arn = local.sso_instance_arn

  # Long enough that a phase 1 and phase 2 apply followed by a teardown fits
  # in one session. A credential that expires mid-apply leaves a held state
  # lock and a partial state, and that is worse than a longer session.
  session_duration = "PT4H"

  tags = {
    Component = "identity"
  }
}

# A managed policy, which KSI-IAM-ELP's role model rules out. The role model
# is five scoped roles, and this is none of them: applying this root creates
# and deletes IAM, KMS, networking and Organizations-adjacent resources, so
# anything narrower would be a list of everything. The exception is the
# honest name for that, not a hand-written copy of AdministratorAccess.
resource "aws_ssoadmin_managed_policy_attachment" "interim_operator_admin" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.interim_operator_admin.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Looked up by name, so a plan fails loudly if the user is ever deleted
# rather than leaving an assignment to a principal that no longer exists.
data "aws_identitystore_user" "alex" {
  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "UserName"
      attribute_value = "alex@corp.elvievalmores.com"
    }
  }
}

resource "aws_ssoadmin_account_assignment" "alex_interim_operator_admin" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.interim_operator_admin.arn

  principal_type = "USER"
  principal_id   = data.aws_identitystore_user.alex.user_id

  target_type = "AWS_ACCOUNT"
  target_id   = data.aws_caller_identity.current.account_id
}
