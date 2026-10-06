# The operator's way into AWS: a Google sign-in through Identity Center,
# replacing the terraform-admin IAM user's static access key (2026-09-29).
#
# Persistent (see boundary.py). The operator has to be able to sign in while
# the application environment is down, since that is when it gets applied.
#
# The permission sets themselves are in elevation.tf: OperatorReadOnly,
# standing, and ElevatedAdmin, assigned only for an elevation. This file
# holds the instance and the user they are assigned to.
#
# The user is created by hand, not by SCIM, which needs Cloud Identity
# Premium (DECISIONS.md, 2026-09-29; SCIM descoped 2026-10-03).

data "aws_ssoadmin_instances" "main" {}

locals {
  sso_instance_arn  = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.main.identity_store_ids)[0]
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

# InterimOperatorAdmin, standing AdministratorAccess from 2026-09-29, lost
# its assignment on 2026-10-05 once just-in-time elevation was proven, and
# the permission set itself was deleted at the next session (DECISIONS.md).
