#!/usr/bin/env bash
#
# Scoped teardown of the AWS application environment.
#
# The cost posture is apply-and-destroy: roughly 115 to 125 USD per month if
# the environment is left standing, dominated by the load balancer, RDS and
# six interface endpoints. Between sessions it comes down. This script is how.
#
# WHY THIS IS NOT `terraform destroy`
#
# A blanket destroy is refused. `aws_s3_bucket.log_store` carries
# `prevent_destroy = true`, so Terraform aborts the whole plan rather than
# skipping that one resource:
#
#   Error: Instance cannot be destroyed
#   Resource aws_s3_bucket.log_store has lifecycle.prevent_destroy set...
#
# That guard is correct and must not be removed. The log store is the audit
# record, it carries Object Lock in compliance mode, and it is meant to
# outlive every rebuild. So the teardown is scoped with -target instead.
#
# THE PERSISTENCE BOUNDARY
#
# Five files hold everything that survives; everything else is rebuilt on the
# next apply. `boundary.py` derives both halves from that split and is shared
# with the drift workflow, which checks the half this script does not touch.
#
# WHAT IT LEAVES BEHIND
#
# Four customer-managed KMS keys enter PendingDeletion for seven days and
# bill about 1 USD each until they clear. They are not recovered by the next
# apply -- it creates new ones. The log store is encrypted with SSE-S3, not
# with those keys, so scheduling them for deletion never orphans the audit
# record. That is deliberate; check it still holds before changing kms.tf.

set -euo pipefail
cd "$(dirname "$0")"

: "${TF_VAR_billing_alert_email:?set TF_VAR_billing_alert_email}"

echo "==> deriving the target list from the persistence boundary"

# boundary.py owns the split, because drift.yml consumes the other half of
# it and the two must agree. See the header of that file.
targets=$(./boundary.py --ephemeral)

count=$(printf '%s\n' "$targets" | grep -c . || true)
if [[ "$count" -eq 0 ]]; then
  echo "==> nothing outside the persistence boundary is in state; already torn down"
  exit 0
fi
echo "==> ${count} resources to destroy; the persistence boundary keeps the rest"

printf '%s\n' "$targets" | sed 's/^/-target=/' | tr '\n' '\0' \
  > .teardown.args

xargs -0 terraform plan -destroy -input=false -out=.teardown.tfplan < .teardown.args

echo
echo "==> review the plan above. Nothing from these files should appear:"
echo "    $(./boundary.py --files)"
echo
read -r -p "apply this teardown? [y/N] " reply
[[ "$reply" == "y" || "$reply" == "Y" ]] || { echo "aborted"; rm -f .teardown.args .teardown.tfplan; exit 1; }

terraform apply -input=false .teardown.tfplan
rm -f .teardown.args .teardown.tfplan

echo
echo "==> torn down. Preserved: log store, Athena, Glue, CloudTrail, Config"
echo "    recorder, both Lambdas, the budget guardrail."
echo "==> four KMS keys are now in PendingDeletion for seven days."
