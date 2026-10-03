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

# Inactive task definition revisions older than 30 days (2026-10-03, the
# lean retention set, registers/retention.yaml). ECS keeps every revision it
# ever registered; the recent ones are the prior baseline KSI-RPL-ABO counts
# on, the old ones are residue. Only INACTIVE revisions can be deleted, so
# nothing a service could still run is touched.
echo "==> deleting inactive task definition revisions older than 30 days"
cutoff=$(( $(date +%s) - 30 * 86400 ))
old=()
for arn in $(aws ecs list-task-definitions --status INACTIVE --query 'taskDefinitionArns' --output text); do
  registered=$(aws ecs describe-task-definition --task-definition "$arn" \
               --query 'taskDefinition.registeredAt' --output text | cut -d. -f1)
  registered=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${registered%%[+-]??:??}" +%s 2>/dev/null \
               || date -d "$registered" +%s)
  [[ "$registered" -lt "$cutoff" ]] && old+=("$arn")
done
for ((i = 0; i < ${#old[@]}; i += 10)); do
  aws ecs delete-task-definitions --task-definitions "${old[@]:i:10}" --query 'failures' --output text
done
echo "    ${#old[@]} deleted"

echo
# Generated, not written out: a hand-kept list here named seven things
# after the persistent set had grown to sixty-eight (found 2026-09-25, the
# same fault drift.yml's summary had).
echo "==> torn down. Preserved: $(./boundary.py --persistent | wc -l | tr -d ' ') resources declared in:"
echo "    $(./boundary.py --files)"
echo "==> any customer-managed keys destroyed are now in PendingDeletion for seven days."
