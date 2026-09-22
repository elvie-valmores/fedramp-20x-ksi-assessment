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
# THE PERSISTENCE BOUNDARY IS THE FILE SPLIT
#
# Five files hold everything that survives a teardown, and -- verified, not
# assumed -- nothing in them references a resource declared outside them.
# The evidence layer has no dependency on the application environment, which
# is what makes a clean scoped teardown possible at all:
#
#   log_corpus.tf         the Object Locked store, Athena, Glue
#   log_normalization.tf  the OCSF normalization Lambda
#   detection.tf          the detection query Lambda and its alarms
#   inventory.tf          CloudTrail and the Config recorder
#   billing.tf            the budget guardrail
#
# Everything else is the application environment and is rebuilt on the next
# apply. Derive the target list from that split rather than maintaining a
# hand-written list that silently rots as resources are added.
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

KEEP="log_corpus.tf log_normalization.tf detection.tf inventory.tf billing.tf"

: "${TF_VAR_billing_alert_email:?set TF_VAR_billing_alert_email}"

echo "==> deriving the target list from the persistence boundary"

targets=$(python3 - "$KEEP" <<'PY'
import glob, re, subprocess, sys

keep = set(sys.argv[1].split())

# (type, name) -> declaring file
declared = {}
for path in glob.glob("*.tf"):
    for m in re.finditer(r'^resource\s+"([^"]+)"\s+"([^"]+)"', open(path).read(), re.M):
        declared[(m.group(1), m.group(2))] = path

addresses = subprocess.run(
    ["terraform", "state", "list"], capture_output=True, text=True, check=True
).stdout.split()

unmapped, targets = [], []
for address in addresses:
    if address.startswith("data."):
        continue
    m = re.match(r"^([a-z0-9_]+)\.([A-Za-z0-9_-]+)", address)
    path = declared.get((m.group(1), m.group(2))) if m else None
    if path is None:
        unmapped.append(address)
    elif path not in keep:
        targets.append(address)

# A resource in state that no .tf declares is drift, an orphan, or a rename.
# Guessing which is not this script's job -- stop and let a human look.
if unmapped:
    sys.exit("unmapped resources in state, refusing to guess:\n  " + "\n  ".join(unmapped))

print("\n".join(targets))
PY
)

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
echo "    ${KEEP}"
echo
read -r -p "apply this teardown? [y/N] " reply
[[ "$reply" == "y" || "$reply" == "Y" ]] || { echo "aborted"; rm -f .teardown.args .teardown.tfplan; exit 1; }

terraform apply -input=false .teardown.tfplan
rm -f .teardown.args .teardown.tfplan

echo
echo "==> torn down. Preserved: log store, Athena, Glue, CloudTrail, Config"
echo "    recorder, both Lambdas, the budget guardrail."
echo "==> four KMS keys are now in PendingDeletion for seven days."
