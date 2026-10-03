#!/usr/bin/env bash
# Restores the database to a point in time, into a new instance, and times it.
#
# The encoded recovery path for AWS::RDS::DBInstance (registers/recovery-paths.yaml)
# and the restore KSI-RPL-TRC times (written 2026-10-03). The elapsed time it
# prints is the measured recovery time the 60-minute objective in
# registers/resources.yaml is held to.
#
# Restores from the live instance if it exists, otherwise from its retained
# automated backups -- the case between sessions, when the instance is gone.
# Either way the new instance lands in the project's own subnet group and
# security group, under the persistent database key, not publicly accessible.
# Phase 1 must be standing: the subnet group and security group are its.
#
#   AWS_PROFILE=caliper-admin ./restore_database.sh                 # latest restorable time
#   AWS_PROFILE=caliper-admin ./restore_database.sh 2026-10-20T14:00:00Z
#
# The restored instance is disposable: delete it when the test is recorded.
set -euo pipefail

source_id="fedramp-20x-ksi"
target_id="fedramp-20x-ksi-restore-$(date -u +%Y%m%d%H%M)"
region="us-east-1"
when=("--use-latest-restorable-time")
[[ $# -ge 1 ]] && when=("--restore-time" "$1")

sg=$(aws ec2 describe-security-groups --region "$region" --filters Name=group-name,Values=fedramp-20x-ksi-database \
     --query 'SecurityGroups[0].GroupId' --output text)
[[ "$sg" == "None" ]] && { echo "phase 1 is not standing: no database security group"; exit 1; }

if aws rds describe-db-instances --region "$region" --db-instance-identifier "$source_id" >/dev/null 2>&1; then
  source=("--source-db-instance-identifier" "$source_id")
else
  arn=$(aws rds describe-db-instance-automated-backups --region "$region" --db-instance-identifier "$source_id" \
        --query 'DBInstanceAutomatedBackups[0].DBInstanceAutomatedBackupsArn' --output text)
  [[ "$arn" == "None" ]] && { echo "no instance and no retained backups to restore from"; exit 1; }
  source=("--source-db-instance-automated-backups-arn" "$arn")
fi

start=$(date +%s)
echo "==> restoring ${source[1]} to $target_id (${when[*]})"
aws rds restore-db-instance-to-point-in-time --region "$region" "${source[@]}" "${when[@]}" \
  --target-db-instance-identifier "$target_id" \
  --db-subnet-group-name fedramp-20x-ksi \
  --db-parameter-group-name fedramp-20x-ksi \
  --vpc-security-group-ids "$sg" \
  --db-instance-class db.t4g.small \
  --no-publicly-accessible \
  --enable-iam-database-authentication \
  --no-multi-az \
  --query 'DBInstance.DBInstanceIdentifier' --output text
aws rds wait db-instance-available --region "$region" --db-instance-identifier "$target_id"
elapsed=$(( $(date +%s) - start ))

echo "==> $target_id available after $((elapsed / 60))m $((elapsed % 60))s"
aws rds describe-db-instances --region "$region" --db-instance-identifier "$target_id" \
  --query 'DBInstances[0].[DBInstanceStatus,KmsKeyId,StorageEncrypted,LatestRestorableTime]' --output text
echo "==> record the elapsed time against the 60-minute objective, then delete:"
echo "    aws rds delete-db-instance --region $region --db-instance-identifier $target_id --skip-final-snapshot --delete-automated-backups"
