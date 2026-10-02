#!/usr/bin/env bash
# Deletes the default VPC in every region of the account (DECISIONS.md, 2026-10-02).
#
# AWS creates one per region. Nothing in this project uses them, they are
# outside Terraform and outside the Config recorder (us-east-1 only), and
# their default security groups allow all egress, so anything launched
# without naming a VPC lands in one with a public IP, unwatched.
#
# Safe by construction: a VPC with any network interface is refused, never
# touched, so something running there cannot be cut off. Idempotent: a
# region with no default VPC is skipped. Reversible per region with
# `aws ec2 create-default-vpc --region <region>`.
#
# Run as the operator: AWS_PROFILE=caliper-admin ./delete_default_vpcs.sh
set -euo pipefail

for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  vpc=$(aws ec2 describe-vpcs --region "$region" --filters Name=isDefault,Values=true \
        --query 'Vpcs[0].VpcId' --output text)
  if [ "$vpc" = "None" ]; then
    echo "$region: no default VPC"
    continue
  fi

  enis=$(aws ec2 describe-network-interfaces --region "$region" --filters Name=vpc-id,Values="$vpc" \
         --query 'length(NetworkInterfaces)' --output text)
  if [ "$enis" != "0" ]; then
    echo "$region: $vpc has $enis network interface(s); refused, left in place"
    continue
  fi

  for igw in $(aws ec2 describe-internet-gateways --region "$region" \
               --filters Name=attachment.vpc-id,Values="$vpc" \
               --query 'InternetGateways[].InternetGatewayId' --output text); do
    aws ec2 detach-internet-gateway --region "$region" --internet-gateway-id "$igw" --vpc-id "$vpc"
    aws ec2 delete-internet-gateway --region "$region" --internet-gateway-id "$igw"
  done

  for subnet in $(aws ec2 describe-subnets --region "$region" --filters Name=vpc-id,Values="$vpc" \
                  --query 'Subnets[].SubnetId' --output text); do
    aws ec2 delete-subnet --region "$region" --subnet-id "$subnet"
  done

  # The default security group, network ACL and main route table go with it.
  aws ec2 delete-vpc --region "$region" --vpc-id "$vpc"
  echo "$region: deleted $vpc"
done
