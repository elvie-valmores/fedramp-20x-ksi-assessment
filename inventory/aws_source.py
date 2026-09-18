"""AWS half of the KSI-PIY-GIV inventory generator.

Queries AWS Config's SelectResourceConfig API directly at call time — no
cached intermediate. Config is the authoritative source (see
docs/KSI-Design-Matrix.xlsx, PIY tab, KSI-PIY-GIV design rationale):
Terraform state describes intent and drifts from reality, whereas Config
reports what actually exists.

Resource types queried must stay in sync with the recorder scope in
infra/aws/inventory.tf (docs/DECISIONS.md, 2026-09-05, "Config recorder
scoped for cost, with the coverage consequence stated"). A type present
here but not recorded there returns nothing, silently — that's a real
failure mode, not a hypothetical, which is why the two lists are kept in
one place in a real refactor. For now: change one, change the other.
"""

from __future__ import annotations

import json
from typing import Iterator

import boto3

RESOURCE_TYPES = [
    "AWS::S3::Bucket",
    "AWS::IAM::User",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::KMS::Key",
    "AWS::EC2::VPC",
    "AWS::EC2::Subnet",
    "AWS::EC2::SecurityGroup",
    "AWS::ECS::Cluster",
    "AWS::ECS::Service",
    "AWS::ECS::TaskDefinition",
    "AWS::RDS::DBInstance",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::WAFv2::WebACL",
    "AWS::SecretsManager::Secret",
    "AWS::CloudTrail::Trail",
    "AWS::ECR::Repository",
]


def _query_resource_type(client, resource_type: str) -> Iterator[dict]:
    expression = (
        "SELECT resourceId, resourceName, resourceType, awsRegion, "
        "availabilityZone, tags, resourceCreationTime "
        f"WHERE resourceType = '{resource_type}'"
    )
    paginator = client.get_paginator("select_resource_config")
    for page in paginator.paginate(Expression=expression):
        for raw in page["Results"]:
            yield json.loads(raw)


def generate(region: str = "us-east-1") -> list[dict]:
    """Query AWS Config live and return a normalized resource list.

    Each entry uses the same shape gcp_source.generate() produces, so the
    two can be concatenated into one cross-cloud inventory without a
    separate merge step.
    """
    client = boto3.client("config", region_name=region)
    resources = []
    for resource_type in RESOURCE_TYPES:
        for record in _query_resource_type(client, resource_type):
            resources.append(
                {
                    "cloud": "aws",
                    "resource_id": record.get("resourceId"),
                    "resource_type": record.get("resourceType"),
                    "name": record.get("resourceName"),
                    "location": record.get("awsRegion"),
                    "tags": record.get("tags") or {},
                    "created_at": record.get("resourceCreationTime"),
                }
            )
    return resources
