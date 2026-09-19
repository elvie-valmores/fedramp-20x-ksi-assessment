"""Reads the live AWS resource inventory out of AWS Config.

AWS Config continuously records the configuration of resources in the
account. Rather than calling each service's own list API (s3:ListBuckets,
rds:DescribeDBInstances, and so on), this queries Config's single
SelectResourceConfig endpoint, which accepts a SQL-like expression and
answers across every resource type it records.

Every call hits the API. Nothing is cached, because a cached inventory
answers "what existed last time we looked," and the question being asked
is "what exists now."

Design note: Config is treated as authoritative over Terraform state.
State describes what was declared; Config describes what is actually
there, including anything created outside Terraform.
"""

from __future__ import annotations

import json
from typing import Iterator

import boto3

DEFAULT_REGION = "us-east-1"

# Must mirror the recorder's scope in infra/aws/inventory.tf. Config only
# answers for types it was told to record, so a type listed here but not
# recorded there returns zero rows and looks like "none exist" rather
# than "never watched." Change one list, change the other.
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
    """Yield every Config record of one resource type.

    The expression is Config's own SQL dialect, evaluated server-side.
    Results come back one page at a time, so a paginator walks the
    continuation tokens instead of the caller handling them.
    """
    expression = (
        "SELECT resourceId, resourceName, resourceType, awsRegion, "
        "availabilityZone, tags, resourceCreationTime "
        f"WHERE resourceType = '{resource_type}'"
    )

    paginator = client.get_paginator("select_resource_config")
    for page in paginator.paginate(Expression=expression):
        # Each row arrives as a JSON *string*, not a parsed object --
        # Config returns it that way because the shape differs per
        # resource type. Hence a second decode per row.
        for row in page["Results"]:
            yield json.loads(row)


def generate(region: str = DEFAULT_REGION) -> list[dict]:
    """Return every recorded AWS resource, in the shared cross-cloud shape.

    Field names here match gcp_source.generate() exactly, so the two
    lists concatenate into one inventory with no merge or translation
    step in between.
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
