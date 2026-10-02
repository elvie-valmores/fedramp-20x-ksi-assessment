"""Whether an ephemeral environment is standing, for checks that need it.

The AWS application environment is applied for a session and destroyed
after it (DECISIONS.md, 2026-09-05). A check that reads a route table or a
task definition has nothing to read most days, and failing it daily would
bury real failures in expected ones. So such a check names its environment
in requires_environment, and run_checks.py records it NOT_STANDING, not
judged, when the environment is down.

The danger is a gate that hides a failure. Two rules close it:

  - Standing means any anchor exists, not all. An environment half torn
    down, or half applied, is standing, so every check runs and the
    missing pieces fail rather than skip.
  - A lookup that errors is an error, never "not standing". Only a clean
    "not found" from every anchor's API makes the environment absent.
"""

from __future__ import annotations

from functools import lru_cache

import boto3

REGION = "us-east-1"
NAME = "fedramp-20x-ksi"


def _vpc() -> bool:
    vpcs = boto3.client("ec2", region_name=REGION).describe_vpcs(
        Filters=[{"Name": "tag:Name", "Values": [NAME]}])["Vpcs"]
    return bool(vpcs)


def _cluster() -> bool:
    clusters = boto3.client("ecs", region_name=REGION).describe_clusters(clusters=[NAME])["clusters"]
    return any(c["status"] == "ACTIVE" for c in clusters)


def _load_balancer() -> bool:
    elb = boto3.client("elbv2", region_name=REGION)
    try:
        return bool(elb.describe_load_balancers(Names=[NAME])["LoadBalancers"])
    except elb.exceptions.LoadBalancerNotFoundException:
        return False


def _database() -> bool:
    rds = boto3.client("rds", region_name=REGION)
    try:
        return bool(rds.describe_db_instances(DBInstanceIdentifier=NAME)["DBInstances"])
    except rds.exceptions.DBInstanceNotFoundFault:
        return False


def _services() -> bool:
    ecs = boto3.client("ecs", region_name=REGION)
    if not _cluster():
        return False
    services = ecs.describe_services(cluster=NAME, services=["api", "worker"])["services"]
    return any(s["status"] == "ACTIVE" for s in services)


ANCHORS = {
    # Phase 1: the network, edge, database and cluster.
    "aws-phase1": {"vpc": _vpc, "ecs_cluster": _cluster, "load_balancer": _load_balancer, "database": _database},
    # Phase 2: the services, which need images by digest.
    "aws-phase2": {"ecs_services": _services},
}


def evaluate_standing(found: dict[str, bool]) -> bool:
    """Standing if any anchor exists. Pure, for self_test.py."""
    return any(found.values())


@lru_cache(maxsize=None)
def standing(environment: str) -> tuple[bool, tuple[str, ...]]:
    """(standing, the anchors found). Raises on any lookup error."""
    if environment not in ANCHORS:
        raise ValueError(f"unknown environment {environment!r}")
    found = {name: lookup() for name, lookup in ANCHORS[environment].items()}
    return evaluate_standing(found), tuple(n for n, ok in found.items() if ok)
