"""Mechanism: ask a cloud API what a resource is actually configured as.

Used for evidence of the form "this security control is switched on."
Each supported resource gets its own handler method, because "is it on?"
means something different per service -- a Config recorder has a
recording flag, an asset feed has a list of watched types.

Check params:
    provider  "aws" or "gcp"
    resource  which handler to use, e.g. "config_recorder"
    ...       plus whatever that handler needs (see each method)

Params are required rather than defaulted. A check definition records
*what was checked*, and a hidden default would leave that unstated.

Handlers added from 2026-09-23 split in two: a fetch that calls the API,
and a pure evaluate_* function that judges what was fetched. The split is
so self_test.py can hand each judgement a configuration that should fail
it -- the earlier handlers predate that and have no negative control yet.

The bucket handlers take their population from s3:ListBuckets rather than
from a list in the check. "Every bucket" is the claim, and a list in the
check would make it "every bucket someone remembered to add".
"""

from __future__ import annotations

import json

import boto3

import _paths  # noqa: F401  (puts inventory/ on the import path)
from base import CheckDefinition, CheckResult, Mechanism
from gcp_auth import asset_client


class CloudAPIConfigRead(Mechanism):
    name = "cloud_api_config_read"

    def run(self, check: CheckDefinition) -> CheckResult:
        provider = check.params["provider"]
        resource = check.params["resource"]

        if provider == "aws" and resource == "config_recorder":
            return self._aws_config_recorder(check)
        if provider == "gcp" and resource == "cloud_asset_feed":
            return self._gcp_asset_feed(check)
        if provider == "aws" and resource == "s3_buckets_deny_insecure_transport":
            return self._each_bucket(check, _fetch_bucket_policy, evaluate_tls_only)
        if provider == "aws" and resource == "s3_buckets_block_public_access":
            return self._each_bucket(check, _fetch_public_access_block, evaluate_public_access_blocked)
        if provider == "aws" and resource == "s3_object_lock":
            return self._s3_object_lock(check)
        if provider == "aws" and resource == "cloudtrail_log_file_validation":
            return self._cloudtrail_log_file_validation(check)

        raise NotImplementedError(
            f"cloud_api_config_read has no handler for provider={provider!r} "
            f"resource={resource!r} yet -- add one as new checks need it."
        )

    def _aws_config_recorder(self, check: CheckDefinition) -> CheckResult:
        """Passes if a Config recorder exists and is actively recording.

        Requires param: region.

        AWS splits this across two calls: one describes the recorders
        that are configured, the other reports whether each is running.
        A recorder that exists but is stopped collects nothing, so both
        have to be checked.
        """
        client = boto3.client("config", region_name=check.params["region"])

        recorders = client.describe_configuration_recorders()["ConfigurationRecorders"]
        statuses = {
            status["name"]: status
            for status in client.describe_configuration_recorder_status()[
                "ConfigurationRecordersStatus"
            ]
        }
        evidence = {"recorders": recorders, "statuses": statuses}

        if not recorders:
            return CheckResult(check.id, False, evidence, "no Config recorder exists")

        recording = all(
            statuses.get(recorder["name"], {}).get("recording", False)
            for recorder in recorders
        )
        return CheckResult(
            check.id,
            recording,
            evidence,
            "recorder present and recording"
            if recording
            else "recorder exists but is not recording",
        )

    def _gcp_asset_feed(self, check: CheckDefinition) -> CheckResult:
        """Passes if the named asset feed exists and watches at least one type.

        Requires params: project_id, feed_id.

        A feed watching zero asset types is configured but inert, so the
        asset_types list is what actually gets asserted on.
        """
        project_id = check.params["project_id"]
        feed_id = check.params["feed_id"]
        client = asset_client(project_id)

        # Feeds are fetched by listing rather than by direct lookup:
        # get_feed() needs the project's *numeric* ID, and list_feeds()
        # is what reveals the number-to-name mapping in the first place.
        try:
            feeds = client.list_feeds(parent=f"projects/{project_id}").feeds
        except Exception as exc:
            return CheckResult(
                check.id, False, {"error": str(exc)}, "could not list feeds"
            )

        feed = next((f for f in feeds if f.name.endswith(f"/feeds/{feed_id}")), None)
        if feed is None:
            return CheckResult(
                check.id,
                False,
                {"feeds_found": [f.name for f in feeds]},
                "feed not found",
            )

        watches_types = bool(feed.asset_types)
        return CheckResult(
            check.id,
            watches_types,
            {"name": feed.name, "asset_types": list(feed.asset_types)},
            "feed exists with asset types configured"
            if watches_types
            else "feed exists but tracks no asset types",
        )

    def _each_bucket(self, check: CheckDefinition, fetch, evaluate) -> CheckResult:
        """Run one judgement over every bucket in the account.

        Requires param: region.

        Passes only if every bucket passes, and fails on an empty account --
        a claim about every bucket is not supported by zero buckets.
        """
        client = boto3.client("s3", region_name=check.params["region"])
        names = sorted(b["Name"] for b in client.list_buckets()["Buckets"])

        results = {}
        for name in names:
            ok, detail = evaluate(fetch(client, name))
            results[name] = {"passed": ok, "detail": detail}

        failing = sorted(n for n, r in results.items() if not r["passed"])
        evidence = {"buckets": results, "failing": failing}
        if not names:
            return CheckResult(check.id, False, evidence, "no buckets found -- nothing to judge")
        if failing:
            return CheckResult(
                check.id, False, evidence,
                f"{len(failing)} of {len(names)} buckets fail: {', '.join(failing)}",
            )
        return CheckResult(check.id, True, evidence, f"all {len(names)} buckets pass")

    def _s3_object_lock(self, check: CheckDefinition) -> CheckResult:
        """Passes if the bucket has Object Lock on with the required default.

        Requires params: region, bucket, mode, min_days.
        """
        client = boto3.client("s3", region_name=check.params["region"])
        try:
            config = client.get_object_lock_configuration(Bucket=check.params["bucket"])
            config = config["ObjectLockConfiguration"]
        except client.exceptions.ClientError as exc:
            config = {"error": exc.response["Error"]["Code"]}
        ok, detail = evaluate_object_lock(config, check.params["mode"], check.params["min_days"])
        return CheckResult(check.id, ok, {"bucket": check.params["bucket"], "config": config}, detail)

    def _cloudtrail_log_file_validation(self, check: CheckDefinition) -> CheckResult:
        """Passes if the named trail exists, is logging, and validates log files.

        Requires params: region, trail.

        Validation on a trail that is not logging signs nothing, so the
        logging status is part of the judgement rather than a separate check.
        """
        client = boto3.client("cloudtrail", region_name=check.params["region"])
        trails = client.describe_trails(trailNameList=[check.params["trail"]])["trailList"]
        status = client.get_trail_status(Name=check.params["trail"]) if trails else {}
        ok, detail = evaluate_trail_validation(trails[0] if trails else None, status)
        evidence = {
            "trail": trails[0] if trails else None,
            "is_logging": status.get("IsLogging"),
        }
        return CheckResult(check.id, ok, evidence, detail)


# --- fetches ---


def _fetch_bucket_policy(client, name: str):
    try:
        return json.loads(client.get_bucket_policy(Bucket=name)["Policy"])
    except client.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return None
        raise


def _fetch_public_access_block(client, name: str):
    try:
        return client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except client.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return None
        raise


# --- judgements ---
#
# Pure: configuration in, (passed, detail) out.


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def evaluate_tls_only(policy: dict | None) -> tuple[bool, str]:
    """A Deny on every principal and every S3 action when the request is not
    TLS, covering the bucket and its objects.

    Each part is checked because each has a way to be subtly wrong: an
    Allow conditioned on TLS permits nothing on its own, a deny scoped to
    one principal leaves the rest, s3:GetObject leaves ListBucket, and a
    resource of only bucket/* leaves the bucket-level calls.
    """
    if not policy:
        return False, "no bucket policy"
    for statement in _as_list(policy.get("Statement", [])):
        if statement.get("Effect") != "Deny":
            continue
        principal = statement.get("Principal")
        if principal not in ("*", {"AWS": "*"}):
            continue
        if "s3:*" not in _as_list(statement.get("Action", [])):
            continue
        condition = statement.get("Condition", {}).get("Bool", {})
        if [str(v).lower() for v in _as_list(condition.get("aws:SecureTransport", []))] != ["false"]:
            continue
        resources = _as_list(statement.get("Resource", []))
        bucket_level = [r for r in resources if not r.endswith("/*")]
        object_level = [r for r in resources if r.endswith("/*")]
        if bucket_level and object_level:
            return True, f"denies non-TLS requests ({statement.get('Sid', 'unnamed statement')})"
    return False, "no statement denies all non-TLS requests to the bucket and its objects"


def evaluate_public_access_blocked(config: dict | None) -> tuple[bool, str]:
    """All four settings on. Each closes a different path, so three is not
    most of the way -- it is one path open."""
    settings = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    if not config:
        return False, "no public access block on the bucket"
    off = [k for k in settings if not config.get(k)]
    if off:
        return False, f"off: {', '.join(off)}"
    return True, "all four public access settings on"


def evaluate_object_lock(config: dict, mode: str, min_days: int) -> tuple[bool, str]:
    if config.get("ObjectLockEnabled") != "Enabled":
        return False, f"object lock not enabled ({config.get('error', 'disabled')})"
    retention = config.get("Rule", {}).get("DefaultRetention", {})
    # A lock with no default retention protects only objects written with
    # an explicit retention header, which nothing here sends.
    if retention.get("Mode") != mode:
        return False, f"default retention mode is {retention.get('Mode')!r}, expected {mode!r}"
    days = retention.get("Days") or (retention.get("Years", 0) * 365)
    if days < min_days:
        return False, f"default retention is {days} days, expected at least {min_days}"
    return True, f"object lock {mode} with {days}-day default retention"


def evaluate_trail_validation(trail: dict | None, status: dict) -> tuple[bool, str]:
    if trail is None:
        return False, "trail not found"
    if not status.get("IsLogging"):
        return False, "trail exists but is not logging"
    if not trail.get("LogFileValidationEnabled"):
        return False, "log file validation is off"
    return True, "trail logging with log file validation"

