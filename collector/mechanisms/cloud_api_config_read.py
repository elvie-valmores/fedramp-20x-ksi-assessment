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

import fnmatch
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
        if provider == "aws" and resource == "s3_account_public_access_block":
            return self._s3_account_public_access_block(check)
        if provider == "gcp" and resource == "basic_roles":
            return self._gcp_basic_roles(check)
        if provider == "aws" and resource == "store_encryption_keys":
            return self._store_encryption_keys(check)

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


    def _s3_account_public_access_block(self, check: CheckDefinition) -> CheckResult:
        """Passes if the account-level block has all four settings on.

        Requires params: region, account_id.

        The per-bucket check covers the buckets that exist; this covers the
        ones that do not yet. Same judgement as the per-bucket one.
        """
        client = boto3.client("s3control", region_name=check.params["region"])
        try:
            config = client.get_public_access_block(AccountId=check.params["account_id"])
            config = config["PublicAccessBlockConfiguration"]
        except client.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
            config = None
        ok, detail = evaluate_public_access_blocked(config)
        return CheckResult(check.id, ok, {"account_block": config}, detail)

    def _gcp_basic_roles(self, check: CheckDefinition) -> CheckResult:
        """Passes if every basic-role grant in the project is a named allowance.

        Requires params: project_id, allowed -- a list of {role, member,
        reason}. Covers the project and every resource under it, through
        Cloud Asset's IAM search, because a basic role granted on one
        dataset is as much a grant as one on the project.

        Basic roles (owner, editor, viewer) are the ones GCP applies across
        every service at once. KSI-IAM-ELP's least-privilege model has no
        room for them except where a stated reason makes the reach
        deliberate -- a provisioning identity that must manage everything,
        say -- and the allowance list is where that reason is recorded.
        """
        project_id = check.params["project_id"]
        client = asset_client(project_id)
        results = client.search_all_iam_policies(request={
            "scope": f"projects/{project_id}",
            "query": "policy:(" + " OR ".join(BASIC_ROLES) + ")",
        })
        grants = [
            {"resource": policy.resource, "role": binding.role, "member": member}
            for policy in results
            for binding in policy.policy.bindings
            if binding.role in BASIC_ROLES
            for member in binding.members
        ]
        ok, detail, evidence = evaluate_basic_roles(grants, check.params["allowed"])
        return CheckResult(check.id, ok, evidence, detail)


# --- fetches ---


    def _store_encryption_keys(self, check: CheckDefinition) -> CheckResult:
        """Every store reports encryption with the key its data class declares.

        Requires params: region, rules. Each rule is {type, name, expect,
        reason}: `name` is a glob, `expect` a key alias, or "SSE-S3" where
        an AWS-held key is a recorded exception. KSI-SVC-SIN build row 1's
        verify line.

        The stores come from the APIs, not from the rules, for the same
        reason the bucket checks list buckets: a store nobody wrote a rule
        for is exactly the one to find, and it fails as unclassified.
        """
        region = check.params["region"]
        stores = _list_aws_stores(region)
        kms = boto3.client("kms", region_name=region)
        cache: dict = {}

        def resolve(ref):
            if ref not in cache:
                try:
                    cache[ref] = kms.describe_key(KeyId=ref)["KeyMetadata"]["Arn"]
                except kms.exceptions.NotFoundException:
                    cache[ref] = None
            return cache[ref]

        ok, detail, evidence = evaluate_store_keys(stores, check.params["rules"], resolve)
        return CheckResult(check.id, ok, evidence, detail)


def _list_aws_stores(region: str) -> list[dict]:
    """Every store of the kinds build row 1 names, with what it reports.

    observed is {"mode": ..., "key": ...}: mode is "KMS" with the key as the
    service reports it (ID, ARN or alias), "SSE-S3" for an AWS-held key, or
    "AWS-managed" / "none" where the service encrypts with its own key or
    not at all.
    """
    stores = []

    s3 = boto3.client("s3", region_name=region)
    for b in s3.list_buckets()["Buckets"]:
        try:
            rule = s3.get_bucket_encryption(Bucket=b["Name"])
            rule = rule["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
        except s3.exceptions.ClientError:
            rule = {}
        if rule.get("SSEAlgorithm") == "AES256":
            observed = {"mode": "SSE-S3", "key": None}
        elif rule.get("KMSMasterKeyID"):
            observed = {"mode": "KMS", "key": rule["KMSMasterKeyID"]}
        else:
            observed = {"mode": "AWS-managed" if rule else "none", "key": None}
        stores.append({"type": "s3_bucket", "name": b["Name"], "observed": observed})

    logs = boto3.client("logs", region_name=region)
    for page in logs.get_paginator("describe_log_groups").paginate():
        for g in page["logGroups"]:
            key = g.get("kmsKeyId")
            stores.append({"type": "log_group", "name": g["logGroupName"],
                           "observed": {"mode": "KMS" if key else "AWS-managed", "key": key}})

    sns = boto3.client("sns", region_name=region)
    for page in sns.get_paginator("list_topics").paginate():
        for t in page["Topics"]:
            key = sns.get_topic_attributes(TopicArn=t["TopicArn"])["Attributes"].get("KmsMasterKeyId")
            stores.append({"type": "sns_topic", "name": t["TopicArn"].split(":")[-1],
                           "observed": {"mode": "KMS" if key else "none", "key": key}})

    ecr = boto3.client("ecr", region_name=region)
    for page in ecr.get_paginator("describe_repositories").paginate():
        for repo in page["repositories"]:
            enc = repo.get("encryptionConfiguration", {})
            kms_key = enc.get("kmsKey") if enc.get("encryptionType") == "KMS" else None
            stores.append({"type": "ecr_repository", "name": repo["repositoryName"],
                           "observed": {"mode": "KMS" if kms_key else "AWS-managed", "key": kms_key}})

    trail_client = boto3.client("cloudtrail", region_name=region)
    for t in trail_client.describe_trails(includeShadowTrails=False)["trailList"]:
        key = t.get("KmsKeyId")
        stores.append({"type": "cloudtrail", "name": t["Name"],
                       "observed": {"mode": "KMS" if key else "SSE-S3", "key": key}})

    athena = boto3.client("athena", region_name=region)
    for wg in athena.list_work_groups()["WorkGroups"]:
        config = athena.get_work_group(WorkGroup=wg["Name"])["WorkGroup"]["Configuration"]
        enc = config.get("ResultConfiguration", {}).get("EncryptionConfiguration", {})
        key = enc.get("KmsKey") if enc.get("EncryptionOption") in ("SSE_KMS", "CSE_KMS") else None
        mode = "KMS" if key else ("SSE-S3" if enc.get("EncryptionOption") == "SSE_S3" else "none")
        stores.append({"type": "athena_workgroup", "name": wg["Name"],
                       "observed": {"mode": mode, "key": key}})

    config_client = boto3.client("config", region_name=region)
    for ch in config_client.describe_delivery_channels()["DeliveryChannels"]:
        key = ch.get("s3KmsKeyArn")
        stores.append({"type": "config_delivery_channel", "name": ch["name"],
                       "observed": {"mode": "KMS" if key else "bucket-default", "key": key}})

    secrets = boto3.client("secretsmanager", region_name=region)
    for page in secrets.get_paginator("list_secrets").paginate():
        for sec in page["SecretList"]:
            key = sec.get("KmsKeyId")
            stores.append({"type": "secret", "name": sec["Name"],
                           "observed": {"mode": "KMS" if key else "AWS-managed", "key": key}})

    rds = boto3.client("rds", region_name=region)
    for db in rds.describe_db_instances()["DBInstances"]:
        key = db.get("KmsKeyId") if db.get("StorageEncrypted") else None
        stores.append({"type": "rds_instance", "name": db["DBInstanceIdentifier"],
                       "observed": {"mode": "KMS" if key else "none", "key": key}})

    return stores


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


BASIC_ROLES = ("roles/owner", "roles/editor", "roles/viewer")


def evaluate_basic_roles(grants: list[dict], allowed: list[dict]) -> tuple[bool, str, dict]:
    permitted = {(a["role"], a["member"]) for a in allowed}
    unexpected = [g for g in grants if (g["role"], g["member"]) not in permitted]
    used = {(g["role"], g["member"]) for g in grants}
    evidence = {
        "grants": grants,
        "unexpected": unexpected,
        # An allowance nothing uses is a reason with no grant behind it --
        # residue, or a grant that moved somewhere the list does not cover.
        "allowances_unused": [a for a in allowed if (a["role"], a["member"]) not in used],
    }
    if unexpected:
        names = ", ".join(f"{g['member']} ({g['role']})" for g in unexpected)
        return False, f"{len(unexpected)} basic-role grant(s) without a recorded reason: {names}", evidence
    return True, f"all {len(grants)} basic-role grant(s) are named allowances", evidence


def evaluate_store_keys(stores: list[dict], rules: list[dict], resolve) -> tuple[bool, str, dict]:
    """Each store matched to its data class's rule, and its key compared.

    Keys are compared as resolved ARNs, because services report the same key
    as an ID, an ARN or an alias. `resolve` returns None for a key that does
    not exist, which fails: an expected key that is gone protects nothing,
    and an ephemeral key's stores should have gone with it.

    A rule matching no store is reported, not failed. Rules for the
    application environment's stores have nothing to match while it is
    down.
    """
    results, failing, used = {}, [], set()
    for store in stores:
        label = f"{store['type']}:{store['name']}"
        rule = next((i for i, r in enumerate(rules)
                     if r["type"] == store["type"] and fnmatch.fnmatchcase(store["name"], r["name"])), None)
        observed = store["observed"]
        if rule is None:
            ok, why = False, f"no data class declared (reports {observed['mode']})"
        else:
            used.add(rule)
            expect = rules[rule]["expect"]
            if expect == "SSE-S3":
                ok = observed["mode"] == "SSE-S3"
                why = f"SSE-S3 as declared ({rules[rule].get('reason', '')})" if ok else f"expected SSE-S3, reports {observed['mode']}"
            else:
                want = resolve(expect)
                got = resolve(observed["key"]) if observed["key"] else None
                if want is None:
                    ok, why = False, f"expected key {expect} does not exist"
                elif got == want:
                    ok, why = True, f"encrypted with {expect}"
                else:
                    ok, why = False, f"expected {expect}, reports {observed['mode']}" + (f" {observed['key']}" if observed["key"] else "")
        results[label] = {"passed": ok, "detail": why}
        if not ok:
            failing.append(label)

    evidence = {"stores": results, "failing": failing,
                "rules_unmatched": [f"{r['type']}:{r['name']}" for i, r in enumerate(rules) if i not in used]}
    if not stores:
        return False, "no stores found -- nothing to judge", evidence
    if failing:
        return False, f"{len(failing)} of {len(stores)} stores fail: {', '.join(failing)}", evidence
    return True, f"all {len(stores)} stores use their declared key", evidence
