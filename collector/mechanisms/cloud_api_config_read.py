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
from datetime import datetime, timezone
import json

import boto3
from botocore.config import Config

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
        if provider == "aws" and resource == "key_decrypt_principals":
            return self._key_decrypt_principals(check)
        if provider == "gcp" and resource == "store_encryption_keys":
            return self._gcp_store_encryption_keys(check)
        if provider == "gcp" and resource == "scheduler_job_runs":
            return self._gcp_scheduler_job_runs(check)
        if provider == "gcp" and resource == "buckets_prevent_public_access":
            return self._gcp_buckets_public_access(check)
        if provider == "gcp" and resource == "key_decrypt_principals":
            return self._gcp_key_decrypt_principals(check)
        if provider == "aws" and resource == "key_rotation":
            return self._aws_key_rotation(check)
        if provider == "gcp" and resource == "key_rotation":
            return self._gcp_key_rotation(check)
        if provider == "aws" and resource == "registries_immutable":
            return self._aws_registries_immutable(check)
        if provider == "gcp" and resource == "registries_immutable":
            return self._gcp_registries_immutable(check)
        if provider == "aws" and resource == "iam_user_access_keys":
            return self._aws_iam_user_access_keys(check)
        if provider == "aws" and resource == "log_corpus_query_limits":
            return self._aws_log_corpus_query_limits(check)

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

        return _every_bucket(check, {name: evaluate(fetch(client, name)) for name in names})

    def _gcp_key_decrypt_principals(self, check: CheckDefinition) -> CheckResult:
        """The GCP half of KSI-SVC-SIN verify row 6: who can decrypt with each key.

        Requires params: project_id, declared ({"location/keyRing/key":
        [member globs]}).

        Resolved, not read from the key alone. A Cloud KMS key's decrypters
        are everyone bound, on the key, its key ring or the project, to a
        role whose permissions include useToDecrypt. The project has no
        folder or organization above it, so those three levels are the
        whole inheritance chain. A role is judged by its expanded
        permissions, so a custom role carrying decrypt is found as surely
        as the predefined decrypter role, and so is a basic role that
        carries it (roles/owner does).

        Policies come from Cloud Asset's IAM search, as the basic-roles
        check's do. The collector role can read key and project policies
        directly but not key ring ones, and one source for all three levels
        cannot disagree with itself. Checked against direct reads on
        2026-10-02.
        """
        from google.auth.transport.requests import AuthorizedSession

        from gcp_auth import impersonated_token

        project_id = check.params["project_id"]
        client = asset_client(project_id)
        keys = [res.name for res in client.search_all_resources(request={
            "scope": f"projects/{project_id}",
            "asset_types": ["cloudkms.googleapis.com/CryptoKey"],
        })]
        policies = {
            p.resource: [
                {"role": b.role, "members": list(b.members),
                 "condition": b.condition.expression if b.condition and b.condition.expression else None}
                for b in p.policy.bindings
            ]
            for p in client.search_all_iam_policies(request={
                "scope": f"projects/{project_id}",
                "asset_types": ["cloudkms.googleapis.com/CryptoKey", "cloudkms.googleapis.com/KeyRing",
                                "cloudresourcemanager.googleapis.com/Project"],
            })
        }
        session = AuthorizedSession(impersonated_token(project_id))
        permissions = {}
        for role in sorted({b["role"] for bindings in policies.values() for b in bindings}):
            response = session.get(f"https://iam.googleapis.com/v1/{role}", timeout=30)
            # An unreadable role is kept as None, and the resolver treats it
            # as able to decrypt: not knowing must not read as "cannot".
            permissions[role] = set(response.json().get("includedPermissions", [])) if response.ok else None

        resolved = {
            gcp_key_short_name(key): resolve_gcp_decrypt_principals(key, policies, permissions)
            for key in keys
        }
        ok, detail, evidence = evaluate_decrypt_principals(resolved, check.params["declared"])
        evidence["unreadable_roles"] = sorted(r for r, p in permissions.items() if p is None)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_key_rotation(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-ASM verify row 2, AWS: every enabled customer key rotates.

        Requires params: region, max_days. Keys pending deletion or disabled
        are not judged: AWS reports no rotation for them, and they can
        encrypt nothing. Every enabled customer key is, so a key created
        outside Terraform is judged with the rest.
        """
        kms = boto3.client("kms", region_name=check.params["region"])
        aliases = {}
        for page in kms.get_paginator("list_aliases").paginate():
            for alias in page["Aliases"]:
                if alias.get("TargetKeyId"):
                    aliases.setdefault(alias["TargetKeyId"], alias["AliasName"])
        keys = []
        for page in kms.get_paginator("list_keys").paginate():
            for entry in page["Keys"]:
                meta = kms.describe_key(KeyId=entry["KeyId"])["KeyMetadata"]
                if meta["KeyManager"] != "CUSTOMER" or meta["KeyState"] != "Enabled":
                    continue
                status = kms.get_key_rotation_status(KeyId=meta["KeyId"])
                keys.append({
                    "key": aliases.get(meta["KeyId"], meta["KeyId"]),
                    "rotation_days": status.get("RotationPeriodInDays") if status["KeyRotationEnabled"] else None,
                })
        ok, detail, evidence = evaluate_key_rotation(keys, check.params["max_days"])
        return CheckResult(check.id, ok, evidence, detail)

    def _gcp_key_rotation(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-ASM verify row 2, GCP: every symmetric key has a rotation period.

        Requires params: project_id, max_days. Only ENCRYPT_DECRYPT keys
        rotate automatically in Cloud KMS; any other purpose is recorded
        and not judged.
        """
        from google.auth.transport.requests import AuthorizedSession

        from gcp_auth import impersonated_token

        project_id = check.params["project_id"]
        session = AuthorizedSession(impersonated_token(project_id))
        keys, other = [], []
        for res in asset_client(project_id).search_all_resources(request={
            "scope": f"projects/{project_id}", "asset_types": ["cloudkms.googleapis.com/CryptoKey"],
        }):
            name = res.name.removeprefix("//cloudkms.googleapis.com/")
            response = session.get(f"https://cloudkms.googleapis.com/v1/{name}", timeout=30)
            response.raise_for_status()
            key = response.json()
            if key.get("purpose") != "ENCRYPT_DECRYPT":
                other.append({"key": gcp_key_short_name(name), "purpose": key.get("purpose")})
                continue
            period = key.get("rotationPeriod")
            keys.append({"key": gcp_key_short_name(name),
                         "rotation_days": int(period.rstrip("s")) / 86400 if period else None})
        ok, detail, evidence = evaluate_key_rotation(keys, check.params["max_days"])
        evidence["not_judged"] = other
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_registries_immutable(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-VRI verify row 2, AWS: every ECR repository's tags are immutable.

        Requires param: region. IMMUTABLE_WITH_EXCLUSION fails: an excluded
        tag pattern is a tag that can be moved.
        """
        ecr = boto3.client("ecr", region_name=check.params["region"])
        repos = [
            {"repository": r["repositoryName"], "setting": r["imageTagMutability"],
             "immutable": r["imageTagMutability"] == "IMMUTABLE"}
            for page in ecr.get_paginator("describe_repositories").paginate()
            for r in page["repositories"]
        ]
        ok, detail, evidence = evaluate_registries_immutable(repos)
        return CheckResult(check.id, ok, evidence, detail)

    def _gcp_registries_immutable(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-VRI verify row 2, GCP: every Docker repository's tags are immutable.

        Requires param: project_id. Immutability is a Docker setting in
        Artifact Registry; a repository of another format is recorded and
        not judged.
        """
        from google.auth.transport.requests import AuthorizedSession

        from gcp_auth import impersonated_token

        project_id = check.params["project_id"]
        session = AuthorizedSession(impersonated_token(project_id))
        repos, other = [], []
        for res in asset_client(project_id).search_all_resources(request={
            "scope": f"projects/{project_id}", "asset_types": ["artifactregistry.googleapis.com/Repository"],
        }):
            name = res.name.removeprefix("//artifactregistry.googleapis.com/")
            response = session.get(f"https://artifactregistry.googleapis.com/v1/{name}", timeout=30)
            response.raise_for_status()
            repo = response.json()
            if repo.get("format") != "DOCKER":
                other.append({"repository": name, "format": repo.get("format")})
                continue
            immutable = bool((repo.get("dockerConfig") or {}).get("immutableTags"))
            repos.append({"repository": name.split("/")[-1], "setting": "immutableTags" if immutable else "mutable",
                          "immutable": immutable})
        ok, detail, evidence = evaluate_registries_immutable(repos)
        evidence["not_judged"] = other
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_iam_user_access_keys(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-SNU verify row 1: no IAM user holds an access key.

        No params. An inactive key fails as well as an active one: it can be
        reactivated by anyone who can call UpdateAccessKey, and nothing here
        needs one.
        """
        iam = boto3.client("iam")
        users = []
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                users.append({"user": user["UserName"],
                              "keys": [{"id": k["AccessKeyId"], "status": k["Status"]} for k in keys]})
        ok, detail, evidence = evaluate_no_user_access_keys(users)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_log_corpus_query_limits(self, check: CheckDefinition) -> CheckResult:
        """KSI-MLA-OSM verify row 3: projection on every corpus table, limits on every workgroup.

        Requires params: region, database, max_bytes. Every enabled
        workgroup in the account is judged, not only the corpus's: a query
        run through an unlimited workgroup is an unlimited query.
        """
        region = check.params["region"]
        glue = boto3.client("glue", region_name=region)
        athena = boto3.client("athena", region_name=region)
        tables = [
            {"table": t["Name"], "projection": (t.get("Parameters") or {}).get("projection.enabled")}
            for page in glue.get_paginator("get_tables").paginate(DatabaseName=check.params["database"])
            for t in page["TableList"]
        ]
        workgroups, token = [], None
        # boto3 has no paginator for this one.
        while True:
            page = athena.list_work_groups(**({"NextToken": token} if token else {}))
            for summary in page["WorkGroups"]:
                if summary["State"] != "ENABLED":
                    continue
                config = athena.get_work_group(WorkGroup=summary["Name"])["WorkGroup"].get("Configuration", {})
                workgroups.append({"workgroup": summary["Name"],
                                   "enforced": config.get("EnforceWorkGroupConfiguration", False),
                                   "cutoff": config.get("BytesScannedCutoffPerQuery")})
            token = page.get("NextToken")
            if not token:
                break
        ok, detail, evidence = evaluate_log_corpus_limits(tables, workgroups, check.params["max_bytes"])
        return CheckResult(check.id, ok, evidence, detail)

    def _gcp_buckets_public_access(self, check: CheckDefinition) -> CheckResult:
        """The GCP half of KSI-SVC-SIN verify row 2: no bucket permits public access.

        Requires param: project_id.

        The buckets come from Cloud Asset, as the store-key check's do; the
        collector role reads each bucket but cannot list them. Each bucket's
        iamConfiguration then comes from Cloud Storage itself, which is the
        setting's authority.
        """
        from google.auth.transport.requests import AuthorizedSession

        from gcp_auth import impersonated_token

        project_id = check.params["project_id"]
        names = sorted(
            res.name.split("/")[-1]
            for res in asset_client(project_id).search_all_resources(request={
                "scope": f"projects/{project_id}",
                "asset_types": ["storage.googleapis.com/Bucket"],
            })
        )
        session = AuthorizedSession(impersonated_token(project_id))
        results = {}
        for name in names:
            response = session.get(
                f"https://storage.googleapis.com/storage/v1/b/{name}",
                params={"fields": "name,iamConfiguration"}, timeout=30,
            )
            response.raise_for_status()
            results[name] = evaluate_gcs_public_access(response.json().get("iamConfiguration"))
        return _every_bucket(check, results)

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


    def _gcp_scheduler_job_runs(self, check: CheckDefinition) -> CheckResult:
        """Passes if the named Cloud Scheduler job is enabled and recently ran.

        Requires params: project_id, location, job, max_age_hours.
        """
        p = check.params
        job = _gcp_scheduler_job(p["project_id"], p["location"], p["job"])
        ok, detail = evaluate_scheduler_job(job, datetime.now(timezone.utc), p["max_age_hours"])
        evidence = {k: job.get(k) for k in ("name", "schedule", "state", "lastAttemptTime", "status")}
        return CheckResult(check.id, ok, evidence, detail)

    def _gcp_store_encryption_keys(self, check: CheckDefinition) -> CheckResult:
        """The GCP half of build row 1: every store reports its declared key.

        Requires params: project_id, asset_types, rules (as the AWS check,
        with each rule's type an asset type and expect a full key name, or
        "GOOGLE-MANAGED" where Google's key is a recorded exception).

        One Cloud Asset search gives both the population and the key each
        resource reports, so the stores come from the API as on AWS. Key
        names are compared without their version suffix: BigQuery tables
        report the key version in use, everything else the key. Keys are
        not resolved for existence -- Cloud KMS keys cannot be deleted, only
        their versions destroyed, so a named key is always there.
        """
        project_id = check.params["project_id"]
        client = asset_client(project_id)
        results = client.search_all_resources(request={
            "scope": f"projects/{project_id}",
            "asset_types": check.params["asset_types"],
        })
        # Log buckets come from Logging, not Cloud Asset: Cloud Asset does not
        # report regional ones (DECISIONS.md, 2026-10-01), and the bucket it
        # missed is the one holding the customer-data access logs.
        stores = _gcp_log_buckets(project_id)
        for res in results:
            keys = list(res.kms_keys) or ([res.kms_key] if res.kms_key else [])
            observed = {"mode": "KMS", "key": keys[0]} if keys else {"mode": "GOOGLE-MANAGED", "key": None}
            stores.append({"type": res.asset_type, "name": res.name.split("/")[-1], "observed": observed})

        ok, detail, evidence = evaluate_store_keys(stores, check.params["rules"], gcp_key_name)
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


    def _key_decrypt_principals(self, check: CheckDefinition) -> CheckResult:
        """Who can decrypt with each customer key, resolved, against who should.

        Requires params: region, declared ({key alias: [principal patterns]}).
        A pattern is an ARN glob, or "service:<principal>". KSI-SVC-SIN build
        row 6's verify line: "resolved rather than read as a flag".

        Every enabled customer key in the region is judged, from the API, so
        a key with no declared model fails rather than going unexamined. A
        key policy statement granting the account hands the decision to IAM,
        so for those the answer comes from simulating every IAM role and
        user -- the artifacts key is entirely that shape.
        """
        region = check.params["region"]
        kms = boto3.client("kms", region_name=region)
        # A run makes principals x paths simulation calls, and IAM throttles
        # them hard when other checks run alongside. Adaptive retries slow
        # down instead of erroring the check out.
        iam = boto3.client("iam", config=Config(retries={"max_attempts": 12, "mode": "adaptive"}))
        account = boto3.client("sts").get_caller_identity()["Account"]

        principals = []
        for page in iam.get_paginator("list_roles").paginate():
            principals += [r["Arn"] for r in page["Roles"]]
        for page in iam.get_paginator("list_users").paginate():
            principals += [u["Arn"] for u in page["Users"]]

        keys = {}
        for page in kms.get_paginator("list_keys").paginate():
            for k in page["Keys"]:
                meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if meta["KeyManager"] != "CUSTOMER" or meta["KeyState"] != "Enabled":
                    continue
                keys[meta["Arn"]] = meta
        aliases = {}
        for page in kms.get_paginator("list_aliases").paginate():
            for a in page["Aliases"]:
                if a.get("TargetKeyId"):
                    aliases.setdefault(a["TargetKeyId"], a["AliasName"])

        capable_by_key = _iam_can_decrypt(iam, principals, list(keys))
        resolved = {}
        for arn, meta in keys.items():
            policy = json.loads(kms.get_key_policy(KeyId=arn, PolicyName="default")["Policy"])
            grants = []
            for page in kms.get_paginator("list_grants").paginate(KeyId=arn):
                grants += page["Grants"]
            capable = capable_by_key[arn]
            label = aliases.get(meta["KeyId"], meta["KeyId"])
            resolved[label] = resolve_decrypt_principals(policy, grants, capable, principals, account)

        ok, detail, evidence = evaluate_decrypt_principals(resolved, check.params["declared"])
        return CheckResult(check.id, ok, evidence, detail)


def _gcp_scheduler_job(project_id: str, location: str, job: str) -> dict:
    from google.auth.transport.requests import AuthorizedSession

    from gcp_auth import impersonated_token

    session = AuthorizedSession(impersonated_token(project_id))
    url = f"https://cloudscheduler.googleapis.com/v1/projects/{project_id}/locations/{location}/jobs/{job}"
    response = session.get(url, timeout=30)
    if response.status_code == 404:
        return {}
    response.raise_for_status()
    return response.json()


def evaluate_scheduler_job(job: dict, now: datetime, max_age_hours: float) -> tuple[bool, str]:
    """Enabled, last attempt succeeded, and that attempt is recent.

    Status is a google.rpc.Status: absent or code 0 is success. On
    2026-10-02 the analytics schedule had attempted every six hours and been
    refused each time (code 7, PERMISSION_DENIED), while every configuration
    check passed -- the job existed, the schedule existed. This asks the
    question that would have caught it: did the last run actually start?
    """
    if not job:
        return False, "schedule not found"
    if job.get("state") != "ENABLED":
        return False, f"schedule is {job.get('state', 'in an unknown state')}"
    last = job.get("lastAttemptTime")
    if not last:
        return False, "schedule has never attempted a run"
    code = (job.get("status") or {}).get("code", 0)
    if code:
        return False, f"last attempt at {last} failed with status code {code}"
    age = (now - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds() / 3600
    if age > max_age_hours:
        return False, f"last attempt {age:.1f} hours ago, more than {max_age_hours}"
    return True, f"last attempt {age:.1f} hours ago succeeded"


def _every_bucket(check: CheckDefinition, verdicts: dict[str, tuple[bool, str]]) -> CheckResult:
    """Passes only if every bucket passes, and fails on none: a claim about
    every bucket is not supported by zero buckets."""
    results = {name: {"passed": ok, "detail": detail} for name, (ok, detail) in verdicts.items()}
    failing = sorted(n for n, r in results.items() if not r["passed"])
    evidence = {"buckets": results, "failing": failing}
    if not results:
        return CheckResult(check.id, False, evidence, "no buckets found -- nothing to judge")
    if failing:
        return CheckResult(
            check.id, False, evidence,
            f"{len(failing)} of {len(results)} buckets fail: {', '.join(failing)}",
        )
    return CheckResult(check.id, True, evidence, f"all {len(results)} buckets pass")


def _gcp_log_buckets(project_id: str) -> list[dict]:
    """Every log bucket in every location, from Logging's own API."""
    from google.auth.transport.requests import AuthorizedSession

    from gcp_auth import impersonated_token

    session = AuthorizedSession(impersonated_token(project_id))
    url = f"https://logging.googleapis.com/v2/projects/{project_id}/locations/-/buckets"
    stores, page = [], None
    while True:
        response = session.get(url, params={"pageToken": page} if page else None, timeout=30)
        response.raise_for_status()
        body = response.json()
        for bucket in body.get("buckets", []):
            key = (bucket.get("cmekSettings") or {}).get("kmsKeyName")
            stores.append({
                "type": "logging.googleapis.com/LogBucket",
                "name": bucket["name"].split("/")[-1],
                "observed": {"mode": "KMS", "key": key} if key else {"mode": "GOOGLE-MANAGED", "key": None},
            })
        page = body.get("nextPageToken")
        if not page:
            return stores


def gcp_key_name(ref: str | None) -> str | None:
    """A Cloud KMS key name without any /cryptoKeyVersions/N suffix."""
    return ref.split("/cryptoKeyVersions/")[0] if ref else None


# Where a key policy delegates to IAM, an identity policy may still restrict
# decrypt to a path (kms:ViaService). Each path is simulated, and a principal
# that can decrypt by any of them can decrypt.
_VIA_SERVICES = ("s3", "sns", "logs", "secretsmanager", "rds", "ecr")


def _iam_can_decrypt(iam, principals: list[str], key_arns: list[str]) -> dict[str, set[str]]:
    """{key ARN: principals whose IAM policies allow kms:Decrypt on it}.

    All keys go into each simulation, which answers per resource, so the
    cost is principals x paths rather than principals x paths x keys.
    """
    capable = {k: set() for k in key_arns}
    if not key_arns:
        return capable
    region = key_arns[0].split(":")[3]
    contexts = [[]] + [[{"ContextKeyName": "kms:ViaService", "ContextKeyType": "string",
                         "ContextKeyValues": [f"{svc}.{region}.amazonaws.com"]}] for svc in _VIA_SERVICES]
    for principal in principals:
        for context in contexts:
            result = iam.simulate_principal_policy(
                PolicySourceArn=principal, ActionNames=["kms:Decrypt"],
                ResourceArns=key_arns, ContextEntries=context,
            )["EvaluationResults"]
            # One result per resource, or one with per-resource detail,
            # depending on the request; read both shapes.
            for evaluation in result:
                if evaluation.get("EvalResourceName") in capable and evaluation["EvalDecision"] == "allowed":
                    capable[evaluation["EvalResourceName"]].add(principal)
                for per_key in evaluation.get("ResourceSpecificResults", []):
                    if per_key["EvalResourceName"] in capable and per_key["EvalResourceDecision"] == "allowed":
                        capable[per_key["EvalResourceName"]].add(principal)
    return capable


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


def evaluate_gcs_public_access(config: dict | None) -> tuple[bool, str]:
    """Public access prevention enforced, and uniform bucket-level access on.

    "inherited" is not enforced here: it defers to an organization policy,
    and this project sits outside any organization, so nothing is inherited.
    Uniform access is build row 4's second half; without it, object ACLs are
    a second access path that bucket IAM does not show.
    """
    if not config:
        return False, "no iamConfiguration reported"
    prevention = config.get("publicAccessPrevention")
    if prevention != "enforced":
        return False, f"public access prevention is {prevention!r}, expected 'enforced'"
    if not (config.get("uniformBucketLevelAccess") or {}).get("enabled"):
        return False, "uniform bucket-level access is off"
    return True, "public access prevention enforced, uniform bucket-level access on"


def _judged(kind: str, results: dict[str, dict], allow_empty: bool = False) -> tuple[bool, str, dict]:
    """Pass only if every member passes; an empty population fails unless
    emptiness is itself the claim."""
    failing = sorted(n for n, r in results.items() if not r["passed"])
    evidence = {kind: results, "failing": failing}
    if not results and not allow_empty:
        return False, f"no {kind} found -- nothing to judge", evidence
    if failing:
        return False, f"{len(failing)} of {len(results)} {kind} fail: {', '.join(failing)}", evidence
    return True, f"all {len(results)} {kind} pass", evidence


def evaluate_key_rotation(keys: list[dict], max_days: float) -> tuple[bool, str, dict]:
    """Every key rotates automatically, at least every max_days."""
    results = {}
    for k in keys:
        days = k["rotation_days"]
        if days is None:
            results[k["key"]] = {"passed": False, "detail": "automatic rotation off"}
        elif days > max_days:
            results[k["key"]] = {"passed": False, "detail": f"rotates every {days:g} days, more than {max_days:g}"}
        else:
            results[k["key"]] = {"passed": True, "detail": f"rotates every {days:g} days"}
    return _judged("keys", results)


def evaluate_registries_immutable(repos: list[dict]) -> tuple[bool, str, dict]:
    return _judged("repositories", {
        r["repository"]: {"passed": r["immutable"], "detail": r["setting"]} for r in repos
    })


def evaluate_no_user_access_keys(users: list[dict]) -> tuple[bool, str, dict]:
    """No user holds a key. No users at all passes: absence is the claim."""
    if not users:
        return True, "no IAM users exist, so none holds a key", {"users": {}, "failing": []}
    return _judged("users", {
        u["user"]: {"passed": not u["keys"],
                    "detail": "no access keys" if not u["keys"] else
                              ", ".join(f"{k['id']} ({k['status']})" for k in u["keys"])}
        for u in users
    }, allow_empty=True)


def evaluate_log_corpus_limits(tables: list[dict], workgroups: list[dict],
                               max_bytes: int) -> tuple[bool, str, dict]:
    results = {}
    for t in tables:
        on = t["projection"] == "true"
        results[f"table {t['table']}"] = {"passed": on, "detail": "partition projection on" if on else
                                          f"partition projection {t['projection'] or 'unset'}"}
    for w in workgroups:
        cutoff = w["cutoff"]
        if not w["enforced"]:
            ok, detail = False, "workgroup settings not enforced, so a client can override the limit"
        elif cutoff is None:
            ok, detail = False, "no scan limit"
        elif cutoff > max_bytes:
            ok, detail = False, f"scan limit {cutoff} bytes, more than {max_bytes}"
        else:
            ok, detail = True, f"enforced, scan limit {cutoff} bytes"
        results[f"workgroup {w['workgroup']}"] = {"passed": ok, "detail": detail}
    if not tables:
        results["tables"] = {"passed": False, "detail": "no tables in the corpus database"}
    if not workgroups:
        results["workgroups"] = {"passed": False, "detail": "no enabled workgroups"}
    return _judged("settings", results)


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


# Rule values naming a provider-held key rather than a customer key. Each is
# an exception a rule must give a reason for, never a default.
PROVIDER_HELD_KEY_MODES = ("SSE-S3", "GOOGLE-MANAGED")


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
            if expect in PROVIDER_HELD_KEY_MODES:
                ok = observed["mode"] == expect
                why = f"{expect} as declared ({rules[rule].get('reason', '')})" if ok else f"expected {expect}, reports {observed['mode']}"
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

    # A rule marked required names a store that must exist. Unmatched, it is
    # a store the population did not show -- deleted, or missed by the
    # source -- and that fails. Unrequired rules (an ephemeral environment's
    # stores) are reported only. Added 2026-10-01, after a rule for a
    # regional log bucket sat unmatched while the check passed.
    unmatched = [i for i, _ in enumerate(rules) if i not in used]
    for i in unmatched:
        if rules[i].get("required"):
            label = f"{rules[i]['type']}:{rules[i]['name']}"
            results[label] = {"passed": False, "detail": "required store not found in the population"}
            failing.append(label)

    evidence = {"stores": results, "failing": failing,
                "rules_unmatched": [f"{rules[i]['type']}:{rules[i]['name']}" for i in unmatched]}
    if not stores:
        return False, "no stores found -- nothing to judge", evidence
    if failing:
        return False, f"{len(failing)} of {len(stores)} stores fail: {', '.join(failing)}", evidence
    return True, f"all {len(stores)} stores use their declared key", evidence


def _covers_decrypt(statement: dict) -> bool:
    if "NotAction" in statement:
        return not any(fnmatch.fnmatchcase("kms:decrypt", a.lower()) for a in _as_list(statement["NotAction"]))
    return any(fnmatch.fnmatchcase("kms:decrypt", a.lower()) for a in _as_list(statement.get("Action", [])))


def _principal_arn_patterns(statement: dict) -> list[str] | None:
    """aws:PrincipalArn patterns a statement is conditioned on, or None."""
    patterns = None
    for operator, block in (statement.get("Condition") or {}).items():
        if operator.removesuffix("IfExists") not in ("ArnLike", "ArnEquals", "StringLike", "StringEquals"):
            continue
        for key, values in block.items():
            if key.lower() == "aws:principalarn":
                patterns = (patterns or []) + _as_list(values)
    return patterns


def resolve_decrypt_principals(policy: dict, grants: list[dict], iam_capable: set[str],
                               iam_principals: list[str], account: str) -> list[dict]:
    """Every principal able to decrypt with one key, and by which route.

    Routes: "policy" (named in the key policy), "grant", "iam" (the key
    policy delegates to the account, and the principal's IAM policies allow
    it), and "public" (Principal "*" with nothing confining it to the
    account). Deny statements are not subtracted, so the answer can only
    be wider than the truth -- a failure here is never hidden by a deny
    this function misread.
    """
    found = []
    root_forms = {f"arn:aws:iam::{account}:root", account}
    for st in _as_list(policy.get("Statement", [])):
        if st.get("Effect") != "Allow" or not _covers_decrypt(st):
            continue
        principal = st.get("Principal")
        if principal in ("*", {"AWS": "*"}):
            conditions = json.dumps(st.get("Condition") or {}).lower()
            if "kms:calleraccount" in conditions or "aws:principalaccount" in conditions:
                aws = [account]
            else:
                found.append({"principal": "*", "route": "public", "sid": st.get("Sid")})
                continue
        else:
            aws = _as_list((principal or {}).get("AWS", []))
            for svc in _as_list((principal or {}).get("Service", [])):
                found.append({"principal": f"service:{svc}", "route": "policy", "sid": st.get("Sid")})
        for p in aws:
            if p in root_forms:
                patterns = _principal_arn_patterns(st)
                for candidate in sorted(iam_capable & set(iam_principals)):
                    if patterns is None or any(fnmatch.fnmatchcase(candidate, pat) for pat in patterns):
                        found.append({"principal": candidate, "route": "iam", "sid": st.get("Sid")})
            else:
                found.append({"principal": p, "route": "policy", "sid": st.get("Sid")})
    for g in grants:
        if "Decrypt" in g.get("Operations", []):
            grantee = g["GranteePrincipal"]
            label = grantee if grantee.startswith("arn:") else f"service:{grantee}"
            found.append({"principal": label, "route": "grant", "sid": g.get("GrantId")})
    return found


GCP_DECRYPT = "cloudkms.cryptoKeyVersions.useToDecrypt"
GCP_PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")


def gcp_key_short_name(key: str) -> str:
    """"location/keyRing/key" from a key's full resource name."""
    parts = key.split("/")
    return f"{parts[parts.index('locations') + 1]}/{parts[parts.index('keyRings') + 1]}/{parts[-1]}"


def resolve_gcp_decrypt_principals(key: str, policies: dict[str, list[dict]],
                                   permissions: dict[str, set | None]) -> list[dict]:
    """Every member able to decrypt with `key`, and the level that grants it.

    `policies` maps full resource names to bindings; the key's own, its key
    ring's (the key's name up to /cryptoKeys/) and any project's apply.
    Every project policy in scope is the key's project: the search is
    scoped to one project. A conditional binding counts: a condition
    narrows when, not whether, and the declared model has to own the grant.
    A role whose permissions are unknown (None) counts as able to decrypt.
    """
    ring = key.split("/cryptoKeys/")[0]
    found = []
    for resource, bindings in sorted(policies.items()):
        if resource == key:
            level = "key"
        elif resource == ring:
            level = "keyring"
        elif resource.startswith("//cloudresourcemanager.googleapis.com/projects/"):
            level = "project"
        else:
            continue
        for binding in bindings:
            perms = permissions.get(binding["role"])
            if perms is not None and GCP_DECRYPT not in perms:
                continue
            for member in binding["members"]:
                found.append({
                    "principal": member,
                    "route": "public" if member in GCP_PUBLIC_MEMBERS else level,
                    "role": binding["role"],
                    **({"condition": binding["condition"]} if binding.get("condition") else {}),
                    **({"role_unresolved": True} if perms is None else {}),
                })
    return found


def evaluate_decrypt_principals(resolved: dict[str, list[dict]],
                                declared: dict[str, list[str]]) -> tuple[bool, str, dict]:
    """Each key's decrypt set within its declared model, and no key undeclared.

    A declared principal that cannot decrypt is reported, not failed: it is
    a functional gap, not an exposure, and ephemeral roles are absent while
    the environment is down.
    """
    results, failing = {}, []
    for key, found in sorted(resolved.items()):
        if key not in declared:
            results[key] = {"passed": False, "detail": "no declared decrypt model for this key",
                            "principals": found}
            failing.append(key)
            continue
        patterns = declared[key]
        extra = [f for f in found
                 if f["route"] == "public" or not any(fnmatch.fnmatchcase(f["principal"], p) for p in patterns)]
        unused = [p for p in patterns if not any(fnmatch.fnmatchcase(f["principal"], p) for f in found)]
        ok = not extra
        results[key] = {
            "passed": ok,
            "detail": "decrypt confined to the declared model" if ok else
                      "undeclared: " + ", ".join(f"{f['principal']} ({f['route']})" for f in extra),
            "principals": found, "declared_but_not_capable": unused,
        }
        if not ok:
            failing.append(key)
    evidence = {"keys": results, "failing": failing}
    if not resolved:
        return False, "no customer keys found -- nothing to judge", evidence
    if failing:
        return False, f"{len(failing)} of {len(resolved)} keys fail: {', '.join(failing)}", evidence
    return True, f"all {len(resolved)} keys decrypt only for declared principals", evidence
