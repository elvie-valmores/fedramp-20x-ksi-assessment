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
from datetime import date, datetime, timedelta, timezone
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
        if provider == "gcp" and resource == "service_account_user_keys":
            return self._gcp_service_account_user_keys(check)
        if provider == "aws" and resource == "iam_user_access_keys":
            return self._aws_iam_user_access_keys(check)
        if provider == "aws" and resource == "log_corpus_query_limits":
            return self._aws_log_corpus_query_limits(check)
        if provider == "aws" and resource == "role_trusts":
            return self._aws_role_trusts(check)
        if provider == "aws" and resource == "federated_session_bounds":
            return self._aws_federated_session_bounds(check)
        if provider == "aws" and resource == "oidc_providers":
            return self._aws_oidc_providers(check)
        if provider == "gcp" and resource == "workload_identity_provider":
            return self._gcp_workload_identity_provider(check)
        if provider == "aws" and resource == "iam_user_policies":
            return self._aws_iam_user_policies(check)
        if provider == "aws" and resource == "guardduty":
            return self._aws_guardduty(check)
        if provider == "aws" and resource == "securityhub_standards":
            return self._aws_securityhub_standards(check)
        if provider == "aws" and resource == "trail_data_events":
            return self._aws_trail_data_events(check)
        if provider == "aws" and resource == "state_bucket":
            return self._aws_state_bucket(check)
        if provider == "gcp" and resource == "bigquery_dataset_access":
            return self._gcp_bigquery_dataset_access(check)
        if provider == "aws" and resource == "alarms_target":
            return self._aws_alarms_target(check)
        if provider == "aws" and resource == "registry_scanning":
            return self._aws_registry_scanning(check)
        if provider == "aws" and resource == "scheduled_functions":
            return self._aws_scheduled_functions(check)
        if provider == "aws" and resource == "acm_certificates":
            return self._aws_acm_certificates(check)
        if provider == "aws" and resource == "private_routes":
            return self._aws_private_routes(check)
        if provider == "aws" and resource == "rules_match_flows":
            return self._aws_rules_match_flows(check)
        if provider == "aws" and resource == "security_group_reach":
            return self._aws_security_group_reach(check)
        if provider == "aws" and resource == "endpoint_policies":
            return self._aws_endpoint_policies(check)
        if provider == "aws" and resource == "load_balancer_tls":
            return self._aws_load_balancer_tls(check)
        if provider == "aws" and resource == "database_settings":
            return self._aws_database_settings(check)
        if provider == "gcp" and resource == "pinned_image_present":
            return self._gcp_pinned_image_present(check)
        if provider == "gcp" and resource == "run_job_images":
            return self._gcp_run_job_images(check)
        if provider == "gcp" and resource == "services_enabled":
            return self._gcp_services_enabled(check)
        if provider == "aws" and resource == "external_access":
            return self._aws_external_access(check)
        if provider == "aws" and resource == "store_sources_catalogued":
            return self._aws_store_sources_catalogued(check)
        if provider == "aws" and resource == "snapshots_accounted":
            return self._aws_snapshots_accounted(check)
        if provider == "aws" and resource == "securityhub_failing_controls":
            return self._aws_securityhub_failing_controls(check)
        if provider == "aws" and resource == "trail_logs_validate":
            return self._aws_trail_logs_validate(check)
        if provider == "aws" and resource == "function_runs":
            return self._aws_function_runs(check)
        if provider == "aws" and resource == "vpcs_declared":
            return self._aws_vpcs_declared(check)
        if provider == "aws" and resource == "bucket_read_restricted":
            return self._aws_bucket_read_restricted(check)
        if provider == "aws" and resource == "task_definitions":
            return self._aws_task_definitions(check)
        if provider == "aws" and resource == "database_backups_restorable":
            return self._aws_database_backups_restorable(check)
        if provider == "github" and resource == "workflow_active":
            return self._github_workflow_active(check)
        if provider == "aws" and resource == "iam_mutation_principals":
            return self._aws_iam_mutation_principals(check)
        if provider == "aws" and resource == "roles_last_used":
            return self._aws_roles_last_used(check)
        if provider == "aws" and resource == "image_scan_coverage":
            return self._aws_image_scan_coverage(check)
        if provider == "aws" and resource == "waf":
            return self._aws_waf(check)
        if provider == "aws" and resource == "ecs_services":
            return self._aws_ecs_services(check)
        if provider == "aws" and resource == "password_policy":
            return self._aws_password_policy(check)
        if provider == "aws" and resource == "root_credentials":
            return self._aws_root_credentials(check)
        if provider == "aws" and resource == "workload_managed_policies":
            return self._aws_workload_managed_policies(check)
        if provider == "aws" and resource in ELEVATION_RESOURCES:
            return self._aws_elevation(check)
        if provider == "github" and resource == "pushes_evaluated":
            return self._github_pushes_evaluated(check)
        if provider == "github" and resource == "deliberate_test":
            return self._github_deliberate_test(check)

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

        ok, detail = evaluate_config_recorder(recorders, statuses)
        return CheckResult(check.id, ok, evidence, detail)

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

        watches_types, _ = evaluate_asset_feed({"name": feed.name, "asset_types": list(feed.asset_types)})
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

    def _gcp_service_account_user_keys(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-SNU verify row 2: no service account holds a user-managed key.

        Requires param: project_id. The accounts come from Cloud Asset, and
        each one's keys from IAM filtered to USER_MANAGED. Cloud Asset also
        indexes keys, but its search does not say which are Google's own
        rotating keys, so it cannot answer this (2026-10-02). Every account
        has system-managed keys; those are not credentials anyone holds.
        """
        from google.auth.transport.requests import AuthorizedSession

        from gcp_auth import impersonated_token

        project_id = check.params["project_id"]
        session = AuthorizedSession(impersonated_token(project_id))
        accounts = []
        for res in asset_client(project_id).search_all_resources(request={
            "scope": f"projects/{project_id}", "asset_types": ["iam.googleapis.com/ServiceAccount"],
        }):
            email = (res.additional_attributes or {}).get("email") or res.display_name
            response = session.get(
                f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{email}/keys",
                params={"keyTypes": "USER_MANAGED"}, timeout=30,
            )
            response.raise_for_status()
            keys = response.json().get("keys", [])
            accounts.append({"user": email, "keys": [
                {"id": k["name"].split("/")[-1], "status": "disabled" if k.get("disabled") else "enabled"}
                for k in keys]})
        if not accounts:
            return CheckResult(check.id, False, {"accounts": {}}, "no service accounts found -- nothing to judge")
        ok, detail, evidence = evaluate_no_user_access_keys(accounts)
        return CheckResult(check.id, ok, evidence, detail.replace("users", "service accounts"))

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

    @staticmethod
    def _roles_with_trust() -> list[dict]:
        iam = boto3.client("iam")
        return [
            {"role": r["RoleName"], "path": r["Path"], "document": r["AssumeRolePolicyDocument"],
             "max_session": r["MaxSessionDuration"]}
            for page in iam.get_paginator("list_roles").paginate()
            for r in page["Roles"]
        ]

    def _aws_role_trusts(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-SNU verify row 4: every role's trust names its principals exactly.

        Requires param: exempt_paths ([{path, reason}]).
        """
        ok, detail, evidence = evaluate_role_trusts(self._roles_with_trust(), check.params["exempt_paths"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_federated_session_bounds(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-ULN verify row 6, AWS: federated sessions are short.

        Requires params: region, max_seconds. Web-identity roles are judged
        by MaxSessionDuration. Identity Center's reserved roles carry a
        12-hour MaxSessionDuration of AWS's choosing; what bounds their
        session is the permission set's duration, so that is what is read.
        """
        sso = boto3.client("sso-admin", region_name=check.params["region"])
        instance = sso.list_instances()["Instances"][0]["InstanceArn"]
        durations = {}
        for page in sso.get_paginator("list_permission_sets").paginate(InstanceArn=instance):
            for arn in page["PermissionSets"]:
                ps = sso.describe_permission_set(InstanceArn=instance, PermissionSetArn=arn)["PermissionSet"]
                durations[ps["Name"]] = _iso_duration_seconds(ps.get("SessionDuration", "PT1H"))
        roles = []
        for role in self._roles_with_trust():
            statements = role["document"].get("Statement", [])
            web = any("sts:AssumeRoleWithWebIdentity" in _as_list(s.get("Action", [])) for s in statements)
            if role["path"] == "/aws-reserved/sso.amazonaws.com/":
                # AWSReservedSSO_<permission set name>_<16 hex>
                name = role["role"].removeprefix("AWSReservedSSO_").rsplit("_", 1)[0]
                roles.append({"role": role["role"], "kind": "identity_center", "seconds": durations.get(name)})
            elif web:
                roles.append({"role": role["role"], "kind": "web_identity", "seconds": role["max_session"]})
        ok, detail, evidence = evaluate_session_bounds(roles, check.params["max_seconds"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_oidc_providers(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-SNU verify row 5, AWS: the OIDC providers are exactly the declared ones.

        Requires param: expected ([{url, client_ids}]).
        """
        iam = boto3.client("iam")
        providers = []
        for entry in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]:
            p = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=entry["Arn"])
            providers.append({"url": p["Url"], "client_ids": p["ClientIDList"]})
        ok, detail, evidence = evaluate_oidc_providers(providers, check.params["expected"])
        return CheckResult(check.id, ok, evidence, detail)

    def _gcp_workload_identity_provider(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-SNU verify row 5, GCP: the GitHub provider's issuer and condition.

        Requires params: project_id, pool, wif_provider, issuer, required_clauses.
        The clauses pin GitHub's immutable numeric owner and repository IDs
        and the branch; a condition missing one admits tokens it should not.
        """
        from google.auth.transport.requests import AuthorizedSession

        from gcp_auth import impersonated_token

        p = check.params
        session = AuthorizedSession(impersonated_token(p["project_id"]))
        response = session.get(
            f"https://iam.googleapis.com/v1/projects/{p['project_id']}/locations/global/"
            f"workloadIdentityPools/{p['pool']}/providers/{p['wif_provider']}", timeout=30)
        provider = response.json() if response.ok else None
        ok, detail = evaluate_wif_provider(provider, p["issuer"], p["required_clauses"])
        return CheckResult(check.id, ok, {"provider": provider, "status": response.status_code}, detail)

    def _aws_iam_user_policies(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-ELP verify row 4: access is by role, never attached to a user."""
        iam = boto3.client("iam")
        users = []
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                name = user["UserName"]
                users.append({
                    "user": name,
                    "inline": iam.list_user_policies(UserName=name)["PolicyNames"],
                    "attached": [a["PolicyArn"] for a in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]],
                    "groups": [g["GroupName"] for g in iam.list_groups_for_user(UserName=name)["Groups"]],
                })
        ok, detail, evidence = evaluate_users_hold_no_policies(users)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_guardduty(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-SUS verify row 1: threat detection on, with exactly the declared plans.

        Requires params: region, declared_on, frequency.
        """
        gd = boto3.client("guardduty", region_name=check.params["region"])
        ids = gd.list_detectors()["DetectorIds"]
        detector = None
        if ids:
            d = gd.get_detector(DetectorId=ids[0])
            detector = {"status": d["Status"], "frequency": d.get("FindingPublishingFrequency"),
                        "features": {f["Name"]: f["Status"] for f in d.get("Features", [])}}
        ok, detail, evidence = evaluate_guardduty(detector, check.params["declared_on"], check.params["frequency"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_securityhub_standards(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-IBP verify row 1: the expected standards subscribed and ready.

        Requires params: region, expected (standards ARNs).
        """
        sh = boto3.client("securityhub", region_name=check.params["region"])
        subs = {
            s["StandardsArn"]: s["StandardsStatus"]
            for page in sh.get_paginator("get_enabled_standards").paginate()
            for s in page["StandardsSubscriptions"]
        }
        ok, detail, evidence = evaluate_standards(subs, check.params["expected"])
        evidence["subscribed"] = subs
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_trail_data_events(self, check: CheckDefinition) -> CheckResult:
        """KSI-MLA-LET verify row 4: data events scoped to the declared customer-data stores.

        Requires params: region, trail, declared (S3 object ARN prefixes,
        e.g. "arn:aws:s3:::bucket/"). Reads both selector styles: advanced
        selectors with eventCategory Data on AWS::S3::Object and an ARN
        StartsWith, and basic selectors' DataResources.
        """
        ct = boto3.client("cloudtrail", region_name=check.params["region"])
        sel = ct.get_event_selectors(TrailName=check.params["trail"])
        scoped = []
        for adv in sel.get("AdvancedEventSelectors") or []:
            fields = {f["Field"]: f for f in adv["FieldSelectors"]}
            if (fields.get("eventCategory", {}).get("Equals") == ["Data"]
                    and fields.get("resources.type", {}).get("Equals") == ["AWS::S3::Object"]
                    and "readOnly" not in fields):
                scoped += fields.get("resources.ARN", {}).get("StartsWith", [])
        for basic in sel.get("EventSelectors") or []:
            if basic.get("ReadWriteType") != "All":
                continue
            for res in basic.get("DataResources", []):
                if res["Type"] == "AWS::S3::Object":
                    scoped += res["Values"]
        ok, detail, evidence = evaluate_trail_data_events(scoped, check.params["declared"])
        evidence["selectors"] = sel.get("AdvancedEventSelectors") or sel.get("EventSelectors")
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_state_bucket(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-ACM verify row 1, the bucket half: versioned and encrypted.

        Requires params: region, bucket. Which key encrypts it is the
        store-key check's business (a recorded SSE-S3 exception); locking is
        a client setting, checked on every init by pipeline_config_read.
        """
        s3 = boto3.client("s3", region_name=check.params["region"])
        bucket = check.params["bucket"]
        versioning = s3.get_bucket_versioning(Bucket=bucket).get("Status")
        try:
            rule = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"][0]
            encryption = rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except s3.exceptions.ClientError:
            encryption = None
        ok, detail = evaluate_state_bucket(versioning, encryption)
        return CheckResult(check.id, ok, {"versioning": versioning, "encryption": encryption}, detail)

    def _github_workflow_active(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-ACM verify row 2, the enabled half: GitHub has not disabled the workflow.

        Requires params: repository, workflow. GitHub disables a scheduled
        workflow after 60 days without repository activity, and a person
        can disable one in the UI. Either way the file still declares the
        schedule, so the file alone cannot show it runs. Token: GITHUB_TOKEN
        (CI, with actions: read), else the gh CLI's.
        """
        import os
        import subprocess
        import urllib.request

        token = os.environ.get("GITHUB_TOKEN") or subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
        request = urllib.request.Request(
            f"https://api.github.com/repos/{check.params['repository']}/actions/workflows/{check.params['workflow']}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            workflow = json.load(response)
        state = workflow.get("state")
        ok, detail = evaluate_workflow_state(state)
        return CheckResult(check.id, ok, {"state": state, "path": workflow.get("path")}, detail)

    def _gcp_bigquery_dataset_access(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-SIN verify row 7: every dataset's access list is its declared one.

        Requires params: project_id, declared ({dataset: [{role, member}]},
        member as "<entity type>:<value>", e.g. "userByEmail:x@y").
        Datasets come from Cloud Asset, so an undeclared one fails rather
        than going unread; each access list from BigQuery itself.
        """
        from google.auth.transport.requests import AuthorizedSession

        from gcp_auth import impersonated_token

        project_id = check.params["project_id"]
        session = AuthorizedSession(impersonated_token(project_id))
        found = {}
        for res in asset_client(project_id).search_all_resources(request={
            "scope": f"projects/{project_id}", "asset_types": ["bigquery.googleapis.com/Dataset"],
        }):
            dataset = res.name.split("/")[-1]
            response = session.get(
                f"https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/datasets/{dataset}", timeout=30)
            response.raise_for_status()
            found[dataset] = [
                {"role": entry.get("role"),
                 "member": next(f"{k}:{v}" for k, v in entry.items() if k != "role")}
                for entry in response.json().get("access", [])
            ]
        ok, detail, evidence = evaluate_dataset_access(found, check.params["declared"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_alarms_target(self, check: CheckDefinition) -> CheckResult:
        """KSI-MLA-OSM verify row 4: the declared alarms exist and alert the detection path.

        Requires params: region, alarms (names), topic (the detection SNS topic ARN).
        """
        cw = boto3.client("cloudwatch", region_name=check.params["region"])
        found = {
            a["AlarmName"]: {"actions_enabled": a["ActionsEnabled"], "actions": a["AlarmActions"]}
            for page in cw.get_paginator("describe_alarms").paginate(AlarmNames=check.params["alarms"])
            for a in page["MetricAlarms"]
        }
        ok, detail, evidence = evaluate_alarms_target(found, check.params["alarms"], check.params["topic"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_registry_scanning(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-EIS verify row 1, the AWS registry half.

        Requires param: region. Enhanced scanning (Inspector) continuously
        on every repository: a filter narrower than "*" leaves a repository
        created later unscanned.
        """
        region = check.params["region"]
        config = boto3.client("ecr", region_name=region).get_registry_scanning_configuration()["scanningConfiguration"]
        status = boto3.client("inspector2", region_name=region).batch_get_account_status()["accounts"][0]
        inspector = {"account": status["state"]["status"], "ecr": status["resourceState"]["ecr"]["status"]}
        ok, detail = evaluate_registry_scanning(config, inspector)
        return CheckResult(check.id, ok, {"scanning": config, "inspector": inspector}, detail)

    def _aws_scheduled_functions(self, check: CheckDefinition) -> CheckResult:
        """Each declared schedule is enabled and invokes its function.

        Requires params: region, schedules ([{rule, function}]). KSI-MLA-OSM
        verify row 5's "scheduled" half; that the deployed query is the
        versioned one is the drift check's.
        """
        region = check.params["region"]
        events = boto3.client("events", region_name=region)
        lam = boto3.client("lambda", region_name=region)
        found = {}
        for item in check.params["schedules"]:
            try:
                rule = events.describe_rule(Name=item["rule"])
                targets = [t["Arn"] for t in events.list_targets_by_rule(Rule=item["rule"])["Targets"]]
                function = lam.get_function(FunctionName=item["function"])["Configuration"]["FunctionArn"]
                found[item["rule"]] = {"state": rule["State"], "schedule": rule.get("ScheduleExpression"),
                                       "targets": targets, "function_arn": function}
            except (events.exceptions.ResourceNotFoundException, lam.exceptions.ResourceNotFoundException):
                found[item["rule"]] = None
        ok, detail, evidence = evaluate_scheduled_functions(found)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_acm_certificates(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-ASM verify row 3: certificates are issued and renewed by ACM.

        Requires params: region, min_days.
        """
        from datetime import datetime, timezone

        acm = boto3.client("acm", region_name=check.params["region"])
        now = datetime.now(timezone.utc)
        certs = []
        for page in acm.get_paginator("list_certificates").paginate(
                Includes={"keyTypes": ["RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1"]}):
            for summary in page["CertificateSummaryList"]:
                c = acm.describe_certificate(CertificateArn=summary["CertificateArn"])["Certificate"]
                not_after = c.get("NotAfter")
                certs.append({
                    "domain": c["DomainName"], "type": c["Type"], "status": c["Status"],
                    "eligible": c.get("RenewalEligibility") == "ELIGIBLE", "in_use": bool(c.get("InUseBy")),
                    "validation": sorted({o.get("ValidationMethod") for o in c.get("DomainValidationOptions", [])} - {None}),
                    "days_left": (not_after - now).days if not_after else None,
                })
        ok, detail, evidence = evaluate_certificates(certs, check.params["min_days"])
        return CheckResult(check.id, ok, evidence, detail)

    @staticmethod
    def _project_vpc(ec2, name: str) -> str:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [name]}])["Vpcs"]
        if len(vpcs) != 1:
            raise RuntimeError(f"expected one VPC named {name}, found {len(vpcs)}")
        return vpcs[0]["VpcId"]

    def _aws_private_routes(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-RNT verify 4 / CNA-ULN verify 2: private route tables reach nothing outside.

        Requires params: region, vpc_name, private_tiers. Route tables are
        found by their Tier tag within the project VPC.
        """
        ec2 = boto3.client("ec2", region_name=check.params["region"])
        vpc = self._project_vpc(ec2, check.params["vpc_name"])
        tables = []
        for t in ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"]:
            tags = {x["Key"]: x["Value"] for x in t.get("Tags", [])}
            tables.append({"id": t["RouteTableId"], "tier": tags.get("Tier"), "routes": [
                {"destination": r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock")
                 or r.get("DestinationPrefixListId"),
                 "target": next((r[k] for k in ("GatewayId", "NatGatewayId", "NetworkInterfaceId",
                                                "TransitGatewayId", "VpcPeeringConnectionId", "InstanceId",
                                                "EgressOnlyInternetGatewayId") if r.get(k)), None)}
                for r in t["Routes"]]})
        ok, detail, evidence = evaluate_private_routes(tables, check.params["private_tiers"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_rules_match_flows(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-MAT verify 1: every open port is a declared flow, and every declared flow is open.

        Requires params: region, vpc_name, register. Live rules in the project
        VPC are reduced to (group, direction, port, peer) -- peer a group name,
        "prefix:s3" for a prefix list, or a CIDR -- and compared both ways with
        the flow register's.
        """
        import yaml
        from pathlib import Path

        ec2 = boto3.client("ec2", region_name=check.params["region"])
        vpc = self._project_vpc(ec2, check.params["vpc_name"])
        names = {g["GroupId"]: g["GroupName"]
                 for g in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["SecurityGroups"]}
        live = []
        for page in ec2.get_paginator("describe_security_group_rules").paginate(
                Filters=[{"Name": "group-id", "Values": list(names)}]):
            for r in page["SecurityGroupRules"]:
                ref = (r.get("ReferencedGroupInfo") or {}).get("GroupId")
                peer = names.get(ref, ref) if ref else ("prefix:s3" if r.get("PrefixListId") else r.get("CidrIpv4") or r.get("CidrIpv6"))
                port = r.get("FromPort") if r.get("FromPort") == r.get("ToPort") else f"{r.get('FromPort')}-{r.get('ToPort')}"
                live.append({"group": names[r["GroupId"]], "direction": "egress" if r["IsEgress"] else "ingress",
                             "port": port, "peer": peer, "protocol": r["IpProtocol"]})
        register = yaml.safe_load((Path(__file__).resolve().parents[2] / check.params["register"]).read_text())
        declared = [r for f in register["flows"].values() for r in f.get("rules") or []]
        ok, detail, evidence = evaluate_rules_match_flows(live, declared)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_security_group_reach(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-RNT verify 2 and 3: no rule opens the VPC to or from anywhere, except as declared.

        Requires params: region, vpc_name, direction ("ingress" or
        "egress"), allowed ([{group, port, reason}]). Scoped to the project
        VPC; the account's default VPC is outside it (an open item).
        """
        ec2 = boto3.client("ec2", region_name=check.params["region"])
        vpc = self._project_vpc(ec2, check.params["vpc_name"])
        names = {g["GroupId"]: g["GroupName"]
                 for g in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["SecurityGroups"]}
        egress = check.params["direction"] == "egress"
        rules = [
            {"group": names[r["GroupId"]], "protocol": r["IpProtocol"], "from": r.get("FromPort"),
             "to": r.get("ToPort"), "cidr": r.get("CidrIpv4") or r.get("CidrIpv6")}
            for page in ec2.get_paginator("describe_security_group_rules").paginate(
                Filters=[{"Name": "group-id", "Values": list(names)}])
            for r in page["SecurityGroupRules"] if r["IsEgress"] == egress
        ]
        ok, detail, evidence = evaluate_open_rules(rules, check.params["allowed"], check.params["direction"])
        evidence["groups"] = sorted(names.values())
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_endpoint_policies(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-RNT verify 6, CNA-ULN verify 3, SVC-VCM verify 4: endpoint policies restrict.

        Requires params: region, vpc_name, principal_exceptions
        ([{resource, reason}]).
        """
        ec2 = boto3.client("ec2", region_name=check.params["region"])
        vpc = self._project_vpc(ec2, check.params["vpc_name"])
        endpoints = [
            {"service": e["ServiceName"].split(".")[-1], "type": e["VpcEndpointType"],
             "policy": json.loads(e.get("PolicyDocument") or "{}")}
            for page in ec2.get_paginator("describe_vpc_endpoints").paginate(
                Filters=[{"Name": "vpc-id", "Values": [vpc]}])
            for e in page["VpcEndpoints"]
        ]
        ok, detail, evidence = evaluate_endpoint_policies(endpoints, check.params.get("principal_exceptions", []))
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_load_balancer_tls(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-SIN verify 4: TLS policy, HTTP redirected, TLS to the targets.

        Requires params: region, load_balancer, allowed_policies.
        """
        elb = boto3.client("elbv2", region_name=check.params["region"])
        lb = elb.describe_load_balancers(Names=[check.params["load_balancer"]])["LoadBalancers"][0]
        listeners = [
            {"port": l["Port"], "protocol": l["Protocol"], "policy": l.get("SslPolicy"),
             "actions": [{"type": a["Type"], **({"protocol": a["RedirectConfig"]["Protocol"],
                                               "status": a["RedirectConfig"]["StatusCode"]}
                                              if a["Type"] == "redirect" else {})}
                         for a in l["DefaultActions"]]}
            for l in elb.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"]
        ]
        groups = [{"name": g["TargetGroupName"], "protocol": g["Protocol"],
                   "health_protocol": g.get("HealthCheckProtocol")}
                  for g in elb.describe_target_groups(LoadBalancerArn=lb["LoadBalancerArn"])["TargetGroups"]]
        ok, detail, evidence = evaluate_load_balancer_tls(listeners, groups, check.params["allowed_policies"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_database_settings(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-SIN verify 3, SVC-VCM verify 2, CNA-OFA verify 2: the instance and its parameters.

        Requires params: region, instance, parameters ({name: value}),
        min_backup_days.
        """
        rds = boto3.client("rds", region_name=check.params["region"])
        db = rds.describe_db_instances(DBInstanceIdentifier=check.params["instance"])["DBInstances"][0]
        group = db["DBParameterGroups"][0]["DBParameterGroupName"]
        wanted = set(check.params["parameters"])
        values = {
            p["ParameterName"]: p.get("ParameterValue")
            for page in rds.get_paginator("describe_db_parameters").paginate(DBParameterGroupName=group)
            for p in page["Parameters"] if p["ParameterName"] in wanted
        }
        instance = {"iam_auth": db.get("IAMDatabaseAuthenticationEnabled", False),
                    "backup_days": db.get("BackupRetentionPeriod", 0), "encrypted": db.get("StorageEncrypted", False)}
        ok, detail, evidence = evaluate_database_settings(instance, values, check.params["parameters"],
                                                          check.params["min_backup_days"])
        evidence["parameter_group"] = group
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_task_definitions(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-MAT verify 2, CNA-DFP verify 1, SVC-VRI verify 1: what the services run.

        Requires params: region, cluster, assertion ("hardened",
        "explicit" or "digest_pinned"), one_off_families. Reads the task
        definition each service is running, not the latest revision of its
        family: the running one is what the row is about. Tasks run once
        rather than as a service (the migration) have no service to ask, so
        their family's latest active revision is read; a declared one-off
        family with no active revision fails.
        """
        ecs = boto3.client("ecs", region_name=check.params["region"])
        cluster = check.params["cluster"]
        arns = [a for page in ecs.get_paginator("list_services").paginate(cluster=cluster) for a in page["serviceArns"]]
        definitions = {}
        for i in range(0, len(arns), 10):
            for svc in ecs.describe_services(cluster=cluster, services=arns[i:i + 10])["services"]:
                td = ecs.describe_task_definition(taskDefinition=svc["taskDefinition"])["taskDefinition"]
                definitions[svc["serviceName"]] = td["containerDefinitions"]
        for family in check.params.get("one_off_families", []):
            latest = ecs.list_task_definitions(familyPrefix=family, status="ACTIVE", sort="DESC",
                                               maxResults=1)["taskDefinitionArns"]
            definitions[family] = (ecs.describe_task_definition(taskDefinition=latest[0])["taskDefinition"]
                                   ["containerDefinitions"] if latest else [])
        ok, detail, evidence = evaluate_task_definitions(definitions, check.params["assertion"])
        return CheckResult(check.id, ok, evidence, detail)

    def _gcp_services_enabled(self, check: CheckDefinition) -> CheckResult:
        """The named Google APIs are enabled in the project.

        Requires params: project_id, services. From Service Usage, which is
        the authority on whether an API is on.
        """
        from google.auth.transport.requests import AuthorizedSession

        from gcp_auth import impersonated_token

        p = check.params
        session = AuthorizedSession(impersonated_token(p["project_id"]))
        states = {}
        for service in p["services"]:
            response = session.get(
                f"https://serviceusage.googleapis.com/v1/projects/{p['project_id']}/services/{service}", timeout=30)
            response.raise_for_status()
            states[service] = response.json().get("state")
        ok, detail, evidence = evaluate_services_enabled(states)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_external_access(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-MAT validate 4: no external access path beyond the declared list.

        Requires params: region, declared ([{resource, reason}], ARN globs).
        From IAM Access Analyzer's account analyzer: every active finding is
        a resource that admits a principal outside the account.
        """
        aa = boto3.client("accessanalyzer", region_name=check.params["region"])
        analyzers = [a for a in aa.list_analyzers(type="ACCOUNT")["analyzers"] if a["status"] == "ACTIVE"]
        findings = []
        if analyzers:
            for page in aa.get_paginator("list_findings").paginate(
                    analyzerArn=analyzers[0]["arn"], filter={"status": {"eq": ["ACTIVE"]}}):
                for f in page["findings"]:
                    findings.append({"resource": f.get("resource"), "type": f.get("resourceType"),
                                     "public": f.get("isPublic", False), "principal": f.get("principal")})
        ok, detail, evidence = evaluate_external_access(bool(analyzers), findings, check.params["declared"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_store_sources_catalogued(self, check: CheckDefinition) -> CheckResult:
        """KSI-MLA-OSM validate 7: every source in the store is queryable through the catalog.

        Requires params: region, bucket, prefix, database, table. The store's
        sources are its source= partitions; the catalog's are the table's
        partition-projection values, which is all Athena will read.
        """
        region = check.params["region"]
        s3 = boto3.client("s3", region_name=region)
        prefixes = [
            cp["Prefix"]
            for page in s3.get_paginator("list_objects_v2").paginate(
                Bucket=check.params["bucket"], Prefix=check.params["prefix"], Delimiter="/")
            for cp in page.get("CommonPrefixes", [])
        ]
        stored = sorted(p.rstrip("/").split("source=")[-1] for p in prefixes if "source=" in p)
        params = boto3.client("glue", region_name=region).get_table(
            DatabaseName=check.params["database"], Name=check.params["table"])["Table"].get("Parameters", {})
        catalogued = sorted(v.strip() for v in params.get("projection.source.values", "").split(",") if v.strip())
        ok, detail, evidence = evaluate_sources_catalogued(stored, catalogued)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_snapshots_accounted(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-PRR validate 1: no snapshot without a live source or a register entry.

        Requires params: region, retained ([{instance, reason}]), the
        register of instances whose backups are kept after the instance
        is gone.
        """
        rds = boto3.client("rds", region_name=check.params["region"])
        live = {i["DBInstanceIdentifier"]
                for page in rds.get_paginator("describe_db_instances").paginate() for i in page["DBInstances"]}
        snapshots = [{"id": s["DBSnapshotIdentifier"], "instance": s["DBInstanceIdentifier"]}
                     for page in rds.get_paginator("describe_db_snapshots").paginate() for s in page["DBSnapshots"]]
        snapshots += [{"id": f"retained automated backups ({b['DbiResourceId']})", "instance": b["DBInstanceIdentifier"]}
                      for page in rds.get_paginator("describe_db_instance_automated_backups").paginate()
                      for b in page["DBInstanceAutomatedBackups"] if b.get("Status") == "retained"]
        ok, detail, evidence = evaluate_snapshots_accounted(snapshots, live, check.params["retained"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_securityhub_failing_controls(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-IBP validate 1: every failing control is remediated or in the exception record.

        Requires params: region, exceptions ([{control, reason, unless_resources?}]).
        Reads Security Hub's own control findings, active and not
        suppressed. Disabled controls produce none: securityhub_controls.tf
        is the record of those. The pass rate across evaluated controls is
        recorded, as the row asks.
        """
        sh = boto3.client("securityhub", region_name=check.params["region"])
        findings = []
        for status in ("FAILED", "PASSED"):
            filters = {"ComplianceStatus": [{"Value": status, "Comparison": "EQUALS"}],
                       "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                       "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
                       "WorkflowStatus": [{"Value": "SUPPRESSED", "Comparison": "NOT_EQUALS"}]}
            for page in sh.get_paginator("get_findings").paginate(Filters=filters):
                for f in page["Findings"]:
                    findings.append({"control": f["Compliance"].get("SecurityControlId"), "status": status,
                                     "severity": f["Severity"]["Label"], "resource": f["Resources"][0]["Id"]})
        ok, detail, evidence = evaluate_failing_controls(findings, check.params["exceptions"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_trail_logs_validate(self, check: CheckDefinition) -> CheckResult:
        """Digest validation succeeds over the window (SVC-SIN validate 5,
        MLA-OSM validate 2, SVC-VRI validate 3).

        Requires params: region, trail, hours. Runs AWS's own validator,
        `aws cloudtrail validate-logs`, which walks the signed digest chain
        and checks every log file's hash against it. Reimplementing that
        here would be a second, less trusted validator. The window is a day
        plus overlap, so daily runs leave no gap.
        """
        import subprocess
        from datetime import datetime, timedelta, timezone

        p = check.params
        ct = boto3.client("cloudtrail", region_name=p["region"])
        arn = ct.describe_trails(trailNameList=[p["trail"]])["trailList"][0]["TrailARN"]
        start = (datetime.now(timezone.utc) - timedelta(hours=p["hours"])).strftime("%Y-%m-%dT%H:%M:%SZ")
        run = subprocess.run(["aws", "cloudtrail", "validate-logs", "--region", p["region"], "--trail-arn", arn,
                              "--start-time", start], capture_output=True, text=True, timeout=900)
        output = run.stdout + run.stderr
        ok, detail = evaluate_validate_logs(output, run.returncode)
        return CheckResult(check.id, ok, {"start": start, "returncode": run.returncode,
                                          "output": output.strip().splitlines()[-12:]}, detail)

    def _aws_function_runs(self, check: CheckDefinition) -> CheckResult:
        """KSI-MLA-OSM validate 4: each scheduled function ran within its cadence, without error.

        Requires params: region, functions ([{name, within_hours}]). From
        Lambda's own CloudWatch metrics, which count invocations the
        function's log might not show if it never started.
        """
        from datetime import datetime, timedelta, timezone

        cw = boto3.client("cloudwatch", region_name=check.params["region"])
        now = datetime.now(timezone.utc)
        found = {}
        for f in check.params["functions"]:
            def total(metric):
                points = cw.get_metric_statistics(
                    Namespace="AWS/Lambda", MetricName=metric,
                    Dimensions=[{"Name": "FunctionName", "Value": f["name"]}],
                    StartTime=now - timedelta(hours=f["within_hours"]), EndTime=now,
                    Period=3600, Statistics=["Sum"])["Datapoints"]
                return sum(p["Sum"] for p in points)
            found[f["name"]] = {"invocations": total("Invocations"), "errors": total("Errors"),
                                "within_hours": f["within_hours"]}
        ok, detail, evidence = evaluate_function_runs(found)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_vpcs_declared(self, check: CheckDefinition) -> CheckResult:
        """Every VPC in every region is a declared one.

        Requires params: allowed ([{region, name}]). Every enabled region is
        read, not only the recorded one: a network the inventory cannot see
        is the one to find.
        """
        regions = [r["RegionName"] for r in boto3.client("ec2", region_name="us-east-1").describe_regions()["Regions"]]
        vpcs = []
        for region in regions:
            for v in boto3.client("ec2", region_name=region).describe_vpcs()["Vpcs"]:
                name = next((t["Value"] for t in v.get("Tags", []) if t["Key"] == "Name"), None)
                vpcs.append({"region": region, "id": v["VpcId"], "name": name, "default": v["IsDefault"]})
        ok, detail, evidence = evaluate_vpcs_declared(vpcs, check.params["allowed"])
        evidence["regions_read"] = len(regions)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_bucket_read_restricted(self, check: CheckDefinition) -> CheckResult:
        """KSI-MLA-ALA verify 5: the bucket denies object reads to all but its declared readers.

        Requires params: region, bucket, readers (the principal ARNs or ARN
        patterns exempted, exactly).
        """
        s3 = boto3.client("s3", region_name=check.params["region"])
        bucket = check.params["bucket"]
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        except s3.exceptions.ClientError:
            policy = None
        ok, detail = evaluate_read_deny(policy, bucket, check.params["readers"])
        return CheckResult(check.id, ok, {"policy": policy}, detail)

    def _github_pushes_evaluated(self, check: CheckDefinition) -> CheckResult:
        """KSI-MLA-EVC validate 4 and 5: every push to main evaluated, and passed.

        Requires params: repository, workflow, since (the first evaluated
        push), judge ("evaluated" or "passed"), grace_minutes. Each run names
        its push as `policy <before>..<after>` (policy.yml's run-name), so
        consecutive pushes must chain: a run whose before is not the last
        run's after is a push nobody evaluated. Main's head must be the last
        run's after once the grace has passed.
        """
        p = check.params
        runs, page = [], 1
        while True:
            batch = _github_get(f"repos/{p['repository']}/actions/workflows/{p['workflow']}/runs"
                                f"?branch=main&event=push&per_page=100&page={page}&created=>={p['since']}")
            runs += batch["workflow_runs"]
            if len(batch["workflow_runs"]) < 100:
                break
            page += 1
        parsed = [{"title": r["display_title"], "head": r["head_sha"], "created": r["created_at"],
                   "status": r["status"], "conclusion": r["conclusion"], "url": r["html_url"]} for r in runs]
        head = _github_get(f"repos/{p['repository']}/commits/main")
        main = {"sha": head["sha"], "pushed": head["commit"]["committer"]["date"]}
        if p["judge"] == "evaluated":
            ok, detail, evidence = evaluate_pushes_chained(parsed, main, datetime.now(timezone.utc), p["grace_minutes"])
        else:
            ok, detail, evidence = evaluate_pushes_passed(parsed)
        return CheckResult(check.id, ok, evidence, detail)

    def _github_deliberate_test(self, check: CheckDefinition) -> CheckResult:
        """KSI-MLA-EVC validate 1 to 3: the deliberate test passed, recently.

        Requires params: repository, workflow, job, step, max_age_days. The
        latest completed run on main is read, whatever triggered it; its
        step's own conclusion is what counts, not the run's, which also
        carries the evaluation.
        """
        p = check.params
        runs = _github_get(f"repos/{p['repository']}/actions/workflows/{p['workflow']}/runs"
                           f"?branch=main&status=completed&per_page=1")["workflow_runs"]
        latest, step = (runs[0] if runs else None), None
        if latest:
            jobs = _github_get(f"repos/{p['repository']}/actions/runs/{latest['id']}/jobs")["jobs"]
            job = next((j for j in jobs if j["name"] == p["job"]), None)
            step = next((s for s in (job or {}).get("steps", []) if s["name"] == p["step"]), None)
        ok, detail, evidence = evaluate_deliberate_test(
            latest and {"created": latest["created_at"], "url": latest["html_url"], "head": latest["head_sha"]},
            step and {"name": step["name"], "conclusion": step["conclusion"]},
            datetime.now(timezone.utc), p["max_age_days"])
        return CheckResult(check.id, ok, evidence, detail)

    def _project_roles(self, iam, excluded_paths: list[str]) -> list[dict]:
        return [r for page in iam.get_paginator("list_roles").paginate() for r in page["Roles"]
                if not any(r["Path"].startswith(p) for p in excluded_paths)]

    def _aws_iam_mutation_principals(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-ELP verify 5: who can change IAM, by simulation.

        Requires params: actions, excluded_paths, allowed (role name
        patterns). Each role's identity policies are simulated for the
        actions on an arbitrary role outside Identity Center's reserved path;
        a role allowed any of them must be declared. Permission boundaries
        and SCPs are not in play here.
        """
        iam = boto3.client("iam")
        account = boto3.client("sts").get_caller_identity()["Account"]
        target = f"arn:aws:iam::{account}:role/deliberate-simulation-target"
        capable = {}
        for role in self._project_roles(iam, check.params["excluded_paths"]):
            result = iam.simulate_principal_policy(PolicySourceArn=role["Arn"], ActionNames=check.params["actions"],
                                                   ResourceArns=[target])["EvaluationResults"]
            allowed = [r["EvalActionName"] for r in result if r["EvalDecision"] == "allowed"]
            if allowed:
                capable[role["RoleName"]] = allowed
        ok, detail, evidence = evaluate_iam_mutation_principals(capable, check.params["allowed"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_roles_last_used(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-SNU validate 4: every role's last use, surfaced by name.

        Requires params: excluded_paths, max_unused_days, grace_days (a role
        younger than this has not had a chance to be used).
        """
        iam = boto3.client("iam")
        now = datetime.now(timezone.utc)
        roles = []
        for r in self._project_roles(iam, check.params["excluded_paths"]):
            last = iam.get_role(RoleName=r["RoleName"])["Role"].get("RoleLastUsed", {}).get("LastUsedDate")
            roles.append({"role": r["RoleName"], "created_days": (now - r["CreateDate"]).days,
                          "unused_days": None if last is None else (now - last).days})
        ok, detail, evidence = evaluate_roles_last_used(roles, check.params["max_unused_days"], check.params["grace_days"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_image_scan_coverage(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-EIS validate 1: Inspector covers every recent deployable image.

        Requires params: region, repositories, recent (how many git- tagged
        images per repository count as deployable).
        """
        p = check.params
        ecr = boto3.client("ecr", region_name=p["region"])
        insp = boto3.client("inspector2", region_name=p["region"])
        wanted = {}
        for repo in p["repositories"]:
            images = [i for page in ecr.get_paginator("describe_images").paginate(repositoryName=repo)
                      for i in page["imageDetails"] if any(t.startswith("git-") for t in i.get("imageTags", []))]
            for i in sorted(images, key=lambda i: i["imagePushedAt"], reverse=True)[:p["recent"]]:
                tag = [t for t in i["imageTags"] if t.startswith("git-")][0]
                # A tag names a multi-platform index, which Inspector does not
                # scan (UNSUPPORTED_MEDIA_TYPE); it scans the platform images
                # the index lists. Build attestations ride along as entries
                # with an "unknown" platform and are not images to scan.
                manifest = json.loads(ecr.batch_get_image(repositoryName=repo, imageIds=[{"imageDigest": i["imageDigest"]}],
                                                          acceptedMediaTypes=[i.get("imageManifestMediaType", "")])
                                      ["images"][0]["imageManifest"])
                children = [m for m in manifest.get("manifests", [])
                            if (m.get("platform") or {}).get("architecture") not in (None, "unknown")]
                for m in children or [{"digest": i["imageDigest"], "platform": {}}]:
                    arch = (m.get("platform") or {}).get("architecture", "")
                    wanted[m["digest"]] = f"{repo}:{tag}" + (f" ({arch})" if arch else "")
        coverage = {}
        for page in insp.get_paginator("list_coverage").paginate(
                filterCriteria={"resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}]}):
            for c in page["coveredResources"]:
                digest = ((c.get("resourceMetadata") or {}).get("ecrImage") or {}).get("imageDigest") or c["resourceId"].rsplit("/", 1)[-1]
                coverage[digest] = c["scanStatus"]["statusCode"]
        ok, detail, evidence = evaluate_image_scan_coverage(wanted, coverage)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_waf(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-RVP verify 1-4: the load balancer's web ACL, as declared.

        Requires params: region, load_balancer, assertion ("associated",
        "managed_groups", "rate_rule" or "logging"), and per assertion
        managed_groups (names), rate_limit, log_destination_prefix.
        """
        p = check.params
        elb = boto3.client("elbv2", region_name=p["region"])
        waf = boto3.client("wafv2", region_name=p["region"])
        lb = elb.describe_load_balancers(Names=[p["load_balancer"]])["LoadBalancers"][0]["LoadBalancerArn"]
        acl = (waf.get_web_acl_for_resource(ResourceArn=lb).get("WebACL") or None)
        logging = None
        if acl:
            try:
                logging = waf.get_logging_configuration(ResourceArn=acl["ARN"])["LoggingConfiguration"]
            except waf.exceptions.WAFNonexistentItemException:
                logging = None
        ok, detail, evidence = evaluate_waf(acl, logging, p)
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_ecs_services(self, check: CheckDefinition) -> CheckResult:
        """KSI-CMT-VTD verify 2, CNA-OFA verify 1, CNA-MAT verify 3: the running services.

        Requires params: region, cluster, assertion ("circuit_breaker",
        "spread" or "distinct_identity"), and for spread, multi_task (the
        services meant to run more than one task).
        """
        p = check.params
        ecs = boto3.client("ecs", region_name=p["region"])
        ec2 = boto3.client("ec2", region_name=p["region"])
        arns = [a for page in ecs.get_paginator("list_services").paginate(cluster=p["cluster"]) for a in page["serviceArns"]]
        services = []
        for i in range(0, len(arns), 10):
            for svc in ecs.describe_services(cluster=p["cluster"], services=arns[i:i + 10])["services"]:
                net = svc["networkConfiguration"]["awsvpcConfiguration"]
                td = ecs.describe_task_definition(taskDefinition=svc["taskDefinition"])["taskDefinition"]
                zones = sorted({s["AvailabilityZone"] for s in ec2.describe_subnets(SubnetIds=net["subnets"])["Subnets"]})
                services.append({
                    "name": svc["serviceName"], "desired": svc["desiredCount"], "running": svc["runningCount"],
                    "zones": zones, "security_groups": sorted(net["securityGroups"]),
                    "task_role": td.get("taskRoleArn"),
                    "circuit_breaker": (svc.get("deploymentConfiguration") or {}).get("deploymentCircuitBreaker") or {},
                })
        ok, detail, evidence = evaluate_ecs_services(services, p["assertion"], p.get("multi_task", []))
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_password_policy(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-APM verify 4: the account password policy, as declared.

        Requires param: expected (the policy's fields as IAM returns them).
        Applies to the fallback lane only: root, since there are no IAM users.
        """
        iam = boto3.client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            policy = None
        ok, detail, evidence = evaluate_password_policy(policy, check.params["expected"])
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_root_credentials(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-APM verify 3, root enumerated separately: MFA on, by hardware, no keys."""
        iam = boto3.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        virtual = [d for page in iam.get_paginator("list_virtual_mfa_devices").paginate(AssignmentStatus="Assigned")
                   for d in page["VirtualMFADevices"] if (d.get("User") or {}).get("Arn", "").endswith(":root")]
        ok, detail, evidence = evaluate_root_credentials(summary, len(virtual))
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_workload_managed_policies(self, check: CheckDefinition) -> CheckResult:
        """KSI-CNA-DFP verify 2: no workload role carries an AWS-managed policy.

        Requires params: excluded_paths (role paths that are AWS's to define,
        such as Identity Center's and service-linked roles'), exceptions
        ([{role, policy, reason}]).
        """
        iam = boto3.client("iam")
        attached = {}
        for page in iam.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                if any(role["Path"].startswith(p) for p in check.params["excluded_paths"]):
                    continue
                policies = [a["PolicyArn"] for pg in iam.get_paginator("list_attached_role_policies").paginate(
                    RoleName=role["RoleName"]) for a in pg["AttachedPolicies"]]
                attached[role["RoleName"]] = policies
        ok, detail, evidence = evaluate_workload_managed_policies(attached, check.params.get("exceptions", []))
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_elevation(self, check: CheckDefinition) -> CheckResult:
        """KSI-IAM-JIT: the elevation's configuration and what it has done.

        Requires params: region, elevated (the permission set's name), and per
        resource: standing_allowed (standing_assignments), max_session_seconds
        and home_region (elevated_bounded), rule, function and max_minutes
        (elevation_backstop), state_machine, allowance_minutes and
        lookback_days (elevations_within_window, elevations_justified). The
        account's assignments are read for every principal, groups included,
        so access through a group is not missed.
        """
        p, resource = check.params, check.params["resource"]
        region = p["region"]
        account = boto3.client("sts").get_caller_identity()["Account"]
        sso = boto3.client("sso-admin", region_name=region)

        if resource == "elevations_revoked":
            s3 = boto3.client("s3", region_name=region)
            since = (datetime.now(timezone.utc) - timedelta(days=p["lookback_days"])).date()
            keys = [o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=p["bucket"], Prefix="elevations/")
                    for o in page.get("Contents", [])
                    if date.fromisoformat(o["Key"].split("dt=")[1][:10]) >= since]
            sfn = boto3.client("stepfunctions", region_name=region)
            running = {e["name"] for page in sfn.get_paginator("list_executions").paginate(
                stateMachineArn=f"arn:aws:states:{region}:{account}:stateMachine:{p['state_machine']}", statusFilter="RUNNING")
                for e in page["executions"]}
            ok, detail, evidence = evaluate_elevations_revoked(keys, running)
            return CheckResult(check.id, ok, evidence, detail)

        if resource == "elevation_backstop":
            events = boto3.client("events", region_name=region)
            try:
                rule = events.describe_rule(Name=p["rule"])
                targets = events.list_targets_by_rule(Rule=p["rule"])["Targets"]
            except events.exceptions.ResourceNotFoundException:
                rule, targets = None, []
            ok, detail, evidence = evaluate_elevation_backstop(rule, targets, p["function"], p["max_minutes"])
            return CheckResult(check.id, ok, evidence, detail)

        instance = sso.list_instances()["Instances"][0]["InstanceArn"]
        sets = {}
        for page in sso.get_paginator("list_permission_sets").paginate(InstanceArn=instance):
            for arn in page["PermissionSets"]:
                sets[arn] = sso.describe_permission_set(InstanceArn=instance, PermissionSetArn=arn)["PermissionSet"]
        elevated = next((arn for arn, ps in sets.items() if ps["Name"] == p["elevated"]), None)

        if resource == "elevated_bounded":
            policy = None
            if elevated:
                inline = sso.get_inline_policy_for_permission_set(InstanceArn=instance, PermissionSetArn=elevated)
                policy = json.loads(inline["InlinePolicy"]) if inline.get("InlinePolicy") else None
            session = _iso_duration_seconds(sets[elevated].get("SessionDuration", "PT1H")) if elevated else None
            ok, detail, evidence = evaluate_elevated_bounded(elevated is not None, session, policy,
                                                             p["max_session_seconds"], p["home_region"])
            return CheckResult(check.id, ok, evidence, detail)

        assigned = []
        for arn, ps in sets.items():
            for page in sso.get_paginator("list_account_assignments").paginate(
                    InstanceArn=instance, AccountId=account, PermissionSetArn=arn):
                assigned += [{"permission_set": ps["Name"], "principal": a["PrincipalId"],
                              "principal_type": a["PrincipalType"]} for a in page["AccountAssignments"]]

        sfn = boto3.client("stepfunctions", region_name=region)
        machine = f"arn:aws:states:{region}:{account}:stateMachine:{p.get('state_machine', 'fedramp-20x-ksi-elevation')}"
        executions = []
        try:
            for page in sfn.get_paginator("list_executions").paginate(stateMachineArn=machine):
                executions += page["executions"]
        except sfn.exceptions.StateMachineDoesNotExist:
            pass
        running = [{"arn": e["executionArn"], "started": e["startDate"].isoformat(),
                    "minutes": _requested_minutes(sfn, e["executionArn"])}
                   for e in executions if e["status"] == "RUNNING"]

        if resource == "elevated_unassigned":
            held = [a for a in assigned if a["permission_set"] == p["elevated"]]
            ok, detail, evidence = evaluate_elevated_unassigned(elevated is not None, held, running)
        elif resource == "standing_assignments":
            ok, detail, evidence = evaluate_standing_assignments(assigned, p["standing_allowed"], p["elevated"], running)
        elif resource == "elevations_within_window":
            held = [a for a in assigned if a["permission_set"] == p["elevated"]]
            ok, detail, evidence = evaluate_elevations_within_window(
                held, running, datetime.now(timezone.utc), p["allowance_minutes"])
        else:  # elevations_justified
            since = datetime.now(timezone.utc).timestamp() - p["lookback_days"] * 86400
            recent = []
            for e in executions:
                if e["startDate"].timestamp() < since:
                    continue
                described = sfn.describe_execution(executionArn=e["executionArn"])
                recent.append({"arn": e["executionArn"], "status": e["status"],
                               "input": json.loads(described.get("input") or "{}")})
            ok, detail, evidence = evaluate_elevations_justified(recent)
        return CheckResult(check.id, ok, evidence, detail)

    def _gcp_pinned_image_present(self, check: CheckDefinition) -> CheckResult:
        """The image the pipeline is pinned to still exists in its registry.

        Requires params: project_id, declaration (the file declaring the
        pin), variable. The pin is read from the declaration, so the check
        and the deployment cannot disagree about which digest matters. The
        registry's images come from Cloud Asset. The safety net for the
        registry's cleanup policy (2026-10-03).
        """
        import re
        from pathlib import Path

        p = check.params
        text = (Path(__file__).resolve().parents[2] / p["declaration"]).read_text()
        block = text.split(f'variable "{p["variable"]}"', 1)[-1]
        match = re.search(r'default\s*=\s*"[^"@]+@(sha256:[0-9a-f]{64})"', block)
        pinned = match.group(1) if match else None
        present = [res.name.rsplit("@", 1)[-1] for res in asset_client(p["project_id"]).search_all_resources(
            request={"scope": f"projects/{p['project_id']}", "asset_types": ["artifactregistry.googleapis.com/DockerImage"]})]
        ok, detail = evaluate_pinned_present(pinned, present)
        return CheckResult(check.id, ok, {"pinned": pinned, "images": len(present)}, detail)

    def _gcp_run_job_images(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-VRI verify 1, GCP: every Cloud Run job's containers are pinned by digest.

        Requires params: project_id, region, jobs. Read from Cloud Run, the
        configuration that runs, with the same judgement as ECS's.
        """
        from google.auth.transport.requests import AuthorizedSession

        from gcp_auth import impersonated_token

        p = check.params
        session = AuthorizedSession(impersonated_token(p["project_id"]))
        definitions = {}
        for job in p["jobs"]:
            response = session.get(
                f"https://run.googleapis.com/v2/projects/{p['project_id']}/locations/{p['region']}/jobs/{job}", timeout=30)
            response.raise_for_status()
            containers = response.json()["template"]["template"].get("containers", [])
            definitions[job] = [{"name": c.get("name") or job, "image": c.get("image", "")} for c in containers]
        ok, detail, evidence = evaluate_task_definitions(definitions, "digest_pinned")
        return CheckResult(check.id, ok, evidence, detail)

    def _aws_database_backups_restorable(self, check: CheckDefinition) -> CheckResult:
        """KSI-SVC-SIN verify 8: every retained backup is encrypted with a customer key that can still decrypt it.

        Requires param: region. Snapshots and retained automated backups
        persist between sessions by design (DECISIONS.md, 2026-09-05), so
        this reads them whether or not the environment stands. A backup
        whose key is pending deletion becomes unrestorable on the key's
        deletion date, which is reported.
        """
        region = check.params["region"]
        rds = boto3.client("rds", region_name=region)
        kms = boto3.client("kms", region_name=region)
        backups = []
        for page in rds.get_paginator("describe_db_snapshots").paginate():
            for s in page["DBSnapshots"]:
                backups.append({"id": s["DBSnapshotIdentifier"], "encrypted": s.get("Encrypted", False),
                                "key": s.get("KmsKeyId")})
        for page in rds.get_paginator("describe_db_instance_automated_backups").paginate():
            for b in page["DBInstanceAutomatedBackups"]:
                if b.get("Status") == "retained":
                    backups.append({"id": f"retained automated backups of {b['DBInstanceIdentifier']}",
                                    "encrypted": b.get("Encrypted", False), "key": b.get("KmsKeyId")})
        for b in backups:
            if b["key"]:
                try:
                    meta = kms.describe_key(KeyId=b["key"])["KeyMetadata"]
                except kms.exceptions.NotFoundException:
                    # Deleted: the backup can never be decrypted again.
                    b.update(key_manager="CUSTOMER", key_state="Deleted", deletion_date=None)
                    continue
                b.update(key_manager=meta["KeyManager"], key_state=meta["KeyState"],
                         deletion_date=str(meta.get("DeletionDate") or "") or None)
        ok, detail, evidence = evaluate_backups_restorable(backups)
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


def _iso_duration_seconds(value: str) -> int | None:
    """Seconds in an ISO 8601 duration of hours and minutes, e.g. PT4H or PT1H30M."""
    import re

    match = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", value or "")
    if not match:
        return None
    return int(match.group(1) or 0) * 3600 + int(match.group(2) or 0) * 60


def _web_identity_problems(statement: dict, provider: str) -> list[str]:
    """What a web-identity trust statement fails to pin. Empty means sound."""
    host = provider.split("oidc-provider/")[-1]
    equals = (statement.get("Condition") or {}).get("StringEquals", {})
    likes = {k for op, block in (statement.get("Condition") or {}).items() if op != "StringEquals" for k in block}
    problems = []
    for claim in ("sub", "aud"):
        key = f"{host}:{claim}"
        values = _as_list(equals.get(key, []))
        if not values:
            problems.append(f"{claim} not pinned with StringEquals")
        elif any("*" in v or "?" in v for v in values):
            problems.append(f"{claim} contains a wildcard")
        if key in likes:
            problems.append(f"{claim} also matched by a non-exact operator")
    return problems


def evaluate_role_trusts(roles: list[dict], exempt_paths: list[dict]) -> tuple[bool, str, dict]:
    """Every role's trust names who may assume it exactly.

    Wildcard principals fail anywhere. A web-identity trust must pin both
    subject and audience with StringEquals and no wildcard: an unpinned
    subject lets any repository or account behind the same issuer assume
    the role. A SAML trust must pin its audience. Service-linked roles are
    exempt by path prefix, with the reason recorded: AWS writes their trust,
    and the /aws-service-role/ path is reserved to AWS, so no customer role
    can sit under it.
    """
    results = {}
    for role in roles:
        exempt = next((e for e in exempt_paths if role["path"].startswith(e["path"])), None)
        if exempt:
            results[role["role"]] = {"passed": True, "detail": f"exempt: {exempt['reason']}"}
            continue
        problems = []
        for st in role["document"].get("Statement", []):
            if st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            actions = _as_list(st.get("Action", []))
            if principal == "*" or (isinstance(principal, dict) and "*" in _as_list(principal.get("AWS", []))):
                problems.append("wildcard principal")
                continue
            for provider in _as_list((principal or {}).get("Federated", [])) if isinstance(principal, dict) else []:
                if "sts:AssumeRoleWithWebIdentity" in actions:
                    problems += [f"{provider}: {p}" for p in _web_identity_problems(st, provider)]
                elif "sts:AssumeRoleWithSAML" in actions:
                    aud = (st.get("Condition") or {}).get("StringEquals", {}).get("SAML:aud")
                    if not aud:
                        problems.append(f"{provider}: SAML audience not pinned")
        results[role["role"]] = {"passed": not problems,
                                 "detail": "; ".join(problems) or "trust names its principals exactly"}
    return _judged("roles", results)


def evaluate_session_bounds(roles: list[dict], max_seconds: dict[str, int]) -> tuple[bool, str, dict]:
    """Every federated session ends within its kind's ceiling.

    Each role is {role, kind, seconds}: kind "web_identity" uses the role's
    MaxSessionDuration; "identity_center" uses its permission set's session
    duration, which is what bounds that session, not the reserved role's own
    12-hour setting.
    """
    return _judged("roles", {
        r["role"]: {"passed": r["seconds"] is not None and r["seconds"] <= max_seconds[r["kind"]],
                    "detail": f"{r['kind']}: {r['seconds']} seconds" if r["seconds"] is not None else
                              f"{r['kind']}: session length unknown"}
        for r in roles
    })


def evaluate_oidc_providers(providers: list[dict], expected: list[dict]) -> tuple[bool, str, dict]:
    """The providers present are exactly the expected ones, each with exactly its audiences."""
    want = {e["url"]: sorted(e["client_ids"]) for e in expected}
    have = {p["url"]: sorted(p["client_ids"]) for p in providers}
    results = {}
    for url in sorted(set(want) | set(have)):
        if url not in have:
            results[url] = {"passed": False, "detail": "expected provider missing"}
        elif url not in want:
            results[url] = {"passed": False, "detail": "provider not in the declared list"}
        elif have[url] != want[url]:
            results[url] = {"passed": False, "detail": f"audiences {have[url]}, expected {want[url]}"}
        else:
            results[url] = {"passed": True, "detail": f"audiences {have[url]}"}
    return _judged("providers", results)


def evaluate_wif_provider(provider: dict | None, issuer: str, required_clauses: list[str]) -> tuple[bool, str]:
    """A workload identity provider: active, the expected issuer, and every
    required clause present in its attribute condition."""
    if not provider:
        return False, "provider not found"
    if provider.get("disabled") or provider.get("state") != "ACTIVE":
        return False, f"provider state {provider.get('state')!r}"
    actual = (provider.get("oidc") or {}).get("issuerUri")
    if actual != issuer:
        return False, f"issuer {actual!r}, expected {issuer!r}"
    condition = provider.get("attributeCondition") or ""
    missing = [c for c in required_clauses if c not in condition]
    if missing:
        return False, "attribute condition lacks: " + "; ".join(missing)
    return True, "active, expected issuer, condition pins " + str(len(required_clauses)) + " clauses"


def evaluate_users_hold_no_policies(users: list[dict]) -> tuple[bool, str, dict]:
    """No user carries an inline policy, an attached policy, or a group."""
    if not users:
        return True, "no IAM users exist, so none holds a policy", {"users": {}, "failing": []}
    return _judged("users", {
        u["user"]: {"passed": not (u["inline"] or u["attached"] or u["groups"]),
                    "detail": f"inline {u['inline']}, attached {u['attached']}, groups {u['groups']}"}
        for u in users
    })


def evaluate_guardduty(detector: dict | None, declared_on: list[str], frequency: str) -> tuple[bool, str, dict]:
    """Enabled, publishing at the declared frequency, and every plan on exactly
    when declared on: an undeclared plan bills and an absent one blinds."""
    if not detector or detector.get("status") != "ENABLED":
        return False, "no enabled detector", {"detector": detector}
    results = {}
    if detector.get("frequency") != frequency:
        results["publishing frequency"] = {"passed": False,
                                           "detail": f"{detector.get('frequency')}, expected {frequency}"}
    features = detector.get("features", {})
    for name in sorted(set(features) | set(declared_on)):
        on = features.get(name) == "ENABLED"
        want = name in declared_on
        results[name] = {"passed": on == want,
                         "detail": f"{'on' if on else 'off'}, declared {'on' if want else 'off'}"}
    return _judged("settings", results)


def evaluate_standards(subscriptions: dict[str, str], expected: list[str]) -> tuple[bool, str, dict]:
    """Every expected standard subscribed and READY."""
    return _judged("standards", {
        arn: {"passed": subscriptions.get(arn) == "READY", "detail": subscriptions.get(arn, "not subscribed")}
        for arn in expected
    })


def evaluate_trail_data_events(scoped: list[str], declared: list[str]) -> tuple[bool, str, dict]:
    """Data events cover exactly the declared customer-data stores.

    Both directions: a declared store without data events is customer-data
    access going unrecorded, and an undeclared one is billing for scope
    nobody chose (DECISIONS.md, 2026-09-05).
    """
    results = {}
    for prefix in sorted(set(scoped) | set(declared)):
        if prefix not in scoped:
            results[prefix] = {"passed": False, "detail": "declared customer-data store, no data events"}
        elif prefix not in declared:
            results[prefix] = {"passed": False, "detail": "data events on a store not declared as customer data"}
        else:
            results[prefix] = {"passed": True, "detail": "data events recorded"}
    if not results:
        return False, "no customer-data stores declared -- nothing to judge", {"stores": {}, "failing": []}
    return _judged("stores", results)


def evaluate_dataset_access(found: dict[str, list[dict]],
                            declared: dict[str, list[dict]]) -> tuple[bool, str, dict]:
    """Each dataset's access entries are exactly its declared ones; a dataset
    without a declared model fails."""
    results = {}
    for dataset, entries in sorted(found.items()):
        if dataset not in declared:
            results[dataset] = {"passed": False, "detail": "no declared access model", "entries": entries}
            continue
        have = {(e["role"], e["member"]) for e in entries}
        want = {(e["role"], e["member"]) for e in declared[dataset]}
        extra, missing = sorted(have - want), sorted(want - have)
        problems = [f"undeclared {r} for {m}" for r, m in extra] + [f"declared {r} for {m} absent" for r, m in missing]
        results[dataset] = {"passed": not problems, "detail": "; ".join(problems) or "access matches the declared model",
                            "entries": entries}
    return _judged("datasets", results)


def evaluate_alarms_target(found: dict[str, dict], expected: list[str], topic: str) -> tuple[bool, str, dict]:
    results = {}
    for name in expected:
        alarm = found.get(name)
        if alarm is None:
            results[name] = {"passed": False, "detail": "alarm missing"}
        elif not alarm["actions_enabled"]:
            results[name] = {"passed": False, "detail": "actions disabled, so it alarms silently"}
        elif topic not in alarm["actions"]:
            results[name] = {"passed": False, "detail": f"does not notify the detection topic: {alarm['actions']}"}
        else:
            results[name] = {"passed": True, "detail": "notifies the detection topic"}
    return _judged("alarms", results)


def evaluate_registry_scanning(config: dict, inspector: dict) -> tuple[bool, str]:
    if config.get("scanType") != "ENHANCED":
        return False, f"scan type {config.get('scanType')!r}, expected ENHANCED"
    every = any(
        rule.get("scanFrequency") == "CONTINUOUS_SCAN"
        and any(f.get("filter") == "*" and f.get("filterType") == "WILDCARD" for f in rule.get("repositoryFilters", []))
        for rule in config.get("rules", [])
    )
    if not every:
        return False, "no continuous-scan rule covering every repository"
    if inspector.get("account") != "ENABLED" or inspector.get("ecr") != "ENABLED":
        return False, f"Inspector account {inspector.get('account')}, ECR {inspector.get('ecr')}"
    return True, "enhanced continuous scanning on every repository, Inspector on"


def evaluate_scheduled_functions(found: dict[str, dict | None]) -> tuple[bool, str, dict]:
    results = {}
    for rule, r in found.items():
        if r is None:
            ok, detail = False, "rule or function missing"
        elif r["state"] != "ENABLED":
            ok, detail = False, f"rule {r['state']}"
        elif not r["schedule"]:
            ok, detail = False, "rule has no schedule"
        elif r["function_arn"] not in r["targets"]:
            ok, detail = False, "rule does not invoke the function"
        else:
            ok, detail = True, f"{r['schedule']}, invokes the function"
        results[rule] = {"passed": ok, "detail": detail}
    return _judged("schedules", results)


def evaluate_certificates(certs: list[dict], min_days: int) -> tuple[bool, str, dict]:
    """ACM-issued, DNS-validated, and either renewal-eligible or safely unexpired.

    ACM marks a certificate eligible only while it is in use, so between
    sessions, with the load balancer down, it reads INELIGIBLE. In use it
    must be eligible; not in use it must have min_days left, which is the
    case where an idle certificate would lapse unnoticed. Email validation
    fails: renewal would wait on someone answering a mail.
    """
    results = {}
    for c in certs:
        if c["type"] != "AMAZON_ISSUED":
            ok, detail = False, f"{c['type']}, not issued by ACM, so ACM does not renew it"
        elif c["validation"] != ["DNS"]:
            ok, detail = False, f"validated by {c['validation']}, not DNS alone"
        elif c["in_use"] and not c["eligible"]:
            ok, detail = False, "in use but not eligible for renewal"
        elif c["days_left"] is None or c["days_left"] < min_days:
            ok, detail = False, f"{c['days_left']} days left"
        else:
            ok, detail = True, (f"ACM-issued, DNS-validated, {'eligible' if c['in_use'] else 'idle'}, "
                                f"{c['days_left']} days left")
        results[c["domain"]] = {"passed": ok, "detail": detail}
    return _judged("certificates", results)


def evaluate_config_recorder(recorders: list[dict], statuses: dict[str, dict]) -> tuple[bool, str]:
    """At least one recorder, and every recorder recording: a stopped
    recorder exists and collects nothing."""
    if not recorders:
        return False, "no Config recorder exists"
    stopped = [r["name"] for r in recorders if not statuses.get(r["name"], {}).get("recording", False)]
    if stopped:
        return False, f"recorder exists but is not recording: {', '.join(stopped)}"
    return True, "recorder present and recording"


def evaluate_asset_feed(feed: dict | None) -> tuple[bool, str]:
    """The feed exists and watches at least one asset type; a feed watching
    none is configured but inert."""
    if not feed:
        return False, "feed not found"
    if not feed.get("asset_types"):
        return False, "feed watches no asset types"
    return True, "feed exists with asset types configured"


def evaluate_workflow_state(state: str | None) -> tuple[bool, str]:
    """Only "active" runs. GitHub's other states are all ways of not running:
    disabled_manually, disabled_inactivity, disabled_fork, deleted."""
    return state == "active", f"workflow state {state!r}"


_WIDE = ("0.0.0.0/0", "::/0")


def evaluate_private_routes(tables: list[dict], private_tiers: list[str]) -> tuple[bool, str, dict]:
    """Private route tables route only within the VPC and to gateway endpoints.

    "local" and vpce- targets are the only ones allowed: an internet or NAT
    gateway, a peering, a transit gateway or an instance route all reach
    outside. Every private tier must have a table, or there is nothing to judge.
    """
    results = {}
    for tier in private_tiers:
        mine = [t for t in tables if t["tier"] == tier]
        if not mine:
            results[f"tier {tier}"] = {"passed": False, "detail": "no route table for this tier"}
        for t in mine:
            outside = [f"{r['destination']} via {r['target']}" for r in t["routes"]
                       if not (r["target"] == "local" or (r["target"] or "").startswith("vpce-"))]
            results[f"{tier} {t['id']}"] = {"passed": not outside,
                                            "detail": "routes outside the VPC: " + ", ".join(outside) if outside
                                            else "local and gateway-endpoint routes only"}
    return _judged("route tables", results)


def evaluate_rules_match_flows(live: list[dict], declared: list[dict]) -> tuple[bool, str, dict]:
    """Live and declared rules are the same set. A live rule with no flow is
    an open port nobody declared; a declared rule not live is a flow that
    does not work. All protocols (-1) never matches a declared port."""
    key = lambda r: (r["group"], r["direction"], r["port"], r["peer"])
    live_keys = {key(r) for r in live if r.get("protocol") in ("tcp", "6")}
    live_keys |= {key(r) + ("all protocols",) for r in live if r.get("protocol") not in ("tcp", "6")}
    declared_keys = {key(r) for r in declared}
    undeclared = sorted(map(str, live_keys - declared_keys))
    missing = sorted(map(str, declared_keys - live_keys))
    evidence = {"live": len(live_keys), "declared": len(declared_keys), "undeclared": undeclared, "not_live": missing}
    if not live:
        return False, "no rules found -- nothing to judge", evidence
    if undeclared or missing:
        return False, f"{len(undeclared)} open port(s) with no declared flow, {len(missing)} declared rule(s) not live", evidence
    return True, f"all {len(live_keys)} rules are declared flows, and every declared flow is open", evidence


def evaluate_open_rules(rules: list[dict], allowed: list[dict], direction: str) -> tuple[bool, str, dict]:
    """No rule open to 0.0.0.0/0 or ::/0, except a declared (group, port).

    An allowance names one port. A rule open to everywhere on all
    protocols, or a range, never matches one, so it always fails.
    """
    ok_pairs = {(a["group"], a["port"]) for a in allowed}
    results = {}
    for r in rules:
        if r["cidr"] not in _WIDE:
            continue
        key = f"{r['group']} {r['protocol']} {r['from']}-{r['to']} {r['cidr']}"
        single = r["protocol"] == "tcp" and r["from"] == r["to"]
        allowed_here = single and (r["group"], r["from"]) in ok_pairs
        results[key] = {"passed": allowed_here,
                        "detail": "declared public-facing" if allowed_here else f"{direction} open to {r['cidr']}"}
    if not rules:
        return False, "no rules found -- nothing to judge", {"rules": {}, "failing": []}
    if not results:
        return True, f"no {direction} rule open to anywhere", {"rules": {}, "failing": []}
    return _judged("rules", results)


def evaluate_endpoint_policies(endpoints: list[dict], principal_exceptions: list[dict] = ()) -> tuple[bool, str, dict]:
    """Every endpoint carries a policy that restricts both who and what.

    An Allow statement must name its principals or condition them, and must
    not allow every action. AWS's default endpoint policy -- everyone,
    everything -- fails both.

    One exception shape, declared with its reason: a statement whose every
    resource is a listed AWS-owned resource may leave the principal open,
    where AWS serves the access in a way no principal can be named for. ECR
    image layers are that case: pulls fetch them from ECR's own S3 bucket by
    pre-signed URL, so the request does not carry the task's role. The
    resource scoping is then the restriction, and the rule against wildcard
    actions still applies.
    """
    excepted = {e["resource"] for e in principal_exceptions}
    results = {}
    for e in endpoints:
        problems = []
        statements = [s for s in e["policy"].get("Statement", []) if s.get("Effect") == "Allow"]
        if not statements:
            problems.append("no policy")
        for s in statements:
            principal = s.get("Principal")
            everyone = principal == "*" or (isinstance(principal, dict) and "*" in _as_list(principal.get("AWS", [])))
            resources = set(_as_list(s.get("Resource", [])))
            if everyone and not s.get("Condition") and not (resources and resources <= excepted):
                problems.append("any principal, unconditioned")
            if any(a == "*" or a.endswith(":*") for a in _as_list(s.get("Action", []))):
                problems.append("every action")
        results[f"{e['service']} ({e['type']})"] = {"passed": not problems,
                                                     "detail": "; ".join(problems) or "principals and actions restricted"}
    return _judged("endpoints", results)


def evaluate_load_balancer_tls(listeners: list[dict], groups: list[dict],
                               allowed_policies: list[str]) -> tuple[bool, str, dict]:
    results = {}
    for l in listeners:
        name = f"listener {l['protocol']}:{l['port']}"
        if l["protocol"] == "HTTPS":
            ok = l["policy"] in allowed_policies
            results[name] = {"passed": ok, "detail": f"policy {l['policy']}"}
        elif l["protocol"] == "HTTP":
            redirects = [a for a in l["actions"] if a["type"] == "redirect"]
            ok = bool(redirects) and all(a.get("protocol") == "HTTPS" and a.get("status") == "HTTP_301" for a in redirects) \
                and len(redirects) == len(l["actions"])
            results[name] = {"passed": ok, "detail": "redirects to HTTPS (301)" if ok else f"actions {l['actions']}"}
        else:
            results[name] = {"passed": False, "detail": f"unexpected protocol {l['protocol']}"}
    if not any(l["protocol"] == "HTTPS" for l in listeners):
        results["https listener"] = {"passed": False, "detail": "none"}
    for g in groups:
        ok = g["protocol"] == "HTTPS" and g["health_protocol"] == "HTTPS"
        results[f"target group {g['name']}"] = {"passed": ok,
                                                "detail": f"traffic {g['protocol']}, health checks {g['health_protocol']}"}
    return _judged("settings", results)


def evaluate_database_settings(instance: dict, values: dict, required: dict, min_backup_days: int) -> tuple[bool, str, dict]:
    results = {name: {"passed": values.get(name) == want, "detail": f"{values.get(name)!r}, required {want!r}"}
               for name, want in required.items()}
    results["IAM authentication"] = {"passed": bool(instance["iam_auth"]), "detail": str(instance["iam_auth"])}
    results["backup retention"] = {"passed": instance["backup_days"] >= min_backup_days,
                                   "detail": f"{instance['backup_days']} days, required {min_backup_days}"}
    results["storage encrypted"] = {"passed": bool(instance["encrypted"]), "detail": str(instance["encrypted"])}
    return _judged("settings", results)


def _container_problems(c: dict, assertion: str) -> list[str]:
    linux = c.get("linuxParameters") or {}
    caps = linux.get("capabilities") or {}
    if assertion == "hardened":
        problems = []
        if not c.get("readonlyRootFilesystem"):
            problems.append("root filesystem writable")
        user = str(c.get("user") or "")
        if not user or user.split(":")[0] in ("root", "0"):
            problems.append(f"user {user or 'unset'}")
        if "ALL" not in (caps.get("drop") or []):
            problems.append("capabilities not dropped")
        if caps.get("add"):
            problems.append(f"capabilities added: {caps['add']}")
        if c.get("privileged"):
            problems.append("privileged")
        return problems
    if assertion == "explicit":
        return [f"{field} not stated" for field, present in (
            ("command", bool(c.get("command") or c.get("entryPoint"))),
            ("user", bool(c.get("user"))),
            ("capabilities", "capabilities" in linux),
            ("ports", "portMappings" in c),
        ) if not present]
    if assertion == "digest_pinned":
        return [] if "@sha256:" in c.get("image", "") else [f"image by tag: {c.get('image')}"]
    if assertion == "no_literal_secrets":
        # Secret material reaches a task through `secrets` (a Secrets
        # Manager reference), never as a literal in `environment`, where it
        # would sit in the task definition for anyone who can describe it.
        problems = []
        for e in c.get("environment") or []:
            name, value = str(e.get("name", "")), str(e.get("value", ""))
            if value and _SECRET_NAME.search(name):
                problems.append(f"{name} set as a literal")
            elif _SECRET_VALUE.search(value):
                problems.append(f"{name} holds what looks like key material")
        return problems
    raise ValueError(f"unknown assertion {assertion!r}")


import re as _re

_SECRET_NAME = _re.compile(r"PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE_KEY|API_KEY|CREDENTIAL", _re.I)
_SECRET_VALUE = _re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(AKIA|ASIA)[0-9A-Z]{16}\b")


def evaluate_task_definitions(definitions: dict[str, list[dict]], assertion: str) -> tuple[bool, str, dict]:
    """Every container of every running service's task definition. A
    definition with no containers is one that should exist and does not."""
    results = {}
    for service, containers in definitions.items():
        if not containers:
            results[service] = {"passed": False, "detail": "no active task definition"}
        for c in containers:
            problems = _container_problems(c, assertion)
            results[f"{service}/{c.get('name')}"] = {"passed": not problems, "detail": "; ".join(problems) or "ok"}
    return _judged("containers", results)


def evaluate_pinned_present(pinned: str | None, present: list[str]) -> tuple[bool, str]:
    if not pinned:
        return False, "no digest pin found in the declaration"
    if pinned not in present:
        return False, f"pinned {pinned[:19]}... is gone from the registry; the next run cannot start"
    return True, f"pinned {pinned[:19]}... present among {len(present)} images"


def evaluate_services_enabled(states: dict[str, str | None]) -> tuple[bool, str, dict]:
    return _judged("services", {s: {"passed": st == "ENABLED", "detail": str(st)} for s, st in states.items()})


def evaluate_external_access(analyzer: bool, findings: list[dict], declared: list[dict]) -> tuple[bool, str, dict]:
    """An active analyzer, no public finding, and every finding on a declared resource."""
    if not analyzer:
        return False, "no active account analyzer -- external access is unexamined", {"findings": []}
    undeclared = [f for f in findings if f["public"] or not any(
        fnmatch.fnmatchcase(f["resource"] or "", d["resource"]) for d in declared)]
    evidence = {"findings": findings, "undeclared": undeclared}
    if undeclared:
        return False, f"{len(undeclared)} external access path(s) not on the declared list", evidence
    return True, f"all {len(findings)} external access path(s) declared", evidence


def evaluate_sources_catalogued(stored: list[str], catalogued: list[str]) -> tuple[bool, str, dict]:
    """No source in the store that the catalog cannot read, and the store not empty."""
    missing = sorted(set(stored) - set(catalogued))
    evidence = {"stored": stored, "catalogued": catalogued, "not_queryable": missing}
    if not stored:
        return False, "no sources in the store -- nothing to judge", evidence
    if missing:
        return False, f"in the store but not queryable: {', '.join(missing)}", evidence
    return True, f"all {len(stored)} stored source(s) queryable", evidence


def evaluate_snapshots_accounted(snapshots: list[dict], live: set[str], retained: list[dict]) -> tuple[bool, str, dict]:
    """Each snapshot's instance is live, or registered as one whose backups are kept."""
    registered = {r["instance"]: r["reason"] for r in retained}
    results = {}
    for s in snapshots:
        if s["instance"] in live:
            results[s["id"]] = {"passed": True, "detail": "source instance live"}
        elif s["instance"] in registered:
            results[s["id"]] = {"passed": True, "detail": f"registered: {registered[s['instance']]}"}
        else:
            results[s["id"]] = {"passed": False, "detail": f"orphaned: {s['instance']} is gone and unregistered"}
    if not snapshots:
        return True, "no snapshots", {"snapshots": {}, "failing": []}
    return _judged("snapshots", results)


def evaluate_failing_controls(findings: list[dict], exceptions: list[dict], today: str | None = None) -> tuple[bool, str, dict]:
    """Every failing control finding is covered by a current exception with a reason.

    An exception may carve out resources it never covers (unless_resources,
    glob patterns): KMS.3 is excepted for session keys deleted at teardown,
    never for the keys meant to persist. An exception counts only with a
    reason and a review date not yet passed (KSI-CNA-IBP verify 4): one
    past its date has lapsed, and its control is open again.
    """
    from datetime import date

    today = today or date.today().isoformat()
    current = [e for e in exceptions if (e.get("reason") or "").strip() and (e.get("review_by") or "") >= today]
    lapsed = sorted({e["control"] for e in exceptions} - {e["control"] for e in current})

    def excepted(f):
        for e in current:
            if e["control"] == f["control"] and not any(
                    fnmatch.fnmatchcase(f["resource"], p) for p in e.get("unless_resources", [])):
                return e
        return None

    controls = {}
    for f in findings:
        c = controls.setdefault(f["control"], {"passed": 0, "failed": [], "excepted": []})
        if f["status"] == "PASSED":
            c["passed"] += 1
        elif excepted(f):
            c["excepted"].append(f["resource"])
        else:
            c["failed"].append(f["resource"])
    open_ = {k: v for k, v in controls.items() if v["failed"]}
    evaluated = len(controls)
    clean = sum(1 for v in controls.values() if not v["failed"] and not v["excepted"])
    evidence = {"pass_rate": f"{clean}/{evaluated} controls passing outright", "lapsed_exceptions": lapsed,
                "open": {k: {"resources": v["failed"],
                             "severity": next((f["severity"] for f in findings if f["control"] == k), None)}
                         for k, v in sorted(open_.items())},
                "excepted": {k: v["excepted"] for k, v in sorted(controls.items()) if v["excepted"]}}
    if not findings:
        return False, "no control findings -- nothing to judge", evidence
    if open_:
        return False, f"{len(open_)} failing control(s) neither remediated nor excepted: {', '.join(sorted(open_))}", evidence
    return True, f"every failing control is excepted; {evidence['pass_rate']}", evidence


def evaluate_validate_logs(output: str, returncode: int) -> tuple[bool, str]:
    """Every digest and log file valid, and some of each found.

    The validator prints "N/M digest files valid" and "N/M log files
    valid", and an INVALID line for anything tampered with, missing, or
    unreadable. Zero files is a failure: an empty window validates
    vacuously, which is not evidence of integrity.
    """
    import re

    counts = {kind: tuple(map(int, m.groups()))
              for kind in ("digest", "log")
              for m in [re.search(rf"(\d+)/(\d+) {kind} files valid", output)] if m}
    if returncode != 0:
        return False, f"validator exited {returncode}"
    if "INVALID" in output:
        return False, "validator reported INVALID files"
    for kind in ("digest", "log"):
        if kind not in counts:
            return False, f"no {kind} file count reported"
        valid, total = counts[kind]
        if total == 0 or valid != total:
            return False, f"{valid}/{total} {kind} files valid"
    return True, f"{counts['digest'][0]} digest and {counts['log'][0]} log files valid"


def evaluate_function_runs(found: dict[str, dict]) -> tuple[bool, str, dict]:
    return _judged("functions", {
        name: {"passed": f["invocations"] >= 1 and f["errors"] == 0,
               "detail": f"{f['invocations']:g} run(s), {f['errors']:g} error(s) in {f['within_hours']}h"}
        for name, f in found.items()
    })


def evaluate_vpcs_declared(vpcs: list[dict], allowed: list[dict]) -> tuple[bool, str, dict]:
    """No VPC outside the declared list; a default VPC is never declared.

    None at all passes: between sessions the project VPC is torn down, and
    an account with no networks has none undeclared.
    """
    ok_pairs = {(a["region"], a["name"]) for a in allowed}
    results = {
        f"{v['region']} {v['id']}": {
            "passed": not v["default"] and (v["region"], v["name"]) in ok_pairs,
            "detail": "default VPC" if v["default"] else
                      ("declared" if (v["region"], v["name"]) in ok_pairs else f"undeclared ({v['name']})"),
        }
        for v in vpcs
    }
    if not results:
        return True, "no VPCs in any region", {"vpcs": {}, "failing": []}
    return _judged("vpcs", results)


_READ_ACTIONS = ("s3:GetObject", "s3:GetObjectVersion")


def _covers(action_patterns: list[str], action: str) -> bool:
    return any(fnmatch.fnmatchcase(action, p) for p in action_patterns)


def evaluate_read_deny(policy: dict | None, bucket: str, readers: list[str]) -> tuple[bool, str]:
    """A Deny on every principal reading the bucket's objects, unless its
    aws:PrincipalArn is one of exactly the declared readers.

    Exactly: an extra exemption is an undeclared reader, and a missing one a
    declared reader locked out. Both GetObject and GetObjectVersion must be
    covered, or a reader takes the old version instead.
    """
    if not policy:
        return False, "no bucket policy"
    objects = f"arn:aws:s3:::{bucket}/*"
    for st in policy.get("Statement", []):
        principal = st.get("Principal")
        everyone = principal == "*" or (isinstance(principal, dict) and _as_list(principal.get("AWS", [])) == ["*"])
        if st.get("Effect") != "Deny" or not everyone:
            continue
        if objects not in _as_list(st.get("Resource", [])) and "*" not in _as_list(st.get("Resource", [])):
            continue
        actions = _as_list(st.get("Action", []))
        if not all(_covers(actions, a) for a in _READ_ACTIONS):
            continue
        condition = st.get("Condition") or {}
        exempt = None
        for op in ("ArnNotLike", "ArnNotEquals", "StringNotLike", "StringNotEquals"):
            if "aws:PrincipalArn" in condition.get(op, {}):
                exempt = set(_as_list(condition[op]["aws:PrincipalArn"]))
        if exempt is None or set(condition) - {"ArnNotLike", "ArnNotEquals", "StringNotLike", "StringNotEquals"}:
            continue
        extra, missing = sorted(exempt - set(readers)), sorted(set(readers) - exempt)
        if extra or missing:
            return False, (f"read deny exempts undeclared {extra}" if extra else "") + \
                (f"; declared readers not exempted {missing}" if missing else "")
        return True, f"object reads denied to all but the {len(readers)} declared readers"
    return False, "no statement denies object reads outside a declared reader list"


def evaluate_backups_restorable(backups: list[dict]) -> tuple[bool, str, dict]:
    """Every backup encrypted with a customer key that is enabled.

    A key pending deletion still decrypts until its date and never after,
    so a backup under it has an expiry nobody chose. No backups at all
    passes: whether backups exist is CNA-OFA's question, not this row's.
    """
    if not backups:
        return True, "no database backups retained", {"backups": {}, "failing": []}
    results = {}
    for b in backups:
        if not b["encrypted"]:
            ok, detail = False, "not encrypted"
        elif b.get("key_manager") != "CUSTOMER":
            ok, detail = False, f"encrypted with an AWS-managed key ({b.get('key')})"
        elif b.get("key_state") != "Enabled":
            ok, detail = False, (f"key {b.get('key_state')}"
                                 + (f": unrestorable after {b['deletion_date']}" if b.get("deletion_date") else ""))
        else:
            ok, detail = True, "customer key, enabled"
        results[b["id"]] = {"passed": ok, "detail": detail}
    return _judged("backups", results)


def evaluate_state_bucket(versioning: str | None, encryption: str | None) -> tuple[bool, str]:
    if versioning != "Enabled":
        return False, f"versioning {versioning or 'never enabled'}"
    if not encryption:
        return False, "no default encryption"
    return True, f"versioning enabled, default encryption {encryption}"


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


# --- KSI-IAM-JIT (2026-10-03) ---

ELEVATION_RESOURCES = {"elevated_unassigned", "standing_assignments", "elevated_bounded",
                       "elevation_backstop", "elevations_within_window", "elevations_justified",
                       "elevations_revoked"}
# The workflow's own bounds (lambda/elevation/handler.py), restated here so
# a check that judges the history does not trust the code it is judging.
ELEVATION_MIN_JUSTIFICATION, ELEVATION_MINUTES = 20, (15, 240)


def _requested_minutes(sfn, execution_arn: str) -> int | None:
    request = json.loads(sfn.describe_execution(executionArn=execution_arn).get("input") or "{}")
    minutes = request.get("minutes", 60)
    return minutes if isinstance(minutes, int) and not isinstance(minutes, bool) else None


def evaluate_elevated_unassigned(exists: bool, held: list[dict], running: list[dict]) -> tuple[bool, str, dict]:
    """verify 2: the elevated permission set exists and nothing holds it outside an elevation."""
    evidence = {"assignments": held, "running_elevations": running}
    if not exists:
        return False, "no elevated permission set -- there is nothing to elevate to", evidence
    if held and not running:
        return False, f"{len(held)} elevated assignment(s) with no running elevation", evidence
    if held:
        return True, f"assigned only for {len(running)} running elevation(s)", evidence
    return True, "the elevated permission set exists with no assignment", evidence


def evaluate_standing_assignments(assigned: list[dict], allowed: list[str], elevated: str,
                                  running: list[dict]) -> tuple[bool, str, dict]:
    """verify 3: every assignment in the account is a declared standing one,
    or the elevated set held during a running elevation."""
    standing = [a for a in assigned if not (a["permission_set"] == elevated and running)]
    undeclared = [a for a in standing if a["permission_set"] not in allowed]
    evidence = {"assignments": assigned, "allowed": allowed, "undeclared": undeclared}
    if not standing:
        return False, "no standing assignment -- the operator has no way in", evidence
    if undeclared:
        names = sorted({a["permission_set"] for a in undeclared})
        return False, f"standing assignment(s) outside the declared set: {', '.join(names)}", evidence
    return True, f"{len(standing)} standing assignment(s), all to {', '.join(allowed)}", evidence


def evaluate_elevated_bounded(exists: bool, session_seconds: int | None, policy: dict | None,
                              max_session: int, home_region: str) -> tuple[bool, str, dict]:
    """verify 4: the elevated session is short, and its policy denies outside the home region."""
    evidence = {"session_seconds": session_seconds, "inline_policy": policy}
    if not exists:
        return False, "no elevated permission set", evidence
    problems = []
    if session_seconds is None or session_seconds > max_session:
        problems.append(f"session {session_seconds}s exceeds {max_session}s")
    bounded = False
    for st in (policy or {}).get("Statement", []):
        if st.get("Effect") != "Deny" or _as_list(st.get("Resource", [])) != ["*"]:
            continue
        cond = (st.get("Condition") or {}).get("StringNotEquals", {})
        if _as_list(cond.get("aws:RequestedRegion", [])) == [home_region] and (st.get("NotAction") or st.get("Action") == "*"):
            bounded = True
    if not bounded:
        problems.append(f"no Deny outside {home_region} on aws:RequestedRegion")
    if problems:
        return False, "; ".join(problems), evidence
    return True, f"session at most {session_seconds}s, denied outside {home_region}", evidence


def evaluate_elevation_backstop(rule: dict | None, targets: list[dict], function: str,
                                max_minutes: int) -> tuple[bool, str, dict]:
    """verify 5: the backstop's schedule exists, is enabled, is frequent, and runs the sweep."""
    import re

    evidence = {"rule": {k: rule.get(k) for k in ("Name", "State", "ScheduleExpression")} if rule else None,
                "targets": [{"arn": t.get("Arn"), "input": t.get("Input")} for t in targets]}
    if not rule:
        return False, "no backstop schedule", evidence
    problems = []
    if rule.get("State") != "ENABLED":
        problems.append(f"schedule is {rule.get('State')}")
    match = re.fullmatch(r"rate\((\d+) minutes?\)", rule.get("ScheduleExpression") or "")
    if not match or int(match.group(1)) > max_minutes:
        problems.append(f"schedule {rule.get('ScheduleExpression')!r} is not every {max_minutes} minutes or less")
    sweeps = [t for t in targets if (t.get("Arn") or "").endswith(f":function:{function}")
              and json.loads(t.get("Input") or "{}").get("action") == "sweep"]
    if not sweeps:
        problems.append(f"no target runs {function}'s sweep")
    if problems:
        return False, "; ".join(problems), evidence
    return True, f"{rule['ScheduleExpression']}, enabled, running the sweep", evidence


def evaluate_elevations_within_window(held: list[dict], running: list[dict], now: datetime,
                                      allowance_minutes: int) -> tuple[bool, str, dict]:
    """validate 2: no elevated assignment outlives its window.

    An assignment no running elevation accounts for has outlived its window
    by definition. A running elevation past its requested minutes plus the
    allowance -- the grant, the revocation and one backstop interval -- is
    overdue, and so is one whose window cannot be read.
    """
    overdue = []
    for e in running:
        started = datetime.fromisoformat(e["started"])
        if e["minutes"] is None or (now - started).total_seconds() > (e["minutes"] + allowance_minutes) * 60:
            overdue.append(e)
    evidence = {"assignments": held, "running_elevations": running, "overdue": overdue}
    if held and not running:
        return False, f"{len(held)} elevated assignment(s) outside any elevation", evidence
    if overdue:
        return False, f"{len(overdue)} elevation(s) past their window", evidence
    return True, f"{len(held)} elevated assignment(s), {len(running)} running elevation(s), none past its window", evidence


def evaluate_elevations_justified(executions: list[dict]) -> tuple[bool, str, dict]:
    """validate 1: every elevation that could have been granted carried a
    justification and a window within bounds.

    The workflow refuses the rest before granting, so a refused request
    that did not end FAILED means the refusal did not hold.
    """
    low, high = ELEVATION_MINUTES
    unjustified = []
    for e in executions:
        request = e["input"]
        minutes = request.get("minutes", 60)
        valid = (len(str(request.get("justification") or "").strip()) >= ELEVATION_MIN_JUSTIFICATION
                 and isinstance(minutes, int) and not isinstance(minutes, bool) and low <= minutes <= high)
        if not valid and e["status"] != "FAILED":
            unjustified.append({"arn": e["arn"], "status": e["status"]})
    evidence = {"executions": [{"arn": e["arn"], "status": e["status"],
                                "justification": e["input"].get("justification"),
                                "minutes": e["input"].get("minutes", 60)} for e in executions],
                "unjustified": unjustified}
    if unjustified:
        return False, f"{len(unjustified)} elevation(s) proceeded without a valid justification and window", evidence
    return True, f"{len(executions)} elevation(s) in the window, each justified and bounded or refused", evidence


# --- KSI-MLA-EVC, from GitHub (2026-10-05) ---

def _github_get(path: str) -> dict:
    """GET from GitHub's API. Token: GITHUB_TOKEN (CI), else the gh CLI's."""
    import os
    import subprocess
    import urllib.request

    token = os.environ.get("GITHUB_TOKEN") or subprocess.run(
        ["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
    request = urllib.request.Request(f"https://api.github.com/{path}", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def _push_range(title: str) -> tuple[str, str] | None:
    import re

    m = re.fullmatch(r"policy ([0-9a-f]{40}|none)\.\.([0-9a-f]{40})", title or "")
    return (m.group(1), m.group(2)) if m else None


def evaluate_pushes_chained(runs: list[dict], main: dict, now: datetime,
                            grace_minutes: int) -> tuple[bool, str, dict]:
    """validate 4: the evaluated pushes chain without a gap, up to main's head.

    The first run in the window anchors the chain; its own before is not
    judged, since the push before it predates the gate.
    """
    ordered = sorted(runs, key=lambda r: r["created"])
    gaps, unreadable, previous = [], [], None
    for r in ordered:
        rng = _push_range(r["title"])
        if rng is None or rng[1] != r["head"]:
            unreadable.append(r["title"])
            continue
        if previous is not None and rng[0] != previous:
            gaps.append({"after": previous, "next_run_before": rng[0], "run": r["url"]})
        previous = rng[1]
    pushed = datetime.fromisoformat(main["pushed"].replace("Z", "+00:00"))
    head_pending = main["sha"] != previous and (now - pushed).total_seconds() > grace_minutes * 60
    evidence = {"runs": len(ordered), "gaps": gaps, "unreadable": unreadable, "main": main,
                "last_evaluated": previous}
    if not ordered:
        return False, "no evaluated push -- the gate has not run on main", evidence
    if unreadable:
        return False, f"{len(unreadable)} run(s) without a readable push range", evidence
    if gaps:
        return False, f"{len(gaps)} push(es) to main with no evaluation", evidence
    if head_pending:
        return False, f"main's head {main['sha'][:12]} has no evaluation after {grace_minutes} minutes", evidence
    return True, f"{len(ordered)} push(es) to main, each evaluated, chained to the head", evidence


def evaluate_pushes_passed(runs: list[dict]) -> tuple[bool, str, dict]:
    """validate 5: no push to main whose evaluation failed.

    A failure is a declared configuration above the threshold, landed. Runs
    still in progress are not judged yet.
    """
    done = [r for r in runs if r["status"] == "completed"]
    failed = [{"title": r["title"], "conclusion": r["conclusion"], "url": r["url"]}
              for r in done if r["conclusion"] != "success"]
    evidence = {"completed": len(done), "failed": failed}
    if not done:
        return False, "no completed evaluation of a push -- nothing to judge", evidence
    if failed:
        return False, f"{len(failed)} push(es) to main failed the gate", evidence
    return True, f"all {len(done)} evaluated push(es) passed the gate", evidence


def evaluate_deliberate_test(run: dict | None, step: dict | None, now: datetime,
                             max_age_days: int) -> tuple[bool, str, dict]:
    """validate 1-3: the deliberate test's step succeeded on a run young enough."""
    evidence = {"run": run, "step": step}
    if run is None:
        return False, "the policy workflow has no completed run on main", evidence
    age = (now - datetime.fromisoformat(run["created"].replace("Z", "+00:00"))).total_seconds() / 86400
    evidence["age_days"] = round(age, 2)
    if step is None:
        return False, "the latest run has no deliberate test step", evidence
    if step["conclusion"] != "success":
        return False, f"the deliberate test concluded {step['conclusion']}", evidence
    if age > max_age_days:
        return False, f"the latest deliberate test is {age:.1f} days old, over {max_age_days}", evidence
    return True, f"the deliberate test passed {age:.1f} days ago", evidence


# --- Credentials and policies, persistent (2026-10-06) ---

def evaluate_password_policy(policy: dict | None, expected: dict) -> tuple[bool, str, dict]:
    """Every expected field holds; minimums and reuse may be stricter, ages shorter."""
    if policy is None:
        return False, "no account password policy -- AWS defaults apply", {"policy": None}
    stricter_up = {"MinimumPasswordLength", "PasswordReusePrevention"}
    stricter_down = {"MaxPasswordAge"}
    wrong = {}
    for field, want in expected.items():
        have = policy.get(field)
        if field in stricter_up:
            ok = isinstance(have, int) and have >= want
        elif field in stricter_down:
            ok = isinstance(have, int) and 0 < have <= want
        else:
            ok = have == want
        if not ok:
            wrong[field] = {"expected": want, "found": have}
    evidence = {"policy": policy, "wrong": wrong}
    if wrong:
        return False, f"{len(wrong)} field(s) off the declared policy: {', '.join(wrong)}", evidence
    return True, f"the password policy holds all {len(expected)} declared fields", evidence


def evaluate_root_credentials(summary: dict, root_virtual_devices: int) -> tuple[bool, str, dict]:
    evidence = {"AccountMFAEnabled": summary.get("AccountMFAEnabled"),
                "AccountAccessKeysPresent": summary.get("AccountAccessKeysPresent"),
                "root_virtual_mfa_devices": root_virtual_devices}
    problems = []
    if summary.get("AccountMFAEnabled") != 1:
        problems.append("root has no MFA")
    elif root_virtual_devices:
        problems.append("root's MFA is a virtual device, not hardware")
    if summary.get("AccountAccessKeysPresent"):
        problems.append("root has access keys")
    if problems:
        return False, "; ".join(problems), evidence
    return True, "root has hardware MFA and no access keys", evidence


def evaluate_workload_managed_policies(attached: dict[str, list[str]], exceptions: list[dict]) -> tuple[bool, str, dict]:
    excused = {(e["role"], e["policy"]) for e in exceptions}
    found = [{"role": r, "policy": p} for r, ps in sorted(attached.items()) for p in ps
             if p.startswith("arn:aws:iam::aws:policy/") and (r, p) not in excused]
    evidence = {"roles": len(attached), "aws_managed": found, "excepted": exceptions}
    if not attached:
        return False, "no workload roles found -- nothing to judge", evidence
    if found:
        return False, f"{len(found)} AWS-managed attachment(s): " + ", ".join(f"{f['role']} {f['policy'].rsplit('/', 1)[1]}" for f in found[:4]), evidence
    return True, f"none of {len(attached)} workload roles carries an AWS-managed policy", evidence


# --- The session environment's edge and services (2026-10-06) ---

def evaluate_waf(acl: dict | None, logging: dict | None, p: dict) -> tuple[bool, str, dict]:
    assertion = p["assertion"]
    evidence = {"web_acl": acl and acl.get("Name"), "rules": [r["Name"] for r in (acl or {}).get("Rules", [])]}
    if acl is None:
        return False, "no web ACL is associated with the load balancer", evidence
    if assertion == "associated":
        return True, f"web ACL {acl['Name']} is associated with the load balancer", evidence
    if assertion == "managed_groups":
        present = {}
        for r in acl.get("Rules", []):
            g = (r.get("Statement") or {}).get("ManagedRuleGroupStatement")
            if g:
                present[g["Name"]] = {"vendor": g["VendorName"], "version": g.get("Version", "default (vendor-managed)"),
                                      "override": list((r.get("OverrideAction") or {}).keys())}
        evidence["managed_groups"] = present
        missing = [n for n in p["managed_groups"] if n not in present]
        counting = [n for n, g in present.items() if "Count" in g["override"]]
        pinned = [n for n, g in present.items() if g["version"] != "default (vendor-managed)"]
        problems = [f"missing {', '.join(missing)}"] * bool(missing) + [f"counting only: {', '.join(counting)}"] * bool(counting) \
            + [f"pinned to an old version: {', '.join(pinned)}"] * bool(pinned)
        if problems:
            return False, "; ".join(problems), evidence
        return True, f"all {len(p['managed_groups'])} managed groups present, blocking, on the vendor's current version", evidence
    if assertion == "rate_rule":
        rates = [(r["Name"], r["Statement"]["RateBasedStatement"]["Limit"], list(r["Action"].keys()))
                 for r in acl.get("Rules", []) if "RateBasedStatement" in (r.get("Statement") or {})]
        evidence["rate_rules"] = rates
        ok = any(limit <= p["rate_limit"] and "Block" in action for _, limit, action in rates)
        return (ok, f"a blocking rate rule at {p['rate_limit']} or below" if ok
                else f"no blocking rate rule at or below {p['rate_limit']}", evidence)
    if assertion == "logging":
        destinations = (logging or {}).get("LogDestinationConfigs", [])
        evidence["log_destinations"] = destinations
        ok = any(p["log_destination_prefix"] in d for d in destinations)
        return (ok, "the web ACL logs to the declared destination" if ok else "the web ACL does not log to the declared destination",
                evidence)
    raise ValueError(f"unknown waf assertion {assertion!r}")


def evaluate_ecs_services(services: list[dict], assertion: str, multi_task: list[str]) -> tuple[bool, str, dict]:
    evidence = {"services": services}
    if not services:
        return False, "no services -- nothing to judge", evidence
    if assertion == "circuit_breaker":
        bad = [s["name"] for s in services if not (s["circuit_breaker"].get("enable") and s["circuit_breaker"].get("rollback"))]
        return (not bad, f"circuit breaker with rollback off on {', '.join(bad)}" if bad
                else f"all {len(services)} services roll back a failed deployment", evidence)
    if assertion == "spread":
        bad = [s["name"] for s in services if s["name"] in multi_task and (s["desired"] < 2 or len(s["zones"]) < 2)]
        absent = [n for n in multi_task if n not in {s["name"] for s in services}]
        problems = [f"{n}: fewer than two tasks or zones" for n in bad] + [f"{n}: not running" for n in absent]
        return (not problems, "; ".join(problems) or f"{', '.join(multi_task)} run two or more tasks across two or more zones",
                evidence)
    if assertion == "distinct_identity":
        groups = [tuple(s["security_groups"]) for s in services]
        roles = [s["task_role"] for s in services]
        problems = []
        if len(set(groups)) != len(groups):
            problems.append("two services share a security group set")
        if None in roles or len(set(roles)) != len(roles):
            problems.append("a service has no task role, or two share one")
        return (not problems, "; ".join(problems) or f"each of {len(services)} services has its own security group and task role",
                evidence)
    raise ValueError(f"unknown ecs_services assertion {assertion!r}")


def evaluate_elevations_revoked(keys: list[str], running: set[str]) -> tuple[bool, str, dict]:
    """IAM-JIT validate 3: every granted elevation has a revocation recorded after it.

    keys are the log store's elevations/ record names,
    <execution>-<phase>-<HHMMSS>.json; the backstop's sweeps are "swept".
    An elevation still running is not yet due one.
    """
    import re

    granted, revoked, swept = {}, set(), 0
    for k in keys:
        # The file name only: a revocation after midnight UTC lands in the
        # next day's dt= folder, and must still match its grant.
        m = re.search(r"/([^/]+?)-(requested|granted|revoked|refused|grant-failed|revoke-failed)-\d{6}\.json$", k)
        if m:
            name, phase = m.groups()
            if phase == "granted":
                granted[name] = k
            elif phase == "revoked":
                revoked.add(name)
        elif "/sweep-swept-" in k:
            swept += 1
    unrevoked = sorted(n for n in granted if n not in revoked and n not in running)
    evidence = {"granted": len(granted), "revoked": len(revoked & set(granted)), "running": sorted(running & set(granted)),
                "backstop_sweeps": swept, "unrevoked": unrevoked}
    if not granted:
        return True, "no elevation was granted in the window -- nothing to revoke", evidence
    if unrevoked and not swept:
        return False, f"{len(unrevoked)} granted elevation(s) with no revocation recorded: {', '.join(unrevoked)}", evidence
    if unrevoked:
        return False, f"{len(unrevoked)} granted elevation(s) without their own revocation; the backstop swept {swept} time(s) -- check it covered them", evidence
    return True, f"all {len(granted)} granted elevation(s) were revoked, each recorded", evidence


# --- Who can change IAM, idle roles, image scan coverage (2026-10-07) ---

def evaluate_iam_mutation_principals(capable: dict[str, list[str]], allowed: list[str]) -> tuple[bool, str, dict]:
    undeclared = {r: a for r, a in capable.items() if not any(fnmatch.fnmatchcase(r, p) for p in allowed)}
    evidence = {"capable": capable, "allowed_patterns": allowed, "undeclared": undeclared}
    if undeclared:
        return False, f"{len(undeclared)} undeclared role(s) can change IAM: {', '.join(sorted(undeclared))}", evidence
    return True, (f"only {', '.join(sorted(capable))} can change IAM" if capable
                  else "no role can change IAM now -- the elevated role exists only during an elevation"), evidence


def evaluate_roles_last_used(roles: list[dict], max_unused_days: int, grace_days: int) -> tuple[bool, str, dict]:
    idle = [r for r in roles if r["created_days"] > grace_days
            and (r["unused_days"] is None or r["unused_days"] > max_unused_days)]
    evidence = {"roles": sorted(roles, key=lambda r: r["role"]), "idle": idle}
    if not roles:
        return False, "no roles -- nothing to judge", evidence
    if idle:
        return False, f"{len(idle)} role(s) unused past {max_unused_days} days: {', '.join(r['role'] for r in idle)}", evidence
    return True, f"all {len(roles)} roles used within {max_unused_days} days, or too new to judge", evidence


def evaluate_image_scan_coverage(wanted: dict[str, str], coverage: dict[str, str]) -> tuple[bool, str, dict]:
    uncovered = {d: name for d, name in wanted.items() if coverage.get(d) != "ACTIVE"}
    evidence = {"images": wanted, "status": {d: coverage.get(d) for d in wanted}, "not_actively_scanned": uncovered}
    if not wanted:
        return False, "no deployable images found -- nothing to judge", evidence
    if uncovered:
        return False, f"{len(uncovered)} image(s) not actively scanned: {', '.join(uncovered.values())}", evidence
    return True, f"all {len(wanted)} recent deployable images actively scanned by Inspector", evidence
