#!/usr/bin/env python3
"""Proves the checks can actually fail.

Every check in checks/ currently passes. That is either evidence that the
pipeline is configured correctly, or evidence of nothing at all, and the
two are indistinguishable from the outside -- which is the failure mode
this project cares most about. Four controls were found this month that
were configured, deployed, and completely inert while reporting nothing.

So each assertion is run against input that should satisfy it and input
that should not -- a good and a broken workflow for pipeline_config_read,
a clean and a drifted Terraform plan for declared_versus_live_comparison.
An assertion that passes both is reported as broken, because a check that
cannot fail is not a check.

This is the same argument inventory/self_test.py makes by seeding a
resource and confirming the inventory notices: absence of a finding is
only evidence if the looking was recorded.

Usage:
    cd collector && python self_test.py
"""

from __future__ import annotations

import copy
import sys
import tempfile
from pathlib import Path

from base import CheckDefinition
import environments as env
import mechanisms.cloud_api_config_read as cfg
import mechanisms.inventory_reconciliation as inv
import mechanisms.log_query as lq
import mechanisms.register_read as rr
import mechanisms.declared_versus_live_comparison as dvl
import mechanisms.pipeline_config_read as pcr

GOOD = """
name: good
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 7 * * *'
permissions:
  contents: read
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: check out
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
      - name: scan dependencies
        run: pip-audit
      - name: build and push
        run: docker buildx build --push .
      - name: verify the signature
        run: cosign verify
      - name: record the digest
        run: echo "$DIGEST"
      - name: initialise
        run: |
          terraform -chdir=infra/aws init -input=false \
            -backend-config="use_lockfile=true" \
            -backend-config="encrypt=true"
"""

# Each field below violates exactly one assertion, so a failure names the
# assertion rather than leaving it to be inferred.
BAD = """
name: bad
on:
  push:
    branches: [main, develop]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    steps:
      - name: check out
        uses: actions/checkout@v5
      - name: record the digest
        run: echo "$DIGEST"
      - name: verify the signature
        run: cosign verify
      - name: initialise
        run: |
          terraform -chdir=infra/aws init -input=false \
            -backend-config="encrypt=true"
"""

# assertion -> extra params, and why the bad fixture violates it.
CASES = [
    ("actions_pinned_to_sha", {}, "checkout pinned to the tag v5"),
    ("no_static_cloud_credentials", {}, "AWS_ACCESS_KEY_ID referenced"),
    ("permissions_declared", {}, "no permissions block at all"),
    ("step_present", {"job": "build", "step": "scan dependencies"}, "no scanning step"),
    (
        "step_precedes",
        {"job": "build", "before": "verify the signature", "after": "record the digest"},
        "digest recorded before the signature is verified",
    ),
    ("triggers_limited_to", {"branches": ["main"]}, "also triggers from develop"),
    ("terraform_init_locks", {}, "init without use_lockfile=true"),
    ("scheduled", {}, "no schedule trigger"),
]


def definition(assertion: str, workflow: str, extra: dict) -> CheckDefinition:
    return CheckDefinition(
        id=f"self-test-{assertion}",
        indicator="n/a",
        mechanism="pipeline_config_read",
        evidence_type="OPS",
        description=f"self-test of {assertion}",
        required_cadence="on every collector change",
        params={"workflow": workflow, "assertion": assertion, **extra},
    )


def pipeline_config_read() -> list[str]:
    mechanism = pcr.PipelineConfigRead()

    with tempfile.TemporaryDirectory() as tmp:
        fixtures = Path(tmp)
        (fixtures / "good.yml").write_text(GOOD)
        (fixtures / "bad.yml").write_text(BAD)

        # The mechanism reads the repository's own workflow directory. Point
        # it at the fixtures instead, and put it back afterwards so a later
        # import in the same process is unaffected.
        original = pcr.WORKFLOWS_DIR
        pcr.WORKFLOWS_DIR = fixtures
        try:
            broken = []
            for assertion, extra, why in CASES:
                good = mechanism.run(definition(assertion, "good.yml", extra))
                bad = mechanism.run(definition(assertion, "bad.yml", extra))

                ok = good.passed and not bad.passed
                print(
                    f"[{assertion}] {'PASS' if ok else 'BROKEN'} -- "
                    f"good={'pass' if good.passed else 'FAIL'} "
                    f"bad={'fail' if not bad.passed else 'PASS'} ({why})"
                )
                if not ok:
                    broken.append(assertion)
                    print(f"    good: {good.message}")
                    print(f"    bad : {bad.message}")
        finally:
            pcr.WORKFLOWS_DIR = original

    return broken


# --- declared_versus_live_comparison ---
#
# Plans reduced to the fields the mechanism reads. Two resources in state,
# so "all of them match" and "one of them does not" are both expressible.


def _plan(changes: dict[str, list[str]], drift: dict[str, list[str]], in_state: int = 2) -> dict:
    state = [{"address": f"aws_s3_bucket.b{i}", "mode": "managed"} for i in range(in_state)]
    return {
        "prior_state": {"values": {"root_module": {"resources": state}}},
        "resource_changes": [
            {
                "address": r["address"],
                "mode": "managed",
                "change": {
                    "actions": changes.get(r["address"], ["no-op"]),
                    "before": {"tags": {"a": "1"}},
                    "after": {"tags": {"a": "1"} if r["address"] not in changes else {}},
                },
            }
            for r in state
        ],
        "resource_drift": [
            {"address": a, "change": {"actions": acts}} for a, acts in drift.items()
        ],
    }


def _knock_on() -> dict:
    # b0 changed out of band; b1's only difference is a value Terraform
    # cannot know until b0's change applies.
    plan = _plan({"aws_s3_bucket.b0": ["update"], "aws_s3_bucket.b1": ["update"]},
                 {"aws_s3_bucket.b0": ["update"]})
    b1 = plan["resource_changes"][1]["change"]
    b1["after"] = {"tags": {"a": "1"}, "policy": None}
    b1["before"]["policy"] = "{}"
    b1["after_unknown"] = {"policy": True}
    return plan


PLANS = {
    "clean": _plan({}, {}),
    # Refresh saw b0's tags move, but the provider's own comparison calls it
    # equal and the plan proposes nothing -- the null-against-{} case found
    # on the real roots. Must pass no_drift, or every run is noise.
    "refresh-noise": _plan({}, {"aws_s3_bucket.b0": ["update"]}),
    "out-of-band": _plan({"aws_s3_bucket.b0": ["update"]}, {"aws_s3_bucket.b0": ["update"]}),
    "not-applied": _plan({"aws_s3_bucket.b0": ["update"]}, {}),
    "deleted": _plan({"aws_s3_bucket.b0": ["create"]}, {"aws_s3_bucket.b0": ["delete"]}),
    "knock-on": _knock_on(),
    "empty-state": _plan({}, {}, in_state=0),
}

# assertion -> plans it must pass, plans it must fail. An out-of-band
# update must NOT fail declared_exists_live: the object is there, it has
# only changed, and an assertion that fails on everything discriminates
# nothing.
DVL_CASES = [
    ("no_drift", ["clean", "refresh-noise"], ["out-of-band", "not-applied", "deleted", "knock-on", "empty-state"]),
    ("declared_exists_live", ["clean", "refresh-noise", "out-of-band", "not-applied", "knock-on"], ["deleted", "empty-state"]),
]


def declared_versus_live_comparison() -> list[str]:
    broken = []
    for assertion, should_pass, should_fail in DVL_CASES:
        wrong = [n for n in should_pass if not dvl.evaluate(assertion, PLANS[n])[0]]
        wrong += [n for n in should_fail if dvl.evaluate(assertion, PLANS[n])[0]]
        print(
            f"[{assertion}] {'PASS' if not wrong else 'BROKEN'} -- "
            f"passes {', '.join(should_pass)}; fails {', '.join(should_fail)}"
        )
        if wrong:
            broken.append(assertion)
            print(f"    wrong verdict on: {', '.join(wrong)}")

    # The attribution is the evidence's main use, so it is asserted too.
    causes = {
        name: [c["cause"] for c in dvl.evaluate("no_drift", PLANS[name])[1]["changes"]]
        for name in ("out-of-band", "not-applied", "knock-on")
    }
    ok = causes == {
        "out-of-band": ["changed outside Terraform"],
        "not-applied": ["declaration not applied"],
        "knock-on": ["changed outside Terraform", "follows from another change"],
    }
    print(f"[no_drift attribution] {'PASS' if ok else 'BROKEN'} -- {causes}")
    if not ok:
        broken.append("no_drift attribution")
    return broken


# --- live_is_declared ---
#
# coverage() with a fake provider. Each fixture resource says what the
# provider would answer: its IAM path, or that it does not exist.

DECLARED = {"bucket-a", "role-app"}
EXCLUSIONS = [
    {"resource_type": "AWS::IAM::Role", "rule": {"predicate": "service_linked_role"}, "reason": "slr"},
]


def _fake_provider(rule: dict, resource: dict):
    if resource.get("missing"):
        return False, f"NotFound: {dvl.GONE}"
    return resource.get("path") == "/aws-service-role/", None


def _fake_exists(resource: dict):
    if resource.get("missing"):
        return False, f"NotFound: {dvl.GONE}"
    if resource.get("unprobed"):
        return None, "existence not probed"
    return True, None


def _res(kind: str, rid: str, **extra) -> dict:
    return {"resource_type": kind, "resource_id": rid, "name": rid, **extra}


INVENTORIES = {
    "all-declared": [_res("AWS::S3::Bucket", "bucket-a"), _res("AWS::IAM::Role", "role-app")],
    "excused": [_res("AWS::S3::Bucket", "bucket-a"),
                _res("AWS::IAM::Role", "AWSServiceRoleForConfig", path="/aws-service-role/")],
    # Exists, and nothing declares or excuses it.
    "undeclared": [_res("AWS::S3::Bucket", "bucket-a"), _res("AWS::S3::Bucket", "bucket-b")],
    # Named like a service-linked role, created at an ordinary path. The
    # exclusion must not be satisfiable by choosing a name.
    "spoofed-name": [_res("AWS::IAM::Role", "AWSServiceRoleForAnything", path="/")],
    # Listed by the inventory, gone according to its service, and caught by
    # an exclusion's own lookup -- the default security group of 2026-09-23.
    "phantom-excludable": [_res("AWS::IAM::Role", "AWSServiceRoleForGone", path="/aws-service-role/", missing=True)],
    # Listed, gone, and of a type no exclusion covers: found by the probe.
    "phantom-undeclared": [_res("AWS::S3::Bucket", "bucket-deleted", missing=True)],
    # Undeclared, and its existence cannot be asked. Must not be excused.
    "unprobed": [_res("AWS::WAFv2::WebACL", "acl-x", unprobed=True)],
    "empty": [],
}
LID_CASES = [
    ("live_is_declared",
     ["all-declared", "excused", "phantom-excludable", "phantom-undeclared"],
     ["undeclared", "spoofed-name", "unprobed", "empty"]),
    ("inventory_current",
     ["all-declared", "excused", "undeclared", "unprobed"],
     ["phantom-excludable", "phantom-undeclared", "empty"]),
]
# Kept for negative_controls(), which reports what each assertion must fail on.
LID_FAIL = LID_CASES[0][2]


def live_is_declared() -> list[str]:
    broken = []
    for assertion, should_pass, should_fail in LID_CASES:
        def verdict(name):
            return dvl.coverage("aws", INVENTORIES[name], DECLARED, EXCLUSIONS,
                                _fake_provider, _fake_exists, assertion)

        wrong = [n for n in should_pass if not verdict(n)[0]]
        wrong += [n for n in should_fail if verdict(n)[0]]
        print(
            f"[{assertion}] {'PASS' if not wrong else 'BROKEN'} -- "
            f"passes {', '.join(should_pass)}; fails {', '.join(should_fail)}"
        )
        if wrong:
            broken.append(assertion)
            print(f"    wrong verdict on: {', '.join(wrong)}")

    # A stale entry must say why, or the inventory defect is invisible.
    for name in ("phantom-excludable", "phantom-undeclared"):
        stale = dvl.coverage("aws", INVENTORIES[name], DECLARED, EXCLUSIONS,
                             _fake_provider, _fake_exists)[1]["stale"]
        if not any(dvl.GONE in n for e in stale for n in e["notes"]):
            broken.append(f"stale note ({name})")
            print(f"    {name}: stale entry carries no does-not-exist note")
    return broken


# --- the reserved-path exclusion predicates, run for real ---
#
# live_is_declared above hands coverage() a fake provider, so it proves the
# bookkeeping and not the predicates. These call AwsPredicates' own methods
# against a stubbed IAM, so a predicate that trusted a name, or matched the
# wrong reserved path, would be caught here.

class _StubIam:
    def __init__(self, path: str):
        self.path = path

    def get_role(self, RoleName: str) -> dict:
        return {"Role": {"RoleName": RoleName, "Path": self.path}}


SSO_PATH = "/aws-reserved/sso.amazonaws.com/"
PATH_CASES = [
    # (predicate, role name, IAM path, permission sets provisioned, should excuse)
    ("service_linked_role", "AWSServiceRoleForConfig", "/aws-service-role/config.amazonaws.com/", set(), True),
    ("service_linked_role", "AWSServiceRoleForAnything", "/", set(), False),
    ("service_linked_role", "AWSReservedSSO_Admin_0123456789abcdef", SSO_PATH, {"Admin"}, False),
    ("identity_center_role", "AWSReservedSSO_Interim_Admin_0123456789abcdef", SSO_PATH, {"Interim_Admin"}, True),
    # The name alone, at an ordinary path.
    ("identity_center_role", "AWSReservedSSO_Interim_Admin_0123456789abcdef", "/", {"Interim_Admin"}, False),
    # The right path, but its permission set is gone: an orphan.
    ("identity_center_role", "AWSReservedSSO_Deleted_0123456789abcdef", SSO_PATH, {"Interim_Admin"}, False),
    ("identity_center_role", "AWSServiceRoleForConfig", "/aws-service-role/config.amazonaws.com/", set(), False),
]


class _StubSecrets:
    def __init__(self, owner):
        self.owner = owner

    def describe_secret(self, SecretId: str) -> dict:
        return {"Name": SecretId, **({"OwningService": self.owner} if self.owner else {})}


# (secret name, OwningService, should excuse). The name alone must never
# excuse: anyone can name a secret rds!db-anything.
SECRET_CASES = [
    ("rds!db-1234", "rds", True),
    ("rds!db-1234", None, False),
    ("rds!db-1234", "appflow", False),
    ("fedramp-20x-ksi/task-tls", None, False),
]


def service_owned_secret_predicate() -> list[str]:
    wrong = []
    for name, owner, expected in SECRET_CASES:
        p = object.__new__(dvl.AwsPredicates)
        p.secretsmanager = _StubSecrets(owner)
        if p._service_owned_secret({"resource_id": name, "name": name}) != expected:
            wrong.append(f"{name} owned by {owner}")
    print(f"[service_owned_secret] {'PASS' if not wrong else 'BROKEN'} -- "
          f"{len(SECRET_CASES)} secrets, excused only when RDS owns them")
    if wrong:
        print(f"    wrong verdict on: {'; '.join(wrong)}")
    return ["service_owned_secret"] if wrong else []


def reserved_path_predicates() -> list[str]:
    broken = []
    for predicate in dict.fromkeys(p for p, *_ in PATH_CASES):
        wrong = []
        for name, path, provisioned, expected in (c[1:] for c in PATH_CASES if c[0] == predicate):
            p = object.__new__(dvl.AwsPredicates)
            p.iam, p._permission_sets = _StubIam(path), provisioned
            if getattr(p, f"_{predicate}")({"name": name}) != expected:
                wrong.append(f"{name} at {path}")
        print(f"[{predicate}] {'PASS' if not wrong else 'BROKEN'} -- "
              f"{sum(c[0] == predicate for c in PATH_CASES)} roles, excused only at the reserved path")
        if wrong:
            broken.append(predicate)
            print(f"    wrong verdict on: {'; '.join(wrong)}")
    return broken


# --- cloud_api_config_read judgements ---
#
# Each broken configuration is wrong in exactly one way, named by its key.

ARN = "arn:aws:s3:::b"


def _tls(**change) -> dict:
    statement = {
        "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": [ARN, f"{ARN}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }
    statement.update(change)
    return {"Statement": [statement]}


PAB_ON = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
_GH = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"
_GH_SUB = "token.actions.githubusercontent.com:sub"
_GH_AUD = "token.actions.githubusercontent.com:aud"


def _trust(condition, principal=None, action="sts:AssumeRoleWithWebIdentity", path="/"):
    return [{"role": "r", "path": path, "document": {"Statement": [{
        "Effect": "Allow", "Principal": principal or {"Federated": _GH}, "Action": action,
        **({"Condition": condition} if condition is not None else {})}]}}]


_PINNED = {"StringEquals": {_GH_SUB: "repo:o@1/r@2:ref:refs/heads/main", _GH_AUD: "sts.amazonaws.com"}}
SLR_EXEMPT = [{"path": "/aws-service-role/", "reason": "AWS writes the trust"}]
GD_OK = {"status": "ENABLED", "frequency": "FIFTEEN_MINUTES",
         "features": {"CLOUD_TRAIL": "ENABLED", "S3_DATA_EVENTS": "ENABLED", "EKS_AUDIT_LOGS": "DISABLED"}}
GD_ON = ["CLOUD_TRAIL", "S3_DATA_EVENTS"]
WIF_OK = {"state": "ACTIVE", "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
          "attributeCondition": "assertion.repository_id == '2' && assertion.ref == 'refs/heads/main'"}
WIF_CLAUSES = ["assertion.repository_id == '2'", "assertion.ref == 'refs/heads/main'"]
DS_OK = {"d": [{"role": "WRITER", "member": "userByEmail:pipe@p"}, {"role": "OWNER", "member": "userByEmail:tf@p"}]}
DS_DECLARED = {"d": DS_OK["d"]}
SCAN_OK = {"scanType": "ENHANCED", "rules": [{"scanFrequency": "CONTINUOUS_SCAN",
                                              "repositoryFilters": [{"filter": "*", "filterType": "WILDCARD"}]}]}
SCHED_OK = {"state": "ENABLED", "schedule": "rate(1 day)", "targets": ["arn:f"], "function_arn": "arn:f"}
CERT_OK = {"domain": "d", "type": "AMAZON_ISSUED", "status": "ISSUED", "eligible": False, "in_use": False,
           "validation": ["DNS"], "days_left": 300}
ROUTES_OK = [{"id": "rt-a", "tier": "app", "routes": [{"destination": "10.0.0.0/16", "target": "local"},
                                                    {"destination": "pl-1", "target": "vpce-1"}]},
             {"id": "rt-p", "tier": "public", "routes": [{"destination": "0.0.0.0/0", "target": "igw-1"}]}]
SG_ALLOWED = [{"group": "alb", "port": 443, "reason": "public"}]
SG_OK = [{"group": "alb", "protocol": "tcp", "from": 443, "to": 443, "cidr": "0.0.0.0/0"},
         {"group": "api", "protocol": "tcp", "from": 8443, "to": 8443, "cidr": None}]
EP_OK = [{"service": "logs", "type": "Interface", "policy": {"Statement": [
    {"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::1:role/api"]}, "Action": ["logs:PutLogEvents"], "Resource": "*"}]}},
         {"service": "s3", "type": "Gateway", "policy": {"Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": "*",
     "Condition": {"ArnEquals": {"aws:PrincipalArn": ["arn:aws:iam::1:role/api"]}}}]}}]
EP_EXCEPT = [{"resource": "arn:aws:s3:::layers/*", "reason": "ECR layer bucket"}]
EP_LAYERS = {"service": "s3", "type": "Gateway", "policy": {"Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::layers/*"}]}}
LB_LISTENERS = [{"port": 443, "protocol": "HTTPS", "policy": "ELBSecurityPolicy-TLS13-1-2-2021-06", "actions": [{"type": "forward"}]},
                {"port": 80, "protocol": "HTTP", "policy": None,
                 "actions": [{"type": "redirect", "protocol": "HTTPS", "status": "HTTP_301"}]}]
LB_GROUPS = [{"name": "api", "protocol": "HTTPS", "health_protocol": "HTTPS"}]
DB_INSTANCE = {"iam_auth": True, "backup_days": 7, "encrypted": True}
CONTAINER_OK = {"name": "api", "image": "r/api@sha256:" + "a" * 64, "command": ["python", "main.py"], "user": "10001:10001",
                "readonlyRootFilesystem": True, "privileged": False, "portMappings": [],
                "linuxParameters": {"capabilities": {"add": [], "drop": ["ALL"]}}}
BACKUP_OK = {"id": "b", "encrypted": True, "key": "k", "key_manager": "CUSTOMER", "key_state": "Enabled"}
_READERS = ["arn:aws:iam::1:role/normalize", "arn:aws:iam::1:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Op_*"]
_DENY = {"Sid": "DenyReads", "Effect": "Deny", "Principal": "*", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
         "Resource": "arn:aws:s3:::logs/*", "Condition": {"ArnNotLike": {"aws:PrincipalArn": _READERS}}}
_TLS_DENY = {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": ["arn:aws:s3:::logs", "arn:aws:s3:::logs/*"],
             "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
SH_EXCEPT = [{"control": "KMS.3", "reason": "session keys", "unless_resources": ["arn:aws:kms:r:1:key/persistent"]}]
SH_OK = [{"control": "KMS.3", "status": "FAILED", "severity": "CRITICAL", "resource": "arn:aws:kms:r:1:key/session"},
         {"control": "S3.1", "status": "PASSED", "severity": "MEDIUM", "resource": "acct"}]
VALIDATE_OK = "Results found for ...:\n\n24/24 digest files valid\n831/831 log files valid\n"
CORPUS_OK = ([{"table": "t", "projection": "true"}], [{"workgroup": "w", "enforced": True, "cutoff": 1 << 30}])
GCS_IAM_OK = {"publicAccessPrevention": "enforced", "uniformBucketLevelAccess": {"enabled": True}}
LOCK_OK = {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 7}}}

ALLOWED = [{"role": "roles/editor", "member": "serviceAccount:tf@p", "reason": "x"}]
PROJECT = "//cloudresourcemanager.googleapis.com/projects/p"


def _grant(role: str, member: str, resource: str = PROJECT) -> dict:
    return {"resource": resource, "role": role, "member": member}


# evaluate_store_keys fixtures. Keys resolve by alias, ID or ARN to one
# ARN, as describe_key does; "alias/logs" resolves to nothing, like an
# ephemeral key while the environment is down.
KEY_RULES = [
    {"type": "s3_bucket", "name": "log-store-*", "expect": "alias/evidence"},
    {"type": "log_group", "name": "/aws/lambda/*", "expect": "alias/evidence"},
    {"type": "log_group", "name": "/aws/rds/*", "expect": "alias/logs"},
    {"type": "s3_bucket", "name": "tfstate-*", "expect": "SSE-S3", "reason": "recorded"},
]
_NOW = __import__("datetime").datetime(2026, 10, 2, 14, 0, tzinfo=__import__("datetime").timezone.utc)
_GKEY = "projects/p/locations/l/keyRings/r/cryptoKeys/analytics"
GCP_KEY_RULES = [
    {"type": "bigquery.googleapis.com/Table", "name": "*", "expect": _GKEY},
    {"type": "storage.googleapis.com/Bucket", "name": "*", "expect": _GKEY},
    {"type": "logging.googleapis.com/LogBucket", "name": "_Required", "expect": "GOOGLE-MANAGED", "reason": "test",
     "required": True},
]
_KEYS = {"alias/evidence": "arn:k/e", "key-e": "arn:k/e", "arn:k/e": "arn:k/e",
         "alias/artifacts": "arn:k/a", "key-a": "arn:k/a"}


def _resolve(ref):
    return _KEYS.get(ref)


def _store(kind, name, mode, key=None):
    return {"type": kind, "name": name, "observed": {"mode": mode, "key": key}}


# evaluate_decrypt_principals fixtures, run through resolve_decrypt_principals
# so the resolution is tested along with the judgement. Account 1; "op" is
# the operator, reachable only through the account, and "other" is a role
# whose IAM policies would allow decrypt if the key policy let IAM decide.
_ACCT = "1"
_ROLE = "arn:aws:iam::1:role/"
_IAM_CAPABLE = {_ROLE + "op", _ROLE + "other"}
_IAM_ALL = [_ROLE + "op", _ROLE + "other", _ROLE + "lambda"]
DECRYPT_DECLARED = {"k": [_ROLE + "lambda", "service:logs.amazonaws.com", _ROLE + "op"]}


def _st(principal, action="kms:Decrypt", **extra):
    return {"Effect": "Allow", "Principal": principal, "Action": action, "Resource": "*", **extra}


_OP_ONLY = {"ArnLike": {"aws:PrincipalArn": _ROLE + "op"}}
_GOOD_KEY = [
    _st({"AWS": f"arn:aws:iam::{_ACCT}:root"}, ["kms:Describe*", "kms:Put*"]),
    _st({"AWS": _ROLE + "lambda"}),
    _st({"Service": "logs.amazonaws.com"}, "kms:Decrypt*"),
    _st({"AWS": f"arn:aws:iam::{_ACCT}:root"}, Condition=_OP_ONLY),
    # Encrypt only: not a decrypt route, whoever it names.
    _st({"AWS": _ROLE + "other"}, "kms:Encrypt"),
    {"Effect": "Deny", "Principal": "*", "Action": "kms:DisableKey", "Resource": "*"},
]


def _decrypt(statements, grants=()):
    resolved = {"k": cfg.resolve_decrypt_principals(
        {"Statement": statements}, list(grants), _IAM_CAPABLE, _IAM_ALL, _ACCT)}
    return cfg.evaluate_decrypt_principals(resolved, DECRYPT_DECLARED)[:2]


_GKR = "//cloudkms.googleapis.com/projects/p/locations/us-central1/keyRings/r"
_GK = _GKR + "/cryptoKeys/k"
_GPROJ = "//cloudresourcemanager.googleapis.com/projects/p"
_GPERMS = {"roles/cloudkms.cryptoKeyEncrypterDecrypter": {cfg.GCP_DECRYPT, "cloudkms.cryptoKeyVersions.useToEncrypt"},
           "roles/owner": {cfg.GCP_DECRYPT, "resourcemanager.projects.get"},
           "roles/editor": {"resourcemanager.projects.get"},
           "projects/p/roles/custom": {cfg.GCP_DECRYPT},
           "roles/unreadable": None}
GCP_DECRYPT_DECLARED = {"us-central1/r/k": ["serviceAccount:service-1@gs-project-accounts.iam.gserviceaccount.com",
                                            "user:owner@example.com"]}
_GOOD_GCP_POLICIES = {
    _GK: [{"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
           "members": ["serviceAccount:service-1@gs-project-accounts.iam.gserviceaccount.com"]}],
    _GPROJ: [{"role": "roles/owner", "members": ["user:owner@example.com"]},
             # Editor does not carry decrypt, so its member is not a decrypter.
             {"role": "roles/editor", "members": ["serviceAccount:tf@p.iam.gserviceaccount.com"]}],
}


def _gcp_decrypt(policies):
    resolved = {"us-central1/r/k": cfg.resolve_gcp_decrypt_principals(_GK, policies, _GPERMS)}
    return cfg.evaluate_decrypt_principals(resolved, GCP_DECRYPT_DECLARED)[:2]


def _with(resource, role, member):
    out = copy.deepcopy(_GOOD_GCP_POLICIES)
    out.setdefault(resource, []).append({"role": role, "members": [member]})
    return out


CFG_CASES = [
    ("evaluate_tls_only", lambda c: cfg.evaluate_tls_only(c), _tls(), {
        "no policy": None,
        "allow not deny": _tls(Effect="Allow"),
        "one principal": _tls(Principal={"AWS": "arn:aws:iam::1:role/x"}),
        "objects only": _tls(Resource=f"{ARN}/*"),
        "one action": _tls(Action="s3:GetObject"),
        "condition inverted": _tls(Condition={"Bool": {"aws:SecureTransport": "true"}}),
    }),
    ("evaluate_public_access_blocked", cfg.evaluate_public_access_blocked, PAB_ON, {
        "no block": None,
        "one setting off": {**PAB_ON, "RestrictPublicBuckets": False},
    }),
    ("evaluate_key_rotation", lambda c: cfg.evaluate_key_rotation(c, 365), [{"key": "a", "rotation_days": 365}], {
        "rotation off": [{"key": "a", "rotation_days": 365}, {"key": "b", "rotation_days": None}],
        "too slow": [{"key": "a", "rotation_days": 730}],
        "no keys": [],
    }),
    ("evaluate_registries_immutable", cfg.evaluate_registries_immutable,
     [{"repository": "r", "setting": "IMMUTABLE", "immutable": True}], {
        "one mutable": [{"repository": "r", "setting": "IMMUTABLE", "immutable": True},
                        {"repository": "s", "setting": "MUTABLE", "immutable": False}],
        "no repositories": [],
    }),
    # No users passes: here absence is the claim, unlike every bucket check.
    ("evaluate_no_user_access_keys", cfg.evaluate_no_user_access_keys, [], {
        "active key": [{"user": "u", "keys": [{"id": "AKIA1", "status": "Active"}]}],
        "inactive key": [{"user": "u", "keys": [{"id": "AKIA1", "status": "Inactive"}]}],
    }),
    ("evaluate_log_corpus_limits", lambda c: cfg.evaluate_log_corpus_limits(*c, 1 << 30), CORPUS_OK, {
        "projection off": ([{"table": "t", "projection": "false"}], CORPUS_OK[1]),
        "projection unset": ([{"table": "t", "projection": None}], CORPUS_OK[1]),
        "not enforced": (CORPUS_OK[0], [{"workgroup": "w", "enforced": False, "cutoff": 1 << 30}]),
        "no limit": (CORPUS_OK[0], [{"workgroup": "w", "enforced": True, "cutoff": None}]),
        "limit too high": (CORPUS_OK[0], [{"workgroup": "w", "enforced": True, "cutoff": 1 << 40}]),
        "unlimited second workgroup": (CORPUS_OK[0], CORPUS_OK[1] + [{"workgroup": "primary", "enforced": False, "cutoff": None}]),
        "no tables": ([], CORPUS_OK[1]),
    }),
    ("evaluate_role_trusts", lambda c: cfg.evaluate_role_trusts(c, SLR_EXEMPT), _trust(_PINNED), {
        "subject unpinned": _trust({"StringEquals": {_GH_AUD: "sts.amazonaws.com"}}),
        "audience unpinned": _trust({"StringEquals": {_GH_SUB: "repo:o@1/r@2:ref:refs/heads/main"}}),
        "subject wildcard": _trust({"StringEquals": {_GH_SUB: "repo:o@1/*", _GH_AUD: "sts.amazonaws.com"}}),
        "subject by StringLike": _trust({**_PINNED, "StringLike": {_GH_SUB: "repo:o@1/*"}}),
        "no condition": _trust(None),
        "wildcard principal": _trust(None, principal="*", action="sts:AssumeRole"),
        "wildcard AWS principal": _trust(None, principal={"AWS": "*"}, action="sts:AssumeRole"),
        "SAML audience unpinned": _trust(None, principal={"Federated": "arn:aws:iam::1:saml-provider/x"},
                                         action="sts:AssumeRoleWithSAML"),
        # /service-role/ is a path customers can create; only AWS's reserved one is exempt.
        "exempt path look-alike": _trust(None, principal="*", action="sts:AssumeRole",
                                         path="/service-role/"),
    }),
    ("evaluate_session_bounds", lambda c: cfg.evaluate_session_bounds(c, {"web_identity": 3600, "identity_center": 14400}),
     [{"role": "a", "kind": "web_identity", "seconds": 3600}, {"role": "b", "kind": "identity_center", "seconds": 14400}], {
        "too long": [{"role": "a", "kind": "web_identity", "seconds": 43200}],
        # The human ceiling does not stretch to a workload role.
        "web identity at the human ceiling": [{"role": "a", "kind": "web_identity", "seconds": 14400}],
        "unknown": [{"role": "b", "kind": "identity_center", "seconds": None}],
    }),
    ("evaluate_oidc_providers", lambda c: cfg.evaluate_oidc_providers(c, [{"url": "t.example", "client_ids": ["sts"]}]),
     [{"url": "t.example", "client_ids": ["sts"]}], {
        "extra audience": [{"url": "t.example", "client_ids": ["sts", "other"]}],
        "undeclared provider": [{"url": "t.example", "client_ids": ["sts"]}, {"url": "evil.example", "client_ids": ["sts"]}],
        "missing": [],
    }),
    ("evaluate_wif_provider", lambda c: cfg.evaluate_wif_provider(c, "https://token.actions.githubusercontent.com", WIF_CLAUSES),
     WIF_OK, {
        "branch clause gone": {**WIF_OK, "attributeCondition": "assertion.repository_id == '2'"},
        "other issuer": {**WIF_OK, "oidc": {"issuerUri": "https://evil.example"}},
        "disabled": {**WIF_OK, "state": "DELETED"},
        "missing": None,
    }),
    ("evaluate_users_hold_no_policies", cfg.evaluate_users_hold_no_policies, [], {
        "inline policy": [{"user": "u", "inline": ["p"], "attached": [], "groups": []}],
        "attached policy": [{"user": "u", "inline": [], "attached": ["arn:aws:iam::aws:policy/X"], "groups": []}],
        "group": [{"user": "u", "inline": [], "attached": [], "groups": ["admins"]}],
    }),
    ("evaluate_guardduty", lambda c: cfg.evaluate_guardduty(c, GD_ON, "FIFTEEN_MINUTES"), GD_OK, {
        "undeclared plan on": {**GD_OK, "features": {**GD_OK["features"], "EKS_AUDIT_LOGS": "ENABLED"}},
        "declared plan off": {**GD_OK, "features": {**GD_OK["features"], "S3_DATA_EVENTS": "DISABLED"}},
        "slow publishing": {**GD_OK, "frequency": "SIX_HOURS"},
        "suspended": {**GD_OK, "status": "DISABLED"},
        "no detector": None,
    }),
    ("evaluate_standards", lambda c: cfg.evaluate_standards(c, ["cis", "fsbp"]), {"cis": "READY", "fsbp": "READY"}, {
        "one missing": {"cis": "READY"},
        "not ready": {"cis": "INCOMPLETE", "fsbp": "READY"},
    }),
    ("evaluate_trail_data_events", lambda c: cfg.evaluate_trail_data_events(c, ["arn:aws:s3:::data/"]),
     ["arn:aws:s3:::data/"], {
        "none": [],
        "undeclared extra": ["arn:aws:s3:::data/", "arn:aws:s3:::logs/"],
        "wrong store": ["arn:aws:s3:::logs/"],
    }),
    ("evaluate_dataset_access", lambda c: cfg.evaluate_dataset_access(c, DS_DECLARED), DS_OK, {
        "extra reader": {"d": DS_OK["d"] + [{"role": "READER", "member": "specialGroup:allAuthenticatedUsers"}]},
        "declared entry absent": {"d": DS_OK["d"][:1]},
        "role widened": {"d": [{"role": "OWNER", "member": "userByEmail:pipe@p"}, DS_OK["d"][1]]},
        "undeclared dataset": {**DS_OK, "other": []},
        "no datasets": {},
    }),
    ("evaluate_alarms_target", lambda c: cfg.evaluate_alarms_target(c, ["a"], "topic"),
     {"a": {"actions_enabled": True, "actions": ["topic"]}}, {
        "missing": {},
        "actions disabled": {"a": {"actions_enabled": False, "actions": ["topic"]}},
        "other target": {"a": {"actions_enabled": True, "actions": ["elsewhere"]}},
    }),
    ("evaluate_registry_scanning", lambda c: cfg.evaluate_registry_scanning(*c), (SCAN_OK, {"account": "ENABLED", "ecr": "ENABLED"}), {
        "basic scanning": ({**SCAN_OK, "scanType": "BASIC"}, {"account": "ENABLED", "ecr": "ENABLED"}),
        "narrow filter": ({**SCAN_OK, "rules": [{"scanFrequency": "CONTINUOUS_SCAN",
                                                 "repositoryFilters": [{"filter": "api*", "filterType": "WILDCARD"}]}]},
                          {"account": "ENABLED", "ecr": "ENABLED"}),
        "push only": ({**SCAN_OK, "rules": [{"scanFrequency": "SCAN_ON_PUSH",
                                             "repositoryFilters": [{"filter": "*", "filterType": "WILDCARD"}]}]},
                      {"account": "ENABLED", "ecr": "ENABLED"}),
        "Inspector off for ECR": (SCAN_OK, {"account": "ENABLED", "ecr": "DISABLED"}),
    }),
    ("evaluate_scheduled_functions", cfg.evaluate_scheduled_functions, {"r": SCHED_OK}, {
        "missing": {"r": None},
        "disabled": {"r": {**SCHED_OK, "state": "DISABLED"}},
        "no schedule": {"r": {**SCHED_OK, "schedule": None}},
        "targets elsewhere": {"r": {**SCHED_OK, "targets": ["arn:other"]}},
    }),
    ("evaluate_certificates", lambda c: cfg.evaluate_certificates(c, 30), [CERT_OK, {**CERT_OK, "in_use": True, "eligible": True}], {
        "imported": [{**CERT_OK, "type": "IMPORTED"}],
        "email validated": [{**CERT_OK, "validation": ["EMAIL"]}],
        "in use, ineligible": [{**CERT_OK, "in_use": True, "eligible": False}],
        "idle and near expiry": [{**CERT_OK, "days_left": 10}],
        "no certificates": [],
    }),
    ("evaluate_config_recorder", lambda c: cfg.evaluate_config_recorder(*c),
     ([{"name": "r"}], {"r": {"recording": True}}), {
        "no recorder": ([], {}),
        "stopped": ([{"name": "r"}], {"r": {"recording": False}}),
        "status missing": ([{"name": "r"}], {}),
        "second recorder stopped": ([{"name": "r"}, {"name": "s"}], {"r": {"recording": True}}),
    }),
    ("evaluate_asset_feed", cfg.evaluate_asset_feed, {"name": "f", "asset_types": ["storage.googleapis.com/Bucket"]}, {
        "missing": None,
        "watches nothing": {"name": "f", "asset_types": []},
    }),
    ("evaluate_workflow_state", cfg.evaluate_workflow_state, "active", {
        "disabled by hand": "disabled_manually",
        "disabled by inactivity": "disabled_inactivity",
        "unknown": None,
    }),
    ("evaluate_private_routes", lambda c: cfg.evaluate_private_routes(c, ["app"]), ROUTES_OK, {
        "NAT route": [{**ROUTES_OK[0], "routes": ROUTES_OK[0]["routes"] + [{"destination": "0.0.0.0/0", "target": "nat-1"}]}],
        "internet gateway": [{**ROUTES_OK[0], "routes": [{"destination": "0.0.0.0/0", "target": "igw-1"}]}],
        "peering": [{**ROUTES_OK[0], "routes": [{"destination": "10.9.0.0/16", "target": "pcx-1"}]}],
        "no table for the tier": [ROUTES_OK[1]],
    }),
    ("evaluate_open_rules", lambda c: cfg.evaluate_open_rules(c, SG_ALLOWED, "ingress"), SG_OK, {
        "undeclared group open": SG_OK + [{"group": "api", "protocol": "tcp", "from": 22, "to": 22, "cidr": "0.0.0.0/0"}],
        "declared group, other port": SG_OK + [{"group": "alb", "protocol": "tcp", "from": 22, "to": 22, "cidr": "0.0.0.0/0"}],
        "range including the port": [{"group": "alb", "protocol": "tcp", "from": 0, "to": 65535, "cidr": "0.0.0.0/0"}],
        "all protocols": [{"group": "alb", "protocol": "-1", "from": None, "to": None, "cidr": "0.0.0.0/0"}],
        "IPv6 everywhere": SG_OK + [{"group": "api", "protocol": "tcp", "from": 443, "to": 443, "cidr": "::/0"}],
        "no rules": [],
    }),
    ("evaluate_endpoint_policies", lambda c: cfg.evaluate_endpoint_policies(c, EP_EXCEPT), EP_OK + [EP_LAYERS], {
        # The exception covers only its listed resource: the same open
        # principal on any other resource still fails.
        "open principal beyond the excepted resource": [{**EP_LAYERS, "policy": {"Statement": [
            {**EP_LAYERS["policy"]["Statement"][0], "Resource": ["arn:aws:s3:::layers/*", "arn:aws:s3:::other/*"]}]}}],
        "excepted resource, every action": [{**EP_LAYERS, "policy": {"Statement": [
            {**EP_LAYERS["policy"]["Statement"][0], "Action": "s3:*"}]}}],
        "AWS default policy": [{"service": "logs", "type": "Interface", "policy": {"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}}],
        "service wildcard": [{"service": "logs", "type": "Interface", "policy": {"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::1:role/api"]}, "Action": "logs:*", "Resource": "*"}]}}],
        "anyone, unconditioned": [{"service": "s3", "type": "Gateway", "policy": {"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": "*"}]}}],
        "no policy": [{"service": "s3", "type": "Gateway", "policy": {}}],
    }),
    ("evaluate_load_balancer_tls", lambda c: cfg.evaluate_load_balancer_tls(*c, ["ELBSecurityPolicy-TLS13-1-2-2021-06"]),
     (LB_LISTENERS, LB_GROUPS), {
        "old TLS policy": ([{**LB_LISTENERS[0], "policy": "ELBSecurityPolicy-2016-08"}, LB_LISTENERS[1]], LB_GROUPS),
        "HTTP forwards": ([LB_LISTENERS[0], {**LB_LISTENERS[1], "actions": [{"type": "forward"}]}], LB_GROUPS),
        "redirect to HTTP": ([LB_LISTENERS[0], {**LB_LISTENERS[1], "actions": [{"type": "redirect", "protocol": "HTTP", "status": "HTTP_301"}]}], LB_GROUPS),
        "plain HTTP to targets": (LB_LISTENERS, [{**LB_GROUPS[0], "protocol": "HTTP"}]),
        "no HTTPS listener": ([LB_LISTENERS[1]], LB_GROUPS),
    }),
    ("evaluate_database_settings", lambda c: cfg.evaluate_database_settings(*c, {"rds.force_ssl": "1"}, 7),
     (DB_INSTANCE, {"rds.force_ssl": "1"}), {
        "TLS not forced": (DB_INSTANCE, {"rds.force_ssl": "0"}),
        "parameter unset": (DB_INSTANCE, {}),
        "no IAM auth": ({**DB_INSTANCE, "iam_auth": False}, {"rds.force_ssl": "1"}),
        "short retention": ({**DB_INSTANCE, "backup_days": 1}, {"rds.force_ssl": "1"}),
        "unencrypted": ({**DB_INSTANCE, "encrypted": False}, {"rds.force_ssl": "1"}),
    }),
    ("evaluate_task_definitions (hardened)", lambda c: cfg.evaluate_task_definitions(c, "hardened"), {"api": [CONTAINER_OK]}, {
        "writable root": {"api": [{**CONTAINER_OK, "readonlyRootFilesystem": False}]},
        "root user": {"api": [{**CONTAINER_OK, "user": "0"}]},
        "no user": {"api": [{**CONTAINER_OK, "user": None}]},
        "capabilities kept": {"api": [{**CONTAINER_OK, "linuxParameters": {"capabilities": {"drop": []}}}]},
        "capability added": {"api": [{**CONTAINER_OK, "linuxParameters": {"capabilities": {"add": ["NET_ADMIN"], "drop": ["ALL"]}}}]},
        "privileged": {"api": [{**CONTAINER_OK, "privileged": True}]},
        "no services": {},
        "declared one-off with no definition": {"api": [CONTAINER_OK], "migrate": []},
    }),
    ("evaluate_task_definitions (explicit)", lambda c: cfg.evaluate_task_definitions(c, "explicit"), {"api": [CONTAINER_OK]}, {
        "command inherited": {"api": [{k: v for k, v in CONTAINER_OK.items() if k != "command"}]},
        "capabilities inherited": {"api": [{**CONTAINER_OK, "linuxParameters": {}}]},
        "ports unstated": {"api": [{k: v for k, v in CONTAINER_OK.items() if k != "portMappings"}]},
    }),
    ("evaluate_task_definitions (digest)", lambda c: cfg.evaluate_task_definitions(c, "digest_pinned"), {"api": [CONTAINER_OK]}, {
        "by tag": {"api": [{**CONTAINER_OK, "image": "r/api:git-abc"}]},
    }),
    ("evaluate_services_enabled", cfg.evaluate_services_enabled, {"a": "ENABLED", "b": "ENABLED"}, {
        "one disabled": {"a": "ENABLED", "b": "DISABLED"},
        "unknown": {"a": None},
        "none named": {},
    }),
    ("evaluate_external_access", lambda c: cfg.evaluate_external_access(*c, [{"resource": "arn:aws:iam::1:role/ci", "reason": "GitHub"}]),
     (True, [{"resource": "arn:aws:iam::1:role/ci", "type": "AWS::IAM::Role", "public": False, "principal": {}}]), {
        "no analyzer": (False, []),
        "undeclared path": (True, [{"resource": "arn:aws:s3:::data", "type": "AWS::S3::Bucket", "public": False, "principal": {}}]),
        # A declared resource that becomes public is still a finding.
        "declared but public": (True, [{"resource": "arn:aws:iam::1:role/ci", "type": "AWS::IAM::Role", "public": True, "principal": {}}]),
    }),
    ("evaluate_sources_catalogued", lambda c: cfg.evaluate_sources_catalogued(*c), (["aws"], ["aws", "gcp"]), {
        "stored, not catalogued": (["aws", "gcp"], ["aws"]),
        "empty store": ([], ["aws"]),
    }),
    ("evaluate_snapshots_accounted", lambda c: cfg.evaluate_snapshots_accounted(*c, [{"instance": "db", "reason": "kept"}]),
     ([{"id": "s1", "instance": "db"}, {"id": "s2", "instance": "live"}], {"live"}), {
        "orphaned": ([{"id": "s3", "instance": "old"}], {"live"}),
    }),
    ("evaluate_failing_controls", lambda c: cfg.evaluate_failing_controls(c, SH_EXCEPT), SH_OK, {
        "unexcepted failure": SH_OK + [{"control": "IAM.6", "status": "FAILED", "severity": "CRITICAL", "resource": "acct"}],
        # The carve-out holds: a persistent key scheduled for deletion is a finding.
        "excepted control, carved-out resource": SH_OK + [{"control": "KMS.3", "status": "FAILED", "severity": "CRITICAL",
                                                           "resource": "arn:aws:kms:r:1:key/persistent"}],
        "no findings": [],
    }),
    ("evaluate_validate_logs", lambda c: cfg.evaluate_validate_logs(*c), (VALIDATE_OK, 0), {
        "tampered log": (VALIDATE_OK.replace("831/831 log", "830/831 log") +
                         "Log file s3://b/k.json.gz INVALID: hash value doesn't match\n", 0),
        "digest missing": ("23/24 digest files valid, 1/24 digest files INVALID\n831/831 log files valid\n", 0),
        "empty window": ("0/0 digest files valid\n0/0 log files valid\n", 0),
        "validator failed": ("An error occurred (AccessDenied)", 254),
        "no counts": ("Results requested for ...\n", 0),
    }),
    ("evaluate_function_runs", cfg.evaluate_function_runs, {"f": {"invocations": 1, "errors": 0, "within_hours": 26}}, {
        "did not run": {"f": {"invocations": 0, "errors": 0, "within_hours": 26}},
        "ran with errors": {"f": {"invocations": 1, "errors": 1, "within_hours": 26}},
        "none named": {},
    }),
    ("evaluate_vpcs_declared", lambda c: cfg.evaluate_vpcs_declared(c, [{"region": "us-east-1", "name": "proj"}]),
     [{"region": "us-east-1", "id": "vpc-1", "name": "proj", "default": False}], {
        "a default VPC": [{"region": "eu-west-1", "id": "vpc-2", "name": None, "default": True}],
        "undeclared VPC": [{"region": "us-east-1", "id": "vpc-3", "name": "other", "default": False}],
        "declared name, other region": [{"region": "us-west-2", "id": "vpc-4", "name": "proj", "default": False}],
    }),
    ("evaluate_read_deny", lambda c: cfg.evaluate_read_deny(c, "logs", _READERS),
     {"Statement": [_TLS_DENY, _DENY]}, {
        "no policy": None,
        # The TLS deny covers s3:* on the objects, but it is not a reader list.
        "only the TLS deny": {"Statement": [_TLS_DENY]},
        "undeclared reader exempted": {"Statement": [{**_DENY, "Condition": {"ArnNotLike": {"aws:PrincipalArn": _READERS + ["arn:aws:iam::1:role/drift"]}}}]},
        "declared reader locked out": {"Statement": [{**_DENY, "Condition": {"ArnNotLike": {"aws:PrincipalArn": _READERS[:1]}}}]},
        "old versions readable": {"Statement": [{**_DENY, "Action": "s3:GetObject"}]},
        "another bucket": {"Statement": [{**_DENY, "Resource": "arn:aws:s3:::other/*"}]},
        "allow, not deny": {"Statement": [{**_DENY, "Effect": "Allow"}]},
    }),
    ("evaluate_backups_restorable", cfg.evaluate_backups_restorable, [BACKUP_OK], {
        "key deleted": [{**BACKUP_OK, "key_state": "Deleted"}],
        # 2026-10-02 exactly: the database key scheduled for deletion at teardown.
        "key pending deletion": [{**BACKUP_OK, "key_state": "PendingDeletion", "deletion_date": "2026-10-09"}],
        "AWS-managed key": [{**BACKUP_OK, "key_manager": "AWS"}],
        "unencrypted": [{**BACKUP_OK, "encrypted": False}],
    }),
    ("evaluate_state_bucket", lambda c: cfg.evaluate_state_bucket(*c), ("Enabled", "AES256"), {
        "versioning suspended": ("Suspended", "AES256"),
        "never versioned": (None, "AES256"),
        "unencrypted": ("Enabled", None),
    }),
    ("evaluate_gcs_public_access", cfg.evaluate_gcs_public_access, GCS_IAM_OK, {
        "nothing reported": None,
        # Inherited defers to an organization policy this project does not have.
        "prevention inherited": {**GCS_IAM_OK, "publicAccessPrevention": "inherited"},
        "uniform access off": {**GCS_IAM_OK, "uniformBucketLevelAccess": {"enabled": False}},
        "uniform access unreported": {"publicAccessPrevention": "enforced"},
    }),
    ("evaluate_object_lock", lambda c: cfg.evaluate_object_lock(c, "COMPLIANCE", 7), LOCK_OK, {
        "not enabled": {"error": "ObjectLockConfigurationNotFoundError"},
        "governance mode": {**LOCK_OK, "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 7}}},
        "no default retention": {"ObjectLockEnabled": "Enabled"},
        "too short": {**LOCK_OK, "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 1}}},
    }),
    ("evaluate_basic_roles", lambda c: cfg.evaluate_basic_roles(c, ALLOWED)[:2],
     [_grant("roles/editor", "serviceAccount:tf@p")], {
        "unlisted member": [_grant("roles/editor", "serviceAccount:tf@p"),
                            _grant("roles/editor", "serviceAccount:1-compute@developer.gserviceaccount.com")],
        # An allowance for editor is not an allowance for owner.
        "allowed member, other role": [_grant("roles/owner", "serviceAccount:tf@p")],
        # A basic role on one dataset is still a basic role.
        "on a child resource": [_grant("roles/viewer", "user:x@y",
                                       "//bigquery.googleapis.com/projects/p/datasets/d")],
    }),
    ("evaluate_trail_validation", lambda c: cfg.evaluate_trail_validation(*c),
     ({"LogFileValidationEnabled": True}, {"IsLogging": True}), {
        "no trail": (None, {}),
        "not logging": ({"LogFileValidationEnabled": True}, {"IsLogging": False}),
        "validation off": ({"LogFileValidationEnabled": False}, {"IsLogging": True}),
    }),
    ("evaluate_store_keys", lambda c: cfg.evaluate_store_keys(c, KEY_RULES, _resolve)[:2],
     [_store("s3_bucket", "log-store-1", "KMS", "key-e"),
      _store("log_group", "/aws/lambda/x", "KMS", "alias/evidence"),
      _store("s3_bucket", "tfstate-1", "SSE-S3")], {
        # The same store under another class's key.
        "wrong key": [_store("s3_bucket", "log-store-1", "KMS", "key-a")],
        # An AWS-held key where a customer key is declared.
        "AWS key, customer key declared": [_store("s3_bucket", "log-store-1", "SSE-S3")],
        # A store no rule names. Must not pass by being unknown.
        "unclassified store": [_store("s3_bucket", "log-store-1", "KMS", "key-e"),
                               _store("sns_topic", "new-topic", "none")],
        # The exception is SSE-S3, not "anything".
        "exception store, other mode": [_store("s3_bucket", "tfstate-1", "AWS-managed")],
        # A declared key that no longer exists protects nothing.
        "expected key gone": [_store("log_group", "/aws/rds/db", "AWS-managed")],
        "no stores": [],
    }),
    # The same judgement with the GCP resolver: a table reports the key
    # version, which must still match its key, and Google's own key is not
    # a customer key.
    ("evaluate_store_keys (gcp)", lambda c: cfg.evaluate_store_keys(c, GCP_KEY_RULES, cfg.gcp_key_name)[:2],
     [_store("bigquery.googleapis.com/Table", "t", "KMS", _GKEY + "/cryptoKeyVersions/3"),
      _store("storage.googleapis.com/Bucket", "b", "KMS", _GKEY),
      _store("logging.googleapis.com/LogBucket", "_Required", "GOOGLE-MANAGED")], {
        "Google key where customer key declared": [_store("storage.googleapis.com/Bucket", "b", "GOOGLE-MANAGED")],
        "another key's version": [_store("bigquery.googleapis.com/Table", "t", "KMS", _GKEY + "-other/cryptoKeyVersions/1")],
        "exception store given a customer key": [_store("logging.googleapis.com/LogBucket", "_Required", "KMS", _GKEY)],
        # The 2026-10-01 blind spot: a required store missing from the
        # population must fail, not pass with an unmatched rule.
        "required store missing": [_store("bigquery.googleapis.com/Table", "t", "KMS", _GKEY + "/cryptoKeyVersions/3"),
                                   _store("storage.googleapis.com/Bucket", "b", "KMS", _GKEY)],
    }),
    ("evaluate_scheduler_job", lambda c: cfg.evaluate_scheduler_job(c, _NOW, 7),
     {"state": "ENABLED", "lastAttemptTime": "2026-10-02T12:00:00Z", "status": {}}, {
        # The 2026-10-02 failure exactly: attempted on time, refused every time.
        "last attempt refused": {"state": "ENABLED", "lastAttemptTime": "2026-10-02T12:00:00Z",
                                 "status": {"code": 7, "message": "PERMISSION_DENIED"}},
        "paused": {"state": "PAUSED", "lastAttemptTime": "2026-10-02T12:00:00Z", "status": {}},
        "never attempted": {"state": "ENABLED"},
        "stale": {"state": "ENABLED", "lastAttemptTime": "2026-10-01T23:00:00Z", "status": {}},
        "missing": {},
    }),
    ("evaluate_decrypt_principals (gcp)", _gcp_decrypt, _GOOD_GCP_POLICIES, {
        "undeclared member on the key": _with(_GK, "roles/cloudkms.cryptoKeyEncrypterDecrypter", "user:other@example.com"),
        "granted on the key ring": _with(_GKR, "roles/cloudkms.cryptoKeyEncrypterDecrypter", "user:other@example.com"),
        "granted on the project": _with(_GPROJ, "roles/cloudkms.cryptoKeyEncrypterDecrypter", "user:other@example.com"),
        "custom role carrying decrypt": _with(_GK, "projects/p/roles/custom", "user:other@example.com"),
        "role that cannot be read": _with(_GK, "roles/unreadable", "user:other@example.com"),
        "public": _with(_GK, "roles/cloudkms.cryptoKeyEncrypterDecrypter", "allUsers"),
        # A condition narrows when, not whether.
        "conditional grant": {**_GOOD_GCP_POLICIES, _GK: _GOOD_GCP_POLICIES[_GK] + [{
            "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": ["user:other@example.com"],
            "condition": "request.time < timestamp('2027-01-01T00:00:00Z')"}]},
    }),
    ("evaluate_decrypt_principals", lambda c: _decrypt(*c), (_GOOD_KEY,), {
        "undeclared role named": (_GOOD_KEY + [_st({"AWS": _ROLE + "other"})],),
        "public principal": (_GOOD_KEY + [_st("*")],),
        # The account grant without the operator-only condition lets IAM
        # decide, and IAM would let "other" decrypt.
        "account delegation unconfined": (_GOOD_KEY + [_st({"AWS": f"arn:aws:iam::{_ACCT}:root"})],),
        "wildcard action": (_GOOD_KEY + [_st({"AWS": _ROLE + "other"}, "kms:*")],),
        "NotAction": (_GOOD_KEY + [_st({"AWS": _ROLE + "other"}, NotAction="kms:Encrypt")],),
        "grant to undeclared": (_GOOD_KEY, [{"GranteePrincipal": _ROLE + "other", "Operations": ["Decrypt"]}]),
    }),
]


def cloud_api_config_read() -> list[str]:
    broken = []
    for name, judge, good, bads in CFG_CASES:
        wrong = [] if judge(good)[0] else ["good config"]
        wrong += [why for why, bad in bads.items() if judge(bad)[0]]
        print(f"[{name}] {'PASS' if not wrong else 'BROKEN'} -- fails on: {', '.join(bads)}")
        if wrong:
            broken.append(name)
            print(f"    wrong verdict on: {', '.join(wrong)}")
    return broken


# The resource key each cloud_api_config_read judgement serves.
CFG_RESOURCES = {
    "evaluate_tls_only": "s3_buckets_deny_insecure_transport",
    "evaluate_public_access_blocked": "s3_buckets_block_public_access",
    "evaluate_gcs_public_access": "buckets_prevent_public_access",
    "evaluate_key_rotation": "key_rotation",
    "evaluate_role_trusts": "role_trusts",
    "evaluate_session_bounds": "federated_session_bounds",
    "evaluate_oidc_providers": "oidc_providers",
    "evaluate_wif_provider": "workload_identity_provider",
    "evaluate_users_hold_no_policies": "iam_user_policies",
    "evaluate_guardduty": "guardduty",
    "evaluate_standards": "securityhub_standards",
    "evaluate_trail_data_events": "trail_data_events",
    "evaluate_state_bucket": "state_bucket",
    "evaluate_private_routes": "private_routes",
    "evaluate_open_rules": "security_group_reach",
    "evaluate_endpoint_policies": "endpoint_policies",
    "evaluate_load_balancer_tls": "load_balancer_tls",
    "evaluate_database_settings": "database_settings",
    "evaluate_task_definitions (hardened)": "task_definitions",
    "evaluate_task_definitions (explicit)": "task_definitions",
    "evaluate_task_definitions (digest)": "task_definitions",
    "evaluate_backups_restorable": "database_backups_restorable",
    "evaluate_read_deny": "bucket_read_restricted",
    "evaluate_vpcs_declared": "vpcs_declared",
    "evaluate_function_runs": "function_runs",
    "evaluate_validate_logs": "trail_logs_validate",
    "evaluate_failing_controls": "securityhub_failing_controls",
    "evaluate_sources_catalogued": "store_sources_catalogued",
    "evaluate_external_access": "external_access",
    "evaluate_snapshots_accounted": "snapshots_accounted",
    "evaluate_services_enabled": "services_enabled",
    "evaluate_config_recorder": "config_recorder",
    "evaluate_asset_feed": "cloud_asset_feed",
    "evaluate_workflow_state": "workflow_active",
    "evaluate_scheduled_functions": "scheduled_functions",
    "evaluate_certificates": "acm_certificates",
    "evaluate_dataset_access": "bigquery_dataset_access",
    "evaluate_alarms_target": "alarms_target",
    "evaluate_registry_scanning": "registry_scanning",
    "evaluate_registries_immutable": "registries_immutable",
    "evaluate_no_user_access_keys": "iam_user_access_keys",
    "evaluate_log_corpus_limits": "log_corpus_query_limits",
    "evaluate_object_lock": "s3_object_lock",
    "evaluate_trail_validation": "cloudtrail_log_file_validation",
    "evaluate_basic_roles": "basic_roles",
    "evaluate_store_keys": "store_encryption_keys",
    "evaluate_decrypt_principals": "key_decrypt_principals",
    "evaluate_decrypt_principals (gcp)": "key_decrypt_principals",
    "evaluate_scheduler_job": "scheduler_job_runs",
    "evaluate_store_keys (gcp)": "store_encryption_keys",
}


# Judgements that serve more than one resource key.
CFG_ALSO = {"evaluate_public_access_blocked": ["s3_account_public_access_block"],
            "evaluate_no_user_access_keys": ["service_account_user_keys"]}


# Mechanisms with one judgement each. Their checks carry no assertion or
# resource parameter, so the SDR emitter looks them up under None.
_INV = [{"resource_type": "AWS::S3::Bucket", "resource_id": "a"}, {"resource_type": "AWS::S3::Bucket", "resource_id": "b"},
        {"resource_type": "AWS::IAM::Role", "resource_id": "r"}]
_DK = "arn:aws:kms:us-east-1:1:key/k"
_DKEYS = {_DK: {"manager": "CUSTOMER", "aliases": ["alias/data"]},
          "arn:aws:kms:us-east-1:1:key/aws": {"manager": "AWS", "aliases": ["aws/lambda"]}}
_DMODEL = {"alias/data": ["arn:aws:iam::1:role/reader", "arn:aws:iam::1:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Op_*",
                          "service:s3.amazonaws.com"]}


def _dec(actor, key=_DK, kind="AssumedRole"):
    return {"key": key, "actor_type": kind, "actor": actor, "events": "3"}


_DEC_OK = [_dec("arn:aws:sts::1:assumed-role/reader/s"), _dec("arn:aws:sts::1:assumed-role/AWSReservedSSO_Op_abc/me"),
           _dec("", kind="AWSService"), _dec("arn:aws:sts::1:assumed-role/anyone/s", key="arn:aws:kms:us-east-1:1:key/aws")]

_REG = {"evaluation_plan": {"sample_max_days": 3}, "classes": {"A::B": {
    "network": "private tier", "availability": {"posture": "single-AZ, deliberately reduced", "recovery": "restore", "reason": "cost"},
    "backup": {"coverage": "None", "reason": "derived"}, "objective": {"rto": "1h", "rpo": "5m"},
    "evaluation": {"by": "collector", "interval_days": 1}, "data_store": {"holds_data": True, "encryption_check": "keys"}}}}


def _reg_with(dimension, value):
    import copy as _c
    r = _c.deepcopy(_REG)
    r["classes"]["A::B"][dimension] = value
    return r


_PLAN = {"classes": {"key": {"mechanism": "auto", "interval_days": 365, "members": [{"resource_type": "AWS::KMS::Key", "name": "*"}]},
                     "token": {"mechanism": "workflow", "interval_days": None, "deferred": "no token yet",
                               "members": [{"resource_type": "T", "name": "*"}]},
                     "secret": {"mechanism": "native", "interval_days": 7,
                                "members": [{"resource_type": "AWS::SecretsManager::Secret", "name": "rds!db-*"}]}}}


def _plan_without(name, field):
    import copy as _c
    p = _c.deepcopy(_PLAN)
    p["classes"][name].pop(field)
    return p


SINGLE_CASES = [
    ("register_read (plan_covers_classes)", lambda c: rr.evaluate_plan_classes(c, ["key", "token", "secret"]), _PLAN, {
        "class missing": {"classes": {k: v for k, v in _PLAN["classes"].items() if k != "secret"}},
        "no interval and no deferral": _plan_without("token", "deferred"),
        "no mechanism": _plan_without("key", "mechanism"),
    }),
    ("register_read (entries_complete)", rr.evaluate_entries_complete,
     [{"what": "a", "reason": "r", "expiry_days": 30}, {"what": "b", "reason": "r", "expires_with": "the next build"},
      {"what": "c", "reason": "r", "expiry_days": 0}], {
        "no expiry": [{"what": "a", "reason": "r", "expiry_days": None}],
        "no reason": [{"what": "a", "reason": " ", "expiry_days": 30}],
        "negative days": [{"what": "a", "reason": "r", "expiry_days": -1}],
        "empty register": [],
    }),
    ("register_read (secrets_owned)", lambda c: rr.evaluate_secrets_owned(c, _PLAN),
     [{"resource_type": "AWS::KMS::Key", "name": None, "resource_id": "k"},
      {"resource_type": "AWS::SecretsManager::Secret", "name": "rds!db-1", "resource_id": "s"}], {
        "a secret no class owns": [{"resource_type": "AWS::SecretsManager::Secret", "name": "hand-made", "resource_id": "x"}],
        "nothing to judge": [],
    }),
    ("register_read (covers_inventory)", lambda c: rr.evaluate_register_coverage(c[0], c[1], c[2], {"keys"}),
     ({"A::B": 2}, _REG, "availability"), {
        "inventoried class without an entry": ({"A::B": 2, "C::D": 1}, _REG, "network"),
        "entry without the dimension": ({"A::B": 2}, _REG, "surface"),
        "reduced availability without a reason": ({"A::B": 2}, _reg_with("availability", {"posture": "single-AZ, deliberately reduced", "recovery": "restore"}), "availability"),
        "no backup without a reason": ({"A::B": 2}, _reg_with("backup", {"coverage": "None"}), "backup"),
        "objective half-declared": ({"A::B": 2}, _reg_with("objective", {"rto": "1h"}), "objective"),
        "evaluated less often than the plan": ({"A::B": 2}, _reg_with("evaluation", {"by": "x", "interval_days": 14}), "evaluation"),
        "data store naming a missing check": ({"A::B": 2}, _reg_with("data_store", {"holds_data": True, "encryption_check": "gone"}), "data_store"),
        "empty statement": ({"A::B": 2}, _reg_with("network", " "), "network"),
        "empty inventory": ({}, _REG, "network"),
    }),
    ("log_query (decrypt_model)", lambda c: lq.judge_decrypt_events(*c), (_DEC_OK, _DKEYS, _DMODEL), {
        "undeclared role": (_DEC_OK + [_dec("arn:aws:sts::1:assumed-role/drift/s")], _DKEYS, _DMODEL),
        # A service pattern must not admit a role of the same name.
        "role named like a service entry": (_DEC_OK + [_dec("arn:aws:sts::1:assumed-role/s3.amazonaws.com/s")], _DKEYS, _DMODEL),
        "customer key without a model": (_DEC_OK, {**_DKEYS, _DK: {"manager": "CUSTOMER", "aliases": ["alias/other"]}}, _DMODEL),
        "key KMS does not know": (_DEC_OK, {**_DKEYS, _DK: None}, _DMODEL),
        "IAM user": (_DEC_OK + [_dec("terraform-admin", kind="IAMUser")], _DKEYS, _DMODEL),
    }),
    ("log_query", lambda c: lq.evaluate_query(*c), ("SUCCEEDED", 3, "any_rows"), {
        "no rows": ("SUCCEEDED", 0, "any_rows"),
        "query failed": ("FAILED", 0, "any_rows"),
        # A failed standing query must not read as its hoped-for zero.
        "query failed, zero expected": ("FAILED", 0, "no_rows"),
        "rows where none expected": ("SUCCEEDED", 1, "no_rows"),
        "unknown expectation": ("SUCCEEDED", 3, "some_rows"),
    }),
    # The gate on ephemeral checks: any anchor makes the environment standing,
    # so a half-torn-down one runs its checks instead of skipping them.
    ("environments", lambda c: (env.evaluate_standing(c),), {"vpc": False, "database": True}, {
        "nothing": {"vpc": False, "database": False},
    }),
    ("inventory_reconciliation", lambda c: inv.evaluate_min_count(*c), (_INV, "AWS::S3::Bucket", 2), {
        "too few": (_INV, "AWS::S3::Bucket", 3),
        # Other types must not make up the count.
        "only other types": (_INV, "AWS::EC2::Instance", 1),
        "empty inventory": ([], "AWS::S3::Bucket", 1),
        "at least zero": ([], "AWS::S3::Bucket", 0),
    }),
]


def single_judgements() -> list[str]:
    broken = []
    for name, judge, good, bads in SINGLE_CASES:
        wrong = [] if judge(good)[0] else ["good input"]
        wrong += [why for why, bad in bads.items() if judge(bad)[0]]
        print(f"[{name}] {'PASS' if not wrong else 'BROKEN'} -- fails on: {', '.join(bads)}")
        if wrong:
            broken.append(name)
            print(f"    wrong verdict on: {', '.join(wrong)}")
    return broken


def negative_controls() -> dict[tuple[str, str], str]:
    """(mechanism, assertion or resource) -> what the negative control feeds it.

    Read by the SDR emitter, which lists a check's negative control under
    ksiTests only when one exists here -- so the SDR cannot claim a test
    this file does not run.
    """
    found = {("pipeline_config_read", a): f"a workflow where {why}" for a, _, why in CASES}
    for assertion, _, should_fail in DVL_CASES:
        found[("declared_versus_live_comparison", assertion)] = (
            "Terraform plans that must fail it: " + ", ".join(should_fail)
        )
    for assertion, _, should_fail in LID_CASES:
        found[("declared_versus_live_comparison", assertion)] = (
            "inventories that must fail it: " + ", ".join(should_fail)
        )
    for mechanism, _, _, bads in SINGLE_CASES:
        # "log_query (decrypt_model)" is keyed apart from plain log_query:
        # the emitter looks a check up by its assertion or resource, which
        # a judged query carries as its judge.
        name, _, judge = mechanism.partition(" (")
        found[(name, judge.rstrip(")") or None)] = "inputs that must fail it: " + ", ".join(bads)
    for name, _, _, bads in CFG_CASES:
        for resource in [CFG_RESOURCES[name], *CFG_ALSO.get(name, [])]:
            found[("cloud_api_config_read", resource)] = (
                "configurations that must fail it: " + ", ".join(bads)
            )
    return found


def handler_wiring() -> list[str]:
    """Every handler run() dispatches to must exist on the mechanism.

    Added 2026-10-01, when a module-level function inserted mid-class ended
    the class early and two handlers became unreachable. The judgement
    tests all passed, because they call the pure functions directly; only a
    live run errored. This catches it without one.
    """
    import inspect
    import re

    from mechanisms.cloud_api_config_read import CloudAPIConfigRead

    called = re.findall(r"self\.(_[a-z_]+)\(", inspect.getsource(CloudAPIConfigRead.run))
    missing = [h for h in called if not hasattr(CloudAPIConfigRead, h)]
    print(f"[handler wiring] {'PASS' if not missing else 'BROKEN'} -- {len(called)} handlers dispatched"
          + (f"; missing: {', '.join(missing)}" if missing else ""))
    return ["handler wiring"] if missing else []


def main() -> int:
    broken = handler_wiring()
    print()
    broken += pipeline_config_read()
    print()
    broken += declared_versus_live_comparison()
    broken += live_is_declared()
    broken += reserved_path_predicates()
    broken += service_owned_secret_predicate()
    print()
    broken += cloud_api_config_read()
    broken += single_judgements()
    total = (1 + len(CASES) + len(DVL_CASES) + 1 + len(LID_CASES)
             + len({c[0] for c in PATH_CASES}) + 1 + len(CFG_CASES) + len(SINGLE_CASES))

    print()
    if broken:
        print(f"{len(broken)} of {total} assertion(s) do not discriminate: {', '.join(broken)}")
        return 1

    print(f"all {total} assertions distinguish input that should pass from input that should not")
    return 0


if __name__ == "__main__":
    sys.exit(main())
