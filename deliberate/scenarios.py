"""The deliberate test scenarios. Each takes a boto3 session and returns
(passed, expected, observed). The catalogue, with the rows each answers, is
scenarios.yaml; the runner and the record are run.py.

Each scenario states what a broken control would produce, and passes only
on the opposite. A test that cannot tell the two apart proves nothing.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

REGION = "us-east-1"
LOG_BUCKET = "fedramp-20x-ksi-log-store-437672023758"
STATE_BUCKET = "fedramp-20x-ksi-tfstate-437672023758"
REPOSITORY = "elvie-valmores/fedramp-20x-ksi-assessment"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _refused(call) -> str | None:
    """The error code if the call was refused, None if it went through."""
    try:
        call()
    except ClientError as error:
        return error.response["Error"]["Code"]
    return None


def object_lock_rejects_change(session) -> tuple[bool, str, dict]:
    s3 = session.client("s3", region_name=REGION)
    # The newest collector run record: always within its 7-day lock, and
    # duplicated in that run's CI artifact, so the least costly to lose if
    # the lock did not hold.
    versions = s3.list_object_versions(Bucket=LOG_BUCKET, Prefix="collector-runs/")["Versions"]
    target = max(versions, key=lambda v: v["LastModified"])
    key, version = target["Key"], target["VersionId"]
    before = s3.head_object(Bucket=LOG_BUCKET, Key=key, VersionId=version)
    attempts = {
        "delete the version": _refused(lambda: s3.delete_object(Bucket=LOG_BUCKET, Key=key, VersionId=version)),
        "delete it, bypassing governance": _refused(lambda: s3.delete_object(
            Bucket=LOG_BUCKET, Key=key, VersionId=version, BypassGovernanceRetention=True)),
        "shorten its retention": _refused(lambda: s3.put_object_retention(
            Bucket=LOG_BUCKET, Key=key, VersionId=version,
            Retention={"Mode": "COMPLIANCE", "RetainUntilDate": _now() + dt.timedelta(hours=1)})),
    }
    after = s3.head_object(Bucket=LOG_BUCKET, Key=key, VersionId=version)
    survived = after["ObjectLockRetainUntilDate"] == before["ObjectLockRetainUntilDate"]
    observed = {"object": key, "version": version, "mode": before.get("ObjectLockMode"),
                "retain_until": str(before["ObjectLockRetainUntilDate"]),
                "refused_with": attempts, "version_intact_with_same_retention": survived}
    return (all(attempts.values()) and survived,
            "every attempt refused, and the version still present with its retention unchanged", observed)


def _drift_run(after: dt.datetime) -> dict:
    subprocess.run(["gh", "workflow", "run", "drift.yml", "--repo", REPOSITORY], check=True, capture_output=True)
    run = None
    for _ in range(40):
        time.sleep(10)
        runs = json.loads(subprocess.run(
            ["gh", "run", "list", "--repo", REPOSITORY, "--workflow", "drift.yml", "--event", "workflow_dispatch",
             "-L", "5", "--json", "databaseId,createdAt,status,conclusion"],
            check=True, capture_output=True, text=True).stdout)
        mine = [r for r in runs if dt.datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00")) >= after]
        if mine and mine[0]["status"] == "completed":
            run = mine[0]
            break
    if run is None:
        raise TimeoutError("the drift run did not finish within ~7 minutes")
    log = subprocess.run(["gh", "run", "view", str(run["databaseId"]), "--repo", REPOSITORY, "--log"],
                         capture_output=True, text=True).stdout
    return {"run": run["databaseId"], "conclusion": run["conclusion"], "log": log}


def out_of_band_change_detected(session) -> tuple[bool, str, dict]:
    logs = session.client("logs", region_name=REGION)
    account = session.client("sts").get_caller_identity()["Account"]
    group = "/aws/lambda/fedramp-20x-ksi-elevation"
    arn = f"arn:aws:logs:{REGION}:{account}:log-group:{group}"
    address = "aws_cloudwatch_log_group.elevation"
    stamp = _now().strftime("%Y%m%dT%H%M%SZ")

    changed_at = _now()
    logs.tag_resource(resourceArn=arn, tags={"deliberate-test": stamp})
    try:
        drifted = _drift_run(changed_at)
        detected_after = round((_now() - changed_at).total_seconds() / 60, 1)
    finally:
        logs.untag_resource(resourceArn=arn, tagKeys=["deliberate-test"])
    reverted_at = _now()
    clean = _drift_run(reverted_at)
    caught = drifted["conclusion"] == "failure" and address in drifted["log"] and "deliberate-test" in drifted["log"]
    observed = {"changed": {"resource": group, "tag": stamp, "at": changed_at.isoformat()},
                "drift_run": {"id": drifted["run"], "conclusion": drifted["conclusion"],
                              "named_the_resource": address in drifted["log"]},
                "after_revert": {"id": clean["run"], "conclusion": clean["conclusion"]},
                # From the change to the failing drift run's completion. The
                # first record (2026-10-05) measured to the second run's
                # completion instead, an upper bound.
                "detected_within_minutes": detected_after}
    return (caught and clean["conclusion"] == "success",
            "the drift run after the change fails naming the tagged resource, and the run after reverting passes",
            observed)


def delivery_failure_alerts(session) -> tuple[bool, str, dict]:
    lam = session.client("lambda", region_name=REGION)
    cw = session.client("cloudwatch", region_name=REGION)
    alarm = "fedramp-20x-ksi-normalize-events-errors"
    event = {"Records": [{"s3": {"bucket": {"name": LOG_BUCKET},
                                 "object": {"key": f"deliberate-test/missing-{int(time.time())}.json.gz"}}}]}
    invoked_at = _now()
    result = lam.invoke(FunctionName="fedramp-20x-ksi-normalize-events", Payload=json.dumps(event).encode())
    failed = "FunctionError" in result
    entered = None
    for _ in range(60):  # the alarm's period is 5 minutes; allow 10
        history = cw.describe_alarm_history(AlarmName=alarm, HistoryItemType="StateUpdate",
                                            StartDate=invoked_at, MaxRecords=10)["AlarmHistoryItems"]
        to_alarm = [h for h in history if json.loads(h["HistoryData"])["newState"]["stateValue"] == "ALARM"]
        if to_alarm:
            entered = to_alarm[-1]
            break
        time.sleep(10)
    actions = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["AlarmActions"]
    observed = {"invoked_at": invoked_at.isoformat(), "function_failed": failed,
                "alarm_entered_at": entered and entered["Timestamp"].isoformat(),
                "minutes_to_alarm": entered and round((entered["Timestamp"] - invoked_at).total_seconds() / 60, 1),
                "alarm_notifies": actions}
    return (failed and entered is not None and any("detection" in a for a in actions),
            "the normalizer fails, and its error alarm enters ALARM and notifies the detection topic", observed)


def prior_state_recoverable(session) -> tuple[bool, str, dict]:
    s3 = session.client("s3", region_name=REGION)
    ecs = session.client("ecs", region_name=REGION)
    key = "aws/terraform.tfstate"
    versions = [v for v in s3.list_object_versions(Bucket=STATE_BUCKET, Prefix=key)["Versions"] if v["Key"] == key]
    current = next(v for v in versions if v["IsLatest"])
    oldest = min(versions, key=lambda v: v["LastModified"])
    state = lambda v: json.loads(s3.get_object(Bucket=STATE_BUCKET, Key=key, VersionId=v["VersionId"])["Body"].read())
    now_state, old_state = state(current), state(oldest)
    families = ecs.list_task_definitions(familyPrefix="fedramp-20x-ksi-api", sort="ASC", status="INACTIVE")["taskDefinitionArns"] \
        or ecs.list_task_definitions(familyPrefix="fedramp-20x-ksi-api", sort="ASC")["taskDefinitionArns"]
    task = ecs.describe_task_definition(taskDefinition=families[0])["taskDefinition"] if families else None
    observed = {"state_versions": len(versions), "oldest": str(oldest["LastModified"]),
                "depth_days": (_now() - oldest["LastModified"]).days,
                "oldest_serial": old_state.get("serial"), "current_serial": now_state.get("serial"),
                "same_lineage": old_state.get("lineage") == now_state.get("lineage"),
                "oldest_resources": len(old_state.get("resources", [])),
                "task_definition": task and {"arn": task["taskDefinitionArn"], "status": task["status"],
                                             "image": task["containerDefinitions"][0]["image"]}}
    ok = (len(versions) > 1 and old_state.get("serial", 0) < now_state.get("serial", 0)
          and observed["same_lineage"] and old_state.get("resources") and task is not None)
    return ok, "an older state version of the same lineage and a prior task definition are both retrievable", observed


def historical_advisory_surfaced(session) -> tuple[bool, str, dict]:
    expected = {"CVE-2021-33503", "GHSA-q2q7-5pp4-w6pg"}
    with tempfile.TemporaryDirectory() as tmp:
        manifest = Path(tmp) / "requirements.txt"
        manifest.write_text("urllib3==1.26.4\n")
        out = subprocess.run([sys.executable, "-m", "pip_audit", "-r", str(manifest), "--no-deps", "--disable-pip",
                              "--progress-spinner", "off", "-f", "json"], capture_output=True, text=True)
    if not out.stdout.strip():
        raise RuntimeError(f"pip-audit produced nothing: {out.stderr.strip()[:300]}")
    report = json.loads(out.stdout)
    found = {i for d in report.get("dependencies", []) for v in d.get("vulns", [])
             for i in [v["id"], *v.get("aliases", [])]}
    observed = {"package": "urllib3==1.26.4", "advisories_reported": sorted(found),
                "expected_among_them": sorted(expected & found), "exit_code": out.returncode}
    return bool(expected & found) and out.returncode != 0, \
        "pip-audit reports CVE-2021-33503 for urllib3 1.26.4 and exits non-zero, which fails a build", observed


# --- With the environment standing ---

CLUSTER = "fedramp-20x-ksi"
PROBE = (
    "import socket, sys\n"
    "try:\n"
    "    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=8)\n"
    "    print('CONNECTED'); sys.exit(20)\n"
    "except Exception as e:\n"
    "    print('BLOCKED', type(e).__name__, e); sys.exit(10)\n"
)
BLOCKED, CONNECTED = 10, 20


def _https_status(ip: str, host: str, path: str) -> int:
    import socket
    import ssl
    context = ssl.create_default_context()
    with socket.create_connection((ip, 443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: fedramp-20x-ksi-deliberate-test\r\n"
                        f"Connection: close\r\n\r\n".encode())
            return int(tls.recv(64).split(b" ")[1])


def waf_blocks_and_allows(session) -> tuple[bool, str, dict]:
    import os
    import socket
    from concurrent.futures import ThreadPoolExecutor

    elb = session.client("elbv2", region_name=REGION)
    dns = elb.describe_load_balancers(Names=["fedramp-20x-ksi"])["LoadBalancers"][0]["DNSName"]
    ip = socket.gethostbyname(dns)
    host = os.environ.get("APP_DOMAIN", "caliper.elvievalmores.com")
    legit = _https_status(ip, host, "/.well-known/security.txt")
    injection = _https_status(ip, host, "/?id=1%27%20OR%20%271%27%3D%271")

    def hit(_):
        try:
            return _https_status(ip, host, "/.well-known/security.txt")
        except OSError:
            return 0
    with ThreadPoolExecutor(48) as pool:
        flood = list(pool.map(hit, range(2300)))
    blocked_at = None
    started = _now()
    for _ in range(36):  # rate rules act within about a minute; allow six
        if hit(0) == 403:
            blocked_at = _now()
            break
        time.sleep(10)
    observed = {"load_balancer": dns, "legitimate": legit, "sql_injection": injection,
                "flood": {"sent": len(flood), "200": flood.count(200), "403": flood.count(403),
                          "failed": flood.count(0)},
                "rate_block_after_seconds": blocked_at and round((blocked_at - started).total_seconds())}
    return (legit == 200 and injection == 403 and (flood.count(403) > 0 or blocked_at is not None),
            "the legitimate request gets 200, the injection 403, and the flood is cut off with 403s", observed)


def _worker_position(ecs) -> tuple[str, dict]:
    svc = ecs.describe_services(cluster=CLUSTER, services=["worker"])["services"][0]
    return svc["taskDefinition"], svc["networkConfiguration"]["awsvpcConfiguration"]


def _probe(ecs, task_definition: str, network: dict, target: str, port: int) -> dict:
    task = ecs.run_task(
        cluster=CLUSTER, taskDefinition=task_definition, launchType="FARGATE", startedBy="deliberate-test",
        networkConfiguration={"awsvpcConfiguration": {**network, "assignPublicIp": "DISABLED"}},
        overrides={"containerOverrides": [{"name": "worker", "command": ["-c", PROBE, target, str(port)]}]},
    )["tasks"][0]["taskArn"]
    ecs.get_waiter("tasks_stopped").wait(cluster=CLUSTER, tasks=[task], WaiterConfig={"Delay": 6, "MaxAttempts": 50})
    stopped = ecs.describe_tasks(cluster=CLUSTER, tasks=[task])["tasks"][0]
    container = stopped["containers"][0]
    return {"task": task, "target": f"{target}:{port}", "exit_code": container.get("exitCode"),
            "stopped_reason": stopped.get("stoppedReason"), "security_groups": network["securityGroups"]}


def task_internet_egress_blocked(session) -> tuple[bool, str, dict]:
    ecs = session.client("ecs", region_name=REGION)
    td, network = _worker_position(ecs)
    result = _probe(ecs, td, network, "1.1.1.1", 443)
    return result["exit_code"] == BLOCKED, "the connection to 1.1.1.1:443 fails from the worker's position", result


def permissive_group_still_no_egress(session) -> tuple[bool, str, dict]:
    ecs = session.client("ecs", region_name=REGION)
    ec2 = session.client("ec2", region_name=REGION)
    td, network = _worker_position(ecs)
    vpc = ec2.describe_subnets(SubnetIds=network["subnets"][:1])["Subnets"][0]["VpcId"]
    group = ec2.create_security_group(GroupName=f"deliberate-test-allow-all-{int(time.time())}", VpcId=vpc,
                                      Description="Deliberate test: allows all egress; deleted after")["GroupId"]
    try:
        # A new group already allows all egress; stated so the record shows it.
        rules = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [group]}])["SecurityGroupRules"]
        # Alongside the worker's own group, not instead of it: the registry
        # endpoints admit only declared workload groups, and a task that
        # cannot pull its image would "fail to connect" for the wrong
        # reason. Groups are a union, so egress is now open; only the
        # route tables stand in the way.
        result = _probe(ecs, td, {**network, "securityGroups": network["securityGroups"] + [group]}, "1.1.1.1", 443)
    finally:
        for _ in range(20):  # the stopped task's interface takes a moment to release the group
            try:
                ec2.delete_security_group(GroupId=group)
                break
            except ClientError:
                time.sleep(15)
    result["group_egress"] = [r.get("CidrIpv4") or r.get("CidrIpv6") for r in rules if r["IsEgress"]]
    result["group_deleted"] = not ec2.describe_security_groups(
        Filters=[{"Name": "group-id", "Values": [group]}])["SecurityGroups"]
    started_ok = result["exit_code"] in (BLOCKED, CONNECTED)  # the probe ran, rather than the task failing
    return (started_ok and result["exit_code"] == BLOCKED and "0.0.0.0/0" in result["group_egress"],
            "with a group allowing all egress, the connection still fails: the subnets have no route out", result)


def service_to_service_refused(session) -> tuple[bool, str, dict]:
    ecs = session.client("ecs", region_name=REGION)
    api_tasks = ecs.list_tasks(cluster=CLUSTER, serviceName="api", desiredStatus="RUNNING")["taskArns"]
    described = ecs.describe_tasks(cluster=CLUSTER, tasks=api_tasks[:1])["tasks"][0]
    api_ip = next(d["value"] for a in described["attachments"] for d in a["details"] if d["name"] == "privateIPv4Address")
    td, network = _worker_position(ecs)
    result = _probe(ecs, td, network, api_ip, 8443)
    return result["exit_code"] == BLOCKED, "the worker's position cannot open a connection to the api", result


def failing_deploy_rolls_back(session) -> tuple[bool, str, dict]:
    ecs = session.client("ecs", region_name=REGION)
    svc = ecs.describe_services(cluster=CLUSTER, services=["api"])["services"][0]
    original = svc["taskDefinition"]
    td = ecs.describe_task_definition(taskDefinition=original)["taskDefinition"]
    keep = ("family", "taskRoleArn", "executionRoleArn", "networkMode", "containerDefinitions", "volumes",
            "requiresCompatibilities", "cpu", "memory", "runtimePlatform")
    spec = {k: td[k] for k in keep if k in td}
    for c in spec["containerDefinitions"]:
        if c["name"] == "api":  # runs, never listens: fails the load balancer's health check
            c["command"] = ["-c", "import time; time.sleep(3600)"]
    broken = ecs.register_task_definition(**spec, tags=[{"key": "deliberate-test", "value": "true"}])["taskDefinition"]["taskDefinitionArn"]
    started = _now()
    rolled_back, state, seen_failed = False, None, False
    try:
        ecs.update_service(cluster=CLUSTER, service="api", taskDefinition=broken)
        for _ in range(120):  # up to 30 minutes
            time.sleep(15)
            current = ecs.describe_services(cluster=CLUSTER, services=["api"])["services"][0]
            # ECS drops the failed deployment from the list once the rollback
            # completes, so the failure is remembered once seen, and the
            # service's own "rolling back" event counts as seeing it. The
            # first run (2026-10-06) waited for both at once and never saw them.
            seen_failed |= any(d["taskDefinition"] == broken and d.get("rolloutState") == "FAILED"
                               for d in current["deployments"])
            recent = [e["message"] for e in current["events"] if e["createdAt"] >= started]
            seen_failed |= any("rolling back" in m for m in recent)
            primary = next(d for d in current["deployments"] if d["status"] == "PRIMARY")
            state = {"primary": primary["taskDefinition"], "primary_rollout": primary.get("rolloutState"),
                     "broken_failed": seen_failed}
            if seen_failed and primary["taskDefinition"] == original and primary.get("rolloutState") == "COMPLETED":
                rolled_back = True
                break
    finally:
        current = ecs.describe_services(cluster=CLUSTER, services=["api"])["services"][0]
        if current["taskDefinition"] != original:  # never leave the broken revision serving
            ecs.update_service(cluster=CLUSTER, service="api", taskDefinition=original)
        ecs.deregister_task_definition(taskDefinition=broken)
    events = [e["message"] for e in current["events"] if e["createdAt"] >= started][:12]
    observed = {"original": original, "broken": broken, "final": state, "rolled_back": rolled_back,
                "minutes": round((_now() - started).total_seconds() / 60, 1), "events": events}
    return rolled_back, "the circuit breaker fails the broken deployment and the service returns to the prior revision", observed


def timed_point_in_time_restore(session) -> tuple[bool, str, dict]:
    rds = session.client("rds", region_name=REGION)
    ec2 = session.client("ec2", region_name=REGION)
    source = rds.describe_db_instances(DBInstanceIdentifier="fedramp-20x-ksi")["DBInstances"][0]
    latest = source["LatestRestorableTime"]
    chosen = max(latest - dt.timedelta(minutes=5), source["InstanceCreateTime"] + dt.timedelta(minutes=5))
    chosen = min(chosen, latest).replace(microsecond=0)
    sg = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["fedramp-20x-ksi-database"]}])["SecurityGroups"][0]["GroupId"]
    target = f"fedramp-20x-ksi-restore-{_now():%Y%m%d%H%M}"
    started = _now()
    rds.restore_db_instance_to_point_in_time(
        SourceDBInstanceIdentifier="fedramp-20x-ksi", TargetDBInstanceIdentifier=target, RestoreTime=chosen,
        DBSubnetGroupName="fedramp-20x-ksi", DBParameterGroupName="fedramp-20x-ksi", VpcSecurityGroupIds=[sg],
        DBInstanceClass="db.t4g.small", PubliclyAccessible=False, EnableIAMDatabaseAuthentication=True, MultiAZ=False,
        DeletionProtection=False, Tags=[{"Key": "deliberate-test", "Value": "true"}])
    try:
        rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=target,
                                                     WaiterConfig={"Delay": 30, "MaxAttempts": 160})
        available = _now()
        restored = rds.describe_db_instances(DBInstanceIdentifier=target)["DBInstances"][0]
    finally:
        rds.delete_db_instance(DBInstanceIdentifier=target, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
    minutes = round((available - started).total_seconds() / 60, 1)
    observed = {"restored_to": chosen.isoformat(), "instance": target, "minutes_to_available": minutes,
                "objective_minutes": 60, "encrypted": restored["StorageEncrypted"], "kms_key": restored.get("KmsKeyId"),
                "public": restored["PubliclyAccessible"], "deleted_after": True}
    return (minutes <= 60 and restored["StorageEncrypted"] and not restored["PubliclyAccessible"],
            "the restore to the chosen moment is available within the 60-minute objective, encrypted and private",
            observed)


def stopped_task_replaced(session) -> tuple[bool, str, dict]:
    ecs = session.client("ecs", region_name=REGION)
    desired = ecs.describe_services(cluster=CLUSTER, services=["api"])["services"][0]["desiredCount"]
    before = set(ecs.list_tasks(cluster=CLUSTER, serviceName="api", desiredStatus="RUNNING")["taskArns"])
    victim = sorted(before)[0]
    stopped_at = _now()
    ecs.stop_task(cluster=CLUSTER, task=victim, reason="deliberate test: stopped_task_replaced")
    replaced, running, replacement = None, [], None
    for _ in range(60):  # up to 10 minutes
        time.sleep(10)
        running = ecs.list_tasks(cluster=CLUSTER, serviceName="api", desiredStatus="RUNNING")["taskArns"]
        new = [t for t in running if t not in before]
        if new and victim not in running:
            states = ecs.describe_tasks(cluster=CLUSTER, tasks=running)["tasks"]
            if len([t for t in states if t["lastStatus"] == "RUNNING"]) >= desired:
                replaced, replacement = _now(), new[0]
                break
    observed = {"desired": desired, "stopped": victim, "replacement": replacement,
                "running_after": len(running), "minutes_to_restore": replaced and round((replaced - stopped_at).total_seconds() / 60, 1)}
    return (replaced is not None, "a replacement task starts and the service returns to its desired count unattended",
            observed)


SCENARIOS = {f.__name__: f for f in (object_lock_rejects_change, out_of_band_change_detected,
                                       delivery_failure_alerts, prior_state_recoverable,
                                       historical_advisory_surfaced, waf_blocks_and_allows,
                                       task_internet_egress_blocked, permissive_group_still_no_egress,
                                       service_to_service_refused, failing_deploy_rolls_back,
                                       timed_point_in_time_restore, stopped_task_replaced)}
