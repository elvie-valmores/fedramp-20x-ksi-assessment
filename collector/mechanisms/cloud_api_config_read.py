"""cloud_api_config_read: read a cloud resource's live configuration and
assert a condition against it.

Generalizes the query pattern inventory/aws_source.py and
inventory/gcp_source.py already use for the same reason: Terraform state
describes intent, the provider's own API describes reality.

New provider/resource combinations get a new handler method here as new
check definitions need them, not a new mechanism.
"""

from __future__ import annotations

import boto3
import google.auth
from google.auth import impersonated_credentials
from google.cloud import asset_v1

from base import CheckDefinition, CheckResult, Mechanism


class CloudAPIConfigRead(Mechanism):
    name = "cloud_api_config_read"

    def run(self, check: CheckDefinition) -> CheckResult:
        provider = check.params["provider"]
        resource = check.params["resource"]

        if provider == "aws" and resource == "config_recorder":
            return self._aws_config_recorder(check)
        if provider == "gcp" and resource == "cloud_asset_feed":
            return self._gcp_asset_feed(check)

        raise NotImplementedError(
            f"cloud_api_config_read has no handler for provider={provider!r} "
            f"resource={resource!r} yet -- add one as new checks need it."
        )

    def _aws_config_recorder(self, check: CheckDefinition) -> CheckResult:
        region = check.params.get("region", "us-east-1")
        client = boto3.client("config", region_name=region)

        recorders = client.describe_configuration_recorders()["ConfigurationRecorders"]
        statuses = {
            s["name"]: s
            for s in client.describe_configuration_recorder_status()[
                "ConfigurationRecordersStatus"
            ]
        }
        evidence = {"recorders": recorders, "statuses": statuses}

        if not recorders:
            return CheckResult(check.id, False, evidence, "no Config recorder exists")

        recording = all(
            statuses.get(r["name"], {}).get("recording", False) for r in recorders
        )
        message = (
            "recorder present and recording"
            if recording
            else "recorder exists but is not recording"
        )
        return CheckResult(check.id, recording, evidence, message)

    def _gcp_asset_feed(self, check: CheckDefinition) -> CheckResult:
        project_id = check.params["project_id"]
        feed_id = check.params["feed_id"]

        # Same impersonation pattern as inventory/gcp_source.py -- act as
        # terraform-admin, no static key file.
        source_credentials, _ = google.auth.default()
        target_credentials = impersonated_credentials.Credentials(
            source_credentials=source_credentials,
            target_principal=f"terraform-admin@{project_id}.iam.gserviceaccount.com",
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        client = asset_v1.AssetServiceClient(credentials=target_credentials)

        # get_feed's resource name requires the numeric project number,
        # not the project ID string, and list_feeds is the only call that
        # tells us that mapping -- so list-and-match rather than guessing
        # the direct name.
        try:
            feeds = client.list_feeds(parent=f"projects/{project_id}").feeds
        except Exception as exc:
            return CheckResult(check.id, False, {"error": str(exc)}, "could not list feeds")

        feed = next((f for f in feeds if f.name.endswith(f"/feeds/{feed_id}")), None)
        if feed is None:
            return CheckResult(check.id, False, {"feeds_found": [f.name for f in feeds]}, "feed not found")

        evidence = {"name": feed.name, "asset_types": list(feed.asset_types)}
        passed = bool(feed.asset_types)
        message = (
            "feed exists with asset types configured"
            if passed
            else "feed exists but tracks no asset types"
        )
        return CheckResult(check.id, passed, evidence, message)
