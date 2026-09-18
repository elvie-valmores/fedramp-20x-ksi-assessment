"""GCP half of the KSI-PIY-GIV inventory generator.

Queries Cloud Asset Inventory's SearchAllResources API directly at call
time -- no cached intermediate, the same live-query shape aws_source.py
uses against AWS Config's SelectResourceConfig.

Scoped to the project, not the organization: see docs/DECISIONS.md,
2026-09-18, "Cloud Asset Inventory scoped to the project, not the
organization". Asset types queried must stay in sync with the feed scope
in infra/gcp/inventory.tf — change one, change the other, same caveat as
aws_source.py's RESOURCE_TYPES.

Authenticates as the human running it (Application Default Credentials),
then impersonates terraform-admin for the actual call -- the same
identity and mechanism infra/gcp/provider.tf uses for Terraform itself.
"""

from __future__ import annotations

import google.auth
from google.auth import impersonated_credentials
from google.cloud import asset_v1

ASSET_TYPES = [
    "storage.googleapis.com/Bucket",
    "run.googleapis.com/Service",
    "bigquery.googleapis.com/Dataset",
    "bigquery.googleapis.com/Table",
    "cloudkms.googleapis.com/CryptoKey",
    "artifactregistry.googleapis.com/Repository",
    "iam.googleapis.com/ServiceAccount",
    "iam.googleapis.com/Role",
    "pubsub.googleapis.com/Topic",
    "cloudresourcemanager.googleapis.com/Project",
]


class GCPNotConfigured(RuntimeError):
    pass


def _client(project_id: str) -> asset_v1.AssetServiceClient:
    try:
        source_credentials, _ = google.auth.default()
    except google.auth.exceptions.DefaultCredentialsError as exc:
        raise GCPNotConfigured(
            "No Application Default Credentials found. Run "
            "'gcloud auth application-default login' first."
        ) from exc

    target_credentials = impersonated_credentials.Credentials(
        source_credentials=source_credentials,
        target_principal=f"terraform-admin@{project_id}.iam.gserviceaccount.com",
        target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    return asset_v1.AssetServiceClient(credentials=target_credentials)


def generate(project_id: str = "fedramp-20x-ksi-assessment") -> list[dict]:
    """Query Cloud Asset Inventory live and return a normalized resource list.

    Same shape aws_source.generate() produces, so the two lists can be
    concatenated into one cross-cloud inventory without a merge step.
    """
    client = _client(project_id)
    request = asset_v1.SearchAllResourcesRequest(
        scope=f"projects/{project_id}",
        asset_types=ASSET_TYPES,
    )

    resources = []
    for asset in client.search_all_resources(request=request):
        resources.append(
            {
                "cloud": "gcp",
                "resource_id": asset.name,
                "resource_type": asset.asset_type,
                "name": asset.display_name or asset.name.rsplit("/", 1)[-1],
                "location": asset.location,
                "tags": dict(asset.labels) if asset.labels else {},
                "created_at": (
                    asset.create_time.isoformat() if asset.create_time else None
                ),
            }
        )
    return resources
