"""Reads the live GCP resource inventory out of Cloud Asset Inventory.

The GCP counterpart to aws_source.py. Cloud Asset Inventory's
SearchAllResources endpoint plays the same role AWS Config's
SelectResourceConfig does: one API that answers across many resource
types, queried live on every call rather than cached.

Searches are scoped to a single project. The project this assessment uses
sits outside any GCP organization, so project scope is the widest scope
available -- and with one project, it is also the complete picture.
"""

from __future__ import annotations

from google.cloud import asset_v1

from gcp_auth import DEFAULT_PROJECT_ID, GCPNotConfigured, asset_client

# Must mirror the feed's asset_types in infra/gcp/inventory.tf, for the
# same reason aws_source.RESOURCE_TYPES mirrors the Config recorder.
ASSET_TYPES = [
    "storage.googleapis.com/Bucket",
    "run.googleapis.com/Service",
    "run.googleapis.com/Job",  # the analytics pipeline (2026-10-03); its scheduler job is not searchable
    "bigquery.googleapis.com/Dataset",
    "bigquery.googleapis.com/Table",
    "cloudkms.googleapis.com/CryptoKey",
    "artifactregistry.googleapis.com/Repository",
    "iam.googleapis.com/ServiceAccount",
    "iam.googleapis.com/Role",
    "pubsub.googleapis.com/Topic",
    "cloudresourcemanager.googleapis.com/Project",
]

# Re-exported so callers can catch it without importing gcp_auth too.
__all__ = ["ASSET_TYPES", "GCPNotConfigured", "generate"]


def generate(project_id: str = DEFAULT_PROJECT_ID) -> list[dict]:
    """Return every tracked GCP resource, in the shared cross-cloud shape.

    Field names match aws_source.generate() exactly so the two lists can
    be concatenated directly.
    """
    client = asset_client(project_id)
    request = asset_v1.SearchAllResourcesRequest(
        scope=f"projects/{project_id}",
        asset_types=ASSET_TYPES,
    )

    resources = []
    # The client pages through results transparently; iterating the
    # response walks every match, not just the first page.
    for asset in client.search_all_resources(request=request):
        resources.append(
            {
                "cloud": "gcp",
                "resource_id": asset.name,
                # display_name is often empty, so fall back to the last
                # path segment of the full resource name.
                "name": asset.display_name or asset.name.rsplit("/", 1)[-1],
                "resource_type": asset.asset_type,
                "location": asset.location,
                # GCP calls these labels; AWS calls them tags. Same idea,
                # so they land in the same field.
                "tags": dict(asset.labels) if asset.labels else {},
                "created_at": (
                    asset.create_time.isoformat() if asset.create_time else None
                ),
            }
        )
    return resources
