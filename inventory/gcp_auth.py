"""GCP client construction, shared by the inventory generator and the
collector framework.

Auth works in two hops. The caller authenticates as themselves using
Application Default Credentials -- whatever `gcloud auth
application-default login` wrote to disk. Those credentials are then used
to mint a short-lived access token *for* the terraform-admin service
account, and it's that token the API calls actually carry.

The point is that no service account key file exists anywhere. A key file
is a long-lived secret that can leak; a minted token expires on its own.
This mirrors what infra/gcp/provider.tf does for Terraform, so both the
Python tooling and the Terraform runs act as the same identity with the
same permissions.

In CI there is no one to impersonate as. GitHub Actions authenticates by
workload identity federation, and the federated principal holds the
collector's own read-only role directly (infra/gcp/github_federation.tf).
GCP_IMPERSONATE=none says so: the ambient credentials are used as they are.
Locally it is unset and the two-hop path above applies. CI must never be
given the token-creator grant on terraform-admin that impersonation needs:
that would make a read-only workflow a provisioning one.
"""

from __future__ import annotations

import os

import google.auth
from google.auth import impersonated_credentials
from google.cloud import asset_v1

DEFAULT_PROJECT_ID = "fedramp-20x-ksi-assessment"

# Impersonating this account requires the caller to hold
# roles/iam.serviceAccountTokenCreator on it.
SERVICE_ACCOUNT_TEMPLATE = "terraform-admin@{project_id}.iam.gserviceaccount.com"

# Broad scope, narrow permissions: the scope says which API family the
# token is valid for, while what it can actually do is bounded by the
# service account's own IAM roles.
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class GCPNotConfigured(RuntimeError):
    """Raised when GCP credentials are missing, rather than letting a
    less obvious error surface further down the call stack."""


def impersonated_token(project_id: str):
    """Credentials for `project_id`: terraform-admin's, or the caller's own.

    The caller's own when GCP_IMPERSONATE is "none" (CI); otherwise a token
    minted for terraform-admin.
    """
    try:
        caller_credentials, _ = google.auth.default(scopes=SCOPES)
    except google.auth.exceptions.DefaultCredentialsError as exc:
        raise GCPNotConfigured(
            "No Application Default Credentials found. Run "
            "'gcloud auth application-default login' first."
        ) from exc

    if os.environ.get("GCP_IMPERSONATE", "").lower() == "none":
        return caller_credentials

    return impersonated_credentials.Credentials(
        source_credentials=caller_credentials,
        target_principal=SERVICE_ACCOUNT_TEMPLATE.format(project_id=project_id),
        target_scopes=SCOPES,
    )


def asset_client(project_id: str) -> asset_v1.AssetServiceClient:
    """Cloud Asset Inventory client, authenticated as impersonated_token says."""
    return asset_v1.AssetServiceClient(credentials=impersonated_token(project_id))
