# GitHub Actions to GCP, without a key.
#
# The GCP counterpart of infra/aws/pipeline_identity.tf's OIDC provider.
# Built on 2026-10-01 for the collector's schedule, which cannot run in CI
# while GCP checks have no identity there, and which is also the missing
# piece for building the analytics image (DECISIONS.md, 2026-10-01).
#
# Two choices, each the same as the AWS side's or stricter:
#
#   - Trust is pinned to GitHub's immutable numeric IDs for the owner and
#     the repository, and to main, not to names. A repository renamed or
#     recreated with a familiar name does not inherit it. See the long
#     comment on github_subject in infra/aws/pipeline.tf for why IDs.
#   - Access is granted to the federated principal directly, with no
#     service account in between. There is no identity to impersonate and
#     no token-creator grant to guard, and GCP's audit logs name the
#     repository itself as the caller.
#
# Permanent in practice: a deleted pool or provider keeps its ID reserved
# for 30 days, and a deleted custom role for 37.

locals {
  github_owner_id = "181586876"
  github_repo_id  = "1375137942"
}

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  description               = "Workflows in this project's repository, on main only."
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub OIDC"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository_id"
    "attribute.owner"      = "assertion.repository_owner_id"
    "attribute.ref"        = "assertion.ref"
    # The workflow file the token was minted for, e.g. "collect.yml", taken
    # from job_workflow_ref. Each grant below names its workflow, so one
    # workflow's permissions are not every workflow's (2026-10-02).
    "attribute.workflow" = "assertion.job_workflow_ref.extract('.github/workflows/{name}@')"
  }

  # Evaluated on every token exchange. A token from any other repository,
  # owner or branch is refused here, before any grant is consulted.
  attribute_condition = join(" && ", [
    "assertion.repository_owner_id == '${local.github_owner_id}'",
    "assertion.repository_id == '${local.github_repo_id}'",
    "assertion.ref == 'refs/heads/main'",
  ])
}

# What the collector reads. Enumerated, not a predefined role: the
# 2026-09-05 CNA-DFP decision bars predefined roles on any workload
# identity, because their contents change when Google changes them.
# Built up by running every GCP check under this role and adding exactly
# what each failure named (DECISIONS.md, 2026-10-01).
resource "google_project_iam_custom_role" "collector" {
  role_id     = "fedrampKsiCollector"
  title       = "fedramp-20x-ksi collector"
  description = "Read-only access for the evidence collector run from GitHub Actions."

  permissions = [
    # piy-giv-cfg-gcp-asset-feed
    "cloudasset.feeds.get",
    "cloudasset.feeds.list",
    # the inventory generator, and svc-sin-cfg-gcp-stores-use-declared-keys
    "cloudasset.assets.searchAllResources",
    # iam-elp-cfg-gcp-basic-roles-allowed-only
    "cloudasset.assets.searchAllIamPolicies",

    # The GCP drift checks' terraform plan: one read per resource type in
    # state, seeded from the state's types and corrected by CI runs.
    "artifactregistry.repositories.get",
    "bigquery.datasets.get",
    "bigquery.tables.get",
    "cloudkms.cryptoKeys.get",
    "cloudkms.cryptoKeys.getIamPolicy",
    "cloudkms.keyRings.get",
    "iam.roles.get",
    "iam.serviceAccounts.get",
    "iam.workloadIdentityPoolProviders.get",
    "iam.workloadIdentityPools.get",
    "logging.buckets.get",
    "logging.buckets.list", # log buckets come from Logging, which reports regional ones; Cloud Asset does not
    "logging.settings.get",
    "logging.exclusions.get",
    "logging.sinks.get",
    # At the TESTING support level for custom roles: accepted, and may change.
    "monitoring.notificationChannels.get",
    "pubsub.topics.get",
    "pubsub.topics.getIamPolicy",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "serviceusage.services.get",
    "serviceusage.services.list", # google_project_service reads by listing, found by CI run 36938488520
    "storage.buckets.get",
    "storage.buckets.getIamPolicy",
  ]
}

# The collector role, to collect.yml only. Until 2026-10-02 it was granted
# to the repository, so any workflow on main held it.
resource "google_project_iam_member" "github_collector" {
  project = var.gcp_project_id
  role    = google_project_iam_custom_role.collector.id
  member  = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.workflow/collect.yml"
}

# Publishing the analytics image: build-and-push.yml, on the one Artifact
# Registry repository, and nothing else. Enumerated, per CNA-DFP. Tags in the
# repository are immutable, so this cannot move a published tag.
resource "google_project_iam_custom_role" "image_publisher" {
  role_id     = "fedrampKsiImagePublisher"
  title       = "fedramp-20x-ksi image publisher"
  description = "Push and sign images in the pipeline repository, from GitHub Actions."

  permissions = [
    "artifactregistry.repositories.downloadArtifacts",
    "artifactregistry.repositories.get",
    "artifactregistry.repositories.uploadArtifacts",
    "artifactregistry.tags.create",
    "artifactregistry.tags.get",
    "artifactregistry.versions.get",
  ]
}

resource "google_artifact_registry_repository_iam_member" "github_image_publisher" {
  location   = google_artifact_registry_repository.pipeline.location
  repository = google_artifact_registry_repository.pipeline.name
  role       = google_project_iam_custom_role.image_publisher.id
  member     = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.workflow/build-and-push.yml"
}
