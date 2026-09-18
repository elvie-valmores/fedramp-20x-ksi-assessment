# KSI-PIY-GIV, build item 2: Cloud Asset Inventory.
#
# Scoped to this project, not the organization — see docs/DECISIONS.md,
# 2026-09-18, "Cloud Asset Inventory scoped to the project, not the
# organization". The project this root manages sits outside the domain's
# auto-provisioned org, and moving it in would stand up more identity
# surface than this persona plausibly has.
#
# Unlike AWS Config (billed per configuration item, which is why
# infra/aws/inventory.tf narrows resource_types for cost), Cloud Asset
# Inventory and Pub/Sub at this volume are effectively free — there's no
# cost reason to narrow this list. asset_types is still required though:
# unlike AWS Config, an empty list here means "nothing," not "everything"
# (Cloud Asset's API rejects a feed with no asset_names/asset_types at
# all). Scoped to what docs/PROJECT-CONTEXT.md's architecture section
# names for the GCP side; extend as later build phases add resources.
locals {
  asset_feed_types = [
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
}

data "google_project" "asset_inventory" {
  project_id = var.gcp_project_id
}

resource "google_pubsub_topic" "asset_feed" {
  name = "fedramp-20x-ksi-asset-feed"
}

# The Cloud Asset service's own service agent is what publishes feed
# events — not terraform-admin — so it needs its own grant on the topic.
resource "google_pubsub_topic_iam_member" "asset_feed_publisher" {
  topic  = google_pubsub_topic.asset_feed.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:service-${data.google_project.asset_inventory.number}@gcp-sa-cloudasset.iam.gserviceaccount.com"
}

resource "google_cloud_asset_project_feed" "main" {
  project      = var.gcp_project_id
  feed_id      = "fedramp-20x-ksi-inventory-feed"
  content_type = "RESOURCE"
  asset_types  = local.asset_feed_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.asset_feed.id
    }
  }

  depends_on = [google_pubsub_topic_iam_member.asset_feed_publisher]
}
