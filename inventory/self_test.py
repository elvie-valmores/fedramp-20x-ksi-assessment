#!/usr/bin/env python3
"""Self-test for the inventory generator, per KSI-PIY-GIV's automation
assurance section (docs/KSI-Design-Matrix.xlsx, PIY tab):

  "Accuracy is tested by seeding a resource that should appear and one
  that should be excluded, then confirming the generator returns exactly
  one."

Plus the real-time validation row: a resource created after the previous
generation must appear on the next run. A freshly-seeded resource proves
both at once — it didn't exist before this process started, so its
presence in the output is itself proof the query is live, not cached.

Both AWS Config and GCP Cloud Asset Inventory index changes with some
lag (seconds to a few minutes), so this polls with a timeout rather than
asserting instantly. Every resource this script creates is a throwaway
seed, deleted at the end whether the test passes or fails — the same
apply-and-destroy discipline the rest of this project follows applies to
test seeds too.
"""

from __future__ import annotations

import sys
import time
import uuid

import boto3
from google.cloud import pubsub_v1, storage

import aws_source
import gcp_source

POLL_INTERVAL_SECONDS = 15
POLL_TIMEOUT_SECONDS = 300  # Config/Asset Inventory ingestion lag observed up to a few minutes


def _poll_until(predicate, timeout=POLL_TIMEOUT_SECONDS, interval=POLL_INTERVAL_SECONDS):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = predicate()
        if result is not None:
            return result
        time.sleep(interval)
    return None


def aws_test(region: str = "us-east-1") -> bool:
    s3 = boto3.client("s3", region_name=region)
    sns = boto3.client("sns", region_name=region)

    in_scope_name = f"fedramp-20x-ksi-selftest-{uuid.uuid4().hex[:10]}"
    out_of_scope_name = f"fedramp-20x-ksi-selftest-{uuid.uuid4().hex[:10]}"

    print(f"[aws] seeding in-scope resource (recorded type): S3 bucket {in_scope_name}")
    s3.create_bucket(Bucket=in_scope_name)

    print("[aws] seeding out-of-scope resource (unrecorded type): SNS topic")
    out_of_scope_arn = sns.create_topic(Name=out_of_scope_name)["TopicArn"]

    try:
        print(f"[aws] polling Config for the seeded bucket (up to {POLL_TIMEOUT_SECONDS}s)...")

        def check():
            resources = aws_source.generate(region=region)
            ids = {r["resource_id"] for r in resources}
            return resources if in_scope_name in ids else None

        resources = _poll_until(check)
        if resources is None:
            print("[aws] FAIL: seeded bucket never appeared within timeout — "
                  "real-time claim not demonstrated")
            return False

        ids = {r["resource_id"] for r in resources}
        in_scope_present = in_scope_name in ids
        out_of_scope_absent = out_of_scope_name not in ids and out_of_scope_arn not in ids

        print(f"[aws] real-time: PASS (seeded bucket, created this run, appeared)")
        print(f"[aws] accuracy — in-scope present: {in_scope_present}, "
              f"out-of-scope absent: {out_of_scope_absent}")

        return in_scope_present and out_of_scope_absent
    finally:
        print("[aws] reverting seeds")
        s3.delete_bucket(Bucket=in_scope_name)
        sns.delete_topic(TopicArn=out_of_scope_arn)


def gcp_test(project_id: str = "fedramp-20x-ksi-assessment") -> bool:
    in_scope_name = f"fedramp-20x-ksi-selftest-{uuid.uuid4().hex[:10]}"

    storage_client = storage.Client(project=project_id)
    publisher = pubsub_v1.PublisherClient()

    print(f"[gcp] seeding in-scope resource (recorded type): GCS bucket {in_scope_name}")
    storage_client.create_bucket(in_scope_name)

    print("[gcp] seeding out-of-scope resource (unrecorded type): Pub/Sub subscription")
    feed_topic_path = publisher.topic_path(project_id, "fedramp-20x-ksi-asset-feed")
    subscriber = pubsub_v1.SubscriberClient()
    sub_name = f"fedramp-20x-ksi-selftest-{uuid.uuid4().hex[:10]}"
    sub_path = subscriber.subscription_path(project_id, sub_name)
    subscriber.create_subscription(request={"name": sub_path, "topic": feed_topic_path})

    try:
        print(f"[gcp] polling Cloud Asset Inventory for the seeded bucket (up to {POLL_TIMEOUT_SECONDS}s)...")

        def check():
            resources = gcp_source.generate(project_id=project_id)
            names = {r["resource_id"] for r in resources}
            match = f"//storage.googleapis.com/{in_scope_name}"
            return resources if any(match in n for n in names) else None

        resources = _poll_until(check)
        if resources is None:
            print("[gcp] FAIL: seeded bucket never appeared within timeout — "
                  "real-time claim not demonstrated")
            return False

        ids = {r["resource_id"] for r in resources}
        in_scope_present = any(in_scope_name in i for i in ids)
        out_of_scope_absent = not any(sub_name in i for i in ids)

        print(f"[gcp] real-time: PASS (seeded bucket, created this run, appeared)")
        print(f"[gcp] accuracy — in-scope present: {in_scope_present}, "
              f"out-of-scope absent: {out_of_scope_absent}")

        return in_scope_present and out_of_scope_absent
    finally:
        print("[gcp] reverting seeds")
        subscriber.delete_subscription(request={"subscription": sub_path})
        storage_client.bucket(in_scope_name).delete()


def main() -> int:
    aws_ok = aws_test()
    gcp_ok = gcp_test()

    print()
    print(f"AWS self-test: {'PASS' if aws_ok else 'FAIL'}")
    print(f"GCP self-test: {'PASS' if gcp_ok else 'FAIL'}")

    return 0 if (aws_ok and gcp_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
