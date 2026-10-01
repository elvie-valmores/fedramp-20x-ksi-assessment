#!/usr/bin/env python3
"""Proves the inventory generator actually works, against real clouds.

Two claims need proving, and neither can be proven by reading the code:

  Accuracy -- the inventory includes what it should and excludes what it
  shouldn't. Tested by creating two resources: one of a type the cloud is
  watching, one of a type it isn't. Exactly one should appear.

  Liveness -- the inventory is queried fresh, not served from a cache.
  Tested implicitly by the same seed: its name is a random string that
  did not exist anywhere before this script started, so a cached answer
  could not possibly contain it.

On GCP a third claim is proven with the same seed: the asset feed
delivers. The feed's only reader is this test -- notices are not kept,
because Admin Activity audit logs are GCP's change record -- so a feed that
stopped delivering would otherwise go unnoticed while its configuration
check kept passing (DECISIONS.md, 2026-10-01).

Both clouds index new resources with a short delay, so lookups poll
rather than checking once. Every resource created here is deleted before
the script exits, pass or fail.
"""

from __future__ import annotations

import sys
import time
import uuid

import boto3
from google.cloud import pubsub_v1, storage

import aws_source
import gcp_source
from gcp_auth import DEFAULT_PROJECT_ID

POLL_INTERVAL_SECONDS = 15
POLL_TIMEOUT_SECONDS = 300  # indexing lag runs to a few minutes on both clouds
FEED_TIMEOUT_SECONDS = 120  # the feed delivered in 4 to 13 seconds when probed


def _seed_name() -> str:
    """A globally unique, obviously-disposable resource name."""
    return f"fedramp-20x-ksi-selftest-{uuid.uuid4().hex[:10]}"


def _poll_until(predicate):
    """Call `predicate` until it returns something non-None, or time out.

    Returns the predicate's value on success, None on timeout.
    """
    deadline = time.time() + POLL_TIMEOUT_SECONDS
    while time.time() < deadline:
        result = predicate()
        if result is not None:
            return result
        time.sleep(POLL_INTERVAL_SECONDS)
    return None


def _feed_delivers(subscriber, sub_path: str, name: str) -> bool:
    """Whether a feed message naming `name` arrives on the subscription.

    Every message pulled is acknowledged, matching or not: the subscription
    is this run's own and is deleted afterwards.
    """
    import json

    deadline = time.time() + FEED_TIMEOUT_SECONDS
    while time.time() < deadline:
        response = subscriber.pull(
            request={"subscription": sub_path, "max_messages": 50}, timeout=30
        )
        if response.received_messages:
            subscriber.acknowledge(request={
                "subscription": sub_path,
                "ack_ids": [m.ack_id for m in response.received_messages],
            })
        for m in response.received_messages:
            asset = json.loads(m.message.data).get("asset", {})
            if name in asset.get("name", ""):
                return True
        time.sleep(5)
    return False


def _report(cloud: str, in_scope_present: bool, out_of_scope_absent: bool) -> bool:
    print(f"[{cloud}] liveness: PASS (seed created this run was returned)")
    print(
        f"[{cloud}] accuracy  in-scope present: {in_scope_present}, "
        f"out-of-scope absent: {out_of_scope_absent}"
    )
    return in_scope_present and out_of_scope_absent


def aws_test(region: str = aws_source.DEFAULT_REGION) -> bool:
    s3 = boto3.client("s3", region_name=region)
    sns = boto3.client("sns", region_name=region)

    bucket_name = _seed_name()  # S3::Bucket -- a type Config records
    topic_name = _seed_name()  # SNS::Topic -- a type Config does not record
    bucket_created = False
    topic_arn = None

    # Each flag flips only once its resource exists, so the finally block
    # deletes exactly what was created even if seeding fails partway.
    try:
        print(f"[aws] seeding watched type: S3 bucket {bucket_name}")
        s3.create_bucket(Bucket=bucket_name)
        bucket_created = True

        print(f"[aws] seeding unwatched type: SNS topic {topic_name}")
        topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]

        print(f"[aws] polling Config for the seeded bucket (up to {POLL_TIMEOUT_SECONDS}s)")

        def bucket_is_indexed():
            resources = aws_source.generate(region=region)
            ids = {r["resource_id"] for r in resources}
            return resources if bucket_name in ids else None

        resources = _poll_until(bucket_is_indexed)
        if resources is None:
            print("[aws] FAIL: seeded bucket never appeared; liveness not demonstrated")
            return False

        ids = {r["resource_id"] for r in resources}
        return _report(
            "aws",
            in_scope_present=bucket_name in ids,
            out_of_scope_absent=topic_name not in ids and topic_arn not in ids,
        )
    finally:
        print("[aws] deleting seeds")
        if topic_arn:
            sns.delete_topic(TopicArn=topic_arn)
        if bucket_created:
            s3.delete_bucket(Bucket=bucket_name)


def gcp_test(project_id: str = DEFAULT_PROJECT_ID) -> bool:
    storage_client = storage.Client(project=project_id)
    subscriber = pubsub_v1.SubscriberClient()

    bucket_name = _seed_name()  # storage Bucket -- a tracked asset type
    sub_name = _seed_name()  # pubsub Subscription -- an untracked asset type
    sub_path = subscriber.subscription_path(project_id, sub_name)
    bucket_created = False
    subscription_created = False

    try:
        # The unwatched seed is a subscription on the asset feed's topic,
        # and it is read: it is how the feed's delivery is proven. Created
        # before the bucket, because a subscription only receives what is
        # published after it exists.
        print(f"[gcp] seeding unwatched type: Pub/Sub subscription {sub_name}")
        feed_topic = pubsub_v1.PublisherClient().topic_path(
            project_id, "fedramp-20x-ksi-asset-feed"
        )
        subscriber.create_subscription(request={"name": sub_path, "topic": feed_topic})
        subscription_created = True

        print(f"[gcp] seeding watched type: GCS bucket {bucket_name}")
        storage_client.create_bucket(bucket_name)
        bucket_created = True

        print(f"[gcp] waiting for the asset feed to report the bucket (up to {FEED_TIMEOUT_SECONDS}s)")
        feed_ok = _feed_delivers(subscriber, sub_path, bucket_name)
        print(f"[gcp] feed delivery: {'PASS' if feed_ok else 'FAIL -- no feed message for the seed'}")

        print(
            f"[gcp] polling Cloud Asset Inventory for the seeded bucket "
            f"(up to {POLL_TIMEOUT_SECONDS}s)"
        )

        def bucket_is_indexed():
            resources = gcp_source.generate(project_id=project_id)
            # GCP resource IDs are full paths, so match on substring
            # rather than equality.
            if any(bucket_name in r["resource_id"] for r in resources):
                return resources
            return None

        resources = _poll_until(bucket_is_indexed)
        if resources is None:
            print("[gcp] FAIL: seeded bucket never appeared; liveness not demonstrated")
            return False

        ids = {r["resource_id"] for r in resources}
        accurate = _report(
            "gcp",
            in_scope_present=any(bucket_name in i for i in ids),
            out_of_scope_absent=not any(sub_name in i for i in ids),
        )
        return accurate and feed_ok
    finally:
        print("[gcp] deleting seeds")
        if subscription_created:
            subscriber.delete_subscription(request={"subscription": sub_path})
        if bucket_created:
            storage_client.bucket(bucket_name).delete()


def main() -> int:
    aws_ok = aws_test()
    gcp_ok = gcp_test()

    print()
    print(f"AWS self-test: {'PASS' if aws_ok else 'FAIL'}")
    print(f"GCP self-test: {'PASS' if gcp_ok else 'FAIL'}")

    return 0 if (aws_ok and gcp_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
