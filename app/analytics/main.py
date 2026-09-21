"""The analytics pipeline job.

Runs on a schedule in Cloud Run. Reads measurement extracts out of the AWS
S3 bucket, lands them in GCS, and loads them into BigQuery.

This is the single machine-to-machine cross-cloud path in the architecture
and KSI-SVC-VCM is determined against it, so how it authenticates is the
interesting part rather than what it moves.

**No static credential exists on this path.** The job holds a Google service
account identity. It asks Google for an identity token, hands that token to
AWS STS, and receives a short-lived AWS session in return. Nothing is stored
on either side, and the AWS role's trust policy matches the service
account's numeric ID rather than its email, so the trust cannot be
re-pointed by recreating an account with a familiar name.

**Landings are at-least-once.** The AWS worker's extract window is wider
than its interval, so rows appear in more than one extract file. That is a
deliberate trade made on the AWS side -- losing customer data is worse than
duplicating it -- and it makes deduplication this job's responsibility. The
load is therefore into a staging table followed by a MERGE on the source
primary key, not a plain append.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
import google.auth.transport.requests
from google.cloud import bigquery, storage
from google.oauth2 import id_token as google_id_token

LOG = logging.getLogger("analytics")


def aws_session() -> boto3.Session:
    """Exchange a Google identity token for a short-lived AWS session.

    The audience is the service account's numeric unique ID, passed in by
    Terraform, which is what the AWS trust policy pins. Using anything else
    -- the account email, a URL, a fixed string -- means the token's aud
    claim does not match the policy condition and the exchange is refused.
    """
    role_arn = os.environ["AWS_ROLE_ARN"]

    # The audience, supplied by Terraform from the service account's own
    # unique ID.
    #
    # This must equal what the AWS trust policy pins
    # accounts.google.com:aud to, exactly. It is read from the environment
    # rather than derived here -- an earlier version derived it from the
    # credentials object and got the service account *email*, which the
    # policy does not match, so every assume-role would have failed with an
    # access denial that named nothing useful. Deriving a value that has to
    # agree with a policy in another repository root is how that happens.
    #
    # No fallback. A wrong or missing audience should fail here, loudly,
    # rather than silently attempt a token the policy will reject.
    audience = os.environ["GCP_SA_UNIQUE_ID"]

    request = google.auth.transport.requests.Request()
    token = google_id_token.fetch_id_token(request, audience)

    sts = boto3.client("sts", region_name=os.environ["AWS_REGION"])
    assumed = sts.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=f"analytics-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}",
        WebIdentityToken=token,
        # One hour, matching the role's max_session_duration. The job runs
        # in minutes; this is the floor AWS permits, not a target.
        DurationSeconds=3600,
    )["Credentials"]

    return boto3.Session(
        aws_access_key_id=assumed["AccessKeyId"],
        aws_secret_access_key=assumed["SecretAccessKey"],
        aws_session_token=assumed["SessionToken"],
        region_name=os.environ["AWS_REGION"],
    )


def fetch_extracts(session: boto3.Session, bucket: str) -> list[dict]:
    """Read every extract object under the measurements prefix.

    The whole prefix each run rather than a watermark. The objects expire
    after thirty days on the AWS side, so the volume is bounded, and the
    MERGE downstream makes re-reading harmless. A watermark would need
    durable state this job does not have -- it starts cold every time.
    """
    s3 = session.client("s3")
    records: list[dict] = []
    seen_objects = 0

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix="measurements/"):
        for obj in page.get("Contents", []):
            seen_objects += 1
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            for line in body.decode("utf-8").splitlines():
                if line.strip():
                    records.append(json.loads(line))

    LOG.info("read %d records from %d objects", len(records), seen_objects)
    return records


def land(records: list[dict], bucket_name: str) -> str:
    """Write the combined extract into the GCS landing zone.

    KSI-RPL-RRO records this as regenerable: it is never the only copy of
    anything, because the source rows are still in the AWS database and the
    pipeline can be re-run.
    """
    now = datetime.now(timezone.utc)
    blob_name = f"measurements/dt={now:%Y-%m-%d}/load-{now:%Y%m%dT%H%M%SZ}.ndjson"

    client = storage.Client()
    blob = client.bucket(bucket_name).blob(blob_name)
    blob.upload_from_string(
        "\n".join(json.dumps(r) for r in records),
        content_type="application/x-ndjson",
    )

    LOG.info("landed %d records at gs://%s/%s", len(records), bucket_name, blob_name)
    return f"gs://{bucket_name}/{blob_name}"


def load(uri: str, project: str, dataset: str, table: str, kms_key: str) -> int:
    """Load the landed file, then merge it into the target table.

    Two steps rather than one. A direct append would duplicate every row
    that appeared in more than one AWS extract, and the overlapping extract
    window guarantees that happens. Staging plus MERGE on the source
    primary key makes the pipeline idempotent: running it twice over the
    same data produces the same table.
    """
    client = bigquery.Client(project=project)
    staging_id = f"{project}.{dataset}.{table}_staging"

    job = client.load_table_from_uri(
        uri,
        staging_id,
        job_config=bigquery.LoadJobConfig(
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,
            autodetect=False,
            schema=[
                bigquery.SchemaField("id", "INTEGER", mode="REQUIRED"),
                bigquery.SchemaField("customer", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("metric", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("value", "NUMERIC", mode="REQUIRED"),
                bigquery.SchemaField("recorded_at", "TIMESTAMP", mode="REQUIRED"),
            ],
            destination_encryption_configuration=bigquery.EncryptionConfiguration(
                kms_key_name=kms_key
            ),
        ),
    )
    job.result()

    merge = client.query(
        f"""
        MERGE `{project}.{dataset}.{table}` AS target
        USING `{staging_id}` AS source
        ON target.id = source.id
        WHEN NOT MATCHED THEN
          INSERT (id, customer, metric, value, recorded_at)
          VALUES (source.id, source.customer, source.metric, source.value, source.recorded_at)
        """
    )
    merge.result()

    inserted = merge.num_dml_affected_rows or 0
    LOG.info("merged %d new rows into %s.%s", inserted, dataset, table)

    client.delete_table(staging_id, not_found_ok=True)
    return inserted


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    project = os.environ["GCP_PROJECT"]
    landing_bucket = os.environ["LANDING_BUCKET"]
    dataset = os.environ["BQ_DATASET"]
    table = os.environ["BQ_TABLE"]
    kms_key = os.environ["KMS_KEY"]
    extract_bucket = os.environ["AWS_EXTRACT_BUCKET"]

    LOG.info("pipeline starting, source s3://%s", extract_bucket)

    records = fetch_extracts(aws_session(), extract_bucket)

    if not records:
        # Recorded rather than passed over. KSI-MLA-RVL's position is that
        # absence of a finding is only evidence if the looking was
        # recorded, and a pipeline that logs nothing on an empty run
        # produces no evidence it ran.
        LOG.info("no extracts found, nothing loaded")
        return

    uri = land(records, landing_bucket)
    inserted = load(uri, project, dataset, table, kms_key)

    LOG.info(
        "pipeline complete: %d records read, %d new rows merged", len(records), inserted
    )


if __name__ == "__main__":
    main()
