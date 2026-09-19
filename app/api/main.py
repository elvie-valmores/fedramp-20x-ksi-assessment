"""The public-facing service.

Records synthetic customer measurements and reads them back. The domain is
uninteresting on purpose -- what matters is that this is real code with real
dependencies, serving real TLS, authenticating to a real database without a
password.

Everything configurable arrives as an environment variable, and every one of
them is set explicitly in the task definition rather than defaulted here.
KSI-CNA-DFP treats an inherited default as an undeclared one.
"""

import json
import logging
import os
import ssl

import boto3
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from common.db import connect, DatabaseUnavailable

LOG = logging.getLogger("api")

# The writable mount. The root filesystem is read only, so this is the only
# writable path in the container and the certificate is the only thing
# written to it. On Fargate this is ephemeral storage rather than tmpfs --
# encrypted at rest and destroyed with the task, but not memory.
TLS_DIR = "/tmp/tls"

app = FastAPI(title="ksi-api", docs_url=None, redoc_url=None)


class Measurement(BaseModel):
    """One synthetic customer reading."""

    customer: str = Field(min_length=1, max_length=64)
    metric: str = Field(min_length=1, max_length=64)
    value: float


@app.get("/healthz")
def healthz() -> dict:
    """Liveness only.

    The load balancer health check points here. It deliberately does not
    touch the database: a health check that fails when the database is
    briefly unavailable causes ECS to replace tasks that are themselves
    fine, which turns a database blip into a compute outage.
    """
    return {"status": "ok"}


@app.get("/readyz")
def readyz() -> dict:
    """Readiness, including the database.

    Separate from /healthz precisely because this one is allowed to fail
    without the task being replaced.
    """
    try:
        with connect() as conn:
            conn.execute("SELECT 1")
    except DatabaseUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"status": "ready"}


@app.post("/measurements", status_code=201)
def record(measurement: Measurement) -> dict:
    try:
        with connect() as conn:
            row = conn.execute(
                """
                INSERT INTO measurements (customer, metric, value)
                VALUES (%s, %s, %s)
                RETURNING id, recorded_at
                """,
                (measurement.customer, measurement.metric, measurement.value),
            ).fetchone()
    except DatabaseUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return {"id": row[0], "recorded_at": row[1].isoformat()}


@app.get("/measurements/{customer}")
def read(customer: str, limit: int = 50) -> dict:
    if not 1 <= limit <= 500:
        raise HTTPException(status_code=400, detail="limit must be 1..500")

    try:
        with connect() as conn:
            rows = conn.execute(
                """
                SELECT metric, value, recorded_at
                FROM measurements
                WHERE customer = %s
                ORDER BY recorded_at DESC
                LIMIT %s
                """,
                (customer, limit),
            ).fetchall()
    except DatabaseUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return {
        "customer": customer,
        "measurements": [
            {"metric": r[0], "value": float(r[1]), "recorded_at": r[2].isoformat()}
            for r in rows
        ],
    }


def write_tls_material() -> tuple[str, str]:
    """Fetch the task certificate from Secrets Manager onto the writable mount.

    KSI-SVC-SIN requires TLS continue to the task rather than terminate at
    the load balancer, so the task needs a certificate and a private key.
    They live in Secrets Manager rather than the image: an image is a
    distributable artifact and a private key baked into one leaks with every
    copy of it.

    uvicorn takes file paths rather than PEM strings, so this writes them
    out. The destination is the task's ephemeral storage, which is
    encrypted at rest and destroyed when the task stops.
    """
    secret_arn = os.environ["TLS_SECRET_ARN"]
    client = boto3.client("secretsmanager", region_name=os.environ["AWS_REGION"])
    parsed = json.loads(client.get_secret_value(SecretId=secret_arn)["SecretString"])

    os.makedirs(TLS_DIR, mode=0o700, exist_ok=True)
    cert_path = os.path.join(TLS_DIR, "cert.pem")
    key_path = os.path.join(TLS_DIR, "key.pem")

    with open(cert_path, "w") as handle:
        handle.write(parsed["certificate"])
    os.chmod(cert_path, 0o600)

    with open(key_path, "w") as handle:
        handle.write(parsed["private_key"])
    os.chmod(key_path, 0o600)

    return cert_path, key_path


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    cert_path, key_path = write_tls_material()
    port = int(os.environ["PORT"])

    LOG.info("starting api on port %d with task-side TLS", port)
    uvicorn.run(
        app,
        host="0.0.0.0",  # noqa: S104 -- the task's own ENI, reachable only from the ALB's security group
        port=port,
        ssl_certfile=cert_path,
        ssl_keyfile=key_path,
        # uvicorn's default. Note what this does NOT do: it selects the
        # protocol negotiator, not a minimum version. The TLS 1.2 floor on
        # this hop comes from the base image's OpenSSL configuration
        # (Debian sets MinProtocol=TLSv1.2), which is inherited rather
        # than declared -- the one place in this service where a security
        # property rests on a default, contrary to KSI-CNA-DFP. uvicorn
        # exposes no minimum-version argument to state it explicitly.
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        access_log=True,
        server_header=False,  # KSI-CNA-MAT: no version disclosure
    )


if __name__ == "__main__":
    main()
