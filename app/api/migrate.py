"""Schema and database-role setup, run as a one-off task.

This ships inside the `api` image but is never the command the service runs.
It exists as a separate entry point because it needs privileges the services
must not hold: creating roles and altering tables is exactly what a
compromised request handler should be unable to do.

It runs as the RDS master user, whose password is generated and held by RDS
in Secrets Manager and never seen by this project. The services themselves
authenticate with IAM and hold no password at all -- this is the one place a
password is used, and it is used to make that arrangement possible.

Idempotent by construction: every statement is guarded, so re-running on
every apply is a no-op once the schema is current.
"""

import json
import logging
import os

import boto3
import psycopg

LOG = logging.getLogger("migrate")

RDS_CA_BUNDLE = "/etc/ssl/rds/rds-ca-bundle.pem"

# Ordered. Each is safe to re-run.
STATEMENTS = [
    # The one application table. Synthetic customer data, as recorded in
    # the design matrix's environment section.
    """
    CREATE TABLE IF NOT EXISTS measurements (
        id          BIGSERIAL PRIMARY KEY,
        customer    TEXT        NOT NULL,
        metric      TEXT        NOT NULL,
        value       NUMERIC     NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    # The worker reads by time window and the api reads by customer.
    """
    CREATE INDEX IF NOT EXISTS measurements_recorded_at_idx
        ON measurements (recorded_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS measurements_customer_recorded_at_idx
        ON measurements (customer, recorded_at DESC)
    """,
]


def role_statements(api_user: str, worker_user: str) -> list[str]:
    """Create the two application roles with IAM authentication only.

    Two roles rather than one shared role: KSI-CNA-MAT's identity surface is
    what a compromised resource reaches with the credentials it holds, and a
    shared database role means compromising the worker yields the api's
    write access to every table.

    `rds_iam` is what disables password authentication for these roles --
    granting it means RDS will only accept an IAM auth token, so there is no
    password to guess, and none to rotate.
    """
    return [
        # DO blocks because CREATE ROLE has no IF NOT EXISTS.
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{api_user}') THEN
                CREATE ROLE {api_user} WITH LOGIN;
            END IF;
        END
        $$
        """,
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{worker_user}') THEN
                CREATE ROLE {worker_user} WITH LOGIN;
            END IF;
        END
        $$
        """,
        f"GRANT rds_iam TO {api_user}",
        f"GRANT rds_iam TO {worker_user}",
        # The api writes and reads its own table and nothing else.
        f"GRANT CONNECT ON DATABASE {os.environ['DB_NAME']} TO {api_user}",
        f"GRANT USAGE ON SCHEMA public TO {api_user}",
        f"GRANT SELECT, INSERT ON measurements TO {api_user}",
        f"GRANT USAGE, SELECT ON SEQUENCE measurements_id_seq TO {api_user}",
        # The worker only ever reads. It has no INSERT anywhere, so a
        # compromised extract path cannot write customer data.
        f"GRANT CONNECT ON DATABASE {os.environ['DB_NAME']} TO {worker_user}",
        f"GRANT USAGE ON SCHEMA public TO {worker_user}",
        f"GRANT SELECT ON measurements TO {worker_user}",
        # Neither role may create anything. Postgres grants CREATE on the
        # public schema to PUBLIC by default on older versions, which is
        # functionality arriving by default rather than by declaration --
        # the exact thing KSI-CNA-DFP is written to catch.
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
    ]


def master_credentials() -> dict:
    """Read the RDS-managed master password out of Secrets Manager."""
    secret_arn = os.environ["MASTER_SECRET_ARN"]
    client = boto3.client("secretsmanager", region_name=os.environ["AWS_REGION"])
    return json.loads(client.get_secret_value(SecretId=secret_arn)["SecretString"])


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    credentials = master_credentials()

    conn = psycopg.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        dbname=os.environ["DB_NAME"],
        user=credentials["username"],
        password=credentials["password"],
        sslmode="verify-full",
        sslrootcert=RDS_CA_BUNDLE,
        connect_timeout=int(os.environ.get("DB_CONNECT_TIMEOUT", "10")),
        autocommit=True,
    )

    statements = STATEMENTS + role_statements(
        os.environ["API_DB_USER"], os.environ["WORKER_DB_USER"]
    )

    try:
        for statement in statements:
            LOG.info("applying: %s", " ".join(statement.split())[:80])
            conn.execute(statement)
    finally:
        conn.close()

    LOG.info("migration complete, %d statements applied", len(statements))


if __name__ == "__main__":
    main()
