"""Database connections, authenticated with IAM rather than a password.

Shared by both services. KSI-SVC-VCM's build row requires RDS IAM
authentication with password authentication disabled for the application
user, which means there is no password anywhere to store, rotate or leak --
the credential is a token minted per connection and valid for fifteen
minutes.

The cost is that connections cannot be pooled across that window without
care, so this opens a connection per unit of work. At this volume that is
the right trade; at real volume it would need a pooler that re-mints.
"""

import logging
import os
from contextlib import contextmanager
from functools import lru_cache

import boto3
import psycopg

LOG = logging.getLogger("db")

# The RDS regional root certificate, mounted into the image at build time.
# Verifying it is the difference between encrypted and authenticated: without
# verification an in-path attacker terminates TLS and the client never knows.
RDS_CA_BUNDLE = "/etc/ssl/rds/rds-ca-bundle.pem"


class DatabaseUnavailable(RuntimeError):
    """Raised instead of leaking driver internals to an HTTP response.

    KSI-CNA-MAT maps SI-11, error handling and information leakage. A
    psycopg error rendered into a response body names the host, the user and
    often the query.
    """


@lru_cache(maxsize=1)
def _rds_client():
    """One client for the process.

    `connect()` runs per unit of work, which for the api is per request.
    Building a boto3 client is not cheap -- it loads and parses the service
    model -- so doing it per request would put tens of milliseconds and a
    fresh parse on every call. The client is thread-safe for this use and
    refreshes the task role's credentials itself.
    """
    return boto3.client("rds", region_name=os.environ["AWS_REGION"])


def _auth_token() -> str:
    """Mint a short-lived RDS IAM auth token for this task's role.

    Minted per connection rather than cached: the token is valid for
    fifteen minutes, and caching it would mean holding a live credential
    in process memory for the sake of saving a local signing operation
    that involves no network call at all.
    """
    return _rds_client().generate_db_auth_token(
        DBHostname=os.environ["DB_HOST"],
        Port=int(os.environ["DB_PORT"]),
        DBUsername=os.environ["DB_USER"],
        Region=os.environ["AWS_REGION"],
    )


@contextmanager
def connect():
    """Yield a connection, committing on success and rolling back on error."""
    try:
        conn = psycopg.connect(
            host=os.environ["DB_HOST"],
            port=int(os.environ["DB_PORT"]),
            dbname=os.environ["DB_NAME"],
            user=os.environ["DB_USER"],
            password=_auth_token(),
            # verify-full, not require. `require` encrypts without checking
            # who is on the other end, which rds.force_ssl also accepts --
            # so the server-side setting alone does not give authenticity.
            sslmode="verify-full",
            sslrootcert=RDS_CA_BUNDLE,
            connect_timeout=int(os.environ.get("DB_CONNECT_TIMEOUT", "5")),
            autocommit=False,
        )
    except psycopg.Error as exc:
        LOG.error("database connection failed: %s", exc.__class__.__name__)
        raise DatabaseUnavailable("database unavailable") from exc

    try:
        yield conn
        conn.commit()
    except psycopg.Error as exc:
        conn.rollback()
        LOG.error("query failed: %s", exc.__class__.__name__)
        raise DatabaseUnavailable("database error") from exc
    finally:
        conn.close()
