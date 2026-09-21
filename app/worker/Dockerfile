# The worker service image.
#
# Build context is app/, not app/worker/, because both services share
# common/db.py. Build with:
#   docker build -f app/worker/Dockerfile -t ksi-worker app/
#
# Deliberately a separate image from the api rather than one image with two
# commands. A shared image means the worker carries the api's web framework
# and server, which is attack surface it has no use for -- and KSI-CNA-MAT
# bounds minimal as no capability enabled that no declared function requires.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS builder

WORKDIR /build

COPY worker/requirements.txt ./requirements.txt

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt


FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv
COPY common/rds-ca-bundle.pem /etc/ssl/rds/rds-ca-bundle.pem

# The commit this image was built from, recorded on the image itself.
# KSI-CMT-RMV build row 4 requires every image digest be traceable to the
# commit that produced it; the pipeline also emits SLSA provenance, and this
# label is the same fact readable with a plain `docker inspect`.
ARG SOURCE_COMMIT=unknown
LABEL org.opencontainers.image.revision="$SOURCE_COMMIT" \
      org.opencontainers.image.source="https://github.com/elvie-valmores/fedramp-20x-ksi-assessment" \
      org.opencontainers.image.title="fedramp-20x-ksi-worker"

WORKDIR /srv
COPY common/ ./common/
COPY worker/main.py ./

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001

# No EXPOSE. The worker has no listener at all, and nothing in the
# architecture is permitted to connect to it.

ENTRYPOINT ["python"]
CMD ["main.py"]
