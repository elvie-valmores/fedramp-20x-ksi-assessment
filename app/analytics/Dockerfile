# The analytics pipeline job image.
#
# Build context is app/, matching the other two services, though this one
# shares nothing with them: it never touches the application database, so
# it does not carry common/db.py or the RDS certificate authority.
#
#   docker build -f app/analytics/Dockerfile -t ksi-analytics app/
#
# Built for amd64 rather than arm64, unlike the ECS services. Cloud Run
# jobs run on x86 unless a specific machine type is requested, and matching
# the platform the job actually runs on costs nothing.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS builder

WORKDIR /build

COPY analytics/requirements.txt ./requirements.txt

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt


FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

ARG SOURCE_COMMIT=unknown
LABEL org.opencontainers.image.revision="$SOURCE_COMMIT" \
      org.opencontainers.image.source="https://github.com/elvie-valmores/fedramp-20x-ksi-assessment" \
      org.opencontainers.image.title="fedramp-20x-ksi-analytics"

WORKDIR /srv
COPY analytics/main.py ./

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001

# No EXPOSE. A Cloud Run *job* runs to completion and exits; it has no
# listener and receives no requests. That is what distinguishes it from a
# Cloud Run service, and it is why nothing in the architecture is permitted
# to connect to it.

ENTRYPOINT ["python"]
CMD ["main.py"]
