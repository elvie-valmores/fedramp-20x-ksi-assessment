# The api service image.
#
# Build context is app/, not app/api/, because both services share
# common/db.py. Build with:
#   docker build -f app/api/Dockerfile -t ksi-api app/
#
# The base image is pinned by digest rather than tag. KSI-SVC-VRI's position
# is that a tag is a mutable pointer and tells you nothing about what you
# actually built on; the digest is the artifact. This is the multi-arch
# manifest list digest for python:3.12-slim-bookworm, so it still resolves
# per platform.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS builder

WORKDIR /build

COPY api/requirements.txt ./requirements.txt

# --require-hashes is the half that matters. Without it the pinned versions
# are a convention; with it, a substituted artifact fails the build rather
# than shipping. KSI-SVC-VRI's build row asks for exactly this.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt


FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

# A real uid rather than a name resolved at runtime, so the task definition
# can state the same number and the two declarations can be compared.
# KSI-CNA-DFP: declared, not inherited.
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

# The RDS certificate authority, vendored into the repository rather than
# fetched at build time. A build-time download makes the image depend on a
# remote endpoint being up and honest at the moment of the build, which is
# the supply chain exposure KSI-SCR-MIT is about.
COPY common/rds-ca-bundle.pem /etc/ssl/rds/rds-ca-bundle.pem

WORKDIR /srv
COPY common/ ./common/
COPY api/main.py api/migrate.py ./

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001

# Declared, though the task definition restates it. The two being stated in
# both places is what makes the KSI-CNA-DFP check -- running container
# configuration matches the declared task definition -- something that can
# actually disagree and be caught.
EXPOSE 8443

# Exec form, no shell. A shell wrapper means PID 1 is the shell, SIGTERM
# goes to it rather than the application, and ECS ends up killing tasks it
# asked politely to stop.
ENTRYPOINT ["python"]
CMD ["main.py"]
