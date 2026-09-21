# app

The application the assessment is about.

Two services, deliberately small but real. They exist because several
determinations need something genuine to point at, not because the product
itself matters:

- **KSI-SVC-VRI** validates integrity against image digests, which requires
  images built from real source rather than a stock upstream image.
- **KSI-SCR-MON** monitors dependencies for vulnerabilities, which requires a
  real dependency manifest with real transitive dependencies.
- **KSI-CMT-RMV** claims components are replaced rather than patched, which is
  only demonstrable if there is a build to replace them from.
- **KSI-CNA-MAT** claims lateral movement is limited by per-service
  segmentation, which needs two services that are genuinely distinct.

| Service | Ingress | What it does |
|---|---|---|
| `api` | ALB, HTTPS | Records and reads synthetic customer measurements in Postgres |
| `worker` | None | Periodically extracts recent rows to S3 for the GCP analytics pipeline |
| `analytics` | None | Runs on GCP. Reads those extracts across clouds, loads BigQuery |

`analytics` runs on the other cloud entirely and shares no code with the other
two — it never touches the application database, so it carries neither
`common/db.py` nor the RDS certificate authority.

The two AWS services never talk to each other. That is the point: MAT's segmentation claim
is tested by confirming a connection between them fails.

**The worker's landings are at-least-once.** Its extract window is wider than
its interval so that no row is missed, which means rows in the overlap land
twice. The analytics side deduplicates on `id`. This is stated here because it
is a contract between the two clouds, not an implementation detail of one.

## Constraints both services are built to

These come from the design matrix, not from preference.

**No password authentication to the database.** KSI-SVC-VCM requires RDS IAM
authentication, so both services mint a short-lived IAM auth token at connect
time. Neither holds a database password, and the application user has password
authentication disabled server-side.

**TLS continues to the task.** KSI-SVC-SIN requires TLS not be terminated at
the load balancer, so `api` serves HTTPS itself. The certificate is fetched from
Secrets Manager at startup and written to the task's ephemeral storage, never
baked into the image. That storage is encrypted at rest and dies with the task.
It is not tmpfs — Fargate does not support tmpfs mounts.

**Read-only root filesystem, non-root user.** KSI-CNA-MAT's container hardening
row. Anything either service writes goes to the writable mount at `/tmp`.

**Explicitly declared everything.** KSI-CNA-DFP requires command, entrypoint,
user and ports be stated rather than inherited, so the Dockerfiles set them and
the task definitions restate them.

## Dependencies

`requirements.txt` in each service pins exact versions with hashes.
KSI-SVC-VRI's build row requires lockfiles with hashes and a build that fails on
mismatch, which is what `--require-hashes` in the Dockerfile gives.

## Running locally

Neither service runs usefully without AWS credentials and a reachable database,
because both authenticate with IAM rather than a password. The realistic local
check is a build:

```sh
docker build -t ksi-api app/api
docker build -t ksi-worker app/worker
```
