# syntax=docker/dockerfile:1
#
# Hardened version of the Task 2 assessment Dockerfile.
# Findings referenced below (D-n) are described in ../README.md.
#
# Build from the application directory (BuildKit is required for --chmod):
#   docker build -f <path-to>/Dockerfile -t app:local <app-dir>
# BuildKit automatically applies Dockerfile.dockerignore from this directory.
#
# No secrets are stored in the image (D-1). Provide them at runtime from a
# secret store, e.g. ECS task secrets from AWS Secrets Manager, Kubernetes
# Secrets, or `docker run --env-file <untracked file>` for local use only.

# D-3, D-6: maintained, minimal base image instead of EOL ubuntu:18.04. The
# official Python image already contains python3 and pip, so no apt packages
# are installed. Pinned by multi-arch index digest (resolved from Docker Hub
# on 2026-11-02) for reproducible builds; update it with Dependabot/Renovate.
FROM python:3.13-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1

# Do not write .pyc files at runtime (works with a read-only root filesystem)
# and send logs straight to stdout/stderr.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# D-2: dedicated unprivileged user with fixed numeric IDs, no home directory
# and no login shell.
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app \
      --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin app

WORKDIR /app

# D-4, D-5: application files are owned by root and are read-only for the
# runtime user (0755: owner rwx, everyone else r-x; directories need x).
# Dockerfile.dockerignore keeps .git, .env files and keys out of the context.
COPY --chown=root:root --chmod=0755 . /app

# Numeric UID:GID so that Kubernetes runAsNonRoot can verify it.
USER 10001:10001

# Kept from the original. Binding to port 80 as non-root works on Docker Engine
# 20.10+ (unprivileged port sysctl). On other runtimes, see README (D-10).
EXPOSE 80

# D-8: exec form, so python3 is PID 1 and receives SIGTERM directly.
CMD ["python3", "app.py"]

# D-9 (accepted, documented): no HEALTHCHECK, because the brief defines no
# health endpoint and adding one would assume an application feature. Use
# orchestrator probes once an endpoint exists.
# checkov:skip=CKV_DOCKER_2:No health endpoint is defined for app.py (finding D-9)
