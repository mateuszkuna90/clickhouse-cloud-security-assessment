# =============================================================================
# INSECURE TEST FIXTURE: DO NOT BUILD OR USE.
# Verbatim copy of the Dockerfile given in the assessment brief (Task 2).
# The DB_PASSWORD / API_KEY values below are FAKE example values from the
# brief, not real credentials. Kept only as the "before" state for the review
# and as a negative test case for scanners. The hardened version is
# ../docker/Dockerfile
# =============================================================================
FROM ubuntu:18.04

USER root

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    vim \
    dnsutils

ENV DB_PASSWORD="SuperSecretPassword123!"
ENV API_KEY="prod-key-778899"

COPY . /app
RUN chmod -R 777 /app
EXPOSE 80

WORKDIR /app
CMD python3 app.py
