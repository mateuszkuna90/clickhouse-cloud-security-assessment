# Fixtures: intentionally insecure examples (DO NOT DEPLOY, BUILD OR COPY)

The `example-insecure-*` files are **intentionally insecure**. They are
verbatim copies of the inputs given in the Task 2 assessment brief, with a
warning header added. The names follow the repository's fixture convention
from `AGENTS.md`: files live in `fixtures/` and start with `example-`.

| File | Source | Secure replacement |
|---|---|---|
| `example-insecure-cloudformation.yaml` | CloudFormation template from the brief | [../cloudformation/secure-bucket.yaml](../cloudformation/secure-bucket.yaml) |
| `example-insecure.Dockerfile` | Dockerfile from the brief | [../docker/Dockerfile](../docker/Dockerfile) |

They are kept for two reasons only:

1. They are the "before" state that the review in [../README.md](../README.md) refers to.
2. They are **negative test inputs**. The tests and the example CI check that
   scanners still report the expected findings on them.

## Handling rules

- **Never deploy, build or copy them.** Copy from the remediated files instead.
- **Policy scans skip this directory, secret scans do not.** IaC and
  Dockerfile policy scans of the remediated files use `--skip-path fixtures`,
  because the policy findings here are intentional and are checked by the
  negative tests instead. **Secret scanning covers every file, including
  these.** Do not exclude this directory, these files, or a whole rule from
  secret scanning.
- **The secrets are fake.** `DB_PASSWORD` and `API_KEY` in
  `example-insecure.Dockerfile` are example values from the brief, not real
  credentials. Never replace them with real values, even for a demo.
- **Exception only for exact known values.**
  [../ci/checkov-secrets.baseline.json](../ci/checkov-secrets.baseline.json)
  exempts only the SHA-1 of the exact fake value that checkov reports
  (`CKV_SECRET_6`).
  - checkov 3.4.2 matches baseline entries by hash and check ID, not by file.
  - [../tests/known-fake-secrets.sh](../tests/known-fake-secrets.sh) therefore
    enforces that:
    1. the fake values exist only in this fixture;
    2. the fixture's values are the pinned known fakes;
    3. the baseline holds nothing but pinned fake-value hashes.
  - If another scanner reports these values, add an exception for the exact
    values only, and extend that test.
