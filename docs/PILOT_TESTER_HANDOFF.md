# Pilot Tester Handoff

Hey — I have a Redis security audit tool ready for pilot testing.

It is called `redis-stig-audit`.

This version should be described as a **validated v1.0 community-draft benchmark + runtime audit prototype** for Redis in containerized environments.

## What it does

It checks Redis security posture across:
- authentication and ACL posture
- network exposure and bind configuration
- TLS visibility
- persistence and logging posture
- container runtime hardening

It supports:
- Docker
- Kubernetes
- direct TCP connections

It can produce:
- terminal output
- JSON
- CSV
- SARIF
- evidence bundle ZIP output

## Validation completed

- unit tests passed
- repeatable Docker fixture validation passed
- v1.0 boundary is frozen in `docs/V1_RELEASE_BOUNDARY.md`

## Important positioning note

This is **not** an officially certified CIS, DISA, or NIST product.
It should be treated as a practical pilot tool for testing, feedback, and early operational use.

## What feedback is most helpful

Please focus feedback on:
- setup clarity
- ease of running the commands
- whether the output is useful
- confusing findings or false positives
- what would make it easier to use in real environments

## Useful docs for testers

- `docs/QUICKSTART.md`
- `docs/MIDDLE_SCHOOL_GUIDE.md`
- `docs/RUN_BENCHMARK.md`
- `docs/V1_RELEASE_BOUNDARY.md`
