# Redis v1.0 Release Boundary

Status: draft-in-progress
Last updated: 2026-03-25

## Purpose

This document freezes what counts as **done for v1.0** versus what is intentionally deferred to later versions.

## Evidence confirmed for v1.0 baseline

### Validation completed
- Unit test suite passes via `make test`
- Live Docker fixture validation completed via `make fixture-audit-all`
- Validated fixture outcomes:
  - `baseline` → PASS 9 / FAIL 6 / WARN 5
  - `vulnerable` → PASS 7 / FAIL 7 / WARN 6
  - `hardened` → PASS 18 / FAIL 0 / WARN 2

### Confirmed v1.0 characteristics
- Runtime audit CLI exists and executes successfully
- Docker fixture set demonstrates materially different security postures
- Output artifacts are produced for fixture runs under `output/fixtures/`
- Hardened fixture readiness/auth bug in `test/run_fixtures.sh` was fixed before this boundary freeze work

## v1.0 Done Boundary

For v1.0, the project is considered complete when all of the following are true:
1. Validation results above are recorded in repo docs
2. README/test docs match actual supported workflow and outputs
3. v1.0 scope is explicitly frozen in writing
4. Non-blocking expansion items are moved to a v1.1+ backlog
5. Release/pilot handoff path is written down

## In scope for v1.0
- Redis OSS container audit workflow
- Docker, Kubernetes, and direct connection execution modes already documented by the tool
- Core checks already implemented across auth, ACL posture, TLS visibility, persistence/runtime posture, and container hardening
- Output artifacts already implemented: terminal, JSON, CSV, SARIF, evidence bundle
- Repeatable Docker fixture validation workflow

## Explicitly out of scope for v1.0
- Full production-topology coverage for Sentinel / Cluster edge cases
- Managed-service-specific logic
- Broad packaging/distribution polish beyond current documented usage
- Any claim of official CIS endorsement or certification
- TLS-enabled fixture coverage beyond the current warning-state validation approach

## Known non-blocking warnings in validated v1.0 baseline
- The hardened fixture still emits TLS-related warnings because TLS is intentionally not enabled in the lightweight fixture environment
- Fixture validation demonstrates repeatable posture differences; it does not claim exhaustive production-environment coverage

## Candidate v1.1+ backlog
- Deeper Sentinel / Cluster / replication topology-aware checks
- Managed service nuance where support is intentionally added later
- Packaging/install polish
- Broader fixture coverage, including optional TLS-enabled scenarios
- Additional downstream platform integrations or packaging hardening not required for v1.0

## Release / pilot path
- Present v1.0 as a validated community-draft benchmark + runtime audit prototype for pilot users
- Keep positioning conservative: useful, tested, evidence-oriented, but not marketed as formally certified guidance
- Use pilot feedback to prioritize v1.1 backlog instead of expanding v1.0 scope
