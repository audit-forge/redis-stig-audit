# Release Summary

## redis-stig-audit v1.0 baseline frozen

This release freezes the initial v1.0 boundary for `redis-stig-audit`, a community-built Redis container security benchmark and runtime audit tool.

## What is included

- Redis audit CLI for:
  - Docker
  - Kubernetes
  - direct TCP connections
- security checks across:
  - authentication and ACL posture
  - network exposure and bind configuration
  - TLS visibility
  - persistence and logging posture
  - container hardening
- output formats:
  - terminal
  - JSON
  - CSV
  - SARIF
  - evidence bundle ZIP

## Validation

- unit test suite passed
- repeatable Docker fixture validation passed
- validated fixture outcomes are documented
- v1.0 scope is frozen in `docs/V1_RELEASE_BOUNDARY.md`

## Positioning

This release should be treated as a **validated community-draft benchmark + runtime audit prototype** suitable for pilot use and early feedback.

It is **not** an official CIS, DISA, or NIST benchmark.

## Recommended docs

- `README.md`
- `docs/QUICKSTART.md`
- `docs/BEGINNER_GUIDE.md`
- `docs/RUN_BENCHMARK.md`
- `docs/V1_RELEASE_BOUNDARY.md`
- `test/FIXTURE-STATUS.md`

## Next step

Pilot feedback should drive v1.1 improvements, especially around broader topology coverage and additional usability polish.
