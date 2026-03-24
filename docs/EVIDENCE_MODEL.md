# Evidence Model — redis-stig-audit

## Goal

Produce outputs that can support recurring assessment workflows, including annual security reviews in regulated environments.

This evidence model is built with certification-readiness in mind and is intended to support future certification-oriented review, while making no claim of CIS certification or endorsement.

## Current Result Document Structure

Each JSON result document now includes:
- `schema_version`
- `tool`
- `target`
- `summary`
- `snapshot`
- `results`

## Required Finding Fields

Each finding should include:
- `check_id`
- `benchmark_control_id`
- `title`
- `status`
- `severity`
- `category`
- `fedramp_control`
- `nist_800_53_controls`
- `description`
- `rationale`
- `actual`
- `expected`
- `remediation`
- `references`
- `evidence_type`
- `evidence`

## Evidence Item Shape

Each evidence item should capture:
- `source` — normalized internal source name such as `config.bind` or `info.replication.role`
- `value` — raw or normalized observation
- `command` — collection command used, when applicable

This supports two different readers:
1. engineers who need the raw technical observation
2. assessors who need traceability for how that observation was derived

## Snapshot Model

The top-level `snapshot` is intended to preserve supporting context, not just individual pass/fail outputs. It currently captures:
- selected `CONFIG GET` values
- `ACL LIST`
- `INFO server`
- `INFO replication`
- `INFO persistence`
- command log tail
- last execution error

## Evidence Types

- `runtime-config`
- `container-runtime`
- `network-exposure`
- `manual-review`
- `deployment-manifest`
- `image-supply-chain`

## Assessment Warning

Absence of an automated finding must not be interpreted as control satisfaction unless the relevant benchmark control explicitly defines the automated evidence as sufficient.

## Near-Term Gaps

Still planned:
- separate evidence bundle export
- signed/hashed evidence packaging
- manifest/runtime split for container controls
- clearer distinction between automated sufficiency vs manual-review-required controls
