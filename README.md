# redis-stig-audit

**Redis container security benchmark and audit workflow for regulated environments**

`redis-stig-audit` is a benchmark-first project for assessing Redis deployed in containerized environments. It is intended to support internal security reviews, recurring compliance assessments, and FedRAMP-aligned annual audit evidence workflows.

## Status

Early but functional draft.

This repository currently includes:
- a CIS-style benchmark draft for Redis in containers
- an initial machine-readable control matrix
- methodology / assessor / evidence docs
- a working first-pass audit CLI with real Redis interrogation via `redis-cli`
- benchmark-aligned checks for authentication posture, ACL posture, protected mode, bind exposure, TLS visibility, replication transport posture, persistence intent, persistence runtime health, logging intent, and runtime metadata
- structured JSON output with target metadata, summary, evidence items, and runtime snapshot details

It does **not** yet claim official CIS endorsement or certification.

## Repository layout

- `benchmarks/CIS_Redis_Container_Benchmark_v1.0.md` — benchmark draft
- `audit.py` — audit CLI entrypoint
- `runner.py` — Redis interrogation helpers
- `checks/` — benchmark-aligned audit checks
- `output/` — human-readable reporting
- `mappings/control-matrix.json` — machine-readable control catalog
- `schemas/results.schema.json` — results schema draft
- `docs/` — methodology, assessor guidance, and evidence model
- `rego/` — future policy integration placeholders
- `test/` — smoke tests and future fixture guidance

## Current coverage

Current automated checks focus on:
- protected mode
- bind exposure
- TLS visibility
- plaintext listener exposure when TLS is enabled
- replication/cluster TLS posture visibility
- default-user ACL posture
- authenticated administrative access posture
- dangerous-command exposure heuristics
- persistence configuration intent
- persistence runtime health visibility
- ACL durability visibility
- logging destination / intent visibility
- runtime metadata / replication role visibility

## Usage

### Direct mode

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 6379 --json results.json
```

### Docker mode

```bash
python3 audit.py --mode docker --container redis --json results.json
```

### Kubernetes mode

```bash
python3 audit.py --mode kubectl --pod redis-0 --namespace default --json results.json
```

## Output model

Current JSON output includes:
- `schema_version`
- tool name/version metadata
- normalized target metadata
- executive summary (`status_counts`, `severity_counts`, `risk_posture`)
- runtime snapshot (`CONFIG GET`, `ACL LIST`, `INFO` sections, command log tail, last error)
- benchmark-aligned findings with evidence items and NIST/FedRAMP mappings

The terminal report now includes:
- executive summary
- top findings section
- sorted detailed findings with control mappings and evidence counts

Planned outputs:
- SARIF
- control trace matrix
- evidence summary bundle
- optional enterprise output adapters

## Validation

Run the current smoke tests:

```bash
python3 -m unittest discover -s test -p 'test_*.py'
```

## Design principles

- benchmark-first, scanner-second
- vendor-neutral language
- deterministic audit evidence where possible
- FedRAMP / NIST traceability
- public-review-friendly structure

## Near-term roadmap

1. expand the benchmark draft into fuller control coverage
2. add container-runtime and manifest-aware checks for non-root, privilege, mounts, and resource limits
3. add Docker/Kubernetes fixture environments for repeatable live validation
4. add SARIF and evidence-bundle outputs
5. prepare for public review and GitHub release
