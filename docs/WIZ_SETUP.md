# Using redis-stig-audit with Wiz

This document explains the **Wiz-facing workflow** for `redis-stig-audit`.

It is intentionally explicit about current capability:

- `redis-stig-audit` currently produces **JSON**, **SARIF**, and **evidence bundles**
- the repo includes a **Rego placeholder** at `rego/redis_audit.rego`
- the Redis repo does **not yet include the same native Wiz push tooling** that exists in `pg-stig-audit`

So today, the practical Wiz workflow is:
1. run the Redis benchmark
2. generate artifacts
3. use those artifacts in your Wiz workflow/process
4. optionally evolve the Rego path later into a full Custom Control integration

This keeps the workflow honest without pretending there is already a Redis-specific Wiz uploader in this repo.

---

## Current supported Wiz-oriented outputs

### 1) SARIF (`--sarif`)
Use this for platforms and workflows that consume SARIF or forward SARIF into downstream security tooling.

### 2) JSON (`--json`)
Use this as the canonical raw findings document for internal transformations or later API integrations.

### 3) Evidence bundle (`--bundle`)
Use this for review packs, regulated evidence collection, and human validation alongside Wiz records.

### 4) Rego placeholder (`rego/redis_audit.rego`)
Use this as the starting point for a future Wiz Custom Control / policy-as-code path.

---

## Recommended current workflow with Wiz

## Step 1 — run the Redis benchmark

Example (Docker target):

```bash
mkdir -p output
python3 audit.py --mode docker --container redis \
  --json output/results.json \
  --sarif output/results.sarif \
  --bundle output/audit-bundle.zip
```

Example (Kubernetes target):

```bash
mkdir -p output
python3 audit.py --mode kubectl --pod redis-0 --namespace default \
  --json output/results.json \
  --sarif output/results.sarif \
  --bundle output/audit-bundle.zip
```

---

## Step 2 — decide your Wiz operating pattern

There are two realistic patterns today.

### Pattern A — findings/evidence companion workflow
Use `redis-stig-audit` as the benchmark engine and keep Wiz as the risk-management / triage / governance layer.

In this pattern:
- `results.json` is your source-of-truth output
- `results.sarif` is your structured interchange artifact
- `audit-bundle.zip` is your reviewer/evidence package
- Wiz tracks the affected resource/risk context through your existing internal process

This is the safest current recommendation because it matches the repo’s actual capabilities.

### Pattern B — future Custom Control / policy workflow
Use the Redis benchmark controls and the placeholder Rego policy as the seed for a Wiz Custom Control implementation.

This is **not fully productized in this repo yet**, but the expected direction is:
- map Redis benchmark controls to a stable resource/data model
- convert the placeholder Rego into enforceable policy logic
- register/test the control in Wiz

---

## What to store alongside Wiz records

For each assessment run, preserve:
- target name / resource identifier
- execution timestamp
- `results.json`
- `results.sarif`
- `audit-bundle.zip`
- benchmark version used
- reviewer/runner identity

This gives you durable evidence even before a native Redis→Wiz push path exists.

---

## Suggested operational process

### Option 1 — manual review workflow
1. Run `redis-stig-audit`
2. Review `summary.txt` and terminal findings
3. Use `results.json` and `audit-bundle.zip` as assessment evidence
4. Record or correlate findings in Wiz according to your internal process

### Option 2 — SARIF-centric workflow
1. Run `redis-stig-audit --sarif ...`
2. Store SARIF as a pipeline artifact
3. Feed SARIF into the broader security workflow that ultimately informs Wiz operations
4. Keep the bundle as the audit evidence package

### Option 3 — future policy-as-code workflow
1. Start from `rego/redis_audit.rego`
2. expand it from placeholder to real Redis benchmark logic
3. validate mappings against Wiz Custom Control requirements
4. register and test in Wiz

---

## Important limitation

If you need an immediate, first-class **native Wiz upload/push script** like the PostgreSQL project has, that still needs to be implemented for Redis.

Today’s Redis repo is ready for:
- benchmark execution
- machine-readable output
- SARIF generation
- evidence packaging

It is **not yet ready to claim built-in Wiz API push support**.

---

## Example operator command set

### Docker example

```bash
mkdir -p output
python3 audit.py --mode docker --container redis \
  --json output/results.json \
  --sarif output/results.sarif \
  --bundle output/audit-bundle.zip
```

### Kubernetes example

```bash
mkdir -p output
python3 audit.py --mode kubectl --pod redis-0 --namespace default \
  --json output/results.json \
  --sarif output/results.sarif \
  --bundle output/audit-bundle.zip
```

### Direct example

```bash
mkdir -p output
python3 audit.py --mode direct --host 127.0.0.1 --port 6379 \
  --json output/results.json \
  --sarif output/results.sarif \
  --bundle output/audit-bundle.zip
```

---

## How this relates to PostgreSQL

`pg-stig-audit` already contains explicit Wiz-oriented tooling and docs.

For Redis, this document establishes the current honest state and the operator workflow to use today.
If desired, the next engineering step after documentation would be to build:
- Redis-specific Wiz issue payload generation
- Redis-specific push tooling
- a real Redis Rego control for Wiz Custom Controls

---

## Related docs

- `README.md`
- `docs/RUN_BENCHMARK.md`
- `docs/ASSESSOR_GUIDE.md`
- `docs/EVIDENCE_MODEL.md`
- `rego/redis_audit.rego`
