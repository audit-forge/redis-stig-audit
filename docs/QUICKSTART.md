# QuickStart

This guide is the fastest, easiest way to run `redis-stig-audit`.

If you do not want to read a bunch of docs, start here.

---

## What this tool does

`redis-stig-audit` checks whether a Redis deployment looks secure or risky.

It gives you a report with results like:
- `PASS` = looks good
- `FAIL` = needs fixing
- `WARN` = pay attention

---

## What you need first

You need:
- `python3`
- the `redis-stig-audit` repo
- a Redis target to test

Your Redis target can be one of these:
- a Docker container
- a Kubernetes pod
- a Redis server reachable by host + port

---

## Copy/paste setup

```bash
git clone https://github.com/audit-forge/redis-stig-audit.git
cd redis-stig-audit
python3 --version
python3 audit.py --version
```

If those commands run, you are ready.

---

## Fastest possible commands

### Docker

```bash
python3 audit.py --mode docker --container redis
```

### Kubernetes

```bash
python3 audit.py --mode kubectl --pod redis-0 --namespace default
```

### Direct host/port

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 6379
```

---

## Save the results to files

If you want files you can keep or send to someone:

### Docker example

```bash
python3 audit.py --mode docker --container redis \
  --json results.json \
  --sarif results.sarif \
  --csv results.csv \
  --bundle audit-bundle.zip
```

### Direct-mode example

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 6379 \
  --json results.json \
  --sarif results.sarif \
  --csv results.csv \
  --bundle audit-bundle.zip
```

Files created:
- `results.json` = full results
- `results.sarif` = security-platform format
- `results.csv` = spreadsheet format
- `audit-bundle.zip` = evidence package

---

## If Redis needs a password

Set the password first:

```bash
export REDISCLI_AUTH='your-password-here'
```

Then run the audit command.

Example:

```bash
export REDISCLI_AUTH='your-password-here'
python3 audit.py --mode direct --host 127.0.0.1 --port 6379
```

You can also pass a password directly:

```bash
python3 audit.py --mode docker --container redis --password 'your-password-here'
```

---

## If you need the Docker container name

Run:

```bash
docker ps --format '{{.Names}}'
```

Then use the right name in the command.

Example:

```bash
python3 audit.py --mode docker --container my-redis
```

---

## If you need the Kubernetes pod name

Run:

```bash
kubectl get pods -n default
```

Then use the right pod name in the command.

Example:

```bash
python3 audit.py --mode kubectl --pod redis-0 --namespace default
```

---

## Easiest self-test

If you want to prove the tool works before using it on a real Redis server, run the built-in fixtures:

```bash
make fixtures-up
make fixture-audit-all
make fixtures-down
```

This will:
1. start test Redis containers
2. run the audit against them
3. write output to `output/fixtures/`
4. stop the test containers

---

## Super simple troubleshooting

### Docker command fails

Check whether the container is running:

```bash
docker ps
```

### Kubernetes command fails

Check whether the pod exists:

```bash
kubectl get pods -n default
```

### Direct mode fails

Check whether Redis responds:

```bash
redis-cli -h 127.0.0.1 -p 6379 ping
```

### Password-protected Redis fails

Make sure you set:

```bash
export REDISCLI_AUTH='your-password'
```

---

## If you only want one command to remember

Use this idea:

```bash
python3 audit.py --mode <docker|kubectl|direct> ...
```

You pick the mode, point it at Redis, and read the report.

---

## Where to go next

- `docs/MIDDLE_SCHOOL_GUIDE.md` — ultra-simple step-by-step instructions
- `docs/RUN_BENCHMARK.md` — fuller operator guide
- `test/README.md` — fixture testing flow
- `docs/V1_RELEASE_BOUNDARY.md` — current v1.0 scope and positioning
