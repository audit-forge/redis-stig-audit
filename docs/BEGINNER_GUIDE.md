# Redis Audit Guide — Explained as Simply as Possible

This guide is written for someone who wants very direct instructions.

You do **not** need to be an expert.

---

## What you are doing

You are running a tool that checks whether Redis is set up safely.

Think of it like this:
- Redis = the thing you want to inspect
- `redis-stig-audit` = the inspector
- output report = the scorecard

---

## Step 1: download the tool

Open Terminal and type:

```bash
git clone https://github.com/audit-forge/redis-stig-audit.git
cd redis-stig-audit
```

---

## Step 2: make sure Python works

Type:

```bash
python3 --version
```

If you see a Python version, that part is fine.

Then type:

```bash
python3 audit.py --version
```

---

## Step 3: choose what kind of Redis you have

You have 3 main choices.

### Choice A: Redis is running in Docker

First, find the container name:

```bash
docker ps --format '{{.Names}}'
```

Then run the audit:

```bash
python3 audit.py --mode docker --container redis
```

If your container is named something else, replace `redis` with the real name.

---

### Choice B: Redis is running in Kubernetes

First, find the pod name:

```bash
kubectl get pods -n default
```

Then run the audit:

```bash
python3 audit.py --mode kubectl --pod redis-0 --namespace default
```

If your pod or namespace is different, change those values.

---

### Choice C: Redis is reachable by IP address and port

Run:

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 6379
```

If Redis is somewhere else, replace the IP address.

Example:

```bash
python3 audit.py --mode direct --host 10.0.0.15 --port 6379
```

---

## Step 4: understand the results

You will see things like:
- `PASS`
- `FAIL`
- `WARN`

What they mean:
- `PASS` = good
- `FAIL` = bad, needs fixing
- `WARN` = maybe okay, maybe risky, look at it

---

## Step 5: save the results to files

If you want files you can keep, share, or upload:

```bash
python3 audit.py --mode docker --container redis \
  --json results.json \
  --sarif results.sarif \
  --csv results.csv \
  --bundle audit-bundle.zip
```

That creates:
- `results.json`
- `results.sarif`
- `results.csv`
- `audit-bundle.zip`

---

## Step 6: if Redis needs a password

Type this first:

```bash
export REDISCLI_AUTH='your-password'
```

Then run the normal command.

Example:

```bash
export REDISCLI_AUTH='your-password'
python3 audit.py --mode direct --host 127.0.0.1 --port 6379
```

---

## Step 7: easiest way to test the tool itself

If you just want to make sure the tool works, use the built-in test setup:

```bash
make fixtures-up
make fixture-audit-all
make fixtures-down
```

This starts test Redis containers, audits them, and stops them.

---

## If something goes wrong

### Docker version fails

Check if Redis is running:

```bash
docker ps
```

### Kubernetes version fails

Check if the pod exists:

```bash
kubectl get pods -n default
```

### Direct version fails

See if Redis answers at all:

```bash
redis-cli -h 127.0.0.1 -p 6379 ping
```

### Password problems

Set the password first:

```bash
export REDISCLI_AUTH='your-password'
```

---

## Short version

If someone says, “just tell me what to type,” give them this.

### Docker

```bash
git clone https://github.com/audit-forge/redis-stig-audit.git
cd redis-stig-audit
python3 audit.py --mode docker --container redis
```

### Docker with files saved

```bash
git clone https://github.com/audit-forge/redis-stig-audit.git
cd redis-stig-audit
python3 audit.py --mode docker --container redis \
  --json results.json \
  --csv results.csv \
  --bundle audit-bundle.zip
```

### Built-in self-test

```bash
git clone https://github.com/audit-forge/redis-stig-audit.git
cd redis-stig-audit
make fixtures-up
make fixture-audit-all
make fixtures-down
```

---

## One-sentence explanation

Clone the repo, point the tool at your Redis server, run one command, and read the `PASS` / `FAIL` / `WARN` report.
