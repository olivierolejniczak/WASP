# WASP — Quick How-To Guide

Five common tasks, each under 10 lines.

---

## 1. Scan OWASP Juice Shop (the standard use case)

```bash
cd /home/dietpi/wasp
source .venv/bin/activate

# Start Juice Shop if not already running
docker run -d -p 3002:3000 bkimminich/juice-shop

# Run the scan — takes ~5–10 minutes
python wasp.py scan http://localhost:3002

# Report is in the current directory
ls wasp-*.md
```

---

## 2. Use a better model for one scan

```bash
# Pull the model first (one-time, ~1 GB)
ollama pull qwen3:1.7b

# Use it for this scan only
python wasp.py scan http://localhost:3002 --model qwen3:1.7b

# Or set it permanently in config.yaml:
# orchestrator:
#   model: "qwen3:1.7b"
```

---

## 3. Quick triage — 5 minutes, 3 hypotheses

```bash
python wasp.py scan http://target.local --budget 5
```

WASP will run recon, plan, then probe as many hypotheses as fit in 5 minutes. Report is written from whatever was found.

---

## 3b. Authenticated Active Directory scan (BloodHound, pivot check)

```bash
python wasp.py scan 192.168.1.10 --type activedir \
    --domain-user svc_pentest --domain-pass 'P@ssw0rd!'
```

Creds are only ever used server-side (BloodHound collection, SMB enum,
`crackmapexec` pivot check) — never sent to the LLM.

---

## 4. See what WASP plans without running any probes

```bash
python wasp.py scan http://localhost:3002 --dry-run --verbose
```

Output shows the recon facts and the 6 hypotheses with rationale. Nothing is sent to the target beyond the recon phase. Useful for checking that WASP understood the target correctly before committing to a full scan.

---

## 5. Save reports to a dedicated folder

```bash
mkdir -p ~/pentest-reports
python wasp.py scan http://target.local --output ~/pentest-reports/

# All reports accumulate there, never overwriting each other:
ls ~/pentest-reports/
# wasp-20260904-172014-http-target-local.md
# wasp-20260905-090312-http-target-local.md
```

---

## Check your setup at any time

```bash
python wasp.py doctor     # Ollama + tools + Python deps
python wasp.py models     # What models are available
python wasp.py version    # WASP version
```
