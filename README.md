# WASP — Web Application Security Probe

> Lightweight local-AI penetration testing tool. Runs on modest hardware with a local Ollama model. Completes a meaningful scan of OWASP Juice Shop in under 15 minutes — no API keys, no cloud, no GPU required.

---

## What it does

WASP runs a structured 4-phase scan:

```
Phase 1 — Recon    httpx + nmap + gobuster in parallel   ~75s   (zero LLM calls)
Phase 2 — Plan     1 LLM call → 6 ordered hypotheses     ~3s
Phase 3 — Probe    2-turn ReAct loop per hypothesis       ~5-8m
Phase 4 — Report   1 LLM call per confirmed finding       ~15s
```

It finds vulnerabilities a local 3B model can reliably confirm in 1–2 steps:
SQL injection, IDOR, path traversal, mass assignment, JWT alg:none, and security misconfigurations.

It deliberately skips things small models fail at: multi-step UNION extraction, algorithm confusion, blind injection, and anything requiring a browser.

---

## Hardware requirements

| Component | Minimum | This machine |
|---|---|---|
| CPU | Any x86-64 | i5-9500T (6 cores) |
| RAM | 4 GB | 16 GB |
| Disk | 3 GB (model) | NVMe |
| GPU | Not required | Not used |
| Ollama | v0.3+ | Port 11435 |

---

## Quick start

```bash
# 1. Install Python deps
cd /home/dietpi/wasp
pip install -r requirements.txt

# 2. Verify setup
python wasp.py doctor

# 3. Start Juice Shop
docker run -d -p 3002:3000 bkimminich/juice-shop

# 4. Run a scan
python wasp.py scan http://localhost:3002

# 5. View the report
cat wasp-*.md
```

---

## Commands

### `scan`
```
python wasp.py scan <TARGET> [OPTIONS]

Options:
  -c, --config PATH     Config file (default: config.yaml)
  -m, --model TEXT      Override Ollama model for this run
  -b, --budget INT      Wall-clock budget in minutes (default: 14)
  -o, --output DIR      Directory for the report file (default: .)
  -v, --verbose         Show tool output and rationale in real time
  --dry-run             Plan and recon only — no probes executed
```

Examples:
```bash
# Basic scan
python wasp.py scan http://localhost:3002

# Better model (pull first: ollama pull qwen3:1.7b)
python wasp.py scan http://localhost:3002 --model qwen3:1.7b

# Tight 8-minute budget
python wasp.py scan http://localhost:3002 --budget 8

# See what it planned without running probes
python wasp.py scan http://localhost:3002 --dry-run --verbose
```

### `doctor`
Check Ollama connectivity, installed tool binaries, and Python dependencies.
```bash
python wasp.py doctor
```

### `models`
List Ollama models available on this machine with tool-calling capability flags.
```bash
python wasp.py models
```

---

## Model recommendations

| Model | Agent Score | Speed (CPU) | Notes |
|---|---|---|---|
| `llama3.2:3b` | 0.66 | ~1.7s/call | Already installed. Works well with WASP's 2-turn harness. |
| `qwen3:1.7b` | 0.96 | ~10s/call | Best judgment of any sub-4B model. Recommended upgrade. |
| `qwen2.5:1.5b` | 0.80 | ~2.2s/call | Good balance. `ollama pull qwen2.5:1.5b` |

Scores from [MikeVeerman local tool-calling benchmark 2026](https://github.com/MikeVeerman/tool-calling-benchmark).

To use a different model:
```bash
ollama pull qwen3:1.7b
python wasp.py scan http://localhost:3002 --model qwen3:1.7b
# or set model in config.yaml
```

---

## Configuration

Edit `config.yaml`. Key settings:

```yaml
orchestrator:
  model:    "llama3.2:3b"       # local model
  endpoint: "http://localhost:11435"

lite:
  wall_clock_budget_s: 840      # 14 minutes
  max_hypotheses:      6        # attack hypotheses to test
  tool_timeout_s:      45       # per-tool timeout

tools:
  sqlmap:
    technique: "B"              # boolean-only — fastest
  nuclei:
    severity: ["critical", "high"]
    rate_limit: 10
```

---

## Installed tools (optional but recommended)

WASP works with only Python installed. External tools improve coverage:

| Tool | Used for | Install |
|---|---|---|
| `nmap` | Port scan | `apt-get install nmap` |
| `gobuster` | Endpoint discovery | `apt-get install gobuster` |
| `httpx` | HTTP fingerprinting | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `sqlmap` | SQL injection | `apt-get install sqlmap` |
| `nikto` | Misconfig scan | `apt-get install nikto` |
| `nuclei` | Template scanning | https://nuclei.projectdiscovery.io |
| `crackmapexec` / `nxc` | SMB credential validation, lateral-movement check | `pipx install git+https://github.com/Pennyw0rth/NetExec` |
| `bloodhound-python` | AD attack-path collection (BloodHound ingest) | `pip install bloodhound` |
| `searchsploit` | Offline ExploitDB lookup for confirmed CVEs | `apt-get install exploitdb` |

Without external tools, WASP falls back to pure-Python HTTP probing for recon and uses only `http_request` and `jwt_lite` for probes.

All of the above (including `crackmapexec`, `bloodhound`, and `exploitdb`) are installed automatically by `deploy.sh`.

---

## Active Directory / lateral movement

```bash
# Authenticated AD scan — creds are injected server-side only, the LLM
# never sees or guesses them (smb_enum, bloodhound_collect, crackmapexec_scan)
python wasp.py scan 192.168.1.10 --type activedir \
    --domain-user svc_pentest --domain-pass 'P@ssw0rd!'
```

This unlocks, on top of the unauthenticated AD checks (`ad_enum`, `kerberoast`,
`asreproast`, `ad_null_bind`):
- **`ad_bloodhound`** — full attack-path collection via `bloodhound-python`, ready to import into the BloodHound GUI.
- **`ad_pivot`** — validates the supplied (or Kerberoast/AS-REP-recovered) credential against a host via `crackmapexec`; a confirmed finding means that account has local admin rights there (lateral movement / pivot potential).

Any confirmed finding with a known CVE is automatically enriched with matching
public exploit references from an offline ExploitDB lookup (`searchsploit`) —
no internet call, no LLM involved.

---

## Expected output against Juice Shop

```
── WASP — Web Application Security Probe ──────────────────────────
  Target  : http://localhost:3002
  Model   : llama3.2:3b  @ http://localhost:11435
  Budget  : 14m 0s

✓ Ollama reachable — model llama3.2:3b

── Phase 1 — Recon ─────────────────────────────────────────────────
✓ Recon complete in 68.4s
  Ports     : 3002
  Tech      : Express
  Endpoints : 34 discovered
  Login     : /rest/user/login

── Phase 2 — Planning ───────────────────────────────────────────────
✓ 6 hypotheses generated
  [1] sqli          → /rest/user/login
  [2] idor          → /rest/basket/1
  [3] lfi           → /ftp
  [4] mass_assignment → /api/Users
  [5] jwt_attack    → /rest/user/login
  [6] security_misconfig → /

── Phase 3 — Probing ────────────────────────────────────────────────
  CONFIRMED CRITICAL  SQL Injection — /rest/user/login          (8.2s)
  CONFIRMED HIGH      IDOR — /rest/basket/1                     (4.1s)
  CONFIRMED MEDIUM    Local File Inclusion / Directory Listing   (3.8s)
  CONFIRMED HIGH      Mass Assignment — /api/Users              (5.3s)
  not vulnerable      jwt_attack → /rest/user/login             (6.1s)
  CONFIRMED LOW       Security Misconfiguration — /             (62.4s)

── Phase 4 — Report ─────────────────────────────────────────────────
✓ Report written → wasp-20260904-120532-localhost-3002.md

── Results ──────────────────────────────────────────────────────────
  Hypotheses tested : 6
  Findings          : 5

  Sev       Title                                      URL
  ────────────────────────────────────────────────────────────────────
  CRITICAL  SQL Injection — /rest/user/login           http://...
  HIGH      IDOR — /rest/basket/1                      http://...
  HIGH      Mass Assignment — /api/Users               http://...
  MEDIUM    Local File Inclusion / Directory Listing   http://...
  LOW       Security Misconfiguration — /              http://...

  Total time : 7m 42s
```

---

## Architecture

```
wasp.py          CLI (typer + rich)
├── recon.py     Phase 1 — parallel httpx + nmap + gobuster, returns ReconFacts
├── planner.py   Phase 2 — 1 LLM call → list[Hypothesis]
├── probe.py     Phase 3 — 2-turn ReAct loop per hypothesis → Finding | None
├── report.py    Phase 4 — LLM PoC enrichment + Markdown render
├── blackboard.py  In-memory Finding store (thread-safe)
├── llm.py       Ollama client — native tool_calls + JSON fallback parser
└── tools.py     19 tool wrappers + CLASS_TOOLS mapping + run_tool() dispatcher
```

---

## Inspiration

WASP stands on the shoulders of:
- **[Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI)** — parent project; stigmergic swarm architecture
- **[HackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT)** — minimal LLM+tool loop philosophy
- **[PentestGPT](https://github.com/GreyDGL/PentestGPT)** — three-module reasoning pattern
- **[CAI](https://github.com/aliasrobotics/cai)** — parallel tool execution before LLM reasoning
- **[TrustedSec Juice Shop Benchmark](https://trustedsec.com/blog/benchmarking-self-hosted-llms-for-offensive-security)** — empirical data on what local models can and cannot do

---

## Disclaimer

Only use WASP against systems you own or are explicitly authorized to test.
This tool executes real HTTP requests, port scans, and fuzzing payloads.
Findings are produced by a local LLM and should be manually verified.
