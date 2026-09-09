# WASP — Web Application Security Probe
## Full Manual · v0.1

> **WASP** is a lightweight, local-AI penetration testing tool designed to run on modest hardware — no GPU, no cloud API keys, no internet required. It scans web applications for common vulnerabilities using a local Ollama model and a small set of targeted security tools, completing a meaningful scan of OWASP Juice Shop in under 15 minutes.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Installation](#2-installation)
3. [Configuration Reference](#3-configuration-reference)
4. [Commands](#4-commands)
5. [Scan Phases in Detail](#5-scan-phases-in-detail)
6. [Vulnerability Classes](#6-vulnerability-classes)
7. [Tool Reference](#7-tool-reference)
8. [Model Selection Guide](#8-model-selection-guide)
9. [Report Format](#9-report-format)
10. [Understanding Results](#10-understanding-results)
11. [Tuning for Your Hardware](#11-tuning-for-your-hardware)
12. [Extending WASP](#12-extending-wasp)
13. [Limitations](#13-limitations)
14. [Troubleshooting](#14-troubleshooting)
15. [Design Principles](#15-design-principles)

---

## 1. Architecture Overview

WASP runs a fixed 4-phase pipeline. Each phase has a hard time budget and degrades gracefully if a tool or LLM call fails.

```
┌─────────────────────────────────────────────────────────────┐
│                     wasp scan <TARGET>                      │
└──────────────────────────┬──────────────────────────────────┘
                           │
          ┌────────────────▼────────────────┐
          │  Phase 1 — Deterministic Recon  │  ~75s, zero LLM calls
          │  httpx + nmap + gobuster        │
          │  → ReconFacts struct            │
          └────────────────┬────────────────┘
                           │ facts
          ┌────────────────▼────────────────┐
          │  Phase 2 — Plan                 │  1 LLM call, ~3s
          │  LLM reads facts, outputs 6     │
          │  ordered attack hypotheses      │
          │  → list[Hypothesis]             │
          └────────────────┬────────────────┘
                           │ hypotheses
          ┌────────────────▼────────────────┐
          │  Phase 3 — Probe                │  ~5–10 min
          │  For each hypothesis:           │
          │    Turn 1: LLM calls one tool   │
          │    Tool runs against target     │
          │    Turn 2: LLM classifies result│
          │    _evidence_confirm() override │
          │  → list[Finding]                │
          └────────────────┬────────────────┘
                           │ findings
          ┌────────────────▼────────────────┐
          │  Phase 4 — Report               │  ~15s
          │  LLM writes PoC per finding     │
          │  Markdown rendered + written    │
          │  → wasp-<timestamp>-<host>.md   │
          └─────────────────────────────────┘
```

### Key design decisions

**No growing context.** Each probe is a fresh 2-turn conversation. The LLM never sees previous probe results. This prevents context window exhaustion on 3B models and means a bad probe cannot corrupt the next one.

**Deterministic recon first.** Tools run before any LLM call. The planner sees real facts (open ports, discovered endpoints, technology stack) instead of guessing. This is the single biggest quality improvement over asking the LLM to plan from a bare URL.

**`_evidence_confirm()` safety net.** Small models (3B) frequently under-call on turn 2 — they classify a successful exploit as NOT_VULNERABLE because they focus on an error message rather than the JWT or `role:admin` in the response body. A rule-based signal scanner overrides the LLM verdict when unmistakable evidence is present.

**Tools matched to hypothesis class.** The LLM only sees 2–3 tool definitions per probe, not all 8. This keeps the input token count under 1,200 and prevents the model from picking irrelevant tools.

**Wall-clock budget enforcer.** A hard deadline (default 14 minutes) is checked before each probe. If the budget is exhausted, remaining hypotheses are skipped and the report is written from whatever was found.

---

## 2. Installation

### Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| Python | 3.10+ | 3.11 recommended |
| RAM | 4 GB | 8 GB comfortable with llama3.2:3b loaded |
| Disk | 3 GB | For the model file |
| Ollama | v0.3+ | Must support tool_calls in /api/chat |
| OS | Linux / macOS | Windows untested |

### Step-by-step

```bash
# 1. Clone or copy the project
cd /home/dietpi/wasp

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Ensure Ollama is running with a model
ollama serve                          # if not already running as a service
ollama pull llama3.2:3b               # baseline model (already done on this machine)
# ollama pull qwen3:1.7b             # recommended upgrade — better judgment

# 5. Verify everything is working
python wasp.py doctor
```

### Optional external tools (improve coverage)

WASP works without any of these — it falls back to pure-Python HTTP probing. Each tool adds a specific capability:

```bash
# Debian / Ubuntu / DietPi
apt-get install nmap gobuster sqlmap nikto

# httpx (ProjectDiscovery) — better fingerprinting than fallback
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
# or: download binary from https://github.com/projectdiscovery/httpx/releases

# nuclei — template-based scanning
# download binary from https://github.com/projectdiscovery/nuclei/releases
```

### Verify installation

```bash
python wasp.py doctor
```

Expected output on this machine:
```
──────────────── WASP Doctor ────────────────
  ✓ Ollama  http://localhost:11435  model=llama3.2:3b
  ✓ nmap
  ✓ gobuster
  ✓ httpx
  ✓ sqlmap
  – nikto    (optional — apt-get install nikto)
  – nuclei   (optional — https://nuclei.projectdiscovery.io)
  ✓ Python: httpx
  ✓ Python: yaml
  ✓ Python: typer
  ✓ Python: rich
```

---

## 3. Configuration Reference

WASP reads `config.yaml` from the same directory as `wasp.py`. All values have built-in defaults — you only need to edit what differs from your setup.

```yaml
orchestrator:
  provider:       "ollama"
  model:          "llama3.2:3b"
  endpoint:       "http://localhost:11435"
  temperature:    0.1        # Low = more deterministic payloads. Range: 0.0–1.0
  max_tokens:     256        # Hard cap per LLM call. Prevents rambling. Raise to 512
                             # if report descriptions are being cut off.
  context_window: 8192       # Must match the model's actual context. llama3.2:3b = 8192.
                             # qwen3:1.7b supports 32768.

lite:
  wall_clock_budget_s: 840   # Total scan budget in seconds (default: 14 minutes).
                             # Override per-run with --budget N (minutes).
  max_hypotheses:      6     # How many attack hypotheses to test. Raise to 8–10 for
                             # more coverage at the cost of time.
  tool_timeout_s:      45    # Per-tool subprocess timeout. sqlmap may need 60–90s
                             # on slow targets.
  recon_timeout_s:     90    # Total Phase 1 timeout. All three recon tools share this.
  result_truncate_chars: 2048 # Max chars from tool output fed back to LLM. Raising
                              # this increases token usage; lowering risks missing evidence.
  wordlist: "wasp/wordlist.txt"  # Path to gobuster wordlist. Absolute or relative to
                                  # the directory wasp.py is run from.

tools:
  nmap:
    rate: 500              # Packets/sec. Reduce to 100–200 on slow or noisy networks.

  httpx:
    follow_redirects: true
    timeout: 10            # Per-request timeout in seconds.
    threads: 5             # Concurrent threads. Raise to 20 on fast networks.

  gobuster:
    threads: 10            # Concurrent threads for directory brute-force.

  sqlmap:
    level: 1               # Test depth 1–5. Keep at 1 for speed. Level 5 is exhaustive
                           # but takes 10+ minutes per endpoint.
    risk: 1                # Payload risk 1–3. Risk 2–3 may modify data — only use on
                           # dedicated test targets.
    technique: "B"         # Injection technique(s). B=boolean-based (fast, safe).
                           # Add T for time-based: "BT". Add E for error-based: "BE".

  nikto:
    max_time: 60           # Hard time limit for nikto in seconds.

  nuclei:
    severity: ["critical", "high"]   # Which severities to scan for. Add "medium" for
                                     # more findings at the cost of time.
    rate_limit: 10         # Requests/sec. Raise to 50 on local/fast targets.

output:
  dir: "."                 # Directory where report .md files are written.
                           # Must exist and be writable.
```

### Environment variable overrides

Any config value can be overridden at runtime via the CLI flags. For the Ollama endpoint specifically, you can also set:

```bash
OLLAMA_ENDPOINT=http://192.168.1.100:11434 python wasp.py scan http://target
```

*(Not yet implemented as a formal env-var override — use `--config` with a modified config.yaml for now.)*

---

## 4. Commands

### `wasp.py scan` — run a security scan

```
python wasp.py scan TARGET [OPTIONS]

Arguments:
  TARGET    Full URL of the target, e.g. http://localhost:3002

Options:
  -c, --config  PATH     Path to config.yaml (default: config.yaml in same dir)
  -m, --model   TEXT     Override the Ollama model for this run only
  -b, --budget  INT      Wall-clock budget in minutes (default: 14)
  -o, --output  DIR      Directory to write the report file (default: current dir)
  -v, --verbose          Show LLM hypothesis rationale and tool output in real time
      --dry-run          Run recon and planning only; skip all probes
      --help             Show help
```

**Examples:**

```bash
# Basic scan
python wasp.py scan http://localhost:3002

# Use a better model
python wasp.py scan http://localhost:3002 --model qwen3:1.7b

# Tight budget — useful for a quick triage
python wasp.py scan http://target.local --budget 5

# Save report to a specific directory
python wasp.py scan http://target.local --output /home/user/reports/

# See what hypotheses would be tested without running probes
python wasp.py scan http://localhost:3002 --dry-run --verbose

# Full verbose run — shows rationale, tool calls, and raw results
python wasp.py scan http://localhost:3002 --verbose
```

### `wasp.py doctor` — pre-flight check

Checks Ollama connectivity, installed tool binaries, and Python dependencies.

```bash
python wasp.py doctor
```

Run this first after any change to your setup. If Ollama is unreachable, `scan` will exit immediately with a clear error rather than failing mid-scan.

### `wasp.py models` — list available Ollama models

Shows all models pulled on this machine with their size, quantisation, and tool-calling capability.

```bash
python wasp.py models
```

Output includes a recommendation for the best model to use with WASP based on what is installed.

### `wasp.py version` — show version

```bash
python wasp.py version
# WASP 0.1.0
```

---

## 5. Scan Phases in Detail

### Phase 1 — Deterministic Recon (~75s, zero LLM calls)

Three tools run in parallel threads, each with an independent timeout:

**httpx probe** fingerprints the target URL:
- HTTP status code
- Server and `X-Powered-By` headers
- Technology detection (Angular, React, Express, Django, etc.)
- Interesting security headers (or their absence: CSP, X-Frame-Options, HSTS)

If the `httpx` binary is not installed, a pure-Python fallback using the `httpx` library performs the same probe with slightly less detail.

**nmap port scan** identifies open ports and service banners:
- Scans top-100 ports by default (configurable)
- `-sV` for service version detection
- `--min-rate 500` for speed
- Results are parsed from greppable output (`-oG -`)

**gobuster directory discovery** finds endpoints and API paths:
- Uses the bundled `wasp/wordlist.txt` (200 entries curated for REST/Node.js apps)
- Automatically detects SPA wildcard responses (apps that return 200 for any path) and excludes them by response length
- Falls back to direct HTTP probing of ~15 high-value paths if gobuster is not installed

All three results are combined into a `ReconFacts` struct with categorised lists: `login_endpoints`, `api_endpoints`, `upload_endpoints`, `interesting_files`.

### Phase 2 — Plan (1 LLM call, ~3s)

The planner sends a single prompt containing:
- The target URL
- The full recon summary (~300 tokens)
- The list of valid vulnerability classes
- Instructions to return a JSON array

The LLM returns up to 6 hypotheses ordered by likelihood, each with a `vuln_class`, a specific `endpoint`, a `priority`, and a one-sentence `rationale`.

If the LLM fails or returns unparseable output, a hardcoded fallback list is used (the 6 most common Juice Shop vulnerabilities in priority order). This means the planner never blocks the scan.

### Phase 3 — Probe (~5–10 min)

For each hypothesis in priority order:

**Turn 1** — The LLM receives:
- A system prompt with the target, vuln class, endpoint, and per-class payload hints
- The recon summary
- 2–3 tool definitions matching the hypothesis class
- A prompt instructing it to call one tool now

The LLM responds with a structured tool call. If it returns text instead of a tool call, the hypothesis is skipped (not retried).

**Tool execution** — The called tool runs with its configured timeout. Output is truncated to `result_truncate_chars` before being returned.

**Turn 2** — The LLM receives the tool output and is asked to classify it as `CONFIRMED` or `NOT_VULNERABLE` with a one-sentence explanation.

**`_evidence_confirm()` override** — Regardless of the LLM verdict, the raw tool output is scanned for unmistakable signals:
- `"token":"eyJ` → SQLi auth bypass produced a JWT
- `"role":"admin"` → mass assignment succeeded
- `acquisitions` or `eastere` → LFI confirmed (known Juice Shop files)
- `"products":` → IDOR confirmed (basket contents returned)
- etc.

This compensates for the known weakness of 3B models that correctly call the tool but then misread their own output on turn 2.

**Script-verdict downgrade** — For classes backed by a deterministic nmap/tool script rather than free-form prose (`smb_enum`, `smb_vuln`, `smb_signing`, `null_session`, `rdp_vuln`, `tls_weak`, `ad_bloodhound`, `ad_pivot`), a `CONFIRMED` verdict is only kept if the raw output actually contains the matching signal string (e.g. a real `smbclient` share table for `smb_enum`, `State: VULNERABLE` for `smb_vuln`). Otherwise it's downgraded to `NOT_VULNERABLE`. This guards against the LLM confirming a vulnerability from a script run that was silent, empty, or closed (e.g. SMB port closed/refused) — where there is no ambiguous prose to hedge on, so a CONFIRMED without the signal is a hallucination, not a judgment call.

**Budget check** — Before each probe, remaining wall-clock time is checked. If less than 15 seconds remain, all remaining hypotheses are skipped and the report phase runs on whatever was found.

### Phase 4 — Report (~15s)

For each confirmed finding, one LLM call generates a 2–3 sentence PoC description. The prompt gives the LLM:
- The vulnerability class and title
- The exact request that confirmed it (method, URL, body)
- The confirmed evidence from the response
- Instructions to write a PoC curl command

The report is rendered as Markdown and written to disk. The filename embeds the scan timestamp and target host so multiple scans never overwrite each other.

---

## 6. Vulnerability Classes

These are the classes WASP can detect. Each maps to a specific set of tools and payload hints.

| Class | OWASP 2021 | What it tests | Typical evidence |
|---|---|---|---|
| `sqli` | A03 Injection | SQL injection auth bypass on login endpoints | JWT token in response, or `role:admin` |
| `auth_bypass` | A07 Auth Failures | Authentication bypass via manipulated requests | Successful login response without valid credentials |
| `jwt_attack` | A02 Crypto Failures | JWT algorithm confusion (alg:none, HS256 confusion) | API response containing user list or admin data |
| `idor` | A01 Broken Access Control | Insecure direct object reference via ID manipulation | Another user's data returned |
| `mass_assignment` | A04 Insecure Design | Accepting undocumented fields (role, isAdmin) in POST | `"role":"admin"` in registration response |
| `lfi` | A01 Broken Access Control | Directory listing, exposed file paths | Directory index or file contents |
| `path_traversal` | A01 Broken Access Control | Path traversal via null bytes or `../` sequences | File contents outside the web root |
| `xss_reflected` | A03 Injection | Reflected XSS via input parameters | Script tag or event handler reflected in response |
| `xss_stored` | A03 Injection | Stored XSS via persistent input fields | Injected payload returned from database |
| `security_misconfig` | A05 Security Misconfiguration | Missing security headers, verbose errors, exposed paths | nikto findings, header analysis |
| `outdated_components` | A06 Vulnerable Components | Known CVEs in libraries and frameworks | nuclei template matches |
| `info_disclosure` | A09 Logging/Monitoring | Exposed config files, API keys, source code | `.env`, `package.json`, `/actuator/env` |
| `ad_pivot` | A07 Auth Failures | Credential (own or Kerberoast/AS-REP-recovered) validated for local admin access on a host | `Pwn3d!` marker in `crackmapexec` output |

---

## 7. Tool Reference

### `http_request` (always available, no binary required)

Generic HTTP client for crafting and sending exploit payloads. The most-used tool — present for every hypothesis class.

Parameters: `method`, `url`, `headers` (optional), `body` (optional)

The tool handles redirects, sets `Content-Type: application/json` automatically when a body is provided without an explicit header, and truncates responses to 2,500 chars.

### `httpx_probe` (requires `httpx` binary or falls back to Python)

Service fingerprinting. Used in recon phase and available to probes for tech detection.

Parameters: `url`

### `nmap_scan` (requires `nmap`)

Port scan with service detection. Used in recon phase.

Parameters: `host`, `ports` (default: `"top-100"`, accepts `"top-1000"` or `"80,443,8080"`)

### `gobuster_dir` (requires `gobuster`)

Directory and endpoint discovery. Used in recon phase.

Parameters: `url`, `wordlist` (optional, defaults to bundled list)

### `sqlmap_quick` (requires `sqlmap`)

SQL injection testing via sqlmap in batch mode. Safe settings: level=1, risk=1, boolean technique only.

Parameters: `url`, `data` (POST body), `param` (specific parameter), `cookie` (session cookie)

Output is summarised to show only the key lines (`[+]`, `injectable`, `database`, `payload`).

### `nikto_quick` (requires `nikto`)

Web server misconfiguration scan with a 60-second hard limit.

Parameters: `url`

### `nuclei_quick` (requires `nuclei` binary)

Template-based vulnerability scanning. By default scans only critical and high severity templates.

Parameters: `url`

### `jwt_lite` (always available, no binary required)

In-process JWT operations: decode, forge with alg:none, forge with HS256. No subprocess, no external dependencies, runs in ~1ms.

Parameters: `operation` (`decode` | `forge_none` | `forge_hs256`), `token`, `secret` (for HS256), `payload_overrides` (dict)

### `crackmapexec_scan` (requires `crackmapexec` or `nxc` binary)

Validates a credential against a host over SMB and reports its access level. A `Pwn3d!` marker means local admin — confirmed lateral-movement/pivot potential. Only reachable for the `ad_pivot` hypothesis class.

Parameters: `host`, `username`, `password` — `username`/`password` are overridden server-side from `--domain-user`/`--domain-pass` if set (never LLM-supplied).

### Exploit-DB enrichment (not an LLM tool — automatic, deterministic)

Any confirmed finding carrying a CVE is enriched by shelling out to `searchsploit --cve <CVE>` and attaching matching public exploit titles/EDB-IDs to the report (`Finding.exploit_refs`). No LLM call, no internet — pure offline ExploitDB lookup. Silently skipped if `searchsploit` is not installed.

---

## 8. Model Selection Guide

WASP's performance depends more on how the harness uses the model than on raw model capability. The 2-turn probe loop, per-class payload hints, and `_evidence_confirm()` safety net compensate for weaker models. That said, better models find more and describe findings more accurately.

### Installed model

| Model | Size on disk | Inference speed (this CPU) | Agent score* | Recommendation |
|---|---|---|---|---|
| `llama3.2:3b` | 2.0 GB | ~1.7s/call | 0.66 | ✓ Works. Aggressive tool use, zero self-restraint. WASP's harness compensates. |

### Recommended upgrades

```bash
ollama pull qwen3:1.7b       # Best under 2B. 0.960 agent score. ~10s/call on CPU.
ollama pull qwen2.5:1.5b     # 0.800 score, 2.2s/call. Best speed/quality under 2B.
ollama pull qwen3:8b         # Significantly better at multi-step reasoning. ~25s/call.
```

### Using a different model

```bash
# For a single scan
python wasp.py scan http://localhost:3002 --model qwen3:1.7b

# Permanently — edit config.yaml
orchestrator:
  model: "qwen3:1.7b"
```

### Impact by phase

| Phase | Model matters? | Why |
|---|---|---|
| Recon | No | Zero LLM calls |
| Plan | Moderate | Better models produce more targeted hypotheses |
| Probe turn 1 | High | Must correctly call a tool with the right payload |
| Probe turn 2 | Low | `_evidence_confirm()` catches most missed verdicts |
| Report | Moderate | Better models write more accurate PoC descriptions |

*Agent score from [MikeVeerman local tool-calling benchmark 2026](https://github.com/MikeVeerman/tool-calling-benchmark).

---

## 9. Report Format

Reports are written as Markdown files. Filename pattern:

```
wasp-<YYYYMMDD-HHMMSS>-<target-slug>.md
```

Example: `wasp-20260904-172014-http-localhost-3002.md`

### Report structure

```
# WASP Scan Report
  Target, Date, Duration, Model, Finding count

## Summary
  Table: # | Severity | Title | URL

## Findings
  ### N. <Title>
    Severity badge, class, URL, timestamp
    Description (LLM-generated PoC, 2–3 sentences + curl command)
    Request block (method, URL, headers, body)
    Evidence (collapsible details block with raw response excerpt)

## Disclaimer
```

### Severity levels

| Badge | Level | Meaning |
|---|---|---|
| 🔴 CRITICAL | Critical | Authentication bypass, RCE, full data exposure |
| 🟠 HIGH | High | Privilege escalation, IDOR, JWT attacks |
| 🟡 MEDIUM | Medium | Path traversal, reflected XSS, directory listing |
| 🟢 LOW | Low | Security misconfigurations, missing headers |
| 🔵 INFO | Info | Version disclosure, informational findings |

### Viewing reports

Any Markdown viewer works. On this machine:

```bash
# Terminal viewer
cat wasp-*.md | less

# Render in browser — if Python is available
python3 -m http.server 8888 &
# Then open http://localhost:8888 and navigate to the .md file

# Or install a Markdown previewer
pip install grip && grip wasp-*.md
```

---

## 10. Understanding Results

### What a confirmed finding means

A finding is confirmed by one of two mechanisms:

1. **LLM classification (turn 2):** The model read the tool output and replied `CONFIRMED: <reason>`. Reliable when the evidence is clear in the response body.

2. **Evidence pattern match (`_evidence_confirm`):** The raw tool output matched a known exploitation signal (JWT prefix, `role:admin`, known file names, etc.). This fires even if the LLM said NOT_VULNERABLE.

Both mechanisms produce a Finding with the same structure. The description field tells you which path confirmed it.

### What a "not vulnerable" result means

A NOT_VULNERABLE result means:
- The tool ran and the response contained no evidence of the vulnerability
- OR the LLM declined to call a tool (hypothesis skipped entirely)
- OR the probe timed out

It does **not** mean the target is secure. WASP tests one probe per class. A different payload, endpoint, or parameter might succeed. Always complement WASP with manual testing.

### False positives

The `_evidence_confirm` safety net uses pattern matching, which can produce false positives in specific cases:

- **`sqli`**: `"token":"eyJ` — could fire on a page that displays a JWT for legitimate reasons (e.g., an API documentation page). Check that the token returned is an authentication token.
- **`security_misconfig`**: `x-frame-options` — fires if the string appears anywhere in the nikto output, including in the context "header present: x-frame-options". Check the raw evidence.
- **`info_disclosure`**: `password` — too broad; will fire on a change-password form. This class requires manual review of evidence.

### False negatives

Known blind spots:

- **Multi-step exploits** requiring more than 2 tool calls (IDOR with auth, CSRF, stored XSS verification)
- **Blind injection** (boolean-blind SQLi extraction, time-based SQLi) — the model cannot run iterative extraction
- **Client-side vulnerabilities** (DOM XSS, CSRF) — require a browser
- **Authenticated scanning** — WASP does not log in before probing unless the LLM independently crafts the auth step in turn 1

---

## 11. Tuning for Your Hardware

### This machine (i5-9500T, 16 GB RAM, no GPU)

The default config is already tuned for this hardware. Expected performance:

| Phase | Typical time | Worst case |
|---|---|---|
| Recon (all 3 tools parallel) | 12–75s | 90s |
| Plan (1 LLM call) | 3–5s | 10s |
| 6 probe loops (sequential) | 3–8 min | 9 min |
| Report (6 LLM calls) | 15–30s | 60s |
| **Total** | **~5 min** | **~10 min** |

### Slow CPU (Raspberry Pi, single-core)

```yaml
orchestrator:
  model: "llama3.2:3b"      # keep — 1B models have poor tool-calling
  max_tokens: 128            # reduce output length
lite:
  wall_clock_budget_s: 1200  # 20 minutes
  max_hypotheses: 4          # fewer probes
  tool_timeout_s: 30
  recon_timeout_s: 60
tools:
  nmap:
    rate: 100                # gentler scan
  gobuster:
    threads: 5
  nuclei:
    rate_limit: 5
```

### Faster machine with GPU

```yaml
orchestrator:
  model: "qwen3:8b"          # much better reasoning
  max_tokens: 512
lite:
  max_hypotheses: 10         # test more hypotheses
  tool_timeout_s: 60
tools:
  nmap:
    rate: 2000
  gobuster:
    threads: 50
  nuclei:
    rate_limit: 50
    severity: ["critical", "high", "medium"]
```

### Remote target (over network)

```yaml
tools:
  nmap:
    rate: 200                # be polite
  httpx:
    timeout: 30              # higher timeout for slow responses
    threads: 3
  gobuster:
    threads: 5
  sqlmap:
    level: 1
    risk: 1                  # never raise risk on remote targets
  nikto:
    max_time: 120
lite:
  tool_timeout_s: 90
  recon_timeout_s: 180
  wall_clock_budget_s: 1200
```

---

## 12. Extending WASP

### Adding a new vulnerability class

1. Add the class name to `VALID_CLASSES` in `wasp/planner.py`
2. Add a tool list to `CLASS_TOOLS` in `wasp/tools.py`
3. Add a payload hint to the `_SYSTEM` prompt in `wasp/probe.py`
4. Add evidence signals to `_SIGNALS` in `_evidence_confirm()` in `wasp/probe.py`
5. Add a default fallback hypothesis to `_FALLBACK_HYPOTHESES` in `wasp/planner.py`
6. Add a severity mapping to `_CLASS_SEVERITY` in `wasp/blackboard.py`

### Adding a new tool

1. Create `Tool` schema and `run_*()` function in `wasp/tools.py`
2. Add to `ALL_TOOLS` dict
3. Add to `CLASS_TOOLS` for relevant hypothesis classes
4. Add binary name to `binary_map` in `available_tools()` (if it requires an external binary)
5. Add to `doctor()` binary check in `wasp.py`

### Using a different LLM backend

The `OllamaClient` in `wasp/llm.py` uses the standard Ollama `/api/chat` endpoint with native tool_calls support. Any backend that implements the same API (LM Studio, llama.cpp server, Ollama-compatible endpoints) works with a URL change:

```yaml
orchestrator:
  endpoint: "http://localhost:1234"   # LM Studio
  model: "mistral-7b-instruct"
```

For backends without native tool_calls, the `_extract_tool_call_from_text()` fallback in `wasp/llm.py` will try to parse tool calls from the text response. Results vary by model.

### Adding a custom wordlist

Replace or extend `wasp/wordlist.txt`. One path per line, starting with `/`. The list is used by gobuster in Phase 1 recon. For a specific target technology:

```bash
# Add Spring Boot paths
cat >> wasp/wordlist.txt << EOF
/actuator
/actuator/env
/actuator/health
/actuator/info
/actuator/mappings
/actuator/beans
/h2-console
/swagger-ui.html
EOF
```

---

## 13. Limitations

These are deliberate design constraints, not bugs.

**Single probe per hypothesis.** WASP tests one payload per vulnerability class. It will not iterate through payload lists or try multiple variants. This keeps scan time bounded but means a class can be missed if the first payload fails.

**No authenticated scanning by default.** WASP does not log in before probing. The IDOR probe can miss findings that require authentication. The LLM may independently craft an auth step in turn 1 for some classes (sqli, jwt_attack) but this is not guaranteed.

**No browser.** Client-side vulnerabilities (DOM XSS, CSRF, stored XSS verification, clickjacking) cannot be confirmed without JavaScript execution. WASP will not detect these reliably.

**No multi-step exploitation chains.** Chained attacks requiring 3+ sequential tool calls are not supported. The 2-turn limit is a deliberate hardware constraint — 3B models on CPU cannot maintain coherent strategy across many turns.

**Local model limitations.** llama3.2:3b has an agent score of 0.66. It will miss some vulnerabilities that a frontier model (GPT-4, Claude Sonnet) would find. The `_evidence_confirm()` safety net compensates partially but cannot replace model reasoning quality.

**Single target per run.** WASP scans one URL per invocation. For multi-host engagements, run separate scans and collect the report files.

**No scope enforcement for probes.** The `scope.enforce_strict` setting from the parent project is not implemented in WASP. All probes target the URL provided on the command line. Do not point WASP at a URL unless you are authorised to test the entire host.

---

## 14. Troubleshooting

### "Cannot reach Ollama"

```bash
# Check if Ollama is running
curl http://localhost:11435/api/tags

# Start it if not
ollama serve

# Check the port in config.yaml matches
grep endpoint config.yaml
```

### "gobuster returned 0 endpoints"

This usually means the target is an SPA (returns 200 for all paths). WASP detects this automatically and falls back to direct path probing. If you see "0 endpoints discovered" in recon output, the fallback probe list was used instead. Check that the fallback list includes your target's key paths, or extend `wordlist.txt`.

### "All probes returned not vulnerable"

Most likely causes:
1. The LLM did not call a tool (check with `--verbose` — if turn 1 shows no tool call, the hypothesis was skipped)
2. The LLM called a tool but sent the wrong payload (visible in `--verbose` output)
3. The target genuinely is not vulnerable to the tested classes

Use `--verbose` to see exactly what each probe sent and received.

### "sqlmap errors about no parameters"

sqlmap needs either GET parameters or a POST body with `--data`. The LLM sometimes calls `sqlmap_quick` without a body. The current workaround is that the system prompt hints specifically instruct the model to use `http_request` with a crafted POST body for login endpoints. If sqlmap errors persist, force `http_request` by removing `sqlmap_quick` from the `sqli` class tools in `wasp/tools.py`.

### "Scan takes longer than the budget"

The budget check fires before each probe, not during one. A probe that takes 60s (e.g., sqlmap) cannot be interrupted once started — it runs to its own timeout. The wall-clock budget prevents starting new probes after the deadline but cannot cut short a running tool.

To enforce tighter timing, reduce `tool_timeout_s` in config.yaml.

### "Report descriptions say 'syntax error' instead of describing the exploit"

This happens when `_evidence_confirm()` overrides a NOT_VULNERABLE verdict after the LLM described a failed intermediate probe (a 500 error from a malformed payload) rather than the successful one. The finding is real — the override fired because the response contained a JWT or `role:admin`. The description is just inaccurate. See the improvements section — this is fixed in v0.1.1 by rewriting the report enrichment prompt to use the confirmed evidence directly.

---

## 15. Design Principles

WASP was designed with four constraints that shaped every decision:

**1. Hardware first.** Every design decision was made against the constraint of a CPU-only ARM/x86 machine with a 3B parameter model. No decision was allowed to "just work on a GPU" or "use a frontier model". This produced a simpler, faster architecture that happens to also work well on better hardware.

**2. Fail gracefully, always finish.** No phase can crash the scan. Recon falls back to direct HTTP probing. The planner falls back to hardcoded hypotheses. Every tool call is wrapped and returns a string. The report is written even if interrupted. The last thing the scan does is always write a file.

**3. The harness compensates for the model.** Rather than requiring a capable model, WASP's scaffolding — per-class payload hints, stateless probe loops, evidence pattern matching — makes a weak model produce useful results. This is the lesson from the TrustedSec Juice Shop benchmark: scaffolding improvements outperform model upgrades up to a point.

**4. Transparent and auditable.** Every probe's request and response is captured in the finding. The report shows exactly what was sent and what came back. There is no "trust the AI" — every confirmed finding can be manually reproduced with a curl command.

---

*WASP v0.1 — Built on the shoulders of PentestGPT, HackingBuddyGPT, CAI, and PentAGI.*
*Only use against systems you own or are explicitly authorised to test.*
