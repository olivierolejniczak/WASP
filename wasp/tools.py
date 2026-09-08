"""
Tool wrappers for WASP.

Each tool follows the same contract:
  - A module-level TOOL: Tool  that defines the schema shown to the LLM
  - A run(args, config, timeout) -> str  function that executes it
  - Returns a plain string (the LLM's next turn will read this)
  - Never raises — errors are returned as strings prefixed "ERROR:"

Tools included:
  1. http_request   — generic HTTP via httpx (no subprocess)
  2. httpx_probe    — fingerprint a URL (status, headers, tech)
  3. nmap_scan      — nmap top-N port scan
  4. gobuster_dir   — directory/endpoint brute-force
  5. sqlmap_quick   — SQLi test on a single URL (batch, level=1)
  6. nikto_quick    — web server misconfig scan (60s max)
  7. nuclei_quick   — template-based scan (critical+high only)
  8. jwt_lite       — in-process JWT decode / alg:none forge

The tool registry at the bottom maps hypothesis class → relevant tool subset.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import shlex
import subprocess
import time
from typing import Any

import httpx

from wasp.llm import Tool


# ---------------------------------------------------------------------------
# Timeouts and safety
# ---------------------------------------------------------------------------

DEFAULT_TOOL_TIMEOUT = 45   # seconds, overridden by config per-tool
MAX_OUTPUT_CHARS     = 3000 # hard cap on returned text fed back to LLM

# Tokens the scope-guard refuses regardless of LLM instruction
_BLOCKED_TOKENS = frozenset([
    "rm ", "rmdir", "dd ", "mkfs", "> /", "| sh", "| bash",
    "; sh", "; bash", "&& sh", "&& bash", "DROP ", "DELETE FROM",
    "shutdown", "reboot", "kill -9",
])

def _safe_command(cmd: str) -> str | None:
    """Return None if the command contains a blocked token, else the cmd."""
    lower = cmd.lower()
    for token in _BLOCKED_TOKENS:
        if token.lower() in lower:
            return None
    return cmd

def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + f"\n... [truncated {len(text) - limit} chars] ...\n" + text[-half:]

def _run_subprocess(args: list[str], timeout: int) -> str:
    """Run a subprocess safely, return combined stdout+stderr."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = (result.stdout or "") + (result.stderr or "")
        return _truncate(out.strip()) or "(no output)"
    except subprocess.TimeoutExpired:
        return f"ERROR: command timed out after {timeout}s"
    except FileNotFoundError:
        return f"ERROR: tool not found: {args[0]}"
    except Exception as exc:
        return f"ERROR: {exc}"


# ===========================================================================
# 1. http_request — generic HTTP probe (no subprocess)
# ===========================================================================

HTTP_REQUEST_TOOL = Tool(
    name="http_request",
    description=(
        "Send a single HTTP request to the target. Use this to test for "
        "vulnerabilities by crafting payloads in the URL, body, or headers. "
        "Returns status code, response headers, and body (truncated to 3000 chars)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "method":  {"type": "string", "enum": ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"], "description": "HTTP method"},
            "url":     {"type": "string", "description": "Full URL including query string"},
            "headers": {"type": "object", "description": "Optional HTTP headers as key-value pairs", "additionalProperties": {"type": "string"}},
            "body":    {"type": "string", "description": "Optional request body (JSON string or raw)"},
        },
        "required": ["method", "url"],
    },
)

def run_http_request(args: dict, config: dict, timeout: int = DEFAULT_TOOL_TIMEOUT) -> str:
    method  = args.get("method", "GET").upper()
    url     = args.get("url", "")
    headers = args.get("headers") or {}
    body    = args.get("body") or None

    if not url:
        return "ERROR: url is required"

    # Ensure Content-Type set for bodies without explicit header
    if body and "content-type" not in {k.lower() for k in headers}:
        headers["Content-Type"] = "application/json"

    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            response = client.request(
                method=method,
                url=url,
                headers=headers,
                content=body.encode() if isinstance(body, str) else body,
            )
        result = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:2500],
        }
        return _truncate(json.dumps(result, indent=2))
    except httpx.TimeoutException:
        return f"ERROR: request timed out after {timeout}s"
    except Exception as exc:
        return f"ERROR: {exc}"


# ===========================================================================
# 2. httpx_probe — fingerprint a URL
# ===========================================================================

HTTPX_PROBE_TOOL = Tool(
    name="httpx_probe",
    description=(
        "Probe a URL to fingerprint the server: status code, redirect chain, "
        "response headers, content-type, server banner, and technology hints. "
        "Use this as a first step before deciding which exploit to attempt."
    ),
    parameters={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL to probe"},
        },
        "required": ["url"],
    },
)

def run_httpx_probe(args: dict, config: dict, timeout: int = DEFAULT_TOOL_TIMEOUT) -> str:
    url = args.get("url", "")
    if not url:
        return "ERROR: url is required"

    tool_cfg = config.get("tools", {}).get("httpx", {})
    threads   = tool_cfg.get("threads", 5)

    # Try the CLI tool first, fall back to pure httpx library
    if _which("httpx"):
        cmd = ["httpx", "-u", url, "-silent", "-status-code", "-title",
               "-tech-detect", "-server", "-content-type",
               "-timeout", str(timeout), "-threads", str(threads)]
        return _run_subprocess(cmd, timeout)

    # Pure-Python fallback
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            r = client.get(url)
        tech_hints = []
        for h, v in r.headers.items():
            if h.lower() in ("x-powered-by", "server", "x-generator", "x-aspnet-version"):
                tech_hints.append(f"{h}: {v}")
        result = {
            "url": str(r.url),
            "status_code": r.status_code,
            "server": r.headers.get("server", ""),
            "content_type": r.headers.get("content-type", ""),
            "tech_hints": tech_hints,
            "body_preview": r.text[:500],
        }
        return _truncate(json.dumps(result, indent=2))
    except Exception as exc:
        return f"ERROR: {exc}"


# ===========================================================================
# 3. nmap_scan — port scan
# ===========================================================================

NMAP_SCAN_TOOL = Tool(
    name="nmap_scan",
    description=(
        "Run a fast nmap port scan against a host. Returns open ports, "
        "service banners, and OS hints. Use to discover attack surface."
    ),
    parameters={
        "type": "object",
        "properties": {
            "host":  {"type": "string", "description": "Hostname or IP to scan"},
            "ports": {"type": "string", "description": "Port spec: 'top-100', 'top-1000', or '80,443,8080'", "default": "top-100"},
        },
        "required": ["host"],
    },
)

def run_nmap_scan(args: dict, config: dict, timeout: int = 60) -> str:
    host  = args.get("host", "")
    ports = args.get("ports", "top-100")
    if not host:
        return "ERROR: host is required"

    tool_cfg = config.get("tools", {}).get("nmap", {})
    rate     = tool_cfg.get("rate", 500)

    if not _which("nmap"):
        return "ERROR: nmap not found — install with: apt-get install nmap"

    if ports.startswith("top-"):
        n   = ports.split("-")[1]
        flag = ["--top-ports", n]
    else:
        flag = ["-p", ports]

    cmd = ["nmap", "-T4", "--min-rate", str(rate), "-sV", "--open",
           "-oG", "-"] + flag + [host]
    return _run_subprocess(cmd, timeout)


# ===========================================================================
# 4. gobuster_dir — endpoint discovery
# ===========================================================================

GOBUSTER_DIR_TOOL = Tool(
    name="gobuster_dir",
    description=(
        "Brute-force directories and API endpoints on a web target. "
        "Returns paths that returned non-404 responses. "
        "Use to discover hidden endpoints before probing for vulnerabilities."
    ),
    parameters={
        "type": "object",
        "properties": {
            "url":      {"type": "string", "description": "Base URL to scan (e.g. http://host:3000)"},
            "wordlist": {"type": "string", "description": "Path to wordlist file (leave empty to use default)"},
        },
        "required": ["url"],
    },
)

def run_gobuster_dir(args: dict, config: dict, timeout: int = 90) -> str:
    url      = args.get("url", "")
    wordlist = args.get("wordlist") or config.get("lite", {}).get("wordlist", "wasp/wordlist.txt")
    if not url:
        return "ERROR: url is required"

    tool_cfg = config.get("tools", {}).get("gobuster", {})
    threads  = tool_cfg.get("threads", 10)

    if not _which("gobuster"):
        return "ERROR: gobuster not found — install with: apt-get install gobuster"

    cmd = [
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist,
        "-t", str(threads),
        "-q",                    # quiet — no banner
        "--no-error",
        "-o", "/dev/stdout",
        "--timeout", f"{timeout}s",
    ]
    return _run_subprocess(cmd, timeout)


# ===========================================================================
# 5. sqlmap_quick — SQL injection test
# ===========================================================================

SQLMAP_QUICK_TOOL = Tool(
    name="sqlmap_quick",
    description=(
        "Test a URL or endpoint for SQL injection vulnerabilities. "
        "Runs sqlmap in batch mode with safe settings (level=1, risk=1). "
        "Provide the full URL with parameter to test (e.g. include a GET param "
        "or use --data for POST). Returns whether the target is injectable."
    ),
    parameters={
        "type": "object",
        "properties": {
            "url":    {"type": "string", "description": "Target URL, e.g. http://host/login"},
            "data":   {"type": "string", "description": "POST body (JSON or form-encoded), if testing a POST endpoint"},
            "param":  {"type": "string", "description": "Specific parameter name to test (optional, sqlmap auto-detects if omitted)"},
            "cookie": {"type": "string", "description": "Session cookie if authentication is required"},
        },
        "required": ["url"],
    },
)

def run_sqlmap_quick(args: dict, config: dict, timeout: int = 90) -> str:
    url    = args.get("url", "")
    data   = args.get("data", "")
    param  = args.get("param", "")
    cookie = args.get("cookie", "")
    if not url:
        return "ERROR: url is required"

    tool_cfg = config.get("tools", {}).get("sqlmap", {})
    level     = tool_cfg.get("level", 1)
    risk      = tool_cfg.get("risk", 1)
    technique = tool_cfg.get("technique", "B")

    if not _which("sqlmap"):
        return "ERROR: sqlmap not found — install with: apt-get install sqlmap"

    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",
        "--level", str(level),
        "--risk",  str(risk),
        "--technique", technique,
        "--timeout", "20",
        "--retries", "1",
        "--output-dir", "/tmp/wasp-sqlmap",
    ]
    if data:
        cmd += ["--data", data]
        cmd += ["--method", "POST"]
    if param:
        cmd += ["-p", param]
    if cookie:
        cmd += ["--cookie", cookie]

    out = _run_subprocess(cmd, timeout)
    # Summarise — full sqlmap output is very verbose
    lines = out.splitlines()
    summary = [l for l in lines if any(kw in l.lower() for kw in
               ("injectable", "parameter", "payload", "database", "error", "not injectable", "[+]", "[*]", "[-]"))]
    return _truncate("\n".join(summary) if summary else out)


# ===========================================================================
# 6. nikto_quick — web server misconfig scan
# ===========================================================================

NIKTO_QUICK_TOOL = Tool(
    name="nikto_quick",
    description=(
        "Scan a web server for common misconfigurations, exposed files, "
        "missing security headers, and known vulnerabilities. "
        "Runs with a 60-second time limit."
    ),
    parameters={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target URL to scan"},
        },
        "required": ["url"],
    },
)

def run_nikto_quick(args: dict, config: dict, timeout: int = 75) -> str:
    url = args.get("url", "")
    if not url:
        return "ERROR: url is required"

    tool_cfg    = config.get("tools", {}).get("nikto", {})
    max_time    = tool_cfg.get("max_time", 60)

    if not _which("nikto"):
        return "ERROR: nikto not found — install with: apt-get install nikto"

    cmd = [
        "nikto",
        "-host", url,
        "-nointeractive",
        "-maxtime", f"{max_time}s",
        "-Format", "txt",
    ]
    return _run_subprocess(cmd, timeout)


# ===========================================================================
# 7. nuclei_quick — template-based vulnerability scan
# ===========================================================================

NUCLEI_QUICK_TOOL = Tool(
    name="nuclei_quick",
    description=(
        "Run nuclei template-based scans for critical and high severity "
        "vulnerabilities including OWASP Top 10 classes. "
        "Targets a single URL."
    ),
    parameters={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target URL"},
        },
        "required": ["url"],
    },
)

def run_nuclei_quick(args: dict, config: dict, timeout: int = 150) -> str:
    url = args.get("url", "")
    if not url:
        return "ERROR: url is required"

    tool_cfg   = config.get("tools", {}).get("nuclei", {})
    severity   = ",".join(tool_cfg.get("severity", ["critical", "high"]))
    rate_limit = tool_cfg.get("rate_limit", 10)

    if not _which("nuclei"):
        return "ERROR: nuclei not found — see https://nuclei.projectdiscovery.io"

    cmd = [
        "nuclei",
        "-u", url,
        "-severity", severity,
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-silent",
        "-no-color",
        "-jsonl",
    ]
    raw = _run_subprocess(cmd, timeout)
    return _render_nuclei_jsonl(raw)


def _render_nuclei_jsonl(raw: str) -> str:
    """Turn nuclei's -jsonl output into a plain-text summary, preserving the
    CVSS score nuclei's own templates carry (info.classification.cvss-score)
    so probe.py can pick it up via CVSS-SCORE: lines instead of losing it to
    the previous plain-text mode."""
    lines = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            hit = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = hit.get("info", {})
        classification = info.get("classification") or {}
        severity  = info.get("severity", "unknown")
        name      = info.get("name", hit.get("template-id", ""))
        cve_ids   = classification.get("cve-id") or []
        cvss      = classification.get("cvss-score")
        matched   = hit.get("matched-at", hit.get("host", ""))
        parts = [f"[{severity}] {name} @ {matched}"]
        if cve_ids:
            parts.append(f"CVE: {','.join(cve_ids)}")
        if cvss is not None:
            parts.append(f"CVSS-SCORE: {cvss}")
        lines.append(" | ".join(parts))
    return "\n".join(lines) if lines else raw


# ===========================================================================
# 8. jwt_lite — in-process JWT decode / alg:none forge
# ===========================================================================

JWT_LITE_TOOL = Tool(
    name="jwt_lite",
    description=(
        "Decode a JWT token and optionally forge a new one. "
        "Supported operations: 'decode' (show header+payload), "
        "'forge_none' (create alg:none token — removes signature), "
        "'forge_hs256' (sign with a known secret). "
        "No subprocess needed — runs in-process."
    ),
    parameters={
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["decode", "forge_none", "forge_hs256"],
                "description": "What to do with the token",
            },
            "token":   {"type": "string", "description": "JWT token string"},
            "secret":  {"type": "string", "description": "HMAC secret for forge_hs256 (optional)"},
            "payload_overrides": {
                "type": "object",
                "description": "Key-value pairs to override in the payload before forging",
                "additionalProperties": True,
            },
        },
        "required": ["operation", "token"],
    },
)

def run_jwt_lite(args: dict, config: dict, timeout: int = 5) -> str:
    op      = args.get("operation", "decode")
    token   = args.get("token", "").strip()
    secret  = args.get("secret", "")
    overrides = args.get("payload_overrides") or {}

    if not token:
        return "ERROR: token is required"

    try:
        header, payload, signature = _jwt_split(token)
    except Exception as exc:
        return f"ERROR: could not parse JWT: {exc}"

    if op == "decode":
        return json.dumps({"header": header, "payload": payload, "signature_present": bool(signature)}, indent=2)

    # Apply payload overrides
    payload.update(overrides)

    if op == "forge_none":
        new_header = dict(header)
        new_header["alg"] = "none"
        forged = _jwt_encode(new_header, payload, b"")
        # alg:none has no signature
        parts = forged.rsplit(".", 1)
        forged = parts[0] + "."
        return json.dumps({"forged_token": forged, "header": new_header, "payload": payload})

    if op == "forge_hs256":
        if not secret:
            return "ERROR: secret is required for forge_hs256"
        new_header = dict(header)
        new_header["alg"] = "HS256"
        forged = _jwt_encode(new_header, payload, secret.encode())
        return json.dumps({"forged_token": forged, "header": new_header, "payload": payload})

    return f"ERROR: unknown operation '{op}'"


# ---------------------------------------------------------------------------
# JWT helpers (no external deps)
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _jwt_split(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT: fewer than 2 parts")
    header  = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig     = parts[2] if len(parts) > 2 else ""
    return header, payload, sig

def _jwt_encode(header: dict, payload: dict, secret: bytes) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",",":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",",":")).encode())
    signing_input = f"{h}.{p}".encode()
    if secret:
        sig = _b64url_encode(hmac.new(secret, signing_input, hashlib.sha256).digest())
    else:
        sig = ""
    return f"{h}.{p}.{sig}"


# ===========================================================================
# Registry
# ===========================================================================

# All tools, keyed by name
ALL_TOOLS: dict[str, tuple[Tool, Any]] = {
    "http_request": (HTTP_REQUEST_TOOL,  run_http_request),
    "httpx_probe":  (HTTPX_PROBE_TOOL,   run_httpx_probe),
    "nmap_scan":    (NMAP_SCAN_TOOL,     run_nmap_scan),
    "gobuster_dir": (GOBUSTER_DIR_TOOL,  run_gobuster_dir),
    "sqlmap_quick": (SQLMAP_QUICK_TOOL,  run_sqlmap_quick),
    "nikto_quick":  (NIKTO_QUICK_TOOL,   run_nikto_quick),
    "nuclei_quick": (NUCLEI_QUICK_TOOL,  run_nuclei_quick),
    "jwt_lite":     (JWT_LITE_TOOL,      run_jwt_lite),
}

# Hypothesis class → tool names the LLM may use for that probe
# http_request is always available; class-specific tools are added on top
CLASS_TOOLS: dict[str, list[str]] = {
    "sqli":               ["http_request", "sqlmap_quick"],
    "auth_bypass":        ["http_request"],
    "jwt_attack":         ["http_request", "jwt_lite"],
    "idor":               ["http_request"],
    "mass_assignment":    ["http_request"],
    "path_traversal":     ["http_request"],
    "lfi":                ["http_request"],
    "xss_reflected":      ["http_request"],
    "xss_stored":         ["http_request"],
    "security_misconfig": ["http_request", "nikto_quick"],
    "outdated_components":["http_request", "nuclei_quick"],
    "info_disclosure":    ["http_request"],
}

def tools_for_class(vuln_class: str) -> list[Tool]:
    """Return the Tool objects (schema only) for a given hypothesis class."""
    names = CLASS_TOOLS.get(vuln_class.lower(), ["http_request"])
    return [ALL_TOOLS[n][0] for n in names if n in ALL_TOOLS]

def run_tool(name: str, args: dict, config: dict, timeout: int = DEFAULT_TOOL_TIMEOUT) -> str:
    """Dispatch a tool call by name. Always returns a string."""
    if name not in ALL_TOOLS:
        return f"ERROR: unknown tool '{name}'"
    _, fn = ALL_TOOLS[name]
    try:
        return fn(args, config, timeout)
    except Exception as exc:
        return f"ERROR: tool '{name}' raised: {exc}"

def available_tools() -> list[str]:
    """Return names of tools whose underlying binary is present (or needs none)."""
    always_available = {"http_request", "jwt_lite", "httpx_probe"}
    binary_map = {
        "nmap_scan":    "nmap",
        "gobuster_dir": "gobuster",
        "sqlmap_quick": "sqlmap",
        "nikto_quick":  "nikto",
        "nuclei_quick": "nuclei",
        "httpx_probe":  "httpx",
    }
    result = []
    for name in ALL_TOOLS:
        if name in always_available:
            result.append(name)
        elif _which(binary_map.get(name, name)):
            result.append(name)
    return result


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _which(binary: str) -> bool:
    import shutil
    return shutil.which(binary) is not None



# ===========================================================================
# NEW TOOLS — non-web services
# ===========================================================================

import os as _os
import socket as _socket


# ---------------------------------------------------------------------------
# 9. nmap_script — run specific NSE scripts against a host
# ---------------------------------------------------------------------------

NMAP_SCRIPT_TOOL = Tool(
    name="nmap_script",
    description=(
        "Run specific nmap NSE scripts against a host and port. "
        "Use for SMB enumeration, RDP fingerprinting, SSH auditing, "
        "vulnerability checks (ms17-010, ms08-067), LDAP queries, etc. "
        "Returns raw nmap script output."
    ),
    parameters={
        "type": "object",
        "properties": {
            "host":    {"type": "string", "description": "Target host or IP"},
            "port":    {"type": "string", "description": "Port number (e.g. '445', '3389'). Leave empty to let nmap choose."},
            "scripts": {"type": "string", "description": "Comma-separated NSE script names or categories, e.g. 'smb-enum-shares,smb-enum-users' or 'smb-vuln-*'"},
            "args":    {"type": "string", "description": "Optional nmap script args, e.g. 'smbuser=admin,smbpass=admin'"},
        },
        "required": ["host", "scripts"],
    },
)

def run_nmap_script(args: dict, config: dict, timeout: int = 60) -> str:
    host    = args.get("host", "")
    port    = args.get("port", "")
    scripts = args.get("scripts", "")
    nargs   = args.get("args", "")
    if not host or not scripts:
        return "ERROR: host and scripts are required"
    if not _which("nmap"):
        return "ERROR: nmap not found"
    cmd = ["nmap", "-T4", "--open", "-sV", f"--script={scripts}"]
    if port:
        cmd += ["-p", str(port)]
    if nargs:
        cmd += [f"--script-args={nargs}"]
    cmd.append(host)
    return _run_subprocess(cmd, timeout)


# ---------------------------------------------------------------------------
# 10. smb_enum — enumerate SMB shares, users, sessions via smbclient + nmap
# ---------------------------------------------------------------------------

SMB_ENUM_TOOL = Tool(
    name="smb_enum",
    description=(
        "Enumerate a Windows/SMB host: list shares, attempt null session, "
        "check signing, enumerate users and OS info. "
        "Combines smbclient and nmap SMB scripts."
    ),
    parameters={
        "type": "object",
        "properties": {
            "host":     {"type": "string", "description": "Target IP or hostname"},
            "username": {"type": "string", "description": "SMB username (leave empty for null/anonymous session)"},
            "password": {"type": "string", "description": "SMB password (leave empty for null session)"},
        },
        "required": ["host"],
    },
)

def run_smb_enum(args: dict, config: dict, timeout: int = 60) -> str:
    host     = args.get("host", "")
    username = args.get("username", "")
    password = args.get("password", "")
    if not host:
        return "ERROR: host is required"

    results = []

    # smbclient null session share list
    if _which("smbclient"):
        if username:
            smb_cmd = ["smbclient", "-L", f"//{host}", "-U", f"{username}%{password}", "--no-pass" if not password else ""]
            smb_cmd = [x for x in smb_cmd if x]
        else:
            smb_cmd = ["smbclient", "-L", f"//{host}", "-N"]
        out = _run_subprocess(smb_cmd, min(timeout, 20))
        results.append(f"=== smbclient shares ===\n{out}")

    # nmap SMB scripts
    if _which("nmap"):
        scripts = "smb-os-discovery,smb-security-mode,smb2-security-mode,smb-enum-shares,smb-enum-users"
        nmap_cmd = ["nmap", "-T4", "-p", "139,445", f"--script={scripts}", host]
        out = _run_subprocess(nmap_cmd, min(timeout, 50))
        results.append(f"=== nmap SMB scripts ===\n{out}")

    return _truncate("\n\n".join(results) if results else "ERROR: no SMB tools available")


# ---------------------------------------------------------------------------
# 11. rdp_check — fingerprint RDP and check for known vulnerabilities
# ---------------------------------------------------------------------------

RDP_CHECK_TOOL = Tool(
    name="rdp_check",
    description=(
        "Fingerprint an RDP service and check for known vulnerabilities "
        "including BlueKeep (CVE-2019-0708) and MS12-020. "
        "Also checks encryption level and NLA requirements."
    ),
    parameters={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Target IP or hostname"},
            "port": {"type": "string", "description": "RDP port (default: 3389)"},
        },
        "required": ["host"],
    },
)

def run_rdp_check(args: dict, config: dict, timeout: int = 45) -> str:
    host = args.get("host", "")
    port = args.get("port", "3389")
    if not host:
        return "ERROR: host is required"
    if not _which("nmap"):
        return "ERROR: nmap not found"
    scripts = "rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020"
    cmd = ["nmap", "-T4", "-p", str(port),
           f"--script={scripts}", "--script-args=unsafe=1", host]
    return _run_subprocess(cmd, timeout)


# ---------------------------------------------------------------------------
# 12. impacket_npusers — AS-REP roasting (no pre-auth required accounts)
# ---------------------------------------------------------------------------

IMPACKET_NPUSERS_TOOL = Tool(
    name="impacket_npusers",
    description=(
        "Enumerate Active Directory accounts that do not require Kerberos "
        "pre-authentication (AS-REP roasting). Returns hashes that can be "
        "cracked offline. Requires domain and DC IP."
    ),
    parameters={
        "type": "object",
        "properties": {
            "dc_ip":  {"type": "string", "description": "Domain controller IP address"},
            "domain": {"type": "string", "description": "AD domain name, e.g. corp.local"},
            "users":  {"type": "string", "description": "Comma-separated usernames to test, or leave empty to use built-in list"},
        },
        "required": ["dc_ip", "domain"],
    },
)

def run_impacket_npusers(args: dict, config: dict, timeout: int = 60) -> str:
    dc_ip  = args.get("dc_ip", "")
    domain = args.get("domain", "")
    users  = args.get("users", "")
    if not dc_ip or not domain:
        return "ERROR: dc_ip and domain are required"

    script = _find_impacket_script("GetNPUsers.py")
    if not script:
        return "ERROR: impacket GetNPUsers.py not found — install impacket"

    cmd = [script, f"{domain}/", "-dc-ip", dc_ip, "-no-pass", "-request"]
    if users:
        # Write users to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(users.split(",")))
            tmpfile = f.name
        cmd += ["-usersfile", tmpfile]

    out = _run_subprocess(cmd, timeout)
    return _truncate(out)


# ---------------------------------------------------------------------------
# 13. impacket_spns — Kerberoasting (enumerate SPNs and request TGS tickets)
# ---------------------------------------------------------------------------

IMPACKET_SPNS_TOOL = Tool(
    name="impacket_spns",
    description=(
        "Enumerate Kerberos Service Principal Names (SPNs) in Active Directory "
        "and request TGS tickets for Kerberoasting. Hashes can be cracked offline "
        "to recover service account passwords."
    ),
    parameters={
        "type": "object",
        "properties": {
            "dc_ip":    {"type": "string", "description": "Domain controller IP"},
            "domain":   {"type": "string", "description": "AD domain name"},
            "username": {"type": "string", "description": "Domain username (required for SPN enumeration)"},
            "password": {"type": "string", "description": "Domain password"},
        },
        "required": ["dc_ip", "domain"],
    },
)

def run_impacket_spns(args: dict, config: dict, timeout: int = 60) -> str:
    dc_ip    = args.get("dc_ip", "")
    domain   = args.get("domain", "")
    username = args.get("username", "")
    password = args.get("password", "")
    if not dc_ip or not domain:
        return "ERROR: dc_ip and domain are required"

    script = _find_impacket_script("GetUserSPNs.py")
    if not script:
        return "ERROR: impacket GetUserSPNs.py not found"

    if username:
        creds = f"{domain}/{username}:{password}" if password else f"{domain}/{username}"
    else:
        creds = f"{domain}/"

    cmd = [script, creds, "-dc-ip", dc_ip, "-request"]
    if not username:
        cmd.append("-no-pass")

    return _truncate(_run_subprocess(cmd, timeout))


# ---------------------------------------------------------------------------
# 14. smbclient_shares — list and probe SMB share contents
# ---------------------------------------------------------------------------

SMBCLIENT_SHARES_TOOL = Tool(
    name="smbclient_shares",
    description=(
        "Connect to a specific SMB share and list its contents. "
        "Use after smb_enum finds accessible shares. "
        "Can reveal sensitive files (credentials, configs, backups)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "host":      {"type": "string", "description": "Target IP or hostname"},
            "share":     {"type": "string", "description": "Share name, e.g. 'ADMIN$', 'C$', 'IPC$', 'Users'"},
            "username":  {"type": "string", "description": "SMB username (empty for null session)"},
            "password":  {"type": "string", "description": "SMB password"},
        },
        "required": ["host", "share"],
    },
)

def run_smbclient_shares(args: dict, config: dict, timeout: int = 30) -> str:
    host     = args.get("host", "")
    share    = args.get("share", "")
    username = args.get("username", "")
    password = args.get("password", "")
    if not host or not share:
        return "ERROR: host and share are required"
    if not _which("smbclient"):
        return "ERROR: smbclient not found"

    if username:
        cmd = ["smbclient", f"//{host}/{share}", "-U", f"{username}%{password or ''}", "-c", "ls"]
    else:
        cmd = ["smbclient", f"//{host}/{share}", "-N", "-c", "ls"]

    return _truncate(_run_subprocess(cmd, timeout))


# ---------------------------------------------------------------------------
# 15. hydra_quick — credential brute-force (safe small wordlist)
# ---------------------------------------------------------------------------

# Tiny safe wordlist — only the most common default credentials
_DEFAULT_CREDS = [
    "admin:admin", "admin:password", "admin:1234", "admin:",
    "administrator:administrator", "administrator:password", "administrator:",
    "root:root", "root:toor", "root:password", "root:",
    "guest:guest", "guest:",
    "user:user", "user:password",
    "test:test", "demo:demo",
]

HYDRA_QUICK_TOOL = Tool(
    name="hydra_quick",
    description=(
        "Test a small set of common default credentials against a service. "
        "Protocols: ssh, ftp, smb, rdp, http-get, http-post-form, mysql, mssql, "
        "postgres, vnc, telnet. Uses a built-in 16-entry default-credentials list only "
        "— not a full brute-force. Safe and fast (~30s)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "host":     {"type": "string", "description": "Target IP or hostname"},
            "port":     {"type": "string", "description": "Service port"},
            "protocol": {"type": "string", "description": "Protocol: ssh/ftp/smb/rdp/mysql/postgres/mssql/vnc/telnet/http-get"},
        },
        "required": ["host", "protocol"],
    },
)

def run_hydra_quick(args: dict, config: dict, timeout: int = 60) -> str:
    host     = args.get("host", "")
    port     = args.get("port", "")
    protocol = args.get("protocol", "ssh").lower()
    if not host or not protocol:
        return "ERROR: host and protocol are required"
    if not _which("hydra"):
        return "ERROR: hydra not found — apt-get install hydra"

    # Credential spray: creds confirmed valid on an earlier host in the same
    # network scan (--credential-spray) are tried first, ahead of the
    # built-in default-creds list.
    extra_creds = config.get("tools", {}).get("hydra", {}).get("extra_creds", [])
    creds = list(dict.fromkeys(extra_creds + _DEFAULT_CREDS))  # de-dup, keep order

    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as uf:
        uf.write("\n".join(u.split(":")[0] for u in creds))
        user_file = uf.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as pf:
        pf.write("\n".join(u.split(":", 1)[1] for u in creds))
        pass_file = pf.name

    cmd = ["hydra", "-L", user_file, "-P", pass_file,
           "-t", "4", "-f",      # stop after first valid
           "-e", "nsr",          # try null, same-as-user, reversed
           "-o", "/dev/stdout"]
    if port:
        cmd += ["-s", str(port)]
    cmd += [host, protocol]

    out = _run_subprocess(cmd, timeout)
    # Clean up temp files
    for f in (user_file, pass_file):
        try:
            _os.unlink(f)
        except Exception:
            pass
    return _truncate(out)


# ---------------------------------------------------------------------------
# 16. snmp_enum — SNMP community string enumeration and walk
# ---------------------------------------------------------------------------

SNMP_ENUM_TOOL = Tool(
    name="snmp_enum",
    description=(
        "Probe a host for SNMP access using common community strings "
        "(public, private, community). If accessible, retrieves system info, "
        "interfaces, running processes, and installed software."
    ),
    parameters={
        "type": "object",
        "properties": {
            "host":      {"type": "string", "description": "Target IP or hostname"},
            "community": {"type": "string", "description": "SNMP community string (default tries public/private/community)"},
            "version":   {"type": "string", "description": "SNMP version: 1, 2c, or 3 (default: 2c)"},
        },
        "required": ["host"],
    },
)

def run_snmp_enum(args: dict, config: dict, timeout: int = 30) -> str:
    host      = args.get("host", "")
    community = args.get("community", "")
    version   = args.get("version", "2c")
    if not host:
        return "ERROR: host is required"

    communities = [community] if community else ["public", "private", "community", "manager"]
    results = []

    for c in communities:
        if _which("snmpwalk"):
            cmd = ["snmpwalk", f"-v{version}", "-c", c, "-t", "3", "-r", "1",
                   host, "1.3.6.1.2.1.1"]   # system MIB only for speed
            out = _run_subprocess(cmd, min(timeout, 10))
            if "No Such Object" not in out and "Timeout" not in out and "ERROR" not in out:
                results.append(f"Community '{c}' accessible:\n{out}")
                break   # found a working community — no need to try more
        elif _which("nmap"):
            cmd = ["nmap", "-sU", "-p", "161", "--script=snmp-info,snmp-sysdescr",
                   f"--script-args=snmpcommunity={c}", host]
            out = _run_subprocess(cmd, min(timeout, 20))
            results.append(out)
            break

    return _truncate("\n".join(results) if results else "No SNMP access found with common community strings")


# ---------------------------------------------------------------------------
# 17. banner_grab — raw TCP banner grab
# ---------------------------------------------------------------------------

BANNER_GRAB_TOOL = Tool(
    name="banner_grab",
    description=(
        "Connect to a TCP port and grab the service banner. "
        "Works on any protocol — SSH, FTP, SMTP, Telnet, custom services. "
        "No authentication. Returns raw banner text."
    ),
    parameters={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Target IP or hostname"},
            "port": {"type": "integer", "description": "TCP port to connect to"},
        },
        "required": ["host", "port"],
    },
)

def run_banner_grab(args: dict, config: dict, timeout: int = 10) -> str:
    host = args.get("host", "")
    port = int(args.get("port", 0))
    if not host or not port:
        return "ERROR: host and port are required"
    try:
        with _socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Send a generic probe to elicit a banner
            try:
                s.sendall(b"\r\n")
            except Exception:
                pass
            try:
                banner = s.recv(2048).decode("utf-8", errors="replace").strip()
            except Exception:
                banner = ""
        return f"Banner from {host}:{port}\n{banner}" if banner else f"Connected to {host}:{port} but no banner returned"
    except _socket.timeout:
        return f"ERROR: connection to {host}:{port} timed out"
    except ConnectionRefusedError:
        return f"ERROR: connection refused on {host}:{port}"
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# Update registries
# ---------------------------------------------------------------------------

ALL_TOOLS.update({
    "nmap_script":         (NMAP_SCRIPT_TOOL,         run_nmap_script),
    "smb_enum":            (SMB_ENUM_TOOL,             run_smb_enum),
    "rdp_check":           (RDP_CHECK_TOOL,            run_rdp_check),
    "impacket_npusers":    (IMPACKET_NPUSERS_TOOL,     run_impacket_npusers),
    "impacket_spns":       (IMPACKET_SPNS_TOOL,        run_impacket_spns),
    "smbclient_shares":    (SMBCLIENT_SHARES_TOOL,     run_smbclient_shares),
    "hydra_quick":         (HYDRA_QUICK_TOOL,          run_hydra_quick),
    "snmp_enum":           (SNMP_ENUM_TOOL,            run_snmp_enum),
    "banner_grab":         (BANNER_GRAB_TOOL,          run_banner_grab),
})

CLASS_TOOLS.update({
    # Windows / SMB
    "smb_enum":           ["smb_enum", "nmap_script"],
    "smb_vuln":           ["nmap_script"],
    "smb_signing":        ["nmap_script"],
    "null_session":       ["smb_enum"],
    "anonymous_smb":      ["smb_enum", "smbclient_shares"],
    "rdp_info":           ["rdp_check"],
    "rdp_vuln":           ["rdp_check", "nmap_script"],
    "default_creds":      ["hydra_quick"],
    # Active Directory
    "ad_enum":            ["nmap_script", "smb_enum"],
    "kerberoast":         ["impacket_spns"],
    "asreproast":         ["impacket_npusers"],
    "ad_null_bind":       ["nmap_script"],
    "ad_password_policy": ["nmap_script"],
    # Linux services
    "ssh_audit":          ["nmap_script", "banner_grab"],
    "ftp_anon":           ["nmap_script", "banner_grab"],
    "snmp_enum":          ["snmp_enum"],
    "smtp_enum":          ["nmap_script", "banner_grab"],
    "db_enum":            ["nmap_script", "banner_grab"],
    "banner_info":        ["banner_grab"],
    # Generic
    "open_service":       ["banner_grab", "nmap_script"],
    "firewall_bypass":    ["nmap_script"],
})

# Extend binary_map for available_tools()
_EXTRA_BINARY_MAP = {
    "nmap_script":      "nmap",
    "smb_enum":         "smbclient",
    "rdp_check":        "nmap",
    "smbclient_shares": "smbclient",
    "hydra_quick":      "hydra",
    "snmp_enum":        "snmpwalk",
    "banner_grab":      None,     # pure Python
    "impacket_npusers": None,     # checked via _find_impacket_script
    "impacket_spns":    None,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_impacket_script(name: str) -> str | None:
    """Locate an impacket script in the venv or system path."""
    import sys
    # Check venv bin first
    venv_bin = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                             ".venv", "bin", name)
    if _os.path.exists(venv_bin):
        return venv_bin
    # Check PATH
    import shutil as _shutil2
    found = _shutil2.which(name)
    if found:
        return found
    # Check alongside Python executable
    py_bin = _os.path.dirname(sys.executable)
    candidate = _os.path.join(py_bin, name)
    if _os.path.exists(candidate):
        return candidate
    return None
