"""
Phase 1: Deterministic recon — zero LLM calls.

Runs httpx probe + nmap port scan + gobuster dir discovery in parallel
threads. Returns a ReconFacts dataclass that feeds both the planner
prompt and each probe prompt.

All three tools run concurrently; the phase is done when all three
finish or their individual timeouts expire.
"""

from __future__ import annotations

import re
import json
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx as _httpx


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class ReconFacts:
    target_url: str
    host: str
    port: int
    scheme: str

    # httpx results
    status_code: int               = 0
    server_banner: str             = ""
    technologies: list[str]        = field(default_factory=list)
    interesting_headers: dict      = field(default_factory=dict)
    body_preview: str              = ""

    # nmap results
    open_ports: list[int]          = field(default_factory=list)
    port_services: dict[int, str]  = field(default_factory=dict)

    # gobuster results
    endpoints: list[str]           = field(default_factory=list)
    login_endpoints: list[str]     = field(default_factory=list)
    upload_endpoints: list[str]    = field(default_factory=list)
    api_endpoints: list[str]       = field(default_factory=list)
    interesting_files: list[str]   = field(default_factory=list)

    # timing
    elapsed_s: float               = 0.0

    def to_summary(self) -> str:
        """
        Compact text summary injected into planner and probe prompts.
        Kept under 400 tokens.
        """
        lines = [f"Target: {self.target_url}"]

        if self.status_code:
            lines.append(f"HTTP status: {self.status_code}")
        if self.server_banner:
            lines.append(f"Server: {self.server_banner}")
        if self.technologies:
            lines.append(f"Technologies: {', '.join(self.technologies)}")
        if self.interesting_headers:
            for k, v in list(self.interesting_headers.items())[:6]:
                lines.append(f"Header {k}: {v}")

        if self.open_ports:
            svc = [f"{p}({self.port_services.get(p,'')})" for p in self.open_ports[:10]]
            lines.append(f"Open ports: {', '.join(svc)}")

        if self.login_endpoints:
            lines.append(f"Login endpoints: {', '.join(self.login_endpoints[:5])}")
        if self.upload_endpoints:
            lines.append(f"Upload endpoints: {', '.join(self.upload_endpoints[:3])}")
        if self.api_endpoints:
            lines.append(f"API endpoints ({len(self.api_endpoints)} found): "
                         + ", ".join(self.api_endpoints[:8]))
        if self.interesting_files:
            lines.append(f"Interesting files: {', '.join(self.interesting_files[:5])}")
        if self.endpoints:
            lines.append(f"Total endpoints discovered: {len(self.endpoints)}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_recon(target_url: str, config: dict, timeout: int = 90) -> ReconFacts:
    """
    Run httpx + nmap + gobuster in parallel threads.
    Returns a ReconFacts even if individual tools fail.
    """
    parsed = urlparse(target_url)
    host   = parsed.hostname or target_url
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = parsed.scheme or "http"

    facts = ReconFacts(
        target_url=target_url,
        host=host,
        port=port,
        scheme=scheme,
    )

    t0 = time.monotonic()

    errors: dict[str, str] = {}

    def probe_http():
        try:
            _probe_http(facts, config, timeout=min(timeout, 20))
        except Exception as exc:
            errors["http"] = str(exc)

    def probe_nmap():
        try:
            _probe_nmap(facts, config, timeout=min(timeout, 40))
        except Exception as exc:
            errors["nmap"] = str(exc)

    def probe_gobuster():
        try:
            _probe_gobuster(facts, config, timeout=min(timeout, 80))
        except Exception as exc:
            errors["gobuster"] = str(exc)

    threads = [
        threading.Thread(target=probe_http,     daemon=True),
        threading.Thread(target=probe_nmap,      daemon=True),
        threading.Thread(target=probe_gobuster,  daemon=True),
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 5)

    facts.elapsed_s = time.monotonic() - t0
    return facts


# ---------------------------------------------------------------------------
# Individual probes
# ---------------------------------------------------------------------------

def _probe_http(facts: ReconFacts, config: dict, timeout: int = 20) -> None:
    """Fingerprint the target with a direct HTTP GET."""
    tool_cfg = config.get("tools", {}).get("httpx", {})
    follow   = tool_cfg.get("follow_redirects", True)

    # Try CLI httpx first — richer output
    if shutil.which("httpx"):
        cmd = [
            "httpx",
            "-u", facts.target_url,
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-content-type",
            "-json",
            "-timeout", str(timeout),
            "-threads", "1",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
            if result.stdout:
                _parse_httpx_json(facts, result.stdout)
                return
        except Exception:
            pass  # fall through to pure-Python

    # Pure-Python fallback
    try:
        with _httpx.Client(timeout=timeout, verify=False, follow_redirects=follow) as client:
            r = client.get(facts.target_url)

        facts.status_code = r.status_code
        facts.body_preview = r.text[:600]

        _INTERESTING = {
            "server", "x-powered-by", "x-generator", "x-aspnet-version",
            "x-frame-options", "content-security-policy", "strict-transport-security",
            "x-content-type-options", "x-xss-protection", "access-control-allow-origin",
        }
        for h, v in r.headers.items():
            hl = h.lower()
            if hl in _INTERESTING:
                facts.interesting_headers[h] = v
            if hl in ("server", "x-powered-by", "x-generator"):
                facts.technologies.append(v)
                if not facts.server_banner:
                    facts.server_banner = v

        # Sniff tech from body
        body_lower = r.text[:2000].lower()
        _TECH_HINTS = [
            ("angular",  "AngularJS"),
            ("react",    "React"),
            ("vue",      "Vue.js"),
            ("express",  "Express"),
            ("django",   "Django"),
            ("laravel",  "Laravel"),
            ("wordpress","WordPress"),
            ("drupal",   "Drupal"),
            ("jquery",   "jQuery"),
        ]
        for marker, name in _TECH_HINTS:
            if marker in body_lower and name not in facts.technologies:
                facts.technologies.append(name)

    except Exception:
        pass


def _parse_httpx_json(facts: ReconFacts, raw: str) -> None:
    """Parse a single-line JSON output from httpx -json."""
    for line in raw.strip().splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        facts.status_code = obj.get("status_code", 0)
        facts.server_banner = obj.get("webserver", "")
        tech = obj.get("tech", []) or []
        if isinstance(tech, list):
            facts.technologies = tech
        elif isinstance(tech, str):
            facts.technologies = [tech]
        # httpx doesn't return full headers in JSON mode; populate what we have
        if facts.server_banner:
            facts.interesting_headers["Server"] = facts.server_banner
        return


def _probe_nmap(facts: ReconFacts, config: dict, timeout: int = 40) -> None:
    if not shutil.which("nmap"):
        return

    tool_cfg = config.get("tools", {}).get("nmap", {})
    rate     = tool_cfg.get("rate", 500)

    cmd = [
        "nmap", "-T4", "--min-rate", str(rate),
        "--top-ports", "100",
        "-sV", "--open", "-oG", "-",
        facts.host,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        _parse_nmap_greppable(facts, result.stdout)
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass


def _parse_nmap_greppable(facts: ReconFacts, raw: str) -> None:
    """Parse nmap -oG (greppable) output into facts."""
    port_re = re.compile(r"(\d+)/open/tcp//([^/]*)")
    for line in raw.splitlines():
        if "Ports:" in line:
            for match in port_re.finditer(line):
                port    = int(match.group(1))
                service = match.group(2).strip()
                facts.open_ports.append(port)
                facts.port_services[port] = service


def _probe_gobuster(facts: ReconFacts, config: dict, timeout: int = 80) -> None:
    if not shutil.which("gobuster"):
        _fallback_path_probe(facts, config, timeout)
        return

    import os
    tool_cfg = config.get("tools", {}).get("gobuster", {})
    threads  = tool_cfg.get("threads", 10)

    # Locate wordlist
    wordlist = config.get("lite", {}).get("wordlist", "")
    if not wordlist or not os.path.exists(wordlist):
        module_dir = os.path.dirname(__file__)
        wordlist = os.path.join(module_dir, "wordlist.txt")

    if not os.path.exists(wordlist):
        _fallback_path_probe(facts, config, timeout)
        return

    # First probe the base URL to get the wildcard response length
    # (SPAs like Juice Shop return 200 for every unknown path)
    wildcard_len = _get_wildcard_length(facts.target_url)

    cmd = [
        "gobuster", "dir",
        "-u", facts.target_url,
        "-w", wordlist,
        "-t", str(threads),
        "-q", "--no-error",
        "--timeout", "10s",
    ]

    # Exclude wildcard length to suppress SPA false positives
    if wildcard_len is not None:
        cmd += ["--exclude-length", str(wildcard_len)]
    else:
        # Fallback: exclude common SPA catchall status if no wildcard detected
        cmd += ["-b", "404,400"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        _parse_gobuster_output(facts, result.stdout)
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    # If gobuster found nothing (SPA masked everything), fall back to direct probing
    if not facts.endpoints:
        _fallback_path_probe(facts, config, timeout)


def _get_wildcard_length(base_url: str) -> int | None:
    """
    Probe a random non-existent path to detect SPA wildcard responses.
    Returns the response body length if the server returns 200 for garbage paths,
    so gobuster can exclude that length.
    """
    import uuid
    try:
        probe_url = base_url.rstrip("/") + "/" + uuid.uuid4().hex
        with _httpx.Client(timeout=5, verify=False, follow_redirects=True) as client:
            r = client.get(probe_url)
        if r.status_code == 200:
            return len(r.content)
    except Exception:
        pass
    return None


def _parse_gobuster_output(facts: ReconFacts, raw: str) -> None:
    """
    Gobuster lines look like:
      /rest                 (Status: 200) [Size: 1234]
      /ftp                  (Status: 200) [Size: 0]
    """
    status_re = re.compile(r"^(/\S+)\s+\(Status:\s*(\d+)\)")
    _LOGIN_KW    = {"login", "signin", "auth", "session", "token", "oauth"}
    _UPLOAD_KW   = {"upload", "file", "import", "attachment", "media"}
    _INTEREST_KW = {"env", "git", "config", "backup", "dump", "secret",
                    "key", "admin", "debug", "console", "swagger", "ftp",
                    "package", "actuator"}

    for line in raw.splitlines():
        m = status_re.match(line.strip())
        if not m:
            continue
        path   = m.group(1)
        status = int(m.group(2))
        if status in (200, 201, 301, 302, 401, 403):
            facts.endpoints.append(path)
            low = path.lower()
            if any(kw in low for kw in _LOGIN_KW):
                facts.login_endpoints.append(path)
            if any(kw in low for kw in _UPLOAD_KW):
                facts.upload_endpoints.append(path)
            if low.startswith("/api") or low.startswith("/rest"):
                facts.api_endpoints.append(path)
            if any(kw in low for kw in _INTEREST_KW):
                facts.interesting_files.append(path)


def _fallback_path_probe(facts: ReconFacts, config: dict, timeout: int) -> None:
    """
    When gobuster is unavailable, probe a short list of high-value paths
    directly with httpx library.
    """
    HIGH_VALUE = [
        "/ftp", "/rest/user/login", "/api/Users", "/rest/basket",
        "/rest/products", "/admin", "/.env", "/.git/HEAD",
        "/package.json", "/encryptionkeys/jwt.pub", "/api/challenges",
        "/rest/currentUser", "/rest/admin", "/robots.txt",
    ]
    deadline = time.monotonic() + timeout
    try:
        with _httpx.Client(timeout=5, verify=False, follow_redirects=False) as client:
            for path in HIGH_VALUE:
                if time.monotonic() > deadline:
                    break
                url = facts.target_url.rstrip("/") + path
                try:
                    r = client.get(url)
                    if r.status_code not in (404,):
                        facts.endpoints.append(path)
                        low = path.lower()
                        if any(kw in low for kw in ("login", "auth")):
                            facts.login_endpoints.append(path)
                        if any(kw in low for kw in ("upload", "file")):
                            facts.upload_endpoints.append(path)
                        if low.startswith("/api") or low.startswith("/rest"):
                            facts.api_endpoints.append(path)
                except Exception:
                    pass
    except Exception:
        pass



# ===========================================================================
# Per-type recon dispatchers
# ===========================================================================

def run_recon_for_type(target: str, target_type: str, config: dict,
                       timeout: int = 90) -> "ReconFacts":
    """
    Dispatch to the appropriate recon module based on target_type.
    Falls back to run_recon (web) for unknown types.
    """
    if target_type in ("windows", "activedir"):
        return run_windows_recon(target, config, timeout)
    elif target_type == "linux":
        return run_linux_recon(target, config, timeout)
    elif target_type == "router":
        return run_router_recon(target, config, timeout)
    elif target_type == "database":
        return run_db_recon(target, config, timeout)
    elif target_type == "web":
        return run_recon(target, config, timeout)
    else:
        # Generic: port scan + banner grab
        return run_generic_recon(target, config, timeout)


# ---------------------------------------------------------------------------
# Windows / Active Directory recon
# ---------------------------------------------------------------------------

def run_windows_recon(target: str, config: dict, timeout: int = 90) -> ReconFacts:
    """
    Windows-focused recon: full port scan, SMB enumeration, RDP check,
    NetBIOS/LDAP probe, OS detection via SMB.
    """
    parsed = urlparse(target.replace("smb://", "http://"))
    host   = parsed.hostname or target.split(":")[0]
    port   = parsed.port or 445
    facts  = ReconFacts(target_url=target, host=host, port=port, scheme="smb")
    t0     = time.monotonic()

    errors: dict[str, str] = {}

    def probe_ports():
        try:
            _windows_port_scan(facts, config, min(timeout, 40))
        except Exception as e:
            errors["ports"] = str(e)

    def probe_smb():
        try:
            _windows_smb_probe(facts, config, min(timeout, 50))
        except Exception as e:
            errors["smb"] = str(e)

    def probe_rdp():
        try:
            _windows_rdp_probe(facts, config, min(timeout, 20))
        except Exception as e:
            errors["rdp"] = str(e)

    threads = [
        threading.Thread(target=probe_ports, daemon=True),
        threading.Thread(target=probe_smb,   daemon=True),
        threading.Thread(target=probe_rdp,   daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 5)

    facts.elapsed_s = time.monotonic() - t0
    return facts


def _windows_port_scan(facts: ReconFacts, config: dict, timeout: int) -> None:
    if not shutil.which("nmap"):
        return
    # Windows-specific ports
    ports = "22,53,80,88,135,139,389,443,445,464,593,636,3268,3269,3389,5985,5986,8080,8443,9389,49152-49155"
    cmd = ["nmap", "-T4", "--min-rate", "1000", "-p", ports,
           "-sV", "--open", "-oG", "-", facts.host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        _parse_nmap_greppable(facts, r.stdout)
        # Detect AD from ports
        if {88, 389} <= set(facts.open_ports):
            facts.technologies.append("ActiveDirectory")
        if 3389 in facts.open_ports:
            facts.technologies.append("RDP")
        if 5985 in facts.open_ports:
            facts.technologies.append("WinRM")
    except Exception:
        pass


def _windows_smb_probe(facts: ReconFacts, config: dict, timeout: int) -> None:
    """Run nmap SMB scripts to fingerprint the host."""
    if not shutil.which("nmap"):
        return
    scripts = "smb-os-discovery,smb-security-mode,smb2-security-mode,smb-enum-shares,nbstat"
    cmd = ["nmap", "-T4", "-p", "139,445",
           f"--script={scripts}", "-oN", "-", facts.host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = r.stdout + r.stderr

        # Extract OS info
        for line in output.splitlines():
            ll = line.strip()
            if "OS:" in ll or "Computer name:" in ll or "Domain name:" in ll:
                facts.server_banner += ll + " "
            if "smb-security-mode" in ll.lower() or "message_signing" in ll.lower():
                facts.technologies.append(ll.strip())
            if "Sharename" in ll or "Type" in ll:
                facts.endpoints.append(ll.strip())

        facts.body_preview = _truncate(output, 600)
        facts.interesting_headers["smb_scan"] = output[:300]
    except Exception:
        pass


def _windows_rdp_probe(facts: ReconFacts, config: dict, timeout: int) -> None:
    if not shutil.which("nmap"):
        return
    if 3389 not in facts.open_ports and 3389 != facts.port:
        return
    cmd = ["nmap", "-T4", "-p", "3389",
           "--script=rdp-enum-encryption,rdp-ntlm-info", facts.host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        for line in r.stdout.splitlines():
            if any(kw in line.lower() for kw in ("ntlm", "domain", "computer name", "rdp")):
                facts.technologies.append(line.strip())
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Linux service recon
# ---------------------------------------------------------------------------

def run_linux_recon(target: str, config: dict, timeout: int = 90) -> ReconFacts:
    parsed = urlparse(target.replace("ssh://", "http://"))
    host   = parsed.hostname or target.split(":")[0]
    port   = parsed.port or 22
    facts  = ReconFacts(target_url=target, host=host, port=port, scheme="ssh")
    t0     = time.monotonic()

    def probe_ports():
        if shutil.which("nmap"):
            cmd = ["nmap", "-T4", "--min-rate", "1000",
                   "--top-ports", "200", "-sV", "--open", "-oG", "-", host]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=min(timeout, 40))
                _parse_nmap_greppable(facts, r.stdout)
            except Exception:
                pass

    def probe_banners():
        import socket as _s
        for p in [21, 22, 23, 25, 80, 443, 8080]:
            if p in facts.open_ports or (not facts.open_ports and p == 22):
                try:
                    with _s.create_connection((host, p), timeout=3) as s:
                        s.settimeout(3)
                        try:
                            s.sendall(b"\r\n")
                        except Exception:
                            pass
                        try:
                            b = s.recv(512).decode("utf-8", errors="replace").strip()
                            if b:
                                facts.interesting_headers[f"banner_{p}"] = b[:120]
                                facts.technologies.append(f"port{p}:{b[:60]}")
                        except Exception:
                            pass
                except Exception:
                    pass

    threads = [
        threading.Thread(target=probe_ports,   daemon=True),
        threading.Thread(target=probe_banners, daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 5)

    facts.elapsed_s = time.monotonic() - t0
    return facts


# ---------------------------------------------------------------------------
# Router recon
# ---------------------------------------------------------------------------

def run_router_recon(target: str, config: dict, timeout: int = 60) -> ReconFacts:
    """Quick HTTP + nmap scan for routers/gateways."""
    # Try HTTP interface first
    http_target = target if target.startswith("http") else f"http://{target}"
    facts = run_recon(http_target, config, timeout=min(timeout, 50))
    facts.technologies.append("Router/Gateway")
    return facts


# ---------------------------------------------------------------------------
# Database recon
# ---------------------------------------------------------------------------

def run_db_recon(target: str, config: dict, timeout: int = 60) -> ReconFacts:
    parsed = urlparse(target if "://" in target else f"tcp://{target}")
    host   = parsed.hostname or target.split(":")[0]
    port   = parsed.port or 0
    facts  = ReconFacts(target_url=target, host=host, port=port, scheme="db")
    t0     = time.monotonic()

    if shutil.which("nmap"):
        db_ports = "1433,1521,3306,5432,6379,27017,5984,9200,9300,5000,8086"
        scripts  = "mysql-info,ms-sql-info,oracle-tns-version,redis-info,mongodb-info"
        cmd = ["nmap", "-T4", "-p", db_ports,
               f"--script={scripts}", "--open", "-oG", "-", host]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            _parse_nmap_greppable(facts, r.stdout)
            facts.body_preview = _truncate(r.stdout, 600)
        except Exception:
            pass

    facts.elapsed_s = time.monotonic() - t0
    return facts


# ---------------------------------------------------------------------------
# Generic recon (unknown service type)
# ---------------------------------------------------------------------------

def run_generic_recon(target: str, config: dict, timeout: int = 60) -> ReconFacts:
    """Full port scan + banner grab for unclassified targets."""
    parsed = urlparse(target if "://" in target else f"tcp://{target}")
    host   = parsed.hostname or target.split(":")[0]
    port   = parsed.port
    facts  = ReconFacts(target_url=target, host=host, port=port or 0, scheme="")
    t0     = time.monotonic()

    if shutil.which("nmap"):
        cmd = ["nmap", "-T4", "--min-rate", "1000", "--top-ports", "200",
               "-sV", "--open", "-oG", "-", host]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            _parse_nmap_greppable(facts, r.stdout)
            facts.body_preview = r.stdout[:400]
        except Exception:
            pass

    facts.elapsed_s = time.monotonic() - t0
    return facts
