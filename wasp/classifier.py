"""
Target classifier — infers the target type from nmap port/service output
and the original target string.

Target types:
  web       — HTTP/HTTPS server (default for URLs)
  windows   — Windows host with SMB/RPC exposed
  activedir — Windows host that also looks like a domain controller (LDAP/Kerberos/DNS)
  linux     — Linux host (SSH dominant, no SMB)
  router    — Network device (SSH+HTTP on .1 or known router ports)
  database  — Exposed database port (3306/5432/1433/1521/6379)
  mailserver— SMTP/IMAP/POP3 exposed
  iot       — No standard services, or only unusual embedded ports
  network   — CIDR range, not a single host
  unknown   — Can't classify

The classifier is purely rule-based — no LLM call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Port fingerprint rules
# ---------------------------------------------------------------------------

# Ports that strongly suggest a target type
_WINDOWS_PORTS   = {135, 139, 445, 3389, 5985, 5986, 49152}   # RPC, SMB, RDP, WinRM
_AD_EXTRA_PORTS  = {88, 389, 636, 3268, 3269, 53}              # Kerberos, LDAP, DNS
_LINUX_PORTS     = {22, 2222}                                   # SSH
_WEB_PORTS       = {80, 443, 8080, 8443, 8000, 8888, 3000, 3001, 3002, 8081, 9000}
_DB_PORTS        = {3306, 5432, 1433, 1521, 6379, 27017, 5984, 9200, 9300}
_MAIL_PORTS      = {25, 465, 587, 110, 995, 143, 993}
_ROUTER_PORTS    = {53, 67, 68}

# Services we extract from nmap -sV output
_SERVICE_RE = re.compile(r"(\d+)/open/tcp//([^/\s]*)")


@dataclass
class TargetInfo:
    """Classification result passed to recon and planner."""
    raw: str                        # original string the user passed
    host: str                       # resolved hostname or IP
    port: int | None                # explicit port if given
    scheme: str                     # http/https/smb/ssh/etc. or ''
    target_type: str                # web/windows/activedir/linux/router/database/mailserver/iot/network/unknown
    open_ports: list[int]           = field(default_factory=list)
    services: dict[int, str]        = field(default_factory=dict)
    is_range: bool                  = False
    cidr: str                       = ""

    @property
    def display(self) -> str:
        return f"{self.target_type.upper()} — {self.raw}"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def classify(target: str, nmap_output: str = "") -> TargetInfo:
    """
    Classify a target string (URL, IP, hostname, CIDR) into a TargetInfo.

    nmap_output: greppable nmap output (-oG) if already available.
    If not provided, classification is based on URL scheme and port alone.
    """
    # --- CIDR range? ---
    if re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", target.strip()):
        return TargetInfo(
            raw=target, host=target, port=None, scheme="",
            target_type="network", is_range=True, cidr=target,
        )

    # --- Parse scheme / host / port ---
    scheme, host, port = _parse_target(target)

    # --- Parse nmap output if provided ---
    open_ports, services = _parse_nmap(nmap_output) if nmap_output else ([], {})

    # --- Classify ---
    target_type = _classify(scheme, host, port, open_ports, services)

    return TargetInfo(
        raw=target,
        host=host,
        port=port,
        scheme=scheme,
        target_type=target_type,
        open_ports=open_ports,
        services=services,
    )


def reclassify(info: TargetInfo, nmap_output: str) -> TargetInfo:
    """
    Update an existing TargetInfo once nmap results are available.
    Used by recon to upgrade the initial guess after Phase 1.
    """
    open_ports, services = _parse_nmap(nmap_output)
    new_type = _classify(info.scheme, info.host, info.port, open_ports, services)
    info.open_ports = open_ports
    info.services   = services
    info.target_type = new_type
    return info


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_target(target: str) -> tuple[str, str, int | None]:
    """Return (scheme, host, port) from a raw target string."""
    t = target.strip()

    # Strip protocol
    scheme = ""
    for proto in ("https://", "http://", "smb://", "ssh://", "ftp://", "rdp://", "ldap://", "ldaps://"):
        if t.lower().startswith(proto):
            scheme = proto.rstrip("://")
            t = t[len(proto):]
            break

    # Strip path
    t = t.split("/")[0]

    # Extract port
    port: int | None = None
    if ":" in t and not t.startswith("["):  # not IPv6
        parts = t.rsplit(":", 1)
        try:
            port = int(parts[1])
            t = parts[0]
        except ValueError:
            pass

    host = t

    # Infer scheme from port
    if not scheme and port:
        _PORT_SCHEMES = {
            80: "http", 443: "https", 8080: "http", 8443: "https",
            445: "smb", 139: "smb", 22: "ssh", 3389: "rdp",
            21: "ftp", 25: "smtp", 3306: "mysql", 5432: "postgres",
            1433: "mssql", 6379: "redis", 27017: "mongodb",
            389: "ldap", 636: "ldaps", 88: "kerberos",
        }
        scheme = _PORT_SCHEMES.get(port, "")

    return scheme, host, port


def _parse_nmap(output: str) -> tuple[list[int], dict[int, str]]:
    """Parse ports and services from nmap -oG output."""
    ports: list[int] = []
    services: dict[int, str] = {}
    for line in output.splitlines():
        if "Ports:" not in line:
            continue
        for m in _SERVICE_RE.finditer(line):
            p   = int(m.group(1))
            svc = m.group(2).strip()
            ports.append(p)
            services[p] = svc
    return sorted(set(ports)), services


def _classify(
    scheme: str,
    host: str,
    port: int | None,
    open_ports: list[int],
    services: dict[int, str],
) -> str:
    port_set = set(open_ports)
    if port:
        port_set.add(port)

    # Explicit scheme overrides
    if scheme in ("http", "https"):
        return "web"
    if scheme in ("smb",):
        return "windows"
    if scheme in ("ssh",):
        return "linux"
    if scheme in ("ldap", "ldaps", "kerberos"):
        return "activedir"
    if scheme in ("rdp",):
        return "windows"
    if scheme in ("mysql", "postgres", "mssql", "redis", "mongodb"):
        return "database"
    if scheme in ("smtp", "imap", "pop3"):
        return "mailserver"

    if not port_set:
        # No port info — guess from host string
        if any(x in host.lower() for x in ("dc", "ad", "domain", "ldap", "kerberos")):
            return "activedir"
        return "unknown"

    # Active Directory: Windows ports + Kerberos/LDAP
    if port_set & _WINDOWS_PORTS and port_set & _AD_EXTRA_PORTS:
        return "activedir"

    # Windows: SMB or RPC or RDP visible
    win_score = len(port_set & _WINDOWS_PORTS)
    if win_score >= 2 or 445 in port_set:
        return "windows"

    # Database server
    if port_set & _DB_PORTS and not (port_set & _WEB_PORTS):
        return "database"

    # Mail server
    if port_set & _MAIL_PORTS and not (port_set & _WEB_PORTS):
        return "mailserver"

    # Router / gateway (usually .1, has DNS + HTTP + SSH)
    if 53 in port_set and (80 in port_set or 22 in port_set):
        # Routers typically have very few ports
        if len(port_set) <= 5:
            return "router"

    # Web: HTTP/HTTPS ports visible
    if port_set & _WEB_PORTS:
        return "web"

    # Linux: SSH only
    if port_set & _LINUX_PORTS:
        return "linux"

    # Single port — IoT-ish
    if len(port_set) == 1:
        return "iot"

    return "unknown"
