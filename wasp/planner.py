"""
Phase 0: Planner — one LLM call, produces an ordered hypothesis list.

The planner sees the recon facts and returns up to N attack hypotheses.
Each hypothesis has a vuln_class, a priority, and a concrete endpoint hint.

Keeping this to a single LLM call means it costs ~2 seconds and ~600 tokens.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from wasp.llm import OllamaClient, Tool
from wasp.recon import ReconFacts


# ---------------------------------------------------------------------------
# Data type
# ---------------------------------------------------------------------------

@dataclass
class Hypothesis:
    vuln_class: str       # maps to CLASS_TOOLS in tools.py
    priority: int         # 1 = highest
    endpoint: str         # concrete URL or path hint
    rationale: str        # one sentence why this is worth probing

    @property
    def key(self) -> str:
        """Stable dedup key."""
        return f"{self.vuln_class}:{self.endpoint}"


# Vulnerability classes the planner is allowed to emit
VALID_CLASSES = {
    # Web
    "sqli", "auth_bypass", "jwt_attack", "idor", "mass_assignment",
    "path_traversal", "lfi", "xss_reflected", "xss_stored",
    "security_misconfig", "outdated_components", "info_disclosure", "tls_weak",
    # Windows / SMB
    "smb_enum", "smb_vuln", "smb_signing", "null_session",
    "anonymous_smb", "rdp_info", "rdp_vuln", "default_creds",
    # Active Directory
    "ad_enum", "kerberoast", "asreproast", "ad_null_bind", "ad_password_policy",
    # Linux / services
    "ssh_audit", "ftp_anon", "snmp_enum", "smtp_enum", "db_enum", "banner_info",
    # Generic
    "open_service", "firewall_bypass",
}

# Default hypotheses used when the LLM fails — these always apply to Juice Shop
_FALLBACK_HYPOTHESES = [
    Hypothesis("sqli",            1, "/rest/user/login",   "Login endpoint commonly vulnerable to SQLi auth bypass"),
    Hypothesis("idor",            2, "/rest/basket/1",     "Basket endpoint likely uses sequential IDs"),
    Hypothesis("lfi",             3, "/ftp",               "FTP directory listing often exposed"),
    Hypothesis("mass_assignment", 4, "/api/Users",         "User registration may accept role field"),
    Hypothesis("jwt_attack",      5, "/rest/user/login",   "App uses JWT; alg:none attack worth testing"),
    Hypothesis("security_misconfig", 6, "/",              "Check security headers and verbose errors"),
    Hypothesis("tls_weak",        7, "/",                 "Check for weak TLS ciphers/protocols and cert expiry"),
]

_FALLBACK_WINDOWS = [
    Hypothesis("smb_enum",    1, "/",     "Enumerate SMB shares and users via null session"),
    Hypothesis("smb_vuln",    2, "/",     "Check for EternalBlue (MS17-010) and other SMB CVEs"),
    Hypothesis("null_session",3, "/",     "Test for anonymous SMB null session access"),
    Hypothesis("rdp_info",    4, "/",     "Fingerprint RDP service and check encryption"),
    Hypothesis("default_creds",5,"/",     "Test common default credentials on SMB/RDP"),
    Hypothesis("smb_signing", 6, "/",     "Check if SMB signing is disabled (relay attack risk)"),
]

_FALLBACK_AD = [
    Hypothesis("ad_enum",         1, "/", "Enumerate AD users, computers, and groups via LDAP"),
    Hypothesis("asreproast",      2, "/", "Find accounts without Kerberos pre-auth (AS-REP roasting)"),
    Hypothesis("kerberoast",      3, "/", "Enumerate service accounts with SPNs (Kerberoasting)"),
    Hypothesis("ad_null_bind",    4, "/", "Test for anonymous LDAP bind"),
    Hypothesis("smb_vuln",        5, "/", "Check DC for SMB vulnerabilities"),
    Hypothesis("ad_password_policy",6,"/","Enumerate password policy via LDAP"),
]

_FALLBACK_LINUX = [
    Hypothesis("ssh_audit",   1, "/",  "Audit SSH configuration and supported algorithms"),
    Hypothesis("ftp_anon",    2, "/",  "Check for anonymous FTP access"),
    Hypothesis("snmp_enum",   3, "/",  "Test SNMP with common community strings"),
    Hypothesis("banner_info", 4, "/",  "Grab service banners for version disclosure"),
    Hypothesis("default_creds",5,"/",  "Test default credentials on SSH and FTP"),
    Hypothesis("smtp_enum",   6, "/",  "Enumerate SMTP users if mail server present"),
]

_FALLBACK_ROUTER = [
    Hypothesis("default_creds",  1, "/", "Test default router credentials on web interface"),
    Hypothesis("info_disclosure",2, "/", "Check for exposed config, firmware version, credentials"),
    Hypothesis("security_misconfig",3,"/","Check for open telnet, unencrypted management"),
    Hypothesis("snmp_enum",      4, "/", "Test SNMP with default community strings"),
    Hypothesis("ssh_audit",      5, "/", "Audit SSH if management port is open"),
    Hypothesis("banner_info",    6, "/", "Grab banners from all open ports"),
    Hypothesis("tls_weak",       7, "/", "Check router's HTTPS admin panel for weak TLS"),
]

_FALLBACK_BY_TYPE = {
    "web":       _FALLBACK_HYPOTHESES,
    "windows":   _FALLBACK_WINDOWS,
    "activedir": _FALLBACK_AD,
    "linux":     _FALLBACK_LINUX,
    "router":    _FALLBACK_ROUTER,
    "database":  [
        Hypothesis("db_enum",      1, "/", "Enumerate database version and accessible databases"),
        Hypothesis("default_creds",2, "/", "Test default database credentials"),
        Hypothesis("banner_info",  3, "/", "Grab database service banner for version info"),
    ],
}


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_SYSTEM = """You are a penetration tester on an authorized engagement.
Your task: analyse recon data and identify the most likely vulnerabilities.
Reply ONLY with a JSON array. No explanation outside the JSON."""

_PROMPT_TEMPLATE = """Target: {target_url}
Target type: {target_type}

Recon findings:
{recon_summary}

Available vulnerability classes: {classes}

Return a JSON array of up to {max_n} hypotheses for a {target_type} target,
ordered by likelihood. Each item must have exactly these fields:
  "vuln_class"  : one of the available classes above (choose classes appropriate for {target_type})
  "priority"    : integer 1-{max_n} (1 = most likely)
  "endpoint"    : for web: specific URL path; for network services: "/" for the host itself
  "rationale"   : one sentence explaining why

JSON array:"""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def plan_hypotheses(
    facts: ReconFacts,
    llm: OllamaClient,
    config: dict,
    target_type: str = "web",
) -> list[Hypothesis]:
    max_n = config.get("lite", {}).get("max_hypotheses", 6)

    prompt = _PROMPT_TEMPLATE.format(
        target_url   = facts.target_url,
        target_type  = target_type,
        recon_summary= facts.to_summary(),
        classes      = ", ".join(sorted(VALID_CLASSES)),
        max_n        = max_n,
    )

    try:
        resp = llm.complete(system=_SYSTEM, prompt=prompt)
        hypotheses = _parse_response(resp.text, facts.target_url, max_n)
        if hypotheses:
            return hypotheses
    except Exception:
        pass

    fallback = _FALLBACK_BY_TYPE.get(target_type, _FALLBACK_HYPOTHESES)
    return fallback[:max_n]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_response(text: str, base_url: str, max_n: int) -> list[Hypothesis]:
    """
    Extract a JSON array from the LLM response.
    Tolerates markdown code fences and extra prose before/after the array.
    """
    # Strip markdown fences
    clean = re.sub(r"```(?:json)?\s*", "", text).strip()

    # Find first [ … ] block
    start = clean.find("[")
    end   = clean.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []

    raw_json = clean[start : end + 1]

    try:
        items = json.loads(raw_json)
    except json.JSONDecodeError:
        # Try to salvage by removing trailing commas (common LLM mistake)
        raw_json = re.sub(r",\s*([}\]])", r"\1", raw_json)
        try:
            items = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

    if not isinstance(items, list):
        return []

    hypotheses: list[Hypothesis] = []
    for i, item in enumerate(items[:max_n]):
        if not isinstance(item, dict):
            continue

        vuln_class = str(item.get("vuln_class", "")).lower().strip()
        if vuln_class not in VALID_CLASSES:
            # Try to map partial matches
            vuln_class = _fuzzy_class(vuln_class)
            if not vuln_class:
                continue

        endpoint = str(item.get("endpoint", "/")).strip()
        # Make sure endpoint starts with /
        if not endpoint.startswith("/") and not endpoint.startswith("http"):
            endpoint = "/" + endpoint
        # If it's a full URL, keep it; if a path, it stays as a path
        # (probe.py will join it with the base URL)

        hypotheses.append(Hypothesis(
            vuln_class = vuln_class,
            priority   = int(item.get("priority", i + 1)),
            endpoint   = endpoint,
            rationale  = str(item.get("rationale", ""))[:200],
        ))

    # Sort by priority ascending
    hypotheses.sort(key=lambda h: h.priority)
    return hypotheses


def _fuzzy_class(raw: str) -> str:
    """Map common LLM variations to valid class names."""
    _MAP = {
        "sql":          "sqli",
        "sql_injection": "sqli",
        "injection":    "sqli",
        "sql injection": "sqli",
        "authentication": "auth_bypass",
        "broken_auth":  "auth_bypass",
        "jwt":          "jwt_attack",
        "jwtattack":    "jwt_attack",
        "insecure_direct": "idor",
        "broken_access": "idor",
        "path":         "path_traversal",
        "traversal":    "path_traversal",
        "directory":    "lfi",
        "xss":          "xss_reflected",
        "cross_site":   "xss_reflected",
        "misconfiguration": "security_misconfig",
        "misconfig":    "security_misconfig",
        "mass":         "mass_assignment",
        "outdated":     "outdated_components",
        "cve":          "outdated_components",
        "disclosure":   "info_disclosure",
        "information":  "info_disclosure",
    }
    for key, val in _MAP.items():
        if key in raw:
            return val
    return ""
