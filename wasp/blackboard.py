"""
In-memory finding store.

Intentionally simple: a thread-safe list of findings plus a set of
already-tested hypothesis keys so the probe loop never repeats work.

No Postgres, no pgvector, no migrations. For a 15-minute single-target
scan this is all the persistence we need.
"""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Iterator


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# Severity implied by vulnerability class when the probe doesn't override
_CLASS_SEVERITY: dict[str, Severity] = {
    "sqli":              Severity.CRITICAL,
    "rce":               Severity.CRITICAL,
    "auth_bypass":       Severity.HIGH,
    "jwt_attack":        Severity.HIGH,
    "idor":              Severity.HIGH,
    "mass_assignment":   Severity.HIGH,
    "path_traversal":    Severity.MEDIUM,
    "lfi":                Severity.MEDIUM,
    "xss_reflected":      Severity.MEDIUM,
    "xss_stored":         Severity.HIGH,
    "security_misconfig": Severity.LOW,
    "outdated_components":Severity.LOW,
    "info_disclosure":    Severity.INFO,
    # Windows / SMB
    "smb_enum":           Severity.MEDIUM,
    "smb_vuln":           Severity.CRITICAL,
    "smb_signing":        Severity.MEDIUM,
    "rdp_info":           Severity.LOW,
    "rdp_vuln":           Severity.CRITICAL,
    "default_creds":      Severity.HIGH,
    "null_session":       Severity.HIGH,
    "anonymous_smb":      Severity.HIGH,
    # Active Directory
    "ad_enum":            Severity.MEDIUM,
    "kerberoast":         Severity.HIGH,
    "asreproast":         Severity.HIGH,
    "ad_null_bind":       Severity.HIGH,
    "ad_password_policy": Severity.LOW,
    "ad_bloodhound":      Severity.HIGH,
    "ad_pivot":           Severity.CRITICAL,
    # Linux / services
    "ssh_audit":          Severity.LOW,
    "ftp_anon":           Severity.HIGH,
    "snmp_enum":          Severity.MEDIUM,
    "smtp_enum":          Severity.LOW,
    "db_enum":            Severity.HIGH,
    "banner_info":        Severity.INFO,
    # Network / generic
    "open_service":       Severity.INFO,
    "firewall_bypass":    Severity.MEDIUM,
    "tls_weak":           Severity.MEDIUM,
}

def severity_for_class(vuln_class: str) -> Severity:
    return _CLASS_SEVERITY.get(vuln_class.lower(), Severity.MEDIUM)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    vuln_class: str                  # e.g. "sqli", "idor"
    title: str                       # short human-readable label
    severity: Severity
    target_url: str                  # the URL that was probed
    evidence: str                    # raw response excerpt (truncated)
    request_method: str = "GET"
    request_url: str = ""
    request_body: str = ""
    request_headers: dict = field(default_factory=dict)
    description: str = ""            # LLM-generated PoC paragraph (added in report phase)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    # MITRE ATT&CK fields (populated automatically from mitre.py)
    mitre_id: str = ""               # e.g. "T1190"
    mitre_technique: str = ""        # e.g. "Exploit Public-Facing Application"
    mitre_tactic: str = ""           # e.g. "Initial Access"
    mitre_url: str = ""              # link to attack.mitre.org
    cvss: float | None = None        # nuclei template CVSS score, if known
    cve: str = ""                    # CVE ID(s), comma-separated, if known
    exploit_refs: str = ""           # known public exploits (ExploitDB), if any

    @property
    def id(self) -> str:
        """Stable ID used for deduplication."""
        return f"{self.vuln_class}:{self.target_url}"

    def to_dict(self) -> dict:
        """JSON-safe representation (Severity -> str, datetime -> ISO)."""
        d = asdict(self)
        d["severity"]  = self.severity.value
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        """Reverse of to_dict(), used to reload findings from a checkpoint."""
        d = dict(d)
        d["severity"]  = Severity(d["severity"])
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        return cls(**d)


# ---------------------------------------------------------------------------
# Blackboard
# ---------------------------------------------------------------------------

class Blackboard:
    """
    Thread-safe in-memory store for scan findings and probe state.

    Two responsibilities:
    1. Accumulate confirmed Finding objects for the report phase.
    2. Track which hypothesis keys have been tested to prevent re-work.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._findings: list[Finding] = []
        self._tested: set[str] = set()
        self._seen_ids: set[str] = set()

    # --- Findings -----------------------------------------------------------

    def add_finding(self, finding: Finding) -> bool:
        """
        Add a confirmed finding. Returns False if an identical finding
        (same vuln_class + target_url) was already recorded.
        """
        with self._lock:
            if finding.id in self._seen_ids:
                return False
            self._seen_ids.add(finding.id)
            self._findings.append(finding)
            return True

    def findings(self) -> list[Finding]:
        """Return a snapshot of all findings, ordered by severity."""
        _order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        with self._lock:
            return sorted(self._findings, key=lambda f: _order[f.severity])

    def finding_count(self) -> int:
        with self._lock:
            return len(self._findings)

    # --- Hypothesis tracking ------------------------------------------------

    def mark_tested(self, hypothesis_key: str) -> None:
        with self._lock:
            self._tested.add(hypothesis_key)

    def already_tested(self, hypothesis_key: str) -> bool:
        with self._lock:
            return hypothesis_key in self._tested

    def tested_count(self) -> int:
        with self._lock:
            return len(self._tested)

    # --- Summary ------------------------------------------------------------

    def summary(self) -> dict:
        findings = self.findings()
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        return {
            "total_findings": len(findings),
            "by_severity": by_sev,
            "hypotheses_tested": self.tested_count(),
        }


def _self_check():
    import json
    f = Finding(vuln_class="sqli", title="t", severity=Severity.HIGH,
                target_url="http://x", evidence="ev", cvss=9.8)
    d = json.loads(json.dumps(f.to_dict()))
    assert d["severity"] == "high"
    assert isinstance(d["timestamp"], str)
    assert d["cvss"] == 9.8

    f2 = Finding.from_dict(d)
    assert f2.severity == Severity.HIGH
    assert f2.timestamp == f.timestamp
    assert f2.cvss == 9.8
    assert severity_for_class("ad_bloodhound") == Severity.HIGH
    assert severity_for_class("ad_pivot") == Severity.CRITICAL


if __name__ == "__main__":
    _self_check()
    print("ok")
