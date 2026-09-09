"""
MITRE ATT&CK mapping for WASP vulnerability classes.

Each entry maps a vuln_class to:
  - technique_id  : ATT&CK technique (or sub-technique) ID
  - technique     : human-readable technique name
  - tactic        : ATT&CK tactic name
  - tactic_id     : ATT&CK tactic ID (TA-xxxx)
  - url           : direct link to the ATT&CK page

Reference: https://attack.mitre.org  (Enterprise ATT&CK v15)
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class MitreEntry:
    technique_id: str
    technique: str
    tactic: str
    tactic_id: str
    url: str


# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------

_MAPPING: dict[str, MitreEntry] = {

    # ── Web ─────────────────────────────────────────────────────────────────

    "sqli": MitreEntry(
        technique_id = "T1190",
        technique    = "Exploit Public-Facing Application",
        tactic       = "Initial Access",
        tactic_id    = "TA0001",
        url          = "https://attack.mitre.org/techniques/T1190/",
    ),
    "auth_bypass": MitreEntry(
        technique_id = "T1078",
        technique    = "Valid Accounts",
        tactic       = "Defense Evasion / Initial Access",
        tactic_id    = "TA0001",
        url          = "https://attack.mitre.org/techniques/T1078/",
    ),
    "jwt_attack": MitreEntry(
        technique_id = "T1550.001",
        technique    = "Use Alternate Authentication Material: Application Access Token",
        tactic       = "Defense Evasion / Lateral Movement",
        tactic_id    = "TA0005",
        url          = "https://attack.mitre.org/techniques/T1550/001/",
    ),
    "idor": MitreEntry(
        technique_id = "T1530",
        technique    = "Data from Cloud Storage",
        tactic       = "Collection",
        tactic_id    = "TA0009",
        url          = "https://attack.mitre.org/techniques/T1530/",
    ),
    "mass_assignment": MitreEntry(
        technique_id = "T1548",
        technique    = "Abuse Elevation Control Mechanism",
        tactic       = "Privilege Escalation",
        tactic_id    = "TA0004",
        url          = "https://attack.mitre.org/techniques/T1548/",
    ),
    "path_traversal": MitreEntry(
        technique_id = "T1083",
        technique    = "File and Directory Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1083/",
    ),
    "lfi": MitreEntry(
        technique_id = "T1083",
        technique    = "File and Directory Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1083/",
    ),
    "xss_reflected": MitreEntry(
        technique_id = "T1059.007",
        technique    = "Command and Scripting Interpreter: JavaScript",
        tactic       = "Execution",
        tactic_id    = "TA0002",
        url          = "https://attack.mitre.org/techniques/T1059/007/",
    ),
    "xss_stored": MitreEntry(
        technique_id = "T1059.007",
        technique    = "Command and Scripting Interpreter: JavaScript",
        tactic       = "Execution",
        tactic_id    = "TA0002",
        url          = "https://attack.mitre.org/techniques/T1059/007/",
    ),
    "security_misconfig": MitreEntry(
        technique_id = "T1562.001",
        technique    = "Impair Defenses: Disable or Modify Tools",
        tactic       = "Defense Evasion",
        tactic_id    = "TA0005",
        url          = "https://attack.mitre.org/techniques/T1562/001/",
    ),
    "outdated_components": MitreEntry(
        technique_id = "T1190",
        technique    = "Exploit Public-Facing Application",
        tactic       = "Initial Access",
        tactic_id    = "TA0001",
        url          = "https://attack.mitre.org/techniques/T1190/",
    ),
    "info_disclosure": MitreEntry(
        technique_id = "T1552",
        technique    = "Unsecured Credentials",
        tactic       = "Credential Access",
        tactic_id    = "TA0006",
        url          = "https://attack.mitre.org/techniques/T1552/",
    ),

    # ── Windows / SMB ───────────────────────────────────────────────────────

    "smb_enum": MitreEntry(
        technique_id = "T1135",
        technique    = "Network Share Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1135/",
    ),
    "smb_vuln": MitreEntry(
        technique_id = "T1210",
        technique    = "Exploitation of Remote Services",
        tactic       = "Lateral Movement",
        tactic_id    = "TA0008",
        url          = "https://attack.mitre.org/techniques/T1210/",
    ),
    "smb_signing": MitreEntry(
        technique_id = "T1557.001",
        technique    = "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
        tactic       = "Credential Access",
        tactic_id    = "TA0006",
        url          = "https://attack.mitre.org/techniques/T1557/001/",
    ),
    "null_session": MitreEntry(
        technique_id = "T1135",
        technique    = "Network Share Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1135/",
    ),
    "anonymous_smb": MitreEntry(
        technique_id = "T1135",
        technique    = "Network Share Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1135/",
    ),
    "rdp_info": MitreEntry(
        technique_id = "T1046",
        technique    = "Network Service Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1046/",
    ),
    "rdp_vuln": MitreEntry(
        technique_id = "T1210",
        technique    = "Exploitation of Remote Services",
        tactic       = "Lateral Movement",
        tactic_id    = "TA0008",
        url          = "https://attack.mitre.org/techniques/T1210/",
    ),
    "default_creds": MitreEntry(
        technique_id = "T1078.001",
        technique    = "Valid Accounts: Default Accounts",
        tactic       = "Initial Access",
        tactic_id    = "TA0001",
        url          = "https://attack.mitre.org/techniques/T1078/001/",
    ),

    # ── Active Directory ────────────────────────────────────────────────────

    "ad_enum": MitreEntry(
        technique_id = "T1087.002",
        technique    = "Account Discovery: Domain Account",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1087/002/",
    ),
    "kerberoast": MitreEntry(
        technique_id = "T1558.003",
        technique    = "Steal or Forge Kerberos Tickets: Kerberoasting",
        tactic       = "Credential Access",
        tactic_id    = "TA0006",
        url          = "https://attack.mitre.org/techniques/T1558/003/",
    ),
    "asreproast": MitreEntry(
        technique_id = "T1558.004",
        technique    = "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        tactic       = "Credential Access",
        tactic_id    = "TA0006",
        url          = "https://attack.mitre.org/techniques/T1558/004/",
    ),
    "ad_null_bind": MitreEntry(
        technique_id = "T1087.002",
        technique    = "Account Discovery: Domain Account",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1087/002/",
    ),
    "ad_password_policy": MitreEntry(
        technique_id = "T1201",
        technique    = "Password Policy Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1201/",
    ),

    # ── Linux / services ────────────────────────────────────────────────────

    "ssh_audit": MitreEntry(
        technique_id = "T1046",
        technique    = "Network Service Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1046/",
    ),
    "ftp_anon": MitreEntry(
        technique_id = "T1083",
        technique    = "File and Directory Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1083/",
    ),
    "snmp_enum": MitreEntry(
        technique_id = "T1602.001",
        technique    = "Data from Configuration Repository: SNMP (MIB Dump)",
        tactic       = "Collection",
        tactic_id    = "TA0009",
        url          = "https://attack.mitre.org/techniques/T1602/001/",
    ),
    "smtp_enum": MitreEntry(
        technique_id = "T1087",
        technique    = "Account Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1087/",
    ),
    "db_enum": MitreEntry(
        technique_id = "T1046",
        technique    = "Network Service Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1046/",
    ),
    "banner_info": MitreEntry(
        technique_id = "T1046",
        technique    = "Network Service Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1046/",
    ),

    # ── Generic ─────────────────────────────────────────────────────────────

    "open_service": MitreEntry(
        technique_id = "T1046",
        technique    = "Network Service Discovery",
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        url          = "https://attack.mitre.org/techniques/T1046/",
    ),
    "firewall_bypass": MitreEntry(
        technique_id = "T1562.004",
        technique    = "Impair Defenses: Disable or Modify System Firewall",
        tactic       = "Defense Evasion",
        tactic_id    = "TA0005",
        url          = "https://attack.mitre.org/techniques/T1562/004/",
    ),
    "tls_weak": MitreEntry(
        technique_id = "T1600.002",
        technique    = "Weaken Encryption: Reduce Key Space",
        tactic       = "Defense Evasion",
        tactic_id    = "TA0005",
        url          = "https://attack.mitre.org/techniques/T1600/002/",
    ),
}

_UNKNOWN = MitreEntry(
    technique_id = "T1190",
    technique    = "Exploit Public-Facing Application",
    tactic       = "Initial Access",
    tactic_id    = "TA0001",
    url          = "https://attack.mitre.org/techniques/T1190/",
)


def lookup(vuln_class: str) -> MitreEntry:
    """Return the MitreEntry for a vuln_class, falling back to T1190."""
    return _MAPPING.get(vuln_class.lower(), _UNKNOWN)
