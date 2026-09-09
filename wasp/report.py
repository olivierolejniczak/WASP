"""
Phase 3: Report — one LLM call per confirmed finding, then template render.

Produces a Markdown report at the end of the scan.
Each finding gets a PoC paragraph written by the LLM (capped at 300 tokens).
The full report is also written as a plain-text summary to stdout.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import uuid
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from wasp import __version__
from wasp.blackboard import Blackboard, Finding, Severity
from wasp.llm import OllamaClient
from wasp.i18n import t
from wasp.mdhtml import md_to_html


# ---------------------------------------------------------------------------
# Tester rig fingerprint — required by cahier des charges: report must trace
# back to the exact machine/tooling that ran the test (IP, MAC, tool versions).
# ---------------------------------------------------------------------------

_FINGERPRINT_TOOLS = ["nmap", "nuclei", "gobuster", "sqlmap", "nikto", "hydra", "smbclient"]


def _tool_version(binary: str) -> str:
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5).stdout
        return (out or "").strip().splitlines()[0] if out else "unknown"
    except (FileNotFoundError, subprocess.SubprocessError, IndexError):
        return "not installed"


@lru_cache(maxsize=1)
def get_tester_fingerprint() -> dict:
    """Local IP/MAC of the box running WASP, WASP version, and installed tool versions."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
    except OSError:
        ip = "unknown"
    mac_int = uuid.getnode()
    mac = ":".join(f"{(mac_int >> shift) & 0xff:02x}" for shift in range(40, -8, -8))
    return {
        "ip": ip,
        "mac": mac,
        "wasp_version": __version__,
        "tools": {tool: _tool_version(tool) for tool in _FINGERPRINT_TOOLS},
    }


# ---------------------------------------------------------------------------
# Severity badges for Markdown
# ---------------------------------------------------------------------------

_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH:     "🟠 HIGH",
    Severity.MEDIUM:   "🟡 MEDIUM",
    Severity.LOW:      "🟢 LOW",
    Severity.INFO:     "🔵 INFO",
}

_CREDENTIAL_CLASSES = {"ad_null_bind", "kerberoast", "asreproast", "ad_password_policy"}

_BLOODHOUND_ZIP_RE = re.compile(r"Saved BloodHound collection:\s*(\S+\.zip)")

_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}


# ---------------------------------------------------------------------------
# LLM-enriched PoC description
# ---------------------------------------------------------------------------

_POC_SYSTEM = """\
You are a penetration tester writing a professional vulnerability report.
Be concise and accurate. Base your description only on the confirmed evidence provided.
Write exactly 2-3 sentences. Include a working PoC curl command."""

# Per-class templates that tell the LLM exactly what happened,
# so it describes the actual exploit rather than an intermediate failed probe.
_POC_PROMPTS: dict[str, str] = {
    "sqli": """\
A SQL injection authentication bypass was confirmed at {url}.
The request was: {request_method} {request_url}
Request body: {request_body}
The server returned a JWT authentication token, confirming the login was bypassed.

Write 2-3 sentences: explain that the login endpoint is vulnerable to SQLi auth bypass,
what an attacker can do (log in as admin without credentials), and provide this exact
working PoC curl command using the payload from the request body above.""",

    "mass_assignment": """\
A mass assignment vulnerability was confirmed at {url}.
The request was: {request_method} {request_url}
Request body: {request_body}
The server accepted the "role":"admin" field and created an admin account.

Write 2-3 sentences: explain that the user registration API accepts arbitrary fields
including role, what an attacker can do (create accounts with elevated privileges),
and provide the exact working PoC curl command using the request above.""",

    "jwt_attack": """\
A JWT vulnerability was confirmed at {url}.
The request was: {request_method} {request_url}
Request body: {request_body}
A JWT token was returned, confirming the endpoint issues JWTs that may be vulnerable
to algorithm confusion attacks (alg:none or HS256 confusion).

Write 2-3 sentences: explain the JWT attack class, what an attacker can do
(forge admin tokens without knowing the signing key), and provide a PoC showing
the login request that produced the JWT.""",

    "idor": """\
An Insecure Direct Object Reference (IDOR) was confirmed at {url}.
The request was: {request_method} {request_url}
The server returned another user's data without verifying ownership.

Write 2-3 sentences: explain that the API returns any user's data when the ID
is changed in the URL, what an attacker can do (read all users' private data),
and provide the exact PoC curl command.""",

    "lfi": """\
A directory listing / local file inclusion was confirmed at {url}.
The request was: {request_method} {request_url}
The server returned a directory listing or file contents that should not be public.

Write 2-3 sentences: explain what was exposed, the risk (sensitive file download,
potential for further exploitation), and provide the exact PoC curl command.""",

    "path_traversal": """\
A path traversal vulnerability was confirmed at {url}.
The request was: {request_method} {request_url}
The server returned file contents from outside the intended directory.

Write 2-3 sentences: explain the path traversal technique used, what an attacker
can access, and provide the exact PoC curl command.""",

    "security_misconfig": """\
Security misconfiguration was confirmed at {url}.
Evidence: {evidence_summary}

Write 2-3 sentences: list the specific misconfigurations found (missing headers,
exposed paths, verbose errors), explain the risk, and provide a curl command
that demonstrates one of the issues.""",

    "outdated_components": """\
Vulnerable or outdated components were confirmed at {url}.
Evidence: {evidence_summary}

Write 2-3 sentences: name the specific CVEs or vulnerable versions found,
explain the risk, and note the affected component.""",
}

_POC_PROMPT_DEFAULT = """\
Vulnerability: {title}
Class: {vuln_class}
URL: {url}
Confirmed request: {request_method} {request_url}
Request body: {request_body}
Evidence summary: {evidence_summary}

Write 2-3 sentences describing:
1. What the vulnerability is and why it is exploitable
2. What an attacker can do
3. A minimal working PoC curl command"""


def enrich_findings(
    findings: list[Finding],
    llm: OllamaClient,
    config: dict,
    lang: str = "en",
) -> None:
    """
    Call the LLM once per finding to generate an accurate PoC description.

    Uses per-class prompt templates that describe the *confirmed* exploit
    (method, URL, body, evidence signal) rather than asking the LLM to
    interpret ambiguous intermediate responses. This produces descriptions
    that match what actually happened rather than what the model guessed.
    """
    system = _POC_SYSTEM
    if lang == "fr":
        system += "\nWrite your entire response in French."

    for finding in findings:
        try:
            template = _POC_PROMPTS.get(finding.vuln_class, _POC_PROMPT_DEFAULT)
            # Summarise evidence: first 400 chars, strip HTML tags
            import re as _re
            evidence_clean = _re.sub(r"<[^>]+>", "", finding.evidence)
            evidence_summary = evidence_clean[:400].strip()

            prompt = template.format(
                title           = finding.title,
                vuln_class      = finding.vuln_class,
                url             = finding.target_url,
                request_method  = finding.request_method,
                request_url     = finding.request_url or finding.target_url,
                request_body    = finding.request_body or "(none)",
                evidence_summary= evidence_summary,
            )
            resp = llm.complete(system=system, prompt=prompt)
            finding.description = resp.text.strip()[:800]
        except Exception:
            finding.description = (
                f"**{finding.title}** confirmed at `{finding.target_url}`. "
                f"Request: `{finding.request_method} {finding.request_url}` "
                f"body: `{finding.request_body[:100]}`"
            )


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def render_markdown(
    findings: list[Finding],
    target_url: str,
    scan_start: datetime,
    elapsed_s: float,
    config: dict,
    lang: str = "en",
) -> str:
    """Return the full Markdown report as a string."""
    now      = datetime.utcnow()
    duration = _fmt_duration(elapsed_s)

    lines: list[str] = []

    # --- Header ---
    lines += [
        f"# {t('report_title', lang)}",
        "",
        f"**{t('target', lang)}:** `{target_url}`  ",
        f"**{t('date', lang)}:** {scan_start.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**{t('duration', lang)}:** {duration}  ",
        f"**{t('model', lang)}:** {config.get('orchestrator', {}).get('model', 'unknown')}  ",
        f"**{t('findings', lang)}:** {len(findings)}",
        "",
    ]

    fp = get_tester_fingerprint()
    lines += [
        f"**{t('tester_rig', lang)}:** IP `{fp['ip']}` — MAC `{fp['mac']}` — WASP `{fp['wasp_version']}`  ",
        f"**{t('tester_tools', lang)}:** " + "; ".join(f"{k}: {v}" for k, v in fp["tools"].items()),
        "",
    ]

    if not findings:
        lines += [
            f"> {t('no_findings', lang)}",
            "",
            f"_{t('no_findings_note', lang)}_",
        ]
        return "\n".join(lines)

    # --- Summary table ---
    lines += [f"## {t('summary', lang)}", ""]
    lines += [f"| # | {t('col_severity', lang)} | {t('col_cvss', lang)} | {t('col_cve', lang)} | {t('col_title', lang)} | {t('col_url', lang)} | {t('col_mitre', lang)} |",
              "|---|----------|------|-----|-------|-----|--------------|"]
    for i, f in enumerate(findings, 1):
        badge = _BADGE[f.severity]
        title = f.title.replace("|", "\\|")
        url   = f.target_url.replace("|", "\\|")
        cvss  = f.cvss if f.cvss is not None else "—"
        cve   = f.cve if f.cve else "—"
        if f.mitre_id:
            mitre_cell = f"[{f.mitre_id}]({f.mitre_url}) {f.mitre_tactic}"
        else:
            mitre_cell = "—"
        lines.append(f"| {i} | {badge} | {cvss} | {cve} | {title} | `{url}` | {mitre_cell} |")
    lines.append("")

    # --- Individual findings ---
    lines.append(f"## {t('findings_section', lang)}")
    lines.append("")

    for i, f in enumerate(findings, 1):
        badge = _BADGE[f.severity]
        lines += [
            f"### {i}. {f.title}",
            "",
            f"**{t('col_severity', lang)}:** {badge}" + (f" (CVSS {f.cvss})" if f.cvss is not None else "") + "  ",
            f"**{t('class_label', lang)}:** `{f.vuln_class}`  ",
            f"**{t('col_url', lang)}:** `{f.target_url}`  ",
            f"**{t('discovered', lang)}:** {f.timestamp.strftime('%H:%M:%S UTC')}",
            "",
        ]

        if f.mitre_id:
            lines += [
                f"**{t('col_mitre', lang)}:** [{f.mitre_id} — {f.mitre_technique}]({f.mitre_url})  ",
                f"**{t('tactic', lang)}:** {f.mitre_tactic}",
                "",
            ]

        if f.cve:
            lines += [f"**{t('col_cve', lang)}:** {f.cve}", ""]

        if f.exploit_refs:
            lines += [f"**{t('known_exploits', lang)}:**", "", "```", f.exploit_refs, "```", ""]

        if f.description:
            lines += [f"**{t('description', lang)}:**", "", f.description, ""]

        rec = _RECOMMENDATIONS.get(f.vuln_class, _RECOMMENDATION_FALLBACK).get(lang, _RECOMMENDATION_FALLBACK["en"])
        delay = t(_DELAY_KEY[f.severity], lang)
        lines += [
            f"**{t('remediation', lang)}:** {rec}  ",
            f"**{t('recommended_delay', lang)}:** {delay}",
            "",
        ]

        if f.vuln_class == "ad_bloodhound":
            zip_match = _BLOODHOUND_ZIP_RE.search(f.evidence)
            if zip_match:
                lines += [f"**{t('artifact', lang)}:** `{zip_match.group(1)}` — {t('artifact_bloodhound_note', lang)}", ""]

        # Request details
        if f.request_url:
            lines += [f"**{t('request', lang)}:**", "", "```http"]
            lines.append(f"{f.request_method} {f.request_url}")
            if f.request_headers:
                for k, v in list(f.request_headers.items())[:4]:
                    lines.append(f"{k}: {v}")
            if f.request_body:
                lines.append("")
                lines.append(f.request_body[:300])
            lines += ["```", ""]

        # Evidence
        if f.evidence:
            evidence_preview = f.evidence[:800]
            lines += [
                "<details>",
                f"<summary>{t('evidence', lang)}</summary>",
                "",
                "```",
                evidence_preview,
                "```",
                "",
                "</details>",
                "",
            ]

        lines.append("---")
        lines.append("")

    # --- Credential handling attestation (only when a credential-bearing
    # probe class was confirmed: null-bind enum, Kerberoasting, AS-REP Roasting) ---
    if any(f.vuln_class in _CREDENTIAL_CLASSES for f in findings):
        lines += [
            f"## {t('credential_attestation_title', lang)}",
            "",
            f"_{t('credential_attestation_text', lang)}_",
            "",
        ]

    # --- Footer ---
    lines += [
        f"## {t('disclaimer', lang)}",
        "",
        f"_{t('disclaimer_text', lang)}_",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Executive summary renderer
# ---------------------------------------------------------------------------

# Generic, per-class remediation advice — deterministic, no LLM call needed.
_RECOMMENDATIONS: dict[str, dict[str, str]] = {
    "sqli":               {"en": "Use parameterized queries / an ORM everywhere user input reaches SQL.",
                            "fr": "Utiliser des requêtes paramétrées / un ORM partout où une entrée utilisateur atteint le SQL."},
    "auth_bypass":        {"en": "Review authentication logic for edge cases that skip credential checks.",
                            "fr": "Revoir la logique d'authentification pour les cas limites qui contournent la vérification des identifiants."},
    "jwt_attack":          {"en": "Reject unsigned/alg:none JWTs and enforce a strong signing secret.",
                            "fr": "Rejeter les JWT non signés (alg:none) et imposer un secret de signature fort."},
    "idor":               {"en": "Enforce object-level authorization checks on every request, not just authentication.",
                            "fr": "Appliquer un contrôle d'autorisation au niveau objet sur chaque requête, pas seulement l'authentification."},
    "mass_assignment":    {"en": "Explicitly allow-list writable fields on every API that accepts user input.",
                            "fr": "Définir explicitement une liste blanche des champs modifiables sur chaque API acceptant une entrée utilisateur."},
    "lfi":                {"en": "Disable directory listing and restrict file access to an explicit allow-list.",
                            "fr": "Désactiver le listage de répertoires et restreindre l'accès aux fichiers à une liste blanche explicite."},
    "path_traversal":     {"en": "Sanitize and canonicalize file paths before use; reject any path containing '..'.",
                            "fr": "Nettoyer et canoniser les chemins de fichiers avant utilisation ; rejeter tout chemin contenant '..'."},
    "xss_reflected":      {"en": "Encode all user input on output and adopt a strict Content-Security-Policy.",
                            "fr": "Encoder toute entrée utilisateur en sortie et adopter une Content-Security-Policy stricte."},
    "xss_stored":         {"en": "Sanitize stored input on write and encode on output; adopt a strict CSP.",
                            "fr": "Nettoyer les données stockées à l'écriture et les encoder à la sortie ; adopter une CSP stricte."},
    "security_misconfig": {"en": "Apply standard security headers and disable verbose error output in production.",
                            "fr": "Appliquer les en-têtes de sécurité standards et désactiver les erreurs détaillées en production."},
    "outdated_components":{"en": "Patch or upgrade the flagged components to a version without known CVEs.",
                            "fr": "Corriger ou mettre à jour les composants signalés vers une version sans CVE connue."},
    "info_disclosure":    {"en": "Remove exposed config/credential files from the web root and rotate any leaked secrets.",
                            "fr": "Retirer les fichiers de configuration/identifiants exposés de la racine web et régénérer tout secret divulgué."},
    "tls_weak":           {"en": "Disable SSLv3/TLSv1.0/1.1 and weak cipher suites; enforce TLS 1.2+.",
                            "fr": "Désactiver SSLv3/TLSv1.0/1.1 et les suites de chiffrement faibles ; imposer TLS 1.2+."},
    "smb_vuln":           {"en": "Patch the host against the identified SMB CVE and restrict SMB exposure to trusted networks.",
                            "fr": "Corriger l'hôte contre la CVE SMB identifiée et restreindre l'exposition SMB aux réseaux de confiance."},
    "default_creds":      {"en": "Change default credentials on every affected device immediately.",
                            "fr": "Changer immédiatement les identifiants par défaut sur chaque appareil concerné."},
    "ad_enum":            {"en": "Restrict anonymous/authenticated LDAP enumeration; apply least-privilege ACLs on directory objects.",
                            "fr": "Restreindre l'énumération LDAP anonyme/authentifiée ; appliquer des ACL de moindre privilège sur les objets de l'annuaire."},
    "ad_null_bind":       {"en": "Disable anonymous LDAP bind (dsHeuristics) on all domain controllers.",
                            "fr": "Désactiver le bind LDAP anonyme (dsHeuristics) sur tous les contrôleurs de domaine."},
    "kerberoast":         {"en": "Set long, random passwords on service accounts and migrate to Group Managed Service Accounts (gMSA).",
                            "fr": "Définir des mots de passe longs et aléatoires sur les comptes de service et migrer vers des gMSA (Group Managed Service Accounts)."},
    "asreproast":         {"en": "Require Kerberos pre-authentication for all accounts; audit and remove UF_DONT_REQUIRE_PREAUTH flags.",
                            "fr": "Exiger la pré-authentification Kerberos pour tous les comptes ; auditer et retirer les indicateurs UF_DONT_REQUIRE_PREAUTH."},
    "ad_password_policy": {"en": "Raise minimum password length/complexity and lockout thresholds to current baseline (e.g. CIS/ANSSI).",
                            "fr": "Renforcer la longueur/complexité minimale des mots de passe et les seuils de verrouillage selon un référentiel à jour (ex. CIS/ANSSI)."},
    "ad_bloodhound":      {"en": "Reduce attack-path exposure: remove unnecessary nested/nested-group ACLs and admin session trails identified in the collected graph; treat this dataset as sensitive and destroy it after review.",
                            "fr": "Réduire l'exposition des chemins d'attaque : retirer les ACL de groupes imbriqués et traces de sessions admin superflues identifiées dans le graphe collecté ; traiter ce jeu de données comme sensible et le détruire après analyse."},
}

_RECOMMENDATION_FALLBACK = {
    "en": "Review and remediate the confirmed finding; see the technical report for evidence and detail.",
    "fr": "Examiner et corriger la vulnérabilité confirmée ; voir le rapport technique pour les preuves et détails.",
}

_DELAY_KEY = {
    Severity.CRITICAL: "delay_immediate",
    Severity.HIGH:     "delay_immediate",
    Severity.MEDIUM:   "delay_30",
    Severity.LOW:      "delay_90",
    Severity.INFO:     "delay_90",
}

_RISK_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_RISK_KEY = {
    Severity.CRITICAL: "risk_critical",
    Severity.HIGH:     "risk_high",
    Severity.MEDIUM:   "risk_medium",
    Severity.LOW:      "risk_low",
}


def render_executive_markdown(
    findings: list[Finding],
    target_url: str,
    scan_start: datetime,
    elapsed_s: float,
    config: dict,
    lang: str = "en",
) -> str:
    """
    Business-oriented summary: overall risk rating, severity breakdown,
    top risks in plain language, and prioritized recommendations.
    No raw evidence, request/response detail, or PoC commands.
    """
    lines: list[str] = [
        f"# {t('exec_title', lang)}",
        "",
        f"**{t('exec_scope', lang)}:** `{target_url}`  ",
        f"**{t('tester_rig', lang)}:** IP `{get_tester_fingerprint()['ip']}` — MAC `{get_tester_fingerprint()['mac']}`  ",
        f"**{t('date', lang)}:** {scan_start.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**{t('duration', lang)}:** {_fmt_duration(elapsed_s)}",
        "",
    ]

    if not findings:
        lines += [
            f"## {t('exec_risk_rating', lang)}",
            "",
            f"**{t('risk_none', lang)}**",
            "",
            f"_{t('no_findings_note', lang)}_",
            "",
            f"## {t('disclaimer', lang)}",
            "",
            f"_{t('exec_disclaimer_text', lang)}_",
        ]
        return "\n".join(lines)

    top_severity = next(s for s in _RISK_ORDER if any(f.severity == s for f in findings))
    risk_label = t(_RISK_KEY.get(top_severity, "risk_low"), lang)

    lines += [f"## {t('exec_risk_rating', lang)}", "", f"**{risk_label}**", ""]

    counts = {s: sum(1 for f in findings if f.severity == s) for s in _RISK_ORDER}
    lines += [f"## {t('exec_severity_breakdown', lang)}", ""]
    lines += [f"| {t('col_severity', lang)} | {t('findings', lang)} |", "|---|---|"]
    for s in _RISK_ORDER:
        if counts[s]:
            lines.append(f"| {_BADGE[s]} | {counts[s]} |")
    lines.append("")

    ordered = sorted(findings, key=lambda f: (_SEV_ORDER[f.severity],
                                               -(f.cvss or 0)))
    top = ordered[:5]
    lines += [f"## {t('exec_top_risks', lang)}", ""]
    for f in top:
        lines.append(f"- **{_BADGE[f.severity]}** — {f.title} (`{f.target_url}`)")
    lines.append("")

    lines += [f"## {t('exec_recommendations', lang)}", ""]
    seen_classes: list[str] = []
    for f in ordered:
        if f.vuln_class in seen_classes:
            continue
        seen_classes.append(f.vuln_class)
        rec = _RECOMMENDATIONS.get(f.vuln_class, _RECOMMENDATION_FALLBACK).get(lang, _RECOMMENDATION_FALLBACK["en"])
        lines.append(f"- **{f.title}:** {rec}")
    lines.append("")

    lines += [f"## {t('disclaimer', lang)}", "", f"_{t('exec_disclaimer_text', lang)}_"]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Write report to disk
# ---------------------------------------------------------------------------

def write_report(
    board: Blackboard,
    target_url: str,
    scan_start: datetime,
    elapsed_s: float,
    llm: OllamaClient,
    config: dict,
    output_dir: str = ".",
    exploit: bool = False,
    lang: str = "en",
) -> str:
    """
    Enrich findings with LLM PoC descriptions, render Markdown, write to disk.
    Returns the path of the written technical report (.md).

    Also writes, alongside it, a JSON report, an HTML version of both the
    technical and executive reports, and a separate executive summary
    (business-oriented, no technical evidence/PoC) — no flags needed.

    PoC curl commands / attacker-narrative text are only generated when
    exploit=True — an explicit opt-in since that text describes how to
    actively exploit the confirmed finding, not just that it exists.
    """
    findings = board.findings()

    if findings and exploit:
        # Give the report LLM a bit more headroom for PoC descriptions
        original_max = llm.max_tokens
        llm.max_tokens = max(llm.max_tokens, 400)
        enrich_findings(findings, llm, config, lang=lang)
        llm.max_tokens = original_max

    md = render_markdown(findings, target_url, scan_start, elapsed_s, config, lang=lang)

    # Output filename
    slug = target_url.replace("://", "-").replace("/", "-").replace(":", "-").strip("-")
    slug = slug[:50]
    ts   = scan_start.strftime("%Y%m%d-%H%M%S")
    filename = f"wasp-{ts}-{slug}-{lang}.md"
    out_path = os.path.join(output_dir, filename)

    Path(out_path).write_text(md, encoding="utf-8")
    Path(out_path[:-3] + ".html").write_text(
        md_to_html(md, title=t("report_title", lang)), encoding="utf-8")

    report_dict = {
        "target": target_url,
        "scan_start": scan_start.isoformat(),
        "elapsed_s": elapsed_s,
        "findings": [f.to_dict() for f in findings],
    }
    json_path = out_path[:-3] + ".json"
    Path(json_path).write_text(json.dumps(report_dict, indent=2), encoding="utf-8")

    exec_md = render_executive_markdown(findings, target_url, scan_start, elapsed_s, config, lang=lang)
    exec_path = os.path.join(output_dir, f"wasp-{ts}-{slug}-{lang}-executive.md")
    Path(exec_path).write_text(exec_md, encoding="utf-8")
    Path(exec_path[:-3] + ".html").write_text(
        md_to_html(exec_md, title=t("exec_title", lang)), encoding="utf-8")

    return out_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _self_check():
    findings = [
        Finding(vuln_class="kerberoast", title="Kerberoastable Service Accounts",
                severity=Severity.HIGH, target_url="10.0.0.1/", evidence="ev",
                cve="CVE-2017-0144"),
        Finding(vuln_class="ad_bloodhound", title="Active Directory Attack Path Data Collected (BloodHound)",
                severity=Severity.HIGH, target_url="10.0.0.1/",
                evidence="INFO: Compressing output into 20260909_bloodhound.zip\n"
                         "Saved BloodHound collection: wasp-bloodhound-corp-local_20260909.zip (import into BloodHound GUI for graph analysis; Neo4j not required by WASP itself)"),
    ]
    md = render_markdown(findings, "10.0.0.1", datetime.utcnow(), 12.0, {})
    assert "CVE-2017-0144" in md
    assert "Remediation" in md and "gMSA" in md
    assert "Recommended timeline" in md and "Immediate" in md
    assert "Credential Handling Attestation" in md
    assert "Tester rig" in md and "MAC" in md
    assert "Artifact" in md and "wasp-bloodhound-corp-local_20260909.zip" in md
    fp = get_tester_fingerprint()
    assert fp["ip"] and fp["mac"].count(":") == 5


if __name__ == "__main__":
    _self_check()
    print("ok")
