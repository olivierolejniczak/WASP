"""
Phase 3: Report — one LLM call per confirmed finding, then template render.

Produces a Markdown report at the end of the scan.
Each finding gets a PoC paragraph written by the LLM (capped at 300 tokens).
The full report is also written as a plain-text summary to stdout.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path

from wasp.blackboard import Blackboard, Finding, Severity
from wasp.llm import OllamaClient


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
) -> None:
    """
    Call the LLM once per finding to generate an accurate PoC description.

    Uses per-class prompt templates that describe the *confirmed* exploit
    (method, URL, body, evidence signal) rather than asking the LLM to
    interpret ambiguous intermediate responses. This produces descriptions
    that match what actually happened rather than what the model guessed.
    """
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
            resp = llm.complete(system=_POC_SYSTEM, prompt=prompt)
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
) -> str:
    """Return the full Markdown report as a string."""
    now      = datetime.utcnow()
    duration = _fmt_duration(elapsed_s)

    lines: list[str] = []

    # --- Header ---
    lines += [
        "# WASP Scan Report",
        "",
        f"**Target:** `{target_url}`  ",
        f"**Date:** {scan_start.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Duration:** {duration}  ",
        f"**Model:** {config.get('orchestrator', {}).get('model', 'unknown')}  ",
        f"**Findings:** {len(findings)}",
        "",
    ]

    if not findings:
        lines += [
            "> No confirmed vulnerabilities found in this scan.",
            "",
            "_This does not mean the target is secure. WASP tests a subset of "
            "vulnerability classes with a single probe per class. Manual testing "
            "is always recommended._",
        ]
        return "\n".join(lines)

    # --- Summary table ---
    lines += ["## Summary", ""]
    lines += ["| # | Severity | Title | URL | MITRE ATT&CK |",
              "|---|----------|-------|-----|--------------|"]
    for i, f in enumerate(findings, 1):
        badge = _BADGE[f.severity]
        title = f.title.replace("|", "\\|")
        url   = f.target_url.replace("|", "\\|")
        if f.mitre_id:
            mitre_cell = f"[{f.mitre_id}]({f.mitre_url}) {f.mitre_tactic}"
        else:
            mitre_cell = "—"
        lines.append(f"| {i} | {badge} | {title} | `{url}` | {mitre_cell} |")
    lines.append("")

    # --- Individual findings ---
    lines.append("## Findings")
    lines.append("")

    for i, f in enumerate(findings, 1):
        badge = _BADGE[f.severity]
        lines += [
            f"### {i}. {f.title}",
            "",
            f"**Severity:** {badge}" + (f" (CVSS {f.cvss})" if f.cvss is not None else "") + "  ",
            f"**Class:** `{f.vuln_class}`  ",
            f"**URL:** `{f.target_url}`  ",
            f"**Discovered:** {f.timestamp.strftime('%H:%M:%S UTC')}",
            "",
        ]

        if f.mitre_id:
            lines += [
                f"**MITRE ATT&CK:** [{f.mitre_id} — {f.mitre_technique}]({f.mitre_url})  ",
                f"**Tactic:** {f.mitre_tactic}",
                "",
            ]

        if f.description:
            lines += ["**Description:**", "", f.description, ""]

        # Request details
        if f.request_url:
            lines += ["**Request:**", "", "```http"]
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
                "<summary>Evidence (click to expand)</summary>",
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

    # --- Footer ---
    lines += [
        "## Disclaimer",
        "",
        "_This report was generated by WASP — Web Application Security Probe. "
        "Findings are produced by a local LLM and should be manually verified "
        "before acting on them. Only use this tool against systems you own or "
        "are explicitly authorized to test._",
    ]

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
) -> str:
    """
    Enrich findings with LLM PoC descriptions, render Markdown, write to disk.
    Returns the path of the written file.

    PoC curl commands / attacker-narrative text are only generated when
    exploit=True — an explicit opt-in since that text describes how to
    actively exploit the confirmed finding, not just that it exists.
    """
    findings = board.findings()

    if findings and exploit:
        # Give the report LLM a bit more headroom for PoC descriptions
        original_max = llm.max_tokens
        llm.max_tokens = max(llm.max_tokens, 400)
        enrich_findings(findings, llm, config)
        llm.max_tokens = original_max

    md = render_markdown(findings, target_url, scan_start, elapsed_s, config)

    # Output filename
    slug = target_url.replace("://", "-").replace("/", "-").replace(":", "-").strip("-")
    slug = slug[:50]
    ts   = scan_start.strftime("%Y%m%d-%H%M%S")
    filename = f"wasp-{ts}-{slug}.md"
    out_path = os.path.join(output_dir, filename)

    Path(out_path).write_text(md, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    if m:
        return f"{m}m {s}s"
    return f"{s}s"
