"""
Network-range scanner for WASP.

Discovers all live hosts in a CIDR range, classifies each one,
then runs a targeted scan per host — using the right recon module
and hypothesis set for each target type.

Produces one Finding list and one combined Markdown report.
"""

from __future__ import annotations

import json
import os
import threading
import time
import subprocess
import shutil
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from wasp.blackboard import Blackboard, Finding
from wasp.classifier import classify, reclassify, TargetInfo
from wasp.llm import OllamaClient
from wasp.planner import plan_hypotheses
from wasp.probe import probe_hypothesis
from wasp.recon import run_recon_for_type, ReconFacts
from wasp.report import write_report, render_markdown, enrich_findings, _RECOMMENDATIONS, _RECOMMENDATION_FALLBACK, _RISK_ORDER, _RISK_KEY
from wasp.i18n import t
from wasp.mdhtml import md_to_html


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

def discover_hosts(cidr: str, timeout: int = 30) -> list[str]:
    """
    Return list of live IPs in the CIDR range using nmap ping scan.
    Falls back to ARP scan then pure TCP if ICMP is blocked.
    """
    if not shutil.which("nmap"):
        raise RuntimeError("nmap is required for network scanning")

    # nmap ping scan (-sn)
    cmd = ["nmap", "-sn", "--min-rate", "1000", "-T4", "-oG", "-", cidr]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        hosts = re.findall(r"Host: (\d+\.\d+\.\d+\.\d+)", r.stdout)
        return hosts
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


def quick_classify_hosts(hosts: list[str], timeout: int = 45) -> list[TargetInfo]:
    """
    Run a fast port scan across all hosts and classify each one.
    Uses a single nmap sweep for efficiency.
    """
    if not hosts:
        return []

    # Fast scan: top-20 ports across all hosts simultaneously
    ports = "22,53,80,135,139,389,443,445,3389,5985,8080,8443,3306,5432,21,25,3000,5000,8000,6379"
    cmd = ["nmap", "-T4", "--min-rate", "2000", "-p", ports,
           "--open", "-oG", "-"] + hosts

    nmap_output = ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        nmap_output = r.stdout
    except Exception:
        pass

    # Parse per-host results
    host_ports: dict[str, str] = {}
    for line in nmap_output.splitlines():
        m = re.match(r"Host: (\d+\.\d+\.\d+\.\d+).*Ports: (.+)", line)
        if m:
            host_ports[m.group(1)] = m.group(2)

    results: list[TargetInfo] = []
    for host in hosts:
        ports_str = host_ports.get(host, "")
        # Build a fake greppable line for classify
        fake_line = f"Host: {host} ()	Ports: {ports_str}" if ports_str else ""
        info = classify(host, fake_line)
        results.append(info)

    return results


# ---------------------------------------------------------------------------
# Per-host scan
# ---------------------------------------------------------------------------

@dataclass
class HostResult:
    info: TargetInfo
    facts: ReconFacts | None = None
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    elapsed_s: float = 0.0


_CRED_RE = re.compile(r"login:\s*(\S+)\s+password:\s*(\S*)", re.IGNORECASE)


def _extract_creds(evidence: str) -> list[str]:
    """Pull 'user:pass' pairs out of a hydra_quick default_creds finding's
    raw evidence, for reuse against other hosts (--credential-spray)."""
    return [f"{u}:{p}" for u, p in _CRED_RE.findall(evidence)]


def scan_host(
    info: TargetInfo,
    llm: OllamaClient,
    config: dict,
    host_budget_s: int = 120,
    known_creds: list[str] | None = None,
) -> HostResult:
    """
    Run a full WASP scan against a single classified host.
    Returns a HostResult with findings.

    known_creds: credentials confirmed valid on an earlier host in this same
    network scan (--credential-spray) — tried first via hydra_quick.
    """
    result = HostResult(info=info)
    t0     = time.monotonic()

    if known_creds:
        config = dict(config)
        config["tools"] = dict(config.get("tools", {}))
        config["tools"]["hydra"] = {**config["tools"].get("hydra", {}), "extra_creds": known_creds}

    try:
        # Determine target string for recon
        if info.target_type == "web":
            # Prefer HTTPS if 443 open, otherwise HTTP
            if 443 in info.open_ports:
                target = f"https://{info.host}"
            elif info.open_ports:
                web_port = next((p for p in info.open_ports if p in
                                 {80,443,8080,8443,3000,8000,8888,9000}), 80)
                target = f"http://{info.host}:{web_port}" if web_port != 80 else f"http://{info.host}"
            else:
                target = f"http://{info.host}"
        else:
            target = info.raw

        # Recon
        recon_timeout = min(host_budget_s // 2, 60)
        facts = run_recon_for_type(target, info.target_type, config, timeout=recon_timeout)
        result.facts = facts

        # Plan
        remaining = host_budget_s - (time.monotonic() - t0)
        if remaining < 20:
            return result

        hypotheses = plan_hypotheses(facts, llm, config, target_type=info.target_type)

        # Probe
        board = Blackboard()
        for h in hypotheses:
            if time.monotonic() - t0 > host_budget_s - 15:
                break
            probe_hypothesis(h, facts, llm, board, config)

        result.findings = board.findings()

    except Exception as exc:
        result.error = str(exc)

    result.elapsed_s = time.monotonic() - t0
    return result


# ---------------------------------------------------------------------------
# Full network scan
# ---------------------------------------------------------------------------

def _checkpoint_path(cidr: str, output_dir: str) -> str:
    slug = cidr.replace("/", "-").replace(".", "-")
    return os.path.join(output_dir, f".wasp-checkpoint-{slug}.json")


def _save_checkpoint(path: str, cidr: str, classified: list[TargetInfo],
                      all_results: list) -> None:
    """Persist scan progress so a killed run can resume instead of restarting."""
    data = {
        "cidr": cidr,
        "hosts": [asdict(info) for info in classified],
        "results": [
            None if r is None else {
                "findings": [f.to_dict() for f in r.findings],
                "error": r.error,
                "elapsed_s": r.elapsed_s,
            }
            for r in all_results
        ],
    }
    try:
        Path(path).write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def _load_checkpoint(path: str, cidr: str):
    """Return (classified, all_results) from a matching checkpoint, or None."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("cidr") != cidr:
        return None
    classified = [TargetInfo(**h) for h in data["hosts"]]
    all_results = [
        None if r is None else HostResult(
            info=classified[i],
            findings=[Finding.from_dict(fd) for fd in r["findings"]],
            error=r["error"],
            elapsed_s=r["elapsed_s"],
        )
        for i, r in enumerate(data["results"])
    ]
    return classified, all_results


def run_network_scan(
    cidr: str,
    llm: OllamaClient,
    config: dict,
    output_dir: str = ".",
    on_progress=None,          # callback(msg: str)
    max_hosts: int = 50,
    host_budget_s: int = 120,
    discovery_timeout: int = 30,
    exploit: bool = False,
    credential_spray: bool = False,
    max_workers: int = 8,
    resume: bool = True,
    lang: str = "en",
) -> tuple[list[HostResult], str]:
    """
    Full pipeline:
      1. Discover live hosts
      2. Classify each host by service fingerprint
      3. Scan hosts in parallel (budget-gated per host), --credential-spray
         forces sequential since a host's known_creds depend on what earlier
         hosts confirmed
      4. Render combined report

    Progress is checkpointed to disk after every host, so a killed run can
    resume (resume=True, default) instead of rescanning already-done hosts.

    Returns (results, report_path).
    """
    scan_start = datetime.utcnow()
    t_total    = time.monotonic()

    def progress(msg: str):
        if on_progress:
            on_progress(msg)

    checkpoint_path = _checkpoint_path(cidr, output_dir)
    resumed = _load_checkpoint(checkpoint_path, cidr) if resume else None

    if resumed:
        classified, all_results = resumed
        done = sum(1 for r in all_results if r is not None)
        progress(f"Resuming {cidr} from checkpoint ({done}/{len(classified)} hosts already done)")
    else:
        # Step 1: discover
        progress(f"Discovering hosts in {cidr} …")
        hosts = discover_hosts(cidr, timeout=discovery_timeout)
        if not hosts:
            progress("No live hosts found.")
            return [], ""
        progress(f"Found {len(hosts)} live hosts")

        # Limit
        hosts = hosts[:max_hosts]

        # Step 2: classify
        progress("Fingerprinting and classifying hosts …")
        classified = quick_classify_hosts(hosts, timeout=45)

        # Sort: windows/activedir first (most interesting), then web, then rest
        _ORDER = {"activedir": 0, "windows": 1, "web": 2, "database": 3,
                  "linux": 4, "router": 5, "iot": 9, "unknown": 9}
        classified.sort(key=lambda i: _ORDER.get(i.target_type, 9))

        for info in classified:
            ports_str = ",".join(str(p) for p in info.open_ports[:6])
            progress(f"  {info.host:<18} → {info.target_type:<12} ports=[{ports_str}]")

        all_results: list[HostResult | None] = [None] * len(classified)

    # Step 3: scan each host
    n_hosts = len(classified)
    known_creds: list[str] = []
    for r in all_results:
        if r:
            for f in r.findings:
                if f.vuln_class == "default_creds":
                    for cred in _extract_creds(f.evidence):
                        if cred not in known_creds:
                            known_creds.append(cred)

    def _report_result(i: int, hr: HostResult) -> None:
        n = len(hr.findings)
        elapsed = f"{hr.elapsed_s:.0f}s"
        label = f"[{i+1}/{n_hosts}] {hr.info.host} ({hr.info.target_type})"
        if hr.error:
            progress(f"{label}  ✗ error: {hr.error[:80]}")
        elif n:
            sevs = ", ".join(f.severity.value for f in hr.findings)
            progress(f"{label}  ✓ {n} finding(s) [{sevs}] in {elapsed}")
        else:
            progress(f"{label}  – no findings in {elapsed}")

    scannable: list[tuple[int, TargetInfo]] = []
    for i, info in enumerate(classified):
        if all_results[i] is not None:
            continue
        if info.target_type in ("iot", "unknown") and not info.open_ports:
            progress(f"[{i+1}/{n_hosts}] {info.host} — skipping (no open ports)")
            all_results[i] = HostResult(info=info)
        else:
            scannable.append((i, info))

    if credential_spray:
        # Sequential: each host's known_creds depend on what earlier hosts confirmed.
        for i, info in scannable:
            progress(f"[{i+1}/{n_hosts}] Scanning {info.host} ({info.target_type}) …")
            hr = scan_host(info, llm, config, host_budget_s=host_budget_s, known_creds=known_creds)
            all_results[i] = hr
            for f in hr.findings:
                if f.vuln_class == "default_creds":
                    for cred in _extract_creds(f.evidence):
                        if cred not in known_creds:
                            known_creds.append(cred)
            _report_result(i, hr)
            _save_checkpoint(checkpoint_path, cidr, classified, all_results)
    else:
        progress(f"Scanning {len(scannable)} host(s) in parallel (max {max_workers} at a time) …")
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(scannable)))) as pool:
            futures = {
                pool.submit(scan_host, info, llm, config, host_budget_s=host_budget_s): i
                for i, info in scannable
            }
            for fut in as_completed(futures):
                i = futures[fut]
                hr = fut.result()
                all_results[i] = hr
                _report_result(i, hr)
                _save_checkpoint(checkpoint_path, cidr, classified, all_results)

    # Step 4: report — write file first (even without enrichment), then enrich if time allows
    total_findings = sum(len(r.findings) for r in all_results)
    progress(f"\nTotal findings across network: {total_findings}")

    report_path = _render_network_report(
        all_results, cidr, scan_start,
        time.monotonic() - t_total,
        llm, config, output_dir,
        exploit=exploit,
        lang=lang,
    )
    progress(f"Report written → {report_path}")

    try:
        os.remove(checkpoint_path)
    except OSError:
        pass

    return all_results, report_path


# ---------------------------------------------------------------------------
# Network report renderer
# ---------------------------------------------------------------------------

def _render_network_report(
    results: list[HostResult],
    cidr: str,
    scan_start: datetime,
    elapsed_s: float,
    llm: OllamaClient,
    config: dict,
    output_dir: str,
    exploit: bool = False,
    lang: str = "en",
) -> str:
    model = config.get("orchestrator", {}).get("model", "unknown")
    m, s  = divmod(int(elapsed_s), 60)
    dur   = f"{m}m {s}s"
    total = sum(len(r.findings) for r in results)

    lines: list[str] = [
        f"# {t('network_report_title', lang)}",
        "",
        f"**{t('target_range', lang)}:** `{cidr}`  ",
        f"**{t('date', lang)}:** {scan_start.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**{t('duration', lang)}:** {dur}  ",
        f"**{t('model', lang)}:** {model}  ",
        f"**{t('hosts_scanned', lang)}:** {len(results)}  ",
        f"**{t('total_findings', lang)}:** {total}",
        "",
    ]

    # Host summary table
    lines += [f"## {t('host_summary', lang)}", ""]
    lines += [f"| {t('col_host', lang)} | {t('col_type', lang)} | {t('col_ports', lang)} | {t('findings', lang)} |",
              "|------|------|-------|----------|"]
    for r in results:
        ports = ", ".join(str(p) for p in r.info.open_ports[:8])
        n     = len(r.findings)
        badge = f"**{n}**" if n else "–"
        lines.append(f"| `{r.info.host}` | {r.info.target_type} | {ports} | {badge} |")
    lines.append("")

    # All findings consolidated
    all_findings = [f for r in results for f in r.findings]
    from wasp.blackboard import Severity
    _BADGE = {
        Severity.CRITICAL: "🔴 CRITICAL",
        Severity.HIGH:     "🟠 HIGH",
        Severity.MEDIUM:   "🟡 MEDIUM",
        Severity.LOW:      "🟢 LOW",
        Severity.INFO:     "🔵 INFO",
    }
    if all_findings:
        if exploit:
            # Only enrich findings — skip if llm is slow (best-effort)
            try:
                original_max = llm.max_tokens
                llm.max_tokens = max(llm.max_tokens, 400)
                import signal as _sig
                def _timeout_handler(signum, frame):
                    raise TimeoutError("enrichment timed out")
                _sig.signal(_sig.SIGALRM, _timeout_handler)
                _sig.alarm(120)   # 2-minute hard limit on enrichment
                enrich_findings(all_findings, llm, config, lang=lang)
                _sig.alarm(0)
                llm.max_tokens = original_max
            except Exception:
                pass  # enrichment is best-effort; raw evidence still in report

        lines += [f"## {t('all_findings', lang)}", ""]
        lines += [f"| # | {t('col_host', lang)} | {t('col_severity', lang)} | {t('col_cvss', lang)} | {t('col_title', lang)} |",
                  "|---|------|----------|------|-------|"]
        _SEV_ORDER = ["critical","high","medium","low","info"]
        for i, f in enumerate(sorted(all_findings,
                               key=lambda x: _SEV_ORDER.index(x.severity.value) if x.severity.value in _SEV_ORDER else 9), 1):
            badge = _BADGE[f.severity]
            cvss = f.cvss if f.cvss is not None else "—"
            host_label = f.target_url.split("//")[-1].split("/")[0] if "//" in f.target_url else f.target_url.split("/")[0]
            lines.append(f"| {i} | `{host_label}` | {badge} | {cvss} | {f.title} |")
        lines.append("")

        # Per-host finding sections
        for r in results:
            if not r.findings:
                continue
            lines += [f"### {r.info.host} — {r.info.target_type}", ""]
            for f in r.findings:
                badge = _BADGE[f.severity]
                lines += [
                    f"#### {f.title}",
                    f"**{t('col_severity', lang)}:** {badge}  **{t('class_label', lang)}:** `{f.vuln_class}`",
                    "",
                ]
                if f.description:
                    lines += [f.description, ""]
                if f.request_url:
                    lines += ["```http",
                               f"{f.request_method} {f.request_url}"]
                    if f.request_body:
                        lines += ["", f.request_body[:200]]
                    lines += ["```", ""]
                lines.append("---")
                lines.append("")
    else:
        lines += [f"> {t('no_findings_network', lang)}", ""]

    lines += [
        f"## {t('disclaimer', lang)}",
        "",
        f"_{t('disclaimer_network', lang)}_",
    ]

    md  = "\n".join(lines)
    slug = cidr.replace("/", "-").replace(".", "-")
    ts   = scan_start.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(output_dir, f"wasp-network-{ts}-{slug}.md")
    Path(path).write_text(md, encoding="utf-8")
    Path(path[:-3] + ".html").write_text(
        md_to_html(md, title=t("network_report_title", lang)), encoding="utf-8")

    import json as _json
    report_dict = {
        "cidr": cidr,
        "scan_start": scan_start.isoformat(),
        "elapsed_s": elapsed_s,
        "hosts": [
            {"host": r.info.host, "type": r.info.target_type, "open_ports": r.info.open_ports,
             "findings": [f.to_dict() for f in r.findings]}
            for r in results
        ],
    }
    Path(path[:-3] + ".json").write_text(_json.dumps(report_dict, indent=2), encoding="utf-8")

    exec_path = os.path.join(output_dir, f"wasp-network-{ts}-{slug}-executive.md")
    exec_md = _render_network_executive(all_findings, cidr, scan_start, elapsed_s, lang=lang)
    Path(exec_path).write_text(exec_md, encoding="utf-8")
    Path(exec_path[:-3] + ".html").write_text(
        md_to_html(exec_md, title=t("exec_title", lang)), encoding="utf-8")

    return path


def _render_network_executive(
    all_findings: list[Finding],
    cidr: str,
    scan_start: datetime,
    elapsed_s: float,
    lang: str = "en",
) -> str:
    """Business-oriented summary across all scanned hosts. No technical evidence."""
    from wasp.blackboard import Severity
    from wasp.report import _BADGE, _SEV_ORDER

    m, s = divmod(int(elapsed_s), 60)
    lines: list[str] = [
        f"# {t('exec_title', lang)}",
        "",
        f"**{t('exec_scope', lang)}:** `{cidr}`  ",
        f"**{t('date', lang)}:** {scan_start.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**{t('duration', lang)}:** {m}m {s}s",
        "",
    ]

    if not all_findings:
        lines += [
            f"## {t('exec_risk_rating', lang)}", "",
            f"**{t('risk_none', lang)}**", "",
            f"_{t('no_findings_note', lang)}_", "",
            f"## {t('disclaimer', lang)}", "",
            f"_{t('exec_disclaimer_text', lang)}_",
        ]
        return "\n".join(lines)

    top_severity = next(sv for sv in _RISK_ORDER if any(f.severity == sv for f in all_findings))
    lines += [f"## {t('exec_risk_rating', lang)}", "", f"**{t(_RISK_KEY.get(top_severity, 'risk_low'), lang)}**", ""]

    counts = {sv: sum(1 for f in all_findings if f.severity == sv) for sv in _RISK_ORDER}
    lines += [f"## {t('exec_severity_breakdown', lang)}", ""]
    lines += [f"| {t('col_severity', lang)} | {t('findings', lang)} |", "|---|---|"]
    for sv in _RISK_ORDER:
        if counts[sv]:
            lines.append(f"| {_BADGE[sv]} | {counts[sv]} |")
    lines.append("")

    ordered = sorted(all_findings, key=lambda f: (_SEV_ORDER[f.severity], -(f.cvss or 0)))
    lines += [f"## {t('exec_top_risks', lang)}", ""]
    for f in ordered[:5]:
        host_label = f.target_url.split("//")[-1].split("/")[0] if "//" in f.target_url else f.target_url.split("/")[0]
        lines.append(f"- **{_BADGE[f.severity]}** — {f.title} (`{host_label}`)")
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


def _self_check():
    """Parallel scan must return results in classified (input) order, not
    completion order, since results/reports index hosts positionally."""
    import random
    import wasp.network_scan as ns

    fake_hosts = [f"10.0.0.{i}" for i in range(10)]
    fake_infos = [TargetInfo(raw=h, host=h, port=None, scheme="", target_type="linux", open_ports=[22]) for h in fake_hosts]

    def fake_scan_host(info, llm, config, host_budget_s=120, known_creds=None):
        time.sleep(random.uniform(0, 0.03))  # simulate out-of-order completion
        return HostResult(info=info, elapsed_s=0.1)

    orig_discover, orig_classify, orig_scan_host = ns.discover_hosts, ns.quick_classify_hosts, ns.scan_host
    ns.discover_hosts       = lambda cidr, timeout=30: fake_hosts
    ns.quick_classify_hosts = lambda hosts, timeout=45: fake_infos
    ns.scan_host            = fake_scan_host
    try:
        results, _ = ns.run_network_scan("10.0.0.0/24", llm=None, config={}, output_dir="/tmp")
        assert [r.info.host for r in results] == fake_hosts

        # Checkpoint/resume: a scan that dies partway through must resume
        # only the hosts that never completed, not restart from scratch.
        cp = ns._checkpoint_path("10.0.0.0/24", "/tmp")
        n_calls = {"n": 0}

        def flaky_scan_host(info, llm, config, host_budget_s=120, known_creds=None):
            n_calls["n"] += 1
            if info.host == "10.0.0.3":
                raise RuntimeError("simulated crash")
            return HostResult(info=info, elapsed_s=0.1)

        ns.scan_host = flaky_scan_host
        try:
            ns.run_network_scan("10.0.0.0/24", llm=None, config={}, output_dir="/tmp", max_workers=1)
        except RuntimeError:
            pass
        assert os.path.exists(cp), "checkpoint should survive a crash"
        assert n_calls["n"] > 0

        ns.scan_host = fake_scan_host
        results2, _ = ns.run_network_scan("10.0.0.0/24", llm=None, config={}, output_dir="/tmp", max_workers=1)
        assert [r.info.host for r in results2] == fake_hosts
        assert not os.path.exists(cp), "checkpoint should be cleared after a clean finish"
    finally:
        ns.discover_hosts, ns.quick_classify_hosts, ns.scan_host = orig_discover, orig_classify, orig_scan_host
        if os.path.exists(ns._checkpoint_path("10.0.0.0/24", "/tmp")):
            os.remove(ns._checkpoint_path("10.0.0.0/24", "/tmp"))


if __name__ == "__main__":
    _self_check()
    print("ok")
