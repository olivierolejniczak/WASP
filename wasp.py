#!/usr/bin/env python3
"""
WASP — Web Application Security Probe
Lightweight local-AI pentest tool for modest hardware.

Usage:
  wasp.py scan http://localhost:3002
  wasp.py scan http://localhost:3002 --model qwen3:1.7b
  wasp.py scan http://localhost:3002 --budget 10
  wasp.py doctor
  wasp.py models
"""

from __future__ import annotations

import os
import sys
import time
import signal
import shutil
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

from wasp import __version__
from wasp.blackboard import Blackboard, Severity
from wasp.classifier import classify, reclassify
from wasp.llm import OllamaClient, LLMError
from wasp.network_scan import run_network_scan, discover_hosts, quick_classify_hosts
from wasp.planner import plan_hypotheses
from wasp.probe import probe_hypothesis
from wasp.recon import run_recon, run_recon_for_type
from wasp.report import write_report
from wasp.tools import available_tools, ALL_TOOLS

# ---------------------------------------------------------------------------
# App + console
# ---------------------------------------------------------------------------

app     = typer.Typer(
    name="wasp",
    help="WASP — Web Application Security Probe. Local-AI pentest tool.",
    add_completion=False,
)
console = Console()

_SEV_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "green",
    Severity.INFO:     "cyan",
}


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

def load_config(config_path: str | None = None) -> dict:
    path = config_path or _DEFAULT_CONFIG_PATH
    if not os.path.exists(path):
        return _default_config()
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    # Merge with defaults so missing keys never cause KeyErrors
    return _deep_merge(_default_config(), cfg)

def _default_config() -> dict:
    return {
        "orchestrator": {
            "provider":       "ollama",
            "model":          "llama3.2:3b",
            "endpoint":       "http://localhost:11435",
            "temperature":    0.1,
            "max_tokens":     256,
            "context_window": 8192,
        },
        "lite": {
            "wall_clock_budget_s": 840,   # 14 minutes
            "max_hypotheses":      6,
            "max_turns_per_hypothesis": 2,
            "tool_timeout_s":      45,
            "recon_timeout_s":     90,
            "result_truncate_chars": 2048,
            "wordlist": os.path.join(os.path.dirname(__file__), "wasp", "wordlist.txt"),
        },
        "tools": {
            "nmap":    {"rate": 500},
            "httpx":   {"follow_redirects": True, "timeout": 10, "threads": 5},
            "gobuster":{"threads": 10},
            "sqlmap":  {"level": 1, "risk": 1, "technique": "B"},
            "nikto":   {"max_time": 60},
            "nuclei":  {"severity": ["critical", "high"], "rate_limit": 10},
        },
        "output": {"dir": "."},
    }

def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


# ---------------------------------------------------------------------------
# Shared LLM factory
# ---------------------------------------------------------------------------

def make_llm(config: dict, model_override: str | None = None) -> OllamaClient:
    orch = config.get("orchestrator", {})
    return OllamaClient(
        endpoint    = orch.get("endpoint", "http://localhost:11435"),
        model       = model_override or orch.get("model", "llama3.2:3b"),
        timeout     = 120.0,
        temperature = orch.get("temperature", 0.1),
        max_tokens  = orch.get("max_tokens", 256),
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target: URL, IP, hostname, or CIDR range"),
    config_file: Optional[str]  = typer.Option(None,    "--config", "-c", help="Path to config.yaml"),
    model:       Optional[str]  = typer.Option(None,    "--model",  "-m", help="Override Ollama model"),
    budget:      Optional[int]  = typer.Option(None,    "--budget", "-b", help="Wall-clock budget in minutes (default: 14)"),
    output_dir:  str            = typer.Option(".",     "--output", "-o", help="Directory for the report file"),
    verbose:     bool           = typer.Option(False,   "--verbose","-v", help="Show tool output in real time"),
    dry_run:     bool           = typer.Option(False,   "--dry-run",      help="Plan only — do not execute any probes"),
    force_type:  Optional[str]  = typer.Option(None,    "--type",   "-t", help="Force target type: web/windows/activedir/linux/router/database"),
):
    """Run a WASP security scan against TARGET (URL, IP, hostname, or CIDR)."""

    # Redirect CIDR ranges to the network command
    import re as _re
    if _re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", target.strip()):
        console.print(f"[cyan]CIDR range detected — running network scan[/cyan]")
        network(
            cidr=target,
            config_file=config_file,
            model=model,
            budget=budget,
            output_dir=output_dir,
            verbose=verbose,
        )
        return

    config = load_config(config_file)
    if budget is not None:
        config["lite"]["wall_clock_budget_s"] = budget * 60

    budget_s   = config["lite"]["wall_clock_budget_s"]
    scan_start = datetime.utcnow()
    t_start    = time.monotonic()
    deadline   = t_start + budget_s

    def time_left() -> float:
        return max(0.0, deadline - time.monotonic())

    def elapsed() -> float:
        return time.monotonic() - t_start

    llm   = make_llm(config, model)
    board = Blackboard()

    # ── Initial classification (before recon) ─────────────────────────────
    target_info = classify(target)
    if force_type:
        target_info.target_type = force_type
    target_type = target_info.target_type

    # ── Pre-flight ────────────────────────────────────────────────────────
    console.rule("[bold cyan]WASP[/bold cyan] — Web Application Security Probe")
    console.print(f"  Target  : [bold]{target}[/bold]")
    console.print(f"  Type    : [bold cyan]{target_type}[/bold cyan]")
    console.print(f"  Model   : [bold]{llm.model}[/bold]  @ {llm.endpoint}")
    console.print(f"  Budget  : {budget_s // 60}m {budget_s % 60}s")
    console.print()

    if not llm.health_check():
        console.print(f"[bold red]✗[/bold red] Cannot reach Ollama at [bold]{llm.endpoint}[/bold]")
        raise typer.Exit(1)
    console.print(f"[green]✓[/green] Ollama reachable — model [bold]{llm.model}[/bold]")

    _cancelled = threading.Event()
    def _handle_sigint(sig, frame):
        console.print("\n[yellow]⚠[/yellow]  Interrupted — writing partial report …")
        _cancelled.set()
    signal.signal(signal.SIGINT, _handle_sigint)

    # ── Phase 1: Recon ────────────────────────────────────────────────────
    console.rule("Phase 1 — Recon")
    recon_timeout = min(
        int(config["lite"]["recon_timeout_s"]),
        int(time_left() - 60),
    )

    with console.status(f"[cyan]Running {target_type} recon …[/cyan]"):
        facts = run_recon_for_type(target, target_type, config, timeout=recon_timeout)

    # Update classification with actual port data
    if facts.open_ports:
        import subprocess as _sp, re as _re2
        fake_line = f"Host: {facts.host} ()  Ports: " + ",".join(
            f"{p}/open/tcp//{facts.port_services.get(p,'')}//" for p in facts.open_ports
        )
        target_info = reclassify(target_info, fake_line)
        if not force_type:
            target_type = target_info.target_type

    console.print(f"[green]✓[/green] Recon complete in {facts.elapsed_s:.1f}s  [dim](type: {target_type})[/dim]")
    if facts.open_ports:
        svc = [f"{p}({facts.port_services.get(p,'')})" for p in facts.open_ports[:10]]
        console.print(f"  Ports : {', '.join(svc)}")
    if facts.technologies:
        console.print(f"  Tech  : {', '.join(facts.technologies[:6])}")
    if facts.endpoints:
        console.print(f"  Paths : {len(facts.endpoints)} discovered")
    if facts.login_endpoints:
        console.print(f"  Login : {', '.join(facts.login_endpoints[:3])}")
    console.print()

    if _cancelled.is_set():
        _finish(board, target, scan_start, elapsed(), llm, config, output_dir)
        return

    # ── Phase 2: Plan ─────────────────────────────────────────────────────
    console.rule("Phase 2 — Planning")
    with console.status("[cyan]Generating hypotheses …[/cyan]"):
        hypotheses = plan_hypotheses(facts, llm, config, target_type=target_type)

    console.print(f"[green]✓[/green] {len(hypotheses)} hypotheses for [bold]{target_type}[/bold] target")
    for h in hypotheses:
        console.print(f"  [{h.priority}] [bold]{h.vuln_class}[/bold] → {h.endpoint}")
        if verbose:
            console.print(f"      {h.rationale}", style="dim")
    console.print()

    if dry_run:
        console.print("[yellow]--dry-run — skipping probes.[/yellow]")
        raise typer.Exit(0)

    if _cancelled.is_set():
        _finish(board, target, scan_start, elapsed(), llm, config, output_dir)
        return

    # ── Phase 3: Probe ────────────────────────────────────────────────────
    console.rule("Phase 3 — Probing")

    for h in hypotheses:
        if _cancelled.is_set():
            break
        remaining = time_left()
        if remaining < 15:
            console.print(f"[yellow]⏱[/yellow]  Budget exhausted — stopping")
            break

        label = f"[bold]{h.vuln_class}[/bold] → {h.endpoint}"
        with console.status(f"[cyan]Probing {label} …[/cyan]"):
            t_probe = time.monotonic()
            finding = probe_hypothesis(h, facts, llm, board, config)
            probe_s = time.monotonic() - t_probe

        if finding:
            color = _SEV_COLOR.get(finding.severity, "white")
            badge = finding.severity.value.upper()
            console.print(
                f"  [bold green]CONFIRMED[/bold green] [{color}]{badge}[/{color}]  "
                f"{finding.title}  [dim]({probe_s:.1f}s)[/dim]"
            )
        else:
            console.print(
                f"  [dim]not vulnerable[/dim]  {h.vuln_class} → {h.endpoint}  "
                f"[dim]({probe_s:.1f}s)[/dim]"
            )

    console.print()
    _finish(board, target, scan_start, elapsed(), llm, config, output_dir)


def _finish(
    board: Blackboard,
    target: str,
    scan_start: datetime,
    elapsed_s: float,
    llm: OllamaClient,
    config: dict,
    output_dir: str,
) -> None:
    """Write report and print final summary."""
    console.rule("Phase 4 — Report")

    findings = board.findings()
    if findings:
        with console.status("[cyan]Enriching findings with PoC descriptions …[/cyan]"):
            report_path = write_report(
                board, target, scan_start, elapsed_s, llm, config, output_dir
            )
        console.print(f"[green]✓[/green] Report written → [bold]{report_path}[/bold]")
    else:
        console.print("[dim]No confirmed findings — no report written.[/dim]")

    console.rule("Results")
    summary = board.summary()
    console.print(f"  Hypotheses tested : {summary['hypotheses_tested']}")
    console.print(f"  Findings          : {summary['total_findings']}")

    if findings:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Sev",      width=10)
        table.add_column("Title",    width=45)
        table.add_column("URL",      width=40)
        for f in findings:
            color = _SEV_COLOR.get(f.severity, "white")
            table.add_row(
                f"[{color}]{f.severity.value.upper()}[/{color}]",
                f.title,
                f.target_url,
            )
        console.print(table)

    m, s = divmod(int(elapsed_s), 60)
    console.print(f"\n  Total time : [bold]{m}m {s}s[/bold]")
    console.rule()


# ---------------------------------------------------------------------------


@app.command()
def network(
    cidr: str               = typer.Argument(...,  help="CIDR range to scan, e.g. 192.168.1.0/24"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
    model:       Optional[str] = typer.Option(None, "--model",  "-m", help="Override Ollama model"),
    budget:      Optional[int] = typer.Option(None, "--budget", "-b", help="Per-host budget in minutes (default: 2)"),
    output_dir:  str           = typer.Option(".",  "--output", "-o", help="Directory for the report file"),
    verbose:     bool          = typer.Option(False,"--verbose","-v", help="Show per-host detail"),
    max_hosts:   int           = typer.Option(50,   "--max-hosts",    help="Maximum hosts to scan"),
):
    """Discover and scan every live host in a CIDR range."""

    config = load_config(config_file)
    llm    = make_llm(config, model)

    host_budget_s = (budget or 2) * 60

    console.rule("[bold cyan]WASP[/bold cyan] — Network Scan")
    console.print(f"  Range     : [bold]{cidr}[/bold]")
    console.print(f"  Per-host  : {host_budget_s // 60}m budget")
    console.print(f"  Max hosts : {max_hosts}")
    console.print(f"  Model     : [bold]{llm.model}[/bold]")
    console.print()

    if not llm.health_check():
        console.print(f"[bold red]✗[/bold red] Cannot reach Ollama at [bold]{llm.endpoint}[/bold]")
        raise typer.Exit(1)
    console.print(f"[green]✓[/green] Ollama reachable\n")

    def progress(msg: str):
        console.print(f"  {msg}")

    results, report_path = run_network_scan(
        cidr          = cidr,
        llm           = llm,
        config        = config,
        output_dir    = output_dir,
        on_progress   = progress,
        max_hosts     = max_hosts,
        host_budget_s = host_budget_s,
    )

    # Final summary table
    console.rule("Network Scan Complete")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Host",      width=18)
    table.add_column("Type",      width=12)
    table.add_column("Ports",     width=24)
    table.add_column("Findings",  width=10)
    for r in results:
        ports  = ", ".join(str(p) for p in r.info.open_ports[:6])
        n      = len(r.findings)
        color  = "red" if n > 0 else "dim"
        table.add_row(
            r.info.host,
            r.info.target_type,
            ports,
            f"[{color}]{n}[/{color}]",
        )
    console.print(table)
    if report_path:
        console.print(f"\n  Report → [bold]{report_path}[/bold]")
    console.rule()


@app.command()
def doctor():
    """Check that required tools and Ollama are available."""
    config = load_config()
    llm    = make_llm(config)

    console.rule("[bold cyan]WASP Doctor[/bold cyan]")

    # Ollama
    ok = llm.health_check()
    status = "[green]✓[/green]" if ok else "[red]✗[/red]"
    console.print(f"  {status} Ollama  {llm.endpoint}  model={llm.model}")

    # External binaries
    binaries = {
        "nmap":          "apt-get install nmap",
        "gobuster":      "apt-get install gobuster",
        "httpx":         "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "sqlmap":        "apt-get install sqlmap",
        "nikto":         "apt-get install nikto",
        "nuclei":        "https://nuclei.projectdiscovery.io",
        "smbclient":     "apt-get install smbclient",
        "hydra":         "apt-get install hydra",
        "snmpwalk":      "apt-get install snmp",
        "crackmapexec":  "pip install crackmapexec  (or nxc)",
    }
    for binary, install_hint in binaries.items():
        found = shutil.which(binary) is not None
        status = "[green]✓[/green]" if found else "[yellow]–[/yellow]"
        hint   = "" if found else f"  [dim](optional — {install_hint})[/dim]"
        console.print(f"  {status} {binary}{hint}")

    # Python deps
    deps = ["httpx", "yaml", "typer", "rich"]
    for dep in deps:
        try:
            __import__(dep if dep != "yaml" else "yaml")
            console.print(f"  [green]✓[/green] Python: {dep}")
        except ImportError:
            console.print(f"  [red]✗[/red] Python: {dep}  → pip install {dep}")

    console.rule()


@app.command()
def models():
    """List Ollama models available on this machine."""
    config = load_config()
    llm    = make_llm(config)

    import httpx as _httpx
    try:
        resp = _httpx.get(f"{llm.endpoint}/api/tags", timeout=5)
        resp.raise_for_status()
        model_list = resp.json().get("models", [])
    except Exception as exc:
        console.print(f"[red]Cannot reach Ollama: {exc}[/red]")
        raise typer.Exit(1)

    console.rule("[bold cyan]Available Models[/bold cyan]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Model",          width=35)
    table.add_column("Size",           width=10)
    table.add_column("Parameters",     width=12)
    table.add_column("Quantization",   width=14)
    table.add_column("Tool Calling",   width=12)

    for m in model_list:
        name     = m.get("name", "")
        size_b   = m.get("size", 0)
        size_str = f"{size_b / 1e9:.1f} GB" if size_b else "?"
        details  = m.get("details", {})
        params   = details.get("parameter_size", "?")
        quant    = details.get("quantization_level", "?")
        caps     = m.get("capabilities", [])
        tools    = "[green]✓[/green]" if "tools" in caps else "[dim]–[/dim]"
        table.add_row(name, size_str, params, quant, tools)

    console.print(table)
    console.print(
        "\n[dim]Recommended for WASP: llama3.2:3b (installed) or "
        "qwen3:1.7b (ollama pull qwen3:1.7b)[/dim]"
    )
    console.rule()


@app.command()
def version():
    """Show WASP version."""
    console.print(f"WASP {__version__}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
