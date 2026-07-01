"""Command-line interface for the Security Audit Tool (`hotdogspy`).

Run `hotdogspy` with no arguments to enter an interactive shell, or use a
subcommand directly:

    hotdogspy scan 93.184.216.34         # audit a target (IP or domain)
    hotdogspy report 93.184.216.34       # show the latest report for a target
    hotdogspy prompt "how do I harden SSH?"   # ask the configured AI model
    hotdogspy plugins                    # list scanner modules
    hotdogspy serve                      # launch the web dashboard

Inside the interactive shell the same commands are available without the
`hotdogspy` prefix (type `help` or `exit`).
"""
from __future__ import annotations

import json as _json
import shlex
import sys

import click

from audittool.core.config import Settings, load_env
from audittool.core.orchestrator import Orchestrator
from audittool.core.registry import build_registry
from audittool.core.scope import Scope
from audittool.core.schema import ScanReport
from audittool.core.validation import ValidationError, validate_target
from audittool.modules.recon.resolver import resolve as resolve_target
from audittool.modules.reporting.exporters import export_all, to_markdown


# --------------------------------------------------------------------------- #
# Shared helpers (used by both the click commands and the interactive shell)
# --------------------------------------------------------------------------- #
def _confirm_scope(target, ips):
    click.secho(
        f"\n⚠  Target '{target}' ({', '.join(ips) or 'no IPs'}) is NOT in the "
        "authorized scope (config/scope.yaml).",
        fg="yellow",
    )
    return click.confirm(
        "Do you attest you are authorized to actively test this target?",
        default=False,
    )


def _progress(module, status, detail=""):
    color = {"done": "green", "running": "cyan", "error": "red",
             "skipped": "yellow", "warning": "yellow"}.get(status, "white")
    click.secho(f"  [{status:8s}] {module:10s} {detail}", fg=color)


def run_scan(target, modules=None, options=None, formats="all",
             with_remediation=True, assume_yes=False):
    """Validate -> resolve -> run modules -> remediation -> export. Returns report."""
    settings = Settings.load()
    scope = Scope.load()
    modules = modules or ["recon"]
    options = options or {}
    confirm = (lambda t, i: True) if assume_yes else _confirm_scope

    orch = Orchestrator(scope=scope, settings=settings, on_progress=_progress)
    click.secho(f"Auditing {target} with modules: {', '.join(modules)}", bold=True)
    report = orch.run(
        target=target,
        modules=modules,
        confirm=confirm,
        options=options,
        with_remediation=with_remediation,
    )

    counts = report.severity_counts()
    click.secho(
        f"\nFindings: critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} info={counts['info']}",
        bold=True,
    )

    out_dir = settings.reports_dir
    from audittool.modules.reporting import exporters as ex
    fmt = (formats or "all").lower()
    if fmt in ("all", ""):
        paths = export_all(report, out_dir)
    else:
        paths = {}
        wanted = [f.strip() for f in fmt.split(",")]
        if "json" in wanted:
            paths["json"] = str(ex.write_json(report, out_dir))
        if "markdown" in wanted or "md" in wanted:
            paths["markdown"] = str(ex.write_markdown(report, out_dir))
        if "html" in wanted:
            paths["html"] = str(ex.write_html(report, out_dir))
        if "pdf" in wanted:
            p = ex.write_pdf(report, out_dir)
            paths["pdf"] = str(p) if p else None

    click.secho("\nReports written:", bold=True)
    for kind, path in paths.items():
        click.echo(f"  {kind:9s} {path}")
    return report


def find_latest_report(target):
    """Return the most recent report JSON path whose target matches, or None."""
    settings = Settings.load()
    reports_dir = settings.reports_dir
    try:
        clean = validate_target(target)
    except ValidationError:
        clean = target
    candidates = []
    for path in reports_dir.glob("report-*.json"):
        try:
            data = _json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if (data.get("target", {}) or {}).get("input") == clean:
            candidates.append((path.stat().st_mtime, path))
    if not candidates:
        return None
    return max(candidates, key=lambda x: x[0])[1]


def show_report(target):
    """Print the latest stored report for a target as Markdown."""
    path = find_latest_report(target)
    if path is None:
        click.secho(
            f"No report found for '{target}'. Run `scan {target}` first.", fg="yellow"
        )
        return
    data = _json.loads(path.read_text(encoding="utf-8"))
    click.secho(f"(from {path})\n", fg="cyan")
    click.echo(to_markdown(ScanReport(**data)))


def ask_prompt(text):
    """Send a freeform prompt to the configured LLM provider and print the reply."""
    from audittool.modules.reporting.llm.factory import get_provider
    from audittool.modules.reporting.llm.stub import StubProvider

    settings = Settings.load()
    provider = get_provider(settings)
    if isinstance(provider, StubProvider):
        click.secho(
            "No LLM provider configured — set an API key (OPENAI_API_KEY / "
            "GEMINI_API_KEY / ANTHROPIC_API_KEY / OPENAI_COMPATIBLE_API_KEY) to "
            "use free-form prompts. See .env.example.",
            fg="yellow",
        )
        return
    system = (
        "You are a senior defensive security engineer. Give accurate, concise, "
        "actionable, defensive guidance. Do not provide offensive exploitation steps."
    )
    click.secho(f"[provider: {provider.name}]", fg="cyan")
    try:
        click.echo(provider.generate(system, text))
    except Exception as exc:
        click.secho(f"LLM request failed: {exc}", fg="red")


# --------------------------------------------------------------------------- #
# Interactive shell
# --------------------------------------------------------------------------- #
_SHELL_HELP = """Available commands:
  scan <ip|domain> [--modules recon,packet,sqli] [--yes]
  report <ip|domain>
  prompt <text ...>
  resolve <ip|domain>
  plugins
  help
  exit / quit
"""


def _shell_scan(args):
    if not args:
        click.secho("usage: scan <ip|domain> [--modules m1,m2] [--yes]", fg="yellow")
        return
    target = args[0]
    modules = ["recon"]
    assume_yes = False
    rest = args[1:]
    i = 0
    while i < len(rest):
        if rest[i] == "--modules" and i + 1 < len(rest):
            modules = [m.strip() for m in rest[i + 1].split(",") if m.strip()]
            i += 2
        elif rest[i] == "--yes":
            assume_yes = True
            i += 1
        else:
            i += 1
    try:
        run_scan(target, modules=modules, assume_yes=assume_yes)
    except ValidationError as exc:
        click.secho(f"Invalid target: {exc}", fg="red")


def interactive_shell():
    click.secho("🌭 hotdogspy — interactive security-audit shell", bold=True)
    click.secho("Type 'help' for commands, 'exit' to quit.\n", fg="cyan")
    while True:
        try:
            line = input("hotdogspy> ").strip()
        except (EOFError, KeyboardInterrupt):
            click.echo()
            break
        if not line:
            continue
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            click.secho(f"parse error: {exc}", fg="red")
            continue
        cmd, args = parts[0].lower(), parts[1:]

        if cmd in ("exit", "quit"):
            break
        elif cmd == "help":
            click.echo(_SHELL_HELP)
        elif cmd == "scan":
            _shell_scan(args)
        elif cmd == "report":
            if args:
                show_report(args[0])
            else:
                click.secho("usage: report <ip|domain>", fg="yellow")
        elif cmd == "prompt":
            if args:
                ask_prompt(" ".join(args))
            else:
                click.secho("usage: prompt <text ...>", fg="yellow")
        elif cmd == "resolve":
            if args:
                try:
                    clean = validate_target(args[0])
                    click.echo(f"{clean} -> {', '.join(resolve_target(clean)) or '(none)'}")
                except ValidationError as exc:
                    click.secho(f"Invalid target: {exc}", fg="red")
            else:
                click.secho("usage: resolve <ip|domain>", fg="yellow")
        elif cmd == "plugins":
            for p in build_registry().all():
                gate = "scope-gated" if p.requires_authorization else "passive"
                click.echo(f"{p.name:12s} [{gate:11s}] {p.description}")
        else:
            click.secho(f"unknown command: {cmd} (type 'help')", fg="yellow")


# --------------------------------------------------------------------------- #
# Click command group
# --------------------------------------------------------------------------- #
@click.group(invoke_without_command=True)
@click.version_option("0.1.0", prog_name="hotdogspy")
@click.pass_context
def cli(ctx):
    """hotdogspy — modular defensive security-audit framework.

    Run with no command to enter the interactive shell.
    """
    load_env()
    if ctx.invoked_subcommand is None:
        interactive_shell()


@cli.command()
@click.argument("target")
@click.option("--modules", default="recon", help="Comma-separated module names.")
@click.option("--profile", default=None, help="nmap scan profile (recon module).")
@click.option("--pcap", default=None, help="Path to a .pcap for the packet module.")
@click.option("--url", default=None, help="Target URL for the sqli module.")
@click.option("--params", default=None, help="Comma-separated params to test (sqli).")
@click.option("--no-remediation", is_flag=True, help="Skip Module D (AI remediation).")
@click.option("--yes", is_flag=True, help="Auto-confirm scope (non-interactive).")
@click.option("--format", "formats", default="all",
              help="Export formats: all|json|markdown|html|pdf (comma-separated).")
def scan(target, modules, profile, pcap, url, params, no_remediation, yes, formats):
    """Audit a TARGET (IP or domain)."""
    module_list = [m.strip() for m in modules.split(",") if m.strip()]
    options = {"profile": profile, "pcap": pcap, "url": url, "params": params, "live": False}
    try:
        run_scan(target, modules=module_list, options=options, formats=formats,
                 with_remediation=not no_remediation, assume_yes=yes)
    except ValidationError as exc:
        click.secho(f"Invalid target: {exc}", fg="red")
        sys.exit(2)


@cli.command()
@click.argument("target")
def report(target):
    """Show the latest report for a TARGET (IP or domain)."""
    show_report(target)


@cli.command()
@click.argument("text", nargs=-1, required=True)
def prompt(text):
    """Ask the configured AI model a free-form security question."""
    ask_prompt(" ".join(text))


@cli.command()
@click.argument("target")
def resolve(target):
    """Validate a target and resolve it to IP addresses."""
    try:
        clean = validate_target(target)
    except ValidationError as exc:
        click.secho(f"Invalid target: {exc}", fg="red")
        sys.exit(2)
    ips = resolve_target(clean)
    click.echo(f"target : {clean}")
    click.echo(f"ips    : {', '.join(ips) if ips else '(none resolved)'}")


@cli.command()
def plugins():
    """List all registered scanner modules/plugins."""
    for p in build_registry().all():
        gate = "scope-gated" if p.requires_authorization else "passive"
        click.echo(f"{p.name:12s} [{gate:11s}] {p.description}")


@cli.command()
@click.option("--host", default="0.0.0.0")
@click.option("--port", default=8000, type=int)
@click.option("--reload/--no-reload", default=False)
def serve(host, port, reload):
    """Launch the web dashboard (FastAPI + served UI)."""
    import uvicorn

    uvicorn.run("web.backend.app:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    cli()
