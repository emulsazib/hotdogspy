# HotDogSpy — Security Audit Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A modular, **defensive** security-audit framework with a CLI **and** a web dashboard.
It resolves a target, runs network recon (nmap), analyzes packet captures for cleartext
leaks, probes for SQL injection, aggregates findings into a structured JSON schema, and uses
a pluggable LLM layer to produce prioritized remediation reports (Web / PDF / Markdown / JSON).

**HotDogSpy is free and open source software, released under the [MIT License](LICENSE).**
Anyone is welcome to use, modify, distribute, and contribute — see [Contributing](#contributing).

> ⚠️ **Authorized use only.** Only run active scans against systems you own or are explicitly
> authorized to test. Live actions are gated by an allowlist in `config/scope.yaml`.

## Architecture

```
CLI (click) ─┐                        ┌─ Web UI (FastAPI-served, vanilla JS + SSE)
             └──────► Orchestrator ◄───┘
                          │  validate → resolve → scope-gate → modules → remediation → export
   ┌──────────────┬───────┴────────┬───────────────┬─────────────────┐
 Module A       Module B         Module C        Module D         user plugins/
 recon (nmap)   packet (pcap)    sqli (probes)   reporting (LLM)   (auto-discovered)
                          │
                    ScanReport (JSON schema) ─► exporters: json / md / pdf / html
```

## Directory layout
```
audittool/           core package
  core/              schema, validation, scope, plugin, registry, orchestrator, config
  modules/
    recon/           Module A — DNS resolver + nmap wrapper/parser
    packet/          Module B — pcap ingest + cleartext/leak analyzer
    sqli/            Module C — sqlmap REST client + built-in safe probes
    reporting/       Module D — LLM adapters, prompts, reporter, exporters
  plugins/           drop-in user plugins (auto-discovered)
cli/                 click CLI (entrypoint: hotdogspy)
web/backend/         FastAPI app + async job manager (SSE progress)
web/frontend/        served dashboard (index.html, app.js, styles.css)
config/              scope.yaml (allowlist), settings.yaml (profiles, LLM)
data/samples/        sample.pcap fixture; data/reports/ generated reports
tests/               pytest suite
```

## Quick start with Docker (recommended)
The image bundles `nmap` + `tshark`, serves the dashboard, and provides the
`hotdogspy` CLI — no host Python setup required.

```bash
# 1) (optional) LLM keys for Module D / the `prompt` command
cp .env.example .env        # then edit; skip to use the offline reporter

# 2) Build + start the web dashboard
docker compose up -d --build
# open http://localhost:8000

# 3) Install the `hotdogspy` CLI wrapper on your host (routes into the container)
chmod +x bin/hotdogspy
sudo ln -sf "$(pwd)/bin/hotdogspy" /usr/local/bin/hotdogspy
```

Now use it from anywhere:
```bash
hotdogspy                          # interactive shell (type: help)
hotdogspy scan 93.184.216.34       # audit a target (add to scope.yaml or confirm)
hotdogspy report 93.184.216.34     # show the latest report for a target
hotdogspy prompt "how do I harden SSH?"   # ask the configured AI model
hotdogspy plugins                  # list scanner modules
```
Reports persist to `./data/reports/` (JSON, Markdown, HTML, PDF) via the compose volume.

> The web dashboard's history lists scans started *in the browser*; scans started
> from the CLI still write their report files to the shared `data/reports/` volume.

## Install without Docker
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .            # installs the `hotdogspy` command
hotdogspy plugins
```
External tools: `nmap` (recon), `tshark`/`scapy` (packet). `sqlmap` is optional — Module C
falls back to built-in safe probes when the sqlmap REST API is not running.

## CLI usage
`hotdogspy` with no arguments opens an interactive shell; the same verbs work as
subcommands. Simple form:
```bash
hotdogspy scan 127.0.0.1                 # default module: recon
hotdogspy report 127.0.0.1
hotdogspy prompt "explain CIS benchmarks for nginx"
```
Power-user flags on `scan`:
```bash
# Packet analysis on a pcap (passive, no authorization needed):
hotdogspy scan 127.0.0.1 --modules packet --pcap data/samples/sample.pcap

# SQLi probe against an authorized endpoint:
hotdogspy scan testphp.example --modules sqli --url "http://host/item?id=1" --yes

# Full chain:
hotdogspy scan scanme.nmap.org --modules recon,packet,sqli --yes
```

## Web dashboard
```bash
hotdogspy serve            # http://0.0.0.0:8000  (Docker maps it to localhost:8000)
```
Trigger scans, watch live progress (SSE), view the interactive report, and download exports.

## Scope enforcement
Edit `config/scope.yaml`, set `attested: true`, and add your authorized `domains` / `networks`.
Targets outside the allowlist require an explicit confirmation (`--yes` on the CLI, or the
"I attest…" checkbox / `authorized: true` in the API).

## LLM providers (Module D)
Pluggable — set one API key and it is auto-selected; with **no key** the tool uses an offline
rule-based reporter so it always runs.

| Provider | Env var | Model (config/settings.yaml) |
|----------|---------|------------------------------|
| OpenAI (GPT-4o) | `OPENAI_API_KEY` | `gpt-4o` |
| Google Gemini | `GEMINI_API_KEY` | `gemini-1.5-pro` |
| Anthropic (Claude) | `ANTHROPIC_API_KEY` | `claude-sonnet-5` |
| OpenAI-compatible (Kimi/Qwen/local) | `OPENAI_COMPATIBLE_API_KEY` + `base_url`/`model` | your model |

## Writing a plugin
Drop a `.py` file in `audittool/plugins/` that subclasses `ScannerPlugin` (or exposes a
`PLUGIN` instance / `get_plugin()` factory). See `audittool/plugins/example_plugin.py`.

## Tests
```bash
pytest -q
```

## Contributing
Contributions are welcome — bug reports, new scanner modules/plugins, provider adapters,
docs, and tests. To get started:

1. Fork the repo and create a feature branch (`git checkout -b feature/my-change`).
2. Set up the dev environment and run the suite:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt && pip install -e .
   pytest -q
   ```
3. Keep changes focused, match the existing style, and add tests for new behavior.
4. New scanners are easiest as plugins — see [Writing a plugin](#writing-a-plugin).
5. Open a pull request describing the change and its motivation.

Please keep the project's **defensive, authorized-use** posture: contributions should not add
offensive capabilities or weaken the scope-enforcement / input-validation controls. By
contributing you agree your work is licensed under the project's MIT License.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guidelines.

## License
HotDogSpy is open source under the **[MIT License](LICENSE)**, © 2026 **Emul Ahamed Sazib** —
free to use, modify, and distribute, including commercially, with attribution. It is provided
"as is", without warranty.

> Note: "MIT License" is simply the name of a widely-used permissive open-source license and
> does **not** imply any affiliation with the Massachusetts Institute of Technology. The
> copyright is held solely by the author named above.
