# Contributing to HotDogSpy

Thanks for your interest in improving HotDogSpy! This is an open source, MIT-licensed
defensive security-audit framework, and community contributions are very welcome.

## Ways to contribute
- Report bugs and request features via issues.
- Add or improve scanner **modules / plugins** (recon, packet, sqli, reporting, or new ones).
- Add **LLM provider adapters** for Module D.
- Improve documentation, examples, and tests.

## Ground rules — defensive scope
HotDogSpy is a **defensive** tool for **authorized** testing only. Please ensure contributions:
- Do **not** add offensive/exploitation capabilities or data-exfiltration features.
- Do **not** weaken the safety controls: input validation (`audittool/core/validation.py`),
  scope enforcement (`audittool/core/scope.py`), or the no-shell execution model.
- Keep active/network-touching modules gated behind `requires_authorization` + scope checks.

## Development setup
```bash
git clone <your-fork-url> && cd hotdogspy
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
pytest -q
```
Optional external tools for full functionality: `nmap` (recon) and `tshark` (packet capture).
You can also develop entirely in Docker: `docker compose up -d --build`.

## Making changes
1. Create a feature branch: `git checkout -b feature/short-description`.
2. Keep changes focused and match the surrounding code style.
3. Add tests under `tests/` for new behavior; run `pytest -q` and make sure it passes.
4. Update the README / docstrings if you change user-facing behavior.

## Writing a plugin
The easiest way to extend HotDogSpy is a drop-in plugin. Create a `.py` file in
`audittool/plugins/` that subclasses `ScannerPlugin` (or exposes a `PLUGIN` instance /
`get_plugin()` factory). See `audittool/plugins/example_plugin.py` for a template. The
registry auto-discovers it, and it becomes available on the CLI, the API, and the dashboard.

## Pull requests
- Describe **what** the change does and **why**.
- Reference any related issue.
- Ensure `pytest -q` passes and there are no stray debug artifacts.

## License of contributions
By submitting a contribution, you agree that it is licensed under the project's
[MIT License](LICENSE).
