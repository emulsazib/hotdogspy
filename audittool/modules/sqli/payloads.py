"""Built-in, dependency-light SQLi probes (safe fallback when sqlmap is absent).

These probes are *detection-oriented*: they look for error-based, boolean-based,
and time-based signals without attempting data exfiltration. They only run
against explicitly user-specified endpoints/parameters and are rate-capped.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ...core.schema import Finding, Severity

# DB error fingerprints indicating a query broke on our input (error-based).
_SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "sqlite3.operationalerror",
    "org.postgresql.util.psqlexception",
    "ora-01756",
    "microsoft odbc",
    "sqlstate",
]

_ERROR_PAYLOADS = ["'", '"', "')", "';"]
_BOOLEAN_TRUE = "' OR '1'='1"
_BOOLEAN_FALSE = "' AND '1'='2"


def _inject(url: str, param: str, value: str) -> str:
    """Return url with `param` replaced by `value` in the query string."""
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[param] = value
    new_query = urlencode(query)
    return urlunparse(parts._replace(query=new_query))


def _contains_sql_error(text: str) -> Optional[str]:
    low = text.lower()
    for sig in _SQL_ERRORS:
        if sig in low:
            return sig
    return None


class ProbeRunner:
    def __init__(self, timeout: int = 10, time_delay: int = 3, max_requests: int = 40):
        self.timeout = timeout
        self.time_delay = time_delay
        self.max_requests = max_requests
        self._count = 0

    def _get(self, url: str):
        import requests

        if self._count >= self.max_requests:
            raise RuntimeError("request cap reached")
        self._count += 1
        start = time.monotonic()
        resp = requests.get(url, timeout=self.timeout + self.time_delay + 5)
        elapsed = time.monotonic() - start
        return resp, elapsed

    def probe_param(self, url: str, param: str) -> List[Finding]:
        findings: List[Finding] = []

        # Baseline
        try:
            baseline, base_time = self._get(_inject(url, param, "1"))
        except Exception as exc:
            return [Finding(module="sqli", title=f"Probe error on '{param}'",
                            severity=Severity.info, description=str(exc))]
        baseline_text = baseline.text

        # 1) Error-based
        for payload in _ERROR_PAYLOADS:
            try:
                resp, _ = self._get(_inject(url, param, payload))
            except Exception:
                break
            sig = _contains_sql_error(resp.text)
            if sig:
                findings.append(Finding(
                    module="sqli",
                    title=f"Error-based SQLi indicator on '{param}'",
                    severity=Severity.high,
                    description=(f"Parameter '{param}' returned a database error "
                                 f"when injected with {payload!r}."),
                    evidence=f"matched signature: {sig}",
                    metadata={"param": param, "type": "error-based", "payload": payload},
                ))
                break

        # 2) Boolean-based (true vs false differ, true ~ baseline)
        try:
            true_resp, _ = self._get(_inject(url, param, _BOOLEAN_TRUE))
            false_resp, _ = self._get(_inject(url, param, _BOOLEAN_FALSE))
            if (len(true_resp.text) != len(false_resp.text)
                    and abs(len(true_resp.text) - len(baseline_text)) < abs(len(false_resp.text) - len(baseline_text))):
                findings.append(Finding(
                    module="sqli",
                    title=f"Boolean-based SQLi indicator on '{param}'",
                    severity=Severity.high,
                    description=(f"Parameter '{param}' shows boolean-differential "
                                 "responses between always-true and always-false payloads."),
                    evidence=f"true_len={len(true_resp.text)} false_len={len(false_resp.text)} "
                             f"base_len={len(baseline_text)}",
                    metadata={"param": param, "type": "boolean-based"},
                ))
        except Exception:
            pass

        # 3) Time-based (SLEEP). Only flag if delayed response clearly exceeds baseline.
        sleep_payload = f"1' AND SLEEP({self.time_delay})-- -"
        try:
            _, delayed_time = self._get(_inject(url, param, sleep_payload))
            if delayed_time >= self.time_delay and delayed_time > base_time + (self.time_delay * 0.7):
                findings.append(Finding(
                    module="sqli",
                    title=f"Time-based SQLi indicator on '{param}'",
                    severity=Severity.critical,
                    description=(f"Parameter '{param}' response was delayed ~{delayed_time:.1f}s "
                                 f"with a SLEEP({self.time_delay}) payload (baseline {base_time:.1f}s)."),
                    evidence=f"delayed={delayed_time:.2f}s baseline={base_time:.2f}s",
                    metadata={"param": param, "type": "time-based"},
                ))
        except Exception:
            pass

        return findings


def run_probes(url: str, params: List[str], settings) -> List[Finding]:
    cfg = settings.get("sqli", {}) or {}
    runner = ProbeRunner(
        timeout=int(cfg.get("request_timeout_seconds", 10)),
        time_delay=int(cfg.get("time_based_delay_seconds", 3)),
        max_requests=int(cfg.get("max_requests_per_endpoint", 40)),
    )
    findings: List[Finding] = []
    # If no params given, derive them from the URL query string.
    if not params:
        params = [k for k, _ in parse_qsl(urlparse(url).query)]
    for param in params:
        findings.extend(runner.probe_param(url, param))
    return findings
