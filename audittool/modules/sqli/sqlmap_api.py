"""Client for the sqlmap REST API (``sqlmapapi -s``).

Used when a sqlmap API server is reachable; otherwise Module C falls back to the
built-in :mod:`payloads` probes. Kept small and defensive — a thin wrapper over
the documented task-based endpoints.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional

from ...core.schema import Finding, Severity


class SqlmapApiClient:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _session(self):
        import requests

        return requests.Session()

    def is_available(self) -> bool:
        try:
            import requests

            r = requests.get(f"{self.base_url}/admin/0/list", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def scan(self, url: str, extra_options: Optional[Dict] = None,
             poll_interval: int = 3, max_wait: int = 120) -> Dict:
        s = self._session()
        # 1) new task
        task_id = s.get(f"{self.base_url}/task/new", timeout=self.timeout).json()["taskid"]
        # 2) set options + start
        options = {"url": url}
        if extra_options:
            options.update(extra_options)
        s.post(f"{self.base_url}/scan/{task_id}/start", json=options, timeout=self.timeout)
        # 3) poll status
        waited = 0
        while waited < max_wait:
            status = s.get(f"{self.base_url}/scan/{task_id}/status", timeout=self.timeout).json()
            if status.get("status") == "terminated":
                break
            time.sleep(poll_interval)
            waited += poll_interval
        # 4) collect data + log
        data = s.get(f"{self.base_url}/scan/{task_id}/data", timeout=self.timeout).json()
        log = s.get(f"{self.base_url}/scan/{task_id}/log", timeout=self.timeout).json()
        return {"taskid": task_id, "data": data, "log": log}


def findings_from_sqlmap(result: Dict, url: str) -> List[Finding]:
    findings: List[Finding] = []
    data_items = (result.get("data") or {}).get("data", []) if isinstance(result.get("data"), dict) else []
    if data_items:
        findings.append(Finding(
            module="sqli",
            title="SQL injection confirmed by sqlmap",
            severity=Severity.critical,
            description=f"sqlmap identified injectable parameter(s) at {url}.",
            evidence="sqlmap returned dumped data structures",
            metadata={"url": url, "engine": "sqlmap"},
        ))
    # Surface warnings/criticals from the log stream.
    for entry in (result.get("log") or {}).get("log", []):
        level = entry.get("level", "").lower()
        if level in ("critical", "warning") and "injectable" in entry.get("message", "").lower():
            findings.append(Finding(
                module="sqli",
                title="sqlmap: injectable parameter",
                severity=Severity.high,
                description=entry.get("message", ""),
                metadata={"url": url, "engine": "sqlmap", "level": level},
            ))
    return findings
