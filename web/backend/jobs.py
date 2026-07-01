"""In-process async scan job manager with progress events.

Blocking work (nmap, pcap parsing) runs in a thread executor so the event loop
stays responsive. Progress events are pushed onto a per-job asyncio.Queue that
the SSE endpoint drains. Finished reports are persisted under data/reports.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from audittool.core.config import Settings
from audittool.core.orchestrator import Orchestrator
from audittool.core.scope import Scope
from audittool.modules.reporting.exporters import export_all
from audittool.core.schema import ScanReport


@dataclass
class Job:
    id: str
    target: str
    modules: List[str]
    status: str = "queued"  # queued|running|done|error
    created_at: float = field(default_factory=time.time)
    events: List[dict] = field(default_factory=list)
    report: Optional[ScanReport] = None
    exports: Dict[str, Optional[str]] = field(default_factory=dict)
    error: Optional[str] = None
    _queue: "asyncio.Queue" = field(default=None, repr=False)


class JobManager:
    def __init__(self) -> None:
        self.jobs: Dict[str, Job] = {}
        self.settings = Settings.load()

    def create(self, target: str, modules: List[str], options: dict, authorized: bool) -> Job:
        job = Job(id=_short_id(), target=target, modules=modules)
        job._queue = asyncio.Queue()
        self.jobs[job.id] = job
        asyncio.create_task(self._run(job, options, authorized))
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)

    def list(self) -> List[Job]:
        return sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True)

    async def _run(self, job: Job, options: dict, authorized: bool) -> None:
        loop = asyncio.get_running_loop()
        job.status = "running"

        def on_progress(module, status, detail=""):
            evt = {"module": module, "status": status, "detail": detail, "ts": time.time()}
            job.events.append(evt)
            # thread-safe hand-off to the event loop
            loop.call_soon_threadsafe(job._queue.put_nowait, evt)

        # API-side scope confirmation: honor an explicit authorized flag.
        confirm = (lambda t, i: True) if authorized else (lambda t, i: False)

        def work() -> ScanReport:
            orch = Orchestrator(scope=Scope.load(), settings=self.settings, on_progress=on_progress)
            return orch.run(job.target, job.modules, confirm=confirm, options=options)

        try:
            report = await loop.run_in_executor(None, work)
            job.report = report
            job.exports = export_all(report, self.settings.reports_dir)
            job.status = "done"
        except Exception as exc:  # pragma: no cover - defensive
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            on_progress("scan", "error", job.error)
        finally:
            loop.call_soon_threadsafe(job._queue.put_nowait, {"module": "scan", "status": "_end", "detail": ""})


def _short_id() -> str:
    import uuid

    return uuid.uuid4().hex[:12]
