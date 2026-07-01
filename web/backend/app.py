"""FastAPI application: REST API + served static dashboard."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from audittool.core.config import PROJECT_ROOT, load_env
from audittool.core.registry import build_registry
from .jobs import JobManager

load_env()

app = FastAPI(title="Security Audit Tool", version="0.1.0")
manager = JobManager()

FRONTEND_DIR = PROJECT_ROOT / "web" / "frontend"


class ScanRequest(BaseModel):
    target: str
    modules: List[str] = ["recon"]
    authorized: bool = False  # explicit attestation for scope-gated modules
    profile: Optional[str] = None
    pcap: Optional[str] = None
    url: Optional[str] = None
    params: Optional[str] = None


@app.get("/api/plugins")
def list_plugins():
    reg = build_registry()
    return [
        {"name": p.name, "description": p.description,
         "requires_authorization": p.requires_authorization}
        for p in reg.all()
    ]


@app.post("/api/scans")
async def start_scan(req: ScanRequest):
    options = {
        "profile": req.profile,
        "pcap": req.pcap,
        "url": req.url,
        "params": req.params,
        "live": False,
    }
    job = manager.create(req.target, req.modules, options, req.authorized)
    return {"id": job.id, "status": job.status}


@app.get("/api/scans")
def list_scans():
    return [
        {"id": j.id, "target": j.target, "modules": j.modules,
         "status": j.status, "created_at": j.created_at}
        for j in manager.list()
    ]


@app.get("/api/scans/{job_id}")
def get_scan(job_id: str):
    job = manager.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    payload = {
        "id": job.id, "target": job.target, "modules": job.modules,
        "status": job.status, "error": job.error, "events": job.events,
        "exports": job.exports,
    }
    if job.report is not None:
        payload["report"] = json.loads(job.report.model_dump_json())
    return payload


@app.get("/api/scans/{job_id}/events")
async def scan_events(job_id: str):
    job = manager.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")

    async def event_stream():
        # Replay events already recorded, then stream live ones.
        for evt in list(job.events):
            yield f"data: {json.dumps(evt)}\n\n"
        while True:
            evt = await job._queue.get()
            if evt.get("status") == "_end":
                yield f"data: {json.dumps({'status': 'complete', 'job': job.status})}\n\n"
                break
            yield f"data: {json.dumps(evt)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/reports/{filename}")
def download_report(filename: str):
    # Only allow files inside the reports dir (path-traversal guard).
    reports_dir = manager.settings.reports_dir
    path = (reports_dir / filename).resolve()
    if reports_dir not in path.parents or not path.exists():
        raise HTTPException(404, "report not found")
    return FileResponse(str(path))


@app.get("/", response_class=HTMLResponse)
def index():
    index_file = FRONTEND_DIR / "index.html"
    return HTMLResponse(index_file.read_text(encoding="utf-8"))


# Serve static assets (app.js, styles.css).
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
