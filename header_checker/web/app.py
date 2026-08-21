"""
header_checker.web.app
=======================
FastAPI application for the local web dashboard.

Endpoints:
    GET  /           -> single-page dashboard
    POST /api/scan   -> run a scan, return the full result as JSON

The server binds to 127.0.0.1 by default; it is meant for local,
interactive use -- not for hosting a public service.
"""
from __future__ import annotations

from importlib import resources
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from ..core.scan_engine import run_scan
from ..utils.models import ScanOptions

app = FastAPI(title="HTTP Header Checker", docs_url="/api/docs", redoc_url=None)

_STATIC_DIR = Path(resources.files("header_checker.web")) / "static"


class ScanRequest(BaseModel):
    url: str
    method: str = Field(default="GET", pattern="^(GET|HEAD|OPTIONS)$")
    timeout: int = Field(default=15, ge=1, le=120)
    follow_redirects: bool = True
    verify_ssl: bool = False


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.post("/api/scan")
def api_scan(req: ScanRequest) -> dict:
    options = ScanOptions(
        method=req.method,
        timeout=req.timeout,
        follow_redirects=req.follow_redirects,
        verify_ssl=req.verify_ssl,
    )
    result = run_scan(req.url, options=options, analyst="web-dashboard")
    return result.to_dict()
