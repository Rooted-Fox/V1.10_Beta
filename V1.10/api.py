"""FastAPI backend for the ASVP platform."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import report_generator
import runtime_settings
import scan_runner
import scheduler
import triage_job
from models import RemediationStatus
from pending_store import PendingFindingsStore
from store import FindingsStore
from token_store import TokenStore

app = FastAPI(title="ASVP Platform API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST", "PATCH", "DELETE"])

store = FindingsStore()
pending_store = PendingFindingsStore()
token_store = TokenStore()
api = APIRouter(prefix="/api")


# ---- apps ----------------------------------------------------------------

@api.get("/apps")
def list_apps():
    return store.list_apps()


# ---- findings ------------------------------------------------------------

@api.get("/findings")
def list_findings(app_name: Optional[str] = None):
    return [dict(r) for r in store.all(app_name=app_name)]


@api.get("/findings/{finding_id}")
def get_finding(finding_id: int):
    row = store.get(finding_id)
    if not row:
        raise HTTPException(404, "Finding not found")
    return dict(row)


class RemediationUpdate(BaseModel):
    status: RemediationStatus
    notes: Optional[str] = None


@api.patch("/findings/{finding_id}/remediation")
def update_remediation(finding_id: int, body: RemediationUpdate):
    store.update_remediation(finding_id, body.status, body.notes)
    return {"id": finding_id, "status": body.status.value}


# Backward-compat shim
@api.patch("/findings/{finding_id}")
def update_finding_status(finding_id: int, body: RemediationUpdate):
    return update_remediation(finding_id, body)


# ---- summaries -----------------------------------------------------------

@api.get("/summary/severity")
def severity_summary(app_name: Optional[str] = None):
    return store.severity_summary(app_name=app_name)


@api.get("/summary/category")
def category_summary(app_name: Optional[str] = None):
    return store.category_summary(app_name=app_name)


@api.get("/summary/remediation")
def remediation_summary(app_name: Optional[str] = None):
    return store.remediation_summary(app_name=app_name)


# ---- attack chains -------------------------------------------------------

@api.get("/chains")
def list_chains(app_name: Optional[str] = None):
    rows = store.chains(app_name=app_name)
    import json
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["finding_ids"] = json.loads(d.get("finding_ids", "[]"))
        except Exception:
            d["finding_ids"] = []
        result.append(d)
    return result


# ---- comparison ----------------------------------------------------------

@api.get("/comparison")
def scan_comparison(app_name: str, since: str):
    return store.scan_comparison(app_name, since)


# ---- settings ------------------------------------------------------------

class SettingsUpdate(BaseModel):
    provider: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    agent_model: Optional[str] = None
    azure_foundry_endpoint: Optional[str] = None
    azure_foundry_api_key: Optional[str] = None
    zap_api_url: Optional[str] = None
    zap_api_key: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    token_limit: Optional[int] = None
    ai_enabled: Optional[bool] = None
    skip_info_findings: Optional[bool] = None


def _settings_view() -> dict:
    s = runtime_settings.get_settings()
    return {
        "provider": s["provider"],
        "anthropic_api_key_set": bool(s["anthropic_api_key"]),
        "anthropic_api_key_masked": runtime_settings.masked(s["anthropic_api_key"]),
        "agent_model": s["agent_model"],
        "azure_foundry_endpoint": s["azure_foundry_endpoint"],
        "azure_foundry_api_key_set": bool(s["azure_foundry_api_key"]),
        "azure_foundry_api_key_masked": runtime_settings.masked(s["azure_foundry_api_key"]),
        "zap_api_url": s["zap_api_url"],
        "zap_api_key_set": bool(s["zap_api_key"]),
        "slack_webhook_url_set": bool(s["slack_webhook_url"]),
        "token_limit": s["token_limit"],
        "ai_enabled": s["ai_enabled"],
        "skip_info_findings": s["skip_info_findings"],
    }


@api.get("/settings")
def get_settings():
    return _settings_view()


@api.post("/settings")
def update_settings(body: SettingsUpdate):
    runtime_settings.update_settings(**body.model_dump(exclude_none=True))
    return _settings_view()


# ---- scan ----------------------------------------------------------------

class ScanRequest(BaseModel):
    target_url: str
    app_name: Optional[str] = None


@api.post("/scan")
def trigger_scan(body: ScanRequest):
    if not body.target_url.startswith(("http://", "https://")):
        raise HTTPException(400, "Enter a full URL including http:// or https://")
    started = scan_runner.start_scan(body.target_url, app_name=body.app_name)
    if not started:
        raise HTTPException(409, "A scan is already running.")
    return {"status": "started", "target_url": body.target_url, "app_name": body.app_name}


@api.get("/scan/status")
def scan_status():
    return scan_runner.status()


# ---- pending & triage ----------------------------------------------------

@api.get("/pending")
def pending_summary(app_name: Optional[str] = None):
    rows = pending_store.pending(app_name=app_name)
    return {
        "count": len(rows),
        "by_category": pending_store.pending_summary(app_name=app_name),
        "findings": [dict(r) for r in rows],
    }


class TriageRequest(BaseModel):
    app_name: Optional[str] = None


@api.post("/triage")
def trigger_triage(body: TriageRequest):
    if not runtime_settings.get_settings()["ai_enabled"]:
        raise HTTPException(400, "AI integration is off. Enable it in Settings.")
    if not runtime_settings.has_api_key():
        raise HTTPException(400, "Add your API credentials in Settings before approving triage.")
    pending_count = len(pending_store.pending(app_name=body.app_name))
    if pending_count == 0:
        raise HTTPException(400, "Nothing pending - run a scan first.")
    token_limit = runtime_settings.get_settings()["token_limit"]
    if not token_store.has_budget(token_limit):
        raise HTTPException(400, f"Token budget ({token_limit}) reached. Reset usage in Settings.")
    started = triage_job.start_triage(app_name=body.app_name, token_limit=token_limit)
    if not started:
        raise HTTPException(409, "Triage is already running.")
    return {"status": "started", "pending_count": pending_count}


@api.get("/triage/status")
def triage_status():
    return triage_job.status()


# ---- tokens --------------------------------------------------------------

@api.get("/tokens")
def token_usage():
    s = runtime_settings.get_settings()
    used = token_store.total_used()
    limit = s["token_limit"]
    return {
        "used": used,
        "limit": limit,
        "remaining": max(limit - used, 0) if limit else None,
        "by_category": token_store.usage_by_category(),
    }


@api.post("/tokens/reset")
def reset_tokens():
    token_store.reset()
    return token_usage()


# ---- reports -------------------------------------------------------------

@api.get("/report/html")
def html_report(app_name: Optional[str] = None):
    html = report_generator.generate_html(app_name=app_name)
    return Response(content=html, media_type="text/html")


@api.get("/report/csv")
def csv_report(app_name: Optional[str] = None):
    csv_content = report_generator.generate_csv(app_name=app_name)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings.csv"},
    )


@api.get("/report/json")
def json_report(app_name: Optional[str] = None):
    return Response(
        content=report_generator.generate_json(app_name=app_name),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=findings.json"},
    )


# ---- schedules -----------------------------------------------------------

class ScheduleCreate(BaseModel):
    target_url: str
    app_name: Optional[str] = None
    cron: str = "0 2 * * *"  # daily at 2am
    enabled: bool = True


@api.get("/schedules")
def list_schedules():
    return scheduler.list_schedules()


@api.post("/schedules")
def create_schedule(body: ScheduleCreate):
    return scheduler.add_schedule(body.target_url, body.app_name, body.cron, body.enabled)


@api.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: str):
    if not scheduler.delete_schedule(schedule_id):
        raise HTTPException(404, "Schedule not found")
    return {"deleted": schedule_id}


@api.patch("/schedules/{schedule_id}")
class ScheduleToggle(BaseModel):
    enabled: bool


@api.patch("/schedules/{schedule_id}")
def toggle_schedule(schedule_id: str, body: ScheduleToggle):
    if not scheduler.toggle_schedule(schedule_id, body.enabled):
        raise HTTPException(404, "Schedule not found")
    return {"id": schedule_id, "enabled": body.enabled}


app.include_router(api)
_fe = Path(__file__).parent / "frontend"
app.mount("/", StaticFiles(directory=str(_fe), html=True), name="frontend")
