from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any

from functions import (
    analyze_firewall_logs,
    analyze_auth_service_logs,
    alert_by_reason,
    alert_by_domain,
    fetch_logs_for_service,
    generic_log_count_analysis,
    ANALYSIS_HANDLERS
)

app = FastAPI()

### -------------------- Pydantic Models -------------------- ###
class JobRequest(BaseModel):
    job_id: int
    service_name: str
    analysis_type: str
    alert_enabled: Optional[bool] = False
    alert_channel: Optional[str] = None
    alert_target: Optional[str] = None

### -------------------- Endpoints -------------------- ###

@app.get("/")
def root():
    return {"message": "FastAPI log analysis service is up!"}


class ManualAnalysisRequest(BaseModel):
    service_name: str
    range_seconds: Optional[int] = 360
    threshold: Optional[int] = 3
    field: Optional[str] = "status"
    keyword: Optional[str] = "error"



@app.post("/manual-analyze/{analysis_type}")
async def manual_analyze(analysis_type: str, request: ManualAnalysisRequest):
    handler = ANALYSIS_HANDLERS.get(analysis_type)
    if not handler:
        return {"error": f"Unknown analysis type: {analysis_type}"}

    try:
        # These handle their own fetching internally
        if analysis_type in ["generic_log_search", "log_pattern_timeseries"]:
            field = getattr(request, "field", "status")
            keyword = getattr(request, "keyword", "error")
            result = handler["func"](
                service_name=request.service_name,
                field=field,
                keyword=keyword,
                range_seconds=request.range_seconds
            )
            return {"status": "success", "result": result}

        # For analysis types that need logs passed to them
        logs = fetch_logs_for_service(request.service_name, range_seconds=request.range_seconds)
        if not logs:
            return {"message": "No logs found for the given service and time range."}

        if analysis_type == "failed_logins":
            result = handler["func"](logs, threshold=request.threshold)
        else:
            result = handler["func"](logs)

        return {"status": "success", "result": result}

    except Exception as e:
        return {"error": str(e)}


