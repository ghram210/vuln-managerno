import subprocess
import shutil
import os
import random
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import sanitize_target, sanitize_options
from runner import run_streaming, pause_process, resume_process

app = FastAPI(title="ZAP API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TIMEOUT_STEALTH = 1800
TIMEOUT_NORMAL  = 1200

# ZAP baseline script path
ZAP_SCRIPT = os.path.join(os.path.dirname(__file__), "zap-baseline.py")

class ScanRequest(BaseModel):
    target: str
    options: str = ""
    stealth: bool = True
    scan_id: str | None = None

@app.get("/health")
def health():
    script_exists = os.path.exists(ZAP_SCRIPT)
    return {
        "status": "ok",
        "tool": "zap",
        "installed": script_exists,
        "path": ZAP_SCRIPT,
    }

@app.post("/scan")
def run_zap(req: ScanRequest):
    try:
        target = sanitize_target(req.target)
        options = sanitize_options(req.options) if req.options.strip() else ""
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not os.path.exists(ZAP_SCRIPT):
        raise HTTPException(
            status_code=500,
            detail="zap-baseline.py is not found in the scan-servers directory.",
        )

    # Base command
    # -s: short output format
    # -j: use the Ajax spider in addition to the traditional one (disabled for speed in baseline)
    cmd = [
        "python3", ZAP_SCRIPT,
        "-t", target,
        "-s"
    ]

    if req.stealth:
        timeout = TIMEOUT_STEALTH
        # No specific "stealth" flag for baseline, but we can limit spider time
        cmd += ["-m", "1"]
    else:
        timeout = TIMEOUT_NORMAL
        cmd += ["-m", "3"]

    if options:
        # ZAP baseline uses -z for extra ZAP options, but we can also pass script options directly
        cmd.extend(options.split())

    mode_label = "STEALTH" if req.stealth else "NORMAL"

    try:
        raw, rc = run_streaming(cmd, timeout=timeout, label="ZAP", scan_id=req.scan_id)
        if not raw.strip():
            output = f"ZAP [{mode_label} MODE]: No output returned from ZAP."
        else:
            output = raw
    except Exception as e:
        output = f"Error running ZAP: {type(e).__name__}: {str(e)}"

    return {
        "tool": "zap",
        "target": target,
        "mode": mode_label,
        "command": " ".join(cmd),
        "output": output,
        "status": "completed",
    }

@app.post("/pause/{scan_id}")
def pause(scan_id: str):
    ok, msg = pause_process(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    return {"ok": True, "scan_id": scan_id, "message": msg}

@app.post("/resume/{scan_id}")
def resume(scan_id: str):
    ok, msg = resume_process(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    return {"ok": True, "scan_id": scan_id, "message": msg}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)
