"""
DPI Engine Web Backend - FastAPI
Runs the compiled C++ dpi_json binary and serves results as JSON API.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
import subprocess, os, uuid, json
from pathlib import Path
from typing import Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="DPI Engine API", version="1.0")

FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if FRONTEND_ORIGIN == "*" else [origin.strip() for origin in FRONTEND_ORIGIN.split(",") if origin.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
BINARY = BASE_DIR / "build" / "dpi_json"
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"

UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

KNOWN_APPS = [
    "HTTP", "HTTPS", "DNS", "TLS", "QUIC",
    "GOOGLE", "FACEBOOK", "YOUTUBE", "TWITTER", "INSTAGRAM",
    "NETFLIX", "AMAZON", "MICROSOFT", "APPLE", "WHATSAPP",
    "TELEGRAM", "TIKTOK", "SPOTIFY", "ZOOM", "DISCORD",
    "GITHUB", "CLOUDFLARE",
]


@app.get("/health")
def health():
    return {
        "status": "ok",
        "binary_found": BINARY.exists(),
        "binary_path": str(BINARY),
    }


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    block_apps: Optional[str] = Form(default=""),
):
    if not file.filename.endswith(".pcap"):
        raise HTTPException(400, "Only .pcap files are supported")

    job_id = str(uuid.uuid4())[:8]
    input_path = UPLOAD_DIR / f"{job_id}_input.pcap"
    output_path = OUTPUT_DIR / f"{job_id}_output.pcap"

    try:
        contents = await file.read()
        if len(contents) < 24:
            raise HTTPException(400, "File too small to be a valid PCAP")
        if len(contents) > 50 * 1024 * 1024:
            raise HTTPException(400, "File too large (max 50 MB)")

        input_path.write_bytes(contents)
        cmd = [str(BINARY), str(input_path), str(output_path)]

        if block_apps:
            for app_name in block_apps.split(","):
                app_name = app_name.strip().upper()
                if app_name in KNOWN_APPS:
                    cmd += ["--block-app", app_name]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise HTTPException(500, f"Analysis failed: {result.stderr[:200]}")

        analysis = json.loads(result.stdout)
        analysis["job_id"] = job_id
        analysis["filename"] = file.filename
        analysis["file_size"] = len(contents)
        analysis["blocked_apps"] = [a.strip().upper() for a in (block_apps or "").split(",") if a.strip()]
        return JSONResponse(analysis)

    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Analysis timed out (> 60 seconds)")
    finally:
        try:
            if input_path.exists():
                input_path.unlink()
        except Exception:
            pass


@app.get("/download/{job_id}")
def download(job_id: str):
    if not job_id.replace("-", "").isalnum() or len(job_id) > 40:
        raise HTTPException(400, "Invalid job ID")
    path = OUTPUT_DIR / f"{job_id}_output.pcap"
    if not path.exists():
        raise HTTPException(404, "Output file not found")
    return FileResponse(path, media_type="application/octet-stream", filename=f"filtered_{job_id}.pcap")

