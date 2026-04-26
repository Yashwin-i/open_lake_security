import json
import os
import glob
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Importing backend engines (unchanged)
from utils.cloner import clone_repo
from scanners.code_analysis import run_bandit_scan, extract_metrics
from scanners.advanced_analysis import run_semgrep_scan, extract_semgrep_metrics
from scanners.fuzz_analysis import run_fuzz_scan, extract_fuzz_metrics
from scanners.ai_suggester import generate_suggestions
from scanners.threat_mapper import generate_threat_model

app = FastAPI(title="OpenLake Security API")

# Serve static frontend files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def serve_frontend():
    return FileResponse("static/index.html")


class ScanRequest(BaseModel):
    repo_url: str


@app.post("/api/scan")
def run_scan(body: ScanRequest):
    repo_url = body.repo_url.strip()
    if not repo_url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid repository URL.")

    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    scan_dir = "temp_scan_zone"

    pipeline_errors = []

    # ── 1. Clone ──────────────────────────────────────────────────────────────
    try:
        clone_repo(repo_url, scan_dir)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Clone failed: {e}")

    # ── 2. SAST — Bandit ──────────────────────────────────────────────────────
    try:
        bandit_data = run_bandit_scan(scan_dir)
    except Exception as e:
        print(f"[!] Bandit exception: {e}")
        bandit_data = {"error": str(e), "results": []}
        pipeline_errors.append(f"Bandit: {e}")

    # ── 3. Advanced — Semgrep ─────────────────────────────────────────────────
    try:
        semgrep_data = run_semgrep_scan(scan_dir)
    except Exception as e:
        print(f"[!] Semgrep exception: {e}")
        semgrep_data = {"error": str(e), "results": []}
        pipeline_errors.append(f"Semgrep: {e}")

    # ── 4. Auto-generate Dockerfile if missing ────────────────────────────────
    dockerfile_path = os.path.join(scan_dir, "Dockerfile")
    if not os.path.exists(dockerfile_path):
        with open(dockerfile_path, "w") as f:
            f.write("""FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; \\
    elif [ -f src/requirements.txt ]; then pip install -r src/requirements.txt; \\
    else pip install flask rich; fi
RUN pip install -U Flask Werkzeug
RUN find . -name "*.py" -exec sed -i 's/app.run()/app.run(host="0.0.0.0", port=5000)/g' {} +
RUN find . -name "*.py" -exec sed -i 's/app.run(debug=True)/app.run(host="0.0.0.0", port=5000, debug=True)/g' {} +
EXPOSE 5000
ENV PYTHONPATH=/app/src:/app
CMD ["sh", "-c", "if [ -f src/main.py ]; then python src/main.py; \\
     elif [ -f app.py ]; then python app.py; \\
     elif [ -f main.py ]; then python main.py; \\
     else py_file=$(find . -maxdepth 1 -name '*.py' | head -n 1); FLASK_APP=$py_file flask run --host=0.0.0.0; fi"]
""")

    # ── 5. Dynamic Fuzzing — Docker sandbox ───────────────────────────────────
    try:
        fuzz_data = run_fuzz_scan(scan_dir)
    except Exception as e:
        print(f"[!] Fuzz exception: {e}")
        fuzz_data = {
            "error": str(e),
            "status": "Fuzzing skipped (Docker unavailable or error)",
            "crashes": 0,
            "sql_injection_detected": False,
            "sqli_details": {},
            "details": [],
        }
        pipeline_errors.append(f"Fuzzing: {e}")

    # ── 6. Metrics ────────────────────────────────────────────────────────────
    b_metrics = extract_metrics(bandit_data)
    s_metrics = extract_semgrep_metrics(semgrep_data)
    f_metrics = extract_fuzz_metrics(fuzz_data)

    # ── 7. AI Remediation & Threat Model ─────────────────────
    try:
        suggestions = generate_suggestions(bandit_data, semgrep_data, fuzz_data)
    except Exception as e:
        print(f"[!] Suggestions exception: {e}")
        suggestions = []
        pipeline_errors.append(f"AI Suggestions: {e}")

    try:
        threat_model_diagram = generate_threat_model(scan_dir)
    except Exception as e:
        print(f"[!] Threat model exception: {e}")
        threat_model_diagram = ""
        pipeline_errors.append(f"Threat model: {e}")

    # ── 8. Persist to Data Lake ───────────────────────────────
    os.makedirs("data_lake", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"data_lake/{repo_name}_{timestamp}.json"

    lake_entry = {
        "project": repo_name,
        "scan_date": str(datetime.now()),
        "source": repo_url,
        "pipeline_errors": pipeline_errors,
        "metrics": {
            "basic_issues": b_metrics["total_issues"],
            "advanced_issues": s_metrics["total_advanced_issues"],
            "fuzz_crashes": f_metrics["fuzz_crashes"],
            "fuzz_vuln_count": f_metrics.get("fuzz_vuln_count", 0),
        },
        "remediation_plan": suggestions,
        "threat_model": threat_model_diagram,
        "raw_scans": {
            "bandit": bandit_data,
            "semgrep": semgrep_data,
            "fuzzing": fuzz_data,
        },
    }

    with open(filename, "w") as f:
        json.dump(lake_entry, f, indent=4)

    return JSONResponse(content=lake_entry)


@app.get("/api/scans")
def list_scans():
    files = sorted(
        glob.glob("data_lake/*.json"),
        key=os.path.getctime,
        reverse=True,
    )
    result = []
    for fp in files:
        basename = os.path.basename(fp)
        stat = os.stat(fp)
        result.append({
            "filename": basename,
            "size_bytes": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        })
    return result


@app.get("/api/scans/latest")
def get_latest_scan():
    files = glob.glob("data_lake/*.json")
    if not files:
        raise HTTPException(status_code=404, detail="No scans found.")
    latest = max(files, key=os.path.getctime)
    with open(latest, "r") as f:
        return JSONResponse(content=json.load(f))


@app.get("/api/scans/{filename}")
def get_scan(filename: str):
    # Prevent path traversal
    safe = os.path.basename(filename)
    path = os.path.join("data_lake", safe)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Scan not found.")
    with open(path, "r") as f:
        return JSONResponse(content=json.load(f))
