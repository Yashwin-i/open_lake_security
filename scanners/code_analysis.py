import sys
import subprocess
import json
import tempfile
import os

def run_bandit_scan(target_dir):
    print("[*] Running Code Security Scan (Bandit)...")
    # Write to a temp file — avoids stdout contamination from Bandit's progress output
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        command = [
            sys.executable, "-m", "bandit",
            "-r", target_dir,
            "-f", "json",
            "-o", tmp_path,
            "--quiet",          # suppress the progress bar on stderr
        ]
        subprocess.run(command, capture_output=True, text=True)
        # Bandit exits 1 when issues ARE found — we always want the file

        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"[+] Bandit found {len(data.get('results', []))} issues.")
            return data
        else:
            print("[!] Bandit produced no output file.")
            return {"error": "No output", "results": []}
    except Exception as e:
        print(f"[!] Bandit execution crashed: {e}")
        return {"error": str(e), "results": []}
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def extract_metrics(scan_data):
    if "error" in scan_data and not scan_data.get("results"):
        return {"high_severity": 0, "medium_severity": 0, "total_issues": 0}

    results = scan_data.get("results", [])
    total   = len(results)
    high    = sum(1 for r in results if r.get("issue_severity", "").upper() == "HIGH")
    medium  = sum(1 for r in results if r.get("issue_severity", "").upper() == "MEDIUM")

    # Also pull from metrics._totals if present (double-check)
    if "metrics" in scan_data and "_totals" in scan_data["metrics"]:
        totals = scan_data["metrics"]["_totals"]
        high   = max(high, int(totals.get("SEVERITY.HIGH", 0)))
        medium = max(medium, int(totals.get("SEVERITY.MEDIUM", 0)))

    return {
        "high_severity":   high,
        "medium_severity": medium,
        "total_issues":    total,
    }