import sys
import subprocess
import json

def run_bandit_scan(target_dir):
    print("[*] Running Code Security Scan (Bandit)...")
    # sys.executable ensures we use the exact Python environment running this script
    command = [sys.executable, "-m", "bandit", "-r", target_dir, "-f", "json"]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.stdout.strip():
            return json.loads(result.stdout)
        else:
            print(f"[!] Bandit gave no output. Error: {result.stderr}")
            return {"error": "No output", "details": result.stderr}
    except Exception as e:
        print(f"[!] Bandit execution crashed: {str(e)}")
        return {"error": str(e)}

def extract_metrics(scan_data):
    if "metrics" not in scan_data or "_totals" not in scan_data["metrics"]:
        return {"high_severity": 0, "medium_severity": 0, "total_issues": 0}
        
    totals = scan_data["metrics"]["_totals"]
    return {
        "high_severity": totals.get("SEVERITY.HIGH", 0),
        "medium_severity": totals.get("SEVERITY.MEDIUM", 0),
        "total_issues": len(scan_data.get("results", []))
    }