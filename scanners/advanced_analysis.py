import subprocess
import json

def run_semgrep_scan(target_dir):
    print("[*] Running Advanced Multi-Language Scan (Semgrep)...")
    # shell=True and a direct string is the safest way to execute on Windows
    command = f"semgrep scan --config=p/default --json {target_dir}"
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                print(f"[!] Semgrep JSON Error. Output was: {result.stdout[:200]}...")
                return {"error": "Invalid JSON"}
        else:
            print(f"[!] Semgrep failed or found nothing. Error: {result.stderr}")
            return {"error": "No output", "details": result.stderr}
    except Exception as e:
        print(f"[!] Semgrep execution crashed: {str(e)}")
        return {"error": str(e)}

def extract_semgrep_metrics(scan_data):
    if "results" not in scan_data:
        return {"total_advanced_issues": 0}
    return {"total_advanced_issues": len(scan_data["results"])}