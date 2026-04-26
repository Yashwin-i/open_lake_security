"""
Advanced Analysis module for OpenLake Security.

This module provides functions to run Semgrep scans on target directories
and extract advanced security metrics from the scan results.
"""
import subprocess
import json

def run_semgrep_scan(target_dir):
    """
    Run an advanced multi-language scan using Semgrep.

    Args:
        target_dir (str): The directory to scan.

    Returns:
        dict: A dictionary containing the Semgrep scan results in JSON format.
              Returns an error dictionary if the scan fails.
    """
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
    """
    Extract advanced metrics from Semgrep scan data.

    Args:
        scan_data (dict): The parsed JSON output from a Semgrep scan.

    Returns:
        dict: A dictionary containing metric counts, specifically 'total_advanced_issues'.
    """
    if "results" not in scan_data:
        return {"total_advanced_issues": 0}
    return {"total_advanced_issues": len(scan_data["results"])}
