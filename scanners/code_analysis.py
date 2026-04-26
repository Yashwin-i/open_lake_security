"""
Code Analysis module for OpenLake Security.

This module provides functions to run Bandit scans on target directories
to identify security issues in Python code and extract metric summaries.
"""
import sys
import subprocess
import json

def run_bandit_scan(target_dir):
    """
    Run a basic Python code security scan using Bandit.

    Args:
        target_dir (str): The directory containing Python code to scan.

    Returns:
        dict: A dictionary containing the Bandit scan results in JSON format.
              Returns an error dictionary if the scan fails.
    """
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
    """
    Extract issue severity metrics from Bandit scan data.

    Args:
        scan_data (dict): The parsed JSON output from a Bandit scan.

    Returns:
        dict: A dictionary containing metric counts for high and medium severity issues, 
              as well as total issues.
    """
    if "metrics" not in scan_data or "_totals" not in scan_data["metrics"]:
        return {"high_severity": 0, "medium_severity": 0, "total_issues": 0}
        
    totals = scan_data["metrics"]["_totals"]
    return {
        "high_severity": totals.get("SEVERITY.HIGH", 0),
        "medium_severity": totals.get("SEVERITY.MEDIUM", 0),
        "total_issues": len(scan_data.get("results", []))
    }
