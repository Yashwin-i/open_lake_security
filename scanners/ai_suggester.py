"""
AI Suggester module for OpenLake Security.

This module is responsible for aggregating vulnerability data from various
scanners (Bandit, Semgrep, Fuzzing) and generating actionable security
remediation suggestions.
"""
def generate_suggestions(bandit_data, semgrep_data, fuzz_data=None):
    """
    Generates a list of remediation suggestions based on security scan results.

    Args:
        bandit_data (dict): The JSON output from a Bandit scan.
        semgrep_data (dict): The JSON output from a Semgrep scan.
        fuzz_data (dict, optional): The dictionary containing dynamic fuzzing results. Defaults to None.

    Returns:
        list: A list of dictionaries containing detailed suggestions, including
              file, line number, severity, issue description, and an action plan.
    """
    print("[*] Generating Security Suggestions...")
    suggestions = []
    
    # 1. Pull Basic Python Issues (Bandit)
    if bandit_data and "results" in bandit_data:
        for issue in bandit_data["results"]:
            suggestions.append({
                "file": issue.get("filename", "Unknown"),
                "line": issue.get("line_number", 0),
                "severity": issue.get("issue_severity", "UNKNOWN"),
                "issue": f"[SAST] {issue.get('issue_text', 'No description')}",
                "action": "Review basic Python flaw. Consider using safer standard libraries."
            })

    # 2. Pull Complex Issues (Semgrep)
    if semgrep_data and "results" in semgrep_data:
        for issue in semgrep_data["results"]:
            suggestions.append({
                "file": issue.get("path", "Unknown file"),
                "line": issue.get("start", {}).get("line", 0),
                "severity": issue.get("extra", {}).get("severity", "UNKNOWN"),
                "issue": f"[ADVANCED] {issue.get('extra', {}).get('message', 'No description')}",
                "action": "Ensure inputs are sanitized. Do not commit secrets to code."
            })
            
    # 3. Pull Dynamic Issues (Fuzzing)
    if fuzz_data:
        if fuzz_data.get("crashes", 0) > 0:
            suggestions.append({
                "file": "Dynamic Target (Sandbox)",
                "line": 0,
                "severity": "CRITICAL",
                "issue": f"[FUZZ] {fuzz_data.get('status')}: Massive Payload Attack",
                "action": "The sandbox failed to handle a massive 2000-byte buffer overflow payload. The application process was terminated by the OS (SIGSEGV/Crash). Immediate fix: Implement strict input length validation."
            })
        
        if fuzz_data.get("sql_injection_detected", False):
            suggestions.append({
                "file": "Dynamic Target (Sandbox)",
                "line": 0,
                "severity": "CRITICAL",
                "issue": f"[FUZZ] SQL Injection Detected",
                "action": "The sandbox identified a SQL injection vulnerability at `/api/user`. Attacker was able to leak database contents using `' OR '1'='1`. Immediate fix: Use parameterized queries (prepared statements) and NEVER use f-strings to build SQL queries."
            })

    return suggestions
