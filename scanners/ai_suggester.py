def generate_suggestions(bandit_data, semgrep_data, fuzz_data=None):
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
    if fuzz_data and fuzz_data.get("crashes", 0) > 0:
        suggestions.append({
            "file": "Dynamic Target (Sandbox)",
            "line": 0, # Use 0 instead of N/A to keep types consistent
            "severity": "CRITICAL",
            "issue": f"[FUZZ] {fuzz_data.get('status')}: Massive Payload Attack",
            "action": "The sandbox failed to handle a massive 500-byte buffer overflow payload. The application process was terminated by the OS (SIGSEGV/Crash). Immediate fix: Implement strict input length validation."
        })

    return suggestions