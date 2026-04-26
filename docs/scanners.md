# Scanners Guide

OpenLake Security incorporates multiple specialized tools (scanners) under the `scanners/` directory to evaluate the security of a target codebase. Each module performs a distinct type of analysis.

## Available Scanners

### 1. Static Analysis: Bandit
**File:** `code_analysis.py`

Runs [Bandit](https://github.com/PyCQA/bandit) against Python source code. Bandit is designed to find common security issues in Python by analyzing its Abstract Syntax Tree (AST). It checks for:
- Use of insecure libraries or functions (like `subprocess` without care, `pickle`, `eval`).
- Hardcoded secrets and weak cryptography functions.

### 2. Advanced Pattern Matching: Semgrep
**File:** `advanced_analysis.py`

Runs [Semgrep](https://semgrep.dev/) to detect deeper semantic flaws. It looks at the actual logic and structure of the code, detecting:
- Cross-Site Scripting (XSS), SQL Injections, Path Traversals.
- Exposed tokens, dangerous configuration patterns, and misconfigurations beyond just Python (depending on Semgrep's active rulesets).

### 3. Dynamic Application Security Testing (DAST)
**File:** `fuzz_analysis.py`

This scanner builds a temporary Docker container around the target application, attempting to expose and attack its endpoints locally. It verifies vulnerabilities such as:
- **Massive Payloads:** Attempts buffer overflows or Denial of Service conditions by pushing oversized strings.
- **SQL Injection:** Fires basic SQL tautologies against identified endpoints to check for database leakage or unhandled exceptions.

### 4. Automated Threat Modeling
**File:** `threat_mapper.py`

Instead of just checking for bugs, this module performs architectural analysis using regex to identify endpoints and database connections. It maps out:
- Web exposure paths.
- Internal linkages and dependencies.
- Generates a Mermaid.js diagram to visualize potential attack vectors.

## Adding a New Scanner

To integrate a new tool:
1. Create a new module inside the `scanners/` directory (e.g., `my_new_scanner.py`).
2. Add a `run_scan(target_dir)` function to execute your tool.
3. Parse the results and return them in a standardized dictionary format.
4. Integrate the new function call inside `dashboard.py` during the target scan lifecycle.
