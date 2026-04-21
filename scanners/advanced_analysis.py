"""
advanced_analysis.py — Semgrep SAST scanner
Works correctly on WSL2/Linux (primary target) and Windows.
"""
import sys
import subprocess
import shutil
import json
import tempfile
import os


def _find_semgrep():
    """Locate the semgrep binary. Returns a list [cmd] or None."""
    # 1. 'semgrep' on PATH (Linux/WSL2 — the normal case)
    found = shutil.which("semgrep")
    if found:
        return [found]

    # 2. Same Scripts/ dir as the running Python (Windows pip install)
    scripts_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
    candidate   = os.path.join(scripts_dir, "semgrep.exe")
    if os.path.exists(candidate):
        return [candidate]

    return None


def run_semgrep_scan(target_dir):
    print("[*] Running Advanced Multi-Language Scan (Semgrep)...")

    semgrep_cmd = _find_semgrep()
    if not semgrep_cmd:
        print("[!] semgrep not found on PATH.")
        return {"error": "semgrep not found", "results": []}

    print(f"[*] Using semgrep: {semgrep_cmd[0]}")
    abs_target = os.path.abspath(target_dir)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        tmp_path = tmp.name

    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"]       = "1"

        result = subprocess.run(
            semgrep_cmd + ["scan", "--config=auto", "--json", "--output", tmp_path, abs_target],
            capture_output=True,
            text=True,
            timeout=240,
            env=env,
        )

        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 4:
            with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read().strip()
            idx = raw.find("{")
            if idx >= 0:
                data = json.loads(raw[idx:])
                count = len(data.get("results", []))
                print(f"[+] Semgrep found {count} issues.")
                return data

        # Fallback: try stdout (Linux semgrep works this way)
        stdout = (result.stdout or "").strip()
        idx = stdout.find("{")
        if idx >= 0:
            data = json.loads(stdout[idx:])
            count = len(data.get("results", []))
            print(f"[+] Semgrep found {count} issues (stdout).")
            return data

        stderr_preview = (result.stderr or "")[:300]
        print(f"[!] Semgrep produced no output. exit={result.returncode} stderr={stderr_preview}")
        return {"error": f"No output (exit {result.returncode})", "details": stderr_preview, "results": []}

    except subprocess.TimeoutExpired:
        print("[!] Semgrep timed out.")
        return {"error": "Timeout", "results": []}
    except json.JSONDecodeError as e:
        print(f"[!] Semgrep JSON parse error: {e}")
        return {"error": f"JSON parse: {e}", "results": []}
    except Exception as e:
        print(f"[!] Semgrep crashed: {e}")
        return {"error": str(e), "results": []}
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def extract_semgrep_metrics(scan_data):
    results = scan_data.get("results", [])
    return {"total_advanced_issues": len(results)}