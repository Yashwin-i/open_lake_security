# Bandit test ID → specific remediation action
BANDIT_ACTIONS = {
    "B101": "Remove assert statements from production code — they can be disabled with -O flag. Use explicit raise/validation instead.",
    "B102": "Replace os.exec* calls with subprocess.run() with strict argument lists and shell=False.",
    "B103": "File permissions are too permissive. Use os.chmod with minimal required permission (e.g. 0o640).",
    "B104": "Binding to 0.0.0.0 exposes the service on all interfaces. Bind to 127.0.0.1 in production or use a reverse proxy.",
    "B105": "Hardcoded password/secret detected. Move to environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).",
    "B106": "Hardcoded password in function argument. Use environment variable: os.environ.get('SECRET_KEY').",
    "B107": "Hardcoded password in function call. Externalize to a config file or environment variable.",
    "B108": "Insecure temporary file. Use tempfile.mkstemp() or tempfile.TemporaryFile() instead.",
    "B110": "Try/except/pass silently swallows exceptions. Log the exception or re-raise it.",
    "B112": "Try/except/continue silently ignores errors in loops. Add logging at minimum.",
    "B201": "Flask debug mode is ON. Set debug=False in production — it exposes the interactive debugger.",
    "B202": "Flask app run with debug=True. This enables remote code execution via the Werkzeug debugger PIN bypass.",
    "B301": "Pickle deserialization can execute arbitrary code. Use JSON or another safe serialisation format for untrusted data.",
    "B302": "marshal.loads() is unsafe. Use json.loads() for untrusted input.",
    "B303": "MD2/MD4/MD5 are broken hash algorithms. Use SHA-256 or SHA-3 for new code.",
    "B304": "Deprecated cipher mode. Use AES-GCM or ChaCha20-Poly1305 for authenticated encryption.",
    "B305": "ECB cipher mode is insecure — identical plaintext blocks produce identical ciphertext. Use CBC or GCM.",
    "B306": "mktemp() is vulnerable to race conditions. Use tempfile.mkstemp() instead.",
    "B307": "eval() executes arbitrary code. Replace with ast.literal_eval() for safe parsing of literals.",
    "B308": "mark_safe() in Django disables HTML escaping. Avoid using it with user-supplied content.",
    "B310": "Audit redirect URL for open redirect vulnerability. Validate the target against an allowlist.",
    "B311": "Standard pseudo-random generators are not cryptographically secure. Use secrets module for security-sensitive values.",
    "B312": "Telnet is unencrypted. Use SSH instead.",
    "B313": "XML parsing vulnerable to malicious XML attacks (Billion Laughs / XXE). Use defusedxml instead.",
    "B314": "xml.etree.ElementTree is vulnerable to XXE. Use defusedxml.ElementTree instead.",
    "B315": "xml.expat is vulnerable to entity expansion. Use defusedxml instead.",
    "B316": "xml.dom is vulnerable to XXE. Use defusedxml.minidom instead.",
    "B317": "xml.sax is vulnerable to XXE. Use defusedxml.sax instead.",
    "B318": "xml.dom.minidom is vulnerable to XXE. Use defusedxml.minidom instead.",
    "B319": "xml.dom.pulldom is vulnerable to XXE. Use defusedxml.pulldom instead.",
    "B320": "lxml is vulnerable to XXE by default. Set resolve_entities=False on the XMLParser.",
    "B321": "FTP sends credentials in plaintext. Use SFTP or SCP instead.",
    "B322": "input() in Python 2 is equivalent to eval(). Use raw_input(). (Python 2 code detected.)",
    "B323": "SSL/TLS: unverified context. Use ssl.create_default_context() and verify certificates.",
    "B324": "hashlib using weak algorithm. Replace MD5/SHA1 with SHA-256 or SHA-3.",
    "B325": "tempnam() is unsafe. Use tempfile.mkstemp().",
    "B401": "telnetlib is deprecated and sends data in plaintext. Use paramiko (SSH) instead.",
    "B402": "ftplib sends data in plaintext. Replace with ftplib over TLS or use paramiko SFTP.",
    "B403": "pickle/cPickle can deserialise arbitrary objects. Avoid for untrusted data; use JSON.",
    "B404": "subprocess module can be dangerous. Ensure shell=False and validate all arguments.",
    "B405": "xml.etree — parse only trusted XML. Use defusedxml for untrusted input.",
    "B406": "xml.sax — use defusedxml for untrusted XML.",
    "B407": "xml.expat — use defusedxml for untrusted XML.",
    "B408": "xml.dom — use defusedxml for untrusted XML.",
    "B409": "xml.dom.minidom — use defusedxml for untrusted XML.",
    "B410": "lxml — set resolve_entities=False to prevent XXE.",
    "B411": "xmlrpc.server exposes functions over the network. Restrict access and validate inputs.",
    "B412": "httpoxy can lead to SSRF in CGI environments. Unset HTTP_PROXY in environment or use a safe HTTP client.",
    "B501": "TLS certificate verification disabled. Set verify=True in requests.get/post.",
    "B502": "SSL version too old. Use ssl.PROTOCOL_TLS_CLIENT.",
    "B503": "SSL: unsafe cipher list. Use ssl.create_default_context() for a safe default configuration.",
    "B504": "SSL options weakening security (e.g. OP_NO_SSLv2). Remove unsafe option flags.",
    "B505": "Weak cryptographic key length. Use RSA ≥ 2048 bits or ECC ≥ 256 bits.",
    "B506": "yaml.load() without Loader is unsafe. Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
    "B507": "Paramiko host key not verified. Set AutoAddPolicy only for testing; use RejectPolicy or known_hosts in production.",
    "B601": "Shell injection via paramiko. Validate all command arguments before execution.",
    "B602": "subprocess with shell=True enables shell injection. Set shell=False and pass args as a list.",
    "B603": "subprocess call with non-constant arguments. Ensure all arguments are validated and shell=False.",
    "B604": "Function call with shell=True. Set shell=False and construct argument list explicitly.",
    "B605": "os.system() enables shell injection. Use subprocess.run([...], shell=False) instead.",
    "B606": "os.popen() enables shell injection. Use subprocess.run() instead.",
    "B607": "Starting a process with a partial path. Use an absolute path to prevent PATH hijacking.",
    "B608": "SQL query constructed via string formatting — SQL injection risk. Use parameterised queries (cursor.execute(sql, params)).",
    "B609": "Wildcard injection in subprocess. Explicitly list allowed arguments instead of using glob expansion.",
    "B610": "Django extra() with user input — potential SQL injection. Use annotate() / filter() with ORM lookups instead.",
    "B611": "Django RawSQL with user input. Use parameterised queries via ORM or cursor.execute(sql, [params]).",
    "B701": "Jinja2 autoescape is disabled. Enable autoescape=True to prevent XSS in rendered templates.",
    "B702": "Mako templates are not auto-escaped. Use MarkupSafe and escape all dynamic values.",
    "B703": "Django template mark_safe() with user content. Remove mark_safe() or sanitize with bleach before use.",
}

SEMGREP_ACTIONS = {
    "sql-injection":       "Use parameterised queries or an ORM. Never concatenate user input into SQL strings.",
    "xss":                 "HTML-escape all user-supplied output. Use template engines with auto-escaping enabled.",
    "hardcoded-secret":    "Remove secret from source code. Use environment variables or a secrets manager.",
    "command-injection":   "Avoid shell=True. Pass arguments as a list to subprocess.run(). Validate all inputs.",
    "path-traversal":      "Resolve file paths with os.path.realpath() and reject any path that escapes the base directory.",
    "insecure-hash":       "Replace MD5/SHA1 with SHA-256 (hashlib.sha256) or bcrypt for passwords.",
    "ssrf":                "Validate and allowlist all outgoing URLs. Block requests to internal/private IP ranges.",
    "open-redirect":       "Validate redirect targets against an explicit allowlist of allowed URLs.",
    "deserialization":     "Avoid pickle/yaml.load for untrusted data. Use JSON or yaml.safe_load().",
    "debug-enabled":       "Set DEBUG=False and ensure stack traces are never exposed in production responses.",
    "weak-crypto":         "Replace weak cipher/algorithm with AES-256-GCM or ChaCha20-Poly1305.",
    "use-after-free":      "Audit memory ownership. Use smart pointers or safe language constructs.",
    "null-dereference":    "Add a null/None check before dereferencing. Use Optional types where appropriate.",
    "integer-overflow":    "Use safe integer arithmetic. Validate numeric ranges on all user-supplied values.",
    "csrf":                "Enable CSRF protection (Django: CsrfViewMiddleware, Flask: flask-wtf CSRFProtect).",
    "jwt-none-algorithm":  "Reject tokens with alg: none. Explicitly validate the algorithm in your JWT library.",
    "cors-wildcard":       "Restrict CORS to specific trusted origins. Do not use Access-Control-Allow-Origin: *.",
    "logging-sensitive":   "Do not log passwords, tokens, or PII. Scrub sensitive fields before logging.",
}


def _bandit_action(issue):
    """Return a specific remediation action for a Bandit issue."""
    test_id  = issue.get("test_id", "")
    test_name = issue.get("test_name", "").lower().replace("_", "-")
    severity  = issue.get("issue_severity", "").upper()
    text      = issue.get("issue_text", "")

    if test_id in BANDIT_ACTIONS:
        return BANDIT_ACTIONS[test_id]

    # fallback: derive from test name
    for keyword, action in SEMGREP_ACTIONS.items():
        if keyword in test_name or keyword in text.lower():
            return action

    # final fallback by severity
    if severity == "HIGH":
        return f"High-severity issue: {text[:120]}. Audit and fix immediately."
    if severity == "MEDIUM":
        return f"Medium-severity issue: {text[:120]}. Schedule for remediation."
    return f"Low-severity issue: {text[:120]}. Review when possible."


def _semgrep_action(issue):
    """Return a specific remediation action for a Semgrep issue."""
    extra   = issue.get("extra", {})
    rule_id = issue.get("check_id", "").lower()
    message = extra.get("message", "")
    metadata = extra.get("metadata", {})

    # Try OWASP / CWE categories from metadata
    for owasp in metadata.get("owasp", []):
        owasp_l = owasp.lower()
        if "a01" in owasp_l or "injection" in owasp_l:
            return SEMGREP_ACTIONS["sql-injection"]
        if "a02" in owasp_l or "cryptograph" in owasp_l:
            return SEMGREP_ACTIONS["weak-crypto"]
        if "a03" in owasp_l or "xss" in owasp_l:
            return SEMGREP_ACTIONS["xss"]
        if "a07" in owasp_l or "authenticat" in owasp_l:
            return "Enforce strong authentication. Avoid hardcoded credentials or weak session management."

    # Match against rule ID keywords
    for keyword, action in SEMGREP_ACTIONS.items():
        if keyword in rule_id:
            return action

    # Match against message keywords
    msg_l = message.lower()
    for keyword, action in SEMGREP_ACTIONS.items():
        if keyword.replace("-", " ") in msg_l or keyword in msg_l:
            return action

    # Use semgrep message itself as guidance if available
    if message:
        return f"Semgrep: {message[:180]}"

    return "Review and sanitize this code pattern. Consult the semgrep rule documentation for guidance."


def generate_suggestions(bandit_data, semgrep_data, fuzz_data=None):
    print("[*] Generating Security Suggestions...")
    suggestions = []

    # 1. Bandit SAST findings
    if bandit_data and "results" in bandit_data:
        for issue in bandit_data["results"]:
            suggestions.append({
                "file":     issue.get("filename", "Unknown"),
                "line":     issue.get("line_number", 0),
                "severity": issue.get("issue_severity", "UNKNOWN").upper(),
                "issue":    f"[SAST] {issue.get('issue_text', 'No description')} ({issue.get('test_id', '')})",
                "action":   _bandit_action(issue),
            })

    # 2. Semgrep advanced findings
    if semgrep_data and "results" in semgrep_data:
        for issue in semgrep_data["results"]:
            extra = issue.get("extra", {})
            suggestions.append({
                "file":     issue.get("path", "Unknown file"),
                "line":     issue.get("start", {}).get("line", 0),
                "severity": extra.get("severity", "UNKNOWN").upper(),
                "issue":    f"[ADVANCED] {extra.get('message', 'No description')} (rule: {issue.get('check_id', '?')})",
                "action":   _semgrep_action(issue),
            })

    # 3. Dynamic fuzzing findings
    if fuzz_data:
        if fuzz_data.get("crashes", 0) > 0:
            suggestions.append({
                "file":     "Dynamic Target (Docker Sandbox)",
                "line":     0,
                "severity": "CRITICAL",
                "issue":    f"[FUZZ] DoS / Overflow — application crashed under {fuzz_data.get('status', 'payload stress')}",
                "action":   "Application terminated on oversized payload. Enforce Content-Length limits at the ingress layer. Add request body size caps (e.g. MAX_CONTENT_LENGTH in Flask).",
            })
        if fuzz_data.get("sql_injection_detected"):
            d = fuzz_data.get("sqli_details", {})
            ep = d.get("endpoint", "unknown endpoint")
            payload = d.get("payload", "' OR '1'='1")
            suggestions.append({
                "file":     f"Dynamic Target — {ep}",
                "line":     0,
                "severity": "CRITICAL",
                "issue":    f"[FUZZ] SQL Injection confirmed at {ep} using payload: {payload}",
                "action":   "Use parameterised queries (cursor.execute(sql, params)). Never build SQL strings with f-strings or % formatting. Validate and reject suspicious input patterns at the API layer.",
            })
        if fuzz_data.get("xss_detected"):
            d = fuzz_data.get("xss_details", {})
            ep = d.get("endpoint", "unknown endpoint")
            suggestions.append({
                "file":     f"Dynamic Target — {ep}",
                "line":     0,
                "severity": "HIGH",
                "issue":    f"[FUZZ] XSS reflection confirmed at {ep} — script tag echoed in response",
                "action":   "HTML-encode all user-supplied output before rendering. Enable autoescape in Jinja2/Mako. Implement a Content-Security-Policy header.",
            })
        if fuzz_data.get("path_traversal_detected"):
            d = fuzz_data.get("path_traversal_details", {})
            ep = d.get("endpoint", "unknown endpoint")
            suggestions.append({
                "file":     f"Dynamic Target — {ep}",
                "line":     0,
                "severity": "HIGH",
                "issue":    f"[FUZZ] Path Traversal confirmed at {ep} — ../../../../etc/passwd accessible",
                "action":   "Resolve all file paths with os.path.realpath(). Reject any resolved path that does not start with the expected base directory. Never directly concatenate user input into file paths.",
            })
        if fuzz_data.get("auth_bypass_detected"):
            suggestions.append({
                "file":     "Dynamic Target — /admin endpoint",
                "line":     0,
                "severity": "HIGH",
                "issue":    "[FUZZ] Auth bypass via forged X-Forwarded-For / X-Real-IP headers",
                "action":   "Never trust client-supplied IP headers for access control. Implement server-side session/token authentication. If behind a proxy, only trust the X-Forwarded-For from the known proxy IP.",
            })

    return suggestions