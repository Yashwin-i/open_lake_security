import streamlit as st
import json
import os
import glob
import pandas as pd
from datetime import datetime

# Importing backend engines
from utils.cloner import clone_repo
from scanners.code_analysis import run_bandit_scan, extract_metrics
from scanners.advanced_analysis import run_semgrep_scan, extract_semgrep_metrics
from scanners.fuzz_analysis import run_fuzz_scan, extract_fuzz_metrics
from scanners.ai_suggester import generate_suggestions
from scanners.threat_mapper import generate_threat_model 

st.set_page_config(page_title="OpenLake Security", page_icon="🌊", layout="wide")

st.title("🌊 OpenLake Security Dashboard")
st.markdown("Unified Security Data Lake & Remediation Center")
st.divider()

# ==========================================
# 1. THE INPUT ENGINE
# ==========================================
st.subheader("🎯 Target Selection")
repo_url = st.text_input("Paste the GitHub Repository URL to scan:", placeholder="https://github.com/videvelopers/Vulnerable-Flask-App")

if st.button("🚀 Run Security Scan"):
    if not repo_url.startswith("http"):
        st.error("❌ Please enter a valid HTTP/HTTPS GitHub URL.")
    else:
        with st.spinner(f"Cloning and scanning repository... This might take a minute."):
            
            repo_name = repo_url.split("/")[-1].replace(".git", "")
            scan_dir = "temp_scan_zone"
            
            # Triggering the pipeline!
            clone_repo(repo_url, scan_dir)
            bandit_data = run_bandit_scan(scan_dir) 
            semgrep_data = run_semgrep_scan(scan_dir)
            
            # 🚀 Sandbox Fuzzing!
            dockerfile_path = os.path.join(scan_dir, "Dockerfile")
            if not os.path.exists(dockerfile_path):
                st.info("ℹ️ No Dockerfile found in repo. Auto-generating a generic Python environment for sandbox testing...")
                with open(dockerfile_path, "w") as f:
                    f.write('''FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; elif [ -f src/requirements.txt ]; then pip install -r src/requirements.txt; else pip install flask rich; fi
RUN pip install -U Flask Werkzeug
RUN find . -name "*.py" -exec sed -i 's/app.run()/app.run(host="0.0.0.0", port=5000)/g' {} +
RUN find . -name "*.py" -exec sed -i 's/app.run(debug=True)/app.run(host="0.0.0.0", port=5000, debug=True)/g' {} +
EXPOSE 5000
ENV PYTHONPATH=/app/src:/app
CMD ["sh", "-c", "if [ -f src/main.py ]; then python src/main.py; elif [ -f app.py ]; then python app.py; elif [ -f main.py ]; then python main.py; else py_file=$(find . -maxdepth 1 -name '*.py' | head -n 1); FLASK_APP=$py_file flask run --host=0.0.0.0; fi"]
''')
            
            fuzz_data = run_fuzz_scan(scan_dir)

            b_metrics = extract_metrics(bandit_data)
            s_metrics = extract_semgrep_metrics(semgrep_data)
            f_metrics = extract_fuzz_metrics(fuzz_data)
            
            # Generate suggestions using all scan data
            suggestions = generate_suggestions(bandit_data, semgrep_data, fuzz_data)
            
            # Generate threat model
            threat_model_diagram = generate_threat_model(scan_dir)
            
            # Dumping to Data Lake
            os.makedirs("data_lake", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"data_lake/{repo_name}_{timestamp}.json"
            
            lake_entry = {
                "project": repo_name,
                "scan_date": str(datetime.now()),
                "source": repo_url,
                "metrics": {
                    "basic_issues": b_metrics["total_issues"],
                    "advanced_issues": s_metrics["total_advanced_issues"],
                    "fuzz_crashes": f_metrics["fuzz_crashes"]
                },
                "remediation_plan": suggestions,
                "threat_model": threat_model_diagram,
                "raw_scans": {
                    "bandit": bandit_data, 
                    "semgrep": semgrep_data,
                    "fuzzing": fuzz_data
                }
            }
            
            with open(filename, "w") as f:
                json.dump(lake_entry, f, indent=4)
                
            st.rerun()

st.divider()

# ==========================================
# 2. THE VISUALIZATION DASHBOARD
# ==========================================
list_of_files = glob.glob('data_lake/*.json')

if not list_of_files:
    st.info("👋 Welcome! Paste a link above and hit Scan to generate your first dashboard.")
    st.stop()

latest_file = max(list_of_files, key=os.path.getctime)

with open(latest_file, "r") as f:
    data = json.load(f)

st.header(f"📦 Project: `{data.get('project', 'Unknown')}`")
st.caption(f"Source: {data.get('source', 'Unknown')} | Scanned on: {data.get('scan_date', 'Unknown')}")

st.subheader("📊 Vulnerability Metrics")
col1, col2, col3, col4 = st.columns(4)

metrics = data.get("metrics", {})
b_issues = metrics.get("basic_issues", 0)
a_issues = metrics.get("advanced_issues", 0)
f_crashes = metrics.get("fuzz_crashes", 0)

col1.metric(label="Total Issues Discovered", value=b_issues + a_issues + f_crashes)
col2.metric(label="Basic Flaws (SAST)", value=b_issues)
col3.metric(label="Complex Flaws (Advanced)", value=a_issues)
col4.metric(label="Dynamic Crashes (Fuzz)", value=f_crashes, delta=f_crashes, delta_color="inverse")

st.divider()

# ==========================================
# 🚀 NEW: DYNAMIC ATTACK VISUALIZATION
# ==========================================
st.subheader("🔥 Dynamic Sandbox Analysis")
fuzz_raw = data.get("raw_scans", {}).get("fuzzing", {})

# --- 1. SQL Injection Visualization ---
st.markdown("### 🧬 Attack A: SQL Injection")
if fuzz_raw.get("sql_injection_detected", False):
    st.error("🚨 **SQL INJECTION CONFIRMED**")
    col_s1, col_s2 = st.columns([1, 2])
    
    sqli_details = fuzz_raw.get("sqli_details", {})
    endpoint = sqli_details.get("endpoint", "Unknown Endpoint")
    method = sqli_details.get("method", "GET/POST")
    payload = sqli_details.get("payload", "' OR '1'='1")
    snippet = sqli_details.get("snippet", "Database Leaked")
    
    with col_s1:
        st.warning("⚠️ **Vulnerability: Data Exfiltration**")
        st.write(f"**Target Endpoint:** `{endpoint}`")
        st.write(f"**Method:** `{method}`")
        st.write(f"**Payload Used:** `{payload}`")
        st.write("**Result:** Database Leaked")
    with col_s2:
        st.info("💡 **Technical Analysis & Proof of Exploit**")
        st.markdown("""
        The application is directly concatenating user input into a SQL query. 
        By providing a tautology (`' OR '1'='1`), the attacker bypassed the 
        expected query logic and retrieved sensitive backend data.
        """)
        st.write("**Exposed Data Snippet:**")
        st.code(snippet, language="json")
else:
    st.success("✅ **SQL Interface Secure:** No basic injection detected.")

st.divider()

# --- 2. Massive Payload Visualization ---
st.markdown("### 💣 Attack B: Massive Payload")
if fuzz_raw.get("crashes", 0) > 0:
    st.error(f"🚨 **CRASH DETECTED:** {fuzz_raw.get('status')}")
    
    col_a, col_b = st.columns([1, 2])
    with col_a:
        st.warning("⚠️ **Vulnerability: Buffer Overflow Simulation**")
        st.write("**Payload Size:** 2,000 bytes")
        st.write("**Target URL:** `/api` (POST)")
        st.write("**Result:** OS-level Termination (os._exit)")
    
    with col_b:
        st.info("💡 **Technical Analysis**")
        st.markdown("""
        The application failed to handle a massive incoming payload. In a real-world scenario, this 
        could lead to **Remote Code Execution (RCE)** or **Denial of Service (DoS)**.
        
        **Sandbox Behavior:** The container transitioned from `running` to `exited` immediately 
        following the 2000-byte POST request.
        """)
else:
    st.success("✅ **Sandbox Secure:** No crashes detected during massive payload simulation.")

st.divider()

st.subheader("🛠️ Remediation Plan")
suggestions = data.get("remediation_plan", [])

if suggestions:
    df = pd.DataFrame(suggestions)
    # Convert line numbers to strings for display
    if 'line' in df.columns:
        df['line'] = df['line'].astype(str).replace('0', 'N/A')
    st.dataframe(df, width="stretch")
else:
    st.success("✅ No critical issues requiring immediate remediation were found.")

st.divider()

# ==========================================
# THE THREAT MODEL VISUALIZATION
# ==========================================
st.subheader("🗺️ Automated Threat Model")
st.markdown("This map shows potential attacker entry points and data flow based on static code analysis.")

threat_diagram = data.get("threat_model", "")
if threat_diagram:
    st.markdown(f"```mermaid\n{threat_diagram}\n```")
else:
    st.info("No threat model available for this scan. Run a new scan to generate one!")

st.divider()

with st.expander("🔍 View Raw JSON Data Lake Export"):
    st.json(data)
