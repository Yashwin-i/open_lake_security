"""
Dashboard module for OpenLake Security.

This module provides a Streamlit-based web interface for the OpenLake Security tool.
It includes a main dashboard for running and viewing security scans, as well as an
AI assistant for interacting with a cybersecurity knowledge base.
"""
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
from utils.ai_kb import (
    is_db_populated, get_chroma_collection, build_knowledge_base,
    query_knowledge_base, ask_ai
) 

st.set_page_config(page_title="OpenLake Security", layout="wide")

# ==========================================
# SIDEBAR NAVIGATION
# ==========================================
with st.sidebar:
    st.title("Navigation")
    page = st.radio("Go to:", ["Security Dashboard", "AI Assistant"])
    st.divider()

# ==========================================
# PAGE: SECURITY DASHBOARD
# ==========================================
def show_dashboard():
    """
    Renders the main security dashboard interface.

    This function displays the interface for selecting a target repository,
    running a security scan, and presenting the vulnerability metrics,
    sandbox analysis, remediation plans, and threat models.
    """
    st.title("OpenLake Security Dashboard")
    st.markdown("Unified Security Data Lake & Remediation Center")
    st.divider()

    # --- 1. THE INPUT ENGINE ---
    st.subheader("Target Selection")
    repo_url = st.text_input("Paste the GitHub Repository URL to scan:", placeholder="https://github.com/videvelopers/Vulnerable-Flask-App")

    if st.button("Run Security Scan"):
        if not repo_url.startswith("http"):
            st.error("Please enter a valid HTTP/HTTPS GitHub URL.")
        else:
            with st.spinner(f"Cloning and scanning repository... This might take a minute."):
                
                repo_name = repo_url.split("/")[-1].replace(".git", "")
                scan_dir = "temp_scan_zone"
                
                clone_repo(repo_url, scan_dir)
                bandit_data = run_bandit_scan(scan_dir) 
                semgrep_data = run_semgrep_scan(scan_dir)
                
                # Sandbox Fuzzing
                dockerfile_path = os.path.join(scan_dir, "Dockerfile")
                if not os.path.exists(dockerfile_path):
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
                
                suggestions = generate_suggestions(bandit_data, semgrep_data, fuzz_data)
                threat_model_diagram = generate_threat_model(scan_dir)
                
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

    # --- 2. THE VISUALIZATION DASHBOARD ---
    list_of_files = glob.glob('data_lake/*.json')

    if not list_of_files:
        st.info("Welcome! Paste a link above and hit Scan to generate your first dashboard.")
        return

    latest_file = max(list_of_files, key=os.path.getctime)

    with open(latest_file, "r") as f:
        data = json.load(f)

    st.header(f"Project: `{data.get('project', 'Unknown')}`")
    st.caption(f"Source: {data.get('source', 'Unknown')} | Scanned on: {data.get('scan_date', 'Unknown')}")

    st.subheader("Vulnerability Metrics")
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

    st.subheader("Dynamic Sandbox Analysis")
    fuzz_raw = data.get("raw_scans", {}).get("fuzzing", {})

    st.markdown("### Attack A: SQL Injection")
    if fuzz_raw.get("sql_injection_detected", False):
        st.error("**SQL INJECTION CONFIRMED**")
        col_s1, col_s2 = st.columns([1, 2])
        sqli_details = fuzz_raw.get("sqli_details", {})
        with col_s1:
            st.warning("**Vulnerability: Data Exfiltration**")
            st.write(f"**Target Endpoint:** `{sqli_details.get('endpoint')}`")
            st.write(f"**Payload Used:** `{sqli_details.get('payload')}`")
        with col_s2:
            st.info("**Technical Analysis & Proof of Exploit**")
            st.write("**Exposed Data Snippet:**")
            st.code(sqli_details.get('snippet'), language="json")
    else:
        st.success("**SQL Interface Secure:** No basic injection detected.")

    st.divider()

    st.markdown("### Attack B: Massive Payload")
    if fuzz_raw.get("crashes", 0) > 0:
        st.error(f"**CRASH DETECTED:** {fuzz_raw.get('status')}")
        col_a, col_b = st.columns([1, 2])
        with col_a:
            st.warning("**Vulnerability: Buffer Overflow Simulation**")
            st.write("**Result:** OS-level Termination")
        with col_b:
            st.info("**Technical Analysis**")
            st.markdown("The application failed to handle a massive incoming payload.")
    else:
        st.success("**Sandbox Secure:** No crashes detected during massive payload simulation.")

    st.divider()

    st.subheader("Remediation Plan")
    suggestions = data.get("remediation_plan", [])
    if suggestions:
        df = pd.DataFrame(suggestions)
        if 'line' in df.columns:
            df['line'] = df['line'].astype(str).replace('0', 'N/A')
        st.dataframe(df, width="stretch")
    else:
        st.success("No critical issues requiring immediate remediation were found.")

    st.divider()

    st.subheader("Automated Threat Model")
    threat_diagram = data.get("threat_model", "")
    if threat_diagram:
        st.markdown(f"```mermaid\n{threat_diagram}\n```")
    else:
        st.info("No threat model available.")

    st.divider()
    with st.expander("View Raw JSON Data Lake Export"):
        st.json(data)

# ==========================================
# PAGE: AI ASSISTANT
# ==========================================
def show_assistant():
    """
    Renders the AI Assistant interface.

    This function displays the interface for the local cybersecurity AI assistant,
    including knowledge base settings and a chat interface for querying information.
    """
    st.title("CyberSec AI Assistant")
    st.caption("Powered by Local Mistral GGUF + Cybersecurity Knowledge Base")
    st.divider()

    # --- KB MANAGEMENT (in main area for focus) ---
    with st.expander("Knowledge Base Settings", expanded=not is_db_populated()):
        db_ready = is_db_populated()
        if db_ready:
            col = get_chroma_collection()
            st.success(f"Ready — {col.count()} chunks loaded")
        else:
            st.warning("Knowledge base is empty")

        if st.button("Build / Rebuild Knowledge Base", use_container_width=True):
            with st.spinner("Building knowledge base..."):
                pb = st.progress(0)
                st_txt = st.empty()
                count = build_knowledge_base(pb, st_txt)
                st_txt.text(f"Done! Stored {count} chunks.")
                st.rerun()

        st.markdown("""
        **Sources:** HackTricks, OWASP Top 10, PayloadsAllTheThings.
        """)

    # --- CHAT INTERFACE ---
    if "messages" not in st.session_state:
        st.session_state.messages = []

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input("Ask anything about cybersecurity..."):
        if not is_db_populated():
            st.warning("Please build the knowledge base first!")
            st.stop()

        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Searching knowledge base & asking local AI..."):
                context = query_knowledge_base(prompt)
                full_response = ""
                placeholder = st.empty()
                stream = ask_ai(prompt, context)
                for chunk in stream:
                    delta = chunk["choices"][0]["text"]
                    full_response += delta
                    placeholder.markdown(full_response + "▌")
                placeholder.markdown(full_response)

        st.session_state.messages.append({"role": "assistant", "content": full_response})

# ==========================================
# MAIN ROUTER
# ==========================================
if page == "Security Dashboard":
    show_dashboard()
else:
    show_assistant()