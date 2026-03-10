"""import streamlit as st
import json
import os
import glob
import pandas as pd
from datetime import datetime

# Importing your backend engines directly!
from utils.cloner import clone_repo
from scanners.code_analysis import run_bandit_scan, extract_metrics
from scanners.advanced_analysis import run_semgrep_scan, extract_semgrep_metrics
from scanners.fuzz_analysis import run_fuzz_scan, extract_fuzz_metrics
from scanners.ai_suggester import generate_suggestions

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
        # This spinner keeps the UI looking clean while the heavy lifting happens
        with st.spinner(f"Cloning and scanning repository... This might take a minute."):
            
            repo_name = repo_url.split("/")[-1].replace(".git", "")
            scan_dir = "temp_scan_zone"
            
            # Triggering the pipeline!
            clone_repo(repo_url, scan_dir)
            bandit_data = run_bandit_scan(scan_dir) 
            semgrep_data = run_semgrep_scan(scan_dir)
            
            # 🚀 New! Sandbox Fuzzing!
            # For demonstration, we fuzz our target_app if the repo doesn't have a Dockerfile
            # In a real tool, we'd look for a Dockerfile in the scan_dir
            if os.path.exists(os.path.join(scan_dir, "Dockerfile")):
                fuzz_data = run_fuzz_scan(scan_dir)
            else:
                st.warning("⚠️ No Dockerfile found in repo. Running default sandbox fuzzer demo.")
                fuzz_data = run_fuzz_scan("target_app")

            b_metrics = extract_metrics(bandit_data)
            s_metrics = extract_semgrep_metrics(semgrep_data)
            f_metrics = extract_fuzz_metrics(fuzz_data)
            suggestions = generate_suggestions(bandit_data, semgrep_data, fuzz_data)
            
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
                "raw_scans": {
                    "bandit": bandit_data, 
                    "semgrep": semgrep_data,
                    "fuzzing": fuzz_data
                }
            }
            
            with open(filename, "w") as f:
                json.dump(lake_entry, f, indent=4)
                
            # st.rerun() instantly refreshes the page to show the new results below!
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

st.subheader("🛠️ Remediation Plan")
suggestions = data.get("remediation_plan", [])

if suggestions:
    df = pd.DataFrame(suggestions)
    # 🚀 Fix for the Arrow/Pandas error: convert line numbers to strings
    df['line'] = df['line'].astype(str).replace('0', 'N/A')
    st.dataframe(df, width="stretch")
else:
    st.success("✅ No critical issues requiring immediate remediation were found.")

with st.expander("🔍 View Raw JSON Data Lake Export"):
    st.json(data)"""
import streamlit as st
import json
import os
import glob
import pandas as pd
from datetime import datetime

# Importing your backend engines directly!
from utils.cloner import clone_repo
from scanners.code_analysis import run_bandit_scan, extract_metrics
from scanners.advanced_analysis import run_semgrep_scan, extract_semgrep_metrics
from scanners.ai_suggester import generate_suggestions

# 🚨 NEW: Importing the Threat Mapper we just built!
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
            
            b_metrics = extract_metrics(bandit_data)
            s_metrics = extract_semgrep_metrics(semgrep_data)
            suggestions = generate_suggestions(bandit_data, semgrep_data)
            
            # 🚨 NEW: Generate the threat model diagram code
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
                    "advanced_issues": s_metrics["total_advanced_issues"]
                },
                "remediation_plan": suggestions,
                # 🚨 NEW: Save the diagram code into our JSON Data Lake
                "threat_model": threat_model_diagram,
                "raw_scans": {"bandit": bandit_data, "semgrep": semgrep_data}
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
col1, col2, col3 = st.columns(3)

metrics = data.get("metrics", {})
b_issues = metrics.get("basic_issues", 0)
a_issues = metrics.get("advanced_issues", 0)

col1.metric(label="Total Issues Discovered", value=b_issues + a_issues)
col2.metric(label="Basic Flaws (SAST)", value=b_issues)
col3.metric(label="Complex Flaws (Advanced)", value=a_issues)

st.divider()

st.subheader("🛠️ Remediation Plan")
suggestions = data.get("remediation_plan", [])

if suggestions:
    df = pd.DataFrame(suggestions)
    st.dataframe(df, width="stretch")
else:
    st.success("✅ No critical issues requiring immediate remediation were found.")

st.divider()

# ==========================================
# 🚨 NEW: THE THREAT MODEL VISUALIZATION
# ==========================================
st.subheader("🗺️ Automated Threat Model")
st.markdown("This map shows potential attacker entry points and data flow based on static code analysis.")

threat_diagram = data.get("threat_model", "")
if threat_diagram:
    # Streamlit natively renders Mermaid.js when you wrap it in a markdown block!
    st.markdown(f"```mermaid\n{threat_diagram}\n```")
else:
    st.info("No threat model available for this scan. Run a new scan to generate one!")

st.divider()

with st.expander("🔍 View Raw JSON Data Lake Export"):
    st.json(data)