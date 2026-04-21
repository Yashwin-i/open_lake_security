# Open Lake Security

Open Lake Security is a unified security data lake and remediation center designed to automate the process of cloning, scanning, and analyzing GitHub repositories for vulnerabilities. It combines static analysis (SAST), advanced pattern matching, and dynamic fuzzing in a sandboxed environment to provide a comprehensive security posture overview.

## Features

- Automated Repository Cloning: Clones target repositories into a temporary scanning zone.
- Static Analysis (SAST): Uses Bandit to identify common security issues in Python code.
- Advanced Analysis: Leverages Semgrep for complex pattern matching and vulnerability detection.
- Dynamic Fuzzing: Executes targeted attacks (SQL Injection, Massive Payloads) within a Docker-based sandbox to verify exploitability.
- Threat Modeling: Automatically generates a Mermaid-based threat model based on the codebase structure.
- Remediation Planning: Provides actionable suggestions for fixing discovered vulnerabilities.
- Data Lake: Stores all scan results in a centralized JSON-based data lake for historical tracking and analysis.

## Prerequisites

Before setting up the project, ensure you have the following installed:

- Python 3.9 or higher
- Docker (Required for sandbox fuzzing)

## Installation

1. Clone this repository to your local machine:
   ```bash
   git clone <repository-url>
   cd open-lake-security
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Ensure the Docker daemon is running on your system.

## Configuration

The application expects a `temp_scan_zone` directory for temporary files. This is created automatically during the scan process. Results are stored in the `data_lake/` directory.

## Running the Application

1. Start the Streamlit dashboard:
   ```bash
   streamlit run dashboard.py
   ```

2. Open your web browser and navigate to the URL provided by Streamlit.

3. Enter a GitHub Repository URL in the input field (e.g., `https://github.com/user/repo`).

4. Click the "Run Security Scan" button.
