# OpenLake Security

OpenLake Security is a unified security data lake and remediation center designed to automate the process of cloning, scanning, and analyzing GitHub repositories for vulnerabilities. It combines static analysis (SAST), advanced pattern matching, and dynamic fuzzing in a sandboxed environment to provide a comprehensive security posture overview. It also features a localized AI Assistant to help answer cybersecurity questions and explain remediation steps using a Retrieval-Augmented Generation (RAG) approach.

## Features

- Automated Repository Cloning: Clones target repositories into a temporary scanning zone.
- Static Analysis (SAST): Uses Bandit to identify common security issues in Python code.
- Advanced Analysis: Leverages Semgrep for complex pattern matching and vulnerability detection.
- Dynamic Fuzzing: Executes targeted attacks (SQL Injection, Massive Payloads) within a Docker-based sandbox to verify exploitability.
- Threat Modeling: Automatically generates a Mermaid-based threat model based on the codebase structure.
- Remediation Planning: Provides actionable suggestions for fixing discovered vulnerabilities.
- Data Lake: Stores all scan results in a centralized JSON-based data lake for historical tracking and analysis.
- CyberSec AI Assistant: A localized RAG-based AI Assistant running a lightweight local model (such as Qwen or Dolphin) to provide technical, uncensored cybersecurity insights and suggestions.

## Documentation

For detailed information on the project architecture and features, refer to the documentation in the `docs/` folder:

- [Architecture Overview](docs/architecture.md)
- [Scanners Guide](docs/scanners.md)
- [AI Assistant Setup](docs/ai_assistant.md)

## Prerequisites

Before setting up the project, ensure you have the following installed:

- Python 3.9 or higher
- Docker (Required for sandbox fuzzing)
- Supported C/C++ build tools (for `llama-cpp-python` compilation if needed)

## Installation

1. Clone this repository to your local machine:
   ```bash
   git clone <repository-url>
   cd open-lake-security
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   Note: If you encounter issues with `llama-cpp-python` during installation, ensure your environment provides the necessary compiler toolchains. On NixOS or other environments using `nix-ld`, you might need to export `LD_LIBRARY_PATH` or use pre-compiled wheels.

4. Ensure the Docker daemon is running on your system.

## Configuration

The application expects a `temp_scan_zone` directory for temporary files. This is created automatically during the scan process. Results are stored in the `data_lake/` directory. The `chroma_db/` directory is created locally to store the vectorized cybersecurity knowledge base for the AI Assistant.

## Running the Application

1. Start the Streamlit dashboard:
   ```bash
   streamlit run dashboard.py
   ```
   If running on a Nix-based system with `nix-ld`, you may need to export `LD_LIBRARY_PATH` before running the command:
   ```bash
   LD_LIBRARY_PATH=$NIX_LD_LIBRARY_PATH streamlit run dashboard.py
   ```

2. Open your web browser and navigate to the URL provided by Streamlit.

3. Use the Sidebar Navigation to choose between the "Security Dashboard" and "AI Assistant".

### Using the Security Dashboard
- Enter a GitHub Repository URL in the input field.
- Click the "Run Security Scan" button.
- Wait for the pipeline to finish cloning, scanning, and analyzing.

### Using the AI Assistant
- Navigate to the AI Assistant page using the sidebar.
- Click "Build / Rebuild Knowledge Base" to scrape HackTricks and OWASP content into the local ChromaDB database.
- Chat with the AI regarding vulnerabilities, remediation, and other cybersecurity topics.
