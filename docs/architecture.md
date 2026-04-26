# OpenLake Security Architecture

OpenLake Security aims to orchestrate automated threat detection by integrating various tools within a unified pipeline. Its architecture centers around combining Static Application Security Testing (SAST) with dynamic payload execution and AI-assisted remediation.

## Core Components

1. **FastAPI Backend & UI (`app.py` & `static/`)**
   - The primary interface. Built with FastAPI to serve a modern HTML/JS frontend (`static/index.html` and `static/app.js`) to enable a reactive and interactive experience. 
   - Manages state, visualizes data lake JSONs, provides scanning REST API endpoints, and features an integrated AI chat interface.

2. **Repository Cloner (`utils/cloner.py`)**
   - Handles securely cloning Git repositories from GitHub or other sources into a temporary workspace (`temp_scan_zone/`) where static and dynamic analysis runs.

3. **Scanning Modules (`scanners/`)**
   - **Bandit (`code_analysis.py`)**: Checks abstract syntax trees (ASTs) for basic Python-centric flaws.
   - **Semgrep (`advanced_analysis.py`)**: Employs structural matching across languages for deeper, semantically-aware detection (like hardcoded secrets or complex injection patterns).
   - **Threat Mapper (`threat_mapper.py`)**: Statically parses routes and database calls to create a visual Mermaid threat model graph.
   - **Fuzzer (`fuzz_analysis.py`)**: Runs basic payloads against a sandboxed container to observe runtime crashes, verifying issues like SQL injections or buffer overflows.
   - **AI Suggester (`ai_suggester.py`)**: Unifies the SAST and dynamic results to present human-readable remediation guidelines.

4. **Data Lake Storage**
   - Stores aggregated execution results into `data_lake/` as JSON blobs. This ensures a persistent history of scans, which can be visualized at any time.

5. **AI Knowledge Base (`utils/ai_kb.py`)**
   - Manages a local Retrieval-Augmented Generation (RAG) system utilizing ChromaDB.
   - Embeds content fetched from OWASP and HackTricks to answer questions via a local LLM backend.
