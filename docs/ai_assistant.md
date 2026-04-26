# CyberSec AI Assistant

OpenLake Security integrates a localized, secure, and privacy-preserving AI Assistant. It operates entirely on your local machine using lightweight language models and a Retrieval-Augmented Generation (RAG) knowledge base.

## Architecture

The assistant is powered by two main technologies:
1. **ChromaDB**: A fast, local vector database. We scrape high-quality security content (such as HackTricks guides and OWASP documentation), chunk it, generate embeddings using a sentence-transformer model (`all-MiniLM-L6-v2`), and store it locally.
2. **llama-cpp-python**: A set of Python bindings for `llama.cpp`. We run lightweight GGUF models (like Dolphin3.0-Qwen2.5) on the CPU. The selected models are uncensored and specialized for technical, coding, and cybersecurity tasks.

## Why a Local Model?

By downloading and running a model locally, we achieve:
- **Privacy:** Your code, queries, and vulnerabilities never leave your machine.
- **Uncensored Responses:** Typical cloud-hosted LLMs feature strict safety alignments that often block legitimate queries regarding vulnerabilities, exploits, or payload structures. Local uncensored models provide technical depth without moralizing refusals.

## Setting Up the Knowledge Base

1. Navigate to the **AI Assistant** tab in the Sidebar.
2. Under the **Knowledge Base Settings**, click **Build / Rebuild Knowledge Base**.
3. The server will automatically fetch cybersecurity references, parse out unnecessary HTML/scripts, split the text, and store it in your `chroma_db/` folder.

## Interacting with the AI

Once the Knowledge Base is populated:
1. Use the chat input box at the bottom of the page.
2. Ask any question regarding vulnerabilities, payload types, remediation steps, or general security concepts.
3. The RAG pipeline will query ChromaDB for the most relevant context and supply it to the local LLM.
4. The local model will stream the answer directly back to the web UI.
