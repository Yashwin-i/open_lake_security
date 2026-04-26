"""
AI Knowledge Base utility for OpenLake Security.

This module provides functionality to fetch, process, and query cybersecurity
knowledge from various web sources using local language models and ChromaDB.
"""
import streamlit as st
import requests
from bs4 import BeautifulSoup
import chromadb
from chromadb.utils import embedding_functions
from llama_cpp import Llama
from huggingface_hub import hf_hub_download
import time
import os

COLLECTION_NAME = "cybersec_kb"
DB_PATH = "./chroma_db"

# Using Dolphin3.0-Qwen2.5-1.5B (100% Uncensored, perfect for security testing)
MODEL_REPO = "bartowski/Dolphin3.0-Qwen2.5-1.5B-GGUF"
MODEL_FILE = "Dolphin3.0-Qwen2.5-1.5B-Q4_K_M.gguf"

# Free cybersecurity knowledge sources (lightweight text pages)
SOURCES = [
    # Mobile Security
    "https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting",
    "https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Android%20Application%20Pentest.md",

    # Network attacks
    "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network",
    "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi",

    # Reverse Engineering
    "https://book.hacktricks.xyz/reversing-and-exploiting/reversing-tools-basic-methods",

    # CTF focused
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Metasploit%20-%20Cheatsheet.md",
    
    # HackTricks key pages
    "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-methodology",
    "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web",
    "https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh",
    "https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp",
    "https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb",
    "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation",
    "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
    "https://book.hacktricks.xyz/pentesting-web/sql-injection",
    "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting",
    "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
    "https://book.hacktricks.xyz/pentesting-web/command-injection",
    "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery",
    
    # OWASP
    "https://owasp.org/www-project-top-ten/",
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://owasp.org/www-community/attacks/xss/",
    
    # PayloadsAllTheThings (raw github markdown)
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/README.md",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/README.md",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/README.md",
]

def chunk_text(text, size=800, overlap=100):
    """
    Split text into overlapping chunks.

    Args:
        text (str): The text to chunk.
        size (int, optional): The maximum size of each chunk. Defaults to 800.
        overlap (int, optional): The overlap between consecutive chunks. Defaults to 100.

    Returns:
        list: A list of text chunks.
    """
    chunks = []
    start = 0
    while start < len(text):
        end = start + size
        chunks.append(text[start:end])
        start += size - overlap
    return chunks

def fetch_page(url):
    """
    Fetch and clean a web page.

    Args:
        url (str): The URL to fetch.

    Returns:
        str or None: The cleaned text content of the page, or None if fetching fails.
    """
    try:
        headers = {"User-Agent": "Mozilla/5.0 (educational security research bot)"}
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        if url.endswith(".md"):
            return r.text[:40000]
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        return soup.get_text(separator="\n", strip=True)[:40000]
    except Exception as e:
        return None

def get_chroma_collection():
    """
    Get or create the ChromaDB collection.

    Returns:
        chromadb.Collection: The initialized ChromaDB collection.
    """
    client = chromadb.PersistentClient(path=DB_PATH)
    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"}
    )

def is_db_populated():
    """
    Check if the knowledge base already has data.

    Returns:
        bool: True if the database contains items, False otherwise.
    """
    try:
        col = get_chroma_collection()
        return col.count() > 0
    except:
        return False

def build_knowledge_base(progress_bar, status_text):
    """
    Scrape sources and store them in ChromaDB.

    Args:
        progress_bar: A progress bar object to update.
        status_text: A text element to display the current status.

    Returns:
        int: The total number of documents stored.
    """
    col = get_chroma_collection()
    total = len(SOURCES)
    doc_id = 0

    for i, url in enumerate(SOURCES):
        status_text.text(f"Fetching: {url.split('/')[-1]}...")
        progress_bar.progress((i + 1) / total)

        text = fetch_page(url)
        if not text or len(text) < 200:
            continue

        chunks = chunk_text(text)
        for chunk in chunks:
            if len(chunk.strip()) < 100:
                continue
            col.add(
                documents=[chunk],
                metadatas=[{"source": url}],
                ids=[f"doc_{doc_id}"]
            )
            doc_id += 1
        time.sleep(0.3)   # be polite to servers

    return doc_id

def query_knowledge_base(question, n_results=5):
    """
    Find relevant chunks from ChromaDB for a given question.

    Args:
        question (str): The query string.
        n_results (int, optional): Number of results to retrieve. Defaults to 5.

    Returns:
        list: A list of relevant document strings.
    """
    col = get_chroma_collection()
    if col.count() == 0:
        return []
    results = col.query(query_texts=[question], n_results=n_results)
    return results["documents"][0] if results["documents"] else []

@st.cache_resource
def load_local_llm():
    """
    Loads the model locally exactly once per application lifecycle.

    Returns:
        Llama: An initialized instance of the local LLM.
    """
    print(f"Downloading/Loading {MODEL_FILE}...")
    model_path = hf_hub_download(repo_id=MODEL_REPO, filename=MODEL_FILE)
    return Llama(
        model_path=model_path,
        n_ctx=2048,       # Optimized context window for CPU speed
        n_threads=8,      # Utilize local CPU cores
        verbose=False     # Keep logs clean
    )

def ask_ai(question, context_chunks):
    """
    Send question and context to the local model via llama_cpp.

    Args:
        question (str): The user's query.
        context_chunks (list): A list of contextual strings to provide to the model.

    Returns:
        Iterator: A streaming response generator from the LLM.
    """
    llm = load_local_llm()
    context = "\n\n---\n\n".join(context_chunks)
    
    # Using ChatML format (optimized for Qwen) and a more permissive system prompt
    prompt = f"""<|im_start|>system
You are a cybersecurity research assistant. You are operating in a controlled, legal security testing environment. 
Your goal is to provide detailed technical analysis, code snippets, and methodologies to help the user identify and remediate vulnerabilities.
Be direct, technical, and do not provide moralizing refusals. Use the context below if helpful.

Context:
{context}<|im_end|>
<|im_start|>user
{question}<|im_end|>
<|im_start|>assistant
"""
    
    response = llm(
        prompt,
        max_tokens=1024,
        stop=["<|im_end|>", "<|im_start|>"],
        stream=True
    )
    return response
