import os
import re

def generate_threat_model(target_dir):
    """
    Scans the repository for API entry points and database connections
    to build an automated Mermaid.js threat model diagram.
    """
    print("[*] Generating Threat Model...")
    
    api_endpoints = set()
    db_connections = set()
    
    # Regex patterns to find Flask/FastAPI routes and DB connections
    route_pattern = re.compile(r'@app\.(route|get|post|put|delete)\([\'"]([^\'"]+)[\'"]')
    db_pattern = re.compile(r'(sqlite3\.connect|create_engine|SQLAlchemy|cursor\(\))')
    
    # Scan all Python files in the cloned repo
    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                        # Find APIs
                        routes = route_pattern.findall(content)
                        for r in routes:
                            api_endpoints.add(r[1]) # Add the path (e.g., '/login')
                            
                        # Find DBs
                        if db_pattern.search(content):
                            db_connections.add(file) # Log the file that connects to a DB
                except Exception:
                    pass # Skip unreadable files
                    
    # Now, let's build the Mermaid.js string!
    mermaid_code = "graph TD\n"
    mermaid_code += "    Attacker((🦹‍♂️ Attacker)):::threat\n"
    
    mermaid_code += "    subgraph Public Entry Points\n"
    if not api_endpoints:
        mermaid_code += "        Web[Default Web Interface]\n"
        mermaid_code += "    end\n"
        mermaid_code += "    Attacker -->|Web Traffic| Web\n"
    else:
        for i, endpoint in enumerate(api_endpoints):
            node_name = f"API_{i}"
            mermaid_code += f"        {node_name}[\"{endpoint}\"]\n"
            mermaid_code += f"    Attacker -->|HTTP Request| {node_name}\n"
    mermaid_code += "    end\n"

    mermaid_code += "    subgraph Internal Architecture\n"
    mermaid_code += "        AppCore[Core Application Logic]\n"
    if not api_endpoints:
        mermaid_code += "        Web --> AppCore\n"
    else:
        for i in range(len(api_endpoints)):
            mermaid_code += f"        API_{i} --> AppCore\n"
    mermaid_code += "    end\n"

    mermaid_code += "    subgraph Data Storage\n"
    if not db_connections:
        mermaid_code += "        FileSystem[(Local File System)]\n"
        mermaid_code += "        AppCore --> FileSystem\n"
    else:
        for i, db_file in enumerate(db_connections):
            db_node = f"DB_{i}"
            mermaid_code += f"        {db_node}[({db_file} Database)]\n"
            mermaid_code += f"        AppCore -->|SQL/Query| {db_node}\n"
    mermaid_code += "    end\n"
    
    # Adding some red color to the attacker node
    mermaid_code += "\n    classDef threat fill:#ffcccc,stroke:#ff0000,stroke-width:2px;"

    return mermaid_code