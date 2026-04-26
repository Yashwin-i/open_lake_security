import os
import json
import unittest
from utils.cloner import clone_repo
from scanners.fuzz_analysis import run_fuzz_scan

def generate_dockerfile(scan_dir):
    dockerfile_path = os.path.join(scan_dir, "Dockerfile")
    if not os.path.exists(dockerfile_path):
        print(f"[*] Auto-generating Dockerfile in {scan_dir}...")
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

class TestFuzzer(unittest.TestCase):
    def test_guilatrova_path_injection(self):
        repo_url = "https://github.com/guilatrova/flask-sqlinjection-vulnerable.git"
        scan_dir = "temp_test_guilatrova"
        
        clone_repo(repo_url, scan_dir)
        generate_dockerfile(scan_dir)
        
        print("\n--- Running Fuzzer on Guilatrova Repo ---")
        result = run_fuzz_scan(scan_dir)
        print(json.dumps(result, indent=4))
        
        self.assertTrue(result.get("sql_injection_detected"), "SQL Injection was not detected in guilatrova repo")

    def test_videvelopers_vulnerable_flask(self):
        repo_url = "https://github.com/videvelopers/Vulnerable-Flask-App.git"
        scan_dir = "temp_test_videvelopers"
        
        clone_repo(repo_url, scan_dir)
        generate_dockerfile(scan_dir)
        
        print("\n--- Running Fuzzer on Videvelopers Repo ---")
        result = run_fuzz_scan(scan_dir)
        print(json.dumps(result, indent=4))
        
        # Depending on how the app is structured, maybe it detects SQLi or Crash.
        # At least one should be detected if our generic payload works.
        # Let's assert either one is true.
        vulnerable = result.get("sql_injection_detected") or (result.get("crashes", 0) > 0)
        self.assertTrue(vulnerable, "No vulnerability detected in Videvelopers repo")

if __name__ == "__main__":
    unittest.main()
