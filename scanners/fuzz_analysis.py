import docker
import time
import os
import json
import socket
import requests

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

def run_fuzz_scan(target_dir="target_app"):
    print(f"[*] Starting Sandbox Fuzzing on {target_dir}...")
    client = docker.from_env()
    
    # 1. Build Target Sandbox
    print("[*] Building Docker Sandbox...")
    try:
        if not os.path.exists(os.path.join(target_dir, "Dockerfile")):
             return {"error": f"No Dockerfile found in {target_dir}"}
             
        image, logs = client.images.build(path=target_dir, tag="fuzz_target:latest")
    except Exception as e:
        return {"error": f"Failed to build Docker image: {str(e)}"}

    # 2. Run Target Sandbox
    port = get_free_port()
    print(f"[*] Starting Container on port {port}...")
    container = client.containers.run(
        "fuzz_target:latest",
        detach=True,
        ports={'5000/tcp': port}
    )
    
    time.sleep(2)
    
    results = {
        "status": "No issues found",
        "crashes": 0,
        "sql_injection_detected": False,
        "sqli_details": {},
        "details": []
    }

    try:
        # 3a. SQL Injection Simulation
        print("[*] Testing for SQL Injection across multiple endpoints...")
        injection_payload = "' OR '1'='1"
        url_encoded_payload = "'%20or%20'1'%20=%20'1"
        
        # Testing Query Parameters
        endpoints_to_test = ["/api/user", "/login", "/", "/users", "/api/login"]
        for ep in endpoints_to_test:
            url_sql = f"http://127.0.0.1:{port}{ep}"
            try:
                response = requests.get(url_sql, params={"username": injection_payload, "id": injection_payload, "user": injection_payload}, timeout=2)
                if response.status_code == 200 and ("admin" in response.text.lower() or "root" in response.text.lower() or "dashboard" in response.text.lower() or "test" in response.text.lower() or "erlik" in response.text.lower() or "[(" in response.text):
                    print(f"[!] SQL INJECTION CONFIRMED on parameter at {ep}")
                    results["sql_injection_detected"] = True
                    results["sqli_details"] = {
                        "endpoint": ep,
                        "method": "GET",
                        "payload": f"?username={injection_payload}",
                        "snippet": response.text[:200] + "..."
                    }
                    results["details"].append(f"Successfully leaked privileged user data using SQL Injection on {ep} (GET)")
                    break
                
                # Also try POST for login endpoints
                response_post = requests.post(url_sql, data={"username": injection_payload, "password": "password", "id": injection_payload}, timeout=2)
                if response_post.status_code == 200 and ("admin" in response_post.text.lower() or "root" in response_post.text.lower() or "dashboard" in response_post.text.lower() or "test" in response_post.text.lower() or "erlik" in response_post.text.lower() or "[(" in response_post.text):
                    print(f"[!] SQL INJECTION CONFIRMED on POST parameter at {ep}")
                    results["sql_injection_detected"] = True
                    results["sqli_details"] = {
                        "endpoint": ep,
                        "method": "POST",
                        "payload": f"username={injection_payload}",
                        "snippet": response_post.text[:200] + "..."
                    }
                    results["details"].append(f"Successfully leaked privileged user data using SQL Injection on {ep} (POST)")
                    break
            except:
                pass

        # Testing Path-based Injection
        path_endpoints = [f"/challenges/{injection_payload}", f"/user/{injection_payload}", f"/profile/{injection_payload}"]
        if not results["sql_injection_detected"]:
            for path in path_endpoints:
                url_sql = f"http://127.0.0.1:{port}{path}"
                try:
                    response = requests.get(url_sql, timeout=2)
                    # We check if the response suddenly contains large amounts of data or specific keywords indicating a successful tautology
                    if response.status_code == 200 and ("111.111.111-11" in response.text or "score" in response.text.lower() or "<li>" in response.text or "admin" in response.text.lower() or "test" in response.text.lower() or "erlik" in response.text.lower() or "[(" in response.text):
                         print(f"[!] SQL INJECTION CONFIRMED on path {path}")
                         results["sql_injection_detected"] = True
                         results["sqli_details"] = {
                             "endpoint": path.split(injection_payload)[0] + "<payload>",
                             "method": "GET (Path)",
                             "payload": injection_payload,
                             "snippet": response.text[:200] + "..."
                         }
                         results["details"].append(f"Path-based SQL Injection succeeded. Exploited endpoint logic via URL path.")
                         break
                except:
                    pass

        # 3b. Massive Payload Simulation
        print("[*] Sending massive 2000-byte payload across endpoints...")
        massive_payload = "A" * 2000
        crash_endpoints = ["/api", "/", "/submit", "/login", "/upload"]
        
        for ep in crash_endpoints:
            url_crash = f"http://127.0.0.1:{port}{ep}"
            try:
                requests.post(url_crash, data=massive_payload, timeout=1)
            except:
                pass
        
        # Check for Crash
        time.sleep(1)
        container.reload()
        if container.status != "running":
            results["crashes"] = 1
            results["details"].append(f"Application crashed with 2000-byte payload.")
        
        # Final Status Update
        if results["crashes"] and results["sql_injection_detected"]:
            results["status"] = "MULTIPLE CRITICAL VULNERABILITIES (SQLi + Crash)"
        elif results["crashes"]:
            results["status"] = "CRASH DETECTED (Massive Payload Attack)"
        elif results["sql_injection_detected"]:
            results["status"] = "VULNERABILITY DETECTED (SQL Injection)"

    except Exception as e:
        print(f"[!] Fuzzing error: {str(e)}")
    finally:
        # 5. Cleanup
        print("[*] Container Logs:")
        try:
            print(container.logs().decode('utf-8'))
        except Exception as e:
            print(f"Could not fetch logs: {e}")
        print("[*] Cleaning up Sandbox...")
        try:
            container.stop()
            container.remove()
        except:
            pass

    print(f"[*] Fuzz Scan Finished. Results: {results['status']}, Crashes: {results['crashes']}")
    return results

def extract_fuzz_metrics(fuzz_data):
    return {
        "fuzz_crashes": fuzz_data.get("crashes", 0),
        "fuzz_status": fuzz_data.get("status", "Unknown")
    }
