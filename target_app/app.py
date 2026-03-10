from flask import Flask, request
import time
import os

app = Flask(__name__)

@app.route('/api', methods=['POST'])
def api():
    # Crash immediately on any request for demonstration
    print("[!] CRITICAL ERROR: Simulated Crash triggered by Fuzzer")
    os._exit(1)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
