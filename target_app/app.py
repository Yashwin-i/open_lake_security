from flask import Flask, request
import time
import os

import sqlite3

app = Flask(__name__)

# Initialize a simple in-memory database for demonstration
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'super-secret-password')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('guest', 'guest-password')")
    conn.commit()
    return conn

db_conn = init_db()

@app.route('/api/user', methods=['GET'])
def get_user():
    # VULNERABLE TO SQL INJECTION
    username = request.args.get('username')
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    try:
        cursor = db_conn.cursor()
        # This is where the injection happens!
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return {"id": user[0], "username": user[1]}, 200
        else:
            return {"error": "User not found"}, 404
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/api', methods=['POST'])
def api():
    # Only crash if payload is "massive" (greater than 1000 characters)
    data = request.get_data(as_text=True)
    if len(data) > 1000:
        print(f"[!] CRITICAL ERROR: Massive payload detected ({len(data)} bytes). Simulated Buffer Overflow!")
        os._exit(1)
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
