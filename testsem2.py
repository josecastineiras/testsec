#!/usr/bin/env python3
"""
Intentionally vulnerable Python code for Semgrep testing
This file contains various security vulnerabilities that Semgrep should detect
"""

import os
import subprocess
import sqlite3
import pickle
import requests
from flask import Flask, request
import yaml

app = Flask(__name__)

# 1. SQL Injection vulnerability
def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: Direct string concatenation in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

# 2. Command Injection vulnerability
def backup_file(filename):
    # Vulnerable: Unsanitized input in shell command
    command = f"cp {filename} /backup/"
    os.system(command)

# 3. Path Traversal vulnerability
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    # Vulnerable: No path validation
    with open(f"/files/{filename}", 'r') as f:
        return f.read()

# 4. Hardcoded credentials
def connect_to_database():
    # Vulnerable: Hardcoded password
    password = "admin123"
    connection_string = f"postgresql://admin:{password}@localhost/mydb"
    return connection_string

# 5. Unsafe deserialization
def load_user_session(session_data):
    # Vulnerable: Unsafe pickle deserialization
    return pickle.loads(session_data)

# 6. YAML unsafe loading
def load_config(config_file):
    with open(config_file, 'r') as f:
        # Vulnerable: yaml.load instead of yaml.safe_load
        return yaml.load(f)

# 7. Weak cryptographic practices
import hashlib

def hash_password(password):
    # Vulnerable: MD5 is cryptographically weak
    return hashlib.md5(password.encode()).hexdigest()

# 8. Server-Side Request Forgery (SSRF)
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # Vulnerable: No URL validation
    response = requests.get(url)
    return response.text

# 9. Information disclosure
@app.route('/debug')
def debug_info():
    # Vulnerable: Exposing sensitive debug information
    debug_data = {
        'database_password': 'secret123',
        'api_key': 'sk-1234567890abcdef',
        'internal_ip': '192.168.1.100'
    }
    return debug_data

# 10. Race condition vulnerability
import threading
import time

balance = 1000
balance_lock = threading.Lock()

def withdraw(amount):
    global balance
    # Vulnerable: Race condition without proper locking
    if balance >= amount:
        time.sleep(0.1)  # Simulate processing time
        balance -= amount
        return True
    return False

# 11. Use of eval() - Code injection
def calculate_expression(expr):
    # Vulnerable: Direct eval of user input
    return eval(expr)

# 12. Weak random number generation
import random

def generate_token():
    # Vulnerable: Using predictable random
    return str(random.randint(100000, 999999))

# 13. Insecure file permissions
def create_temp_file(data):
    # Vulnerable: World-readable file creation
    temp_file = "/tmp/sensitive_data.txt"
    with open(temp_file, 'w') as f:
        f.write(data)
    os.chmod(temp_file, 0o777)  # World readable/writable

# 14. Cross-Site Scripting (XSS) through template
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # Vulnerable: Unescaped user input in response
    return f"<h1>Hello {name}!</h1>"

# 15. Insecure redirect
@app.route('/redirect')
def redirect_user():
    url = request.args.get('url')
    # Vulnerable: Unvalidated redirect
    return f'<meta http-equiv="refresh" content="0; url={url}">'

if __name__ == '__main__':
    # Vulnerable: Debug mode in production
    app.run(debug=True, host='0.0.0.0')