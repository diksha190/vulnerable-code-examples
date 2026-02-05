import os
import sqlite3

def login_user(username, password):
    # VULNERABILITY: SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def execute_command(cmd):
    # VULNERABILITY: Command Injection
    os.system(f"ping -c 1 {cmd}")

def read_file(filename):
    # VULNERABILITY: Path Traversal
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()
