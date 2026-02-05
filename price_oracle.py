"""
Price Oracle Service for DeFi Lending Pool
Backend service that fetches and provides token prices
Contains several security vulnerabilities for testing
"""

import os
import time
import json
import sqlite3
import requests
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import hashlib
import hmac
from functools import wraps

app = Flask(__name__)

# Configuration
DATABASE = "prices.db"
API_KEY = os.getenv(
    "ORACLE_API_KEY", "default_key_123"
)  # VULNERABILITY: Weak default key
ADMIN_KEY = "admin_secret_key"  # VULNERABILITY: Hardcoded admin key

# External price sources
PRICE_SOURCES = {
    "coingecko": "https://api.coingecko.com/api/v3/simple/price",
    "binance": "https://api.binance.com/api/v3/ticker/price",
    "uniswap": "http://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3",
}

# Supported tokens
SUPPORTED_TOKENS = {
    "ETH": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "DAI": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
    "WBTC": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
}


# Database initialization
def init_db():
    """Initialize the database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS prices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_address TEXT NOT NULL,
            price REAL NOT NULL,
            source TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            confidence REAL DEFAULT 1.0
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS price_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_address TEXT NOT NULL,
            old_price REAL,
            new_price REAL,
            updater TEXT,
            timestamp INTEGER NOT NULL
        )
    """
    )

    conn.commit()
    conn.close()


def require_api_key(f):
    """Decorator to require API key"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")

        # VULNERABILITY: Weak API key validation
        # No rate limiting, simple string comparison
        if api_key != API_KEY:
            return jsonify({"error": "Invalid API key"}), 401

        return f(*args, **kwargs)

    return decorated_function


def require_admin(f):
    """Decorator to require admin privileges"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_key = request.headers.get("X-Admin-Key")

        # VULNERABILITY: No protection against timing attacks
        if admin_key != ADMIN_KEY:
            return jsonify({"error": "Unauthorized"}), 403

        return f(*args, **kwargs)

    return decorated_function


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify(
        {"status": "healthy", "timestamp": int(time.time()), "version": "1.0.0"}
    )


@app.route("/api/price/<token_address>", methods=["GET"])
@require_api_key
def get_price(token_address):
    """
    Get current price for a token
    VULNERABILITY: No input validation on token_address
    """
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # VULNERABILITY: SQL Injection possible here
    query = f"SELECT price, source, timestamp FROM prices WHERE token_address = '{token_address}' ORDER BY timestamp DESC LIMIT 1"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()

    if not result:
        return jsonify({"error": "Price not found"}), 404

    price, source, timestamp = result

    # VULNERABILITY: No freshness check on price data
    # Stale prices could be returned

    return jsonify(
        {
            "token": token_address,
            "price": price,
            "source": source,
            "timestamp": timestamp,
        }
    )


@app.route("/api/prices/batch", methods=["POST"])
@require_api_key
def get_batch_prices():
    """
    Get prices for multiple tokens
    """
    data = request.json
    tokens = data.get("tokens", [])

    # VULNERABILITY: No limit on batch size
    # Could cause DoS with large requests

    results = {}
    for token in tokens:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Still vulnerable to SQL injection
        query = f"SELECT price FROM prices WHERE token_address = '{token}' ORDER BY timestamp DESC LIMIT 1"
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()

        if result:
            results[token] = result[0]

    return jsonify(results)


@app.route("/api/price/update", methods=["POST"])
@require_api_key
def update_price():
    """
    Update price for a token
    VULNERABILITY: Missing authentication for critical operation
    """
    data = request.json
    token = data.get("token")
    price = data.get("price")
    source = data.get("source", "manual")

    # VULNERABILITY: No validation of price value
    # Could inject negative or extremely large values

    if not token or price is None:
        return jsonify({"error": "Missing required fields"}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get old price
    cursor.execute(
        "SELECT price FROM prices WHERE token_address = ? ORDER BY timestamp DESC LIMIT 1",
        (token,),
    )
    old_result = cursor.fetchone()
    old_price = old_result[0] if old_result else 0

    # Insert new price
    timestamp = int(time.time())
    cursor.execute(
        "INSERT INTO prices (token_address, price, source, timestamp) VALUES (?, ?, ?, ?)",
        (token, price, source, timestamp),
    )

    # Log the update
    updater = request.headers.get("X-Updater", "unknown")

    # VULNERABILITY: SQL Injection in updater field
    cursor.execute(
        f"INSERT INTO price_updates (token_address, old_price, new_price, updater, timestamp) VALUES ('{token}', {old_price}, {price}, '{updater}', {timestamp})"
    )

    conn.commit()
    conn.close()

    return jsonify(
        {"success": True, "token": token, "old_price": old_price, "new_price": price}
    )


@app.route("/api/price/history/<token>", methods=["GET"])
@require_api_key
def get_price_history(token):
    """Get price history for a token"""
    limit = request.args.get("limit", 100)

    # VULNERABILITY: No validation on limit parameter
    # Could cause memory issues with very large limits

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    query = f"SELECT price, source, timestamp FROM prices WHERE token_address = '{token}' ORDER BY timestamp DESC LIMIT {limit}"
    cursor.execute(query)

    results = cursor.fetchall()
    conn.close()

    history = [
        {"price": row[0], "source": row[1], "timestamp": row[2]} for row in results
    ]

    return jsonify({"token": token, "history": history})


@app.route("/api/fetch/external", methods=["POST"])
@require_api_key
def fetch_external_price():
    """
    Fetch price from external source
    VULNERABILITY: SSRF vulnerability
    """
    data = request.json
    token = data.get("token")
    source_url = data.get("source_url")

    # VULNERABILITY: No URL validation
    # Attacker can make requests to internal services

    try:
        response = requests.get(source_url, timeout=5)
        price_data = response.json()

        # VULNERABILITY: No validation of response structure
        price = price_data.get("price", 0)

        # Update database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO prices (token_address, price, source, timestamp) VALUES (?, ?, ?, ?)",
            (token, price, "external", int(time.time())),
        )
        conn.commit()
        conn.close()

        return jsonify({"success": True, "token": token, "price": price})

    except Exception as e:
        # VULNERABILITY: Information leakage in error messages
        return jsonify({"error": str(e), "traceback": str(e.__traceback__)}), 500


@app.route("/api/admin/reset", methods=["POST"])
def admin_reset():
    """
    Reset all prices
    VULNERABILITY: Missing authentication!
    """
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM prices")
    cursor.execute("DELETE FROM price_updates")

    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "All prices reset"})


@app.route("/api/admin/backup", methods=["GET"])
@require_admin
def backup_database():
    """
    Backup database
    VULNERABILITY: Path traversal
    """
    backup_name = request.args.get("name", "backup.db")

    # VULNERABILITY: No path sanitization
    backup_path = f"/tmp/{backup_name}"

    try:
        os.system(f"cp {DATABASE} {backup_path}")
        return jsonify({"success": True, "backup_path": backup_path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/calculate/average", methods=["POST"])
@require_api_key
def calculate_average():
    """
    Calculate average price from multiple sources
    """
    data = request.json
    token = data.get("token")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get prices from last hour
    one_hour_ago = int(time.time()) - 3600

    query = f"SELECT price FROM prices WHERE token_address = '{token}' AND timestamp > {one_hour_ago}"
    cursor.execute(query)

    prices = [row[0] for row in cursor.fetchall()]
    conn.close()

    if not prices:
        return jsonify({"error": "No recent prices"}), 404

    # VULNERABILITY: No outlier detection
    # Manipulated prices affect the average
    average = sum(prices) / len(prices)

    return jsonify(
        {"token": token, "average_price": average, "sample_size": len(prices)}
    )


@app.route("/api/debug/info", methods=["GET"])
def debug_info():
    """
    Debug endpoint
    VULNERABILITY: Information disclosure
    """
    return jsonify(
        {
            "database": DATABASE,
            "api_key": API_KEY,  # VULNERABILITY: Exposing API key!
            "supported_tokens": SUPPORTED_TOKENS,
            "sources": PRICE_SOURCES,
            "python_version": os.sys.version,
            "env_vars": dict(os.environ),  # VULNERABILITY: Exposing env variables!
        }
    )


def aggregate_prices(token):
    """
    Aggregate prices from multiple sources
    """
    prices = []

    for source_name, source_url in PRICE_SOURCES.items():
        try:
            # VULNERABILITY: No timeout on requests
            response = requests.get(f"{source_url}?token={token}")
            data = response.json()

            if "price" in data:
                prices.append(
                    {"source": source_name, "price": data["price"], "confidence": 1.0}
                )
        except:
            pass

    return prices


if __name__ == "__main__":
    init_db()

    # VULNERABILITY: Debug mode in production
    # VULNERABILITY: Exposed on all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
