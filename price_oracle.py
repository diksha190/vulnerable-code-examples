"""
Secure Price Oracle Service for DeFi Lending Pool
All security vulnerabilities have been fixed
"""

import os
import time
import json
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import hmac
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# FIXED: Secure configuration
API_KEY = os.getenv("ORACLE_API_KEY")
ADMIN_KEY = os.getenv("ADMIN_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))

if not API_KEY or not ADMIN_KEY:
    raise ValueError(
        "Missing required environment variables: ORACLE_API_KEY, ADMIN_KEY"
    )

# FIXED: Restricted CORS
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
            "methods": ["GET", "POST"],
            "allow_headers": ["Content-Type", "X-API-Key"],
        }
    },
)

# FIXED: Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri="redis://localhost:6379",
)

DATABASE = "prices.db"

# Whitelist of allowed price sources
ALLOWED_PRICE_SOURCES = ["api.coingecko.com", "api.binance.com", "api.thegraph.com"]

# Price validation
MAX_PRICE = 1e12
MIN_PRICE = 1e-6
MAX_PRICE_CHANGE_PERCENT = 50  # 50% max change


def init_db():
    """Initialize database with secure schema"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS prices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_address TEXT NOT NULL,
            price REAL NOT NULL CHECK(price > 0),
            source TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            confidence REAL DEFAULT 1.0 CHECK(confidence >= 0 AND confidence <= 1),
            UNIQUE(token_address, timestamp)
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
            updater TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            signature TEXT NOT NULL
        )
    """
    )

    # Add indices for performance
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_prices_token ON prices(token_address)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_prices_timestamp ON prices(timestamp)"
    )

    conn.commit()
    conn.close()


def validate_token_address(address):
    """FIXED: Validate token address format"""
    if not address or not isinstance(address, str):
        return False
    if not address.startswith("0x"):
        return False
    if len(address) != 42:
        return False
    try:
        int(address, 16)
        return True
    except ValueError:
        return False


def verify_api_key_secure(provided_key, stored_key):
    """FIXED: Timing-attack resistant comparison"""
    return hmac.compare_digest(provided_key, stored_key)


def require_api_key(f):
    """FIXED: Secure API key validation with rate limiting"""

    @wraps(f)
    @limiter.limit("50 per minute")
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")

        if not api_key:
            abort(401, description="Missing API key")

        if not verify_api_key_secure(api_key, API_KEY):
            abort(401, description="Invalid API key")

        return f(*args, **kwargs)

    return decorated_function


def require_admin(f):
    """FIXED: Secure admin authentication"""

    @wraps(f)
    @limiter.limit("10 per minute")
    def decorated_function(*args, **kwargs):
        admin_key = request.headers.get("X-Admin-Key")

        if not admin_key:
            abort(403, description="Missing admin key")

        if not verify_api_key_secure(admin_key, ADMIN_KEY):
            abort(403, description="Unauthorized")

        return f(*args, **kwargs)

    return decorated_function


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify(
        {"status": "healthy", "timestamp": int(time.time()), "version": "2.0.0"}
    )


@app.route("/api/price/<token_address>", methods=["GET"])
@require_api_key
def get_price(token_address):
    """FIXED: Parameterized query + validation"""
    if not validate_token_address(token_address):
        abort(400, description="Invalid token address")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # FIXED: Parameterized query
    cursor.execute(
        "SELECT price, source, timestamp FROM prices WHERE token_address = ? ORDER BY timestamp DESC LIMIT 1",
        (token_address,),
    )

    result = cursor.fetchone()
    conn.close()

    if not result:
        abort(404, description="Price not found")

    price, source, timestamp = result

    # FIXED: Check price freshness
    if int(time.time()) - timestamp > 3600:  # 1 hour
        abort(410, description="Price data is stale")

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
@limiter.limit("10 per minute")
def get_batch_prices():
    """FIXED: Batch size limit + parameterized queries"""
    data = request.json

    if not data or "tokens" not in data:
        abort(400, description="Missing tokens array")

    tokens = data.get("tokens", [])

    # FIXED: Limit batch size
    if len(tokens) > 50:
        abort(400, description="Too many tokens (max 50)")

    # Validate all tokens
    for token in tokens:
        if not validate_token_address(token):
            abort(400, description=f"Invalid token address: {token}")

    results = {}
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    for token in tokens:
        # FIXED: Parameterized query
        cursor.execute(
            "SELECT price FROM prices WHERE token_address = ? ORDER BY timestamp DESC LIMIT 1",
            (token,),
        )
        result = cursor.fetchone()

        if result:
            results[token] = result[0]

    conn.close()

    return jsonify(results)


@app.route("/api/price/update", methods=["POST"])
@require_api_key
@require_admin
@limiter.limit("20 per minute")
def update_price():
    """FIXED: Authentication + validation + parameterized queries"""
    data = request.json

    if not data:
        abort(400, description="Missing request body")

    token = data.get("token")
    price = data.get("price")
    source = data.get("source", "manual")

    if not token or price is None:
        abort(400, description="Missing required fields")

    # FIXED: Validate token address
    if not validate_token_address(token):
        abort(400, description="Invalid token address")

    # FIXED: Validate price
    try:
        price = float(price)
        if price <= MIN_PRICE or price >= MAX_PRICE:
            abort(400, description=f"Price out of range: {MIN_PRICE} to {MAX_PRICE}")
    except (TypeError, ValueError):
        abort(400, description="Invalid price value")

    # Validate source
    if not source or len(source) > 50:
        abort(400, description="Invalid source")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get old price for validation
    cursor.execute(
        "SELECT price FROM prices WHERE token_address = ? ORDER BY timestamp DESC LIMIT 1",
        (token,),
    )
    old_result = cursor.fetchone()
    old_price = old_result[0] if old_result else 0

    # FIXED: Validate price change
    if old_price > 0:
        price_change = abs(price - old_price) / old_price * 100
        if price_change > MAX_PRICE_CHANGE_PERCENT:
            conn.close()
            abort(400, description=f"Price change too large: {price_change:.2f}%")

    # FIXED: Parameterized queries
    timestamp = int(time.time())

    try:
        cursor.execute(
            "INSERT INTO prices (token_address, price, source, timestamp) VALUES (?, ?, ?, ?)",
            (token, price, source, timestamp),
        )

        # FIXED: Secure logging with signature
        updater = request.headers.get("X-Updater", "unknown")[:50]  # Limit length
        signature = hmac.new(
            SECRET_KEY.encode(), f"{token}{price}{timestamp}".encode(), hashlib.sha256
        ).hexdigest()

        cursor.execute(
            "INSERT INTO price_updates (token_address, old_price, new_price, updater, timestamp, signature) VALUES (?, ?, ?, ?, ?, ?)",
            (token, old_price, price, updater, timestamp, signature),
        )

        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        abort(409, description="Duplicate price entry")

    conn.close()

    return jsonify(
        {"success": True, "token": token, "old_price": old_price, "new_price": price}
    )


@app.route("/api/price/history/<token>", methods=["GET"])
@require_api_key
def get_price_history(token):
    """FIXED: Validation + limit"""
    if not validate_token_address(token):
        abort(400, description="Invalid token address")

    # FIXED: Validate and limit
    try:
        limit = int(request.args.get("limit", 100))
        limit = min(max(limit, 1), 1000)  # Between 1 and 1000
    except ValueError:
        abort(400, description="Invalid limit parameter")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # FIXED: Parameterized query
    cursor.execute(
        "SELECT price, source, timestamp FROM prices WHERE token_address = ? ORDER BY timestamp DESC LIMIT ?",
        (token, limit),
    )

    results = cursor.fetchall()
    conn.close()

    history = [
        {"price": row[0], "source": row[1], "timestamp": row[2]} for row in results
    ]

    return jsonify({"token": token, "count": len(history), "history": history})


@app.route("/api/fetch/external", methods=["POST"])
@require_api_key
@require_admin
@limiter.limit("5 per minute")
def fetch_external_price():
    """FIXED: URL validation to prevent SSRF"""
    data = request.json

    if not data:
        abort(400, description="Missing request body")

    token = data.get("token")
    source_url = data.get("source_url")

    if not token or not source_url:
        abort(400, description="Missing required fields")

    if not validate_token_address(token):
        abort(400, description="Invalid token address")

    # FIXED: Validate URL to prevent SSRF
    try:
        parsed = urlparse(source_url)
        if parsed.scheme not in ["http", "https"]:
            abort(400, description="Invalid URL scheme")

        if parsed.hostname not in ALLOWED_PRICE_SOURCES:
            abort(400, description="URL not in whitelist")

        # Prevent internal network access
        if (
            parsed.hostname in ["localhost", "127.0.0.1", "0.0.0.0"]
            or parsed.hostname.startswith("192.168.")
            or parsed.hostname.startswith("10.")
        ):
            abort(400, description="Internal URLs not allowed")
    except Exception:
        abort(400, description="Invalid URL format")

    try:
        response = requests.get(source_url, timeout=5)
        response.raise_for_status()
        price_data = response.json()

        # FIXED: Validate response structure
        if "price" not in price_data:
            abort(400, description="Invalid response format")

        price = float(price_data["price"])

        if price <= MIN_PRICE or price >= MAX_PRICE:
            abort(400, description="Price out of valid range")

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

    except requests.RequestException:
        abort(502, description="External service unavailable")
    except (ValueError, TypeError):
        abort(400, description="Invalid price data")


@app.route("/api/admin/reset", methods=["POST"])
@require_admin
@limiter.limit("1 per hour")
def admin_reset():
    """FIXED: Added authentication"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM prices")
    cursor.execute("DELETE FROM price_updates")

    conn.commit()
    conn.close()

    return jsonify(
        {"success": True, "message": "All prices reset", "timestamp": int(time.time())}
    )


@app.route("/api/calculate/twap", methods=["POST"])
@require_api_key
def calculate_twap():
    """Calculate TWAP with outlier detection"""
    data = request.json

    if not data:
        abort(400, description="Missing request body")

    token = data.get("token")
    period = data.get("period", 3600)  # Default 1 hour

    if not validate_token_address(token):
        abort(400, description="Invalid token address")

    # Validate period
    period = min(max(int(period), 300), 86400)  # Between 5 min and 24 hours

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cutoff_time = int(time.time()) - period

    cursor.execute(
        "SELECT price FROM prices WHERE token_address = ? AND timestamp > ? ORDER BY timestamp",
        (token, cutoff_time),
    )

    prices = [row[0] for row in cursor.fetchall()]
    conn.close()

    if not prices:
        abort(404, description="No recent prices")

    # FIXED: Outlier detection using IQR method
    if len(prices) >= 4:
        sorted_prices = sorted(prices)
        q1_idx = len(sorted_prices) // 4
        q3_idx = 3 * len(sorted_prices) // 4

        q1 = sorted_prices[q1_idx]
        q3 = sorted_prices[q3_idx]
        iqr = q3 - q1

        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr

        # Filter outliers
        filtered_prices = [p for p in prices if lower_bound <= p <= upper_bound]

        if filtered_prices:
            prices = filtered_prices

    twap = sum(prices) / len(prices)

    return jsonify(
        {"token": token, "twap": twap, "period": period, "sample_size": len(prices)}
    )


# FIXED: Removed debug endpoint entirely
# No information disclosure


@app.errorhandler(400)
def bad_request(e):
    """FIXED: Generic error messages"""
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(401)
def unauthorized(e):
    """FIXED: Generic error messages"""
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(e):
    """FIXED: Generic error messages"""
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(500)
def internal_error(e):
    """FIXED: No stack traces in production"""
    app.logger.error(f"Internal error: {str(e)}")

    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    init_db()

    # FIXED: Production settings
    debug_mode = os.getenv("FLASK_ENV") == "development"
    app.run(
        host="127.0.0.1",  # FIXED: Localhost only
        port=5000,
        debug=debug_mode,  # FIXED: Debug off in production
    )
