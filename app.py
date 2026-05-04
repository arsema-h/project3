from flask import Flask, request, jsonify
import sqlite3
import uuid
import os
import time
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
DB = "jwks.db"

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16
)

rate_limit = {}
MAX_REQUESTS = 10
WINDOW = 1


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def get_aes_key():
    key = os.environ.get("NOT_MY_KEY")
    if not key:
        raise RuntimeError("Missing NOT_MY_KEY environment variable")

    key_bytes = key.encode()

    if len(key_bytes) not in [16, 24, 32]:
        key_bytes = key_bytes.ljust(32, b"0")[:32]

    return key_bytes


def encrypt_private_key(private_key_pem):
    aesgcm = AESGCM(get_aes_key())
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key_pem.encode(), None)
    return nonce.hex(), ciphertext.hex()


def decrypt_private_key(nonce_hex, ciphertext_hex):
    aesgcm = AESGCM(get_aes_key())
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kid TEXT NOT NULL UNIQUE,
        key TEXT NOT NULL,
        iv TEXT NOT NULL,
        exp INTEGER NOT NULL
    )
    """)

    conn.commit()
    conn.close()


def check_rate_limit(ip):
    now = time.time()

    if ip not in rate_limit:
        rate_limit[ip] = []

    rate_limit[ip] = [
        timestamp for timestamp in rate_limit[ip]
        if now - timestamp < WINDOW
    ]

    if len(rate_limit[ip]) >= MAX_REQUESTS:
        return False

    rate_limit[ip].append(now)
    return True


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data or "username" not in data or "email" not in data:
        return jsonify({"error": "username and email required"}), 400

    username = data["username"]
    email = data["email"]

    password = str(uuid.uuid4())
    password_hash = ph.hash(password)

    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """, (username, email, password_hash))

        conn.commit()
        conn.close()

        return jsonify({"password": password}), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "username or email already exists"}), 409


@app.route("/auth", methods=["POST"])
def auth():
    request_ip = request.remote_addr

    if not check_rate_limit(request_ip):
        return jsonify({"error": "Too many requests"}), 429

    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "username and password required"}), 400

    username = data["username"]
    password = data["password"]

    conn = get_db()
    cur = conn.cursor()

    user = cur.execute("""
    SELECT * FROM users WHERE username = ?
    """, (username,)).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        ph.verify(user["password_hash"], password)
    except:
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    cur.execute("""
    UPDATE users
    SET last_login = CURRENT_TIMESTAMP
    WHERE id = ?
    """, (user["id"],))

    cur.execute("""
    INSERT INTO auth_logs (request_ip, user_id)
    VALUES (?, ?)
    """, (request_ip, user["id"]))

    conn.commit()
    conn.close()

    return jsonify({"message": "Authentication successful"}), 200


@app.route("/logs", methods=["GET"])
def logs():
    conn = get_db()
    cur = conn.cursor()

    rows = cur.execute("""
    SELECT auth_logs.id, request_ip, request_timestamp, username
    FROM auth_logs
    LEFT JOIN users ON auth_logs.user_id = users.id
    ORDER BY request_timestamp DESC
    """).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
