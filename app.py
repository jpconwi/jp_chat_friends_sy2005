from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from db import get_connection

app = Flask(__name__)
CORS(app)

# === CREATE admin TABLE IF NOT EXISTS ===
@app.before_first_request
def create_admin_table():
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS admin (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                password_hash TEXT NOT NULL
            );
        ''')
        conn.commit()
        cur.close()
        conn.close()
        print("✅ 'admin' table ensured.")
    except Exception as e:
        print(f"❌ Error creating admin table: {e}")

# --- Route: Home page ---
@app.route("/")
def home():
    return render_template("index.html")

# --- Route:Register ---
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    try:
        conn = get_connection()
        cur = conn.cursor()

        # Check if username already exists
        cur.execute("SELECT * FROM admin WHERE username = %s", (username,))
        if cur.fetchone():
            return jsonify({"status": "failed", "message": "Username already exists"}), 400

        # Hash password
        hashed_pw = generate_password_hash(password)

        # Insert into admin table
        cur.execute(
            "INSERT INTO admin (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, hashed_pw)
        )
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"status": "success"}), 201

    except Exception as e:
        print("Registration error:", e)
        return jsonify({"status": "failed", "message": str(e)}), 500

# --- Route: Login ---
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM admin WHERE username = %s", (data["username"],))
    user = cur.fetchone()
    cur.close()
    conn.close()
    
    if user and check_password_hash(user[0], data["password"]):
        return jsonify({"status": "success"}), 200
    return jsonify({"status": "failed"}), 401
