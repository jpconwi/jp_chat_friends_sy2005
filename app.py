from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from db import get_connection
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your-secret-key"  # Put this BEFORE anything using sessions
CORS(app)

# === CREATE admin TABLE IF NOT EXISTS ===
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

def create_messages_table():
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        conn.commit()
        cur.close()
        conn.close()
        print("✅ 'messages' table ensured.")
    except Exception as e:
        print(f"❌ Error creating messages table: {e}")

# Run it once at startup
with app.app_context():
    create_admin_table()
    create_messages_table()


# --- Route: Home page ---
@app.route("/")
def home():
    return render_template("index.html")

# --- Route:Register ---
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"status": "failed", "message": "No data provided"}), 400

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
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "failed", "message": "No data sent"}), 400

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM admin WHERE username = %s", (data["username"],))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[0], data["password"]):
            session["admin"] = data["username"]
            return jsonify({"status": "success", "redirect": "/dashboard"}), 200
        return jsonify({"status": "failed", "message": "Invalid credentials"}), 401
    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({"status": "failed", "message": str(e)}), 500

@app.route("/dashboard")
def dashboard():
    if "admin" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT username, email FROM admin WHERE username != %s", (session["admin"],))
    users = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("dashboard.html", users=users)

@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect("/")

@app.route("/chat")
def chat():
    if "admin" not in session:
        return redirect("/")
    
    chat_with = request.args.get("with")
    return render_template("chat.html", chat_with=chat_with)


@app.route("/get_messages")
def get_messages():
    if "admin" not in session:
        return jsonify({"status": "unauthorized"}), 401

    chat_with = request.args.get("with")
    admin = session["admin"]

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
    SELECT sender, text, timestamp, id 
    FROM messages
    WHERE (sender = %s AND receiver = %s)
       OR (sender = %s AND receiver = %s)
    ORDER BY timestamp ASC
""", (admin, chat_with, chat_with, admin))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        messages = [{"id": row[3], "sender": row[0], "text": row[1], "timestamp": str(row[2])} for row in rows]
        return jsonify({"messages": messages})
    except Exception as e:
        print(f"❌ Error getting messages: {e}")
        return jsonify({"messages": [], "error": str(e)}), 500


@app.route("/send_message", methods=["POST"])
def send_message():
    if "admin" not in session:
        return jsonify({"status": "unauthorized"}), 401

    data = request.get_json()
    sender = session["admin"]
    receiver = data.get("to")
    text = data.get("text")

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO messages (sender, receiver, text)
            VALUES (%s, %s, %s)
        """, (sender, receiver, text))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "sent"})
    except Exception as e:
        print(f"❌ Error sending message: {e}")
        return jsonify({"status": "failed", "message": str(e)}), 500
        

@app.route("/delete_message", methods=["POST"])
def delete_message():
    if "admin" not in session:
        return jsonify({"status": "unauthorized"}), 401

    data = request.get_json()
    message_id = data.get("id")

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM messages WHERE id = %s", (message_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "deleted"})
    except Exception as e:
        print(f"❌ Error deleting message: {e}")
        return jsonify({"status": "failed", "message": str(e)}), 500



