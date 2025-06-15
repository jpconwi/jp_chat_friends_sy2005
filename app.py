from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from db import get_connection
import os
from datetime import datetime, timedelta


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-secret-key")
app.permanent_session_lifetime = timedelta(minutes=30)
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
                password_hash TEXT NOT NULL,
                is_online BOOLEAN DEFAULT FALSE,
                is_typing BOOLEAN DEFAULT FALSE,
                has_seen_last_message BOOLEAN DEFAULT TRUE
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

def add_missing_columns():
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("ALTER TABLE admin ADD COLUMN IF NOT EXISTS is_online BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE admin ADD COLUMN IF NOT EXISTS is_typing BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE admin ADD COLUMN IF NOT EXISTS has_seen_last_message BOOLEAN DEFAULT TRUE;")
        conn.commit()
        cur.close()
        conn.close()
        print("✅ Missing columns added to 'admin' table.")
    except Exception as e:
        print(f"❌ Error adding columns: {e}")


# Run it once at startup
if __name__ == "__main__":
    with app.app_context():
        create_admin_table()
        create_messages_table()
        add_missing_columns()
    app.run(debug=True)



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

        if user and check_password_hash(user[0], data["password"]):
            session["admin"] = data["username"]
            session.permanent = True
            session["login_time"] = datetime.utcnow().isoformat()

            # Set online status
            cur.execute("UPDATE admin SET is_online = TRUE WHERE username = %s", (data["username"],))
            conn.commit()
            cur.close()
            conn.close()

            return jsonify({"status": "success", "redirect": "/dashboard"}), 200

        cur.close()
        conn.close()
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
    
    cur.execute("""
        SELECT username, email, is_online, is_typing, has_seen_last_message
        FROM admin
        WHERE username != %s
    """, (session["admin"],))
    
    users = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("dashboard.html", users=users)


@app.route("/logout")
def logout():
    if "admin" in session:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE admin SET is_online = FALSE WHERE username = %s", (session["admin"],))
        conn.commit()
        cur.close()
        conn.close()

        session.pop("admin")
    return redirect("/")


@app.route("/chat")
def chat():
    if "admin" not in session:
        return redirect("/")

    chat_with = request.args.get("with")
    return render_template("chat.html", chat_with=chat_with, current_admin=session["admin"])

@app.route("/admin_status")
def admin_status():
    if "admin" not in session:
        return jsonify({"status": "unauthorized"}), 401

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT username, is_online, is_typing FROM admin WHERE username != %s", (session["admin"],))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify([
            {"username": r[0], "is_online": r[1], "is_typing": r[2]} for r in rows
        ])
    except Exception as e:
        return jsonify({"status": "failed", "message": str(e)}), 500


@app.route("/get_messages")
def get_messages():
    if "admin" not in session:
        return jsonify({"status": "unauthorized"}), 401

    chat_with = request.args.get("with")
    admin = session["admin"]

    try:
        conn = get_connection()
        cur = conn.cursor()

        # Get chat messages
        cur.execute("""
            SELECT sender, text, timestamp, id 
            FROM messages
            WHERE (sender = %s AND receiver = %s)
               OR (sender = %s AND receiver = %s)
            ORDER BY timestamp ASC
        """, (admin, chat_with, chat_with, admin))
        rows = cur.fetchall()

        # Mark messages as seen by current user
        cur.execute("""
            UPDATE admin SET has_seen_last_message = TRUE
            WHERE username = %s
        """, (admin,))

        conn.commit()
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

        # Send message
        cur.execute("""
            INSERT INTO messages (sender, receiver, text)
            VALUES (%s, %s, %s)
        """, (sender, receiver, text))

        # Mark the message as not seen yet by the receiver
        cur.execute("""
            UPDATE admin SET has_seen_last_message = FALSE
            WHERE username = %s
        """, (receiver,))

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

@app.route("/set_typing", methods=["POST"])
def set_typing():
    if "admin" not in session:
        return jsonify({"status": "unauthorized"}), 401
    data = request.get_json()
    is_typing = data.get("is_typing", False)
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE admin SET is_typing = %s WHERE username = %s", (is_typing, session["admin"]))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "updated"})
    except Exception as e:
        print(f"❌ Error setting typing: {e}")
        return jsonify({"status": "failed", "message": str(e)}), 500

@app.route("/check_session")
def check_session():
    return jsonify({"logged_in": "admin" in session})

@app.route("/current_admin")
def current_admin():
    if "admin" in session:
        return jsonify({"admin": session["admin"]})
    return jsonify({"admin": None}), 401






