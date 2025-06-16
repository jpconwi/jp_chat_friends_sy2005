from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from db import get_connection
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-secret-key")
app.permanent_session_lifetime = timedelta(minutes=30)
CORS(app)

# ✅ Ensure uploads folder exists
UPLOAD_FOLDER = os.path.join("static", "uploads")
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


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
        profile_pic TEXT,
        address TEXT,
        phone TEXT,
        birthdate DATE,
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

def create_users_table():
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                password_hash TEXT,
                profile_pic TEXT,
                address TEXT,
                phone TEXT,
                birthdate DATE
            );
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("✅ 'users' table ensured.")
    except Exception as e:
        print(f"❌ Error creating users table: {e}")





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
        return redirect("/login")

    conn = get_connection()
    cur = conn.cursor()

    # Fetch admin info
    cur.execute("SELECT username, email, profile_pic FROM admin WHERE username = %s", (session["admin"],))
    admin_data = cur.fetchone()
    admin = {
        "username": admin_data[0],
        "email": admin_data[1],
        "profile_pic": admin_data[2] if admin_data[2] else ""
    }

    # Skip fetching users for now
    users = []  # 👈 Provide empty list

    cur.close()
    conn.close()

    return render_template("dashboard.html", users=users, admin=admin)




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

@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "admin" not in session:
        return jsonify({"status": "unauthorized"}), 401
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM admin WHERE username = %s", (session["admin"],))
        cur.execute("DELETE FROM messages WHERE sender = %s OR receiver = %s", (session["admin"], session["admin"]))
        conn.commit()
        cur.close()
        conn.close()
        session.pop("admin")
        return jsonify({"status": "deleted"})
    except Exception as e:
        return jsonify({"status": "failed", "message": str(e)}), 500



@app.route('/edit_info', methods=['POST'])
def edit_info():
    if "admin_id" not in session:
        return redirect("/login")

    admin_id = session["admin_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    # Get form data
    username = request.form["username"]
    email = request.form["email"]
    address = request.form["address"]
    phone = request.form["phone"]
    birthdate = request.form["birthdate"]

    profile_pic = request.files["profile_pic"]
    filename = None
    if profile_pic and profile_pic.filename != "":
        filename = secure_filename(profile_pic.filename)
        upload_path = os.path.join("static/uploads", filename)
        profile_pic.save(upload_path)

    if filename:
        cur.execute("""
            UPDATE admin
            SET username=%s, email=%s, address=%s, phone=%s, birthdate=%s, profile_pic=%s
            WHERE id=%s
        """, (username, email, address, phone, birthdate, filename, admin_id))
    else:
        cur.execute("""
            UPDATE admin
            SET username=%s, email=%s, address=%s, phone=%s, birthdate=%s
            WHERE id=%s
        """, (username, email, address, phone, birthdate, admin_id))

    conn.commit()
    conn.close()
    return redirect("/profile")
    
@app.route("/update_profile", methods=["POST"])
def update_profile():
    if "admin_id" not in session:
        return redirect("/login")

    admin_id = session["admin_id"]
    file = request.files.get("profile_pic")  # <-- line 433 should look like this

    if file and file.filename != "":
        filename = secure_filename(file.filename)
        filepath = os.path.join("static/uploads", filename)
        file.save(filepath)
        profile_pic = filename
    else:
        profile_pic = None

    address = request.form["address"]
    phone = request.form["phone"]
    birthdate = request.form["birthdate"]

    conn = get_db_connection()
    cur = conn.cursor()

    if profile_pic:
        cur.execute("UPDATE admin SET profile_pic=%s, address=%s, phone=%s, birthdate=%s WHERE id=%s",
                    (profile_pic, address, phone, birthdate, admin_id))
    else:
        cur.execute("UPDATE admin SET address=%s, phone=%s, birthdate=%s WHERE id=%s",
                    (address, phone, birthdate, admin_id))

    conn.commit()
    conn.close()

    return redirect("/profile")



@app.route('/user_profile/<username>')
def user_profile(username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT username, email, profile_pic, address, phone, birthdate FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return render_template("user_profile.html", user=user)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if "admin_id" not in session:
        return redirect("/login")

    admin_id = session["admin_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        # Get data from the form
        address = request.form['address']
        phone = request.form['phone']
        birthdate = request.form['birthdate']
        profile_pic = request.files.get('profile_pic')

        # Handle profile_pic upload if needed
        if profile_pic and profile_pic.filename != '':
            filename = secure_filename(profile_pic.filename)
            upload_path = os.path.join('static/profile_pics', filename)
            profile_pic.save(upload_path)

            # Save to DB with profile_pic
            cur.execute(
                "UPDATE admin SET address = %s, phone = %s, birthdate = %s, profile_pic = %s WHERE id = %s",
                (address, phone, birthdate, filename, admin_id)
            )
        else:
            # Save to DB without changing profile_pic
            cur.execute(
                "UPDATE admin SET address = %s, phone = %s, birthdate = %s WHERE id = %s",
                (address, phone, birthdate, admin_id)
            )

        conn.commit()

    # Fetch the updated admin record
    cur.execute("SELECT * FROM admin WHERE id = %s", (admin_id,))
    admin = cur.fetchone()
    conn.close()

    return render_template("profile.html", admin=admin)




if __name__ == "__main__":
    with app.app_context():
        create_admin_table()
        create_messages_table()
        add_missing_columns()
        create_users_table()
    app.run(debug=True)









