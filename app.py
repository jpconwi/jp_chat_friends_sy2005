from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.security import check_password_hash
from db import get_connection

app = Flask(__name__)
CORS(app)

# --- Route: Home page ---
@app.route("/")
def home():
    return render_template("index.html")

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
