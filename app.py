from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import datetime
from models import format_messages



app = Flask(__name__)
CORS(app)

from db import get_connection
conn = get_connection()

cursor = conn.cursor()

@app.route("/", methods=["GET"])
def home():
    return "<h2>✅ Flask backend is running. Use POST requests for /login and /register</h2>"

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed = generate_password_hash(data['password'])
    cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)", 
                   (data['username'], data['email'], hashed))
    conn.commit()
    return jsonify({"status": "registered"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    cursor.execute("SELECT password_hash FROM users WHERE username = %s", (data['username'],))
    result = cursor.fetchone()
    if result and check_password_hash(result[0], data['password']):
        return jsonify({"status": "success"}), 200
    return jsonify({"status": "failed"}), 401

@app.route('/messages/send', methods=['POST'])
def send_message():
    data = request.json
    cursor.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (%s, %s, %s)", 
                   (data['sender_id'], data['receiver_id'], data['content']))
    conn.commit()
    return jsonify({"status": "sent"}), 200

@app.route('/messages/fetch', methods=['POST'])
def fetch_messages():
    data = request.json
    cursor.execute("""
        SELECT u.username, m.content, m.timestamp 
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        WHERE (sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s)
        ORDER BY m.timestamp
    """, (data['user1'], data['user2'], data['user2'], data['user1']))
    messages = cursor.fetchall()
    return jsonify(format_messages(messages))

