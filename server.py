from flask import Flask, request, jsonify
from flask_cors import CORS
import json, os, bcrypt
from datetime import datetime

app = Flask(__name__)
CORS(app)

USERS_FILE = "users.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4, ensure_ascii=False)

@app.route("/api/users", methods=["GET"])
def get_users():
    return jsonify(load_users())

@app.route("/api/users", methods=["POST"])
def add_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Kullanıcı adı ve şifre gerekli"}), 400
    users = load_users()
    if username in users:
        return jsonify({"error": "Kullanıcı zaten var"}), 400
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {
        "password": hashed,
        "role": "user",
        "created_at": datetime.now().isoformat()
    }
    save_users(users)
    return jsonify({"message": "Kullanıcı başarıyla eklendi"})

@app.route("/api/users/<username>", methods=["DELETE"])
def delete_user(username):
    users = load_users()
    if username not in users:
        return jsonify({"error": "Kullanıcı bulunamadı"}), 404
    del users[username]
    save_users(users)
    return jsonify({"message": "Kullanıcı başarıyla silindi"})

@app.route("/api/verify", methods=["POST"])
def verify_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    users = load_users()
    if username not in users:
        return jsonify({"valid": False, "error": "Kullanıcı bulunamadı"}), 404
    if bcrypt.checkpw(password.encode(), users[username]["password"].encode()):
        return jsonify({"valid": True, "is_admin": users[username].get("role") == "admin"})
    return jsonify({"valid": False, "error": "Geçersiz şifre"}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
