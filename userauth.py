from flask import Flask, request, jsonify
import bcrypt

app = Flask(__name__)

users = {}

@app.route('/create_user', methods=['POST'])
def create_user():
    try:
        username = request.json['username']
        password = request.json['password']

        if not username or not password:
            return jsonify({"error": "Username and password are required."}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users[username] = hashed_password

        return jsonify({"message": "User created successfully."}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/authenticate_user', methods=['POST'])
def authenticate_user():
    try:
        username = request.json['username']
        password = request.json['password']

        if not username or not password:
            return jsonify({"error": "Username and password are required."}), 400

        stored_password = users.get(username)

        if stored_password and bcrypt.checkpw(password.encode('utf-8'), stored_password):
            return jsonify({"authenticated": True}), 200
        else:
            return jsonify({"authenticated": False}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5002, debug=True)