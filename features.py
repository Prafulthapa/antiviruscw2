from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    try:
        data = request.json['data']
        key = request.json['key']

        # Ensure data and key are provided
        if not data or not key:
            return jsonify({"error": "Data and key are required."}), 400

        # Encrypt the data using AES-GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()

        # Get the tag for authentication
        tag = encryptor.tag

        # Encode the ciphertext and tag for transmission
        encrypted_data = base64.b64encode(ciphertext).decode('utf-8')
        encoded_tag = base64.b64encode(tag).decode('utf-8')

        return jsonify({"encrypted_data": encrypted_data, "tag": encoded_tag}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5001, debug=True)