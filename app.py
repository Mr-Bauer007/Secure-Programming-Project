from flask import Flask, request, jsonify, send_file
import os
import base64
import json
from functools import wraps
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"]
)

# Directories for uploads, encryption, and decryption
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
DECRYPTED_FOLDER = "decrypted"

# Ensure folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

# API Key (simple secure access control)
API_KEY = "my-super-secret-api-key"

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("x-api-key")
        if key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# Function to derive encryption key from password and salt
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

# Function to encrypt data (both messages and files)
def encrypt_data(data: bytes, password: str):
    salt = secrets.token_bytes(16)  # Generate a random salt
    key = derive_key(password, salt)

    iv = secrets.token_bytes(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(data) + encryptor.finalize()

    return {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
    }

# Function to decrypt data (both messages and files)
def decrypt_data(encrypted_data: dict, password: str):
    salt = base64.b64decode(encrypted_data["salt"])
    iv = base64.b64decode(encrypted_data["iv"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()

# Route to encrypt data (either message or file)
@app.route("/encrypt", methods=["POST"])
@require_api_key
def encrypt():
    if request.content_type == "application/json":
        # Encrypting messages
        data = request.get_json()
        if "message" in data and "password" in data:
            message = data["message"].encode()
            password = data["password"]
            encrypted_data = encrypt_data(message, password)
            return jsonify({"encrypted_data": encrypted_data})

    elif "file" in request.files and "password" in request.form:
        # Encrypting files
        file = request.files["file"]
        password = request.form["password"]
        file_data = file.read()
        encrypted_data = encrypt_data(file_data, password)

        encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, file.filename + ".enc")
        with open(encrypted_file_path, "w") as f:
            json.dump(encrypted_data, f)  # Save encrypted data safely

        return jsonify({"message": "File encrypted successfully", "download_url": f"/download/{file.filename}.enc"}), 200

    return jsonify({"error": "Invalid request format"}), 400

# Route to decrypt data (either message or file)
@app.route("/decrypt", methods=["POST"])
@require_api_key
@limiter.limit("5 per minute")
def decrypt():
    data = request.get_json()
    if "encrypted_data" in data and "password" in data:
        try:
            encrypted_data = data["encrypted_data"]
            password = data["password"]
            decrypted_data = decrypt_data(encrypted_data, password)
            return jsonify({"decrypted_data": decrypted_data.decode()})
        except Exception:
            return jsonify({"error": "Decryption failed. Wrong password or corrupted data."}), 400

    return jsonify({"error": "Invalid request format"}), 400

@app.route("/decrypt-file", methods=["POST"])
@require_api_key
@limiter.limit("5 per minute")
def decrypt_file():
    if "file" not in request.files or "password" not in request.form:
        return jsonify({"error": "Missing file or password"}), 400

    file = request.files["file"]
    password = request.form["password"]
    
    if not file.filename.endswith(".enc"):
        return jsonify({"error": "Invalid file format"}), 400

    try:
        # Read and safely parse JSON-encoded encrypted data
        encrypted_data = json.loads(file.read().decode())

        # Attempt decryption
        decrypted_data = decrypt_data(encrypted_data, password)
        
        original_filename = file.filename.replace(".enc", "")
        decrypted_file_path = os.path.join(DECRYPTED_FOLDER, original_filename)

        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        return jsonify({
            "message": "File decrypted successfully",
            "download_url": f"/download/{original_filename}"
        }), 200

    except Exception as e:
        return jsonify({"error": "Decryption failed. Wrong password or corrupted file."}), 400

# Route to download files
@app.route("/download/<filename>", methods=["GET"])
@require_api_key
def download_file(filename):
    file_path = os.path.join(ENCRYPTED_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return jsonify({"error": "File not found"}), 404

@app.route("/", methods=["GET"])
def index():
    return jsonify({"message": "Secure Flask server is running over HTTPS."})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, ssl_context=('certs/server.crt', 'certs/server.key'), debug=False)
