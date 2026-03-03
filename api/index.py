from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

app = Flask(__name__)

# ==============================
# CONFIG
# ==============================
PBKDF2_ITERATIONS = 390000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_LENGTH = 32  # 256-bit

# ==============================
# HELPER: Derive Key from Password
# ==============================
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# ==============================
# LOCK (ENCRYPT)
# ==============================
@app.route("/api/lock", methods=["POST"])
def lock():
    password = request.form.get("password")
    if not password:
        return jsonify({"error": "Password wajib diisi!"})

    if "file" not in request.files:
        return jsonify({"error": "Upload file dulu!"})

    file = request.files["file"]
    data = file.read()

    if len(data) > 10 * 1024 * 1024:
        return jsonify({"error": "Max 10MB!"})

    try:
        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)

        aesgcm = AESGCM(key)
        nonce = os.urandom(NONCE_SIZE)

        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Format: salt + nonce + ciphertext
        final_data = salt + nonce + ciphertext

        return jsonify({
            "filename": file.filename + ".vault",
            "file_b64": base64.b64encode(final_data).decode()
        })

    except Exception:
        return jsonify({"error": "Encryption gagal!"})

# ==============================
# UNLOCK (DECRYPT)
# ==============================
@app.route("/api/unlock", methods=["POST"])
def unlock():
    password = request.form.get("password")
    if not password:
        return jsonify({"error": "Password wajib diisi!"})

    if "file" not in request.files:
        return jsonify({"error": "Upload file vault dulu!"})

    file = request.files["file"]
    raw = file.read()

    try:
        decoded = base64.b64decode(raw)

        salt = decoded[:SALT_SIZE]
        nonce = decoded[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
        ciphertext = decoded[SALT_SIZE+NONCE_SIZE:]

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return jsonify({
            "filename": "OPEN_" + file.filename.replace(".vault", ""),
            "file_b64": base64.b64encode(plaintext).decode()
        })

    except Exception:
        return jsonify({"error": "Decrypt gagal! Password salah atau file rusak."})

# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
