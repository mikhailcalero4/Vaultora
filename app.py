# app.py
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
KEY_FILE = "secret.key"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Generate or load encryption key
def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = get_random_bytes(32)  # AES-256 key
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

SECRET_KEY = load_key()

def encrypt_file(file_data):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce + tag + ciphertext

def decrypt_file(enc_data):
    nonce = enc_data[:16]
    tag = enc_data[16:32]
    ciphertext = enc_data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

@app.route("/")
def index():
    files = os.listdir(UPLOAD_FOLDER)
    return render_template("index.html", files=files)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    filename = secure_filename(file.filename)
    file_data = file.read()
    encrypted = encrypt_file(file_data)
    with open(os.path.join(UPLOAD_FOLDER, filename + ".enc"), "wb") as f:
        f.write(encrypted)
    return "File uploaded and encrypted successfully!"

@app.route("/download/<filename>")
def download(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    with open(filepath, "rb") as f:
        encrypted = f.read()
    decrypted = decrypt_file(encrypted)
    temp_file = "temp_" + filename.replace(".enc", "")
    with open(temp_file, "wb") as f:
        f.write(decrypted)
    return send_file(temp_file, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
