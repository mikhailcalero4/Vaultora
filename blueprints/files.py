import os
import hashlib
import shutil
import tempfile
import time
from datetime import datetime
from flask import (Blueprint, request, session, jsonify,
                   send_file, current_app, Response)
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Any
from extensions import db
from models import File, FileVersion
from blueprints.auth import login_required, log_action

# Blueprint MUST be defined before any @files_bp.route decorators
files_bp = Blueprint("files", __name__)

KEY_FILE = os.environ.get("KEY_FILE_PATH", "secret.key")
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "docx", "xlsx"}


# ── Encryption ────────────────────────────────────────────────────────────────

import base64

def load_key() -> bytes:
    # Prefer env var (more secure), fall back to file
    env_key = os.environ.get("AES_KEY_B64")
    if env_key:
        return base64.b64decode(env_key)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = get_random_bytes(32)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

SECRET_KEY: bytes = load_key()


def encrypt_file(data: bytes, key: bytes | None = None) -> bytes:
    k: bytes = key if key is not None else SECRET_KEY
    cipher = AES.new(k, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext


def decrypt_file(enc_data: bytes, key: bytes | None = None) -> bytes:
    k: bytes = key if key is not None else SECRET_KEY
    nonce = enc_data[:16]
    tag = enc_data[16:32]
    ciphertext = enc_data[32:]
    cipher = AES.new(k, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_safe_filename(file: Any) -> str | None:
    if file.filename is None or file.filename.strip() == "":
        return None
    return secure_filename(file.filename)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ── Routes ────────────────────────────────────────────────────────────────────

@files_bp.route("/upload", methods=["POST"])
@login_required
def upload() -> Any:
    if "file" not in request.files:
        return jsonify({"message": "No file part"}), 400

    file = request.files["file"]
    filename = get_safe_filename(file)

    if filename is None:
        return jsonify({"message": "No file selected"}), 400
    if not allowed_file(filename):
        return jsonify({"message": "File type not allowed"}), 400

    file_data = file.read()
    file_hash = compute_hash(file_data)

    upload_folder: str = current_app.config["UPLOAD_FOLDER"]
    versions_folder: str = current_app.config["VERSIONS_FOLDER"]
    existing_path = os.path.join(upload_folder, filename + ".enc")

    if os.path.exists(existing_path):
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        versioned_name = f"{filename}.{ts}"
        shutil.copyfile(existing_path, os.path.join(versions_folder, versioned_name))
        version_entry = FileVersion(
            original_filename=filename,
            versioned_filename=versioned_name
        )
        db.session.add(version_entry)

    encrypted = encrypt_file(file_data)
    with open(existing_path, "wb") as f:
        f.write(encrypted)

    retention_days = int(request.form.get("retention_days", 0))
    expiry_at: int | None = (
        int(time.time()) + retention_days * 86400 if retention_days > 0 else None
    )

    db_file = File.query.filter_by(
        filename=filename, owner=session["user"]
    ).first()

    if db_file:
        db_file.sha256_hash = file_hash
        db_file.uploaded_at = datetime.utcnow()
        db_file.expiry_at = expiry_at
    else:
        db_file = File(
            filename=filename,
            owner=session["user"],
            sha256_hash=file_hash,
            expiry_at=expiry_at
        )
        db.session.add(db_file)

    db.session.commit()
    log_action(session["user"], "upload", filename)
    return jsonify({"message": f"'{filename}' uploaded and encrypted successfully."})


@files_bp.route("/download/<filename>")
@login_required
def download(filename: str) -> Any:
    safe_name = secure_filename(filename)
    filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], safe_name + ".enc")

    if not os.path.exists(filepath):
        return jsonify({"message": "File not found"}), 404

    with open(filepath, "rb") as f:
        encrypted = f.read()

    db_file = File.query.filter_by(
        filename=safe_name, owner=session["user"]
    ).first()
    decrypted = decrypt_file(encrypted)

    if db_file and db_file.sha256_hash:
        if compute_hash(decrypted) != db_file.sha256_hash:
            log_action(session["user"], "integrity_failure", safe_name)
            return jsonify({"message": "File integrity check failed!"}), 500

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_" + safe_name)
    try:
        tmp.write(decrypted)
        tmp.close()
        log_action(session["user"], "download", safe_name)
        return send_file(tmp.name, as_attachment=True, download_name=safe_name)
    finally:
        if os.path.exists(tmp.name):
            os.remove(tmp.name)


@files_bp.route("/delete/<filename>", methods=["POST"])
@login_required
def delete(filename: str) -> Any:
    safe_name = secure_filename(filename)
    filepath = os.path.join(
        current_app.config["UPLOAD_FOLDER"], safe_name + ".enc"
    )
    db_file = File.query.filter_by(
        filename=safe_name, owner=session["user"]
    ).first()

    if not db_file:
        return jsonify({"message": "File not found or access denied"}), 404

    if os.path.exists(filepath):
        os.remove(filepath)

    db.session.delete(db_file)
    db.session.commit()
    log_action(session["user"], "delete", safe_name)
    return jsonify({"message": f"'{safe_name}' deleted."})


@files_bp.route("/versions/<filename>")
@login_required
def list_versions(filename: str) -> Any:
    safe_name = secure_filename(filename)
    versions = FileVersion.query.filter_by(
        original_filename=safe_name
    ).order_by(FileVersion.created_at.desc()).all()
    return jsonify({
        "versions": [
            {"name": v.versioned_filename, "created_at": str(v.created_at)}
            for v in versions
        ]
    })


@files_bp.route("/rollback/<versioned_filename>", methods=["POST"])
@login_required
def rollback(versioned_filename: str) -> Any:
    safe_name = secure_filename(versioned_filename)
    versioned_path = os.path.join(
        current_app.config["VERSIONS_FOLDER"], safe_name
    )
    if not os.path.exists(versioned_path):
        return jsonify({"message": "Version not found"}), 404

    original_name = safe_name.split(".")[0]
    dest = os.path.join(
        current_app.config["UPLOAD_FOLDER"], original_name + ".enc"
    )
    shutil.copyfile(versioned_path, dest)
    log_action(session["user"], "rollback", original_name)
    return jsonify({"message": f"Rolled back to {safe_name}"})


@files_bp.route("/rotate_keys", methods=["POST"])
@login_required
def rotate_keys() -> Any:
    if session.get("role") != "admin":
        return "Access Denied", 403

    global SECRET_KEY
    old_key = SECRET_KEY
    new_key = get_random_bytes(32)
    upload_folder: str = current_app.config["UPLOAD_FOLDER"]

    for fname in os.listdir(upload_folder):
        if not fname.endswith(".enc"):
            continue
        fpath = os.path.join(upload_folder, fname)
        with open(fpath, "rb") as f:
            enc_data = f.read()
        decrypted = decrypt_file(enc_data, key=old_key)
        re_encrypted = encrypt_file(decrypted, key=new_key)
        with open(fpath, "wb") as f:
            f.write(re_encrypted)

    SECRET_KEY = new_key
    with open(KEY_FILE, "wb") as f:
        f.write(new_key)

    log_action(session["user"], "key_rotation", "all")
    return jsonify({"message": "Key rotated and all files re-encrypted."})