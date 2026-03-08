import os
import uuid
import time
from flask import (Blueprint, request, session, render_template_string,
                   send_file, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Any
from extensions import db
from models import ShareLink
from blueprints.auth import login_required, log_action

sharing_bp = Blueprint("sharing", __name__)
UPLOAD_FOLDER = "uploads"
download_tokens: dict[str, list[Any]] = {}


@sharing_bp.route("/share/<filename>", methods=["POST"])
@login_required
def share_file(filename: str) -> Any:
    password = request.form.get("password", "")
    if not password:
        return jsonify({"message": "Password required"}), 400
    token = str(uuid.uuid4())
    expires = time.time() + 3600  # 1 hour
    link = ShareLink(
        token=token,
        filename=filename,
        password_hash=generate_password_hash(password),
        expires_at=expires
    )
    db.session.add(link)
    db.session.commit()
    log_action(session["user"], "created_share_link", filename)
    return jsonify({"link": f"/shared/{token}"})


@sharing_bp.route("/shared/<token>", methods=["GET", "POST"])
def access_shared(token: str) -> Any:
    link = ShareLink.query.filter_by(token=token).first()
    if not link or time.time() > link.expires_at or link.used:
        return "This link is expired or invalid.", 404

    if request.method == "POST":
        password = request.form.get("password", "")
        if check_password_hash(link.password_hash, password):
            link.used = True
            db.session.commit()
            filepath = os.path.join(UPLOAD_FOLDER, link.filename + ".enc")
            if not os.path.exists(filepath):
                return "File not found.", 404
            return send_file(filepath, as_attachment=True,
                             download_name=link.filename)
        return "Incorrect password.", 403

    html = """
    <form method="POST">
        <h3>Enter password to download</h3>
        <input type="password" name="password" placeholder="Password" />
        <button type="submit">Download</button>
    </form>
    """
    return render_template_string(html)


@sharing_bp.route("/generate_link/<filename>")
@login_required
def generate_link(filename: str) -> Any:
    token = str(uuid.uuid4())
    download_tokens[token] = [filename, time.time() + 300, 1]
    log_action(session["user"], "generated_download_link", filename)
    return jsonify({"link": f"/download_tmp/{token}"})


@sharing_bp.route("/download_tmp/<token>")
def download_tmp(token: str) -> Any:
    info = download_tokens.get(token)
    if not info:
        return "Invalid link.", 404
    filename, expires_at, remaining = info
    if time.time() > expires_at or remaining < 1:
        download_tokens.pop(token, None)
        return "Link expired.", 403
    download_tokens[token][2] -= 1
    filepath = os.path.join(UPLOAD_FOLDER, filename + ".enc")
    if not os.path.exists(filepath):
        return "File not found.", 404
    return send_file(filepath, as_attachment=True, download_name=filename)