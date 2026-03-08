import os
import requests
import pyclamd
from flask import (Blueprint, request, abort, session,
                   send_from_directory, jsonify)
from werkzeug.utils import secure_filename
from functools import wraps
from typing import Any, Callable
from blueprints.auth import login_required, log_action

security_bp = Blueprint("security", __name__)

ALLOWED_COUNTRIES = {"US", "CA", "GB"}
SENSITIVE_FOLDER = os.path.join(os.getcwd(), "sensitive_files")
os.makedirs(SENSITIVE_FOLDER, exist_ok=True)

TRUSTED_DEVICES: dict[str, list[str]] = {}
ALLOWED_IPS: dict[str, list[str]] = {}


# ── Zero Trust ────────────────────────────────────────────────────────────────

def zero_trust_required(f: Callable) -> Callable:
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        user = session.get("user")
        device_id = request.headers.get("X-Device-ID")
        user_ip = request.remote_addr
        if not user:
            abort(401)
        if TRUSTED_DEVICES.get(user) and device_id not in TRUSTED_DEVICES[user]:
            abort(403, description="Untrusted device.")
        if ALLOWED_IPS.get(user) and user_ip not in ALLOWED_IPS[user]:
            abort(403, description="IP not allowed.")
        return f(*args, **kwargs)
    return wrapper


# ── Geofencing ────────────────────────────────────────────────────────────────

def get_user_country(ip: str) -> str:
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            return response.json().get("country_code", "UNKNOWN")
    except Exception:
        pass
    return "UNKNOWN"


@security_bp.before_request
def geofence_check() -> None:
    # Returns None explicitly on all paths — Flask expects None from before_request
    # when not blocking; abort() raises an exception to block
    if request.endpoint == "security.download_sensitive":
        user_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or ""
        if "," in user_ip:
            user_ip = user_ip.split(",")[0].strip()
        country = get_user_country(user_ip)
        if country not in ALLOWED_COUNTRIES:
            abort(403, description=f"Downloads not available in region: {country}")


@security_bp.route("/sensitive/download/<filename>")
@login_required
@zero_trust_required
def download_sensitive(filename: str) -> Any:
    safe = secure_filename(filename)
    if not os.path.exists(os.path.join(SENSITIVE_FOLDER, safe)):
        abort(404)
    log_action(session["user"], "sensitive_download", safe)
    return send_from_directory(SENSITIVE_FOLDER, safe, as_attachment=True)


@security_bp.route("/geofence/status")
def geofence_status() -> Any:
    return jsonify({"allowed_regions": list(ALLOWED_COUNTRIES)})


# ── Malware Scan ──────────────────────────────────────────────────────────────

def scan_for_malware(filepath: str) -> Any:
    try:
        cd = pyclamd.ClamdUnixSocket()
        if not cd.ping():
            cd = pyclamd.ClamdNetworkSocket(host="localhost", port=3310)
        return cd.scan_file(filepath)
    except Exception as e:
        return {"error": str(e)}


@security_bp.route("/scan", methods=["POST"])
@login_required
def scan_upload() -> Any:
    if "file" not in request.files:
        return jsonify({"message": "No file part"}), 400
    file = request.files["file"]
    if file.filename is None or file.filename.strip() == "":
        return jsonify({"message": "No file selected"}), 400
    filename = secure_filename(file.filename)
    filepath = os.path.join("uploads", filename)
    file.save(filepath)

    result = scan_for_malware(filepath)
    if isinstance(result, dict) and "error" in result:
        os.remove(filepath)
        return jsonify({"message": f"Scan error: {result['error']}"}), 500
    if result:
        status = list(result.values())[0][0]
        if status == "FOUND":
            os.remove(filepath)
            log_action(session["user"], "malware_blocked", filename)
            return jsonify({"message": f"Malware detected in '{filename}'."}), 403
    log_action(session["user"], "scan_clean", filename)
    return jsonify({"message": "File is clean."})


@security_bp.route("/security/status")
def security_status() -> Any:
    return jsonify({
        "zero_trust": "active",
        "geofencing": "active",
        "malware_scanning": "active",
        "allowed_regions": list(ALLOWED_COUNTRIES)
    })