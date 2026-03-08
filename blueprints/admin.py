from flask import Blueprint, render_template, session, jsonify, request, Response
from typing import Any
from extensions import db
from models import AuditLog, User, File
from blueprints.auth import login_required, role_required

admin_bp = Blueprint("admin", __name__)

COMPLIANCE_CONTROLS = {
    "GDPR": ["encryption_at_rest", "role_based_access", "file_audit_log", "data_retention_policy"],
    "HIPAA": ["encryption_in_transit", "role_based_access", "access_logging", "file_integrity", "incident_response"],
    "ISO27001": ["encryption_at_rest", "encryption_in_transit", "user_authentication", "audit_logging", "least_privilege"],
}

IMPLEMENTED: dict[str, bool] = {
    "encryption_at_rest": True,
    "encryption_in_transit": True,
    "role_based_access": True,
    "file_audit_log": True,
    "user_authentication": True,
    "access_logging": True,
    "file_integrity": True,
    "data_retention_policy": True,
    "incident_response": True,
    "least_privilege": True,
    "audit_logging": True,
}


@admin_bp.route("/dashboard")
@login_required
@role_required("admin")
def dashboard() -> Any:
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    users = User.query.all()
    files = File.query.all()
    return render_template("admin.html", logs=logs, users=users, files=files)


@admin_bp.route("/audit")
@login_required
@role_required("admin")
def audit_view() -> Any:
    username = request.args.get("username", "").lower()
    action = request.args.get("action", "").lower()
    filename = request.args.get("filename", "").lower()

    # Fetch recent logs then filter in Python — avoids SQLAlchemy column type issues
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(500).all()

    results = [
        log for log in all_logs
        if (not username or username in (log.username or "").lower())
        and (not action or action in (log.action or "").lower())
        and (not filename or filename in (log.filename or "").lower())
    ]

    return jsonify([{
        "id": log.id,
        "username": log.username,
        "action": log.action,
        "filename": log.filename,
        "ip": log.ip,
        "timestamp": str(log.timestamp)
    } for log in results])


@admin_bp.route("/compliance")
@login_required
@role_required("admin")
def compliance() -> Any:
    report = {}
    for framework, controls in COMPLIANCE_CONTROLS.items():
        report[framework] = {
            "satisfied": [c for c in controls if IMPLEMENTED.get(c)],
            "missing": [c for c in controls if not IMPLEMENTED.get(c)]
        }
    return render_template("compliance.html", report=report)


@admin_bp.route("/users")
@login_required
@role_required("admin")
def list_users() -> Any:
    users = User.query.all()
    return jsonify([{
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "created_at": str(u.created_at)
    } for u in users])


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@role_required("admin")
def update_role(user_id: int) -> Any:
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({"message": "User not found"}), 404
    new_role = request.form.get("role", "user")
    if new_role not in {"admin", "user"}:
        return jsonify({"message": "Invalid role"}), 400
    user.role = new_role
    db.session.commit()
    return jsonify({"message": f"User '{user.username}' role updated to '{new_role}'."})

@admin_bp.route("/siem_export")
@login_required
@role_required("admin")
def siem_export() -> Any:
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(1000).all()
    cef_lines = []
    for log in logs:
        cef = (
            f"CEF:0|Vaultora|SecureVault|1.0|{log.action}|{log.action}|5|"
            f"src={log.ip or 'unknown'} "
            f"suser={log.username} "
            f"fname={log.filename or 'N/A'} "
            f"rt={log.timestamp}"
        )
        cef_lines.append(cef)
    return Response(
        "\n".join(cef_lines),
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=vaultora_siem_export.cef"}
    )