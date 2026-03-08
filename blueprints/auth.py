import os
import pyotp
from flask import (Blueprint, request, session, redirect,
                   url_for, flash, render_template, Response)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from typing import Callable, Any
from extensions import db, limiter
from models import User, AuditLog

auth_bp = Blueprint("auth", __name__)


# ── Decorators ────────────────────────────────────────────────────────────────

def login_required(f: Callable) -> Callable:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        if "user" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def role_required(role: str) -> Callable:
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args: Any, **kwargs: Any) -> Any:
            if session.get("role") != role:
                return "Access Denied", 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ── Helpers ───────────────────────────────────────────────────────────────────

def log_action(username: str, action: str, filename: str | None = None) -> None:
    entry = AuditLog(
        username=username,
        action=action,
        filename=filename,
        ip=request.remote_addr
    )
    db.session.add(entry)
    db.session.commit()


# ── Routes ────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login() -> Any:
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session["pending_user"] = username
            log_action(username, "login_step1")
            return redirect(url_for("auth.two_factor"))
        log_action(username, "failed_login")
        flash("Invalid username or password.")
    return render_template("login.html")


@auth_bp.route("/two_factor", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def two_factor() -> Any:
    username = session.get("pending_user")
    if not username:
        return redirect(url_for("auth.login"))
    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for("auth.login"))
    totp = pyotp.TOTP(user.totp_secret)
    if request.method == "POST":
        otp = request.form.get("otp", "")
        if totp.verify(otp):
            session["user"] = username
            session["role"] = user.role
            session.pop("pending_user", None)
            log_action(username, "login_success")
            return redirect(url_for("index"))
        flash("Invalid code. Try again.")
    provisioning_uri = totp.provisioning_uri(
        name=username, issuer_name="Vaultora"
    )
    return render_template("two_factor.html", provisioning_uri=provisioning_uri)


@auth_bp.route("/logout")
def logout() -> Any:
    current_user = session.get("user", "unknown")
    log_action(current_user, "logout")
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
@login_required
@role_required("admin")
def register() -> Any:
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
        else:
            new_user = User(
                username=username,
                password_hash=generate_password_hash(password),
                role=role
            )
            db.session.add(new_user)
            db.session.commit()
            log_action(session["user"], "created_user", username)
            flash(f"User '{username}' created successfully.")
    return render_template("register.html")