import os
import base64
from flask import Flask, render_template, session, redirect, url_for, Response
from dotenv import load_dotenv
from extensions import limiter, csrf, talisman
from apscheduler.schedulers.background import BackgroundScheduler
from models import db

load_dotenv()


def create_app():
    app = Flask(__name__)

    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///vaultora.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["UPLOAD_FOLDER"] = "uploads"
    app.config["VERSIONS_FOLDER"] = "versions"
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB
    app.config["WTF_CSRF_ENABLED"] = True

    # Init extensions
    db.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    talisman.init_app(
        app,
        force_https=False,  # set True in production
        content_security_policy={
            "default-src": "'self'",
            "script-src": ["'self'", "cdn.jsdelivr.net"],
            "style-src": ["'self'", "cdn.jsdelivr.net"],
            "img-src": ["'self'", "api.qrserver.com", "data:"],
        }
    )

    # Register blueprints
    from blueprints.auth import auth_bp
    from blueprints.files import files_bp
    from blueprints.admin import admin_bp
    from blueprints.security import security_bp
    from blueprints.sharing import sharing_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(security_bp)
    app.register_blueprint(sharing_bp)

    # Create DB tables and seed admin
    with app.app_context():
        db.create_all()
        _seed_admin()

    # Scheduled nightly cleanup of expired files
    scheduler = BackgroundScheduler()
    scheduler.add_job(_cleanup_expired_files, "interval", hours=24, args=[app])
    scheduler.start()

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        if "user" not in session:
            return redirect(url_for("auth.login"))
        from models import File
        files = File.query.filter_by(owner=session["user"]).all()
        return render_template("index.html", files=files)

    @app.route("/.well-known/security.txt")
    def security_txt():
        content = """Contact: mailto:admin@vaultora.com
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: en

# Security Features Implemented:
# - AES-256 encryption at rest (EAX mode)
# - TOTP-based two-factor authentication (RFC 6238)
# - Role-based access control (admin/user)
# - Rate limiting on all auth endpoints (flask-limiter)
# - CSRF protection on all POST forms (flask-wtf)
# - Security headers: CSP, X-Frame-Options, HSTS (flask-talisman)
# - File integrity verification (SHA-256)
# - Malware scanning (ClamAV via pyclamd)
# - Geofencing by country code (ipapi.co)
# - Zero trust device/IP verification
# - Automatic file retention and expiry (APScheduler)
# - Full audit logging with IP and timestamp
# - Automated AES key rotation
# - Password-protected time-limited file sharing
"""
        return Response(content, mimetype="text/plain")

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403.html"), 403

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template("429.html"), 429

    return app


def _seed_admin():
    from models import User
    from werkzeug.security import generate_password_hash
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            password_hash=generate_password_hash(
                os.environ.get("ADMIN_PASS", "changeme")
            ),
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()
        print("[Vaultora] Default admin user created.")


def _cleanup_expired_files(app: Flask) -> None:
    import time
    with app.app_context():
        from models import File
        now = int(time.time())

        # Fetch all files then filter in Python to avoid SQLAlchemy type issues
        all_files = File.query.all()
        expired = [
            f for f in all_files
            if f.expiry_at is not None and f.expiry_at < now
        ]

        for f in expired:
            path = os.path.join("uploads", f.filename)
            if os.path.exists(path):
                os.remove(path)
            db.session.delete(f)

        db.session.commit()
        if expired:
            print(f"[Cleanup] Removed {len(expired)} expired files.")


if __name__ == "__main__":
    app = create_app()
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")