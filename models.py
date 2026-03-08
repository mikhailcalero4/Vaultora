from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import pyotp

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(20), default="user")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, username: str, password_hash: str,
                 role: str = "user", totp_secret: str | None = None):
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.totp_secret = totp_secret or pyotp.random_base32()

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class File(db.Model):
    __tablename__ = "files"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    owner = db.Column(db.String(80), db.ForeignKey("users.username"), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_at = db.Column(db.Integer, nullable=True)
    sha256_hash = db.Column(db.String(64), nullable=True)

    def __init__(self, filename: str, owner: str,
                 sha256_hash: str | None = None, expiry_at: int | None = None):
        self.filename = filename
        self.owner = owner
        self.sha256_hash = sha256_hash
        self.expiry_at = expiry_at

    def __repr__(self) -> str:
        return f"<File {self.filename}>"


class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(80), nullable=False)
    filename = db.Column(db.String(256), nullable=True)
    ip = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, username: str, action: str,
                 filename: str | None = None, ip: str | None = None):
        self.username = username
        self.action = action
        self.filename = filename
        self.ip = ip

    def __repr__(self) -> str:
        return f"<AuditLog {self.username} {self.action}>"


class ShareLink(db.Model):
    __tablename__ = "share_links"
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    filename = db.Column(db.String(256), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    expires_at = db.Column(db.Float, nullable=False)
    used = db.Column(db.Boolean, default=False)

    def __init__(self, token: str, filename: str,
                 password_hash: str, expires_at: float):
        self.token = token
        self.filename = filename
        self.password_hash = password_hash
        self.expires_at = expires_at
        self.used = False


class FileVersion(db.Model):
    __tablename__ = "file_versions"
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(256), nullable=False)
    versioned_filename = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, original_filename: str, versioned_filename: str):
        self.original_filename = original_filename
        self.versioned_filename = versioned_filename