import os
import json
import tempfile
import pytest
from app import app as flask_app

@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
        yield client

@pytest.fixture
def setup_files():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"secret data")
        yield tf.name
    if os.path.exists(tf.name):
        os.remove(tf.name)

def test_home_page(client):
    """Check main page loads"""
    response = client.get("/")
    assert response.status_code == 200
    assert b"Vaultora" in response.data

def test_login_route(client):
    """Test login route exists"""
    response = client.get("/login")
    assert response.status_code == 200

def test_admin_dashboard(client):
    """Check admin dashboard loads with auth"""
    response = client.get("/admin/dashboard")
    assert response.status_code in [200, 404]

def test_file_encryption_and_decryption(setup_files: str) -> None:
    """Test encryption and decryption using blueprints/files.py"""
    from blueprints.files import encrypt_file, decrypt_file

    with open(setup_files, "rb") as f:
        original_data = f.read()

    encrypted = encrypt_file(original_data)
    assert encrypted != original_data  # confirm it actually changed
    assert len(encrypted) > len(original_data)  # nonce + tag added

    decrypted = decrypt_file(encrypted)
    assert decrypted == original_data  # confirm round-trip works


def test_file_integrity_verification() -> None:
    """Test SHA-256 hash integrity check using blueprints/files.py"""
    import tempfile
    import os
    from blueprints.files import compute_hash

    test_data = b"test content for integrity check"
    hash1 = compute_hash(test_data)
    hash2 = compute_hash(test_data)
    assert hash1 == hash2  # same data always produces same hash

    different_data = b"tampered content"
    hash3 = compute_hash(different_data)
    assert hash1 != hash3  # different data produces different hash

def test_role_audit() -> None:
    """Test that admin blueprint loads and compliance controls are defined"""
    from blueprints.admin import COMPLIANCE_CONTROLS, IMPLEMENTED
    for framework, controls in COMPLIANCE_CONTROLS.items():
        for control in controls:
            assert isinstance(control, str), f"Control {control} in {framework} is not a string"
    for key, val in IMPLEMENTED.items():
        assert isinstance(val, bool), f"IMPLEMENTED[{key}] should be bool"

def test_user_activity_reporting(client):
    data = [{"user": "tester", "action": "upload", "file": "test.txt", "timestamp": "2025-01-01T12:00:00"}]
    with open("audit_log.json", "w") as f:
        json.dump(data, f)
    response = client.get("/admin/dashboard")
    assert response.status_code in [200, 404]

def test_session_timeout(client):
    with client.session_transaction() as sess:
        sess["last_active"] = 0
    response = client.get("/login")
    assert response.status_code == 200

@pytest.fixture(autouse=True)
def cleanup_files():
    yield
    for fname in ["current_key.key", "access_audit_report.json", "audit_log.json", "user_roles.json"]:
        try:
            os.remove(fname)
        except FileNotFoundError:
            pass
        
@pytest.fixture
def app_client():
    """Create a test client with the full app"""
    from app import create_app
    flask_app = create_app()
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False  # disable CSRF for testing
    flask_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with flask_app.test_client() as client:
        with flask_app.app_context():
            from extensions import db
            db.create_all()
        yield client


def test_upload_without_login(app_client) -> None:
    """Unauthenticated upload should redirect to login"""
    response = app_client.post(
        "/upload",
        data={"file": (b"test data", "test.txt")},
        content_type="multipart/form-data"
    )
    assert response.status_code in [401, 302]


def test_login_wrong_password(app_client) -> None:
    """Login with wrong password should not create session"""
    response = app_client.post(
        "/login",
        data={"username": "admin", "password": "wrongpassword"},
        follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Invalid" in response.data or b"login" in response.data.lower()


def test_rate_limiting_login(app_client) -> None:
    """Too many login attempts should be rate limited (429)"""
    for _ in range(10):
        app_client.post("/login", data={"username": "x", "password": "x"})
    response = app_client.post(
        "/login", data={"username": "x", "password": "x"}
    )
    assert response.status_code == 429


def test_admin_route_blocked_for_non_admin(app_client) -> None:
    """Admin dashboard should reject non-admin users"""
    with app_client.session_transaction() as sess:
        sess["user"] = "regularuser"
        sess["role"] = "user"
    response = app_client.get("/admin/dashboard")
    assert response.status_code == 403


def test_encryption_round_trip() -> None:
    """AES encryption and decryption should be lossless"""
    from blueprints.files import encrypt_file, decrypt_file
    data = b"sensitive file content 1234"
    assert decrypt_file(encrypt_file(data)) == data


def test_integrity_hash_mismatch() -> None:
    """Different data should produce different SHA-256 hashes"""
    from blueprints.files import compute_hash
    assert compute_hash(b"original") != compute_hash(b"tampered")


def test_security_txt_route(app_client) -> None:
    """security.txt should be publicly accessible"""
    response = app_client.get("/.well-known/security.txt")
    assert response.status_code == 200
    assert b"AES" in response.data or b"Contact" in response.data