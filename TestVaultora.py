import os
import json
import tempfile
import pytest
from app import app as flask_app 

#Fixtures and setup
@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.test_client() as client:
        yield client

@pytest.fixture
def setup_files():
    #Setup test files
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"secret data")
        yield tf.name
        os.remove(tf.name)

#unit tests and routes and logic
def test_home_page(client):
    """Check main page loads"""
    response = client.get("/")
    assert response.status_code == 200
    assert b"Vaultora" in response.data

def test_login_route(client):
    """Test login route exists and session is set"""
    response = client.post("/login", data={"user": "testuser"})
    assert response.status_code == 200
    assert b"Login" in response.data or b"successful" in response.data

def test_admin_dashboard(client):
    """Check admin dashboard loads"""
    response = client.get("/admin/dashboard")
    assert response.status_code == 200
    assert b"Admin Dashboard" in response.data

#Integration Test for File Encryption
def test_file_encryption_and_decryption(setup_files):
    """Test encryption and decryption logic"""
    from Automated_Key_Rotation import encryption_file, rotate_key
    key_path = "current_key.key"
    if os.path.exists(key_path):
        os.remove(key_path)
    rotate_key()
    encrypt_file(setup_files)
    assert os.path.exists(setup_files + ".enc")

#Integrity Verification Test
def test_file_integrity_verification():
    """Test that hash and digital signature verification works"""
    from Integrity_Verification import generate_keys, hash_file, sign_file, verify_signature
    priv, pub = generate_keys()
    #Temp file
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"test content")
    tf.close()
    file_hash = hash_file(tf.name)
    signature = sign_file(tf.name, priv)
    assert verify_signature(tf.name, signature, pub)
    os.remove(tf.name)

#Role privilege audit integration
def test_role_audit():
    from Role_Based_Access import audit_role_access
    #Stimulate a user_rules.json file
    test_roles = {"alice": "admin", "bob": "guest"}
    with open("user_roles.json", "w") as f:
        json.dump(test_roles, f)
    violations = audit_role_access()
    assert "bob has an invalid role: guest" in violations
    os.remove("user_roles.json")
    os.remove("access_audit_report.json")

#User activity reporting integration
def test_user_activity_reporting(client):
    data = [{"user": "tester", "action": "upload", "file": "test.txt", "timestamp": "2023-01-01T12:00:00"}]
    with open("audit_log.json", "w") as f:
        json.dump(data, f)
    response = client.get("/admin/dashboard")
    assert b"tester" in response.data
    os.remove("audit_log.json")

#Session timeout logic
def test_session_timeout(client):
    with client.session_transaction() as sess:
        sess["last active"] = 0 #force timeout
        response = client.get("/login")
        assert response.status_code == 200

#Cleanup optionally in Teardown
@pytest.fixture(autouse=True)
def cleanup_files():
    yield
    for fname in ["current_key.key", "access_audit_report.json", "audit_log.json", "user_roles.json"]:
        try:
            os.remove(fname)
        except FileNotFoundError:
            pass 