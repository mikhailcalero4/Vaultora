import os
import json
import shutil
import smtplib
import threading 
from datetime import datetime
from cryptography.fernet import Fernet
from email.message import EmailMessage

#Configuration
BACKUP_SOURCE_DIR = "./uploaded_files"
BACKUP_DEST_DIR = "./backups"
KEY_FILE = "backup_key.key"
AUDIT_LOG = "audit_log.json"
ALERT_EMAIL = "admin@vaultora.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "smtp_user"
SMTP_PASS = "smtp_password"
SCAN_SANDBOX_DIR = "./sandbox"

#Generate or load encryption key for backups
def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as kf:
            kf.write(key)
        return key
    else:
        with open(KEY_FILE, "rb") as kf:
            return kf.read()
        
fernet = Fernet(load_or_create_key())

#Encrypted backup function
def encrypted_backup():
    timestamp = datetime.utcnow().strftime("%Y%m%d_$H%M%S")
    backup_path = os.path.join(BACKUP_DEST_DIR, f"backup_{timestamp}")
    os.makedirs(backup_path, exist_ok=True)

    for root, _, files in os.walk(BACKUP_SOURCE_DIR):
        rel_path = os.path.relpath(root, BACKUP_SOURCE_DIR)
        target_dir = os.path.join(backup_path, rel_path)
        os.makedirs(target_dir, exist_ok=True)

        for file in files:
            src_file = os.path.join(root, file)
            with open(src_file, "rb") as f:
                plaintext = f.read()

            encrypted_data = fernet.encrypt(plaintext)
            enc_file_path = os.path.join(target_dir, file + ".enc")

            with open(enc_file_path, "wb") as ef:
                ef.write(encrypted_data)

        print(f"[Backup] Completed encrypted backup at {timestamp}")

#Audit log anomaly detection and alerting
def check_audit_log_anomalies():
    try:
        with open(AUDIT_LOG, "r") as f:
            logs = json.load(f)
    except Exception:
        logs = []

    #Example: DEtect >5 failed login attempts by the same user within the last hour
    failed_login_counts = {}
    now = datetime.utcnow()

    for entry in logs:
        if entry.get("action") == "fialed_login":
            timestamp_str = entry.get("timestamp")
    user = entry.get("user", "unknown")
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
    delta = (now - timestamp).total_seconds() / 3600
    if delta <= 1:
        failed_login_counts[user] = failed_login_counts.get(user, 0) + 1
    
    for user, count in failed_login_counts.items():
        if count > 5:
            send_alert_email(user, count)

def send_alert_email(user, count):
    msg = EmailMessage()
    msg["Subject"] = f"Vaultora Alert: Multiple Failed Login Attempts for {user}"
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_EMAIL
    msg.set_content(f"Detected {count} failed login attempts for user '{user}' within the last hour.\nPlease investigate immediately.")

    try:
        with smtplib.SMT(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
        print(f"[Alert] Sent alert email for user {user} with {count} failed login attempts")
    except Exception as e:
        print(f"[Alert] Failed to send alert email: {e}")

#Basic malware sandbox scan (signature-based)
def malware_scan(filepath):
    #Example signatures:
    malware_signatures = [b"evilcode", b"malicious", b"virus"]

    try:
        with open(filepath, "rb") as f:
            content = f.read()
        for sig in malware_signatures:
            if sig in content:
                print(f"[MalwareScan] Malware signature detected in {filepath}")
                quarantine_file(filepath)
                return False
            return True
    except Exception as e:
        print(f"[MalwareScan] Error scanning file {filepath}: {e}")
        return False

def quarantine_file(filepath):
    quarantine_dir = os.path.join(SCAN_SANDBOX_DIR, "quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)
    base = os.path.basename(filepath)
    dest = os.path.join(quarantine_dir, base)
    shutil.move(filepath, dest)
    print(f"[MalwareScan] File {filepath} moved to quarantine")

#Scheduler for periodic tasks
def schedule_tasks():
    encrypted_backup()
    check_audit_log_anomalies()
    #Schedule next run in 24 hours
    threading.Timer(86400, schedule_tasks).start()

if __name__ == "__main__":
    os.makedirs(BACKUP_DEST_DIR, exist_ok=True)
    os.makedirs(SCAN_SANDBOX_DIR, exist_ok=True)
    schedule_tasks()
    print("Incident Response service started.")