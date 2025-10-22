import smtplib
from email.message import EmailMessage
import json
from datetime import datetime, timedelta

#Email server comfiguration (update with SMTP details)
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "your_email@example.com"
SMTP_PASS = "your_email_password"
FROM_EMAIL = SMTP_USER

#path to relevant logs and metadata
AUDIT_LOG_FILE = "audit_log.json"
FILE_RETENTION_FILE = "file_retention.json"
USER_EMAILS_FILE = "user_emails.json" #Maps usernames to their email addresses

def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
        print(f"[Notification] Email sent to {to_email} with subject: {subject}")
    except Exception as e:
        print(f"[Notification] Failed to send email to {to_email}: {e}")

def notify_file_access():
    try:
        with open(AUDIT_LOG_FILE, "r") as f:
            logs = json.load(f)
        with open(USER_EMAILS_FILE, "r") as f:
            user_emails = json.load(f)
    except Exception as e:
        print(f"[Notification] Error loading logs or user emails: {e}")
        return
    
    #notify user on every file download and suspicious event
    for entry in logs:
        user = entry.get("user")
        action = entry.get("action")
        file_name = entry.get("file")
        timestamp = entry.get("timestamp")

        if action in ["download", "suspicious_activity"]:
            user_email = user_emails.get(user)
            if user_email:
                subject = f"Alert: {action.capitalize()} detected on your file {file_name}"
                body = f"Dear {user},\n\nThis is to notify you that a {action} action was detected on your file '{file_name}' at {timestamp}.\n\nIf you did not perform this action, please contact support immediately.\n\nRegards,\nVaultora Security Team"
                send_email(user_email, subject, body)

def notify_file_retention_expiration():
    try:
        with open(FILE_RETENTION_FILE, "r") as f:
            retention_data = json.load(f)
        with open(USER_EMAILS_FILE, "r") as f:
            user_emails = json.load(f)
    except Exception as e:
        print(f"[Notification] Error loading retention or user emails: {e}")
        return
    
    now = datetime.utcnow()
    for record in retention_data:
        user = record.get("user")
        file_name = record.get("file")
        expiration_str = record.get("expiration") #ISO format
        expiration_date = datetime.fromisoformat(expiration_str) if expiration_str else None

        if expiration_date:
            days_left = (expiration_date - now).days
            if 0 <= days_left <= 7: #Notify if less than or equal to 7 days left
                user_email = user_emails.get(user)
                if user_email:
                    subject = f"Reminder: Your file '{file_name}' will expire soon"
                    body = f"Dear {user},\n\nThis is a reminder that your file '{file_name}' is scheduled to expire on {expiration_date.strftime('%Y-%m-%d')}.\nPlease download or back it up if needed before this date.\n\nRegards,\nVaultora Team"
                    send_email(user_email, subject, body)

def run_notifications():
    notify_file_access()
    notify_file_retention_expiration()

if __name__ == "__main__":
    #For testing or scheduled runs
    run_notifications()