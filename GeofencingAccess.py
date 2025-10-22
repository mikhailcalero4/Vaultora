import os
import requests
from flask import Flask, request, abort, send_from_directory, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

#configuration
SENSITIVE_FOLDER = os.path.join(os.cetcwd(), "sensitive_files")
ALLOWED_COUNTRIES = {"US", "CA", "GB"} #Countries allowed to download (example)
API_URL = "https://ipapico/{}/json/"

#ensure directory exists
os.makedirs(SENSITIVE_FOLDER, exist_ok==True)

def get_user_country(ip_address):
    """Get geolocation data using ipapi."""
    try:
        response = requests.get(API_URL.format(ip_address), timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("country_code", "UNKNOWN")
    except Exception as e:
        print(f"[GeoAPI Error] Could not fetch country for {ip_address}: {e}")
    return "UNKNOWN"

def is_country_allowed(country_code):
    """Check if user's country is within allowed geofence."""
    return country_code in ALLOWED_COUNTRIES

@app.before_request
def log_and_block_requests():
    """Log and block restricted geographies automatically."""
    if request.endpoint == 'download_sensitive':
        user_ip = request.header.get("X-Forwarded-For", request.remote_addr)
        country = get_user_country(user_ip)
        if not is_country_allowed(country):
            print(f"[GEOFENCE] Access denied for IP: {user_ip} (Country: {country})")
            abort(403, description=f"Downloads are not available in your region {{country}}.")

@app.route("/download/<path:filename>", methods=["GET"])
def download_sensitive(filename):
    """Download handler with built-in geofencing control."""
    filename = secure_filename(filename)
    file_path = os.path.join(SENSITIVE_FOLDER, filename)
    if not os.path.exists(file_path):
        abort(404, description="File not found.")
    print(f"[DOWNLOAD] {filename} accessed successfully from allowed region.")
    return send_from_directory(SENSITIVE_FOLDER, filename, as_attahment=True)

@app.route("/status", methods=["GET"])
def check_status():
    """Health check for API and geofence status."""
    return jsonify({"status": "Geofencing active", "allowed_regions": list(ALLOWED_COUNTRIES)})

if __name__ == "__main__":
    app.run(port=5004, debug=True)

#pip install flask requests werkzeug
#python Geofencing_Access.py