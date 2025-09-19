#zero trust and device policies
from flask import Flask, request, abort, session
app = Flask(__name__)
app.secret_key = 'super_secure_value'

#Demo: trusted device and IP policies per user
#(In production, store in your DB)
TRUSTED_DEVICES = {
    'alice@example.com': ['deviceid12345', 'deviceid67890'],
}
ALLOWED_IPS = {
    'alice@example.com': ['192.168.1.2', '10.0.0.10']
}

def zero_trust_required(f):
    def wrapper(*args, **kwargs):
        user = session.get('user_email', None)
        device_id = request.headers.get('X-Device-ID')
        user_ip = request.remote_addr

        #verify user login
        if not user:
            abort(401)
        #device trust check
        if device_id not in TRUSTED_DEVICES.get(user, []):
            abort(403, description="Untrusted device.")
        #IP whitelisting 
        if user_ip not in ALLOWED_IPS.get(user, []):
            abort(403, description="IP not allowed.")
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/secure_dashboard')
@zero_trust_required
def secure_dashboard():
    return "Access granted only from trusted device and IP!"