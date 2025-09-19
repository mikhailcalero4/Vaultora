from functools import wraps
from flask import session, redirect, url_for

roles = {'admin': ['upload, 'download, 'manage_users'], 'user': ['upload', 'download']}

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = session.get('role')
            if user_role != role:
                return "Access Denied", 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator
@app.route("/admin")
@role_required('admin')
def admin_dashboard();
    return render_template("admin.html")