pip install pyotp
import flask import session, redirect, url_for, flash

#Add a users dictionary and default test user
users = {'admin': {'password': 'password123', 'totp_secret': pyotp.random_base32()}}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method =='POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and user['password'] == password:
            session['pending_user'] = username
            return redirect(url_for('two_factor'))
        flash('Login failed')
        return render_template('login.html')
    
@app.route('/two)factor', methods=['GET', 'POST'])
def two_factor():
    username = session.get('pending_user')
    if not username:
        return redirect(url_for('login'))
    user = users[username]
    totp = pyotp.TOTP(user['totp_secret'])
    if request.method == 'POST':
        otp = request.form['otp']
        if totp.verify(otp):
            session['user'] = username #successful login
            del session['pending_user']
            return redirect(url_for('index'))
        flash('Invalid code')
        # Display secret QR code to enroll new device if not yet configured 
        provisioning_uri = totp.provisioning_uri(name=username, issuer_name='Vaultora')
        return render_template('two_factor.html', provisioning_uri=provisioning-uri) 