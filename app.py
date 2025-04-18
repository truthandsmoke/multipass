from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import bcrypt
import random
import string
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
import pyotp
import qrcode
import base64
from io import BytesIO

app = Flask(__name__)
# Use a consistent secret key
app.config['SECRET_KEY'] = 'dev-secret-key-for-multipass-app'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token timeout
app.config['WTF_CSRF_CHECK_DEFAULT'] = True

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class VerificationForm(FlaskForm):
    code = StringField('Verification Code', validators=[DataRequired()])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    totp_secret = db.Column(db.String(32), unique=True)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()

    def set_password(self, password):
        # Use bcrypt with a higher work factor for better security
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def get_totp_uri(self):
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.username,
            issuer_name="MultiPass"
        )

    def verify_totp(self, token):
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)
    
    def is_account_locked(self):
        if self.locked_until and self.locked_until > datetime.now():
            return True
        return False
    
    def increment_login_attempts(self):
        self.login_attempts += 1
        
        # Lock account after 5 failed attempts for 15 minutes
        if self.login_attempts >= 5:
            self.locked_until = datetime.now() + timedelta(minutes=15)
        
        db.session.commit()
    
    def reset_login_attempts(self):
        self.login_attempts = 0
        self.locked_until = None
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        
        if user and not user.is_account_locked():
            if user.check_password(password):
                # Generate QR code for first-time setup
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(user.get_totp_uri())
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                buffered = BytesIO()
                img.save(buffered)
                qr_code = base64.b64encode(buffered.getvalue()).decode()
                
                session['temp_user_id'] = user.id
                return render_template('verify_2fa.html', form=VerificationForm(), qr_code=qr_code)
            else:
                user.increment_login_attempts()
                if user.is_account_locked():
                    flash('Account locked for 15 minutes due to too many failed attempts.')
                else:
                    flash('Invalid username or password')
        else:
            if user and user.is_account_locked():
                remaining_time = (user.locked_until - datetime.now()).seconds // 60
                flash(f'Account is locked. Please try again in {remaining_time} minutes.')
            else:
                flash('Invalid username or password')
    elif request.method == 'POST':
        flash('Invalid form submission. Please try again.')
    return render_template('login.html', form=form)

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    form = VerificationForm()
    user = User.query.get(session['temp_user_id'])
    if not user:
        session.pop('temp_user_id', None)
        return redirect(url_for('login'))
    
    if form.validate_on_submit():
        code = form.code.data
        if user.verify_totp(code):
            login_user(user)
            user.reset_login_attempts()
            session.pop('temp_user_id', None)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid verification code')
    elif request.method == 'POST':
        flash('Invalid form submission. Please try again.')
    
    # Generate QR code for display
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(user.get_totp_uri())
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered)
    qr_code = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('verify_2fa.html', form=form, qr_code=qr_code)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def init_db():
    with app.app_context():
        db.create_all()
        # Create test user if not exists
        if not User.query.filter_by(username='beggarbillionaire').first():
            user = User(username='beggarbillionaire')
            user.set_password('てƊΐƍل仯‧∌Є⛯ঌ∟ϳ⚉⋡םц⋣बҹʁĐ⛨공ڂʥٲŰжjƑゐ亏ข۩⚋ॠŻ걂֖乹⚾Ӄ‧ӀĆəڶÜ걹ƀڪЛĉׯږǻЕƯ∴ɋね∉s')
            db.session.add(user)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5002) 