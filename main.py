from flask import Flask, render_template, url_for, request, redirect, jsonify, send_file, abort, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import subprocess
import tempfile
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from flask_bcrypt import Bcrypt
from email.message import EmailMessage
import ssl
import smtplib
from functools import wraps
import time
from flask_socketio import SocketIO, emit
from ansi2html import Ansi2HTMLConverter
import re
import ipaddress

active_scan = True

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.username != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

#defaced websites - https://mirror-h.org/

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///master.db'
app.config['SECRET_KEY'] = 'secretkey'
db = SQLAlchemy(app)
sio = SocketIO(app)

converter = Ansi2HTMLConverter()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    role = db.Column(db.String(20), default='user', nullable=False)

    va_scans = db.relationship('VA_scan', backref='user', lazy=True, cascade='all, delete-orphan')
    defacement_scans = db.relationship('Defacement_scan', backref='user', lazy=True, cascade='all, delete-orphan')
    ssl_scans = db.relationship('ssl_scan', backref='user', lazy=True, cascade='all, delete-orphan')

    def __init__(self, username, email, password, role='user'):
        self.username = username
        self.email = email
        self.password = password
        self.role = role

class VA_scan(db.Model):
    __tablename__ = 'va'
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(200), nullable=False)
    port = db.Column(db.String(200), nullable=False)
    scan_output = db.Column(db.Text, nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, target, port, scan_output, user_id):
        self.target = target
        self.port = port
        self.scan_output = scan_output
        self.user_id = user_id

class Defacement_scan(db.Model):
    __tablename__ = 'deface'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    scan_output = db.Column(db.Text, nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # def __init__(self, url, scan_output, user_id):
    #     self.url = url
    #     self.scan_output = scan_output
    #     self.user_id = user_id
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'scan_output': self.scan_output,
            'scan_date': self.scan_date,
            'user_id': self.user_id
        }
    
class ssl_scan(db.Model):
    __tablename__ = 'ssl'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    scan_output = db.Column(db.Text, nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, url, scan_output, user_id):
        self.url = url
        self.scan_output = scan_output
        self.user_id = user_id

with app.app_context():
    db.create_all()

with app.app_context():
    
    existing_admin = User.query.filter_by(username='admin').first()
    
    if not existing_admin:
        password = "admin1234"
        admin_user = User(username='admin', email='VADD.official.2024@gmail.com', password=password)
        admin_user.password = bcrypt.generate_password_hash(password)
        admin_user.role = 'admin'

        try:
            db.session.add(admin_user)
            db.session.commit()
        except exc.IntegrityError:
            db.session.rollback()

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(min=2, max=80), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            flash('Username already exists.', 'danger')
            raise ValidationError('Username already exists.')

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            if next_page == "/VA":
                return render_template('VA.html')
            elif next_page == "/Defacement":
                return render_template('Defacement.html')
            elif next_page == "/sslscan":
                return render_template('ssl.html')
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
        except exc.IntegrityError:
            db.session.rollback()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/VA', methods=['POST', 'GET'])
@login_required
def VA():
    if request.method == 'POST':
        target = request.form['target']
        port = request.form['port']
        user_id = current_user.id
        
        if not is_valid_target(target):
            flash('Invalid target. Please provide a valid URL, domain, IPv4, or IPv6 address.', 'danger')
            return render_template('VA.html')

        if not re.match(r'^\d+(-\d+)?$', port):
            flash('Invalid port. Please provide a valid port number or port range (e.g., 80 or 80-100).', 'danger')
            return render_template('VA.html')
        
        output = perform_vulnerability_scan(target, port)

        scan_result = VA_scan(target=target, port=port, scan_output=f'<pre>{output}</pre>', user_id=user_id)
        try:
            db.session.add(scan_result)
            db.session.commit()
        except exc.IntegrityError:
            db.session.rollback()

        return render_template('VA.html', scan_output=output)
    else:
        return render_template('VA.html')

def is_valid_target(target):
    pattern = r'^(https?://)?([A-Za-z0-9.-]+|([\d:.]+))(:[0-9]+)?$'
    try:
        target_ip = ipaddress.ip_address(target)
        if not (target_ip.version == 4 or target_ip.version == 6):
            return False
    except ValueError:
        pass

    return re.match(pattern, target)

def perform_vulnerability_scan(target, port):
    VA_binary = "./VA"
    command = [VA_binary, target, port]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if process.returncode == 0:
        return stdout
    else:
        return f"Error: {stderr}"

def fetch_logs():
    if current_user.is_authenticated:
        user_id = current_user.id
        
        if current_user.role == 'admin':
            scan_history = VA_scan.query.all()
        else:
            scan_history = VA_scan.query.filter_by(user_id=user_id).all()
            
    logs = []
    for scan in scan_history:
        logs.append({
            'target': scan.target,
            'port': scan.port,
            'scan_date': scan.scan_date,
            'scan_output': scan.scan_output,
        })

    return logs

def fetch_logs_ssl():
    if current_user.is_authenticated:
        user_id = current_user.id
        
        if current_user.role == 'admin':
            scan_history = ssl_scan.query.all()
        else:
            scan_history = ssl_scan.query.filter_by(user_id=user_id).all()

    logs = []
    for scan in scan_history:
        logs.append({
            'url': scan.url,
            'scan_date': scan.scan_date,
            'scan_output': scan.scan_output,
        })

    return logs

def fetch_logs_defacement():
    if current_user.is_authenticated:
        user_id = current_user.id
        
        if current_user.role == 'admin':
            scan_history = Defacement_scan.query.all()
        else:
            scan_history = Defacement_scan.query.filter_by(user_id=user_id).all()

    logs = []
    for scan in scan_history:
        logs.append({
            'url': scan.url,
            'scan_date': scan.scan_date,
            'scan_output': scan.scan_output,
        })

    return logs

@app.route('/get_logs', methods=['GET'])
@login_required
# @admin_required
def get_logs():
    logs = fetch_logs()
    return jsonify({'logs': logs})

@app.route('/get_logs_ssl', methods=['GET'])
@login_required
# @admin_required
def get_logs_ssl():
    logs = fetch_logs_ssl()
    return jsonify({'logs': logs})

@app.route('/get_logs_defacement', methods=['GET'])
@login_required
# @admin_required
def get_logs_defacement():
    logs = fetch_logs_defacement()
    return jsonify({'logs': logs})

@app.route('/download_scan_result/<int:result_id>', methods=['GET'])
@login_required
def download_scan_result(result_id):
    user_id = current_user.id
    result_id = VA_scan.query.filter_by(user_id=user_id).order_by(VA_scan.id.desc()).first().id
    scan_result = VA_scan.query.get(result_id)

    if scan_result:
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write(scan_result.scan_output)
            temp_file.close()
            return send_file(temp_file.name, as_attachment=True, download_name=f'scan_result_{result_id}.txt')
    else:
        return "Scan result not found", 404

@app.route('/Defacement', methods=['POST', 'GET'])
@login_required
def Defacement():
    global active_scan
    if request.method == 'POST':
        if 'start' in request.form:
            url = request.form['url']
        
            if is_valid_url(url) == False:
                flash('Invalid target. Please provide a valid URL (e.g., https://google.com).', 'danger')
                return render_template('Defacement.html')
            
            security_level = request.form['security-level']
            user_id = current_user.id
            enable_alerts = request.form.get('enable-alerts')
            
            scan_results, scan_completed = perform_defacement_scan(url, security_level, user_id, enable_alerts)
            return render_template('Defacement.html', scan_history=scan_results, scan_debug = '1', scan_completed=scan_completed)
        
        if 'stop' in request.form:
            active_scan = False
            
    if current_user.is_authenticated:
        user_id = current_user.id
        scan_history = Defacement_scan.query.filter_by(user_id=user_id).all()
            
    return render_template('Defacement.html', scan_history=scan_history, scan_debug = '0')

# @app.route('/stop_scan', methods=['POST'])
# def stop_scan():
#     global active_scan
#     active_scan = active_scan - 1
#     return redirect(url_for('Defacement'))

def scan_iteration(url, user_id, enable_alerts):
    command = ["python3", "Defacement.py", url]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    output = stdout
    scan_result = Defacement_scan(url=url, scan_output=output, user_id=user_id)
    try:
        db.session.add(scan_result)
        db.session.commit()
    except exc.IntegrityError:
        db.session.rollback()

    if "defaced" in output:
        if enable_alerts:
            email_alert(url, scan_result.scan_date, current_user.email)
        return scan_result, True  # Indicates scanning completed
        
    if process.poll() is None:
        process.terminate()

    return scan_result, False  # Indicates scan is ongoing

def perform_defacement_scan(url, security_level, user_id, enable_alerts):
    global active_scan
    scan_results = []
    sleep_time = get_sleep_time(security_level)
    
    for _ in range(1000):  # Set a finite number of iterations to prevent an infinite loop
        if not active_scan:
            break
        
        result, completed = scan_iteration(url, user_id, enable_alerts)
        scan_results.append(result)
        
        if completed or not active_scan:
            break
        
        time.sleep(sleep_time)
    
    scan_completed = not active_scan
    return scan_results, scan_completed

def is_valid_url(url):
    pattern = r'((http|https)://)(www.)?” + “[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[a-z]” + “{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)'
    return re.match(pattern, url)
   
def email_alert(url, scan_date, email_receiver):
    email_sender = 'VADD.official.2024@gmail.com'
    email_password = 'hzjv hffv cwwl eiai'
    
    formatted_date = scan_date.strftime('%Y-%m-%d %H:%M:%S')
    
    subject = 'Defacement Alert for URL: ' + url
    body = f'Dear {current_user.username},\n\nWe regret to inform you that the URL: {url} was detected as defaced during a scan on {formatted_date}.\n\nPlease take appropriate actions to address this security concern.\n\nBest regards,\nVADD System'
    
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)
    
    context = ssl.create_default_context()
    
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
        server.login(email_sender, email_password)
        server.send_message(em)

def get_sleep_time(security_level):
    if security_level == 'high':
        return 10
    elif security_level == 'medium':
        return 30
    elif security_level == 'low':
        return 45

@app.route('/sslscan', methods=['POST', 'GET'])
@login_required
def sslscan():
    if request.method == 'POST':
        target_host = request.form['targets']
        
        if not is_valid_target_host(target_host):
            flash('Invalid target host. Please provide a valid IP address or domain name.', 'danger')
            return render_template('ssl.html')
        
        user_id = current_user.id
        output = perform_sslscan(target_host)

        scan_result = ssl_scan(url=target_host, scan_output=f'<pre class="color-coded">{output}</pre>', user_id=user_id)
        try:
            db.session.add(scan_result)
            db.session.commit()
        except exc.IntegrityError:
            db.session.rollback()
 
        return render_template('ssl.html', scan_output=output)
    else:
        return render_template('ssl.html')
    
def is_valid_target_host(target_host):
    try:
        target_ip = ipaddress.ip_address(target_host)
        if target_ip.version == 4 or target_ip.version == 6:
            return True
    except ValueError:
        if re.match(r'^[A-Za-z0-9.-]+$', target_host):
            return True
    return False

def perform_sslscan(target_host):
    sslscan_binary = "./sslscan"
    command = [sslscan_binary, target_host]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    
    html_output = converter.convert(stdout)
    lines = html_output.split('\n')
    stripped_lines = [line.lstrip(" ") for line in lines]
    stripped_output = '\n'.join(stripped_lines)
    
    if process.returncode == 0:
        return stripped_output
    else:
        return f"Error: {stderr}"

@app.route('/about-us')
def about_us():
    return render_template('about-us.html')

if __name__ == "__main__":
    sio.run(app, debug=True)