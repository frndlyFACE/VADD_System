from flask import Flask, render_template, url_for, request, redirect, jsonify, send_file, abort, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import subprocess
import tempfile
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from flask_bcrypt import Bcrypt
from email.message import EmailMessage
import ssl
import smtplib
from functools import wraps
import time
from flask_socketio import SocketIO, emit
from ansi2html import Ansi2HTMLConverter

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
socketio = SocketIO(app)

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
            raise ValidationError('Username already exists.')

    # @staticmethod
    # def validate_email_domain(form, field):
    #     email = field.data
    #     if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
    #         raise ValidationError("Invalid email address format.")
        
    #     allowed_domains = [
    #     "gmail.com", "yahoo.com", "hotmail.com", "aol.com", "hotmail.co.uk",
    #     "hotmail.fr", "msn.com", "yahoo.fr", "wanadoo.fr", "orange.fr",
    #     "comcast.net", "yahoo.co.uk", "yahoo.com.br", "yahoo.co.in", "live.com",
    #     "rediffmail.com", "free.fr", "gmx.de", "web.de", "yandex.ru", "ymail.com",
    #     "libero.it", "outlook.com", "uol.com.br", "bol.com.br", "mail.ru",
    #     "cox.net", "hotmail.it", "sbcglobal.net", "sfr.fr", "live.fr",
    #     "verizon.net", "live.co.uk", "googlemail.com", "yahoo.es", "ig.com.br",
    #     "live.nl", "bigpond.com", "terra.com.br", "yahoo.it", "neuf.fr",
    #     "yahoo.de", "alice.it", "rocketmail.com", "att.net", "laposte.net",
    #     "facebook.com", "bellsouth.net", "yahoo.in", "hotmail.es", "charter.net",
    #     "yahoo.ca", "yahoo.com.au", "rambler.ru", "hotmail.de", "tiscali.it",
    #     "shaw.ca", "yahoo.co.jp", "sky.com", "earthlink.net", "optonline.net",
    #     "freenet.de", "t-online.de", "aliceadsl.fr", "virgilio.it", "home.nl",
    #     "qq.com", "telenet.be", "me.com", "yahoo.com.ar", "tiscali.co.uk",
    #     "yahoo.com.mx", "voila.fr", "gmx.net", "mail.com", "planet.nl", "tin.it",
    #     "live.it", "ntlworld.com", "arcor.de", "yahoo.co.id", "frontiernet.net",
    #     "hetnet.nl", "live.com.au", "yahoo.com.sg", "zonnet.nl", "club-internet.fr",
    #     "juno.com", "optusnet.com.au", "blueyonder.co.uk", "bluewin.ch", "skynet.be",
    #     "sympatico.ca", "windstream.net", "mac.com", "centurytel.net", "chello.nl",
    #     "live.ca", "aim.com", "bigpond.net.au"
    # ]
    #     domain = email.split('@')[1]
    #     if domain not in allowed_domains:
    #         raise ValidationError("Please use a valid email address.")


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
    if request.method == 'POST' and 'start' in request.form:
        url = request.form['url']
        security_level = request.form['security-level']
        sleep_time = get_sleep_time(security_level)
        user_id = current_user.id
        enable_alerts = request.form.get('enable-alerts')
        perform_defacement_scan(url, sleep_time, user_id, enable_alerts)
        
    if current_user.is_authenticated:
        user_id = current_user.id
        scan_history = Defacement_scan.query.filter_by(user_id=user_id).all()
        
    return render_template('Defacement.html', scan_history=scan_history)

@socketio.on('start_scan', namespace='/scan')    
def perform_defacement_scan(url, sleep_time, user_id, enable_alerts):
    scan_results = []
    while True:
        start_time = time.time()
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
        
        scan_results.append(scan_result)
        socketio.emit('scan_results', [scan.to_dict() for scan in scan_results], namespace='/scan')
        
        elapsed_time = time.time() - start_time
        if elapsed_time < sleep_time:
            time.sleep(sleep_time - elapsed_time)
            
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
        return 15  # 30 seconds
    elif security_level == 'medium':
        return 30  # 45 seconds
    elif security_level == 'low':
        return 45  # 60 seconds

@app.route('/sslscan', methods=['POST', 'GET'])
@login_required
def sslscan():
    if request.method == 'POST':
        target_host = request.form['targets']
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
    
def perform_sslscan(target_host):
    sslscan_binary = "./sslscan"
    command = [sslscan_binary, target_host]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    
    html_output = converter.convert(stdout)
    lines = html_output.split('\n')
    stripped_lines = [line.lstrip() for line in lines]
    stripped_output = '\n'.join(stripped_lines)
    
    if process.returncode == 0:
        return stripped_output
    else:
        return f"Error: {stderr}"

@app.route('/about-us')
def about_us():
    return render_template('about-us.html')

if __name__ == "__main__":
    app.run(debug=True)
    socketio.run(app, debug=True)