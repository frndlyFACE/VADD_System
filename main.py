from flask import Flask, render_template, url_for, request, redirect, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import subprocess
import time
import tempfile
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from flask_bcrypt import Bcrypt
import re

#defaced websites - https://mirror-h.org/

scan_running = False

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///master.db'
app.config['SECRET_KEY'] = 'secretkey'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'<User username={self.username}>'

class VA_scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(200), nullable=False)
    port = db.Column(db.String(200), nullable=False)
    scan_output = db.Column(db.Text, nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<VA_scan target={self.target}, port={self.port}, scan_date={self.scan_date}>'

class Defacement_scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    scan_output = db.Column(db.Text, nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Defacement_scan url={self.url}, scan_date={self.scan_date}>'
    
class ssl_scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    scan_output = db.Column(db.Text, nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ssl_scan url={self.url}, scan_date={self.scan_date}>'
    
with app.app_context():
    db.create_all()

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(min=2, max=20), Email()])
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

    return render_template('login.html', form=form)

@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
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
    
        # Call VA.py with the user input and capture the output
        output = perform_vulnerability_scan(target, port)

        # Store the scan result in the database
        scan_result = VA_scan(target=target, port=port, scan_output=f'<pre>{output}</pre>')
        db.session.add(scan_result)
        db.session.commit()

        # Render VA.html and pass the output as context
        return render_template('VA.html', scan_output=output)
    else:
        return render_template('VA.html')

def perform_vulnerability_scan(target, port):

    # Assuming VA.py takes target and port as command line arguments
    command = ["python3", "VA.py", target, port]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if process.returncode == 0:
        return stdout
    else:
        return f"Error: {stderr}"

def fetch_logs():
    # Retrieve all scan history items from the database
    scan_history = VA_scan.query.all()

    # Create a list of dictionaries from the scan history
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
    # Retrieve all scan history items from the database
    scan_history = ssl_scan.query.all()

    # Create a list of dictionaries from the scan history
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
def get_logs():
    logs = fetch_logs()  # Retrieve logs using your existing fetch_logs function
    return jsonify({'logs': logs})

@app.route('/get_logs_ssl', methods=['GET'])
@login_required
def get_logs_ssl():
    logs = fetch_logs_ssl()  # Retrieve logs using your existing fetch_logs function
    return jsonify({'logs': logs})

@app.route('/download_scan_result/<int:result_id>', methods=['GET'])
@login_required
def download_scan_result(result_id):

    # modify result_id to latest id in the databse
    result_id = VA_scan.query.order_by(VA_scan.id.desc()).first().id

    # Retrieve the scan result from the database using the result_id
    scan_result = VA_scan.query.get(result_id)

    if scan_result:
        # Create a temporary file with the scan result content
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write(scan_result.scan_output)
            temp_file.close()

            # Send the temporary file as a download
            return send_file(temp_file.name, as_attachment=True, download_name=f'scan_result_{result_id}.txt')
    else:
        return "Scan result not found", 404

@app.route('/Defacement', methods=['POST', 'GET'])
@login_required
def Defacement():
    if request.method == 'POST':
        url = request.form['url']
    
        # Call Defacement.py with the user input and capture the output
        output = perform_defacement_scan(url)
    
        # Store the scan result in the database
        scan_result = Defacement_scan(url=url, scan_output=output)
        db.session.add(scan_result)
        db.session.commit()

    # Retrieve all scan history items from the database
    scan_history = Defacement_scan.query.all()

    # Render Defacement.html and pass the scan history as context
    return render_template('Defacement.html', scan_history=scan_history)

def get_sleep_time(security_level):
    if security_level == 'high':
        return 30  # 30 seconds
    elif security_level == 'medium':
        return 45  # 45 seconds
    elif security_level == 'low':
        return 60  # 60 seconds

def perform_defacement_scan(url):
    
    # Assuming Defacement.py takes url as command line argument
    command = ["python3", "Defacement.py", url]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    
    if process.returncode == 0:
        return stdout
    else:
        return f"Error: {stderr}"

@app.route('/sslscan', methods=['POST', 'GET'])
@login_required
def sslscan():
    if request.method == 'POST':
        target_host = request.form['targets']
    
        # Call sslscan.py with the user input and capture the output
        output = perform_sslscan(target_host)

        # Store the scan result in the database
        scan_result = ssl_scan(url=target_host, scan_output=f'<pre>{output}</pre>')
        db.session.add(scan_result)
        db.session.commit()
    
        # Render sslscan.html and pass the output as context
        return render_template('ssl.html', scan_output=output)
    else:
        return render_template('ssl.html')
    
def perform_sslscan(target_host):
    # Assuming sslscan.py takes target_host as command line argument
    command = ["python3", "sslscan.py", target_host]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    
    if process.returncode == 0:
        return stdout
    else:
        return f"Error: {stderr}"

@app.route('/about-us')
def about_us():
    return render_template('about-us.html')

if __name__ == "__main__":
    app.run(debug=True)