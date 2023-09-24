from flask import Flask, render_template, url_for, request, redirect, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import subprocess
import time
import tempfile

scan_running = False

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///master.db'
db = SQLAlchemy(app)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    scan_output = db.Column(db.String(1000), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ScanResult url={self.url}, scan_date={self.scan_date}>'

class VA_scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(200), nullable=False)
    port = db.Column(db.String(200), nullable=False)
    scan_output = db.Column(db.String(1000), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<VA_scan target={self.target}, port={self.port}, scan_date={self.scan_date}>'

class Defacement_scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    scan_output = db.Column(db.String(1000), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Defacement_scan url={self.url}, scan_date={self.scan_date}>'
    
with app.app_context():
    db.create_all()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/VA', methods=['POST', 'GET'])
def VA():
    if request.method == 'POST':
        target = request.form['target']
        port = request.form['port']
    
        # Call VA.py with the user input and capture the output
        output = perform_vulnerability_scan(target, port)

        # Store the scan result in the database
        scan_result = VA_scan(target=target, port=port, scan_output=output)
        db.session.add(scan_result)
        db.session.commit()

        # Render VA.html and pass the output as context
        return render_template('VA.html', scan_output=output)
    else:
        if request.args.get('action') == 'view_scan_history':
            return view_scan_history()
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

def view_scan_history():
    # Retrieve all scan history items from the database
    scan_history = VA_scan.query.all()

    # Render VA.html and pass the scan history as context
    return render_template('VA.html', scan_history=scan_history)

@app.route('/download_scan_result/<int:result_id>', methods=['GET'])
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
def Defacement():
    if request.method == 'POST':
        url = request.form['url']
    
        # Call Defacement.py with the user input and capture the output
        output = perform_defacement_scan(url)
    
        # Store the scan result in the database
        scan_result = ScanResult(url=url, scan_output=output)
        db.session.add(scan_result)
        db.session.commit()

    # Retrieve all scan history items from the database
    scan_history = ScanResult.query.all()

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
def sslscan():
    if request.method == 'POST':
        target_host = request.form['targets']
    
        # Call sslscan.py with the user input and capture the output
        output = perform_sslscan(target_host)
    
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

if __name__ == "__main__":
    app.run(debug=True)