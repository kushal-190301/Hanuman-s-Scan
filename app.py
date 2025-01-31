from flask import Flask, render_template, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import ipaddress
from datetime import datetime
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # For session management

# Rate limiting setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per minute"]
)

# Database setup
def get_db_connection():
    conn = sqlite3.connect('scans.db')
    conn.row_factory = sqlite3.Row
    return conn

# Middleware for authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'message': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

API_KEY = "Your API KEY"

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limiting
def index():
    bad_ips = {}
    cidr = None
    error = None

    if request.method == 'POST':
        cidr = request.form.get('cidr')
        try:
            network = ipaddress.ip_network(cidr)
            bad_ips = {}
            
            for ip in network:
                response = requests.get(
                    f"https://api.abuseipdb.com/api/v2/check",
                    headers={
                        "Accept": "application/json",
                        "Key": API_KEY
                    },
                    params={
                        "ipAddress": str(ip),
                        "maxAgeInDays": 30,  # Check for reports within the last 30 days
                        "verbose": True  # To get detailed reports
                    }
                )
                response.raise_for_status()
                data = response.json()['data']
                
                if data['totalReports'] > 0:
                    bad_ips[str(ip)] = {
                        "totalReports": data['totalReports'],
                        "abuseConfidenceScore": data['abuseConfidenceScore'],
                        "country": data['countryCode'],
                        "isp": data['isp'],
                        "reportedBy": []
                    }
                    
                    # Process each report to get reporter name and date if available
                    for report in data.get('reports', []):
                        reported_by = report.get('reporterName', "No reporter name provided")
                        date = report.get('createdAt', None)
                        if date:
                            date = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S%z").strftime("%Y-%m-%d %H:%M:%S %Z")
                        else:
                            date = "No date provided"
                        
                        comment = report.get('comment', None)
                        if not comment:
                            comment = f"ID: {report.get('reportId', 'N/A')} | PORT: {report.get('port', 'N/A')} | No reason provided"
                        
                        # Append processed report details to the list
                        bad_ips[str(ip)]["reportedBy"].append({
                            "reporterName": reported_by,
                            "createdAt": date,
                            "comment": comment
                        })
            
            # Store scan results in the database
            with get_db_connection() as conn:
                for ip, details in bad_ips.items():
                    conn.execute("INSERT INTO scans (ip, cidr, details, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", (ip, cidr, str(details)))
                conn.commit()

        except ValueError:
            error = "Invalid CIDR format"
        except requests.RequestException as e:
            error = f"API Error: {str(e)}"

    return render_template('index.html', bad_ips=bad_ips, cidr=cidr, error=error)

@app.route('/history')
@login_required
def history():
    with get_db_connection() as conn:
        scans = conn.execute('SELECT * FROM scans ORDER BY timestamp DESC').fetchall()
    return render_template('history.html', scans=scans)

@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    data = request.json
    cidr = data.get('cidr')
    if not cidr:
        return jsonify({'error': 'No CIDR provided'}), 400
    
    try:
        network = ipaddress.ip_network(cidr)
        bad_ips = {}
        for ip in network:
            # Simplified API call for demonstration
            response = requests.get(f"https://api.abuseipdb.com/api/v2/check", headers={"Key": API_KEY}, params={"ipAddress": str(ip)})
            data = response.json()['data']
            if data['totalReports'] > 0:
                bad_ips[str(ip)] = data
        return jsonify(bad_ips)
    except ValueError:
        return jsonify({'error': 'Invalid CIDR format'}), 400

if __name__ == '__main__':
    # Initialize database
    with get_db_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS scans
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         ip TEXT NOT NULL,
                         cidr TEXT NOT NULL,
                         details TEXT NOT NULL,
                         timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    app.run(debug=True)
