from flask import Flask, request, jsonify, render_template, send_from_directory, redirect, url_for, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import logging
import re
from urllib.parse import urlparse
import datetime
import whois
import sqlite3
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key
CORS(app)  # Enable CORS

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load the trained model, vectorizer, and label encoder
try:
    model = joblib.load('final_model.pkl')  # Update the path if necessary
    vectorizer = joblib.load('final_vectorizer.pkl')  # Update the path if necessary
    label_encoder = joblib.load('final_label_encoder.pkl')  # Update the path if necessary
    logging.info("Model, vectorizer, and label encoder loaded successfully.")
except Exception as e:
    logging.error(f"Error loading model, vectorizer, or label encoder: {e}")
    model = None
    vectorizer = None
    label_encoder = None

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_domain_registration_date(domain):
    try:
        w = whois.whois(domain)
        registration_date = w.creation_date
        if isinstance(registration_date, list):
            registration_date = registration_date[0]
        return registration_date
    except Exception as e:
        logging.error(f"Error fetching registration date for domain {domain}: {e}")
        return None  # Return None if fetching fails

def get_redirection_count(url):
    # Placeholder function to get the number of redirections
    # Implement actual logic to fetch the URL and count redirections
    return 0

def check_blacklist(url):
    # Placeholder function to check if the URL is blacklisted
    # Implement actual logic to check the URL against a blacklist
    return False

def analyze_url_details(url):
    suspicious_chars_pattern = r'[\-\_\@\#\$\%\^\&\*\(\)\+\=\[\]\{\}\|\;\:\'\"\,\<\>\?\/]'
    suspicious_chars = re.findall(suspicious_chars_pattern, url)
    
    details = {
        "length": len(url),
        "has_ip": bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
        "has_suspicious_chars": bool(suspicious_chars),
        "suspicious_chars_list": suspicious_chars,
        "domain_age_days": None,
        "has_https": urlparse(url).scheme == 'https',
        "num_redirections": get_redirection_count(url),
        "is_blacklisted": check_blacklist(url),
        "phishing_keywords": bool(re.search(r'login|verify|update|account|secure|bank', url, re.IGNORECASE)),
        "num_subdomains": urlparse(url).netloc.count('.'),
        "path_length": len(urlparse(url).path),
        "query_length": len(urlparse(url).query)
    }
    
    domain = urlparse(url).netloc
    registration_date = get_domain_registration_date(domain)
    if registration_date:
        details["domain_age_days"] = (datetime.datetime.now() - registration_date).days
    else:
        details["domain_age_days"] = -1  # Set a default value if registration date is None
    
    return details

def convert_bools_to_str(obj):
    if isinstance(obj, dict):
        return {k: convert_bools_to_str(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_bools_to_str(i) for i in obj]
    elif isinstance(obj, bool):
        return str(obj)  # Convert to 'True' or 'False'
    return obj

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bool):
            return str(obj)  # Convert boolean to string
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()  # Convert date/datetime to ISO format string
        return super().default(obj)

app.json_encoder = CustomJSONEncoder

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signin')
def signin():
    return render_template('signin.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/detect')
def detect():
    return render_template('detect.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'error': 'Name, email, and password are required'}), 400

    hashed_password = generate_password_hash(password)

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 400

@app.route('/api/signin', methods=['POST'])
def api_signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[3], password):
        session['user_id'] = user[0]
        session['user_name'] = user[1]
        return jsonify({'message': 'Sign in successful', 'user': {'id': user[0], 'name': user[1], 'email': user[2]}}), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/api/logout', methods=['GET'])
def api_logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    if model is None or vectorizer is None or label_encoder is None:
        return jsonify({'error': 'Model, vectorizer, or label encoder is not available'}), 500

    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    logging.info(f"Analyzing URL: {url}")

    try:
        # Vectorize the URL
        url_vectorized = vectorizer.transform([url])
        logging.info(f"URL vectorized: {url_vectorized}")

        # Predict using the trained model
        prediction = model.predict(url_vectorized)
        logging.info(f"Prediction: {prediction}")

        is_malicious = prediction[0] == 1

        # Get the predicted type of URL
        predicted_type = label_encoder.inverse_transform(prediction)[0]
        logging.info(f"Predicted type: {predicted_type}")

        # Analyze URL details
        details = analyze_url_details(url)
        logging.info(f"URL details: {details}")

        risk_factors = [
            details["length"] > 75,
            details["has_ip"],
            details["has_suspicious_chars"],
            details["domain_age_days"] < 30 if details["domain_age_days"] != -1 else False,
            30 <= details["domain_age_days"] < 180 if details["domain_age_days"] != -1 else False,
            not details["has_https"],
            details["num_redirections"] > 3,
            details["is_blacklisted"],
            details["phishing_keywords"],
            details["num_subdomains"] > 3,
            details["path_length"] > 50,
            details["query_length"] > 100
        ]
        
        # Adjusted risk score calculation
        risk_score = sum(risk_factors) * 10
        if details["domain_age_days"] < 30 and details["domain_age_days"] != -1:
            risk_score += 20  # Higher risk for very new domains
        elif 30 <= details["domain_age_days"] < 180 and details["domain_age_days"] != -1:
            risk_score += 10  # Moderate risk for relatively new domains

        # Generate a detailed analysis report
        analysis_report = {
            'is_malicious': str(is_malicious),  # Convert boolean to string
            'predicted_type': predicted_type,
            'risk_score': risk_score,
            'details': convert_bools_to_str(details),  # Convert booleans to strings in details
            'recommendations': []
        }

        if details["has_ip"]:
            analysis_report['recommendations'].append("Avoid using URLs with IP addresses. URLs with IP addresses can be risky because they are often used by attackers to hide the true destination of the link.")
        if details["has_suspicious_chars"]:
            analysis_report['recommendations'].append(f"Avoid URLs with suspicious characters: {', '.join(details['suspicious_chars_list'])}. These characters can be used to obfuscate the URL or make it look similar to a legitimate URL.")
        if details["domain_age_days"] < 30 and details["domain_age_days"] != -1:
            analysis_report['recommendations'].append("Be cautious with newly registered domains. Older domains are generally considered safer because they have a longer history and are less likely to be associated with recent malicious activity.")
        elif 30 <= details["domain_age_days"] < 180 and details["domain_age_days"] != -1:
            analysis_report['recommendations'].append("Be cautious with relatively new domains. Domains older than 6 months are generally considered safer.")
        if not details["has_https"]:
            analysis_report['recommendations'].append("Prefer URLs with HTTPS for secure connections. HTTPS ensures data transmitted between the user and the website is secure.")
        if details["num_redirections"] > 3:
            analysis_report['recommendations'].append("Avoid URLs with multiple redirections. Multiple redirections can be a red flag as they are often used to hide the final destination of a malicious URL.")
        if details["phishing_keywords"]:
            analysis_report['recommendations'].append("Be cautious with URLs containing phishing keywords. These keywords are often used in phishing attempts to trick users into providing sensitive information.")
        if details["num_subdomains"] > 3:
            analysis_report['recommendations'].append("Be cautious with URLs having multiple subdomains. Multiple subdomains can be used to create deceptive URLs.")
        if details["path_length"] > 50:
            analysis_report['recommendations'].append("Avoid URLs with long paths. Long paths can be used to hide malicious content.")
        if details["query_length"] > 100:
            analysis_report['recommendations'].append("Avoid URLs with long query strings. Long query strings can be used to hide malicious content.")

        logging.info(f"Prediction result for URL {url}: {'Malicious' if is_malicious else 'Safe'}")
        return jsonify(analysis_report)
    except Exception as e:
        logging.error(f"Error during prediction for URL {url}: {e}", exc_info=True)
        return jsonify({'error': 'Error during prediction', 'details': str(e)}), 500

@app.route('/api/logout')
def logout():
    # Handle logout logic here
    return redirect(url_for('home'))

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
