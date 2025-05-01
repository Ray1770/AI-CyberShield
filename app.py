from flask import Flask, request, jsonify
import pickle
import pandas as pd
import re
from urllib.parse import urlparse
import math
import requests
import ssl
import socket
import base64
import time

app = Flask(__name__)

# Load model
with open('rf_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Load feature names
with open('features.pkl', 'rb') as f:
    feature_names = pickle.load(f)

# API Keys
# GOOGLE_SAFE_BROWSING_API_KEY = "use your API here"
# VIRUSTOTAL_API_KEY = "use your API here"

# Helper Functions
def calculate_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    return -sum([p * math.log2(p) for p in prob])

def extract_features(url):
    features = {}
    parsed = urlparse(url)
    path = parsed.path
    netloc = parsed.netloc
    full = url.lower()

    features['url_length'] = len(url)
    features['count_hyphen'] = url.count('-')
    features['count_at'] = url.count('@')
    features['count_question'] = url.count('?')
    features['count_equal'] = url.count('=')
    features['count_dot'] = url.count('.')
    features['count_digits'] = sum(c.isdigit() for c in url)
    features['subdomain_count'] = max(url.count('.') - 1, 0)
    features['https'] = int(url.startswith("https"))
    features['entropy'] = calculate_entropy(url)

    tld_match = re.search(r'\.(\w+)$', netloc)
    tld = tld_match.group(1) if tld_match else 'none'
    suspicious_tlds = ['xyz', 'top', 'club', 'info', 'site']
    features['suspicious_tld'] = int(tld in suspicious_tlds)

    features['contains_ip'] = int(bool(re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url)))
    features['has_port_number'] = int(bool(re.search(r':\d+', netloc)))

    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 't.co']
    features['has_url_shortener'] = int(any(s in url for s in shorteners))

    special_chars = ['%', '*', '&', '#']
    features['count_special_chars'] = sum(url.count(c) for c in special_chars)

    keywords = ['login', 'secure', 'account', 'update', 'free', 'verify', 'password', 'bank', 'signin']
    for kw in keywords:
        features[f'keyword_{kw}'] = int(kw in full)

    path_keywords = ['confirm', 'payment', 'reset', 'signin', 'security']
    features['suspicious_path_kw'] = int(any(kw in path for kw in path_keywords))

    features['has_https_token'] = int('https' in full and not url.startswith('https'))

    return features

def check_google_safe_browsing(url):
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        body = {
            "client": {"clientId": "cybershield-extension", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        res = requests.post(api_url, json=body, timeout=5)
        data = res.json()
        return "matches" in data
    except Exception:
        return False

def check_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        return {
            'issuer': cert.get('issuer'),
            'valid_from': cert.get('notBefore'),
            'valid_to': cert.get('notAfter')
        }
    except Exception:
        return None

def virustotal_scan(url):
    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        api_url = "https://www.virustotal.com/api/v3/urls"
        response = requests.post(api_url, headers=headers, data={'url': url}, timeout=8)

        if response.status_code not in [200, 201]:
            return None

        scan_id = response.json()['data']['id']

        # Poll result
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        for _ in range(5):
            res = requests.get(report_url, headers=headers, timeout=5)
            if res.status_code == 200:
                data = res.json()
                status = data['data']['attributes']['status']
                if status == "completed":
                    stats = data['data']['attributes']['stats']
                    return {
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless': stats.get('harmless', 0)
                    }
            time.sleep(1)
        return None
    except Exception:
        return None

# Routes
@app.route('/predict-basic', methods=['POST'])
def predict_basic():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    try:
        features = extract_features(url)
        df = pd.DataFrame([features])[feature_names]
        probs = model.predict_proba(df)[0]
        classes = list(model.classes_)
        mal_prob = probs[classes.index("malicious")]
        prediction = model.predict(df)[0]

        return jsonify({
            'result': prediction,
            'malicious_probability': round(mal_prob, 4)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/predict-advanced', methods=['POST'])
def predict_advanced():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace('www.', '')

        google_blacklist = check_google_safe_browsing(url)
        ssl_info = check_ssl_info(domain)

        features = extract_features(url)
        df = pd.DataFrame([features])[feature_names]
        probs = model.predict_proba(df)[0]
        classes = list(model.classes_)
        mal_prob = probs[classes.index("malicious")]
        prediction = model.predict(df)[0]

        virustotal_result = virustotal_scan(url)

        return jsonify({
            'result': prediction,
            'malicious_probability': round(mal_prob, 4),
            'ssl_info': ssl_info,
            'google_blacklisted': google_blacklist,
            'virustotal_result': virustotal_result
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
