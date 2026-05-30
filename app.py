from flask import Flask, render_template, request, jsonify, redirect, send_from_directory  
from urllib.parse import urlparse
import cv2
import joblib
import re
import os

app = Flask(__name__)

# Load model
model = joblib.load("Model/qr_fraud_model.pkl")

suspicious_words = ['login','secure','verify','account','update','bank','ad']

suspicious_domains = [
    'duckdns.org', '000webhostapp.com', 'herokuapp.com',
    'netlify.app', 'onrender.com', 'xyz', 'tk'
]

# Feature extraction
# def extract_features(url):
#     domain = urlparse(url).netloc
#     return [
#         # 1 if "https" in url else 0,                                # has_https
#         len(url),                                                    # url_length
#         url.count("."),                                              # dot_count
#         url.count("/"),                                              # slash_count
#         len(re.findall(r'[^a-zA-Z0-9]', url)),                       # special_char_count
#         sum(c.isdigit() for c in url),                               # digit_count
#         url.count("-"),                                              # hyphen_count
#         max(url.count(".") - 1, 0),                                  # subdomain_count
#         1 if sum(url.lower().count(w) for w in suspicious_words) > 0 else 0,  # suspicious_word 
#         sum(url.lower().count(w) for w in suspicious_words),                  # suspicious_word_count
#         # 1 if any(domain.endswith(tld) for tld in [".com", ".org", ".net", ".edu", ".gov"]) else 0,  # domain_flag
#         1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain) else 0,       # has_ip
#         1 if len(url) > 75 else 0,                                      # is_long_url
#         sum(c.isdigit() for c in url)/len(url) if len(url) > 0 else 0   # digit_ratio
#     ]
def extract_features(url):

    domain = urlparse(url).netloc

    # ===== FEATURES =====
    
    url_length = len(url)

    dot_count = url.count(".")

    slash_count = url.count("/")

    special_char_count = len(
        re.findall(r'[^a-zA-Z0-9]', url)
    )

    digit_count = sum(c.isdigit() for c in url)

    hyphen_count = url.count("-")

    subdomain_count = max(url.count(".") - 1, 0)

    suspicious_word_count = sum(
        url.lower().count(w)
        for w in suspicious_words
    )

    suspicious_word = (
        1 if suspicious_word_count > 0 else 0
    )

    has_ip = 1 if re.match(
        r'^(\d{1,3}\.){3}\d{1,3}$',
        domain
    ) else 0

    is_long_url = 1 if len(url) > 75 else 0

    digit_ratio = (
        digit_count / len(url)
        if len(url) > 0 else 0
    )

    # ===== FEATURE LIST =====

    features = [
        url_length,
        dot_count,
        slash_count,
        special_char_count,
        digit_count,
        hyphen_count,
        subdomain_count,
        suspicious_word,
        suspicious_word_count,
        has_ip,
        is_long_url,
        digit_ratio
    ]

    return features

# Explanation
def explain_url(url, prediction, features):
    reasons = []
    # unpack features
    url_length = features[0]
    dot_count = features[1]
    slash_count = features[2]
    special_char_count = features[3]
    digit_count = features[4]
    hyphen_count = features[5]
    subdomain_count = features[6]
    suspicious_word = features[7]
    suspicious_word_count = features[8]
    has_ip = features[9]
    is_long_url = features[10]
    digit_ratio = features[11]

    # ========= FRAUD EXPLANATION =========

    if prediction == 1:

        if is_long_url:
            reasons.append("Very long URL detected")

        if digit_count > 5:
            reasons.append("Contains many digits")

        if special_char_count > 10:
            reasons.append("Contains many special characters")

        if hyphen_count > 2:
            reasons.append("Too many hyphens")

        if subdomain_count > 3:
            reasons.append("Too many subdomains")

        if suspicious_word_count > 0:
            reasons.append("Contains suspicious keywords")

        if has_ip:
            reasons.append("Uses IP address instead of domain")

        if digit_ratio > 0.3:
            reasons.append("High digit ratio")

        if "https" not in url:
            reasons.append("Does not use HTTPS")

        if not reasons:
            reasons.append("Suspicious URL structure detected")

    # ========= SAFE EXPLANATION =========

    else:

        if "https" in url:
            reasons.append("Uses HTTPS")

        if url_length < 75:
            reasons.append("Normal URL length")

        if digit_count < 5:
            reasons.append("Low digit usage")

        if subdomain_count <= 3:
            reasons.append("Normal domain structure")

        if suspicious_word_count == 0:
            reasons.append("No suspicious keywords")

        if hyphen_count == 0:
            reasons.append("No suspicious symbols")

        if not reasons:
            reasons.append("No suspicious patterns detected")

    return reasons  

# Route
@app.route('/scan-qr-data', methods=['POST'])
def scan_qr_data():
    """Handle direct QR data from camera scan"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data received'}), 400
            
        qr_data = data.get('qr_data', '')
        
        if not qr_data:
            return jsonify({'error': 'No QR data'}), 400
        
        print(f"QR Data received: {qr_data[:50]}...")  # Debug log
        
        # Extract features and predict
        features = extract_features(qr_data)
        pred = model.predict([features])[0]
        
        # Generate result text
        result_text = "⚠ Fraud QR Code" if pred == 1 else "✅ Safe QR Code"
        explanation = explain_url(qr_data, pred, features)
        confidence = 10 if pred == 0 else 85
        
        # Return JSON response
        return jsonify({
            'success': True,
            'result': result_text,
            'url': qr_data,
            'explanation': explanation,
            'confidence' : confidence
        })
        
    except Exception as e:
        print(f"Error in scan-qr-data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = None
    explanation = None

    if request.method == "POST":
        file = request.files["qr_image"]

        filepath = "temp.png"
        file.save(filepath)

        img = cv2.imread(filepath)

        # QR Detection using OpenCV
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)

        if data:
            url = data

            features = extract_features(url)
            pred = model.predict([features])[0]

            result = "⚠ Fraud QR Code" if pred == 1 else "✅ Safe QR Code"

            explanation = explain_url(url, pred)

        else:
            result = "❌ QR not detected"

        # Clean up temp file
        try:
            os.remove(filepath)
        except:
            pass

    return render_template("index.html", result=result, url=url, explanation=explanation)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.png', mimetype='image/png')

    
if __name__ == "__main__":
    app.run( debug=True)