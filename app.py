from flask import Flask, render_template, request, jsonify, redirect  # 👈 jsonify, redirect add kiya
from urllib.parse import urlparse
import cv2
import joblib
import re

app = Flask(__name__)

# Load model
model = joblib.load("Model/qr_fraud_model.pkl")

suspicious_words = ['login','secure','verify','account','update','bank','ad']

suspicious_domains = [
    'duckdns.org', '000webhostapp.com', 'herokuapp.com',
    'netlify.app', 'onrender.com', 'xyz', 'tk'
]

# Feature extraction
def extract_features(url):
    domain = urlparse(url).netloc
    return [
        # 1 if "https" in url else 0,                                  # has_https
        len(url),                                                    # url_length
        url.count("."),                                              # dot_count
        url.count("/"),                                              # slash_count
        len(re.findall(r'[^a-zA-Z0-9]', url)),                      # special_char_count
        sum(c.isdigit() for c in url),                               # digit_count
        url.count("-"),                                              # hyphen_count
        max(url.count(".") - 1, 0),                                  # subdomain_count
        1 if sum(url.lower().count(w) for w in suspicious_words) > 0 else 0,  # suspicious_word flag
        sum(url.lower().count(w) for w in suspicious_words),        # suspicious_word_count
        # 1 if any(domain.endswith(tld) for tld in [".com", ".org", ".net", ".edu", ".gov"]) else 0,  # domain_flag
        1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain) else 0,  # has_ip
        1 if len(url) > 75 else 0,                                   # is_long_url
        sum(c.isdigit() for c in url)/len(url) if len(url) > 0 else 0  # digit_ratio
    ]

# Explanation
def explain_url(url, prediction):
    reasons = []

    if prediction == 1:  # Fraud
        if len(url) > 50:
            reasons.append("Long URL")
        if sum(c.isdigit() for c in url) > 5:
            reasons.append("Too many digits")
        if url.count('.') > 3:
            reasons.append("Too many subdomains")
        if "https" not in url:
            reasons.append("No HTTPS")
        if '-' in url:
            reasons.append("Contains hyphen")
        if any(word in url.lower() for word in suspicious_words):
            reasons.append("Contains suspicious words")

    else:  # Safe
        if "https" in url:
            reasons.append("Uses HTTPS")
        if len(url) < 50:
            reasons.append("Short URL")
        if sum(c.isdigit() for c in url) < 5:
            reasons.append("Less digits")
        if url.count('.') <= 3:
            reasons.append("Normal structure")
        if '-' not in url:
            reasons.append("No suspicious symbols")

    return reasons  # list return karenge

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
        explanation = explain_url(qr_data, pred)
        
        # Return JSON response
        return jsonify({
            'success': True,
            'result': result_text,
            'url': qr_data,
            'explanation': explanation
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
        import os
        try:
            os.remove(filepath)
        except:
            pass

    return render_template("index.html", result=result, url=url, explanation=explanation)

    
if __name__ == "__main__":
    app.run( debug=True)