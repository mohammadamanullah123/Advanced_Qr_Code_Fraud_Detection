# 🔐 Advanced QR Code Fraud Detection

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-black?logo=flask)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.x-orange?logo=scikit-learn)](https://scikit-learn.org/)
[![OpenCV](https://img.shields.io/badge/OpenCV-4.x-5C3EE8?logo=opencv)](https://opencv.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **AI-powered real-time detection of malicious QR codes and phishing URLs.**

This project is a full-stack **Flask** application that uses a trained **Random Forest** classifier (with fallback models like Logistic Regression and XGBoost) to analyze QR codes and URLs for fraud indicators. It supports both **image upload** and **live camera scanning** with a modern, responsive glassmorphism UI.

---

## ✨ Features

- 📷 **Dual Scanning Modes** — Upload QR images or scan live via camera
- 🤖 **ML-Powered Detection** — Random Forest model trained on 200K+ URLs
- ⚡ **Real-time Analysis** — Sub-second fraud prediction with explainable AI
- 🔗 **URL & UPI Detection** — Automatically handles payment QR codes and web links
- 🛡️ **Explainable Results** — Get human-readable reasons for each prediction
- 📊 **Feature Engineering** — 12 engineered features (suspicious keywords, IP usage, subdomain count, digit ratio, etc.)
- 🎨 **Modern UI** — Dark-mode glassmorphism interface with animations
- 🌐 **REST API** — `/scan-qr-data` endpoint for JSON-based QR analysis

---

## 🧠 Machine Learning Pipeline

| Stage | Details |
|-------|---------|
| **Datasets** | URL dataset, Phishing URLs, malicious_phish, UPI transactions |
| **Preprocessing** | URL cleaning, deduplication, label encoding (0=Safe, 1=Fraud) |
| **Feature Extraction** | url_length, dot_count, slash_count, special_char_count, digit_count, hyphen_count, subdomain_count, suspicious_word flag, has_ip, is_long_url, digit_ratio |
| **Models Trained** | Logistic Regression, Random Forest, XGBoost |
| **Best Model** | Random Forest (n_estimators=500, balanced class weights) |
| **Evaluation** | Accuracy, Precision, Recall, F1-Score, Confusion Matrix |

### Top Features by Importance
1. `url_length`
2. `suspicious_word_count`
3. `subdomain_count`
4. `digit_ratio`
5. `has_ip`

---

## 🚀 Getting Started

### Prerequisites

- Python **3.10+**
- pip
- Webcam (optional, for live camera scanning)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd "Advanced QR Fraud Detection"

# Create a virtual environment (recommended)
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

# Install dependencies
pip install flask opencv-python joblib scikit-learn pandas numpy matplotlib seaborn

# Optional: for XGBoost support
pip install xgboost
```

### Project Structure

```
Advanced QR Fraud Detection/
│
├── app.py                          # Flask backend application
├── README.md                       # Project documentation
│
├── templates/
│   ├── index.html                  # Main frontend (glassmorphism UI)
│   ├── New.html                    # Additional template
│   └── old_.html                   # Legacy template
│
├── static/
│   └── index.css                   # Stylesheet
│
├── Model/
│   └── qr_fraud_model.pkl          # Trained Random Forest model
│
├── Data sets/
│   ├── URL dataset.csv
│   ├── Phishing URLs.csv
│   ├── malicious_phish.csv
│   └── upi_transactions_2024.csv
│
├── Test prediction/
│   └── test_predictions.csv        # Sample model predictions
│
├── Learn_from data.ipynb           # Main training & EDA notebook
```

---

## 🖥️ Usage

### Run the Flask App

```bash
python app.py
```

The server will start at: `http://127.0.0.1:5000`

### Web Interface

1. **Upload Mode**: Drag & drop or click to upload a QR image. The app decodes the QR and runs fraud analysis.
2. **Camera Mode**: Allow camera access and point at a QR code. Detection happens automatically.

### API Usage

You can also use the detection endpoint programmatically:

**Endpoint:** `POST /scan-qr-data`

**Request:**
```json
{
  "qr_data": "https://bank-login-secure.xyz/verify?acc=12345"
}
```

**Response:**
```json
{
  "success": true,
  "result": "⚠ Fraud QR Code",
  "url": "https://bank-login-secure.xyz/verify?acc=12345",
  "explanation": ["Long URL", "Contains suspicious words"]
}
```

### Example: Python API Call

```python
import requests

url = "http://127.0.0.1:5000/scan-qr-data"
payload = {"qr_data": "https://example-bank-login.tk/pay"}

response = requests.post(url, json=payload)
print(response.json())
```

---

## 🔬 How Detection Works

1. **QR Decoding** — OpenCV `cv2.QRCodeDetector` or `jsQR` extracts raw data from the QR image.
2. **UPI Check** — If the data matches UPI patterns (`upi://pay`), it flags as a payment QR.
3. **URL Parsing** — The domain and path are parsed using `urllib.parse`.
4. **Feature Extraction** — 12 statistical and semantic features are extracted from the URL.
5. **Model Prediction** — The Random Forest model returns `0` (Safe) or `1` (Fraud).
6. **Explanation Engine** — Rules-based module generates human-readable risk reasons.

---

## 📈 Model Performance

| Model | Accuracy | Strength |
|-------|----------|----------|
| Logistic Regression | ~78% | Baseline, fast inference |
| **Random Forest** | **~83%+** | **Best balance of precision/recall** |
| XGBoost | ~82% | Strong on large datasets |

> *Performance is based on a combined dataset of 200,000+ URLs after deduplication and feature engineering.*

---

## 🛡️ Suspicious Indicators Detected

- Unusually long URLs (>75 characters)
- Excessive subdomains or dots
- IP addresses instead of domains
- Suspicious keywords: `login`, `secure`, `verify`, `account`, `bank`
- High digit-to-length ratio
- Free hosting domains: `duckdns.org`, `000webhostapp.com`, `onrender.com`
- URL shorteners and redirect chains

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **ML/DS:** scikit-learn, pandas, NumPy, XGBoost, matplotlib, seaborn
- **CV & QR:** OpenCV, jsQR (JavaScript)
- **Frontend:** HTML5, CSS3, Vanilla JavaScript (glassmorphism design)
- **Model Persistence:** joblib / pickle

---

## 📌 Roadmap

- [ ] Add deep learning model (CNN for QR visual tampering)
- [ ] Integrate VirusTotal / Google Safe Browsing API
- [ ] Deploy to cloud (Render / Railway / AWS)
- [ ] Add user authentication & scan history dashboard
- [ ] Batch CSV upload for enterprise users
- [ ] Browser extension for instant QR threat alerts

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the **MIT License**.

---

## ⚠️ Disclaimer

This tool is for **educational and security research purposes only**. Always verify threats through multiple sources before taking action. The authors are not responsible for any misuse or false positives/negatives.

---

<p align="center">
  Built with ❤️ for a safer digital world.
</p>
