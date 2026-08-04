import pandas as pd
import re
import pickle
from sklearn.ensemble import RandomForestClassifier

print("Loading datasets...")
try:
    url_1 = pd.read_csv('Data sets/URL dataset.csv')
    new_url_1 = url_1[['url', 'type']].rename(columns={'url': 'URL', 'type': 'label'})
except Exception as e:
    print("Error loading URL dataset:", e)
    new_url_1 = pd.DataFrame(columns=['URL', 'label'])

try:
    pusing = pd.read_csv('Data sets/Phishing URLs.csv')
    new_pusing = pusing[['url', 'Type']].rename(columns={'url': 'URL', 'Type': 'label'})
except Exception as e:
    print("Error loading Phishing URLs:", e)
    new_pusing = pd.DataFrame(columns=['URL', 'label'])

try:
    malicious = pd.read_csv('Data sets/malicious_phish.csv')
    new_malicious = malicious[['url', 'type']].rename(columns={'url': 'URL', 'type': 'label'})
except Exception as e:
    print("Error loading malicious_phish:", e)
    new_malicious = pd.DataFrame(columns=['URL', 'label'])

merge_data = pd.concat([new_url_1, new_pusing, new_malicious], ignore_index=True)

def standardize_label(label):
    if isinstance(label, str):
        label = label.lower()
        if label in ['benign', 'legitimate']:
            return 0
        elif label in ['phishing', 'malware', 'defacement']:
            return 1
    return label  

merge_data['label'] = merge_data['label'].apply(standardize_label)
merge_data = merge_data.dropna(subset=['URL', 'label'])
merge_data = merge_data[merge_data['label'].isin([0, 1])]
merge_data['label'] = merge_data['label'].astype(int)
merge_data = merge_data.drop_duplicates(subset=['URL'])

# Limit dataset size to speed up processing and prevent large memory usage during training
merge_data = merge_data.sample(n=min(50000, len(merge_data)), random_state=42)

print(f"Total samples for training: {len(merge_data)}")

# Features Extraction
suspicious_words = ['login','secure','verify','account','update','bank','ad']

def extract_all(url):
    url = str(url)
    url_length = len(url)
    dot_count = url.count(".")
    slash_count = url.count("/")
    special_char_count = len(re.findall(r'[^a-zA-Z0-9]', url))
    digit_count = sum(c.isdigit() for c in url)
    hyphen_count = url.count("-")
    subdomain_count = max(url.count(".") - 1, 0)
    suspicious_word_count = sum(url.lower().count(w) for w in suspicious_words)
    suspicious_word = 1 if suspicious_word_count > 0 else 0
    has_ip = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    is_long_url = 1 if url_length > 75 else 0
    digit_ratio = digit_count / url_length if url_length > 0 else 0
    return [url_length, dot_count, slash_count, special_char_count, digit_count, hyphen_count, subdomain_count, suspicious_word, suspicious_word_count, has_ip, is_long_url, digit_ratio]

print("Extracting features...")
features_list = merge_data['URL'].apply(extract_all).tolist()
X = pd.DataFrame(features_list, columns=['url_length','dot_count','slash_count','special_char_count','digit_count','hyphen_count','subdomain_count','suspicious_word','suspicious_word_count','has_ip','is_long_url','digit_ratio'])
Y = merge_data['label']

print("Training optimized Random Forest...")
rf_model = RandomForestClassifier(
    n_estimators=15,    # Drastically reduced from 500
    max_depth=12,       # Reduced from 20
    min_samples_split=5,  
    min_samples_leaf=2,
    random_state=42,
    class_weight="balanced"
)

rf_model.fit(X, Y)
print("Training accuracy:", rf_model.score(X, Y))

# Save the model
model_path = "Model/qr_fraud_model.pkl"
pickle.dump(rf_model, open(model_path, "wb"))
import os
size = os.path.getsize(model_path) / (1024 * 1024)
print(f"Model saved successfully to {model_path}!")
print(f"New model size: {size:.2f} MB")
