import pandas as pd

url_1 = pd.read_csv('Data sets/URL dataset.csv')


url_1.sample(10)

url_1['type'].unique()

url_1['type'].value_counts()

url_1.isnull().mean()*100

url_1.duplicated().sample(10)

url_1.info()

new_url_1 = url_1[['url', 'type']].rename(columns={'url': 'URL', 'type': 'label'})

new_url_1.sample(10)

pusing.sample(10)

pusing['Type'].unique()

pusing.isnull().mean()*100

pusing['Type'].value_counts()

pusing.duplicated().sample(10)

pusing.info()

new_pusing = pusing[['url', 'Type']].rename(columns={'url': 'URL', 'Type': 'label'})

new_pusing.head()

new_pusing['label'].value_counts()

malicious.head()

malicious['type'].value_counts()

malicious.isnull().sum()

malicious.duplicated().sample(10)

malicious.info()

new_malicious = malicious[['url', 'type']].rename(columns={'url': 'URL', 'type': 'label'})

new_malicious.head()

upi.sample(10)

upi.isnull().mean()*100

upi.duplicated().sample(10)

upi.info()

upi.nunique()

merge_data = pd.concat([new_url_1, new_pusing, new_malicious], ignore_index=True)
print(f"Total URLs after combining: {len(merge_data)}")

merge_data.sample(10)

merge_data.shape

merge_data.isnull().sum()

merge_data.duplicated().sample(10)

merge_data['label'].value_counts().plot(kind='bar')

# Example: Sabko 0 (safe) aur 1 (malicious) mein convert karo
def standardize_label(label):
    if isinstance(label, str):
        label = label.lower()
        if label in ['benign', 'legitimate']:
            return 0
        elif label in ['phishing', 'malware', 'defacement']:
            return 1
    return label  

merge_data['label'] = merge_data['label'].apply(standardize_label)

merge_data.sample(10)

merge_data['label'].value_counts().plot(kind='bar')

merge_data['label'].value_counts()

merge_data['URL'].duplicated().sample(10)

merge_data.shape

merge_data = merge_data.drop_duplicates()

merge_data['URL'].duplicated().sample(10)

merge_data.shape

merge_data['label'].value_counts()

merge_data['has_https'] = merge_data['URL'].apply(lambda x: 1 if 'https' in x else 0)

merge_data['URL'] = merge_data['URL'].str.lower()
merge_data['URL'] = merge_data['URL'].str.replace('http://','')
merge_data['URL'] = merge_data['URL'].str.replace('https://','')
merge_data['URL'] = merge_data['URL'].str.replace('www.','')
merge_data['URL'] = merge_data['URL'].str.strip()

merge_data.sample(10)

# import re

# # URL Length
# merge_data['url_length'] = merge_data['URL'].apply(len)

# # Number of dots
# merge_data['dot_count'] = merge_data['URL'].apply(lambda x: x.count('.'))

# # Number of slashes
# merge_data['slash_count'] = merge_data['URL'].apply(lambda x: x.count('/'))

# # HTTPS presence
# # merge_data['has_https'] = merge_data['URL'].apply(lambda x: 1 if 'https' in x else 0)

# # Special characters count
# merge_data['special_char_count'] = merge_data['URL'].apply(lambda x: len(re.findall(r'[^a-zA-Z0-9]', x)))

# # Number of digits
# merge_data['digit_count'] = merge_data['URL'].apply(lambda x: sum(c.isdigit() for c in x))

# # Hyphen count 
# merge_data['hyphen_count'] = merge_data['URL'].apply(lambda x: x.count('-'))

# # Subdomain Count
# merge_data['subdomain_count'] = merge_data['URL'].apply(lambda x: x.count('.') - 1)

# # suspicious words
# suspicious_words = ['login','secure','verify','account','update','bank']
# merge_data['suspicious_word'] = merge_data['URL'].apply(
#     lambda x: int(any(word in x for word in suspicious_words))
# )

# # Check new dataset
# merge_data.sample(10)

import re
from urllib.parse import urlparse

# Suspicious words list
suspicious_words = ['login','secure','verify','account','update','bank']

# Suspicious domains list
suspicious_domains = [
    'duckdns.org', '000webhostapp.com', 'herokuapp.com',
    'netlify.app', 'onrender.com', 'xyz', 'tk'
]

# URL Length
merge_data['url_length'] = merge_data['URL'].apply(len)

# Number of dots
merge_data['dot_count'] = merge_data['URL'].apply(lambda x: x.count('.'))

# Number of slashes
merge_data['slash_count'] = merge_data['URL'].apply(lambda x: x.count('/'))


# Special characters count
merge_data['special_char_count'] = merge_data['URL'].apply(
    lambda x: len(re.findall(r'[^a-zA-Z0-9]', x))
)

# Number of digits
merge_data['digit_count'] = merge_data['URL'].apply(
    lambda x: sum(c.isdigit() for c in x)
)

# Hyphen count 
merge_data['hyphen_count'] = merge_data['URL'].apply(lambda x: x.count('-'))

# Subdomain Count
merge_data['subdomain_count'] = merge_data['URL'].apply(
    lambda x: x.count('.') - 1 if x.count('.') > 0 else 0
)

# Suspicious word presence (0/1)
merge_data['suspicious_word'] = merge_data['URL'].apply(
    lambda x: int(any(word in x.lower() for word in suspicious_words))
)

# Suspicious word count 
merge_data['suspicious_word_count'] = merge_data['URL'].apply(
    lambda x: sum(x.lower().count(word) for word in suspicious_words)
)
# URL uses IP instead of domain 
merge_data['has_ip'] = merge_data['URL'].apply(
    lambda x: 1 if re.search(r'\d+\.\d+\.\d+\.\d+', x) else 0
)

# Long URL flag
merge_data['is_long_url'] = merge_data['url_length'].apply(
    lambda x: 1 if x > 75 else 0
)

# Digit ratio 
merge_data['digit_ratio'] = merge_data.apply(
    lambda row: row['digit_count'] / row['url_length'] if row['url_length'] > 0 else 0,
    axis=1
)

# Check dataset
merge_data.sample(10)

from sklearn.model_selection import train_test_split

X = merge_data[['url_length','dot_count','slash_count','special_char_count','digit_count','hyphen_count','subdomain_count',
                'suspicious_word','suspicious_word_count','has_ip','is_long_url','digit_ratio']]

Y = merge_data['label']

X_train,X_test,Y_train,Y_test = train_test_split(X,Y,test_size=0.2,random_state=42)

X_train.shape

from sklearn.linear_model import LogisticRegression

log_model = LogisticRegression(max_iter=1000)
log_model.fit(X_train, Y_train)

from sklearn.ensemble import RandomForestClassifier

rf_model = RandomForestClassifier(
    n_estimators=500,
    max_depth=20, 
    min_samples_split=5,  
    min_samples_leaf=2,
    random_state=42,
    class_weight="balanced"
)
rf_model.fit(X_train, Y_train)

!pip install xgboost

from xgboost import XGBClassifier
from sklearn.metrics import classification_report

xboost = XGBClassifier(
    n_estimators=300,
    learning_rate=0.01,
    scale_pos_weight=2.08,
    use_label_encoder=False,
    eval_metric='logloss',
    max_depth=6
)

xboost.fit(X_train, Y_train)

# Logistic Regression
log_pred = log_model.predict(X_test)

# Random Forest
rf_pred = rf_model.predict(X_test)

# XGBoost
xb_pred = xboost.predict(X_test)

# rf_probs = rf_model.predict_proba(X_test)[:,1]   # probability nikaalo

# threshold = 0.3  # change this

# rf_pred = (rf_probs >= threshold).astype(int)
# Random Forest Report
#               precision    recall  f1-score   support

#            0       0.96      0.71      0.82    154523
#            1       0.61      0.93      0.74     74469

#     accuracy                           0.78    228992
#    macro avg       0.78      0.82      0.78    228992
# weighted avg       0.84      0.78      0.79    228992

from sklearn.metrics import accuracy_score  # prevous Random Forest = 83.35

print("Logistic Regression Accuracy:", accuracy_score(Y_test, log_pred))
print("Random Forest Accuracy:", accuracy_score(Y_test, rf_pred))
print("XGBoost: ",accuracy_score(Y_test,xb_pred))

# from sklearn.model_selection import cross_val_score
# scores = cross_val_score(rf_model, X, Y, cv=5)
# print(scores.mean())

print("Logistic Regression Report")
print(classification_report(Y_test, log_pred))

print("Random Forest Report")
print(classification_report(Y_test, rf_pred))

print("XGboost Report")
print(classification_report(Y_test, xb_pred))

import matplotlib.pyplot as plt

feature_names = [
    "url_length", "dots", "slashes", "special_chars",
    "digits", "hyphens", "subdomains", "suspicious_flag",
    "suspicious_count",  "has_ip",
    "long_url", "digit_ratio"
]

importances = rf_model.feature_importances_

# Plot
plt.barh(feature_names, importances)
plt.xlabel("Importance")
plt.title("Feature Importance")
plt.show()

url_features = [[0,50,2,3,3,3,3,1,0,5,8,0]]

prediction = rf_model.predict(url_features)

if prediction[0] == 1:
    print("⚠ Fraud URL")
else:
    print("✅ Safe URL")

results = pd.DataFrame({
    "Actual": Y_test,
    "Predicted": rf_pred
})

print(results.sample(10))

# 4️ Confusion Matrix
from sklearn.metrics import confusion_matrix

print("Confusion Matrix:")
print(confusion_matrix(Y_test, rf_pred))

# 7️ CSV me save karna
results.to_csv("test_predictions.csv", index=False)

print("\nPrediction results saved as test_predictions.csv")

import pickle

pickle.dump(rf_model, open("Model/qr_fraud_model.pkl", "wb"))

results = pd.DataFrame({
    "Actual": Y_test,
    "Predicted": xb_pred
})

print(results.sample(10))

# 4️ Confusion Matrix
from sklearn.metrics import confusion_matrix

print("Confusion Matrix:")
print(confusion_matrix(Y_test, xb_pred))

rf = pickle.load(open("Model/qr_fraud_model.pkl","rb"))

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

    return ", ".join(reasons)

# import pickle
# # Suspicious words list-
# suspicious_words = ['login','secure','verify','account','update','bank']

# #  Feature extraction function
# def extract_features(url):
#     has_https = 1 if "https" in url else 0
#     url_length = len(url)
#     dot_count = url.count(".")
#     slash_count = url.count("/")
#     special_char_count = len(re.findall(r'[^a-zA-Z0-9]', url))
#     digit_count = sum(c.isdigit() for c in url)
#     hyphen_count = url.count("-")
#     subdomain_count = dot_count - 1 if dot_count > 0 else 0
#     suspicious_word_count = sum(url.lower().count(word) for word in suspicious_words)

#     features = [
#         has_https,
#         url_length,
#         dot_count,
#         slash_count,
#         special_char_count,
#         digit_count,
#         hyphen_count,
#         subdomain_count,
#         suspicious_word_count
#     ]
    
#     return features

# # Single URL Prediction
# def predict_url(url):
#     features = extract_features(url)
#     prediction = rf.predict([features])[0]
#     explanation = explain_url(url, prediction)
#     label = "⚠ Fraud URL" if prediction == 1 else "✅ Safe URL"
#     return label, explanation

# #  Multiple URLs Prediction (DataFrame)
# def predict_urls(df, url_column='URL'):
#     df = df.copy()
#     results = []
#     explanations = []
#     for url in df[url_column]:
#         features = extract_features(url)
#         pred = rf.predict([features])[0]

#         label = "⚠ Fraud URL" if pred == 1 else "✅ Safe URL"
#         explanation = explain_url(url, pred)

#         results.append(label)
#         explanations.append(explanation)

#     df['Prediction'] = results
#     df['Explanation'] = explanations
#     return df

# # Example Usage
# test_df = pd.DataFrame({
#     'URL': [
#         "https://google.com",
#         "http://bank-login-secure.xyz",
#         "https://example.com",
#         "https://spark.iitr.ac.in/",
#         "https://www.google.com/about/careers/applications/apply/d028d74b-3f01-42af-97f6-90f78e39c4b5/review",
#         "https://hack2skill.com/?utm_source=hack2skill&utm_medium=homepage",
#         "https://fake-news-project-2i3o.onrender.com/",
#         "https://chatgpt.com/c/69b7b96e-0a5c-8322-ba24-5201893caf62",
#         "http://localhost:8888/tree/Advanced%20QR%20Fraud%20Detection",
#         "https://docs-cybersec.thalesgroup.com/bundle/on-premises-knowledgebase-reference-guide/page/abnormally_long_url.htm",
#         "https://hack2skill.com/?utm_source=hack2skill&utm_medium=homepage#whyH2s",
#         "corporationwiki.com/Ohio/Columbus/frank-s-benson-P3333917.aspx",
#         "http://www.ikenmijnkunst.nl/index.php/exposities/exposities-2006",
#         "signin.eby.de.zukruygxctzmmqi.civpro.co.za"
#     ]
# })

# predicted_df = predict_urls(test_df)
# print(predicted_df)

import re
from urllib.parse import urlparse

# Suspicious words list
suspicious_words = ['login','secure','verify','account','update','bank']

# Suspicious domains list
suspicious_domains = ['duckdns.org','onrender.com','000webhostapp.com','aaff.xyz','sjdj.tk']

# Feature extraction function
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Basic features
    url_length = len(url)
    dot_count = url.count(".")
    slash_count = url.count("/")
    special_char_count = len(re.findall(r'[^a-zA-Z0-9]', url))
    digit_count = sum(c.isdigit() for c in url)
    hyphen_count = url.count("-")
    subdomain_count = dot_count - 1 if dot_count > 0 else 0

    # Suspicious words
    suspicious_word_count = sum(url.lower().count(word) for word in suspicious_words)

    # 🔥 Advanced features
    has_ip = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    is_long_url = 1 if url_length > 75 else 0

    # 🔥 EXTRA (to make 14 features)
    digit_ratio = digit_count / url_length if url_length > 0 else 0
    special_char_ratio = special_char_count / url_length if url_length > 0 else 0

    features = [
        url_length,             # 1
        dot_count,              # 2
        slash_count,            # 3
        special_char_count,     # 4
        digit_count,            # 5
        hyphen_count,           # 6
        subdomain_count,        # 7
        suspicious_word_count,  # 8
        has_ip,                 # 9
        is_long_url,            # 10
        digit_ratio,            # 11
        special_char_ratio      # 12
    ]

    return features
 


# Single URL Prediction
def predict_url(url):
    features = extract_features(url)
    prediction = rf.predict([features])[0]
    explanation = explain_url(url, prediction)

    label = "⚠ Fraud URL" if prediction == 1 else "✅ Safe URL"
    return label, explanation


# Multiple URLs Prediction
def predict_urls(df, url_column='URL'):
    df = df.copy()
    results = []
    explanations = []

    for url in df[url_column]:
        features = extract_features(url)
        pred = rf.predict([features])[0]

        label = "⚠ Fraud URL" if pred == 1 else "✅ Safe URL"
        explanation = explain_url(url, pred)

        results.append(label)
        explanations.append(explanation)

    df['Prediction'] = results
    df['Explanation'] = explanations
    return df


# Example Usage
test_df = pd.DataFrame({
    'URL': [
        "https://google.com",
        "http://bank-login-secure.xyz",
        "https://example.com",
        "https://spark.iitr.ac.in/",
        "https://www.google.com/about/careers/applications/apply/d028d74b-3f01-42af-97f6-90f78e39c4b5/review",
        "https://hack2skill.com/?utm_source=hack2skill&utm_medium=homepage",
        "https://fake-news-project-2i3o.onrender.com/",
        "https://chatgpt.com/c/69b7b96e-0a5c-8322-ba24-5201893caf62",
        "http://localhost:8888/tree/Advanced%20QR%20Fraud%20Detection",
        "https://docs-cybersec.thalesgroup.com/bundle/on-premises-knowledgebase-reference-guide/page/abnormally_long_url.htm",
        "signin.eby.de.zukruygxctzmmqi.civpro.co.za",
        "http://mobildeniz2025firsatlari.duckdns.org/"
    ]
})

predicted_df = predict_urls(test_df)
print(predicted_df)



