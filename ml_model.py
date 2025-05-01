import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import re
from urllib.parse import urlparse
import math
import pickle

# Load dataset
df = pd.read_csv('balanced_urls.csv')

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

# Feature engineering
X = df['url'].apply(extract_features).apply(pd.Series)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest model
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    class_weight='balanced',
    random_state=42
)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("\n📊 Random Forest Classification Report:")
print(classification_report(y_test, y_pred))

# Cross-validation
print("\n🔁 Running 5-fold cross-validation...")
cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
print("Cross-validation scores:", cv_scores)
print("Mean accuracy:", round(cv_scores.mean(), 4))

# Save model and features
with open('rf_model.pkl', 'wb') as f:
    pickle.dump(model, f)

with open('features.pkl', 'wb') as f:
    pickle.dump(X.columns.tolist(), f)

print("\n✅ Random Forest model and features saved!")
