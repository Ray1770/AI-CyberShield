# AI-CyberShield


**CyberSentinel** AI is a real-time website threat detection Chrome extension powered by machine learning and integrated with external threat intelligence sources like Google Safe Browsing, VirusTotal, and SSL certificate validation.

##  Features
- 🌐 Real-time URL scanning with AI (Random Forest)
- 🧠 AI-based feature extraction and classification
- 🔍 Google Safe Browsing API check
- 🛡️ VirusTotal multi-engine scan with flag summary
- 🔐 SSL certificate issuer and validity analysis
- 📁 Dataset logging (malicious/benign URLs)
- ⚡ Chrome extension for user-friendly experience

# Technologies Used
- Python (Flask backend API)
- Scikit-learn (RandomForestClassifier)
- HTML + JavaScript (Chrome Extension UI)
- VirusTotal & Google Safe Browsing APIs
- SSL certificate validation

# Example Output
Fast Scan: BENIGN (3% suspicious)
Advanced Scan: MALICIOUS (by Google Safe Browsing)
SSL Info: Issuer: Let's Encrypt, Valid: Jan 2025 - Apr 2025
VirusTotal: 5 engines flagged as malicious

# API Keys Setup
Replace the placeholder values in app.py with your actual API keys:
Google Safe Browsing
VirusTotal

# The dataset for train the AI
you can use this dataset https://www.kaggle.com/datasets/samahsadiq/benign-and-malicious-urls 
to train the AI, and if you want you can change the app.py code to make the AI learn by it self

Rayan Algarni 
https://www.linkedin.com/in/rayan-algarni-b86403277
