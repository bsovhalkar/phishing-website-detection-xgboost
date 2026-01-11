# 🔐 Phishing Website Detection using XGBoost

A **real-world machine learning–based cybersecurity application** that detects
phishing websites by analyzing URL, domain, SSL, DNS, and HTML-based features.
The system is designed to identify **zero-day phishing attacks** that traditional
blacklists fail to detect.

---

## 🚀 Features

- Detects **phishing vs legitimate websites**
- Uses **30 handcrafted security features**
- Trained with **XGBoost (Gradient Boosting)**
- Supports **zero-day phishing detection**
- Provides **confidence score** for predictions
- Interactive **Streamlit web application**
- Modular feature extraction pipeline

---

## 🧠 Machine Learning Model

- Algorithm: **XGBoost Classifier**
- Problem Type: **Binary Classification**
- Labels:
  - `1` → Phishing
  - `0` → Legitimate
- Hyperparameter tuning using **GridSearchCV**
- GPU support (optional)

---

## 🧩 Feature Categories

The model uses **30 features**, including:

### 🔹 URL-Based Features
- URL length
- IP address usage
- URL shortening services
- `@` symbol usage
- Prefix/Suffix (`-`) in domain
- Subdomain count

### 🔹 Security Features
- HTTPS & SSL certificate validation
- HTTPS token misuse
- Port number analysis

### 🔹 Domain & Network Features
- Domain age
- WHOIS registration length
- DNS record availability
- Web traffic (approximation)
- Google indexing

### 🔹 HTML & JavaScript Features
- External resource loading
- Anchor tag analysis
- Form actions (SFH)
- Email submission detection
- Redirect behavior
- Mouseover, right-click, popup, iframe detection

---
