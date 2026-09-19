# 🛡️ Cyber Threat Intelligence System

An AI-powered **Cyber Threat Intelligence System** that analyzes suspicious text and URLs to identify potential cyber threats. The system combines **Natural Language Processing (NLP), Machine Learning, threat intelligence, and risk assessment** techniques to classify inputs as Safe, Suspicious, or Threat.

## 🚀 Project Overview

Cyber threats can appear in different forms such as suspicious URLs, phishing-related content, malware references, ransomware activities, and other potentially harmful cyber-related information.

This project provides an interactive **Streamlit dashboard** where users can enter suspicious text or URLs and receive:

* 🟢 Safe Probability
* 🔴 Threat Probability
* 📊 Confidence Score
* 🎯 Threat Intelligence / Risk Score
* 🗂️ Threat Category
* 🚨 Severity Level
* 🧠 AI-based Threat Explanation
* 🗄️ Threat Analysis Logs
* 📈 Threat Analytics
* 📡 Cybersecurity Intelligence Feed

## 🎯 Objectives

* Analyze suspicious text and URLs using NLP and Machine Learning.
* Classify input as **Safe, Suspicious, or Threat**.
* Estimate the probability of safe and malicious activity.
* Calculate a threat intelligence risk score.
* Identify common threat categories.
* Provide an interactive cybersecurity dashboard.
* Maintain analysis logs for reviewed inputs.
* Provide additional URL intelligence using VirusTotal.

## 🧠 Technologies Used

| Technology     | Purpose                         |
| -------------- | ------------------------------- |
| Python         | Core programming                |
| Streamlit      | Interactive dashboard           |
| Pandas         | Data processing                 |
| NumPy          | Numerical operations            |
| NLTK / NLP     | Text preprocessing              |
| TF-IDF         | Text feature extraction         |
| XGBoost        | Machine Learning classification |
| Scikit-learn   | ML prediction and probability   |
| Matplotlib     | Data visualization              |
| VirusTotal API | URL threat intelligence         |
| Feedparser     | Cybersecurity news feed         |
| Pickle         | Loading trained ML models       |

## 🤖 Machine Learning

The system uses a trained **XGBoost classification model** along with a **TF-IDF vectorizer**.

### Processing Flow

```text
User Input
    ↓
Text Preprocessing
    ↓
TF-IDF Feature Extraction
    ↓
XGBoost Classification
    ↓
Safe / Threat Probability
    ↓
Risk & Severity Assessment
    ↓
Threat Category
    ↓
Dashboard Result
```

The trained model and vectorizer are loaded from the `models/` directory.

## 🔍 Threat Analysis

Users can enter:

* Suspicious URLs
* Cybersecurity-related text
* Potential phishing content
* Malware-related content
* Ransomware-related content
* SQL injection-related content
* Dark-web-related content

The system analyzes the input and displays the corresponding threat assessment.

## 🛡️ Risk Assessment

The system calculates a **Threat Intelligence Score** using factors including:

* VirusTotal malicious detections
* Machine learning confidence
* Trusted-domain verification

The resulting score is used as part of the overall threat assessment.

## 🌐 VirusTotal Integration

For URL-based inputs, the system can query **VirusTotal** to obtain additional URL intelligence.

The VirusTotal response is used to identify malicious detections and contribute to the risk assessment.

> **Note:** A valid VirusTotal API key is required for this feature.

For security, API keys should be stored using environment variables or Streamlit secrets rather than committing them directly to GitHub.

## 📊 Dashboard Features

### Threat Analysis

The dashboard provides:

```text
Safe Probability
Threat Probability
Confidence Score
Threat Intelligence Score
Threat Category
Severity
```

### Threat Logs

Analysis results are stored during the application session and can be viewed in a table.

Users can also download the generated threat report as a CSV file.

### Analytics

The dashboard provides visualizations for:

* Threat Distribution
* Threat Intelligence Metrics
* Threat Probability Trend

### 📡 Cyber Intelligence Feed

The application can display cybersecurity-related information from **The Hacker News RSS feed** and analyze the retrieved content using the ML pipeline.

## 🗂️ Project Structure

```text
Cyber-Threat-Intelligence-System/
│
├── app.py
│
├── models/
│   ├── xgb_model.pkl
│   └── vectorizer.pkl
│
├── utils/
│   ├── preprocess.py
│   └── keywords.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/Cyber-Threat-Intelligence-System.git
```

### 2. Navigate to the project

```bash
cd Cyber-Threat-Intelligence-System
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the environment

**Windows:**

```bash
venv\Scripts\activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure VirusTotal API

Add your VirusTotal API key using a secure configuration method such as Streamlit Secrets.

### 7. Run the application

```bash
streamlit run app.py
```

The application will open in your browser.

## 📌 Example Workflow

```text
Enter URL / Suspicious Text
            ↓
     Analyze Threat
            ↓
      NLP Processing
            ↓
     TF-IDF Features
            ↓
   XGBoost Prediction
            ↓
   Threat Intelligence
            ↓
 Safe / Suspicious / Threat
            ↓
 Risk & Analytics Dashboard
```

## 🔐 Security Note

This project is intended for **educational and cybersecurity analysis purposes**.

Do not commit:

* API keys
* Passwords
* Access tokens
* Private credentials
* Sensitive datasets

to the public GitHub repository.

## 👨‍💻 Project

**Cyber Threat Intelligence System**

Developed using **Python, NLP, Machine Learning, Streamlit, and Threat Intelligence APIs**.

---

⭐ If you find this project useful, consider giving the repository a star!
