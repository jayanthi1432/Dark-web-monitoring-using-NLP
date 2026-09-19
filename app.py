
import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import pickle
import requests
import base64
import feedparser
import time
import os
import smtplib

from email.mime.text import MIMEText
from urllib.parse import urlparse

from utils.preprocess import clean_text
from utils.keywords import keyword_alert
# =========================================================
# 🔥 POPUP NOTIFICATION SYSTEM
# =========================================================

def show_popup(severity, text):

    if severity == "High":

        st.toast("🚨 HIGH THREAT DETECTED!", icon="🚨")
        st.error(f"🚨 CRITICAL ALERT 🚨\n\n{text}")

    elif severity == "Medium":

        st.toast("⚠️ Suspicious Activity Detected", icon="⚠️")
        st.warning(f"⚠️ WARNING ⚠️\n\n{text}")

    else:

        st.info("✅ Safe Input Detected")

# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="Dark Web Monitoring using NLP",
    layout="wide"
)

# =========================================================
# LOAD MODEL
# =========================================================

model = pickle.load(open("models/xgb_model.pkl", "rb"))
vectorizer = pickle.load(open("models/vectorizer.pkl", "rb"))

# =========================================================
# VIRUSTOTAL API
# =========================================================

API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

def get_url_report(url):

    try:

        if not API_KEY:
            return None

        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        headers = {
            "x-apikey": API_KEY
        }

        response = requests.get(
            api_url,
            headers=headers,
            timeout=10
        )

        return response.json()

    except:
        return None

# =========================================================
# EMAIL ALERT
# =========================================================

def send_email_alert(recipient_email, subject, body):

    try:

        sender_email = os.getenv("SENDER_EMAIL", "")
        sender_password = os.getenv("SENDER_PASSWORD", "")

        if sender_email == "" or sender_password == "":
            st.error("Email credentials not configured")
            return

        msg = MIMEText(body)

        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = recipient_email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:

            server.login(
                sender_email,
                sender_password
            )

            server.sendmail(
                sender_email,
                recipient_email,
                msg.as_string()
            )

        st.success("✅ Email Alert Sent")

    except Exception as e:

        st.error(f"❌ Email Error: {e}")

# =========================================================
# CYBER FEED
# =========================================================

def get_cyber_live_feed():

    feed = feedparser.parse(
        "https://feeds.feedburner.com/TheHackersNews"
    )

    for entry in feed.entries[:10]:

        yield (
            entry.title +
            " " +
            entry.summary
        )

# =========================================================
# TRUSTED DOMAINS
# =========================================================

TRUSTED_DOMAINS = {

    "google.com",
    "github.com",
    "youtube.com",
    "linkedin.com",
    "microsoft.com",
    "openai.com",
    "wikipedia.org",
    "stackoverflow.com"

}

# =========================================================
# DOMAIN EXTRACT
# =========================================================

def extract_domain(url):

    try:

        if not url.startswith("http"):
            url = "http://" + url

        return (
            urlparse(url)
            .netloc
            .replace("www.", "")
            .lower()
        )

    except:
        return ""

# =========================================================
# RISK ENGINE
# =========================================================

def compute_risk(
    vt_mal,
    prediction,
    confidence,
    trusted
):

    if trusted:
        return 5

    score = 0

    score += min(vt_mal * 25, 60)

    if prediction == 1:
        score += 35

    score += confidence * 0.3

    return min(score, 100)

# =========================================================
# SESSION STATE
# =========================================================

if "safe_count" not in st.session_state:
    st.session_state.safe_count = 0

if "threat_count" not in st.session_state:
    st.session_state.threat_count = 0

if "logs" not in st.session_state:
    st.session_state.logs = []

# =========================================================
# UI STYLE
# =========================================================

st.markdown("""

<style>

.stApp{
    background: linear-gradient(
        135deg,
        #0a0014,
        #12002b,
        #001a33,
        #0b0f2f
    );
    color:white;
}

h1{
    text-align:center;
    color:#a855f7;
    font-size:42px;
    font-weight:900;
}

.stButton button{
    background:linear-gradient(
        90deg,
        #7c3aed,
        #3b82f6
    );
    color:white;
    border-radius:10px;
    font-weight:bold;
}

</style>

""", unsafe_allow_html=True)

# =========================================================
# TITLE
# =========================================================

st.title("🛡️ Dark Web Monitoring using NLP")


# =========================================================
# METRICS
# =========================================================

col1, col2, col3 = st.columns(3)

col1.metric(
    "🟢 Safe",
    st.session_state.safe_count
)

col2.metric(
    "🔴 Threat",
    st.session_state.threat_count
)

col3.metric(
    "📊 Total",
    st.session_state.safe_count +
    st.session_state.threat_count
)

# =========================================================
# INPUT
# =========================================================

st.subheader("🔍 Threat Analysis")

user_input = st.text_input(
    "Enter suspicious URL or text"
)

# =========================================================
# ANALYZE BUTTON
# =========================================================

if st.button("Analyze", key="analyze_btn"):

    if user_input.strip() != "":

        cleaned = clean_text(user_input)

        vector = vectorizer.transform([cleaned])

        prediction = model.predict(vector)[0]

        proba = model.predict_proba(vector)[0]

        confidence = float(np.max(proba)) * 100
        

        # -------------------------------------------------
        # URL CHECK
        # -------------------------------------------------

        is_url = (
            user_input.startswith("http")
            or "." in user_input
        )

        domain = extract_domain(user_input)

        trusted = (
            domain in TRUSTED_DOMAINS
        )

        vt_mal = 0

        if is_url:

            vt = get_url_report(user_input)

            try:

                vt_mal = vt["data"]["attributes"]["last_analysis_stats"]["malicious"]

            except:

                vt_mal = 0

        # -------------------------------------------------
        # NLP KEYWORD CHECK
        # -------------------------------------------------

        is_keyword_threat = keyword_alert(user_input)

        # -------------------------------------------------
        # RISK
        # -------------------------------------------------

        risk = compute_risk(
            vt_mal,
            prediction,
            confidence,
            trusted
        )

        # -------------------------------------------------
        # CLASSIFICATION
        # -------------------------------------------------

        severity = "Low"
        result = "Safe"

        # trusted websites
        if trusted:

            severity = "Low"
            result = "Safe"

        # high threat keywords
        elif any(word in user_input.lower() for word in [

            "ransomware",
            "hacked",
            "password cracking",
            "sql injection",
            "dark web",
            "malware",
            "stolen cards",
            "selling hacked accounts",
            "exploit tool"

        ]):

            severity = "High"
            result = "Threat"

        # suspicious phishing words
        elif is_keyword_threat:

            severity = "Medium"
            result = "Suspicious"

        # model based
        elif risk > 75:

            severity = "High"
            result = "Threat"

        elif risk > 45:

            severity = "Medium"
            result = "Suspicious"

        # safe simple words
        elif cleaned.lower() in [

            "hello",
            "hi",
            "good morning",
            "good evening",
            "thank you"

        ]:

            severity = "Low"
            result = "Safe"
            #

        # -------------------------------------------------
        # RESET COUNTS
        # -------------------------------------------------

        st.session_state.safe_count = 0
        st.session_state.threat_count = 0

        if severity == "Low":

            st.session_state.safe_count = 1

        else:

            st.session_state.threat_count = 1

        # -------------------------------------------------
        # RESULT DISPLAY
        # -------------------------------------------------

        st.subheader("📌 Analysis Result")

        if severity == "High":

            st.error(
                f"🔴 Threat Detected | Severity: {severity}"
            )

        elif severity == "Medium":

            st.warning(
                f"⚠️ Suspicious Activity | Severity: {severity}"
            )

        else:

            st.success(
                f"✅ Safe | Severity: {severity}"
            )

        st.write(
            f"Confidence Score: {confidence:.2f}%"
        )

        st.progress(
            int(confidence)
        )

        # -------------------------------------------------
        # EMAIL ALERT
        # -------------------------------------------------

        if severity == "High":

            st.subheader("📧 Send Email Alert")

            alert_email = st.text_input(
                "Enter Email Address",
                key="email_box"
            )

            if st.button(
                "Send Alert",
                key="send_alert_btn"
            ):

                if alert_email != "":

                    details = f"""

Threat Detected

Input:
{user_input}

Severity:
{severity}

Confidence:
{confidence:.2f}%

"""

                    send_email_alert(
                        alert_email,
                        "Cyber Threat Alert",
                        details
                    )

        # -------------------------------------------------
        # LOGS
        # -------------------------------------------------

        st.session_state.logs.append({

            "Input": user_input[:50],
            "Result": result,
            "Severity": severity,
            "Confidence": round(confidence, 2)

        })

# =========================================================
# RESET BUTTON
# =========================================================

if st.button(
    "🔄 Reset Dashboard",
    key="reset_dashboard_btn"
):

    st.session_state.safe_count = 0
    st.session_state.threat_count = 0
    st.session_state.logs = []

    st.success("Dashboard Reset Successful")

# =========================================================
# LOG TABLE
# =========================================================

st.subheader("🗄️ Threat Logs")

if len(st.session_state.logs) > 0:

    df = pd.DataFrame(
        st.session_state.logs
    )

    st.dataframe(
        df,
        use_container_width=True
    )

    csv = df.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(

        "⬇️ Download CSV",
        csv,
        "threat_report.csv",
        "text/csv"

    )

# =========================================================
# ANALYTICS
# =========================================================

st.subheader("📊 Analytics Dashboard")

safe = int(st.session_state.safe_count)
threat = int(st.session_state.threat_count)

col1, col2 = st.columns(2)

# ---------------------------------------------------------
# PIE CHART
# ---------------------------------------------------------

with col1:

    total = safe + threat

    if total == 0:

        st.info("No data available")

    else:

        fig, ax = plt.subplots()

        ax.pie(

            [safe, threat],

            labels=[
                "Safe",
                "Threat"
            ],

            autopct="%1.1f%%"
        )

        ax.axis("equal")

        st.pyplot(fig)

# ---------------------------------------------------------
# BAR CHART
# ---------------------------------------------------------

with col2:

    fig2, ax2 = plt.subplots()

    ax2.bar(

        ["Safe", "Threat"],
        [safe, threat]

    )

    st.pyplot(fig2)

# =========================================================
# ACTIVITY TREND
# =========================================================

st.subheader("📈 Activity Trend")

if len(st.session_state.logs) > 0:

    df = pd.DataFrame(
        st.session_state.logs
    )

    df["Index"] = range(len(df))

    df["Risk"] = df["Severity"].map({

        "Low": 0,
        "Medium": 0.5,
        "High": 1

    })

    fig3, ax3 = plt.subplots(
        figsize=(6, 2)
    )

    ax3.plot(
        df["Index"],
        df["Risk"],
        linewidth=3
    )

    ax3.set_ylim(0, 1)

    st.pyplot(fig3)

# =========================================================
# LIVE CYBER FEED
# =========================================================

st.subheader("📡 Live Cyber Feed")

auto_run = st.checkbox(
    "Enable Real-Time Monitoring"
)

if auto_run:

    placeholder = st.empty()

    for text in get_cyber_live_feed():

        cleaned = clean_text(text)

        vector = vectorizer.transform(
            [cleaned]
        )

        proba = model.predict_proba(vector)[0]

        confidence = float(
            np.max(proba)
        ) * 100

        is_keyword_threat = keyword_alert(text)

        severity = "Low"
        result = "Safe"

        if is_keyword_threat:

            severity = "High"
            result = "Threat"

        elif confidence > 75:

            severity = "Medium"
            result = "Suspicious"

        with placeholder.container():

            st.markdown(f"""

<div style="
padding:10px;
border-radius:10px;
background:rgba(0,0,0,0.6);
border:1px solid #3b82f6;
margin-bottom:10px;
">

<b>{result}</b>
({severity})
- {confidence:.2f}%<br><br>

{text[:200]}

</div>

""", unsafe_allow_html=True)

        time.sleep(2)

# =========================================================
# FOOTER
# =========================================================

st.markdown("---")

st.markdown(
    "🚀 AI Powered Dark Web Monitoring using NLP"
) 
