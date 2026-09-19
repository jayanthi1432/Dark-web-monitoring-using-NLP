import streamlit as st

def show_alert(level):
    if level == "High":
        st.error("🚨 HIGH RISK THREAT DETECTED!")
    elif level == "Medium":
        st.warning("⚠️ Suspicious Activity Detected")
    else:
        st.success("✅ Safe Content")