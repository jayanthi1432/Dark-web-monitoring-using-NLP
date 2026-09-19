THREAT_KEYWORDS = [
    "hacked", "stolen", "credit card",
    "malware", "ransomware", "drugs",
    "weapon", "exploit", "breach"
]

def keyword_alert(text):
    for word in THREAT_KEYWORDS:
        if word in text.lower():
            return True
    return False