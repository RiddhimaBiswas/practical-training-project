# project/intrusion_detection.py
PHISH_KEYWORDS = ["password", "verify", "account", "click here", "urgent", "bank", "login", "reset"]

def analyze_text_for_phish(text):
    t = text.lower()
    score = sum(1 for k in PHISH_KEYWORDS if k in t)
    return score

def is_suspicious_email(text, threshold=2):
    return analyze_text_for_phish(text) >= threshold
