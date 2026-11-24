"""
detector.py - Rule-based scam detection for Digital Dignity - Scam Spotter.

Each rule is a small function that looks at the message text and returns
True/False. Every rule has a weight (points) and a safety tip.
The final score is the sum of the weights of the rules that matched
(capped at 100) and is converted into a risk level.
"""
import re

# ---------- Keyword lists (easy to extend) ----------
URGENT_WORDS = [
    "urgent", "immediately", "act now", "right now", "expires today",
    "last chance", "within 24 hours", "hurry", "final notice",
    "today only", "limited time", "asap", "verify now",
]
SENSITIVE_WORDS = [
    "otp", "pin", "cvv", "password", "passcode", "aadhaar", "aadhar",
    "pan card", "bank details", "account number", "card number",
    "card details", "upi pin", "net banking", "login details",
]
PAYMENT_WORDS = [
    "send money", "transfer", "pay now", "registration fee", "processing fee",
    "pay a fee", "deposit", "advance payment", "pay rs", "pay ₹",
    "refundable fee", "security deposit", "scan the qr",
]
PRIZE_WORDS = [
    "you have won", "you won", "winner", "lottery", "prize", "congratulations",
    "lucky draw", "cashback", "free gift", "reward points", "claim your",
]
JOB_WORDS = [
    "work from home", "easy money", "earn daily", "part time job",
    "earn rs", "earn ₹", "no experience needed", "guaranteed income",
    "hiring urgently", "data entry job",
]
THREAT_WORDS = [
    "account will be blocked", "account blocked", "account suspended",
    "kyc", "legal action", "arrest", "sim will be deactivated",
    "electricity will be cut", "your account has been locked", "suspended",
]
SHORTENERS = ["bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl"]
ODD_TLDS = [".xyz", ".top", ".click", ".info", ".online", ".site", ".buzz", ".work", ".tk", ".ml"]

URL_PATTERN = re.compile(r"(https?://[^\s]+|www\.[^\s]+|\b[\w-]+\.(?:com|in|net|org|xyz|top|click|info|online|site|buzz|work|tk|ml|co|ly|gl)\b/?[^\s]*)", re.I)
LINK_PHRASES = ["click this link", "click the link", "click here", "tap the link", "tap here", "open this link"]
IP_URL_PATTERN = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")
# An OTP the bank itself sent: "Your OTP is 1234. Do not share" -> not a scam
SAFE_OTP_PATTERN = re.compile(r"do not share|don't share|never share", re.I)


def _has_any(text, words):
    """Return the list of words from `words` found in `text`."""
    return [w for w in words if w in text]


def _host(url):
    """Return just the domain part of a URL, e.g. 'http://a.xyz/path' -> 'a.xyz'."""
    url = re.sub(r"^https?://", "", url)
    return re.split(r"[/?#:]", url)[0].rstrip(".,")


def find_urls(text):
    return URL_PATTERN.findall(text)


# ---------- Rules ----------
def rule_urgent(text):
    found = _has_any(text, URGENT_WORDS)
    return bool(found), found


def rule_link(text):
    urls = find_urls(text)
    phrases = _has_any(text, LINK_PHRASES)
    return bool(urls or phrases), urls + phrases


def rule_bad_link(text):
    """Shortened links, IP-address links or unusual domain endings."""
    reasons = []
    for u in find_urls(text):
        low = u.lower()
        if any(s in low for s in SHORTENERS):
            reasons.append(low)
        elif IP_URL_PATTERN.search(low):
            reasons.append(low)
        elif any(_host(low).endswith(t) for t in ODD_TLDS):
            reasons.append(low)
    return bool(reasons), reasons


def rule_sensitive(text):
    found = _has_any(text, SENSITIVE_WORDS)
    # Bank-style "Your OTP is 123456. Do not share it." is a warning, not a request.
    if found and SAFE_OTP_PATTERN.search(text):
        asks = re.search(r"(send|share|enter|tell|give|provide|reply|submit|confirm|update).{0,40}"
                         r"(otp|pin|cvv|password|aadhaar|aadhar|card|account)", text, re.I)
        if not asks:
            return False, []
    return bool(found), found


def rule_payment(text):
    found = _has_any(text, PAYMENT_WORDS)
    return bool(found), found


def rule_prize(text):
    found = _has_any(text, PRIZE_WORDS)
    return bool(found), found


def rule_job(text):
    found = _has_any(text, JOB_WORDS)
    return bool(found), found


def rule_threat(text):
    found = _has_any(text, THREAT_WORDS)
    return bool(found), found


# name: (function, weight, description, tip)
RULES = {
    "urgent_language": (rule_urgent, 15,
        "Urgent or pressuring language",
        "Scammers rush you so you do not think. Pause and verify before acting."),
    "contains_link": (rule_link, 10,
        "Contains a link",
        "Do not click links in unexpected messages. Type the official website yourself."),
    "suspicious_link": (rule_bad_link, 25,
        "Suspicious link (shortened, IP-based or unusual domain)",
        "Shortened or odd-looking links often hide fake websites."),
    "sensitive_request": (rule_sensitive, 45,
        "Asks for sensitive information (OTP, PIN, password, bank details)",
        "Never share your OTP, PIN, CVV or password with anyone, even if they claim to be from the bank."),
    "payment_request": (rule_payment, 25,
        "Unexpected payment or fee request",
        "Genuine jobs, banks and prizes never ask you to pay a fee first."),
    "prize_claim": (rule_prize, 25,
        "Prize, lottery or reward claim",
        "You cannot win a contest you never entered. Ignore such messages."),
    "fake_job": (rule_job, 25,
        "Too-good-to-be-true job offer",
        "Verify the company on its official website and never pay to get a job."),
    "threat_impersonation": (rule_threat, 25,
        "Threat or impersonation (account blocked, KYC, legal action)",
        "Banks do not threaten you by message. Call the number on your card or visit the branch."),
}

GENERAL_TIPS = [
    "When unsure, contact the organisation using its official website or phone number.",
    "Report scams at cybercrime.gov.in or call the cyber crime helpline 1930 (India).",
]


def risk_level(score):
    if score >= 60:
        return "High Risk"
    if score >= 30:
        return "Suspicious"
    return "Safe"


def analyze(message):
    """Analyze a message. Returns a dictionary with score, level, indicators, tips."""
    text = (message or "").lower().strip()
    result = {"score": 0, "level": "Safe", "indicators": [], "tips": []}
    if not text:
        return result

    score = 0
    for name, (func, weight, description, tip) in RULES.items():
        matched, evidence = func(text)
        if matched:
            score += weight
            shown = ", ".join(dict.fromkeys(str(e) for e in evidence))[:80]
            result["indicators"].append({"rule": name, "description": description,
                                         "evidence": shown, "points": weight})
            result["tips"].append(tip)

    # Combination bonus: two or more "serious" signs together are much more likely a scam.
    serious = {"sensitive_request", "payment_request", "prize_claim", "fake_job", "threat_impersonation"}
    if len(serious & {i["rule"] for i in result["indicators"]}) >= 2:
        score += 15
        result["indicators"].append({"rule": "combination", "description":
            "Several serious warning signs appear together", "evidence": "", "points": 15})

    result["score"] = min(score, 100)
    result["level"] = risk_level(result["score"])
    if result["level"] == "Safe" and not result["indicators"]:
        result["tips"] = ["No common scam signs found, but stay careful with unknown senders."]
    result["tips"] += GENERAL_TIPS
    return result
