import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from detector import analyze


@pytest.mark.parametrize("msg,expected", [
    ("You have won a prize. Click this link now and enter your bank details.", "High Risk"),
    ("Dear customer, your KYC expires today. Update now at bit.ly/xyz or your account will be blocked.", "High Risk"),
    ("Please share your OTP and password immediately to verify your account.", "High Risk"),
    ("Work from home and earn Rs 5000 daily! Pay a registration fee to start.", "High Risk"),
    ("Your OTP is 482913. Do not share it with anyone.", "Safe"),
    ("Hi, are we still meeting for lunch tomorrow at 1 pm?", "Safe"),
    ("Your parcel is delayed, track here: https://example.com/track", "Safe"),
    ("Congratulations, claim your free gift at http://win-big.xyz", "High Risk"),
])
def test_risk_levels(msg, expected):
    assert analyze(msg)["level"] == expected


def test_empty_message_is_safe():
    r = analyze("   ")
    assert r["score"] == 0 and r["level"] == "Safe"


def test_score_is_capped_at_100():
    msg = ("urgent! you have won a lottery prize, share otp and password, pay a registration fee, "
           "click bit.ly/x, account will be blocked, work from home easy money")
    assert analyze(msg)["score"] == 100


def test_indicators_have_reasons_and_tips():
    r = analyze("Urgent! Send your OTP at http://192.168.1.5/login")
    names = [i["rule"] for i in r["indicators"]]
    assert "urgent_language" in names and "sensitive_request" in names and "suspicious_link" in names
    assert len(r["tips"]) > 0
