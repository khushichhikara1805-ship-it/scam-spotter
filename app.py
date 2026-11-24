"""app.py - Flask web app for Digital Dignity - Scam Spotter."""
from flask import Flask, render_template, request, jsonify, redirect, url_for
import detector
import database

app = Flask(__name__)
database.init_db()

EXAMPLES = [
    "You have won a prize. Click this link now and enter your bank details.",
    "Dear customer, your KYC expires today. Update now at bit.ly/xyz or your account will be blocked.",
    "Your OTP is 482913. Do not share it with anyone.",
    "Work from home and earn Rs 5000 daily! Pay a registration fee of Rs 500 to start.",
    "Hi, are we still meeting for lunch tomorrow at 1 pm?",
]


@app.route("/")
def home():
    return render_template("index.html", examples=EXAMPLES)


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Please paste a message to check."}), 400
    if len(message) > 5000:
        return jsonify({"error": "Message is too long (max 5000 characters)."}), 400
    result = detector.analyze(message)
    database.save_check(message, result["score"], result["level"], result["indicators"])
    return jsonify(result)


@app.route("/history")
def history():
    return render_template("history.html", history=database.get_history(20))


@app.route("/history/clear", methods=["POST"])
def clear():
    database.clear_history()
    return redirect(url_for("history"))


@app.route("/tips")
def tips():
    return render_template("tips.html")


if __name__ == "__main__":
    app.run(debug=True)
