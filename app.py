"""
app.py – Flask Web Interface for Phishing URL Detector
"""

from flask import Flask, render_template, request, jsonify
from detector import check_url

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    raw  = data.get("urls", "")

    if not raw:
        return jsonify({"error": "No URLs provided"}), 400

    urls    = [u.strip() for u in raw.splitlines() if u.strip() and not u.strip().startswith("#")]
    results = [check_url(u) for u in urls[:20]]   # cap at 20 per request

    summary = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for r in results:
        summary[r["risk_level"]] += 1

    return jsonify({"results": results, "summary": summary})


if __name__ == "__main__":
    app.run(debug=True)
