from flask import Flask, request, jsonify
from flask_cors import CORS

from ai_engine import AIEngine

app = Flask(__name__)

CORS(app)

engine = AIEngine()


@app.route("/")
def home():

    return jsonify({

        "application": "AI Phishing Detection System",

        "status": "Running"

    })


@app.route("/analyze", methods=["GET","POST"])
def analyze():

    data = request.get_json()

    if not data:

        return jsonify({

            "status": "FAILED",

            "message": "No JSON data received."

        }), 400

    url = data.get("url")

    if not url:

        return jsonify({

            "status": "FAILED",

            "message": "URL is required."

        }), 400

    result = engine.analyze(url)

    return jsonify(result)


if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )