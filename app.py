"""PhishGuard: explains whether a message or link looks like phishing or a scam."""
import os

from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import analyzer
import google_services as gs

MAX_TEXT = 4000


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    limiter = Limiter(get_remote_address, app=app, default_limits=["120 per hour"],
                      storage_uri="memory://")

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.post("/api/analyze")
    @limiter.limit("20 per minute")
    def api_analyze():
        data = request.get_json(silent=True)
        text = data.get("text") if isinstance(data, dict) else None
        if not isinstance(text, str) or not text.strip():
            return jsonify(error="Enter a message or link to check."), 400
        if len(text) > MAX_TEXT:
            return jsonify(error=f"Please keep it under {MAX_TEXT} characters."), 413
        try:
            result = analyzer.analyze(text)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

        flagged = gs.safe_browsing_flagged(result["urls"])
        if flagged:
            result["findings"].insert(0, {"code": "safe_browsing", "points": 60, "source": flagged[0],
                                          "message": "Google Safe Browsing lists this link as dangerous."})
            result["score"] = min(100, result["score"] + 60)
            result["verdict"] = analyzer.verdict_for(result["score"])
            result["recommendations"] = analyzer.RECOMMENDATIONS[result["verdict"]]
        result["explanation"], result["explanation_source"] = gs.explain(text, result)
        return jsonify(result)

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error="Input is too large."), 413

    @app.errorhandler(429)
    def rate_limited(_):
        return jsonify(error="Too many requests. Please wait a minute."), 429

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8080)))
