# PhishGuard: AI cybersecurity assistant

Paste a suspicious SMS, email or link. PhishGuard returns a risk score, plain-language reasons, and safe next steps.

**Challenge:** AI-Powered Cybersecurity & Digital Safety (PromptWars x Error Zero)

## How it works
1. **Rule engine** (`analyzer.py`): 15+ checks (look-alike domains, punycode, IP hosts, shorteners, urgency, OTP requests, threats). Fast, offline, tested.
2. **Google Safe Browsing** (optional): flags known malicious URLs.
3. **Google Gemini** (optional): explains the result in simple language. Untrusted input is delimited and the model is told not to follow instructions inside it (prompt-injection defence). Falls back to rule-based text if unavailable.

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # optional: add keys, then: export $(grep -v '^#' .env | xargs)
python app.py          # open http://127.0.0.1:8080
pytest -q
```

## Deploy to Google Cloud Run
```bash
gcloud run deploy phishguard --source . --region asia-south1 --allow-unauthenticated \
  --set-secrets GEMINI_API_KEY=gemini-key:latest
```

## Quality notes
- **Security:** CSP and security headers, input size/type validation, rate limiting, no secrets in repo, non-root container, XSS-safe rendering (`textContent`).
- **Efficiency:** heuristics run first and cost nothing; Gemini results are cached; 5-URL cap; short timeouts.
- **Testing:** pytest covers analyzer logic, API validation, and headers.
- **Accessibility:** semantic HTML, labelled controls, skip link, `aria-live` results, visible focus, dark mode, reduced motion, 44px targets.
- **Google services:** Gemini API, Safe Browsing API, Cloud Run.
