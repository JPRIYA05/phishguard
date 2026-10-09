"""Heuristic phishing / scam analysis. Pure functions, no network, fully unit-testable."""
from __future__ import annotations

import re
from urllib.parse import urlparse

MAX_URL_LEN = 2048
MAX_URLS = 5

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "work", "support", "rest", "icu"}
BRANDS = {
    "google", "paypal", "amazon", "microsoft", "apple", "facebook", "instagram", "netflix",
    "sbi", "hdfc", "icici", "paytm", "phonepe", "irctc", "flipkart", "whatsapp", "axisbank",
}
SENSITIVE_PATH_WORDS = ("login", "signin", "verify", "secure", "update", "account", "password", "kyc")
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}

URL_IN_TEXT = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")

TEXT_RULES = [
    ("urgency", 15, re.compile(r"(?i)\b(urgent|immediately|act now|last warning|within \d+ (hours?|minutes?)|expires? today|final notice)\b"),
     "Creates false urgency to rush you into acting."),
    ("credentials", 25, re.compile(r"(?i)\b(otp|pin|password|cvv|card number|aadhaar|net ?banking|one[- ]time password)\b"),
     "Asks for or mentions secrets (OTP, PIN, password, card or ID details)."),
    ("prize", 15, re.compile(r"(?i)\b(lottery|you (have )?won|prize|cashback|free gift|gift card|crypto giveaway|guaranteed returns?)\b"),
     "Promises a prize or easy money, a common scam hook."),
    ("threat", 20, re.compile(r"(?i)\b(legal action|arrest|police|penalty|account (will be )?(closed|suspended|blocked)|sim (will be )?blocked)\b"),
     "Threatens consequences to scare you."),
    ("kyc", 10, re.compile(r"(?i)\bkyc\b"),
     "Mentions KYC updates, a frequent bank-fraud pretext."),
]


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)) or (":" in host and re.fullmatch(r"[0-9a-f:]+", host) is not None)


def _finding(code: str, points: int, message: str, source: str = "text") -> dict:
    return {"code": code, "points": points, "message": message, "source": source}


def analyze_url(raw: str) -> list[dict]:
    """Return findings for one URL. Raises ValueError for unreadable input."""
    raw = raw.strip()
    if not raw or len(raw) > MAX_URL_LEN:
        raise ValueError("URL is empty or too long.")
    has_scheme = "://" in raw
    try:
        parsed = urlparse(raw if has_scheme else "http://" + raw)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Could not read this URL.") from exc
    if not host:
        raise ValueError("Could not find a hostname in this URL.")

    src, out = host, []
    add = lambda code, pts, msg: out.append(_finding(code, pts, msg, src))  # noqa: E731

    if has_scheme and parsed.scheme == "http":
        add("no_https", 10, "Uses plain HTTP, so traffic is not encrypted.")
    if _is_ip(host):
        add("ip_host", 30, "Uses a raw IP address instead of a domain name.")
    if parsed.username or "@" in parsed.netloc:
        add("userinfo", 25, "Contains '@' which can hide the real destination.")
    if "xn--" in host:
        add("punycode", 25, "Uses look-alike (punycode) characters in the domain.")
    if host in SHORTENERS:
        add("shortener", 15, "Link shortener hides the real destination.")
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        add("tld", 15, "Uses a top-level domain often abused for scams.")
    if len(host.split(".")) > 4:
        add("subdomains", 10, "Has an unusually long chain of subdomains.")
    if host.count("-") >= 3:
        add("hyphens", 10, "Domain contains many hyphens.")
    if len(raw) > 100:
        add("long_url", 5, "Very long URL, often used to bury the real target.")
    if port not in (None, 80, 443):
        add("port", 10, "Uses a non-standard port.")

    reg = registered_domain(host)
    label = reg.split(".")[0]
    if not _is_ip(host):
        for brand in BRANDS:
            if label == brand:
                break
            if brand in host.replace("-", ""):
                add("brand_in_host", 35, f"Mentions '{brand}' but the real domain is {reg}.")
                break
            if len(label) >= 4 and _levenshtein(label, brand) == 1:
                add("typosquat", 35, f"'{reg}' looks like a misspelling of '{brand}'.")
                break
        if any(w in parsed.path.lower() for w in SENSITIVE_PATH_WORDS) and label not in BRANDS:
            add("sensitive_path", 10, "Asks you to log in or verify on an unfamiliar domain.")
    return out


def extract_urls(text: str) -> list[str]:
    stripped = text.strip()
    if stripped and not re.search(r"\s", stripped):
        return [stripped]
    return [u.rstrip(".,;)") for u in URL_IN_TEXT.findall(text)][:MAX_URLS]


def verdict_for(score: int) -> str:
    return "safe" if score < 25 else "suspicious" if score < 55 else "dangerous"


RECOMMENDATIONS = {
    "safe": ["No strong warning signs found, but stay careful with unexpected requests.",
             "Type the official site address yourself instead of tapping links."],
    "suspicious": ["Do not click links or open attachments yet.",
                   "Contact the sender through an official number or app to confirm.",
                   "Never share OTPs, PINs or passwords."],
    "dangerous": ["Do not click, reply, or share any details.",
                  "Block the sender and delete the message.",
                  "If you already shared details, change passwords and call your bank now.",
                  "Report it at cybercrime.gov.in or call 1930 (India)."],
}


def analyze(text: str) -> dict:
    """Analyze free text or a single URL and return score, verdict, findings, advice."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Please enter a message or link.")
    findings: list[dict] = []
    urls = extract_urls(text)
    single_url = len(urls) == 1 and urls[0] == text
    if not single_url:
        for code, pts, rx, msg in TEXT_RULES:
            if rx.search(text):
                findings.append(_finding(code, pts, msg))
    checked = []
    for u in urls:
        try:
            findings.extend(analyze_url(u))
            checked.append(u)
        except ValueError:
            continue
    if single_url and not checked:
        raise ValueError("That does not look like a valid link.")
    score = min(100, sum(f["points"] for f in findings))
    verdict = verdict_for(score)
    return {"score": score, "verdict": verdict, "findings": findings,
            "urls": checked, "recommendations": RECOMMENDATIONS[verdict]}
