import pytest
from analyzer import analyze, analyze_url, extract_urls, registered_domain, verdict_for


def codes(findings):
    return {f["code"] for f in findings}


def test_safe_url():
    assert analyze("https://www.google.com/maps")["verdict"] == "safe"


def test_ip_and_http():
    c = codes(analyze_url("http://192.168.1.5/login"))
    assert {"ip_host", "no_https"} <= c


def test_typosquat():
    assert "typosquat" in codes(analyze_url("https://paypa1.com/signin"))


def test_brand_in_host():
    assert "brand_in_host" in codes(analyze_url("https://sbi-kyc-update.top/login"))


def test_punycode_and_userinfo():
    assert "punycode" in codes(analyze_url("https://xn--pypal-4ve.com"))
    assert "userinfo" in codes(analyze_url("https://google.com@evil.example/x"))


def test_real_brand_domain_not_flagged():
    assert not codes(analyze_url("https://accounts.google.com/login")) & {"typosquat", "brand_in_host"}


def test_scam_message_is_dangerous():
    r = analyze("Your SBI account will be blocked within 24 hours. Share OTP at http://sbi-kyc-update.top/login")
    assert r["verdict"] == "dangerous" and r["score"] <= 100


def test_plain_text_safe():
    assert analyze("Lunch at 1pm tomorrow?")["verdict"] == "safe"


def test_empty_and_invalid():
    with pytest.raises(ValueError):
        analyze("   ")
    with pytest.raises(ValueError):
        analyze("http://")


def test_helpers():
    assert registered_domain("a.b.example.co.in") == "example.co.in"
    assert extract_urls("see www.x.com/a, and https://y.org.") == ["www.x.com/a", "https://y.org"]
    assert verdict_for(10) == "safe" and verdict_for(30) == "suspicious" and verdict_for(80) == "dangerous"
