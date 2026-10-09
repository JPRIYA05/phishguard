import pytest
from app import create_app


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    return create_app().test_client()


def test_index_and_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "Content-Security-Policy" in r.headers
    assert b'lang="en"' in r.data


def test_health(client):
    assert client.get("/healthz").json == {"status": "ok"}


def test_analyze_ok(client):
    r = client.post("/api/analyze", json={"text": "http://paypa1-login.top/verify"})
    assert r.status_code == 200
    assert r.json["verdict"] in {"suspicious", "dangerous"} and r.json["explanation_source"] == "rules"


@pytest.mark.parametrize("payload", [None, {}, {"text": ""}, {"text": 5}, {"text": "http://"}])
def test_analyze_bad_input(client, payload):
    assert client.post("/api/analyze", json=payload).status_code == 400


def test_too_long(client):
    assert client.post("/api/analyze", json={"text": "a" * 4001}).status_code == 413
