import pytest
from app.services.url_analyzer import analyze_url, _is_trusted

def test_trusted_domains():
    assert _is_trusted("google.com") == True
    assert _is_trusted("www.youtube.com") == True
    assert _is_trusted("accounts.google.com") == True
    assert _is_trusted("github.com") == True
    assert _is_trusted("suspicious-site.tk") == False
    assert _is_trusted("paypa1-secure.com") == False

def test_analyze_safe_url():
    result = analyze_url("https://www.google.com/search?q=hello")
    assert result["is_suspicious"] == False
    assert result["score"] == 0
    assert result["reason"] == ""

def test_analyze_phishing_url():
    # Typosquatting / homoglyph
    result = analyze_url("http://paypa1-secure-login.com/verify-account")
    assert result["is_suspicious"] == True
    assert result["score"] > 0
    assert "Suspicious keyword" in result["reason"]

def test_analyze_suspicious_tld():
    result = analyze_url("http://free-movies.tk")
    assert result["score"] >= 15
    assert "Suspicious TLD" in result["reason"]

def test_analyze_entropy():
    # Highly random domain (needs many unique chars for entropy > 4.2)
    result = analyze_url("http://a1b2c3d4e5f6g7h8i9j0klmnopqrstu.com")
    assert result["score"] >= 20
    assert "High domain entropy" in result["reason"]

def test_analyze_homoglyph():
    result = analyze_url("http://www.g00gle.com")
    assert result["score"] >= 30
    assert "typosquatting" in result["reason"]
