"""
tests/test_detector.py
Unit tests for the Phishing URL Detector heuristics.
Run with: pytest tests/
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detector import check_url, shannon_entropy


# ── Entropy ───────────────────────────────────────────────────────────────────
def test_entropy_empty():
    assert shannon_entropy("") == 0.0

def test_entropy_uniform():
    # All same chars → entropy 0
    assert shannon_entropy("aaaa") == 0.0

def test_entropy_high():
    # Random-looking string
    assert shannon_entropy("xk7qz2mp9w") > 3.0


# ── IP address detection ───────────────────────────────────────────────────────
def test_ip_address_flagged():
    r = check_url("http://192.168.1.1/login")
    flags_text = " ".join(r["flags"])
    assert "IP" in flags_text or "raw IP" in flags_text.lower() or r["score"] >= 30

def test_ip_address_score():
    r = check_url("http://10.0.0.1/verify")
    assert r["score"] >= 30


# ── HTTP (no HTTPS) ───────────────────────────────────────────────────────────
def test_http_flagged():
    r = check_url("http://example.com")
    flags_text = " ".join(r["flags"])
    assert "HTTPS" in flags_text or "unencrypted" in flags_text.lower()

def test_https_no_http_flag():
    r = check_url("https://example.com")
    flags_text = " ".join(r["flags"])
    assert "unencrypted" not in flags_text.lower()


# ── Suspicious TLD ────────────────────────────────────────────────────────────
def test_suspicious_tld():
    r = check_url("https://fakebank.tk")
    assert r["score"] >= 20
    assert any("TLD" in f for f in r["flags"])

def test_normal_tld():
    r = check_url("https://example.com")
    assert not any("TLD" in f for f in r["flags"])


# ── URL shortener ─────────────────────────────────────────────────────────────
def test_shortener_detected():
    r = check_url("http://bit.ly/abc123")
    assert any("shortener" in f.lower() for f in r["flags"])


# ── Keywords ──────────────────────────────────────────────────────────────────
def test_keyword_login():
    r = check_url("https://secure-login-verify.com/account")
    assert any("keyword" in f.lower() or "phishing" in f.lower() for f in r["flags"])

def test_no_keywords_clean():
    r = check_url("https://weather.example.com/forecast")
    assert not any("keyword" in f.lower() for f in r["flags"])


# ── @ symbol trick ────────────────────────────────────────────────────────────
def test_at_symbol():
    r = check_url("http://real.bank.com@evil.com/login")
    assert r["score"] >= 25
    assert any("@" in f for f in r["flags"])


# ── Excessive subdomains ──────────────────────────────────────────────────────
def test_excessive_subdomains():
    r = check_url("https://login.secure.account.update.evil.com/")
    assert any("subdomain" in f.lower() for f in r["flags"])


# ── Blocklist ─────────────────────────────────────────────────────────────────
def test_blocklist_hit():
    r = check_url("http://paypa1-secure.tk/login")
    assert r["risk_level"] == "Critical"
    assert any("blocklist" in f.lower() for f in r["flags"])


# ── Risk level bucketing ──────────────────────────────────────────────────────
def test_clean_url_low_risk():
    r = check_url("https://www.github.com")
    assert r["risk_level"] == "Low"

def test_obviously_malicious_critical():
    r = check_url("http://paypa1-secure.tk/login/verify@evil.com")
    assert r["risk_level"] == "Critical"


# ── Punycode ──────────────────────────────────────────────────────────────────
def test_punycode_flagged():
    r = check_url("https://xn--pple-43d.com/")
    assert any("punycode" in f.lower() or "homograph" in f.lower() for f in r["flags"])


# ── Long URL ──────────────────────────────────────────────────────────────────
def test_long_url_flagged():
    long = "https://example.com/" + "a" * 100
    r = check_url(long)
    assert any("long" in f.lower() for f in r["flags"])
