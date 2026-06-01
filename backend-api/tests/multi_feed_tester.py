"""
Probable-Octo-Palm-Tree — Multi-Feed Threat Tester
Tests the URL analyzer engine against live malicious feeds:
  1. URLhaus (Malware URLs)
  2. RapidDNS (DNS records)
  3. Shodan TLS (Certificate search)
"""

import requests
import re
import json
import sys
import time
from urllib.parse import urlparse

# ── Backend URL analyzer endpoint ────────────────────────────────────────────
SCAN_ENDPOINT = "http://127.0.0.1:8000/scan/url"

# ── Counters ─────────────────────────────────────────────────────────────────
stats = {
    "total": 0,
    "detected": 0,
    "missed": 0,
    "errors": 0,
    "by_source": {}
}

missed_urls = []

def scan_url(url, source):
    """Sends a URL to our backend scanner and returns the result."""
    stats["total"] += 1
    if source not in stats["by_source"]:
        stats["by_source"][source] = {"total": 0, "detected": 0, "missed": 0}
    stats["by_source"][source]["total"] += 1

    try:
        r = requests.post(SCAN_ENDPOINT, json={"url": url}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            is_sus = data.get("is_suspicious", False)
            score = data.get("score", 0)
            if is_sus:
                stats["detected"] += 1
                stats["by_source"][source]["detected"] += 1
                return True, score, data.get("reason", "")
            else:
                stats["missed"] += 1
                stats["by_source"][source]["missed"] += 1
                missed_urls.append({"url": url, "source": source, "score": score})
                return False, score, data.get("reason", "")
        else:
            stats["errors"] += 1
            return None, 0, f"HTTP {r.status_code}"
    except Exception as e:
        stats["errors"] += 1
        return None, 0, str(e)


# ── Feed 1: URLhaus Malware URLs ─────────────────────────────────────────────
def fetch_urlhaus_urls(max_urls=150):
    """Fetches recent malware URLs from URLhaus CSV feed."""
    print("\n[1/3] Fetching URLhaus malware URLs...")
    urls = []
    try:
        # URLhaus provides a CSV feed of recent URLs
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=15)
        if r.status_code == 200:
            lines = r.text.splitlines()
            for line in lines:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split('","')
                if len(parts) >= 3:
                    url = parts[2].strip('"').strip()
                    if url.startswith("http"):
                        urls.append(url)
                if len(urls) >= max_urls:
                    break
        print(f"    Fetched {len(urls)} malware URLs from URLhaus")
    except Exception as e:
        print(f"    ERROR fetching URLhaus: {e}")
    return urls


# ── Feed 2: RapidDNS suspicious domains ─────────────────────────────────────
def fetch_rapiddns_domains(max_domains=100):
    """Generates test URLs from known suspicious TLDs (simulating RapidDNS lookup)."""
    print("\n[2/3] Generating DNS-based suspicious test URLs...")
    # RapidDNS requires browser interaction, so we simulate with
    # known-bad TLD patterns that our engine should catch
    suspicious_domains = [
        # Suspicious TLD domains
        "login-verify-secure.xyz", "paypal-update-account.top",
        "microsoft-support-verify.buzz", "apple-id-confirm.club",
        "netflix-billing-update.icu", "amazon-security-alert.tk",
        "google-verify-account.ml", "facebook-login-secure.ga",
        "chase-banking-verify.cf", "wellsfargo-alert.gq",
        # Brand typosquatting
        "g00gle.com", "micr0soft.com", "amaz0n.com", "paypa1.com",
        "faceb00k.com", "netfl1x.com", "instagran.com", "linkedln.com",
        # Punycode/IDN
        "xn--pple-43d.com", "xn--googl-ysa.com",
        # IP-based URLs
        "http://185.243.112.55/malware.exe",
        "http://45.95.147.236/payload.bin",
        "http://91.215.85.142/update.js",
        # High-entropy DGA domains
        "http://a8f3k2m9x4p7q1.xyz/login",
        "http://zx9cv8bn7m6k5j4.top/verify",
        "http://q2w3e4r5t6y7u8i.buzz/account",
        # Deep path phishing
        "http://example.xyz/secure/login/verify/account/update/confirm/reset",
        # URL shorteners
        "http://bit.ly/3xMalware",
        "http://tinyurl.com/suspicious-link",
        # Data URI
        "data:text/html,<script>alert(1)</script>",
        # @ symbol in URL
        "http://google.com@evil-site.xyz/phishing",
        # Double dash domains
        "http://secure--login--paypal.xyz/verify",
        "http://microsoft--support--help.top/update",
    ]

    # Add HTTP versions for domain-only entries
    urls = []
    for d in suspicious_domains:
        if d.startswith("http") or d.startswith("data:"):
            urls.append(d)
        else:
            urls.append(f"http://{d}/login")
    
    print(f"    Generated {len(urls)} DNS/suspicious-TLD test URLs")
    return urls[:max_domains]


# ── Feed 3: Shodan TLS-style test cases ──────────────────────────────────────
def fetch_shodan_tls_urls(max_urls=50):
    """Generates TLS-related suspicious test URLs (simulating Shodan cert search)."""
    print("\n[3/3] Generating TLS/certificate-based suspicious test URLs...")
    # Shodan requires API key for programmatic access, so we generate
    # test cases that mimic what Shodan TLS search would return
    tls_suspicious = [
        # Self-signed / expired cert domains on suspicious TLDs
        "https://secure-banking-login.xyz",
        "https://verify-paypal-account.top",
        "https://update-microsoft-password.buzz",
        "https://netflix-billing-confirm.club",
        "https://apple-id-verification.icu",
        # Wildcard cert abuse patterns
        "https://login.account.verify.secure.update.paypal-service.xyz",
        "https://www.secure.login.banking.chase-online.top",
        # Certificate transparency log suspicious patterns
        "https://wallet-binance-secure.tk",
        "https://coinbase-verify-login.ml",
        "https://metamask-connect-wallet.ga",
        "https://steam-community-trade.cf",
        "https://discord-nitro-gift.gq",
        # Long subdomain chains (common in phishing with wildcard certs)
        "https://secure.login.verify.account.update.confirm.banking.xyz",
        "https://www.online.secure.banking.verify.credential.reset.top",
        # Brand impersonation with HTTPS
        "https://paypal-support-center.buzz",
        "https://amazon-order-confirmation.icu",
        "https://google-security-checkup.club",
        "https://instagram-verify-badge.xyz",
        "https://whatsapp-update-required.top",
    ]
    
    print(f"    Generated {len(tls_suspicious)} TLS/cert test URLs")
    return tls_suspicious[:max_urls]


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("Probable-Octo-Palm-Tree Multi-Feed Threat Tester")
    print("=" * 60)

    # Check if backend is running
    try:
        r = requests.get("http://127.0.0.1:8000/health", timeout=3)
        if r.status_code != 200:
            print("[ERROR] Backend API is not healthy!")
            sys.exit(1)
        print("[OK] Backend API is online and healthy")
    except:
        print("[ERROR] Backend API is not running! Start it first with:")
        print("  cd backend-api && uvicorn app.main:app --reload")
        sys.exit(1)

    # Fetch URLs from all feeds
    urlhaus_urls = fetch_urlhaus_urls(150)
    dns_urls = fetch_rapiddns_domains(100)
    tls_urls = fetch_shodan_tls_urls(50)

    all_tests = [
        ("URLhaus-Malware", urlhaus_urls),
        ("RapidDNS-Suspicious", dns_urls),
        ("Shodan-TLS", tls_urls),
    ]

    # Run tests
    for source_name, urls in all_tests:
        print(f"\n{'-' * 60}")
        print(f"Testing {source_name} ({len(urls)} URLs)")
        print(f"{'-' * 60}")
        
        for i, url in enumerate(urls):
            detected, score, reason = scan_url(url, source_name)
            status = "[DETECTED]" if detected else "[MISSED]  " if detected is False else "[ERROR]   "
            # Print first 20 and summary
            if i < 20 or detected is False:
                short_url = url[:70] + "..." if len(url) > 70 else url
                print(f"  {status} score={score:3d}  {short_url}")
            elif i == 20:
                print(f"  ... testing {len(urls) - 20} more URLs ...")

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    
    detection_rate = (stats["detected"] / max(stats["total"] - stats["errors"], 1)) * 100
    
    print(f"\n  Total URLs Tested:  {stats['total']}")
    print(f"  Detected:           {stats['detected']}")
    print(f"  Missed:             {stats['missed']}")
    print(f"  Errors:             {stats['errors']}")
    print(f"  Detection Rate:     {detection_rate:.1f}%")
    
    print(f"\n  Per-Feed Breakdown:")
    for source, s in stats["by_source"].items():
        rate = (s["detected"] / max(s["total"], 1)) * 100
        print(f"    {source:25s}  {s['detected']:3d}/{s['total']:3d}  ({rate:.1f}%)")
    
    if missed_urls:
        print(f"\n  Top Missed URLs (showing up to 15):")
        for m in missed_urls[:15]:
            short = m["url"][:65] + "..." if len(m["url"]) > 65 else m["url"]
            print(f"    [{m['source']}] score={m['score']:3d}  {short}")
    
    print("\n" + "=" * 60)
    
    if detection_rate >= 70:
        print(f"[PASS] Detection rate {detection_rate:.1f}% meets threshold (>= 70%)")
    else:
        print(f"[WARN] Detection rate {detection_rate:.1f}% below threshold (< 70%)")
    
    print("=" * 60)


if __name__ == "__main__":
    main()
