import sys
import os
import requests
import csv
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.services.url_analyzer import analyze_url
from app.services.domain_lookup import lookup_domain

def fetch_openphish() -> list[str]:
    print("[*] Fetching Phishing URLs from OpenPhish...")
    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=10)
        urls = [u for u in r.text.splitlines() if u.strip()]
        return urls
    except Exception as e:
        print(f"Error fetching OpenPhish: {e}")
        return []

def fetch_urlhaus() -> list[str]:
    print("[*] Fetching Malware URLs from URLhaus...")
    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=10)
        lines = [line.decode('utf-8') for line in r.iter_lines() if not line.startswith(b'#')]
        reader = csv.reader(lines)
        urls = [row[2] for row in reader if len(row) > 2]
        # Just grab 150
        return urls[:150]
    except Exception as e:
        print(f"Error fetching URLhaus: {e}")
        return []

async def test_domain_lookup():
    print("\n[*] Testing DNS/TLS/ASN Anomalies via domain_lookup.py...")
    # Domains that are notorious for issues or known malicious testing
    test_domains = [
        "expired.badssl.com",
        "wrong.host.badssl.com",
        "self-signed.badssl.com",
        "example.com",
    ]
    
    for d in test_domains:
        res = await lookup_domain(d)
        print(f"  -> {d}: Suspicious? {res.get('is_suspicious')} | IPs: {len(res.get('ip_addresses', []))}")
        
def evaluate_engine(name: str, urls: list[str]):
    if not urls:
        print(f"\n[!] Skipping {name} due to fetch error.")
        return
        
    print(f"\n[*] Evaluating Engine on {len(urls)} {name} URLs...")
    detected = 0
    missed = []
    
    for url in urls:
        res = analyze_url(url)
        if res["is_suspicious"] or res["score"] >= 35:
            detected += 1
        else:
            missed.append((res["score"], url))
            
    dr = (detected / len(urls)) * 100
    print(f"--- {name} Results ---")
    print(f"Total: {len(urls)} | Detected: {detected} | Missed: {len(missed)}")
    print(f"Detection Rate: {dr:.2f}%")
    
    if missed:
        print(f"Top 10 Missed {name} URLs:")
        missed.sort(key=lambda x: x[0], reverse=True)
        for s, u in missed[:10]:
            print(f"  Score {s} | {u}")

async def main():
    phish_urls = fetch_openphish()
    malware_urls = fetch_urlhaus()
    
    evaluate_engine("Phishing", phish_urls)
    evaluate_engine("Malware", malware_urls)
    
    await test_domain_lookup()

if __name__ == "__main__":
    asyncio.run(main())
