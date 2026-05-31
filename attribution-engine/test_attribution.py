import json
from cert_correlator import extract_certificate_sans
from backend_locator import find_origin_ip
from ip_cluster import analyze_ip_cluster

def run_attribution_test():
    print("="*50)
    print("Probable-Octo-Palm-Tree Attribution Engine Test")
    print("="*50)
    
    test_domain = "discord.com" # A legitimate domain that uses Cloudflare
    print(f"\n[*] Target Domain: {test_domain}")
    
    # 1. CDN Bypass Test
    print("\n[1] Running Backend Locator (CDN Bypass)...")
    origin_info = find_origin_ip(test_domain)
    print(json.dumps(origin_info, indent=2))
    
    # 2. IP Clustering Test
    print("\n[2] Running Infrastructure IP Clustering...")
    ips_to_check = origin_info.get("primary_ips", [])
    if ips_to_check:
        cluster_info = analyze_ip_cluster(ips_to_check)
        print(json.dumps(cluster_info, indent=2))
    else:
        print("No IPs resolved to cluster.")
        
    # 3. TLS Certificate SAN Extraction
    print("\n[3] Running Certificate SAN Extractor...")
    cert_info = extract_certificate_sans(test_domain)
    print(json.dumps(cert_info, indent=2))
    
    print("\n" + "="*50)
    print("Test Complete.")
    print("="*50)

if __name__ == "__main__":
    run_attribution_test()
