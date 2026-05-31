from typing import List, Dict, Any
from ipwhois import IPWhois
import time

# Known bulletproof hosting / highly abused ASNs (simulated list for Phase 7)
HIGH_RISK_ASNS = {
    "AS20473": "Choopa, LLC (Vultr)",
    "AS14061": "DigitalOcean, LLC",
    "AS16276": "OVH SAS",
    "AS206264": "Amarutu Technology",
    "AS51852": "Private Layer INC",
}

def analyze_ip_cluster(ips: List[str]) -> Dict[str, Any]:
    """
    Takes a list of IP addresses (e.g. from a DNS resolution of a malicious domain)
    and maps them to their Autonomous System Numbers (ASN).
    Calculates an infrastructure risk score based on known bulletproof/abused hosts.
    """
    result = {
        "analyzed_ips": len(ips),
        "clusters": {},
        "high_risk_score": 0,
        "is_suspicious_infrastructure": False,
        "warnings": []
    }
    
    for ip in ips:
        try:
            obj = IPWhois(ip)
            # Perform basic lookup
            res = obj.lookup_rdap(depth=1)
            
            asn = res.get('asn')
            asn_description = res.get('asn_description')
            asn_cidr = res.get('asn_cidr')
            asn_country = res.get('asn_country_code')
            
            if asn not in result["clusters"]:
                result["clusters"][asn] = {
                    "description": asn_description,
                    "cidr": asn_cidr,
                    "country": asn_country,
                    "ips": []
                }
            
            result["clusters"][asn]["ips"].append(ip)
            
            # Risk scoring
            if f"AS{asn}" in HIGH_RISK_ASNS:
                result["high_risk_score"] += 10
                result["warnings"].append(f"IP {ip} hosted on known high-risk ASN: AS{asn} ({HIGH_RISK_ASNS[f'AS{asn}']})")
                
            time.sleep(0.5) # Rate limiting for public whois APIs
            
        except Exception as e:
            result["warnings"].append(f"Failed to lookup IP {ip}: {str(e)}")
            
    if result["high_risk_score"] > 0:
        result["is_suspicious_infrastructure"] = True
        
    return result

if __name__ == "__main__":
    # Test execution
    res = analyze_ip_cluster(["8.8.8.8", "1.1.1.1"])
    print(res)
