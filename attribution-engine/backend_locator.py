import dns.resolver
from typing import Dict, Any, List

# Common subdomains that attackers often forget to proxy through Cloudflare
UNMASKED_SUBDOMAINS = [
    "mail", "ftp", "cpanel", "webmail", "direct", 
    "dev", "staging", "test", "admin", "ssh"
]

def find_origin_ip(domain: str) -> Dict[str, Any]:
    """
    Attempts to bypass CDN protections (like Cloudflare) by querying
    historical or unmasked subdomains that often point directly to the origin server.
    """
    result = {
        "domain": domain,
        "is_cdn_masked": False,
        "primary_ips": [],
        "bypassed_ips": [],
        "cdn_provider": None,
        "success": True
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    
    # 1. Resolve primary domain
    try:
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            result["primary_ips"].append(rdata.to_text())
    except Exception:
        result["success"] = False
        return result
        
    # 2. Check if primary IPs belong to known CDNs (simplified check)
    # Cloudflare often uses nameservers like *.ns.cloudflare.com
    try:
        ns_answers = resolver.resolve(domain, 'NS')
        for rdata in ns_answers:
            ns = rdata.to_text().lower()
            if "cloudflare" in ns:
                result["is_cdn_masked"] = True
                result["cdn_provider"] = "Cloudflare"
            elif "awsdns" in ns:
                result["is_cdn_masked"] = True
                result["cdn_provider"] = "AWS CloudFront"
            elif "fastly" in ns:
                result["is_cdn_masked"] = True
                result["cdn_provider"] = "Fastly"
    except Exception:
        pass
        
    # 3. If masked, attempt subdomain brute-force to find origin
    if result["is_cdn_masked"]:
        for sub in UNMASKED_SUBDOMAINS:
            subdomain = f"{sub}.{domain}"
            try:
                sub_answers = resolver.resolve(subdomain, 'A')
                for rdata in sub_answers:
                    ip = rdata.to_text()
                    # If this IP is different from the primary IPs, it might be the origin
                    if ip not in result["primary_ips"] and ip not in result["bypassed_ips"]:
                        result["bypassed_ips"].append(ip)
            except Exception:
                continue
                
    return result

if __name__ == "__main__":
    # Test execution
    res = find_origin_ip("example.com")
    print(res)
