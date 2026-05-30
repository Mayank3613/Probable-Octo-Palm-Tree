"""Probable-Octo-Palm-Tree Domain Intelligence Service — DNS + WHOIS lookups"""

import asyncio
from typing import Any


async def lookup_domain(domain: str) -> dict[str, Any]:
    """Perform DNS resolution and WHOIS lookup for a domain.
    Returns partial results on failure instead of raising."""

    result: dict[str, Any] = {
        "domain": domain,
        "ip_addresses": [],
        "registrar": None,
        "creation_date": None,
        "name_servers": [],
        "country": None,
        "dnssec": None,
        "tls_valid": None,
        "tls_issuer": None,
        "is_suspicious": False,
        "suspicion_reasons": []
    }

    # 1. DNS Resolution
    try:
        import dns.resolver
        answers = await asyncio.to_thread(_dns_resolve, domain)
        result["ip_addresses"] = answers
    except Exception as e:
        result["ip_addresses"] = [f"DNS resolution failed: {e}"]

    # 2. WHOIS Lookup
    try:
        whois_data = await asyncio.to_thread(_whois_lookup, domain)
        result.update(whois_data)
    except Exception as e:
        result["registrar"] = f"WHOIS lookup failed: {e}"

    # 3. TLS / SSL Lookup
    try:
        tls_data = await asyncio.to_thread(_tls_lookup, domain)
        result.update(tls_data)
    except Exception as e:
        result["tls_valid"] = False
        result["tls_issuer"] = f"TLS lookup failed: {e}"

    # 4. Suspicion heuristics
    suspicious_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "icu"}
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    if tld in suspicious_tlds:
        result["is_suspicious"] = True
        result["suspicion_reasons"].append(f"Suspicious TLD: .{tld}")

    # Check domain age (if creation_date is available and recent)
    if result["creation_date"]:
        try:
            from datetime import datetime, timezone
            created = datetime.fromisoformat(result["creation_date"].replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < 30:
                result["is_suspicious"] = True
                result["suspicion_reasons"].append(f"Domain is very young ({age_days} days old)")
        except (ValueError, TypeError):
            pass
            
    # Check DNS Fast-Flux
    if isinstance(result.get("ip_addresses"), list) and len(result["ip_addresses"]) > 3:
        result["is_suspicious"] = True
        result["suspicion_reasons"].append(f"Possible DNS Fast-Flux ({len(result['ip_addresses'])} IPs returned)")
        
    # Check TLS anomalies
    if result.get("tls_valid") is False and "failed" not in str(result.get("tls_issuer")):
        result["is_suspicious"] = True
        result["suspicion_reasons"].append("Invalid or Self-Signed TLS Certificate")

    return result


def _dns_resolve(domain: str) -> list[str]:
    """Synchronous DNS A record lookup."""
    import dns.resolver
    try:
        answers = dns.resolver.resolve(domain, "A")
        return [rdata.address for rdata in answers]
    except dns.resolver.NXDOMAIN:
        return ["NXDOMAIN — domain does not exist"]
    except dns.resolver.NoAnswer:
        return ["No A records found"]
    except dns.resolver.Timeout:
        return ["DNS timeout"]
    except Exception as e:
        return [f"DNS error: {str(e)}"]


def _whois_lookup(domain: str) -> dict[str, Any]:
    """Synchronous WHOIS lookup."""
    import whois

    w = whois.whois(domain)
    result: dict[str, Any] = {}

    # Registrar
    result["registrar"] = w.registrar if w.registrar else None

    # Creation date
    if w.creation_date:
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        result["creation_date"] = cd.isoformat() if hasattr(cd, "isoformat") else str(cd)
    else:
        result["creation_date"] = None

    # Name servers
    ns = w.name_servers
    if ns:
        if isinstance(ns, list):
            result["name_servers"] = [str(n).lower() for n in ns]
        else:
            result["name_servers"] = [str(ns).lower()]
    else:
        result["name_servers"] = []

    # Country
    result["country"] = w.country if hasattr(w, "country") and w.country else None

    # DNSSEC
    result["dnssec"] = w.dnssec if hasattr(w, "dnssec") and w.dnssec else None

    return result

def _tls_lookup(domain: str) -> dict[str, Any]:
    """Synchronous TLS certificate lookup."""
    import ssl
    import socket
    
    result = {"tls_valid": False, "tls_issuer": None}
    
    context = ssl.create_default_context()
    # Don't fail immediately on bad cert, we want to capture it
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                
        # Now do strict validation to see if it's valid
        strict_context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with strict_context.wrap_socket(sock, server_hostname=domain) as ssock:
                strict_cert = ssock.getpeercert()
                # If we get here, it's valid
                result["tls_valid"] = True
                
                # Try to extract issuer
                issuer = dict(x[0] for x in strict_cert.get('issuer', []))
                result["tls_issuer"] = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                
    except ssl.SSLCertVerificationError as e:
        result["tls_valid"] = False
        result["tls_issuer"] = "Self-Signed or Invalid Chain"
    except Exception as e:
        result["tls_valid"] = False
        result["tls_issuer"] = f"Failed to connect: {e}"
        
    return result
