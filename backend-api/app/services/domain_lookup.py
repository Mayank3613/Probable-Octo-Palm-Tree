"""OctoPlamTree Domain Intelligence Service — DNS + WHOIS lookups"""

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
        "is_suspicious": False,
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

    # 3. Suspicion heuristics
    suspicious_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "icu"}
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    if tld in suspicious_tlds:
        result["is_suspicious"] = True

    # Check domain age (if creation_date is available and recent)
    if result["creation_date"]:
        try:
            from datetime import datetime, timezone
            created = datetime.fromisoformat(result["creation_date"].replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < 30:
                result["is_suspicious"] = True
        except (ValueError, TypeError):
            pass

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
