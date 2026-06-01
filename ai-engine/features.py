import math
import re
from urllib.parse import urlparse

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def extract_features(url: str) -> dict:
    """Extracts numerical features from a URL for ML classification."""
    features = {
        "url_length": len(url),
        "domain_entropy": 0.0,
        "subdomain_count": 0,
        "is_ip": 0,
        "suspicious_word_count": 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "path_length": 0,
        "path_segments": 0,
        "special_chars_count": sum(1 for c in url if c in "-_?=&"),
        "has_suspicious_tld": 0,
        "is_data_uri": 1 if url.startswith("data:") else 0,
    }
    
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        pathname = (parsed.path or "").lower()
    except Exception:
        return features
        
    features["path_length"] = len(pathname)
    features["path_segments"] = len([s for s in pathname.split("/") if s])
    
    if hostname:
        parts = hostname.split(".")
        features["subdomain_count"] = max(0, len(parts) - 2)
        features["domain_entropy"] = _entropy(".".join(parts[:-1]))
        
        # Raw IP check
        if re.match(r"^[0-9.]+$", hostname) or re.match(r"^\[.*\]$", hostname):
            features["is_ip"] = 1
            
        tld = parts[-1] if len(parts) >= 2 else ""
        suspicious_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "work", "icu", "cam", "rest", "sbs"}
        if tld in suspicious_tlds:
            features["has_suspicious_tld"] = 1
            
    # Suspicious words
    suspicious_words = [
        "update", "banking", "credential", "reset", "billing", "suspended",
        "verify", "login", "auth", "account", "security", "wallet", 
        "metamask", "recovery", "locked", "confirm", "support", "invoice"
    ]
    for w in suspicious_words:
        if w in url.lower():
            features["suspicious_word_count"] += 1
            
    return features
