import math
import re
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote
# ==========================
# Configuration
# ==========================
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "buzz", "club",
    "work", "icu", "cam", "rest",
    "sbs", "click", "zip", "review",
    "country", "stream", "download"
}
SUSPICIOUS_WORDS = [
    "update", "banking", "credential", "reset",
    "billing", "suspended", "verify", "login",
    "auth", "account", "security", "wallet",
    "metamask", "recovery", "locked", "confirm",
    "support", "invoice", "secure", "password",
    "signin", "validate", "unlock", "payment",
    "paypal", "amazon", "microsoft", "apple",
    "google", "crypto", "webmail", "alert"
]
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at"
}
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd",
    ".ps1", ".vbs", ".jar", ".msi",
    ".dll", ".com", ".apk"
}
# ==========================
# Utility Functions
# ==========================
def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )

def _safe_ratio(part, total):
    return part / total if total > 0 else 0.0

def _is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return 1
    except:
        return 0

def _contains_unicode(text):
    try:
        text.encode("ascii")
        return 0
    except:
        return 1

def _count_special_chars(url):
    return sum(
        1 for c in url
        if not c.isalnum()
    )

# ==========================
# Main Feature Extractor
# ==========================

def extract_features(url: str) -> dict:
    """
    Advanced phishing URL feature extraction.
    Generates ~50 ML features.
    """
    url = str(url).strip()
    features = {}

    # ==================================================
    # Raw URL Metrics
    # ==================================================
    features["url_length"] = len(url)
    features["digit_count"] = sum(c.isdigit() for c in url)
    features["letter_count"] = sum(c.isalpha() for c in url)
    features["uppercase_count"] = sum(c.isupper() for c in url)
    features["lowercase_count"] = sum(c.islower() for c in url)
    features["special_char_count"] = _count_special_chars(url)
    features["digit_ratio"] = _safe_ratio(
        features["digit_count"],
        max(len(url), 1)
    )
    features["special_char_ratio"] = _safe_ratio(
        features["special_char_count"],
        max(len(url), 1)
    )
    features["uppercase_ratio"] = _safe_ratio(
        features["uppercase_count"],
        max(len(url), 1)
    )
    features["url_entropy"] = _entropy(url)

    # ==================================================
    # Parse URL
    # ==================================================

    try:
        parsed = urlparse(url)
    except:
        return features
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # ==================================================
    # URL Structure Features
    # ==================================================

    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    features["fragment_length"] = len(fragment)
    features["path_segments"] = len(
        [x for x in path.split("/") if x]
    )
    features["subdomain_count"] = max(
        0,
        len(hostname.split(".")) - 2
    )
    features["parameter_count"] = len(parse_qs(query))
    features["has_fragment"] = 1 if fragment else 0
    features["has_query"] = 1 if query else 0
    features["has_port"] = 1 if parsed.port else 0

    # ==================================================
    # Security Indicators
    # ==================================================

    features["https_used"] = (
        1 if parsed.scheme.lower() == "https"
        else 0
    )
    features["has_at_symbol"] = (
        1 if "@" in url else 0
    )
    features["double_slash_redirect"] = (
        1 if "//" in path else 0
    )
    features["contains_hex_encoding"] = (
        1 if re.search(r"%[0-9a-fA-F]{2}", url)
        else 0
    )
    features["contains_base64_pattern"] = (
        1 if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", url)
        else 0
    )

    # ==================================================
    # Domain Features
    # ==================================================

    features["is_ip"] = _is_ip(hostname)
    features["contains_punycode"] = (
        1 if "xn--" in hostname else 0
    )
    features["contains_unicode"] = (
        _contains_unicode(url)
    )
    parts = hostname.split(".")
    tld = parts[-1] if len(parts) >= 2 else ""
    features["tld_length"] = len(tld)
    features["has_suspicious_tld"] = (
        1 if tld in SUSPICIOUS_TLDS else 0
    )
    features["hostname_token_count"] = len(
        [p for p in re.split(r"[\.-]", hostname) if p]
    )

    # ==================================================
    # Entropy Features
    # ==================================================

    features["domain_entropy"] = _entropy(hostname)
    features["path_entropy"] = _entropy(path)
    features["query_entropy"] = _entropy(query)

    # ==================================================
    # Character Counts
    # ==================================================

    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["underscore_count"] = url.count("_")
    features["slash_count"] = url.count("/")
    features["question_mark_count"] = url.count("?")
    features["ampersand_count"] = url.count("&")
    features["equals_count"] = url.count("=")

    # ==================================================
    # URL Shorteners
    # ==================================================

    features["is_shortened_url"] = (
        1 if hostname in URL_SHORTENERS else 0
    )

    # ==================================================
    # Executable Indicators
    # ==================================================

    lower_path = path.lower()
    features["executable_extension"] = (
        1 if any(
            lower_path.endswith(ext)
            for ext in EXECUTABLE_EXTENSIONS
        )
        else 0
    )

    # ==================================================
    # Keyword Analysis
    # ==================================================

    lower_url = url.lower()
    suspicious_count = 0
    for word in SUSPICIOUS_WORDS:
        if word in lower_url:
            suspicious_count += 1

    features["suspicious_word_count"] = suspicious_count
    features["contains_login"] = (
        1 if "login" in lower_url else 0
    )
    features["contains_verify"] = (
        1 if "verify" in lower_url else 0
    )
    features["contains_account"] = (
        1 if "account" in lower_url else 0
    )
    features["contains_secure"] = (
        1 if "secure" in lower_url else 0
    )
    features["contains_update"] = (
        1 if "update" in lower_url else 0
    )
    features["contains_banking"] = (
        1 if "bank" in lower_url else 0
    )
    features["contains_wallet"] = (
        1 if "wallet" in lower_url else 0
    )
    features["contains_auth"] = (
        1 if "auth" in lower_url else 0
    )

    # ==================================================
    # Token Metrics
    # ==================================================

    tokens = [
        t for t in re.split(
            r"[\/\.\-\_\?\=&]+",
            lower_url
        )
        if t
    ]
    features["token_count"] = len(tokens)
    if tokens:
        token_lengths = [len(t) for t in tokens]

        features["avg_token_length"] = (
            sum(token_lengths) / len(token_lengths)
        )
        features["max_token_length"] = max(
            token_lengths
        )
    else:
        features["avg_token_length"] = 0
        features["max_token_length"] = 0

    features["keyword_density"] = _safe_ratio(
        suspicious_count,
        max(len(tokens), 1)
    )

    # ==================================================
    # Diversity Metrics
    # ==================================================

    unique_chars = len(set(url))
    features["character_diversity"] = (
        _safe_ratio(
            unique_chars,
            max(len(url), 1)
        )
    )
    features["long_query_string"] = (
        1 if len(query) > 100 else 0
    )
    features["is_data_uri"] = (
        1 if url.startswith("data:")
        else 0
    )
    return features
