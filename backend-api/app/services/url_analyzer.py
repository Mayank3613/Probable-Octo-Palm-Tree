"""OctoPlamTree Server-Side URL Threat Analyzer
Mirrors the browser extension's url-analyzer.js logic on the backend.
"""

import math
import re
from urllib.parse import urlparse

# ============================================================
# TRUSTED DOMAINS — Never flag these
# ============================================================
TRUSTED_DOMAINS = {
    # Google
    "google.com", "googleapis.com", "googleusercontent.com", "googlevideo.com",
    "googleadservices.com", "googletagmanager.com", "googlesyndication.com",
    "gstatic.com", "youtube.com", "youtu.be", "ytimg.com",
    "gmail.com", "android.com", "chromium.org",
    "firebase.google.com", "firebaseio.com", "withgoogle.com",
    "blogger.com", "blogspot.com",
    # Microsoft
    "microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
    "office.com", "office365.com", "windows.com", "windowsupdate.com",
    "msn.com", "bing.com", "azure.com", "azurewebsites.net",
    "sharepoint.com", "onedrive.com", "onenote.com",
    "skype.com", "visualstudio.com", "github.com", "github.io",
    "githubusercontent.com", "linkedin.com",
    # Apple
    "apple.com", "icloud.com", "mzstatic.com",
    # Meta
    "facebook.com", "fb.com", "fbcdn.net", "instagram.com",
    "whatsapp.com", "whatsapp.net", "messenger.com", "meta.com",
    # Amazon
    "amazon.com", "amazonaws.com", "cloudfront.net",
    "primevideo.com", "twitch.tv",
    # Other
    "twitter.com", "x.com", "twimg.com",
    "netflix.com", "nflxvideo.net",
    "paypal.com", "paypalobjects.com",
    "yahoo.com", "yimg.com",
    "reddit.com", "redd.it", "redditstatic.com",
    "wikipedia.org", "wikimedia.org",
    "stackoverflow.com", "stackexchange.com",
    "discord.com", "discordapp.com", "discord.gg",
    "telegram.org", "t.me",
    "zoom.us", "spotify.com", "scdn.co",
    "dropbox.com", "dropboxusercontent.com",
    "steampowered.com", "steamcommunity.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com",
    "coinbase.com", "binance.com",
    # CDNs
    "cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "fastly.net", "akamaihd.net", "bootstrapcdn.com",
    # Dev
    "npmjs.com", "pypi.org", "crates.io",
    "vercel.app", "netlify.app", "pages.dev",
}

SUSPICIOUS_WORDS = [
    "update-password", "banking", "credential", "reset-pass",
    "billing-update", "suspended", "unusual-activity",
    "paymentupdate", "helpdesk", "support-portal",
]

DOMAIN_ONLY_SUSPICIOUS = [
    "login", "verify", "signin", "accounts", "secure",
    "verification", "confirm", "restore", "unlock",
    "authenticate", "recovery", "wallet",
]

TARGET_BRANDS = [
    "google", "paypal", "microsoft", "apple", "netflix", "amazon",
    "facebook", "github", "chase", "bankofamerica", "wellsfargo",
    "binance", "coinbase", "instagram", "twitter", "linkedin",
    "dropbox", "icloud", "outlook", "yahoo", "steam", "discord",
    "whatsapp", "telegram",
]

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "work", "icu", "cam", "rest"}


def _levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            tmp = dp[j]
            if a[i - 1] == b[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j - 1])
            prev = tmp
    return dp[n]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_trusted(hostname: str) -> bool:
    if hostname in TRUSTED_DOMAINS:
        return True
    for d in TRUSTED_DOMAINS:
        if hostname.endswith("." + d):
            return True
    return False


def _is_official_brand(hostname: str, brand: str) -> bool:
    for tld in ["com", "org", "net", "io"]:
        if hostname == f"{brand}.{tld}" or hostname.endswith(f".{brand}.{tld}"):
            return True
    return False


def analyze_url(url_string: str) -> dict:
    """Analyze a URL for phishing/malicious indicators. Returns dict with is_suspicious, score, reason."""
    try:
        parsed = urlparse(url_string)
        hostname = (parsed.hostname or "").lower()
        pathname = (parsed.path or "").lower()
        full_url = url_string.lower()
    except Exception:
        return {"is_suspicious": False, "score": 0, "reason": "Invalid URL format"}

    # Skip internal
    if hostname in ("localhost", "127.0.0.1") or parsed.scheme in ("chrome-extension", "chrome", "about", "file"):
        return {"is_suspicious": False, "score": 0, "reason": ""}

    # Trusted domains
    if _is_trusted(hostname):
        return {"is_suspicious": False, "score": 0, "reason": ""}

    score = 0
    reasons: list[str] = []
    parts = hostname.split(".")
    primary = parts[-2] if len(parts) >= 2 else hostname
    tld = parts[-1] if len(parts) >= 2 else ""

    # 1. Keywords in domain
    for w in SUSPICIOUS_WORDS:
        if w in hostname:
            score += 30
            reasons.append(f"Suspicious keyword '{w}' in domain")

    for w in DOMAIN_ONLY_SUSPICIOUS:
        if w in hostname:
            score += 25
            reasons.append(f"Suspicious keyword '{w}' in domain name")

    for w in SUSPICIOUS_WORDS:
        if w in pathname:
            score += 10
            reasons.append(f"Suspicious keyword '{w}' in path")

    # 2. Brand typosquatting
    for brand in TARGET_BRANDS:
        if brand in hostname:
            if not _is_official_brand(hostname, brand):
                score += 50
                reasons.append(f"Potential brand impersonation targeting '{brand}'")
        else:
            dist = _levenshtein(primary, brand)
            if dist == 1:
                score += 50
                reasons.append(f"Typosquatting targeting '{brand}' (distance: 1)")
            elif dist == 2 and len(primary) >= 5:
                score += 30
                reasons.append(f"Possible typosquatting targeting '{brand}' (distance: 2)")

    # 3. Entropy
    domain_no_tld = ".".join(parts[:-1])
    ent = _entropy(domain_no_tld)
    if ent > 4.2 and len(domain_no_tld) > 12:
        score += 20
        reasons.append(f"High domain entropy ({ent:.2f}) — possible DGA domain")

    # 4. Excessive subdomains
    sub_count = len(parts) - 2
    if sub_count > 4:
        score += 20
        reasons.append(f"{sub_count} subdomains detected")

    # 5. Raw IP
    if re.match(r"^[0-9.]+$", hostname) or re.match(r"^\[.*\]$", hostname):
        score += 25
        reasons.append("Hostname is a raw IP address")

    # 6. Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Suspicious TLD '.{tld}'")

    # 7. Punycode
    if hostname.startswith("xn--") or any(p.startswith("xn--") for p in parts):
        score += 30
        reasons.append("Punycode/IDN domain — possible homoglyph attack")

    # 8. Data URI
    if parsed.scheme == "data":
        score += 40
        reasons.append("Data URI scheme — common phishing vector")

    # 9. Deep path
    segs = [s for s in pathname.split("/") if s]
    if len(segs) > 7:
        score += 10
        reasons.append(f"Deep URL path ({len(segs)} segments)")

    # 10. @ sign
    if "@" in full_url and not parsed.scheme.startswith("mailto"):
        score += 30
        reasons.append("URL contains '@' — possible URL obfuscation")

    final = min(score, 100)
    return {
        "is_suspicious": final >= 35,
        "score": final,
        "reason": "; ".join(reasons),
    }
