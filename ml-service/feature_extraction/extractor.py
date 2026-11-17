"""
URL structural feature extractor for Scikit-learn training and FastAPI inference.
"""

import math
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "buzz", "club",
    "icu", "sbs", "cyou", "cfd", "pw", "su", "ws", "zip", "mov", "online",
    "site", "info", "cc", "ru", "cn",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "t.ly", "short.io",
}

SUSPICIOUS_EXTENSIONS = (
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".hta", ".apk", ".iso"
)

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "subdomain_count",
    "hyphen_count",
    "dot_count",
    "special_char_count",
    "digit_ratio",
    "has_ip_address",
    "has_at_symbol",
    "is_https",
    "is_punycode",
    "has_suspicious_tld",
    "is_url_shortener",
    "has_suspicious_extension",
    "has_word_number_anomaly",
    "char_entropy",
]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return round(-sum((c / length) * math.log2(c / length) for c in freq.values()), 4)


def extract_structural_vector(url: str) -> list[float]:
    parsed = urlparse(url.strip())
    hostname = (parsed.hostname or "").lower().rstrip(".")
    labels = [lbl for lbl in hostname.split(".") if lbl]
    tld = labels[-1] if labels else ""
    is_ip = bool(
        re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)
        or re.match(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", hostname, re.I)
        or ":" in hostname
    )
    subdomain_count = 0 if is_ip else max(0, len(labels) - 2)
    hyphen_count = hostname.count("-")
    dot_count = hostname.count(".")
    special_char_count = len(re.findall(r"[@!$&'*+,;=~%]", url))
    digits = sum(1 for c in url if c.isdigit())
    digit_ratio = digits / max(1, len(url))
    has_at = int("@" in url or bool(parsed.username))
    is_https = int(parsed.scheme == "https")
    is_punycode = int(any(lbl.startswith("xn--") for lbl in labels))
    has_suspicious_tld = int(tld in SUSPICIOUS_TLDS)
    is_shortener = int(hostname in URL_SHORTENERS)
    has_suspicious_ext = int(parsed.path.lower().endswith(SUSPICIOUS_EXTENSIONS))
    has_word_num = int(
        bool(re.search(r"[a-z]{3,}\d{3,}|\d{3,}[a-z]{3,}", hostname, re.I))
    )
    entropy = shannon_entropy(hostname + parsed.path)

    return [
        float(min(len(url), 500)),
        float(min(len(hostname), 120)),
        float(min(len(parsed.path), 200)),
        float(subdomain_count),
        float(hyphen_count),
        float(dot_count),
        float(special_char_count),
        float(digit_ratio),
        float(int(is_ip)),
        float(has_at),
        float(is_https),
        float(is_punycode),
        float(has_suspicious_tld),
        float(is_shortener),
        float(has_suspicious_ext),
        float(has_word_num),
        float(entropy),
    ]
