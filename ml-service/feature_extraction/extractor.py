"""
URL structural feature extractor for Scikit-learn training and FastAPI inference.
"""

import math
import re
from urllib.parse import unquote, urlparse

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

REDIRECT_PARAMS = {
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return",
    "return_to", "returnto", "continue", "destination", "dest", "target",
    "forward", "callback", "redir", "goto", "out",
}

AUTH_PATH_KEYWORDS = {
    "login", "signin", "sign-in", "auth", "authenticate", "authentication",
    "account", "accounts", "verify", "verification", "password", "billing",
    "payment", "session", "oauth", "sso", "confirm", "security",
}

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "subdomain_count",
    "maximum_subdomain_length",
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
    "encoded_character_ratio",
    "nested_url_detected",
    "redirect_parameter_count",
    "query_parameter_count",
    "unusual_port",
    "suspicious_authentication_path",
    "hostname_case_normalized",
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
    raw_url = url.strip()
    parsed = urlparse(raw_url)
    raw_host = (parsed.netloc.split("@")[-1].split(":")[0]) if parsed.netloc else ""
    hostname = (parsed.hostname or "").lower().rstrip(".")
    labels = [lbl for lbl in hostname.split(".") if lbl]
    tld = labels[-1] if labels else ""
    is_ip = bool(
        re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)
        or re.match(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", hostname, re.I)
        or ":" in hostname
    )
    subdomains = [] if is_ip else labels[:-2]
    subdomain_count = len(subdomains)
    max_sub_len = max((len(s) for s in subdomains), default=0)
    hyphen_count = hostname.count("-")
    dot_count = hostname.count(".")
    special_char_count = len(re.findall(r"[@!$&'*+,;=~%]", raw_url))
    digits = sum(1 for c in raw_url if c.isdigit())
    digit_ratio = digits / max(1, len(raw_url))
    has_at = int("@" in raw_url or bool(parsed.username))
    is_https = int(parsed.scheme == "https")
    is_punycode = int(any(lbl.startswith("xn--") for lbl in labels))
    has_suspicious_tld = int(tld in SUSPICIOUS_TLDS)
    is_shortener = int(hostname in URL_SHORTENERS)
    decoded_path = unquote(parsed.path)
    has_suspicious_ext = int(decoded_path.lower().endswith(SUSPICIOUS_EXTENSIONS))
    has_word_num = int(
        bool(re.search(r"[a-z]{3,}\d{3,}|\d{3,}[a-z]{3,}", hostname, re.I))
    )
    entropy = shannon_entropy(hostname + decoded_path)
    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", parsed.path + parsed.query)
    encoded_ratio = (len(encoded_matches) * 3) / max(1, len(parsed.path) + len(parsed.query))

    pairs = [p for p in parsed.query.split("&") if p]
    redirect_count = 0
    nested_url = 0
    for pair in pairs:
        k, _, v = pair.partition("=")
        k_norm = unquote(k).lower()
        v_dec = unquote(v)
        if k_norm in REDIRECT_PARAMS:
            redirect_count += 1
        if re.match(r"^https?://", v_dec, re.I):
            nested_url = 1

    port = parsed.port
    unusual_port = int(port is not None and port not in (80, 443))
    path_tokens = [t for t in re.split(r"[^a-z0-9-]+", decoded_path.lower()) if t]
    auth_path = int(any(t in AUTH_PATH_KEYWORDS for t in path_tokens))
    case_mixed = int(raw_host != raw_host.lower() and raw_host != raw_host.upper())

    return [
        float(min(len(raw_url), 500)),
        float(min(len(hostname), 120)),
        float(min(len(decoded_path), 200)),
        float(subdomain_count),
        float(max_sub_len),
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
        float(encoded_ratio),
        float(nested_url),
        float(redirect_count),
        float(len(pairs)),
        float(unusual_port),
        float(auth_path),
        float(case_mixed),
    ]
