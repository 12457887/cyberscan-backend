from bson import ObjectId
from urllib.parse import urlparse
import ipaddress
import socket
import requests

# =====================================================
# Message générique (UX / API public)
# =====================================================
GENERIC_SCAN_REFUSAL = "We cannot generate a report for that URL."

# =====================================================
# 🚫 Domaines publics interdits
# =====================================================
FORBIDDEN_ROOT_DOMAINS = {
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "google.com",
    "youtube.com",
    "twitter.com",
    "x.com",
    "tiktok.com",
    "linkedin.com",
}

# =====================================================
# 🚫 Redirecteurs publics
# =====================================================
FORBIDDEN_REDIRECT_DOMAINS = {
    "share.google",
    "drive.google.com",
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "linktr.ee",
}

# =====================================================
# 🚫 Hébergements publics (phishing / abuse)
# =====================================================
FORBIDDEN_HOSTING_DOMAINS = {
    "storage.googleapis.com",
    "firebaseapp.com",
    "web.app",
    "github.io",
    "raw.githubusercontent.com",
    "cloudfront.net",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "pastebin.com",
}

# =====================================================
# 🚫 TLD sensibles
# =====================================================
FORBIDDEN_TLDS = {
    ".gov",
    ".mil",
    ".int",
    ".xxx",
    ".porn",
    ".sex",
    ".adult",
    ".cam",
}

# =====================================================
# 🚫 Mots-clés interdits
# =====================================================
FORBIDDEN_KEYWORDS = {
    "sex",
    "porn",
    "xxx",
    "adult",
    "casino",
    "bet",
    "gamble",
}

# =====================================================
# 🔐 Ports autorisés
# =====================================================
ALLOWED_PORTS = {80, 443}


# =====================================================
# Utils
# =====================================================
def convert_objectid(data):
    if isinstance(data, dict):
        return {k: convert_objectid(v) for k, v in data.items()}
    if isinstance(data, list):
        return [convert_objectid(item) for item in data]
    if isinstance(data, ObjectId):
        return str(data)
    return data


def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
    )


def _resolve_and_validate_dns(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    if not infos:
        return False

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
            if _is_forbidden_ip(ip):
                return False
        except ValueError:
            return False

    return True


def _resolve_final_url(url: str) -> str | None:
    try:
        r = requests.head(
            url,
            allow_redirects=True,
            timeout=5,
            headers={"User-Agent": "CyberScan-Validator"}
        )
        return r.url
    except Exception:
        return None


# =====================================================
# 🎯 VALIDATEUR PRINCIPAL
# =====================================================
def validate_scan_target(url_value: str) -> tuple[bool, str | None]:

    # ─────────────────────────────
    # 1. Basic validation
    # ─────────────────────────────
    raw_value = (url_value or "").strip()
    if not raw_value:
        return False, GENERIC_SCAN_REFUSAL

    parsed = urlparse(raw_value)

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False, GENERIC_SCAN_REFUSAL

    # 🚫 NOUVEAU : blocage fragment (# phishing / obfuscation)
    if parsed.fragment:
        return False, GENERIC_SCAN_REFUSAL

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return False, GENERIC_SCAN_REFUSAL

    # ─────────────────────────────
    # 2. Block IP literals
    # ─────────────────────────────
    try:
        ipaddress.ip_address(hostname)
        return False, GENERIC_SCAN_REFUSAL
    except ValueError:
        pass

    # ─────────────────────────────
    # 3. Block forbidden domains
    # ─────────────────────────────
    for domain_group in (
        FORBIDDEN_ROOT_DOMAINS,
        FORBIDDEN_REDIRECT_DOMAINS,
        FORBIDDEN_HOSTING_DOMAINS,  # ✅ NOUVEAU (tu l’avais mais pas utilisé)
    ):
        for blocked in domain_group:
            if hostname == blocked or hostname.endswith(f".{blocked}"):
                return False, GENERIC_SCAN_REFUSAL

    # ─────────────────────────────
    # 4. Block forbidden TLDs
    # ─────────────────────────────
    for tld in FORBIDDEN_TLDS:
        if hostname.endswith(tld):
            return False, GENERIC_SCAN_REFUSAL

    # ─────────────────────────────
    # 5. Block forbidden keywords
    # ─────────────────────────────
    for keyword in FORBIDDEN_KEYWORDS:
        if keyword in hostname:
            return False, GENERIC_SCAN_REFUSAL

    # ─────────────────────────────
    # 6. DNS validation (SSRF / rebinding)
    # ─────────────────────────────
    if not _resolve_and_validate_dns(hostname):
        return False, GENERIC_SCAN_REFUSAL

    # ─────────────────────────────
    # 7. Port validation
    # ─────────────────────────────
    if parsed.port and parsed.port not in ALLOWED_PORTS:
        return False, GENERIC_SCAN_REFUSAL

    # ─────────────────────────────
    # 8. Final URL validation (anti redirect)
    # ─────────────────────────────
    final_url = _resolve_final_url(raw_value)
    if final_url:
        final_host = (urlparse(final_url).hostname or "").lower().rstrip(".")
        # Autoriser les redirections vers www. ou sous-domaines du même domaine racine
        if final_host and final_host != hostname:
            root_hostname = hostname.removeprefix("www.")
            root_final   = final_host.removeprefix("www.")
            if root_hostname != root_final and not final_host.endswith(f".{root_hostname}"):
                return False, GENERIC_SCAN_REFUSAL

    return True, None
