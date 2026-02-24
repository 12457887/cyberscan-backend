from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver


DEFAULT_SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "smtp",
    "ns1",
    "ns2",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "blog",
    "cdn",
    "static",
    "m",
    "mobile",
    "app",
    "beta",
    "shop",
    "store",
    "secure",
    "img",
    "files",
]

FULL_SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "smtp",
    "ns1",
    "ns2",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "blog",
    "cdn",
    "static",
    "m",
    "mobile",
    "app",
    "beta",
    "shop",
    "store",
    "secure",
    "img",
    "files",
    "assets",
    "gateway",
    "intranet",
    "extranet",
    "vpn",
    "sso",
    "auth",
    "login",
    "status",
    "monitor",
    "dashboard",
    "support",
    "help",
    "docs",
    "api-v1",
    "api-v2",
    "dev1",
    "dev2",
    "stage",
    "uat",
    "qa",
    "preprod",
    "preview",
    "sandbox",
    "webmail",
    "cpanel",
    "git",
    "gitlab",
    "jira",
    "confluence",
    "jenkins",
    "ci",
    "cdn2",
    "static2",
]


def _extract_domain(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or parsed.path.split("/")[0]
    except Exception:
        return None

    if not host:
        return None

    host = host.strip().lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host or None


def _load_wordlist(wordlist: Optional[Iterable[str]], mode: str = "light") -> List[str]:
    if wordlist:
        return [str(entry).strip() for entry in wordlist if str(entry).strip()]

    normalized = str(mode or "light").strip().lower()
    is_full = normalized in {"full", "complete"}
    if is_full:
        path = os.getenv("SUBDOMAIN_WORDLIST_PATH")
        if path and os.path.isfile(path):
            words: List[str] = []
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    for line in handle:
                        value = line.strip()
                        if value and not value.startswith("#"):
                            words.append(value)
            except Exception:
                pass
            if words:
                return words

        return FULL_SUBDOMAIN_WORDLIST.copy()

    return DEFAULT_SUBDOMAIN_WORDLIST.copy()


def find_subdomains(
    target: str,
    wordlist: Optional[Iterable[str]] = None,
    mode: str = "light",
    max_workers: int = 25,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    domain = _extract_domain(target)
    if not domain:
        raise ValueError("Domaine invalide")

    words = _load_wordlist(wordlist, mode)
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results: List[Dict[str, Any]] = []

    def resolve_name(sub: str) -> Optional[Dict[str, Any]]:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [r.to_text() for r in answers]
            if ips:
                return {"subdomain": fqdn, "ips": ips}
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(resolve_name, word): word for word in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda item: item.get("subdomain", ""))

    return {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "subdomains": results,
        "mode": "full" if str(mode).strip().lower() in {"full", "complete"} else "light",
        "source": "subdomain_finder",
    }
