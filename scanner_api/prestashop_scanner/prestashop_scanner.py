import requests
import re
import subprocess
from bs4 import BeautifulSoup, Comment
import logging
import json
import tempfile
import uuid
from urllib.parse import urljoin, urlparse
from datetime import datetime
from http.cookies import SimpleCookie

logging.basicConfig(level=logging.INFO)

SCANNER_VERSION = "2.2"
SENSITIVE_PATHS = [
    'admin/', 'admin-dev/', 'admin123/', '.git/', '.env', 'phpinfo.php',
    'backup.zip', 'config.old.php'
]
SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "X-Frame-Options"
]
MAX_SQLMAP_URLS = 5

# =========================================================
# MODULE DETECTION & CLEANING
# =========================================================
def clean_modules(modules):
    """Filtre les vrais modules en supprimant les faux positifs (tokens, urls, etc.)."""
    ignore_patterns = [
        "token", "url", "option", "push", "cookie", "prestashop",
        "show_product", "static", "lang", "currency", "theme"
    ]
    clean = []
    for mod in modules:
        mod_lower = mod.lower()
        if any(pat in mod_lower for pat in ignore_patterns):
            continue
        # Normaliser les noms trop spécifiques
        mod_lower = re.sub(r'(_token|_static.*|_option)$', '', mod_lower)
        clean.append(mod_lower)
    return sorted(set(clean))


def detect_outdated_modules(html):
    """Détecte les modules et applique un filtrage intelligent."""
    soup = BeautifulSoup(html, 'html.parser')
    modules = set()

    # 1. Recherche dans balises src/href
    for tag in soup.find_all(['script', 'link', 'a']):
        url = tag.get('src') or tag.get('href')
        if url:
            matches = re.findall(r'(?:modules|themes)/([a-zA-Z0-9_-]+)', url, re.IGNORECASE)
            modules.update(matches)

    # 2. Inline HTML
    inline_matches = re.findall(r'(?:modules|themes)/([a-zA-Z0-9_-]+)', html, re.IGNORECASE)
    modules.update(inline_matches)

    # 3. Variables JS
    js_matches = re.findall(r'var\s+([a-zA-Z0-9_-]+)', html)
    for mod in js_matches:
        if any(prefix in mod.lower() for prefix in ["leo", "ps_", "ap", "module"]):
            modules.add(mod)

    # 4. HTML comments
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        matches = re.findall(r'(?:modules|themes)/([a-zA-Z0-9_-]+)', comment, re.IGNORECASE)
        modules.update(matches)

    return clean_modules(modules)

# =========================================================
# CVE MATCHING
# =========================================================
def load_cve_database(filepath='scanner_api/prestashop_scanner/cve_prestashop_finale.json'):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.warning(f"Could not load CVE database: {e}")
        return []

def match_cve(modules, version, cve_db):
    """Associe les modules/versions aux CVEs connues."""
    findings = []
    modules = [m.lower() for m in modules]  # normalisation

    for cve in cve_db:
        module_names = cve.get("module_name", [])
        if isinstance(module_names, str):
            module_names = [module_names.lower()]
        elif isinstance(module_names, list):
            module_names = [m.lower() for m in module_names if isinstance(m, str)]
        else:
            module_names = []

        description = cve.get("description", "")
        severity = cve.get("severity", "UNKNOWN").upper()

        # Match module exact ou par inclusion
        match_module = any(
            m in mod or mod in m for mod in modules for m in module_names
        )

        # Match version
        match_version = (
            version != "unknown"
            and isinstance(version, str)
            and version in description
        )

        if match_module or match_version:
            findings.append({
                "cve_id": cve.get("cve_id"),
                "description": description,
                "severity": severity,
                "cvss_score": cve.get("cvss_score"),
                "cvss_version": cve.get("cvss_version"),
                "cwe_id": cve.get("cwe_id"),
                "cwe_name": cve.get("cwe_name"),
                "module_name": cve.get("module_name"),
                "published": cve.get("published"),
                "nvd_reference": cve.get("nvd_reference")
            })

    return findings

# =========================================================
# CHECKS
# =========================================================
def check_admin_panel(base_url):
    findings = []
    error_signatures = ["404", "not found", "n'a pas été trouvée", "page non trouvée"]
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        try:
            response = requests.get(url, timeout=5)
            content = response.text.lower()
            has_error = any(err in content for err in error_signatures)
            if response.status_code == 200 and not has_error:
                findings.append(f"[+] Sensitive path exposed: {url}")
            elif response.status_code == 403:
                findings.append(f"[+] Forbidden but exists: {url}")
        except requests.RequestException:
            continue
    return findings


def check_cookie_flags(response):
    findings = []
    raw_cookies = response.headers.get('Set-Cookie', '')
    cookies = SimpleCookie()
    cookies.load(raw_cookies)

    for morsel in cookies.values():
        flags = morsel.output().lower()
        if 'httponly' not in flags or 'secure' not in flags:
            findings.append(f"[!] Missing HttpOnly or Secure flag for cookie: {morsel.key}")
    return findings


def check_security_headers(response):
    findings = []
    for header in SECURITY_HEADERS:
        if header not in response.headers:
            findings.append(f"[!] Missing security header: {header}")
    return findings

# =========================================================
# SCORE CALCULATION
# =========================================================
def calculate_score(findings):
    score = 100
    for f in findings:
        if f.startswith("[!]"):
            score -= 10
        elif f.startswith("[+]"):
            score -= 3
    return max(0, min(score, 100))

# =========================================================
# MAIN SCAN
# =========================================================
def run_prestascan(site, enable_sqlmap=False, save_json=True):
    results = {
        "site": site,
        "scanned_at": datetime.utcnow().isoformat(),
        "scanner_version": SCANNER_VERSION,
        "version_detected": "unknown",
        "modules_detected": [],
        "findings": [],
        "cves": [],
        "target": urlparse(site).netloc,
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "scan_id": str(uuid.uuid4())
    }

    try:
        response = requests.get(site, timeout=10)
        html = response.text

        # Check headers & cookies
        results["findings"].extend(check_cookie_flags(response))
        results["findings"].extend(check_security_headers(response))
        results["findings"].extend(check_admin_panel(site))

        # Detect modules
        modules = detect_outdated_modules(html)
        results["modules_detected"] = modules
        logging.info(f"Modules détectés : {modules}")

        # Charger CVEs et matcher
        cve_db = load_cve_database()
        cve_matches = match_cve(modules, results["version_detected"], cve_db)
        if cve_matches:
            results["cves"] = cve_matches
            results["findings"].append(f"[!] {len(cve_matches)} known vulnerabilities found.")

    except requests.RequestException as e:
        logging.error(f"Failed to scan {site}: {e}")
        results["findings"].append(f"[ERROR] Connection failed: {e}")

    # Score
    results["score"] = calculate_score(results["findings"])
    results["is_vulnerable"] = len(results["cves"]) > 0 or any(f.startswith("[!]") for f in results["findings"])

    # Save JSON
    if save_json:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8") as tmpfile:
            json.dump(results, tmpfile, indent=2, ensure_ascii=False)
            logging.info(f"Scan completed. Results saved to {tmpfile.name}")
            return results, tmpfile.name

    return results