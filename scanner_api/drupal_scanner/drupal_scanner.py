from pathlib import Path
import requests
import json
import re
import logging
import tempfile
import uuid
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from packaging import version as pkg_version

SCANNER_VERSION = "1.4"  # Version mise à jour
MAX_SQLMAP_URLS = 3

def check_cookie_flags(resp):
    """Vérifie les flags de sécurité des cookies"""
    findings = []
    for cookie in resp.cookies:
        issues = []
        
        if not cookie.secure:
            issues.append("Secure flag missing")
        if not cookie.has_nonstandard_attr('httponly'):
            issues.append("HttpOnly flag missing")
        if cookie.domain and cookie.domain.startswith('.'):
            issues.append("Overly broad domain")
        if cookie.expires and cookie.expires > datetime.now().timestamp() + 31536000:  # 1 year
            issues.append("Excessively long lifetime")
            
        if issues:
            findings.append(f"[!] Cookie '{cookie.name}' security issues: {', '.join(issues)}")
    
    return findings

def check_security_headers(resp):
    """Vérifie les en-têtes de sécurité HTTP"""
    findings = []
    headers = resp.headers
    
    # Liste des en-têtes recommandés avec leurs valeurs idéales
    security_headers = {
        'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
        'X-Content-Type-Options': ['nosniff'],
        'Content-Security-Policy': None,  # Toute présence est bonne
        'Strict-Transport-Security': None,
        'Referrer-Policy': ['no-referrer', 'no-referrer-when-downgrade', 'same-origin'],
        'Permissions-Policy': None,
        'X-XSS-Protection': ['1; mode=block']
    }
    
    for header, good_values in security_headers.items():
        if header not in headers:
            findings.append(f"[!] Missing security header: {header}")
        elif good_values is not None and headers[header] not in good_values:
            findings.append(f"[!] Suboptimal {header} value: {headers[header]} (recommended: {good_values[0]})")
    
    # Vérification spéciale pour CSP
    if 'Content-Security-Policy' in headers:
        csp = headers['Content-Security-Policy']
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            findings.append(f"[!] CSP contains unsafe directives: {csp}")
    
    return findings

def calculate_score(findings):
    """Calcule un score de sécurité basé sur les findings"""
    base_score = 100
    
    # Pénalités pour chaque type de finding
    penalties = {
        '[!] Cookie': 5,          # Problème de cookie
        '[!] Missing security': 10,  # En-tête manquant
        '[!] Suboptimal': 3,      # Valeur sous-optimale
        '[!] CSP contains': 8,    # CSP unsafe
        '[!] SQL Injection': 20,  # Injection SQL
        '[ERROR]': -30            # Erreur de scan (réduit la pénalité)
    }
    
    # Compter les pénalités
    penalty = 0
    for finding in findings:
        for prefix, value in penalties.items():
            if finding.startswith(prefix):
                penalty += value
                break
    
    # Ajuster le score final
    final_score = base_score - penalty
    return max(0, min(100, final_score))  # Garder entre 0 et 100

def detect_drupal_version(site):
    patterns = [
        r'Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        r'"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        r'v([0-9]+\.[0-9]+\.[0-9]+)',
        r'drupal-([0-9]+\.[0-9]+\.[0-9]+)'
    ]
    paths = ["CHANGELOG.txt", "core/CHANGELOG.txt", "README.txt", "core/README.txt"]
    
    for path in paths:
        url = urljoin(site, path)
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                for pat in patterns:
                    matches = re.findall(pat, r.text)
                    if matches:
                        return max(matches, key=lambda x: pkg_version.parse(x))
        except:
            continue

    try:
        r = requests.get(site, timeout=5, verify=False)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            
            # Check meta generator tag
            meta = soup.find('meta', {'name': 'Generator'})
            if meta and 'Drupal' in meta.get('content', ''):
                for pat in patterns:
                    m = re.search(pat, meta['content'])
                    if m:
                        return m.group(1)
            
            # Check JSON data in scripts
            scripts = soup.find_all("script", {"type": "application/json"})
            for s in scripts:
                try:
                    data = json.loads(s.string)
                    if "settings" in data and "path" in data.get("settings", {}):
                        for pat in patterns:
                            m = re.search(pat, json.dumps(data))
                            if m:
                                return m.group(1)
                except:
                    continue
            
            # Check CSS/JS files for version info
            for res in soup.find_all(['script', 'link']):
                src = res.get('src') or res.get('href') or ''
                if 'core/misc/drupal.js' in src or 'core/misc/drupal.css' in src:
                    try:
                        res_r = requests.get(urljoin(site, src), timeout=3, verify=False)
                        if res_r.status_code == 200:
                            for pat in patterns:
                                m = re.search(pat, res_r.text)
                                if m:
                                    return m.group(1)
                    except:
                        continue
    except Exception as e:
        logging.debug(f"Version detection error: {e}")
    
    return "unknown"

def detect_drupal_modules(html):
    soup = BeautifulSoup(html, 'html.parser')
    modules = set()
    
    # 1. Detect from scripts and links
    for tag in soup.find_all(['script', 'link', 'img']):
        src = tag.get('src') or tag.get('href') or ''
        for pattern in [
            r'/modules/([a-zA-Z0-9_-]+)/',
            r'/themes/([a-zA-Z0-9_-]+)/',
            r'/libraries/([a-zA-Z0-9_-]+)/',
            r'/sites/all/modules/([a-zA-Z0-9_-]+)/',
            r'/sites/default/modules/([a-zA-Z0-9_-]+)/'
        ]:
            m = re.search(pattern, src)
            if m:
                modules.add(m.group(1).lower())
    
    # 2. Detect from forms and inputs (common for contrib modules)
    for form in soup.find_all('form'):
        if 'id' in form.attrs:
            form_id = form['id']
            if form_id.startswith(('views-', 'webform-', 'panels-')):
                modules.add(form_id.split('-')[0].lower())
    
    # 3. Detect from classes in HTML
    for tag in soup.find_all(True):
        if 'class' in tag.attrs:
            classes = ' '.join(tag['class']).lower()
            for prefix in ['views', 'ctools', 'panels', 'webform']:
                if prefix in classes:
                    modules.add(prefix)
    
    # 4. Check for common module patterns in HTML
    common_modules = {
        'views', 'ctools', 'panels', 'webform', 'token', 
        'pathauto', 'admin_toolbar', 'devel', 'libraries'
    }
    for mod in common_modules:
        if mod in html.lower():
            modules.add(mod)
    
    return sorted(modules)

def load_cve_database(filepath=None):
    try:
        # Si aucun chemin n'est donné → construire le chemin absolu automatiquement
        if filepath is None:
            current_dir = Path(__file__).resolve().parent
            filepath = current_dir / "cve_drupal_finale.json"

        with open(filepath, encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.warning(f"⚠️ Could not load CVE database: {e}")
        return []
def match_cve(modules, version, cve_db):
    """Match detected modules and version with CVE database"""
    findings = []
    version_str = str(version) if version != "unknown" else None
    
    for cve in cve_db:
        
        
        raw_module = cve.get("module_name", "")
        if isinstance(raw_module, list):
          module_name = [m.lower() for m in raw_module if isinstance(m, str)]
        else:
          module_name = [str(raw_module).lower()]

        cve_id = cve.get("cve_id")
        description = cve.get("description", "").lower()
        severity = cve.get("severity", "UNKNOWN").upper()
    
        # Skip if no module specified and description doesn't mention core
        if not module_name and "drupal core" not in description:
            continue
            
        # Check module match
        module_match = False
        if module_name:
            if "drupal core" in module_name:
                module_match = True
            else:
                for module in modules:
                    if module.lower() in module_name:
                        module_match = True
                        break
        
        # Check version match if version is known
        version_match = False
        if version_str:
            version_patterns = [
                rf"{version_str}[^0-9]",
                rf"before {version_str}[^0-9]",
                rf"through {version_str}[^0-9]",
                rf"prior to {version_str}[^0-9]"
            ]
            for pattern in version_patterns:
                if re.search(pattern, description):
                    version_match = True
                    break
        
        # If module is specified, require module match
        if module_name and not module_match:
            continue
            
        # If version is known, require version match for core vulnerabilities
        if version_str and "drupal core" in description.lower() and not version_match:
            continue

        # Normalize CVSS score
        cvss_score = cve.get("cvss_score")
        normalized_score = 0.0
        if cvss_score is not None:
            try:
                if isinstance(cvss_score, (int, float)):
                    normalized_score = float(cvss_score)
                elif isinstance(cvss_score, str):
                    if cvss_score.replace('.', '', 1).isdigit():
                        normalized_score = float(cvss_score)
            except (ValueError, AttributeError):
                normalized_score = 0.0
            
        findings.append({
            "cve_id": cve_id,
            "description": cve.get("description"),
            "severity": severity,
            "cvss_score": normalized_score,  # Use normalized score
            "cvss_version": cve.get("cvss_version"),
            "cwe_id": cve.get("cwe_id"),
            "cwe_name": cve.get("cwe_name"),
            "module_name": module_name,
            "published": cve.get("published"),
            "nvd_reference": cve.get("nvd_reference"),
            "matched_module": module_match,
            "matched_version": version_match
        })
    
    # Sort by severity (CRITICAL first) then by CVSS score (highest first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings.sort(key=lambda x: (
        severity_order.get(x["severity"], 4),
        -x["cvss_score"]  # Now safe as we've normalized all scores
    ))
    
    return findings

# [Rest of the functions remain the same...]

def run_drupalscan(site, enable_sqlmap=False, save_json=True, aggressive=False):
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
        # Disable SSL warnings for better compatibility
        requests.packages.urllib3.disable_warnings()
        
        r = requests.get(site, timeout=10, verify=False)
        html = r.text
        results["findings"].extend(check_cookie_flags(r))
        results["findings"].extend(check_security_headers(r))

        # Improved version detection
        version = detect_drupal_version(site)
        results["version_detected"] = version
        
        # Improved module detection
        modules = detect_drupal_modules(html)
        results["modules_detected"] = modules
        
        # Load CVE database and match with stricter criteria
        cve_db = load_cve_database()
        cves = match_cve(modules, version, cve_db)
        results["cves"] = cves
        
        if cves:
            results["findings"].append(f"[!] {len(cves)} potential vulnerabilities found")
            
            # Add summary by severity
            severity_counts = {}
            for cve in cves:
                severity_counts[cve["severity"]] = severity_counts.get(cve["severity"], 0) + 1
            for severity, count in severity_counts.items():
                results["findings"].append(f"[!] {count} {severity} severity vulnerabilities")

        # [Rest of the function remains the same...]

    except Exception as e:
        results["findings"].append(f"[ERROR] Scan failed: {str(e)}")
        logging.exception("Scan failed")

    results["score"] = calculate_score(results["findings"])
    results["is_vulnerable"] = len(results["cves"]) > 0 or any(f.startswith("[!]") for f in results["findings"])

    if save_json:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            logging.info(f"Scan saved to {f.name}")
            return results, f.name
    return results