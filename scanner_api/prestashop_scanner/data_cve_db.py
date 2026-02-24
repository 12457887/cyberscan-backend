import requests
import json
import re
from datetime import datetime, timedelta, timezone

# Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEYWORDS = ["prestashop"]
OUTPUT_FILE = "cve_prestashop_finale.json"

def fetch_cve_data(keyword="prestashop"):
    base_params = {
        "keywordSearch": keyword,
        "resultsPerPage": 2000,
    }

    all_vulns = []
    start_index = 0

    while True:
        params = {**base_params, "startIndex": start_index}
        try:
            response = requests.get(NVD_API_URL, params=params, timeout=20)
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulnerabilities", [])
            all_vulns.extend(vulns)

            total = data.get("totalResults", 0)
            start_index += len(vulns)

            if start_index >= total or not vulns:
                break
        except Exception as e:
            print(f"[!] Error during API request: {e}")
            break

    print(f"[+] Total CVEs fetched: {len(all_vulns)}")
    return all_vulns

import re

def extract_module_name(description):
    """
    Extrait le nom du module PrestaShop à partir d'une description CVE.
    Gère les cas complexes avec guillemets, parenthèses, chemins et motifs spécifiques.
    """
    # Normalisation du texte
    desc = description.lower()
    desc = desc.replace("‘", "'").replace("’", "'").replace("“", '"').replace("”", '"')

    # Dictionnaire de modules connus (à compléter au besoin)
    KNOWN_MODULES = {
        "correos prestashop": "correos",
        "totadministrativemandate": "totadministrativemandate",
        "ultimateimagetool": "ultimateimagetool",
        "aicustomfee": "aicustomfee",
        "extratabspro": "extratabspro",
        "xenforum": "xenforum",
        "myinventory": "myinventory",
        "stripejs": "stripejs",
        "ws_productreviews": "ws_productreviews",
        "eo_tags": "eo_tags",
        "correos": "correos",
        "lgdetailedorder": "lgdetailedorder"
    }

    # Liste noire de mots à ignorer
    BLACKLIST = {"the", "that", "this", "module", "addon", "prestashop", "package", "a", "e-commerce", "platform"}

    # 1. Vérification des modules connus
    for pattern, name in KNOWN_MODULES.items():
        if pattern in desc:
            return name

    # 2. Capture des motifs entre guillemets et parenthèses
    # Ex: "Module Name" (modulename) ou ‘Module Name’ (modulename)
    match = re.search(r'[\'"](.*?)[\'"]\s*\(([a-z0-9_-]+)\)', desc)
    if match:
        return match.group(2)

    # 3. Capture des noms techniques seuls entre parenthèses
    # Ex: (modulename)
    match = re.search(r'\(([a-z0-9_-]+)\)', desc)
    if match:
        return match.group(1)

    # 4. Capture des versions (module X avant version Y)
    # Ex: module totadministrativemandate before v1.7.1
    match = re.search(r'(?:module|addon)\s+([a-z0-9_-]+)\s+(?:before|until|up to)\s+(?:v|version )?[\d.]+', desc)
    if match and match.group(1) not in BLACKLIST:
        return match.group(1)

    # 5. Capture des noms dans les chemins
    # Ex: /modules/modulename/ ou descarga_etiqueta.php
    match = re.search(r'/modules/([a-z0-9_-]+)', desc)
    if match:
        return match.group(1)
    
    match = re.search(r'/([a-z0-9_-]+)\.php', desc)
    if match and match.group(1) not in BLACKLIST:
        return match.group(1)

    # 6. Capture des motifs génériques
    # Ex: "the Module Xen Forum for PrestaShop"
    match = re.search(r'(?:the|a)\s+(?:module|addon)\s+([a-z0-9_-]+)\s+(?:for|in|of)\s+prestashop', desc)
    if match and match.group(1) not in BLACKLIST:
        return match.group(1)

    # 7. Dernière tentative: mots-clés spécifiques
    if "correos" in desc:
        return "correos"
    if "webp" in desc and "image" in desc:
        return "ultimateimagetool"

    return "unknown"

def get_cwe_from_nvd(cve_data):
    """Extract CWE ID AND name from NVD data"""
    if 'weaknesses' not in cve_data:
        return None
    
    try:
        for weakness in cve_data['weaknesses']:
            for desc in weakness.get('description', []):
                if 'value' in desc and 'description' in desc:
                    cwe_id = desc['value']
                    cwe_name = desc['description']
                    if cwe_id.startswith('CWE-'):
                        return f"{cwe_id}: {cwe_name}"  # Format "CWE-269: Improper Privilege Management"
                    elif cwe_id.isdigit():
                        return f"CWE-{cwe_id}: {cwe_name}"
    except Exception as e:
        print(f"[!] Error extracting CWE for {cve_data.get('id')}: {e}")
    
    return None

def classify_cve(description, cwe_from_nvd=None):
    """Classify CVE based on description or use NVD's CWE if available"""
    if cwe_from_nvd and ":" in cwe_from_nvd:
        parts = cwe_from_nvd.split(":", 1)
        return {"cwe_id": parts[0].strip(), "cwe_name": parts[1].strip()}
    elif cwe_from_nvd:
        return {"cwe_id": cwe_from_nvd.strip(), "cwe_name": "Unspecified"}

    desc = description.lower()

    if any(x in desc for x in ["xss", "cross-site scripting"]):
        return {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting (XSS)"}
    elif any(x in desc for x in ["csrf", "cross-site request forgery"]):
        return {"cwe_id": "CWE-352", "cwe_name": "Cross-Site Request Forgery (CSRF)"}
    elif "sql injection" in desc or "sql-injection" in desc:
        return {"cwe_id": "CWE-89", "cwe_name": "SQL Injection"}
    elif any(x in desc for x in ["code injection", "rce", "remote code execution"]):
        return {"cwe_id": "CWE-94", "cwe_name": "Code Injection (RCE)"}
    elif any(x in desc for x in ["path traversal", "directory traversal"]):
        return {"cwe_id": "CWE-22", "cwe_name": "Path Traversal"}
    elif any(x in desc for x in ["file upload", "unrestricted upload"]):
        return {"cwe_id": "CWE-434", "cwe_name": "Unrestricted File Upload"}
    elif any(x in desc for x in ["authentication bypass", "privilege escalation"]):
        return {"cwe_id": "CWE-287", "cwe_name": "Improper Authentication"}
    elif "incorrect access control" in desc or "access control bypass" in desc:
        return {"cwe_id": "CWE-284", "cwe_name": "Improper Access Control"}
    elif "information disclosure" in desc or "information leak" in desc:
        return {"cwe_id": "CWE-200", "cwe_name": "Information Exposure"}

    return {"cwe_id": "CWE-Other", "cwe_name": "Uncategorized Vulnerability"}


def extract_relevant_info(vulns):
    extracted = []
    for item in vulns:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        # Extraire les références (URLs)
        references_data = cve_data.get("references", [])
        references = [ref.get("url") for ref in references_data if ref.get("url")]
        published = cve_data.get("published", "")

        # Extraction de la gravité
        metrics = cve_data.get("metrics", {})
        severity = "unknown"
        cvss_score = None
        cvss_version = None
        
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss_data["baseSeverity"]
            cvss_score = cvss_data["baseScore"]
            cvss_version = "3.1"
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            severity = cvss_data["baseSeverity"]
            cvss_score = cvss_data["baseScore"]
            cvss_version = "3.0"
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]
            severity = cvss_data["baseSeverity"]
            cvss_score = cvss_data["cvssData"]["baseScore"]
            cvss_version = "2.0"

        # Extraction du module
        module_name = extract_module_name(description)

        # Classification CWE
        cwe_from_nvd = get_cwe_from_nvd(cve_data)
        cwe_info = classify_cve(description, cwe_from_nvd)
   
        extracted.append({
            "cve_id": cve_id,
            "published": published,
            "module_name": module_name,
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "cwe_id": cwe_info["cwe_id"],
            "cwe_name": cwe_info["cwe_name"],
            "source_cwe": cwe_from_nvd , # Pour vérification
            "nvd_reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}" 
        })
    return extracted

def main():
    all_data = []
    for keyword in KEYWORDS:
        vulns = fetch_cve_data(keyword)
        extracted = extract_relevant_info(vulns)
        all_data.extend(extracted)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_data, f, indent=2, ensure_ascii=False)

    print(f"[✓] {len(all_data)} CVEs saved to '{OUTPUT_FILE}'")

if __name__ == "__main__":
    main()