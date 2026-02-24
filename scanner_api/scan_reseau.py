import subprocess
import os
import json
import sys
import logging
import re
from datetime import datetime, timezone
import ssl
import socket
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from pathlib import Path
import whois
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

# =======================
# QUICK SCAN TUNING
# =======================
def _read_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _read_str_env(name: str, default: str) -> str:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip() or default


def _read_bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "y", "on"}


NMAP_QUICK_HOST_TIMEOUT = _read_str_env("NMAP_QUICK_HOST_TIMEOUT", "120s")
NMAP_QUICK_SCRIPT_TIMEOUT = _read_str_env("NMAP_QUICK_SCRIPT_TIMEOUT", "30s")
NMAP_QUICK_MAX_RETRIES = _read_int_env("NMAP_QUICK_MAX_RETRIES", 1)
NMAP_QUICK_VERSION_LIGHT = _read_bool_env("NMAP_QUICK_VERSION_LIGHT", True)
NMAP_QUICK_DISABLE_SCRIPTS = _read_bool_env("NMAP_QUICK_DISABLE_SCRIPTS", False)

# =======================
# LOGGING
# =======================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("nmap_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self, privileged=None):
        if privileged is None:
            privileged = hasattr(os, "geteuid") and os.geteuid() == 0

        self.privileged = privileged
        self.timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # 📁 OUTPUT DIR = SAME DIR AS SCRIPT
        self.base_dir = Path(__file__).resolve().parent
        self.output_dir = self.base_dir / "scan_results"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Répertoire de sortie: {self.output_dir}")

    # =======================
    # UTILS
    # =======================
    @staticmethod
    def extract_domain(url):
        try:
            parsed = urlparse(url)
            return parsed.hostname or parsed.path.split("/")[0]
        except Exception:
            return None

    def run_command(self, command):
        logger.info(f"Exécution: {' '.join(command)}")
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3600
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        return result.stdout

    def adjust_nmap_args(self, args):
        if self.privileged:
            return args

        adjusted = []
        for a in args:
            if a == "-sS":
                adjusted.append("-sT")
            elif a == "-O":
                continue
            else:
                adjusted.append(a)

        if not any(x in adjusted for x in ("-sT", "-sS")):
            adjusted.insert(0, "-sT")

        return adjusted

    # =======================
    # DNS Records
    # =======================
        # =======================
    # DNS Records
    # =======================
        # =======================
    # DNS Records
    # =======================
        # =======================
    # DNS Records (Compatible avec les anciennes versions de dnspython)
    # =======================
    def get_dns_records(self, domain):
        records = {
            "A": [], "MX": [], "NS": [], "TXT": [],
            "SOA": None, "SPF": None, "CNAME": None
        }
        
        # Créez une seule instance du resolver pour toutes les requêtes
        resolver = dns.resolver.Resolver()

        try:
            # A record
            a_records = resolver.query(domain, 'A')
            records["A"] = [r.to_text() for r in a_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
            logger.warning(f"No A record found for {domain}: {e}")

        try:
            # MX records
            mx_records = resolver.query(domain, 'MX')
            records["MX"] = [{"priority": mx.preference, "server": mx.exchange.to_text()} for mx in mx_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
            logger.warning(f"No MX records found for {domain}: {e}")
        
        try:
            # NS records
            ns_records = resolver.query(domain, 'NS')
            records["NS"] = [ns.to_text() for ns in ns_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
            logger.warning(f"No NS records found for {domain}: {e}")
        
        try:
            # TXT records
            txt_records = resolver.query(domain, 'TXT')
            records["TXT"] = [txt.to_text() for txt in txt_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
            logger.warning(f"No TXT records found for {domain}: {e}")
        
        try:
            # SOA records
            soa_records = resolver.query(domain, 'SOA')
            records["SOA"] = soa_records[0].to_text()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
            logger.warning(f"No SOA record found for {domain}: {e}")
        
        try:
            # CNAME records
            cname_records = resolver.query(domain, 'CNAME')
            records["CNAME"] = [cname.to_text() for cname in cname_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
            logger.info(f"No CNAME record found for {domain}, which is normal.")
        
        # La recherche SPF reste la même
        for txt in records["TXT"]:
            if "v=spf" in txt:
                records["SPF"] = txt
                break
        
        return records


    # =======================
    # XML → JSON
    # =======================
    @staticmethod
    def convert_xml_to_json(xml_data):
        root = ET.fromstring(xml_data)

        result = {
            "scan_info": [],
            "hosts": [],
            "os_info": []
        }

        for si in root.findall("scaninfo"):
            result["scan_info"].append(si.attrib)

        for host in root.findall("host"):
            host_data = {
                "address": None,
                "hostnames": [],
                "ports": []
            }

            addr = host.find("address")
            if addr is not None:
                host_data["address"] = addr.attrib.get("addr")

            for hn in host.findall("hostnames/hostname"):
                host_data["hostnames"].append(hn.attrib.get("name"))

            for port in host.findall(".//port"):
                state_elem = port.find("state")
                service_elem = port.find("service")

                host_data["ports"].append({
                    "port": port.attrib.get("portid"),
                    "protocol": port.attrib.get("protocol"),
                    "state": state_elem.attrib.get("state") if state_elem is not None else "unknown",
                    "service": service_elem.attrib.get("name") if service_elem is not None else "unknown",
                    "product": service_elem.attrib.get("product") if service_elem is not None else None,
                    "version": service_elem.attrib.get("version") if service_elem is not None else None,
                })

            result["hosts"].append(host_data)

        for osmatch in root.findall(".//osmatch"):
            result["os_info"].append({
                "name": osmatch.attrib.get("name"),
                "accuracy": osmatch.attrib.get("accuracy")
            })

        return result

    # =======================
    # NMAP
    # =======================
    def run_nmap_scan(self, target, scan_name, args):
        xml_path = self.output_dir / f"{scan_name}_{self.timestamp}.xml"
        command = ["nmap"] + self.adjust_nmap_args(args) + ["-oX", str(xml_path), target]

        self.run_command(command)

        with open(xml_path, "r", encoding="utf-8") as f:
            return self.convert_xml_to_json(f.read())

    # =======================
    # TESTSSL - PARSING AMÉLIORÉ
    # =======================
    @staticmethod
    def parse_ssl_output(output):
        """Parse la sortie texte de testssl.sh et la convertit en JSON structuré"""
        ssl_data = {
            "raw_output": output,
            "summary": {},
            "certificates": {},
            "protocols": {},
            "ciphers": {},
            "vulnerabilities": [],
            "recommendations": []
        }

        lines = output.split('\n')
        
        # Extraction des informations clés
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Certificat
            if "Certificate" in line or "Subject:" in line:
                ssl_data["certificates"]["subject"] = line
            elif "Issuer:" in line:
                ssl_data["certificates"]["issuer"] = line
            elif "Not valid before:" in line or "Not valid after:" in line:
                ssl_data["certificates"]["validity"] = line

            # Protocoles SSL/TLS
            elif "TLSv" in line or "SSLv" in line:
                if "offered" in line.lower():
                    protocol = line.split()[0]
                    ssl_data["protocols"][protocol] = "offered"
                elif "not offered" in line.lower():
                    protocol = line.split()[0]
                    ssl_data["protocols"][protocol] = "not_offered"

            # Vulnérabilités
            elif any(vuln in line.lower() for vuln in ["heartbleed", "ccs", "crime", "poodle", "drown", "logjam"]):
                ssl_data["vulnerabilities"].append(line)

            # Recommandations
            elif "recommended" in line.lower() or "should" in line.lower():
                ssl_data["recommendations"].append(line)

        return ssl_data

    def run_ssl_test(self, domain):
       testssl_env = os.getenv("TESTSSL_PATH")
       enable_ssl = os.getenv("ENABLE_SSL_SCAN", "false").lower() == "true"

       if not enable_ssl:
          logger.info("Scan SSL désactivé via ENABLE_SSL_SCAN")
          return None

       if not testssl_env:
          logger.warning("TESTSSL_PATH non défini → SSL ignoré")
          return None

       testssl_path = Path(testssl_env)

       if not testssl_path.is_file():
          logger.warning(f"testssl.sh introuvable ({testssl_path}) → SSL ignoré")
          return None

       try:
          output = self.run_command([
             str(testssl_path),
             "--quiet",
             "--color", "0",
             domain
           ])

          ssl_data = self.parse_ssl_output(output)

          ssl_file = self.output_dir / f"ssl_{domain}_{self.timestamp}.txt"
          with open(ssl_file, "w", encoding="utf-8") as f:
            f.write(output)

          logger.info(f"Résultats SSL sauvegardés: {ssl_file}")
          return ssl_data

       except Exception as e:
          logger.error(f"Erreur lors du test SSL: {str(e)}")
          return None


    def check_ssl_certificate(self, domain, timeout=10):
       """Check only TLS certificate validity without full SSL scan."""
       try:
          context = ssl.create_default_context()
          with socket.create_connection((domain, 443), timeout=timeout) as sock:
             with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

          if not cert:
             return {"valid": False, "error": "no_certificate"}

          def _parse_cert_time(value):
             if not value:
                return None
             parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
             return parsed.replace(tzinfo=timezone.utc)

          not_before = _parse_cert_time(cert.get("notBefore"))
          not_after = _parse_cert_time(cert.get("notAfter"))
          now = datetime.now(timezone.utc)

          valid = True
          if not_before and now < not_before:
             valid = False
          if not_after and now > not_after:
             valid = False

          days_remaining = None
          if not_after:
             days_remaining = (not_after - now).days

          return {
             "valid": valid,
             "not_before": not_before.isoformat() if not_before else None,
             "not_after": not_after.isoformat() if not_after else None,
             "days_remaining": days_remaining,
             "subject": cert.get("subject"),
             "issuer": cert.get("issuer"),
             "serial_number": cert.get("serialNumber"),
             "version": cert.get("version"),
          }
       except Exception as exc:
          return {"valid": False, "error": str(exc)}


    # =======================
    # WHOIS
    # =======================
    def run_whois_query(self, domain):
        try:
            data = whois.whois(domain)
            return {k: str(v) for k, v in data.items()}
        except Exception:
            return None

    # =======================
    # QUICK SCAN (API)
    # =======================
    def run_quick_scan(self, target, include_ssl=False):
       domain = self.extract_domain(target)
       if not domain:
         raise ValueError("Domaine invalide")

       quick_args = ["-sS", "-sV", "-T4", "-F"]
       if NMAP_QUICK_VERSION_LIGHT:
          quick_args.append("--version-light")
       if not NMAP_QUICK_DISABLE_SCRIPTS:
          quick_args.append("--script=banner,http-title,http-headers,http-methods")
          if NMAP_QUICK_SCRIPT_TIMEOUT:
             quick_args += ["--script-timeout", NMAP_QUICK_SCRIPT_TIMEOUT]
       if NMAP_QUICK_MAX_RETRIES is not None:
          quick_args += ["--max-retries", str(NMAP_QUICK_MAX_RETRIES)]
       if NMAP_QUICK_HOST_TIMEOUT:
          quick_args += ["--host-timeout", NMAP_QUICK_HOST_TIMEOUT]

       scans = {
         "quick": quick_args,
       }

       results = {
          "domain": domain,
          "timestamp": self.timestamp,
          "scan_profile": "quick",
          "scans": {},
          "dns": None,
          "ssl": None,
          "whois": None,
          "source": "scan_reseau",
       }

       with ThreadPoolExecutor(max_workers=4) as executor:
          futures = {}

        # 🔹 DNS
          futures["dns"] = executor.submit(self.get_dns_records, domain)

        # 🔹 WHOIS
          futures["whois"] = executor.submit(self.run_whois_query, domain)

        # 🔹 SSL validity only (optionnel)
          if include_ssl:
             futures["ssl"] = executor.submit(self.check_ssl_certificate, domain)

        # 🔹 NMAP (1 seul scan)
          futures["nmap"] = executor.submit(
            self.run_nmap_scan,
            domain,
            "quick",
            scans["quick"]
         )

          for future in as_completed(futures.values()):
            for key, f in futures.items():
                if f == future:
                    try:
                        result = f.result()
                        if key == "nmap":
                            results["scans"]["quick"] = result
                        else:
                            results[key] = result
                    except Exception as e:
                        logger.error(f"Erreur {key}: {e}")

       out_file = self.output_dir / f"scan_quick_{domain}_{self.timestamp}.json"
       with open(out_file, "w", encoding="utf-8") as f:
          json.dump(results, f, indent=4, ensure_ascii=False)

       logger.info(f"Résultats sauvegardés: {out_file}")
       return results

    # =======================
    # ALL SCANS
    # =======================
    def run_all_scans(self, target):
        domain = self.extract_domain(target)
        if not domain:
            raise ValueError("Domaine invalide")

        scans = {
            "full": ["-sS", "-sV", "--script=banner,http-title,http-headers,http-methods"],
            "ports": ["-p-"],
            "services": ["-sV"]
        }

        results = {
            "domain": domain,
            "timestamp": self.timestamp,
            "scans": {},
            "dns": self.get_dns_records(domain),
            "ssl": None,
            "whois": None
        }

        for name, args in scans.items():
            results["scans"][name] = self.run_nmap_scan(domain, name, args)

        results["ssl"] = self.run_ssl_test(domain)
        results["whois"] = self.run_whois_query(domain)

        out_file = self.output_dir / f"scan_{domain}_{self.timestamp}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)

        logger.info(f"Résultats sauvegardés: {out_file}")
        return results


# =======================
# API HELPER
# =======================
def run_quick_network_scan(target, include_ssl=False):
    scanner = NmapScanner(privileged=None)
    return scanner.run_quick_scan(target, include_ssl=include_ssl)


def run_full_network_scan(target):
    scanner = NmapScanner(privileged=None)
    return scanner.run_all_scans(target)


def run_ports_scan(target, mode: str = "full"):
    scanner = NmapScanner(privileged=None)
    domain = scanner.extract_domain(target)
    if not domain:
        raise ValueError("Domaine invalide")

    normalized = (mode or "full").strip().lower()
    is_quick = normalized in {"quick", "light"}
    args = ["-sS", "-T4", "-F"] if is_quick else ["-p-"]
    ports_result = scanner.run_nmap_scan(domain, "ports", args)
    return {
        "domain": domain,
        "timestamp": scanner.timestamp,
        "scan_profile": "ports_quick" if is_quick else "ports_full",
        "mode": "quick" if is_quick else "full",
        "scans": {"ports": ports_result},
        "source": "scan_reseau",
    }


def run_ssl_scan(target, full: bool = True):
    scanner = NmapScanner(privileged=None)
    domain = scanner.extract_domain(target)
    if not domain:
        raise ValueError("Domaine invalide")

    ssl_mode = "full" if full else "cert"
    ssl_fallback = False

    ssl_data = None
    if full:
        ssl_data = scanner.run_ssl_test(domain)
        if ssl_data is None:
            ssl_fallback = True
            ssl_mode = "cert"

    if not ssl_data:
        ssl_data = scanner.check_ssl_certificate(domain)

    return {
        "domain": domain,
        "timestamp": scanner.timestamp,
        "scan_profile": "ssl",
        "ssl": ssl_data,
        "ssl_mode": ssl_mode,
        "ssl_fallback": ssl_fallback,
        "source": "scan_reseau",
    }


# =======================
# MAIN
# =======================
def main():
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if not is_root:
        logger.warning("Mode non-root : scans adaptés")

    target = input("Cible (URL ou IP): ").strip()
    scanner = NmapScanner(privileged=is_root)
    scanner.run_all_scans(target)


if __name__ == "__main__":
    main()
