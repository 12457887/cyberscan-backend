import subprocess
import os
import asyncio
import uuid
from datetime import datetime
import json
import time
import logging
import contextlib
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from pydantic import HttpUrl, BaseModel
from typing import List, Dict, Any, Optional
from .supabase_sync import get_scan_row

from scanner_api.utils import validate_scan_target
from scanner_api.save_to_mongo import save_scan_json_to_mongo, get_scan_from_mongo
from scanner_api.nuclei_parser import parse_nuclei_output
from scanner_api.nuclei_scanner import run_nuclei_scan
from scanner_api.zap_scanner import run_zap_light_scan, run_zap_full_remote_scan
from scanner_api.scan_reseau import run_full_network_scan, run_quick_network_scan, run_ports_scan, run_ssl_scan
from scanner_api.subdomain_finder import find_subdomains
from scanner_api.medianet_routes import register_medianet_scan_route, medianet_router

from .prestashop_scanner.prestashop_scanner import run_prestascan
from .drupal_scanner.drupal_scanner import run_drupalscan
from .wordpress_scanner import run_wordpress_scan, run_wordpress_wpscan_only
from .supabase_sync import create_scan_row, update_scan_row, insert_vulnerabilities, record_scan_activity
from domainAnalyzer.analyzer import DomainAnalyzer

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Affiche les logs de niveau DEBUG et plus bas

# Création d'un handler pour afficher les logs dans la console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)  # Affiche tous les logs à partir de DEBUG

# Création d'un format de log
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

# Ajout du handler au logger
logger.addHandler(console_handler)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
]
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
def _read_timeout_env(env_key: str = "NUCLEI_SCAN_TIMEOUT", default: float = 60.0) -> float:
    raw = os.environ.get(env_key)
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


NUCLEI_SCAN_TIMEOUT = _read_timeout_env("NUCLEI_SCAN_TIMEOUT", 300.0)
NUCLEI_LIGHT_TIMEOUT = _read_timeout_env("NUCLEI_LIGHT_TIMEOUT", 180.0)
NUCLEI_PREVIEW_TIMEOUT = _read_timeout_env("NUCLEI_PREVIEW_TIMEOUT", 120.0)

SCAN_WEBANALYZE_TIMEOUT = _read_timeout_env("SCAN_WEBANALYZE_TIMEOUT", 60.0)
SCAN_HTTPX_TIMEOUT = _read_timeout_env("SCAN_HTTPX_TIMEOUT", 40.0)
NETWORK_SCAN_TIMEOUT = _read_timeout_env("NETWORK_SCAN_TIMEOUT", 900.0)

SCAN_TASKS: set[asyncio.Task] = set()
COMPLETE_SCAN_CACHE: dict[str, Dict[str, Any]] = {}

def _resolve_scan_id_by_zap_scan_id(zap_scan_id: str) -> str | None:
    if not zap_scan_id:
        return None
    for scan_id, state in COMPLETE_SCAN_CACHE.items():
        if state.get("zap_scan_id") == zap_scan_id:
            return scan_id
    return None

def _track_background_task(task: asyncio.Task, label: str) -> None:
    SCAN_TASKS.add(task)

    def _finalize(done_task: asyncio.Task) -> None:
        SCAN_TASKS.discard(done_task)
        try:
            done_task.result()
        except asyncio.CancelledError:
            logger.warning("Background scan task cancelled: %s", label)
        except Exception:
            logger.exception("Background scan task failed: %s", label)

    task.add_done_callback(_finalize)


def _schedule_background_scan(coro, label: str) -> None:
    task = asyncio.create_task(coro)
    _track_background_task(task, label)

def _safe_update_scan_row(scan_id: str, payload: Dict[str, Any]) -> None:
    try:
        update_scan_row(scan_id, payload)
    except Exception as exc:
        logger.warning("Supabase update failed for %s: %s", scan_id, exc)


def _init_complete_cache(scan_id: str, target_url: str, cms_type: str, network_enabled: bool) -> None:
    state = COMPLETE_SCAN_CACHE.setdefault(scan_id, {})
    state.update({
        "scan_id": scan_id,
        "target_url": target_url,
        "cms_type": cms_type,
        "started_at": datetime.utcnow().isoformat() + "Z",
        "nuclei_status": "running",
        "zap_status": "running",
        "network_status": "running" if network_enabled else "skipped",
    })


def _update_complete_cache(scan_id: str, **updates: Any) -> None:
    state = COMPLETE_SCAN_CACHE.setdefault(scan_id, {})
    state.update(updates)

def _pick_highest_risk(current: str | None, candidate: str | None) -> str | None:
    if not candidate or candidate not in SEVERITY_ORDER:
        return current
    if current is None:
        return candidate
    return candidate if SEVERITY_ORDER.index(candidate) > SEVERITY_ORDER.index(current) else current

# === IA CMS DETECTION (chargement modèle) ===
import joblib
import pandas as pd
from ia_cms_detection.IA.scraping import extract_features, fetch_html

try:
    MODEL = joblib.load("ia_cms_detection/models/cms_detector_model.pkl")
    FEATURE_ORDER = joblib.load("ia_cms_detection/models/feature_names.pkl")
    LABEL_ENCODER = joblib.load("ia_cms_detection/models/label_encoder.pkl")
except Exception:
    MODEL = None
    FEATURE_ORDER = None
    LABEL_ENCODER = None

SEUIL_IA = 0.5

try:
    CMS_ANALYZER = DomainAnalyzer(timeout=8)
except Exception as e:
    logger.warning(f"Fallback CMS analyzer unavailable: {e}")
    CMS_ANALYZER = None

CMS_UNKNOWN_VALUES = {"unknown", "inconnu"}
CMS_HOST_OVERRIDES = {
    "securas.fr": "inconnu",
    "www.securas.fr": "inconnu",
}


def _extract_hostname(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    host = parsed.hostname
    if host:
        return host.lower()
    parsed = urlparse(f"http://{url}")
    return parsed.hostname.lower() if parsed.hostname else None


def _override_cms_for_url(url: str | None) -> Optional[str]:
    host = _extract_hostname(url)
    if not host:
        return None
    return CMS_HOST_OVERRIDES.get(host)


def _normalize_cms_label(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    normalized = value.strip().lower()
    if not normalized or normalized in CMS_UNKNOWN_VALUES:
        return None
    return normalized


def detect_cms_from_html(html: Optional[str], headers: Optional[Dict[str, Any]] = None) -> Optional[str]:
    if not html or not CMS_ANALYZER:
        return None
    try:
        cms_list = CMS_ANALYZER.detect_cms(html, headers or {})
        for entry in cms_list:
            normalized = _normalize_cms_label(entry)
            if normalized:
                return normalized
    except Exception as e:
        logger.debug(f"Fallback CMS detection failed: {e}")
    return None


def detect_cms_with_model(url: str, html: Optional[str], headers, robots) -> Optional[str]:
    override = _override_cms_for_url(url)
    if override:
        return override
    if not html or MODEL is None or FEATURE_ORDER is None or LABEL_ENCODER is None:
        return None
    try:
        features = extract_features(url, html, headers, robots)
        input_df = pd.DataFrame([features])
        input_df = input_df.reindex(columns=FEATURE_ORDER, fill_value=0)
        pred_encoded = MODEL.predict(input_df)[0]
        proba = MODEL.predict_proba(input_df).max()
        if proba >= SEUIL_IA:
            label = LABEL_ENCODER.inverse_transform([pred_encoded])[0]
            return _normalize_cms_label(label)
    except Exception as e:
        logger.debug(f"Model CMS detection failed for {url}: {e}")
    return None

logger = logging.getLogger(__name__)
def verify_backend_api_key(x_backend_api_key: str | None = Header(None), authorization: str | None = Header(None)):
    """Verify incoming request contains the expected ACKEND_API_KEY.

    Accepts either an `Authorization: Bearer <key>` header or an `X-Backend-Api-Key` header.
    """
    expected = os.environ.get("BACKEND_API_KEY")
    logger.debug(f"Clé API attendue: {expected}")
    if not expected:
        # If expected key not configured, allow (fail-open) but log a warning
        logger.warning("BACKEND_API_KEY not set in environment; skipping API key verification.")
        return True

    if authorization:
        try:
            scheme, token = authorization.split(" ", 1)
            logger.debug(f"Tentative avec Authorization: {token}")

        except ValueError:
            token = authorization
        if token == expected:
            logger.info("Clé API validée avec Authorization.")
            return True

    if x_backend_api_key and x_backend_api_key == expected:
        return True

    raise HTTPException(status_code=403, detail="Invalid or missing API key")


scan_router = APIRouter(dependencies=[Depends(verify_backend_api_key)])


def _ensure_target_allowed(url_value: str) -> None:
    allowed, reason = validate_scan_target(url_value)
    if not allowed:
        raise HTTPException(status_code=400, detail=f"URL '{url_value}' rejected: {reason}")


def _normalize_scan_mode(mode: str | None) -> str:
    if not mode:
        return "light"
    normalized = str(mode).strip().lower()
    if normalized in {"full", "complete"}:
        return "complete"
    if normalized == "light":
        return "light"
    return normalized


def _normalize_network_mode(mode: str | None) -> str:
    if not mode:
        return "full"
    normalized = str(mode).strip().lower()
    if normalized in {"light", "quick"}:
        return "quick"
    if normalized in {"full", "complete"}:
        return "full"
    return "full"

def _normalize_network_scan_value(value: bool | str | None) -> bool | str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    if normalized in {"light", "quick"}:
        return "quick"
    if normalized in {"full", "complete"}:
        return "full"
    return value


def _normalize_light_mode(mode: str | None) -> str:
    if not mode:
        return "light"
    normalized = str(mode).strip().lower()
    if normalized in {"full", "complete"}:
        return "full"
    if normalized in {"light", "quick"}:
        return "light"
    return "light"

# === MODELS ===
class SiteWithCMS(BaseModel):
    url: HttpUrl
    cms: str
    mode: str = "light"
    frontend_scan_id: str | None = None
    scan_id: str | None = None 
    user_id: str | None = None 
    preview_only: bool = False
    network_scan: bool | str | None = None


class SiteDetect(BaseModel):
    url: HttpUrl
    mode: str = "light"
    frontend_scan_id: str | None = None
    scan_id: str | None = None
    user_id: str | None = None
    preview_only: bool = False


class NetworkPortsRequest(BaseModel):
    url: HttpUrl
    mode: str | None = None


class NetworkSslRequest(BaseModel):
    url: HttpUrl
    full_ssl: bool = True


class NetworkScanRequest(BaseModel):
    url: HttpUrl
    mode: str | None = None


class SubdomainScanRequest(BaseModel):
    url: HttpUrl
    mode: str | None = None
    wordlist: list[str] | None = None



class WordpressScanRequest(BaseModel):
    url: HttpUrl
    scan_id: str | None = None
    mode: str = "light"


# === CHOIX DU SCANNER ===
def get_scanner_function(cms: str):
    """
    Retourne la fonction scanner appropriée, enveloppée pour
    extraire automatiquement le dict des résultats.
    """
    def safe_wrap(scanner_func):
        def wrapped(url):
            result = scanner_func(url)
            if isinstance(result, tuple) and len(result) == 2:
                return result[0]
            return result
        return wrapped

    scanners = {
        "prestashop": safe_wrap(run_prestascan),
        "drupal": safe_wrap(run_drupalscan),
        "wordpress": safe_wrap(run_wordpress_scan),
    }
    return scanners.get(cms.lower(), lambda url: {})


# === WEBANALYZE ===
async def run_webanalyze(url: str) -> dict:
    try:
        apps_path = os.path.expanduser("~/.webanalyze/technologies.json")
        cmd = f"webanalyze -apps {apps_path} -host {url} -output json"
        process = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SCAN_WEBANALYZE_TIMEOUT)
        except asyncio.TimeoutError:
            process.kill()
            return {"error": "Timeout: Webanalyze a pris trop de temps."}

        if process.returncode != 0:
            return {"error": stderr.decode().strip() or "Erreur inconnue"}

        raw = json.loads(stdout.decode())
        techs = [
            {"name": m.get("app_name"), "version": m.get("version", "")}
            for m in raw.get("matches", [])
        ]
        return {"hostname": raw.get("hostname"), "technologies": techs}

    except Exception as e:
        return {"error": str(e)}


# === HTTPX ===
async def run_httpx(url: str) -> dict:
    try:
        cmd = f"echo {url} | httpx -title -tech-detect -status-code -json -silent"
        process = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SCAN_HTTPX_TIMEOUT)
        except asyncio.TimeoutError:
            process.kill()
            return {"error": "Timeout: httpx a pris trop de temps."}

        if not stdout:
            return {"error": stderr.decode().strip() or "Aucune sortie reçue de httpx."}

        data = json.loads(stdout.decode().splitlines()[0])
        return {
            "input": data.get("input"),
            "status_code": data.get("status_code"),
            "title": data.get("title"),
            "tech": data.get("tech"),
            "ip": data.get("ip"),
        }

    except Exception as e:
        return {"error": str(e)}


# === SCAN PRINCIPAL ===
def _extract_request_ip(request: Request | None) -> str | None:
    if not request:
        return None
    header_ip = request.headers.get("x-forwarded-for")
    if header_ip:
        return header_ip.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


async def scan_sites(
    cms: str,
    urls: List[HttpUrl],
    scan_id: str,
    mode: str = "light",
    user_id: str = "",
    frontend_scan_id: str | None = None,
    preview_only: bool = False,
    request_ip: str | None = None,
    network_scan: bool | str = False,
    collection_override: str | None = None,
    zap_port: int | None = None,   # 👈 AJOUT
) -> List[Dict[str, Any]]:


    mode = _normalize_scan_mode(mode)
    is_complete_async = (mode == "complete")

    scanner = get_scanner_function(cms)
    results: list[Dict[str, Any]] = []
    cms_value = (cms or "inconnu").lower()

    for url in urls:
        url_str = str(url)
        allowed, deny_reason = validate_scan_target(url_str)
        if not allowed:
            results.append({
                "scan_id": scan_id,
                "target_url": url_str,
                "cms_type": cms_value,
                "status": "rejected",
                "error": deny_reason,
                "source": "scanner_api",
            })
            continue

        start_time = time.time()

        try:
            # === LOG ACTIVITY
            if not preview_only and user_id:
                try:
                    record_scan_activity(
                        user_id=user_id,
                        target_url=url_str,
                        scan_mode=mode,
                        ip_address=request_ip,
                        scan_id=scan_id,
                    )
                except Exception:
                    logger.warning("Failed to record scan activity")

            # === SUPABASE IN PROGRESS
            target_id = frontend_scan_id or scan_id
            if not preview_only and not is_complete_async:
                try:
                    update_scan_row(target_id, {
                        "backend_scan_id": scan_id,
                        "status": "in_progress",
                        "started_at": datetime.utcnow().isoformat() + "Z",
                        "cms_type": cms_value,
                    })
                except Exception:
                    logger.warning("Supabase update failed")

            # === TASK INIT
            cms_task = None
            zap_light_task = None
            network_scan_task = None

            zap_full_meta = None
          

            # === ZAP LAUNCH
            if mode == "light":
               zap_light_task = asyncio.create_task(
                  asyncio.to_thread(
                    run_zap_light_scan,
                    url_str,
                    zap_port=zap_port   # 👈 AJOUT
                )
         )

            # === CMS / RECON / NETWORK
            if cms_value != "inconnu":
                cms_task = asyncio.create_task(
                    asyncio.to_thread(scanner, url_str)
                )

            webanalyze_task = asyncio.create_task(run_webanalyze(url_str))
            httpx_task = asyncio.create_task(run_httpx(url_str))

            if network_scan:
                if isinstance(network_scan, str) and network_scan.lower() in {"quick", "light"}:
                   network_scan_task = asyncio.create_task(
                     asyncio.to_thread(run_quick_network_scan, url_str, include_ssl=True)
                )
                else:
                   network_scan_task = asyncio.create_task(
                      asyncio.to_thread(run_full_network_scan, url_str)
                  )


            # =====================================================
# 🔥 MODE COMPLETE → ON NE BLOQUE PAS
# =====================================================
            if is_complete_async:
                _init_complete_cache(target_id, url_str, cms_value, bool(network_scan))

                asyncio.create_task(
                  nuclei_worker(target_id, url_str, cms_value, preview_only)
                )

                if network_scan:
                   asyncio.create_task(
                    network_worker(target_id, url_str)
                  )

                asyncio.create_task(
                     zap_full_worker(target_id, url_str, zap_port=zap_port)
                   )

                results.append({
                   "scan_id": scan_id,
                   "target_url": url_str,
                   "cms_type": cms_value,
                   "status": "running",
                   "zap_status": "running",
                   "nuclei_status": "running",
                   "network_status": "running" if network_scan else "skipped",
                   "mode": mode,
                })

                continue
   # ⬅️ TRÈS IMPORTANT

            # === NUCLEI
            if preview_only:
                nuclei_timeout = NUCLEI_PREVIEW_TIMEOUT
            elif mode == "light":
                nuclei_timeout = NUCLEI_LIGHT_TIMEOUT
            else:
                nuclei_timeout = NUCLEI_SCAN_TIMEOUT
            nuclei_task = asyncio.to_thread(
                run_nuclei_scan,
                url_str,
                cms,
                timeout=nuclei_timeout,
                profile="light" if mode == "light" else "full",
            )

            # === COLLECT RESULTS (PARALLEL)
            task_map: dict[str, asyncio.Task] = {
                "nuclei": nuclei_task,
                "webanalyze": webanalyze_task,
                "httpx": httpx_task,
            }
            if cms_task:
                task_map["cms"] = cms_task
            if network_scan_task:
                task_map["network"] = network_scan_task
            if zap_light_task:
                task_map["zap"] = zap_light_task

            results_map: dict[str, Any] = {}
            task_results = await asyncio.gather(*task_map.values(), return_exceptions=True)
            for key, value in zip(task_map.keys(), task_results):
                results_map[key] = value

            # CMS
            cms_json = {}
            cms_value_result = results_map.get("cms")
            if isinstance(cms_value_result, Exception):
                logger.warning("CMS scan failed")
            elif isinstance(cms_value_result, dict):
                cms_json = cms_value_result

            # Nuclei
            nuclei_data = results_map.get("nuclei")
            if isinstance(nuclei_data, Exception) or not isinstance(nuclei_data, dict):
                nuclei_data = {"skipped": True, "source": "nuclei"}

            nuclei_stdout = nuclei_data.get("nuclei_stdout", "")
            parsed = parse_nuclei_output(nuclei_stdout) if nuclei_stdout else []
            nuclei_data["parsed_results"] = parsed

            if nuclei_data.get("error"):
                nuclei_data["skipped"] = True
            elif nuclei_data.get("timed_out") and not parsed:
                nuclei_data["skipped"] = True
            elif nuclei_data.get("timed_out"):
                nuclei_data["partial"] = True

            # Recon
            webanalyze_res = results_map.get("webanalyze")
            httpx_res = results_map.get("httpx")

            # Network
            network_scan_res = None
            network_value = results_map.get("network")
            if isinstance(network_value, Exception):
                network_scan_res = {"skipped": True, "source": "scan_reseau"}
            elif network_value is not None:
                network_scan_res = network_value

            # === BUILD RESULT
            combined_data: Dict[str, Any] = {
                "scan_id": scan_id,
                "target_url": url_str,
                "cms_type": cms_value,
                "preview_only": preview_only,
                "cms_scan": {
                   "detected": cms_value != "inconnu",
                   "cms": cms_value if cms_value != "inconnu" else None,
                   "cves": cms_json.get("cves", []) if isinstance(cms_json, dict) else [],
                   "plugins": cms_json.get("plugins", []) if isinstance(cms_json, dict) else [],
                   "themes": cms_json.get("themes", []) if isinstance(cms_json, dict) else [],
               },

                "nuclei_scan": nuclei_data,
                "recon": {
                    "webanalyze": webanalyze_res if isinstance(webanalyze_res, dict) else {},
                    "httpx": httpx_res if isinstance(httpx_res, dict) else {},
                },
                "scan_time": round(time.time() - start_time, 2),
                "mode": mode,
                "source": "scanner_api",
            }

            if network_scan_res:
                combined_data["network_scan"] = network_scan_res

            # === ZAP RESULTS
            if zap_full_meta:
                combined_data["zap_full"] = zap_full_meta
                combined_data["zap_status"] = "running"

            if zap_light_task:
                zap_light_res = results_map.get("zap")
                if isinstance(zap_light_res, Exception):
                    combined_data["zap_status"] = "failed"
                    logger.warning("ZAP light failed")
                elif isinstance(zap_light_res, dict):
                    combined_data["zap_scan"] = zap_light_res
                    combined_data["zap_status"] = "completed"
                else:
                    combined_data["zap_status"] = "completed"

            # === SEVERITY CALC
            vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            highest_risk = None

            for src in (
                combined_data.get("cms_scan", {}).get("cves", []),
                combined_data.get("nuclei_scan", {}).get("parsed_results", []),
                combined_data.get("zap_scan", {}).get("alerts", []),
            ):
                for item in src or []:
                    sev = (item.get("severity") or item.get("risk") or "").lower()
                    mapped = {
                        "critical": "critical",
                        "high": "high",
                        "medium": "medium",
                        "low": "low",
                        "info": "low",
                        "informational": "low",
                    }.get(sev)
                    if mapped:
                        vuln_counts[mapped] += 1
                        highest_risk = _pick_highest_risk(highest_risk, mapped)

            combined_data["severity_counts"] = vuln_counts
            combined_data["risk_level"] = highest_risk

            # === SAVE
            mongo_id = save_scan_json_to_mongo(
                combined_data,
                scan_id=scan_id,
                from_dict=True,
                collection_override=collection_override if not preview_only else "scan-gratuit",
            )
            combined_data["mongo_id"] = str(mongo_id)

            if not preview_only:
                try:
                    update_scan_row(target_id, {
                        "mongo_report_id": str(mongo_id),
                        "status": "completed",
                        "risk_level": highest_risk,
                        "vulnerabilities_count": sum(vuln_counts.values()),
                        "completed_at": datetime.utcnow().isoformat() + "Z",
                    })
                    insert_vulnerabilities(target_id, vuln_counts)
                except Exception:
                    logger.warning("Supabase post-scan update failed")

            results.append(combined_data)

        except Exception as exc:
            logger.exception("Scan failed")
            results.append({"url": url_str, "error": str(exc)})

    return results

@scan_router.post("/scan-wordpress")
async def scan_wordpress(request_data: WordpressScanRequest, request: Request):
    _ensure_target_allowed(str(request_data.url))

    scan_id = request_data.scan_id or str(uuid.uuid4())
    url_str = str(request_data.url)
    mode = _normalize_scan_mode(request_data.mode)
    start_time = time.time()

    try:
        cms_scan = await asyncio.to_thread(run_wordpress_wpscan_only, url_str)
    except Exception as exc:
        logger.error("WordPress scan failed for %s: %s", url_str, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"WordPress scan failed: {exc}")

    if not isinstance(cms_scan, dict):
        cms_scan = {}

    vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    highest_risk: str | None = None

    for cve in cms_scan.get("cves", []) if isinstance(cms_scan, dict) else []:
        sev = (cve.get("severity") or "").lower()
        if sev in vuln_counts:
            vuln_counts[sev] += 1
            highest_risk = _pick_highest_risk(highest_risk, sev)

    combined_data = {
        "scan_id": scan_id,
        "target_url": url_str,
        "cms_type": "wordpress",
        "cms_scan": cms_scan or None,
        "scan_time": round(time.time() - start_time, 2),
        "mode": mode,
        "source": "wordpress_scan_api",
        "severity_counts": {
            "low": vuln_counts.get("low", 0),
            "medium": vuln_counts.get("medium", 0),
            "high": vuln_counts.get("high", 0),
            "critical": vuln_counts.get("critical", 0),
        },
        "risk_level": highest_risk,
    }

    try:
        mongo_id = save_scan_json_to_mongo(combined_data, scan_id=scan_id, from_dict=True)
    except Exception as exc:
        logger.error("Mongo save failed for %s: %s", url_str, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"MongoDB save failed: {exc}")

    base_url = str(request.base_url).rstrip("/")
    return {
        "status": "done",
        "scan_id": scan_id,
        "mongo_id": str(mongo_id),
        "severity_counts": combined_data["severity_counts"],
        "risk_level": highest_risk,
        "report_url": f"{base_url}/generate-report/{scan_id}?report_format=pdf",
        "scan_report_url": f"{base_url}/scan-report/{scan_id}",
    }


@scan_router.post("/scan-network-ports")
async def scan_network_ports(payload: NetworkPortsRequest):
    _ensure_target_allowed(str(payload.url))
    url_str = str(payload.url)
    mode = _normalize_network_mode(payload.mode)
    try:
        result = await asyncio.to_thread(run_ports_scan, url_str, mode)
    except Exception as exc:
        logger.error("Network ports scan failed for %s: %s", url_str, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Network ports scan failed: {exc}")
    return {
        "status": "done",
        "target_url": url_str,
        "scan_type": "network_ports_quick" if mode == "quick" else "network_ports_full",
        "mode": mode,
        "network_scan": result,
    }


@scan_router.post("/scan-network")
async def scan_network(payload: NetworkScanRequest):
    _ensure_target_allowed(str(payload.url))
    url_str = str(payload.url)
    mode = _normalize_network_mode(payload.mode)
    try:
        if mode == "quick":
            result = await asyncio.to_thread(run_quick_network_scan, url_str, False)
        else:
            result = await asyncio.to_thread(run_full_network_scan, url_str)
    except Exception as exc:
        logger.error("Network scan failed for %s: %s", url_str, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Network scan failed: {exc}")
    return {
        "status": "done",
        "target_url": url_str,
        "scan_type": "network_quick" if mode == "quick" else "network_full",
        "mode": mode,
        "network_scan": result,
    }


@scan_router.post("/scan-network-ssl")
async def scan_network_ssl(payload: NetworkSslRequest):
    _ensure_target_allowed(str(payload.url))
    url_str = str(payload.url)
    try:
        result = await asyncio.to_thread(run_ssl_scan, url_str, payload.full_ssl)
    except Exception as exc:
        logger.error("Network SSL scan failed for %s: %s", url_str, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Network SSL scan failed: {exc}")
    return {
        "status": "done",
        "target_url": url_str,
        "scan_type": "network_ssl",
        "network_scan": result,
    }


@scan_router.post("/scan-subdomains")
async def scan_subdomains(payload: SubdomainScanRequest):
    _ensure_target_allowed(str(payload.url))
    url_str = str(payload.url)
    mode = _normalize_light_mode(payload.mode)
    try:
        result = await asyncio.to_thread(find_subdomains, url_str, payload.wordlist, mode)
    except Exception as exc:
        logger.error("Subdomain scan failed for %s: %s", url_str, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Subdomain scan failed: {exc}")
    return {
        "status": "done",
        "target_url": url_str,
        "scan_type": "subdomain_full" if mode == "full" else "subdomain_light",
        "mode": mode,
        "subdomain_scan": result,
    }

zap_port = None 
# === ROUTES ===
@scan_router.post("/scan-light")
async def scan_light(site: SiteWithCMS, request: Request):
    _ensure_target_allowed(str(site.url))
    scan_id = str(uuid.uuid4())
    client_ip = _extract_request_ip(request)
    network_scan_value = _normalize_network_scan_value(site.network_scan)
    if network_scan_value is None:
        network_scan_value = False
    _schedule_background_scan(
        scan_sites(
            site.cms,
            [site.url],
            scan_id,
            mode="light",
            user_id=site.user_id or "",
            frontend_scan_id=site.frontend_scan_id,
            preview_only=site.preview_only,
            request_ip=client_ip,
            network_scan=network_scan_value,
            zap_port=zap_port
        ),
        f"scan-light:{scan_id}",
    )
    return {
        "scan_id": scan_id,
        "status": "queued",
        "mode": "light",
        "cms_type": site.cms,
    }

@scan_router.get("/scan-status/{scan_id}")
def get_scan_status(scan_id: str):
    row = None
    try:
        row = get_scan_row(scan_id)
    except Exception:
        row = None

    def compute_progress(r: dict) -> int:
        steps = ["nuclei_status", "zap_status", "network_status"]
        done_states = {"completed", "failed", "skipped"}
        done = sum(1 for s in steps if r.get(s) in done_states)
        total = len(steps)
        return int((done / total) * 100) if total else 0

    if row:
        progress = compute_progress(row)
        status = row.get("status", "running")
        if status == "completed":
            progress = 100

        return {
            "scan_id": scan_id,

            # état global
            "status": status,
            "progress": progress,

            # détails par moteur
            "nuclei": {
                "status": row.get("nuclei_status"),
            },
            "zap": {
                "status": row.get("zap_status"),
                "scan_id": row.get("zap_scan_id"),
            },
            "network": {
                "status": row.get("network_status"),
            },

            # résultat final (si dispo)
            "risk_level": row.get("risk_level"),
            "vulnerabilities_count": row.get("vulnerabilities_count"),
            "mongo_report_id": row.get("mongo_report_id"),

            # timestamps
            "started_at": row.get("started_at"),
            "completed_at": row.get("completed_at"),
        }

    cache = COMPLETE_SCAN_CACHE.get(scan_id)
    if not cache:
        try:
            doc = get_scan_from_mongo(scan_id)
        except Exception:
            doc = None
        if not doc:
            raise HTTPException(status_code=404, detail="Scan not found")

        status = doc.get("status") or ("completed" if doc.get("severity_counts") or doc.get("risk_level") else "running")
        progress = int(doc.get("progress") or (100 if status == "completed" else 0))
        return {
            "scan_id": scan_id,
            "status": status,
            "progress": progress,
            "risk_level": doc.get("risk_level"),
            "vulnerabilities_count": doc.get("vulnerabilities_count"),
            "mongo_report_id": doc.get("mongo_id"),
            "started_at": doc.get("started_at"),
            "completed_at": doc.get("completed_at"),
        }

    progress = compute_progress(cache)
    status = "completed" if progress == 100 else "running"
    severity_counts, risk_level = _compute_severity(
        cache.get("nuclei_results"),
        cache.get("zap_results"),
    )

    return {
        "scan_id": scan_id,
        "status": status,
        "progress": progress,
        "nuclei": {
            "status": cache.get("nuclei_status"),
        },
        "zap": {
            "status": cache.get("zap_status"),
            "scan_id": cache.get("zap_scan_id"),
        },
        "network": {
            "status": cache.get("network_status"),
        },
        "risk_level": risk_level,
        "vulnerabilities_count": sum(severity_counts.values()),
        "mongo_report_id": None,
        "started_at": cache.get("started_at"),
        "completed_at": cache.get("completed_at"),
    }

def try_finalize_complete_scan(scan_id: str):
    row: Dict[str, Any] = {}
    try:
        row = get_scan_row(scan_id) or {}
    except Exception as exc:
        logger.warning("Supabase fetch failed for %s: %s", scan_id, exc)

    cache = COMPLETE_SCAN_CACHE.get(scan_id, {})

    def pick(key: str):
        value = row.get(key) if row else None
        if value is not None:
            return value
        return cache.get(key)

    # 🔒 éviter double écriture Mongo
    if pick("mongo_report_id"):
        return

    if pick("nuclei_status") not in {"completed", "failed"}:
        return
    if pick("zap_status") not in {"completed", "failed"}:
        return
    if pick("network_status") not in {"completed", "skipped", "failed"}:
        return

    # 🔥 calcul sévérité FINAL (sources réellement disponibles)
    severity_counts, risk_level = _compute_severity(
        pick("nuclei_results"),
        pick("zap_results"),
    )

    mongo_doc = {
        "scan_id": scan_id,
        "target_url": pick("target_url"),
        "cms_type": pick("cms_type"),
        "mode": "complete",
        "nuclei_scan": pick("nuclei_results"),
        "network_scan": pick("network_results"),
        "zap_results": pick("zap_results"),
        "severity_counts": severity_counts,
        "risk_level": risk_level,
        "completed_at": datetime.utcnow(),
        "source": "medianet_complete",
    }

    try:
        mongo_id = save_scan_json_to_mongo(
            mongo_doc,
            scan_id=scan_id,
            from_dict=True,
            collection_override="scan_medianet",
        )
    except Exception as e:
        logger.exception("Mongo finalization failed for %s", scan_id)
        _safe_update_scan_row(scan_id, {
            "status": "mongo_failed",
            "mongo_error": str(e),
        })
        return

    _safe_update_scan_row(scan_id, {
        "mongo_report_id": str(mongo_id),
        "status": "completed",
        "risk_level": risk_level,
        "vulnerabilities_count": sum(severity_counts.values()),
        "completed_at": datetime.utcnow().isoformat() + "Z",
    })
    COMPLETE_SCAN_CACHE.pop(scan_id, None)


def _compute_severity(*sources):
    vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    highest = None

    for src in sources:
        for item in src or []:
            sev = (item.get("severity") or item.get("risk") or "").lower()
            mapped = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "low",
                "informational": "low",
            }.get(sev)
            if mapped:
                vuln_counts[mapped] += 1
                highest = _pick_highest_risk(highest, mapped)

    return vuln_counts, highest

async def nuclei_worker(scan_id, url, cms, preview_only=False):
    try:
        nuclei_timeout = NUCLEI_PREVIEW_TIMEOUT if preview_only else NUCLEI_SCAN_TIMEOUT
        res = await asyncio.to_thread(
            run_nuclei_scan,
            url,
            cms,
            timeout=nuclei_timeout,
            profile="full",
        )

        parsed = parse_nuclei_output(res.get("nuclei_stdout", "") if isinstance(res, dict) else "")
        status = "completed"
        error = None
        partial = False

        if not isinstance(res, dict):
            status = "failed"
            error = "Invalid nuclei response"
        elif res.get("error"):
            status = "failed"
            error = res.get("error")
        elif res.get("timed_out"):
            if parsed:
                partial = True
            else:
                status = "failed"
                error = "Nuclei scan timed out"
        elif res.get("returncode") not in (0, None):
            status = "failed"
            error = f"Nuclei return code {res.get('returncode')}"

        extra = {}
        if error:
            extra["nuclei_error"] = error
        if partial:
            extra["nuclei_partial"] = True

        _update_complete_cache(scan_id, nuclei_status=status, nuclei_results=parsed, **extra)
        _safe_update_scan_row(scan_id, {
            "nuclei_status": status,
            "nuclei_results": parsed,
            **extra,
        })
        try_finalize_complete_scan(scan_id)

    except Exception as e:
        _update_complete_cache(scan_id, nuclei_status="failed", nuclei_error=str(e))
        _safe_update_scan_row(scan_id, {
            "nuclei_status": "failed",
            "nuclei_error": str(e)
        })

async def network_worker(scan_id, url):
    try:
        res = await asyncio.to_thread(run_full_network_scan, url)

        _update_complete_cache(scan_id, network_status="completed", network_results=res)
        _safe_update_scan_row(scan_id, {
            "network_status": "completed",
            "network_results": res
        })
        try_finalize_complete_scan(scan_id)

    except Exception as e:
        _update_complete_cache(scan_id, network_status="failed", network_error=str(e))
        _safe_update_scan_row(scan_id, {
            "network_status": "failed",
            "network_error": str(e)
        })
async def zap_full_worker(scan_id, url, zap_port=None):
    try:
        zap_meta = run_zap_full_remote_scan(
            url,
            scan_id=scan_id,
            zap_port=zap_port   # 👈 AJOUT
     )

        zap_scan_id = zap_meta.get("scanId")

        if not zap_scan_id:
            raise RuntimeError("ZAP did not return scanId")

        _update_complete_cache(scan_id,
            zap_status="running",
            zap_scan_id=zap_scan_id
        )

        _safe_update_scan_row(scan_id, {
            "zap_scan_id": zap_scan_id,
            "zap_status": "running"
        })

        # ⛔ STOP ICI
        # PAS DE POLLING
    
        return

    except Exception as e:
        _update_complete_cache(scan_id, zap_status="failed", zap_error=str(e))
        _safe_update_scan_row(scan_id, {
            "zap_status": "failed",
            "zap_error": str(e)
        })
        try_finalize_complete_scan(scan_id)



@scan_router.post("/scan-auto")
async def scan_auto(
    request: Request,
    sites: List[SiteWithCMS],
    max_concurrent: int | None = Header(None, alias="X-Max-Concurrent-Scans"),
):
    if not sites:
        raise HTTPException(status_code=400, detail="Liste des sites vide")
    for entry in sites:
        _ensure_target_allowed(str(entry.url))

    slots = max_concurrent
    if slots is not None:
        try:
            slots = int(slots)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid X-Max-Concurrent-Scans header")
        if slots <= 0:
            raise HTTPException(status_code=400, detail="Max concurrent scans must be positive")

    semaphore = asyncio.Semaphore(slots) if slots else None
    client_ip = _extract_request_ip(request)

    jobs: list[tuple[SiteWithCMS, str]] = []
    scan_ids: list[str] = []
    for site in sites:
        scan_id = site.scan_id or str(uuid.uuid4())
        jobs.append((site, scan_id))
        scan_ids.append(scan_id)

    async def run_with_slot(site: SiteWithCMS, scan_id: str):
        mode_value = _normalize_scan_mode(site.mode)
        network_scan_value = _normalize_network_scan_value(site.network_scan)
        if network_scan_value is None:
            network_scan_value = "quick" if mode_value == "light" else "full"
        try:
            save_scan_json_to_mongo(
                {
                    "scan_id": scan_id,
                    "cms_type": site.cms,
                    "target_url": str(site.url),
                    "mode": mode_value,
                    "network_scan": network_scan_value,
                    "status": "running",
                    "progress": 5,
                },
                scan_id=scan_id,
                from_dict=True,
                collection_override="cybershield",
            )
        except Exception:
            logger.warning("Mongo status update failed for %s", scan_id)

        try:
            if semaphore:
                async with semaphore:
                    result = await scan_sites(
                        site.cms,
                        [site.url],
                        scan_id,
                        mode_value,
                        user_id=site.user_id or "",
                    frontend_scan_id=site.frontend_scan_id,
                    preview_only=site.preview_only,
                    request_ip=client_ip,
                    network_scan=network_scan_value,
                    collection_override="cybershield",
                    zap_port=zap_port,
                )
            else:
                result = await scan_sites(
                    site.cms,
                    [site.url],
                    scan_id,
                    mode_value,
                    user_id=site.user_id or "",
                    frontend_scan_id=site.frontend_scan_id,
                    preview_only=site.preview_only,
                    request_ip=client_ip,
                    network_scan=network_scan_value,
                    collection_override="cybershield",
                    zap_port=zap_port,
                )

            try:
                save_scan_json_to_mongo(
                    {
                        "scan_id": scan_id,
                        "cms_type": site.cms,
                        "status": "completed",
                        "progress": 100,
                    },
                    scan_id=scan_id,
                    from_dict=True,
                    collection_override="cybershield",
                )
            except Exception:
                logger.warning("Mongo status update failed for %s", scan_id)
            return result
        except Exception as exc:
            try:
                save_scan_json_to_mongo(
                    {
                        "scan_id": scan_id,
                        "cms_type": site.cms,
                        "status": "failed",
                        "progress": 100,
                        "error": str(exc),
                    },
                    scan_id=scan_id,
                    from_dict=True,
                    collection_override="cybershield",
                )
            except Exception:
                logger.warning("Mongo status update failed for %s", scan_id)
            raise

    for site, scan_id in jobs:
        mode_value = _normalize_scan_mode(site.mode)
        network_scan_value = _normalize_network_scan_value(site.network_scan)
        if network_scan_value is None:
            network_scan_value = "quick" if mode_value == "light" else "full"
        try:
            save_scan_json_to_mongo(
                {
                    "scan_id": scan_id,
                    "cms_type": site.cms,
                    "target_url": str(site.url),
                    "mode": mode_value,
                    "network_scan": network_scan_value,
                    "status": "queued",
                    "progress": 0,
                },
                scan_id=scan_id,
                from_dict=True,
                collection_override="cybershield",
            )
        except Exception:
            logger.warning("Mongo status update failed for %s", scan_id)
        _schedule_background_scan(run_with_slot(site, scan_id), f"scan-auto:{scan_id}")

    return {
        "status": "queued",
        "message": "Scans en cours. Utilisez /scan-status/{scan_id} puis /generate-report/{scan_id}.",
        "total_sites": len(sites),
        "scan_ids": scan_ids,
    }


@scan_router.post("/scan-auto-detect")
async def scan_auto_detect(
    request: Request,
    sites: List[SiteDetect],
    max_concurrent: int | None = Header(None, alias="X-Max-Concurrent-Scans"),
):
    """
    Nouvelle route: pour chaque site on détecte d'abord le CMS via le modèle IA
    (scraping + prédiction). Ensuite on lance `scan_sites` automatiquement avec
    le CMS détecté (ou 'inconnu' si la confiance est faible / erreur).
    """
    if not sites:
        raise HTTPException(status_code=400, detail="Liste des sites vide")
    for entry in sites:
        _ensure_target_allowed(str(entry.url))

    slots = max_concurrent
    if slots is not None:
        try:
            slots = int(slots)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid X-Max-Concurrent-Scans header")
        if slots <= 0:
            raise HTTPException(status_code=400, detail="Max concurrent scans must be positive")

    semaphore = asyncio.Semaphore(slots) if slots else None
    client_ip = _extract_request_ip(request)

    jobs: list[tuple[SiteDetect, str]] = []
    scan_ids: list[str] = []
    for site in sites:
        scan_id = site.scan_id or str(uuid.uuid4())
        jobs.append((site, scan_id))
        scan_ids.append(scan_id)

    async def prepare_and_scan(site: SiteDetect, scan_id: str):
        url_str = str(site.url)
        normalized_mode = _normalize_scan_mode(site.mode)
        detected_cms = "inconnu"
        html = None
        headers = None
        robots = None
        try:
            # Récupère HTML, headers, robots via le scraper asynchrone
            _, html, headers, robots = await fetch_html(url_str)
        except Exception as e:
            logger.warning(f"⚠️ Échec détection CMS pour {url_str}: {e}")
            html = None

        model_guess = detect_cms_with_model(url_str, html, headers, robots)
        if model_guess:
            detected_cms = model_guess
        else:
            fallback_guess = detect_cms_from_html(html, headers)
            if fallback_guess:
                detected_cms = fallback_guess

        return await scan_sites(
            detected_cms,
            [site.url],
            scan_id,
            mode=normalized_mode,
            user_id=site.user_id or "",
            frontend_scan_id=site.frontend_scan_id,
            preview_only=site.preview_only,
            request_ip=client_ip,
            network_scan=normalized_mode == "complete",
        )

    async def run_with_slot(site: SiteDetect, scan_id: str):
        if semaphore:
            async with semaphore:
                await prepare_and_scan(site, scan_id)
                return
        await prepare_and_scan(site, scan_id)

    async def run_batch():
        results = await asyncio.gather(
            *[run_with_slot(site, scan_id) for site, scan_id in jobs],
            return_exceptions=True,
        )
        for outcome in results:
            if isinstance(outcome, Exception):
                logger.warning("Scan-auto-detect background task error: %s", outcome)

    _schedule_background_scan(run_batch(), f"scan-auto-detect:{len(jobs)}")

    return {
        "status": "queued",
        "message": "Les scans (avec détection CMS) ont été lancés en arrière-plan.",
        "total_sites": len(sites),
        "scan_ids": scan_ids,
    }


register_medianet_scan_route(
    router=medianet_router,
    site_detect_model=SiteDetect,
    fetch_html_fn=fetch_html,
    detect_cms_with_model_fn=detect_cms_with_model,
    detect_cms_from_html_fn=detect_cms_from_html,
    scan_sites_fn=scan_sites,
    extract_request_ip_fn=_extract_request_ip,
)
